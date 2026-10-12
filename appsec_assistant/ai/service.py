"""
High-level AI Triage Service orchestrating providers, user consent, and finding enrichment.
"""

from typing import Dict, List, Optional, Any
import datetime

from appsec_assistant.models import (
    VulnerabilityFinding,
    FindingTier,
    HTTPTransaction,
)
from appsec_assistant.ai.models import (
    AITriageResult,
    DuplicateSuggestion,
    AIProviderConfig,
)
from appsec_assistant.ai.providers import (
    BaseAIProvider,
    MockAIProvider,
    OpenAIProvider,
    AnthropicProvider,
    GeminiProvider,
    LocalAIProvider,
    AIProviderError,
    ProviderNotConfiguredError,
    ProviderTimeoutError,
    ProviderRateLimitError,
)


class ConsentRequiredError(AIProviderError):
    """Raised when an external AI provider is requested without explicit user consent."""
    pass


class AIService:
    """
    Orchestrates AI-assisted triage, user consent checks, fallback mechanisms,
    and semantic duplicate reviews.
    """

    EXTERNAL_PROVIDERS = {"openai", "anthropic", "gemini"}

    def __init__(
        self,
        config: Optional[AIProviderConfig] = None,
        fallback_to_mock: bool = True,
    ):
        self.config = config or AIProviderConfig(provider_type="mock")
        self.fallback_to_mock = fallback_to_mock
        self._provider = self._init_provider(self.config)

    def _init_provider(self, config: AIProviderConfig) -> BaseAIProvider:
        ptype = (config.provider_type or "mock").lower()

        if ptype in self.EXTERNAL_PROVIDERS and not config.consent_given:
            if not self.fallback_to_mock:
                raise ConsentRequiredError(
                    f"Explicit user consent is required before sending finding data to external provider '{ptype}'. "
                    "Configure consent_given=True to proceed."
                )
            # Default safely to Mock provider when consent is absent
            return MockAIProvider(config)

        if ptype == "openai":
            return OpenAIProvider(config)
        elif ptype == "anthropic":
            return AnthropicProvider(config)
        elif ptype == "gemini":
            return GeminiProvider(config)
        elif ptype == "local":
            return LocalAIProvider(config)
        else:
            return MockAIProvider(config)

    @property
    def provider(self) -> BaseAIProvider:
        return self._provider

    def update_config(self, config: AIProviderConfig) -> None:
        """Updates provider configuration and re-initializes."""
        self.config = config
        self._provider = self._init_provider(config)

    def triage_finding(
        self,
        finding: VulnerabilityFinding,
        source_transaction: Optional[HTTPTransaction] = None,
    ) -> AITriageResult:
        """
        Executes AI triage for a single finding and attaches the result
        to the finding's `ai_triage` dictionary.
        """
        ptype = (self.config.provider_type or "mock").lower()
        if ptype in self.EXTERNAL_PROVIDERS and not self.config.consent_given:
            if not self.fallback_to_mock:
                raise ConsentRequiredError(
                    f"Explicit user consent is required before sending finding data to external provider '{ptype}'."
                )
            # Fail closed or fallback to deterministic mock
            provider = MockAIProvider(self.config)
        else:
            provider = self._provider

        try:
            result = provider.triage_finding(finding, source_transaction=source_transaction)
        except (ProviderNotConfiguredError, ProviderTimeoutError, ProviderRateLimitError, AIProviderError) as e:
            if self.fallback_to_mock and provider.name != "mock":
                # Graceful degradation to deterministic mock provider
                mock_prov = MockAIProvider(self.config)
                result = mock_prov.triage_finding(finding, source_transaction=source_transaction)
                result.plain_english_explanation = (
                    f"[{provider.name.upper()} UNAVAILABLE: {e} - Fell back to offline analysis] "
                    + result.plain_english_explanation
                )
            else:
                raise

        # Attach to finding data model
        finding.ai_triage = result.to_dict()
        return result

    def triage_all(
        self,
        findings: List[VulnerabilityFinding],
        source_transaction: Optional[HTTPTransaction] = None,
    ) -> Dict[str, AITriageResult]:
        """Runs triage across all findings."""
        results: Dict[str, AITriageResult] = {}
        for f in findings:
            res = self.triage_finding(f, source_transaction=source_transaction)
            results[f.finding_id] = res
        return results

    def detect_duplicates(
        self,
        findings: List[VulnerabilityFinding],
    ) -> List[DuplicateSuggestion]:
        """Detects semantic duplicate suggestions across findings."""
        return self._provider.detect_duplicates(findings)

    @staticmethod
    def approve_duplicate(
        suggestion: DuplicateSuggestion,
        reviewer: str = "Security Researcher",
    ) -> None:
        """Marks a duplicate suggestion as approved by human researcher."""
        suggestion.is_approved = True
        suggestion.reviewed_by = reviewer
        suggestion.review_date = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    @staticmethod
    def merge_duplicates(
        primary: VulnerabilityFinding,
        duplicate: VulnerabilityFinding,
    ) -> VulnerabilityFinding:
        """
        Merges an approved duplicate finding into the primary finding.
        PRESERVES:
        - All affected URLs from both findings.
        - Full evidence snippets from both findings.
        - Timestamps and source analyzer references.
        """
        # 1. Combine affected URLs preserving order and uniqueness
        combined_urls = list(primary.affected_urls)
        for u in duplicate.affected_urls:
            if u not in combined_urls:
                combined_urls.append(u)
        primary.affected_urls = combined_urls

        # 2. Preserve evidence
        dup_raw_ev = duplicate.evidence
        dup_san_ev = duplicate.sanitized_evidence or duplicate.evidence
        if dup_raw_ev and dup_raw_ev not in primary.evidence:
            primary.evidence = f"{primary.evidence}\n[Merged Instance from {duplicate.target_url}]:\n{dup_raw_ev}"
        if dup_san_ev and dup_san_ev not in primary.sanitized_evidence:
            primary.sanitized_evidence = f"{primary.sanitized_evidence}\n[Merged Instance from {duplicate.target_url}]:\n{dup_san_ev}"

        # 3. Update review notes with merge history
        merge_note = (
            f" [Merged duplicate instance '{duplicate.finding_id}' from '{duplicate.target_url}' "
            f"on {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}]"
        )
        primary.review_notes = (primary.review_notes + merge_note).strip()

        return primary

    def draft_report_narrative(
        self,
        findings: List[VulnerabilityFinding],
        target_url: str,
    ) -> str:
        """Generates an executive narrative report draft."""
        return self._provider.draft_report_narrative(findings, target_url)
