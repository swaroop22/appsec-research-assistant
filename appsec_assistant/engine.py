"""
Audit Engine coordinating the client, analyzers, finding aggregation, and deduplication.
"""

from typing import List, Optional, Dict
from urllib.parse import urlparse
from appsec_assistant.client import SafeHTTPClient
from appsec_assistant.analyzers.base import BaseAnalyzer
from appsec_assistant.analyzers.headers_analyzer import HeadersAnalyzer
from appsec_assistant.analyzers.cookies_analyzer import CookiesAnalyzer
from appsec_assistant.analyzers.access_control_analyzer import AccessControlAnalyzer
from appsec_assistant.models import HTTPTransaction, VulnerabilityFinding, TargetConfig, WorkflowMode


from appsec_assistant.policy import ProgramPolicyManager
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from appsec_assistant.knowledge_base import GuidedExercise


class AuditEngine:
    """Orchestrates defensive analysis of target endpoints with deduplication and evidence tracking."""

    SITEWIDE_FINDING_IDS = {
        "SEC-HDR-001",  # Missing CSP
        "SEC-HDR-003",  # Missing Clickjacking
        "SEC-HDR-004",  # Missing nosniff
        "SEC-HDR-005",  # Missing HSTS
        "SEC-HDR-006",  # Server banner leak
        "SEC-HDR-007",  # Wildcard CORS
        "SEC-HDR-008",  # Missing Referrer-Policy
        "SEC-HDR-010",  # Missing Permissions-Policy
    }

    def __init__(
        self,
        config: TargetConfig,
        analyzers: Optional[List[BaseAnalyzer]] = None,
        policy_manager: Optional[ProgramPolicyManager] = None,
        mode: WorkflowMode = WorkflowMode.LOCAL_LAB,
    ):
        self.config = config
        self.policy_manager = policy_manager
        self.mode = mode
        self.client = SafeHTTPClient(config, policy_manager=policy_manager, mode=mode)
        self.analyzers: List[BaseAnalyzer] = analyzers or [
            HeadersAnalyzer(),
            CookiesAnalyzer(),
            AccessControlAnalyzer(),
        ]
        self._findings: List[VulnerabilityFinding] = []

    @property
    def findings(self) -> List[VulnerabilityFinding]:
        """Returns consolidated and deduplicated findings."""
        return list(self._findings)

    def clear_findings(self) -> None:
        self._findings.clear()

    @classmethod
    def normalize_url_path(cls, url: str) -> str:
        """Normalizes URL for deduplication by stripping redundant slashes."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    def audit_transaction(self, transaction: HTTPTransaction) -> List[VulnerabilityFinding]:
        """Runs all configured analyzers against an already-captured transaction with smart deduplication."""
        new_findings: List[VulnerabilityFinding] = []
        parsed = urlparse(transaction.url)
        host_netloc = parsed.netloc

        for analyzer in self.analyzers:
            results = analyzer.analyze(transaction)
            for res in results:
                # 1. Sitewide header findings consolidation
                if res.finding_id in self.SITEWIDE_FINDING_IDS:
                    existing = next(
                        (f for f in self._findings if f.finding_id == res.finding_id and urlparse(f.target_url).netloc == host_netloc),
                        None
                    )
                    if existing:
                        if transaction.url not in existing.affected_urls:
                            existing.affected_urls.append(transaction.url)
                            existing.evidence = (
                                f"{res.evidence} (Observed across {len(existing.affected_urls)} endpoints: "
                                f"{', '.join(existing.affected_urls[:4])}"
                                f"{'...' if len(existing.affected_urls) > 4 else ''})"
                            )
                        continue

                # 2. Cookie findings consolidation across paths
                elif res.finding_id.startswith("SEC-CK-"):
                    existing = next(
                        (f for f in self._findings if f.finding_id == res.finding_id and urlparse(f.target_url).netloc == host_netloc),
                        None
                    )
                    if existing:
                        if transaction.url not in existing.affected_urls:
                            existing.affected_urls.append(transaction.url)
                        continue

                # 3. Endpoint-specific findings deduplication by canonical URL
                else:
                    canon_url = self.normalize_url_path(res.target_url)
                    existing = next(
                        (f for f in self._findings if f.finding_id == res.finding_id and self.normalize_url_path(f.target_url) == canon_url),
                        None
                    )
                    if existing:
                        continue

                # Add new finding
                if transaction.url not in res.affected_urls:
                    res.affected_urls.append(transaction.url)
                self._findings.append(res)
                new_findings.append(res)

        return new_findings

    def audit_endpoint(self, endpoint_or_url: str, method: str = "GET") -> List[VulnerabilityFinding]:
        """Fetches the endpoint safely and runs all analyzers against the resulting transaction."""
        transaction = self.client.fetch(endpoint_or_url, method=method)
        return self.audit_transaction(transaction)

    def audit_exercise(self, exercise: "GuidedExercise") -> List[VulnerabilityFinding]:
        """
        Executes a targeted audit against the endpoint specified by a guided training exercise.
        Returns the discovered findings for verification against exercise criteria.
        """
        return self.audit_endpoint(exercise.target_endpoint)

    def run_suite(self, endpoints: List[str]) -> List[VulnerabilityFinding]:
        """Executes a defensive audit suite across a list of endpoints."""
        all_new: List[VulnerabilityFinding] = []
        for ep in endpoints:
            try:
                res = self.audit_endpoint(ep)
                all_new.extend(res)
            except Exception as e:
                print(f"[!] Warning: Could not audit endpoint '{ep}': {e}")
        return all_new

