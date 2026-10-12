"""
Tests for AI Provider Abstraction (Phase 4).
Verifies:
- Modular provider interface
- MockAIProvider deterministic offline execution
- Environment variables and credential management
- Missing credentials, timeout, rate limit error handling
- Consent requirement enforcement for external providers
- Graceful degradation and fallback to offline mock provider
"""

import os
import pytest
import requests
from unittest.mock import patch, MagicMock

from appsec_assistant.models import (
    VulnerabilityFinding,
    SeverityLevel,
    ConfidenceLevel,
    FindingTier,
    FindingType,
)
from appsec_assistant.ai import (
    BaseAIProvider,
    MockAIProvider,
    OpenAIProvider,
    AnthropicProvider,
    GeminiProvider,
    LocalAIProvider,
    AIService,
    AIProviderConfig,
    PriorityLevel,
    ConsentRequiredError,
    ProviderNotConfiguredError,
    ProviderTimeoutError,
    ProviderRateLimitError,
)


@pytest.fixture
def sample_finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        finding_id="SEC-AC-002",
        title="Unauthenticated Access to Administrative Endpoint: '/admin'",
        category="Broken Access Control",
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.CONFIRMED,
        confidence_explanation="Reproducible GET request returned HTTP 200 with admin dashboard telemetry.",
        finding_tier=FindingTier.INDEPENDENTLY_VERIFIED,
        target_url="http://127.0.0.1:5000/admin",
        description="Endpoint /admin returned HTTP 200 without authentication credentials.",
        impact="Full administrative compromise.",
        evidence="HTTP 200 OK. Body: <h1>Admin Dashboard</h1><p>user_management: enabled</p>",
        remediation="Enforce authentication middleware across all admin routes.",
    )


@pytest.fixture
def idor_finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        finding_id="SEC-AC-001",
        title="Heuristic Indicator: Potential IDOR via Sequential Identifier ('/api/Users/1')",
        category="Broken Access Control",
        severity=SeverityLevel.LOW,
        confidence=ConfidenceLevel.HEURISTIC,
        confidence_explanation="Sequential identifier detected in route.",
        finding_tier=FindingTier.HEURISTIC_INDICATOR,
        target_url="http://127.0.0.1:5000/api/Users/1",
        description="Sequential numerical identifier observed.",
        impact="Possible unauthorized object reference if authorization is missing.",
        evidence="Sequential integer '1' observed in path /api/Users/1",
        remediation="Validate user ownership server-side.",
    )


def test_mock_provider_deterministic_offline_triage(sample_finding):
    """Verifies that MockAIProvider operates purely offline with deterministic, grounded outputs."""
    provider = MockAIProvider()
    assert provider.name == "mock"
    assert provider.is_configured is True

    triage = provider.triage_finding(sample_finding)
    assert triage.finding_id == "SEC-AC-002"
    assert "admin" in triage.plain_english_explanation.lower()
    assert triage.recommended_priority == PriorityLevel.CRITICAL
    assert triage.finding_tier == FindingTier.INDEPENDENTLY_VERIFIED
    assert triage.potential_false_positive is False
    assert len(triage.recommended_next_steps) >= 2
    assert "Admin Dashboard" in " ".join(triage.evidence_references)


def test_external_provider_consent_enforcement(sample_finding):
    """Verifies that external providers strictly reject transmission without explicit user consent."""
    config = AIProviderConfig(
        provider_type="openai",
        api_key="test-sk-12345",
        consent_given=False,  # Consent NOT granted
    )

    # When fallback_to_mock is False, must raise ConsentRequiredError on init or triage
    with pytest.raises(ConsentRequiredError) as exc_info:
        service_strict = AIService(config, fallback_to_mock=False)
        service_strict.triage_finding(sample_finding)
    assert "consent is required" in str(exc_info.value).lower()

    # When fallback_to_mock is True, falls back safely to Mock provider without network call
    service_fallback = AIService(config, fallback_to_mock=True)
    triage = service_fallback.triage_finding(sample_finding)
    assert triage is not None
    assert triage.finding_id == sample_finding.finding_id


def test_missing_credentials_handling(sample_finding):
    """Verifies that unconfigured external providers raise ProviderNotConfiguredError or fallback gracefully."""
    config = AIProviderConfig(
        provider_type="openai",
        api_key="",  # Empty API key
        consent_given=True,
    )
    with patch.dict(os.environ, {}, clear=True):
        provider = OpenAIProvider(config)
        assert provider.is_configured is False

        with pytest.raises(ProviderNotConfiguredError):
            provider.triage_finding(sample_finding)


def test_provider_timeout_and_rate_limit_handling(sample_finding):
    """Verifies handling of network timeouts and rate limits (HTTP 429)."""
    config = AIProviderConfig(
        provider_type="openai",
        api_key="sk-valid-key",
        consent_given=True,
    )
    provider = OpenAIProvider(config)

    # 1. Test timeout
    import requests
    with patch("requests.post", side_effect=requests.exceptions.Timeout("Connection timed out")):
        with pytest.raises(ProviderTimeoutError):
            provider.triage_finding(sample_finding)

    # 2. Test rate limit (429)
    mock_resp_429 = MagicMock()
    mock_resp_429.status_code = 429
    with patch("requests.post", return_value=mock_resp_429):
        with pytest.raises(ProviderRateLimitError):
            provider.triage_finding(sample_finding)


def test_ai_service_graceful_fallback_on_provider_error(sample_finding):
    """Verifies that AIService degrades gracefully to offline mock provider upon external failures."""
    config = AIProviderConfig(
        provider_type="anthropic",
        api_key="sk-ant-test",
        consent_given=True,
    )
    service = AIService(config, fallback_to_mock=True)

    # Simulate provider timeout
    with patch("requests.post", side_effect=requests.exceptions.Timeout("Read timeout")):
        result = service.triage_finding(sample_finding)
        assert result is not None
        assert "UNAVAILABLE" in result.plain_english_explanation
        assert result.finding_id == sample_finding.finding_id
        # Verify finding model was enriched
        assert sample_finding.ai_triage is not None
