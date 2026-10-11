"""
Tests for Finding Verification Tiers and Evidence Sanitization.

Verifies:
- Separation of Observations, Heuristic Indicators, Suspected Vulnerabilities, and Independently Verified Findings.
- Critical severity is NEVER inferred from an HTTP status code alone.
- Reproducible supporting evidence is required before labeling confirmed.
- Sensitive credentials, tokens, and passwords in evidence are redacted (sanitized_evidence).
- Reproduction steps are structured and reproducible.
- Human review sign-off workflow.
"""

import pytest

from appsec_assistant.models import (
    FindingTier,
    SeverityLevel,
    ConfidenceLevel,
    VulnerabilityFinding,
    HTTPTransaction,
    sanitize_evidence_text,
)
from appsec_assistant.analyzers.access_control_analyzer import AccessControlAnalyzer
from appsec_assistant.analyzers.headers_analyzer import HeadersAnalyzer
from appsec_assistant.reporters.markdown_reporter import MarkdownReporter


def test_verification_tiers_distinct():
    tiers = [
        FindingTier.OBSERVATION,
        FindingTier.HEURISTIC_INDICATOR,
        FindingTier.SUSPECTED_VULNERABILITY,
        FindingTier.INDEPENDENTLY_VERIFIED,
    ]
    assert len(tiers) == 4
    assert len(set(t.value for t in tiers)) == 4


def test_status_code_200_alone_does_not_infer_critical():
    analyzer = AccessControlAnalyzer()

    # 1. HTTP 200 on an admin path displaying a login challenge is NOT Critical
    login_challenge_tx = HTTPTransaction(
        url="http://127.0.0.1:5000/admin/login",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={"Content-Type": "text/html"},
        response_body='<html><body><h1>Please Log In</h1><form><input type="password" name="password" /></form></body></html>',
    )
    findings = analyzer.analyze(login_challenge_tx)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == SeverityLevel.INFO
    assert f.finding_tier == FindingTier.OBSERVATION
    assert f.finding_id == "SEC-AC-002-INFO"

    # 2. HTTP 200 on an admin path without privileged content or forms
    neutral_tx = HTTPTransaction(
        url="http://127.0.0.1:5000/admin/help",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={"Content-Type": "text/html"},
        response_body="<html><body><h1>General Help</h1><p>Documentation page.</p></body></html>",
    )
    neutral_findings = analyzer.analyze(neutral_tx)
    # Neutral 200 page without privileged controls or login form is not confirmed critical
    critical_findings = [f for f in neutral_findings if f.severity == SeverityLevel.CRITICAL]
    assert len(critical_findings) == 0


def test_critical_requires_reproducible_privileged_content():
    analyzer = AccessControlAnalyzer()
    privileged_tx = HTTPTransaction(
        url="http://127.0.0.1:5000/admin/users",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={"Content-Type": "text/html"},
        response_body="<html><body><h1>Admin Console</h1><p>user_management: enabled</p><p>delete user</p></body></html>",
    )
    findings = analyzer.analyze(privileged_tx)
    assert any(f.finding_id == "SEC-AC-002" and f.severity == SeverityLevel.CRITICAL and f.finding_tier == FindingTier.INDEPENDENTLY_VERIFIED for f in findings)


def test_status_code_500_alone_is_not_an_injection_vulnerability():
    analyzer = AccessControlAnalyzer()
    generic_error_tx = HTTPTransaction(
        url="http://127.0.0.1:5000/api/items",
        method="GET",
        request_headers={},
        status_code=500,
        response_headers={"Content-Type": "text/plain"},
        response_body="Internal Server Error",
    )
    findings = analyzer.analyze(generic_error_tx)
    # An HTTP 500 error code alone with generic message must NOT be labeled an injection or critical flaw
    assert len(findings) == 0


def test_evidence_sanitization():
    raw_evidence = (
        "GET /api/profile HTTP/1.1\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_payload.signature\n"
        "Cookie: session_id=sess_active_987654321; other=123\n"
        "Body: password=SuperSecretPassword123&user=admin"
    )
    sanitized = sanitize_evidence_text(raw_evidence)

    assert "SuperSecretPassword123" not in sanitized
    assert "sess_active_987654321" not in sanitized
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized
    assert "[REDACTED_SESSION]" in sanitized
    assert "[REDACTED_TOKEN]" in sanitized or "[REDACTED_CREDENTIALS]" in sanitized


def test_finding_reproduction_steps_and_human_review_signoff():
    finding = VulnerabilityFinding(
        finding_id="TEST-001",
        title="Test Finding",
        category="Test Category",
        severity=SeverityLevel.HIGH,
        target_url="http://127.0.0.1:5000/test",
        description="Test description",
        impact="Test impact",
        evidence="Authorization: Bearer my_secret_token_abc1234567890",
        remediation="Test remediation",
        finding_tier=FindingTier.SUSPECTED_VULNERABILITY,
    )
    # Reproduction steps automatically initialized if empty
    assert len(finding.reproduction_steps) >= 3
    assert "curl" in finding.reproduction_steps[0]

    # Evidence automatically sanitized if not explicitly supplied
    assert "my_secret_token_abc1234567890" not in finding.sanitized_evidence
    assert "[REDACTED" in finding.sanitized_evidence

    # Human review defaults to False
    assert finding.human_reviewed is False

    # Perform auditor sign-off
    finding.human_reviewed = True
    finding.reviewed_by = "Lead Researcher"
    finding.review_date = "2026-10-10 20:00:00 UTC"
    finding.review_notes = "Independent reproduction succeeded on isolated local lab."

    md_report = MarkdownReporter.generate([finding], "http://127.0.0.1:5000/test")
    assert "Lead Researcher" in md_report
    assert "Verified by Human Auditor" in md_report
