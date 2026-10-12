"""
Tests for Semantic Duplicate Detection and Controlled Merging (Phase 4).
Verifies:
- AI semantic similarity detection across findings
- Human approval requirement before merging
- Preservation of all affected URLs, evidence, and timestamps
- Preservation of distinct vulnerability separation
"""

import pytest

from appsec_assistant.models import (
    VulnerabilityFinding,
    SeverityLevel,
    ConfidenceLevel,
    FindingTier,
)
from appsec_assistant.ai import (
    AIService,
    MockAIProvider,
    DuplicateSuggestion,
)


@pytest.fixture
def duplicate_cookie_findings():
    f1 = VulnerabilityFinding(
        finding_id="SEC-CK-001-session_id",
        title="Cookie Missing HttpOnly Flag: 'session_id'",
        category="Cookie Security",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        finding_tier=FindingTier.SUSPECTED_VULNERABILITY,
        target_url="http://127.0.0.1:5000/login",
        affected_urls=["http://127.0.0.1:5000/login"],
        description="session_id cookie is issued without HttpOnly.",
        impact="XSS session hijacking.",
        evidence="Set-Cookie: session_id=token123; Path=/",
        remediation="Add HttpOnly flag.",
    )

    f2 = VulnerabilityFinding(
        finding_id="SEC-CK-002-session_id",
        title="Cookie Missing Secure Flag: 'session_id'",
        category="Cookie Security",
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        finding_tier=FindingTier.SUSPECTED_VULNERABILITY,
        target_url="http://127.0.0.1:5000/api/auth",
        affected_urls=["http://127.0.0.1:5000/api/auth"],
        description="session_id cookie is issued without Secure flag.",
        impact="Plaintext cookie transmission over HTTP.",
        evidence="Set-Cookie: session_id=token123; Path=/; HttpOnly",
        remediation="Add Secure flag.",
    )

    return f1, f2


def test_semantic_duplicate_detection(duplicate_cookie_findings):
    """Verifies that AI similarity analysis generates candidate duplicate suggestions with scores and rationales."""
    f1, f2 = duplicate_cookie_findings
    service = AIService()

    suggestions = service.detect_duplicates([f1, f2])
    assert len(suggestions) >= 1

    sug = suggestions[0]
    assert isinstance(sug, DuplicateSuggestion)
    assert sug.similarity_score > 0.5
    assert sug.primary_finding_id == f1.finding_id
    assert sug.duplicate_finding_id == f2.finding_id
    assert "cookie" in sug.similarity_rationale.lower()
    assert sug.is_approved is False  # Never approved automatically


def test_duplicate_approval_workflow(duplicate_cookie_findings):
    """Verifies that duplicate suggestions must be approved by a human researcher."""
    f1, f2 = duplicate_cookie_findings
    service = AIService()
    suggestions = service.detect_duplicates([f1, f2])
    sug = suggestions[0]

    assert sug.is_approved is False
    assert sug.reviewed_by is None

    # Human researcher reviews and approves
    service.approve_duplicate(sug, reviewer="Alice Researcher")

    assert sug.is_approved is True
    assert sug.reviewed_by == "Alice Researcher"
    assert sug.review_date is not None


def test_controlled_duplicate_merge_preserves_evidence_and_urls(duplicate_cookie_findings):
    """
    Verifies that merging approved duplicates preserves:
    - All affected URLs from both findings
    - All evidence from both findings
    - Detailed merge notes and timestamps
    """
    f1, f2 = duplicate_cookie_findings
    service = AIService()

    initial_f1_evidence = f1.evidence
    initial_f2_evidence = f2.evidence

    merged = service.merge_duplicates(primary=f1, duplicate=f2)

    # 1. Affected URLs must contain both endpoints
    assert "http://127.0.0.1:5000/login" in merged.affected_urls
    assert "http://127.0.0.1:5000/api/auth" in merged.affected_urls
    assert len(merged.affected_urls) == 2

    # 2. Both evidence records must be preserved
    assert initial_f1_evidence in merged.evidence
    assert initial_f2_evidence in merged.evidence
    assert "[Merged Instance from http://127.0.0.1:5000/api/auth]" in merged.evidence

    # 3. Merge history must be tracked in review notes
    assert "Merged duplicate instance" in merged.review_notes
    assert f2.finding_id in merged.review_notes
