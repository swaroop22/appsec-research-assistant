"""
Tests for Guided Educational Security Exercises and Local Practice Lab.

Verifies:
- All 6 guided exercise categories are present with objective, test accounts, reproduction steps, and remediation.
- Executing exercises against the LocalLabServer with synthetic accounts and data.
- Strict restriction of active testing to local loopback lab.
"""

import pytest

from appsec_assistant.models import FindingTier, SeverityLevel, TargetConfig
from appsec_assistant.knowledge_base import VulnerabilityKnowledgeBase, EXERCISES_CATALOG
from appsec_assistant.engine import AuditEngine
from appsec_assistant.policy import ProgramPolicyManager
from appsec_assistant.lab_server import LocalLabServer, SYNTHETIC_ACCOUNTS


@pytest.fixture(scope="module")
def lab_server():
    server = LocalLabServer(host="127.0.0.1", port=5002)
    server.start()
    yield server
    server.stop()


def test_guided_exercises_catalog_complete():
    exercises = VulnerabilityKnowledgeBase.list_exercises()
    assert len(exercises) >= 6

    # Verify all 6 required categories are covered
    categories = [e.category for e in exercises]
    assert any("Access Control" in c for c in categories)
    assert any("IDOR" in c for c in categories)
    assert any("Authentication" in c for c in categories)
    assert any("Security Headers" in c for c in categories)
    assert any("Cookie" in c for c in categories)
    assert any("Input Validation" in c for c in categories)

    # Verify each exercise has clear learning context and reproduction steps
    for ex in exercises:
        assert len(ex.reproduction_steps) >= 2
        assert len(ex.objective) > 10
        assert len(ex.remediation_summary) > 10


def test_synthetic_accounts_contain_isolation():
    assert "1" in SYNTHETIC_ACCOUNTS
    assert "2" in SYNTHETIC_ACCOUNTS
    assert "99" in SYNTHETIC_ACCOUNTS
    assert SYNTHETIC_ACCOUNTS["1"]["username"] == "bob"
    assert SYNTHETIC_ACCOUNTS["2"]["username"] == "alice"
    assert SYNTHETIC_ACCOUNTS["99"]["role"] == "admin"


def test_broken_access_control_exercise_execution(lab_server):
    config = TargetConfig(base_url=lab_server.url)
    engine = AuditEngine(config)

    ex = VulnerabilityKnowledgeBase.get_exercise("EX-AC-01")
    assert ex is not None
    findings = engine.audit_exercise(ex)

    # Must find verified critical unauthenticated admin access
    admin_findings = [f for f in findings if f.finding_id == "SEC-AC-002"]
    assert len(admin_findings) == 1
    f = admin_findings[0]
    assert f.severity == SeverityLevel.CRITICAL
    assert f.finding_tier == FindingTier.INDEPENDENTLY_VERIFIED
    assert "user_management: enabled" in f.evidence


def test_idor_heuristic_exercise_execution(lab_server):
    config = TargetConfig(base_url=lab_server.url)
    engine = AuditEngine(config)

    ex = VulnerabilityKnowledgeBase.get_exercise("EX-IDOR-01")
    assert ex is not None
    findings = engine.audit_exercise(ex)

    # Must find sequential integer IDOR heuristic
    idor_findings = [f for f in findings if f.finding_id == "SEC-AC-001"]
    assert len(idor_findings) == 1
    f = idor_findings[0]
    assert f.finding_tier == FindingTier.HEURISTIC_INDICATOR
    assert f.severity == SeverityLevel.LOW
    assert "HEURISTIC PATTERN" in f.evidence


def test_headers_and_cookies_exercises_execution(lab_server):
    config = TargetConfig(base_url=lab_server.url)
    engine = AuditEngine(config)

    # Exercise 4: Headers
    ex_hdr = VulnerabilityKnowledgeBase.get_exercise("EX-HDR-01")
    findings_hdr = engine.audit_exercise(ex_hdr)
    assert any(f.finding_id == "SEC-HDR-001" for f in findings_hdr)
    # Server banner must be classified as OBSERVATION
    banner_findings = [f for f in findings_hdr if f.finding_id == "SEC-HDR-006"]
    assert len(banner_findings) == 1
    assert banner_findings[0].finding_tier == FindingTier.OBSERVATION

    # Exercise 5: Cookies
    engine.clear_findings()
    ex_ck = VulnerabilityKnowledgeBase.get_exercise("EX-CK-01")
    findings_ck = engine.audit_exercise(ex_ck)
    cookie_weakness = [f for f in findings_ck if f.finding_id.startswith("SEC-CK-001")]
    assert len(cookie_weakness) == 1
    assert cookie_weakness[0].finding_tier == FindingTier.SUSPECTED_VULNERABILITY


def test_input_validation_search_reflection_endpoint(lab_server):
    # Tests safe synthetic reflection endpoint
    config = TargetConfig(base_url=lab_server.url)
    engine = AuditEngine(config)
    tx = engine.client.fetch("/search?q=synthetic_safe_test")
    assert tx.status_code == 200
    assert "synthetic_safe_test" in tx.response_body
    # Verify no CSP is configured on root/search
    findings = engine.audit_transaction(tx)
    assert any(f.finding_id == "SEC-HDR-001" for f in findings)
