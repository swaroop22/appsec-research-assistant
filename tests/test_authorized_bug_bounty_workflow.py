"""
Test suite for Phase 5: Authorized Bug Bounty Research Workflow.

Tests:
- Program scope parsing and registry
- Asset inclusion and exclusion precedence
- Ambiguous and contradictory scope rejection
- Policy expiry and stale verification
- Scope changes revoking verification
- Workflow modes (Mode A: OFFLINE, Mode B: LOCAL_LAB, Mode C: AUTHORIZED_PROGRAM_PREPARATION)
- Secret, credential, and PII redaction
- Evidence completeness auditing and missing evidence detection
- Report readiness gates and out-of-scope asset blocking
- Research status transitions and human confirmation requirements
- Policy-aware report generation, human sign-off export, and bounty disclaimer
"""

import os
import json
import datetime
import pytest

from appsec_assistant.models import (
    ProgramPolicy,
    VulnerabilityFinding,
    SeverityLevel,
    ConfidenceLevel,
    FindingTier,
    WorkflowMode,
    ResearchStatus,
    ResearchTask,
    TargetConfig,
    sanitize_evidence_text,
)
from appsec_assistant.policy import (
    ProgramPolicyManager,
    PolicyError,
    PolicyVerificationError,
    PolicyStaleError,
    ScopeIntegrityError,
    UnauthorizedTargetError,
    create_sample_fictional_policy,
)
from appsec_assistant.client import (
    SafeHTTPClient,
    NetworkDisabledInOfflineModeError,
    ActiveTestingDisabledInPrepModeError,
)
from appsec_assistant.research import (
    ResearchManager,
    ResearchError,
    ReportReadinessError,
    HumanConfirmationRequiredError,
    TaskNotFoundError,
)
from appsec_assistant.reporters.policy_report_generator import (
    PolicyReportGenerator,
    ResearcherReviewRequiredError,
)


# ---------------------------------------------------------------------------
# 1. Program Policy Registry and Parsing Tests
# ---------------------------------------------------------------------------

def test_default_policy_and_fictional_sample():
    manager = ProgramPolicyManager()
    local_p = manager.get_policy("local-lab-vdp")
    assert local_p is not None
    assert local_p.is_verified is True
    assert local_p.is_enabled is True
    assert "http://127.0.0.1:5000/*" in local_p.eligible_assets

    # Create sample fictional policy
    sample_policy = create_sample_fictional_policy()
    assert sample_policy.program_id == "acme-fintech-bounty"
    assert sample_policy.company_name == "Acme Financial Services Inc."
    assert "https://app.acmefintech.example.com/*" in sample_policy.eligible_assets
    assert "https://internal.acmefintech.example.com/*" in sample_policy.excluded_assets
    assert sample_policy.is_verified is False  # Defaults unverified
    assert sample_policy.is_enabled is False


def test_import_policy_from_json_and_file(tmp_path):
    manager = ProgramPolicyManager()
    sample = create_sample_fictional_policy()
    json_path = tmp_path / "test_policy.json"
    json_path.write_text(json.dumps(sample.to_dict()))

    imported = manager.import_policy_from_file(str(json_path))
    assert imported.program_id == "acme-fintech-bounty"
    assert imported.company_name == "Acme Financial Services Inc."
    assert len(imported.eligible_assets) >= 3
    assert len(imported.excluded_assets) >= 3
    assert imported.is_verified is False
    assert imported.is_enabled is False


# ---------------------------------------------------------------------------
# 2. Scope Verification, Inclusion, and Exclusion Precedence
# ---------------------------------------------------------------------------

def test_asset_inclusion_and_exclusion_precedence():
    manager = ProgramPolicyManager()
    policy = create_sample_fictional_policy()
    manager.add_policy(policy)

    # Verify and enable the policy
    manager.verify_policy(
        program_id=policy.program_id,
        reviewer_name="Lead Security Researcher",
        verification_notes="Verified policy terms against official Acme disclosure portal.",
    )
    manager.enable_policy(policy.program_id)

    # 1. Eligible in-scope asset
    assert manager.is_asset_authorized("https://app.acmefintech.example.com/dashboard", program_id=policy.program_id) is True
    assert manager.is_asset_authorized("https://api.acmefintech.example.com/v1/users", program_id=policy.program_id) is True

    # 2. Excluded asset - MUST BE BLOCKED even if it matched an eligible wildcard pattern
    # internal.acmefintech.example.com is explicitly in excluded_assets
    assert manager.is_asset_authorized("https://internal.acmefintech.example.com/login", program_id=policy.program_id) is False
    assert manager.is_asset_authorized("https://admin.acmefintech.example.com/internal-billing/invoice", program_id=policy.program_id) is False

    with pytest.raises(UnauthorizedTargetError) as exc_info:
        manager.validate_target_authorization("https://internal.acmefintech.example.com/login", program_id=policy.program_id)
    assert "EXPLICITLY EXCLUDED" in str(exc_info.value)

    # 3. Arbitrary asset outside allowlist
    assert manager.is_asset_authorized("https://payment.acmefintech.example.com/", program_id=policy.program_id) is False
    with pytest.raises(UnauthorizedTargetError):
        manager.validate_target_authorization("https://payment.acmefintech.example.com/", program_id=policy.program_id)


# ---------------------------------------------------------------------------
# 3. Ambiguous and Contradictory Scope Rejection
# ---------------------------------------------------------------------------

def test_ambiguous_and_contradictory_scope_rejection():
    manager = ProgramPolicyManager()

    # Ambiguous wildcard pattern '*'
    bad_policy_1 = ProgramPolicy(
        program_id="bad-wildcard",
        program_name="Bad Wildcard Program",
        policy_url="https://example.com/policy",
        eligible_assets=["*"],
        prohibited_methods=["None"],
    )
    with pytest.raises(ScopeIntegrityError) as exc_1:
        manager.add_policy(bad_policy_1)
    assert "Ambiguous scope pattern '*'" in str(exc_1.value)

    # Ambiguous wildcard pattern 'https://*'
    bad_policy_2 = ProgramPolicy(
        program_id="bad-scheme-wildcard",
        program_name="Bad Scheme Wildcard",
        policy_url="https://example.com/policy",
        eligible_assets=["https://*"],
        prohibited_methods=["None"],
    )
    with pytest.raises(ScopeIntegrityError):
        manager.add_policy(bad_policy_2)

    # Contradictory scope: same asset in eligible and excluded
    contradictory_policy = ProgramPolicy(
        program_id="contradictory-scope",
        program_name="Contradictory Policy",
        policy_url="https://example.com/policy",
        eligible_assets=["https://app.example.com/*"],
        excluded_assets=["https://app.example.com/*"],
        prohibited_methods=["None"],
    )
    with pytest.raises(ScopeIntegrityError) as exc_3:
        manager.add_policy(contradictory_policy)
    assert "Contradictory scope definition" in str(exc_3.value)

    # Invalid scheme (ftp://)
    bad_scheme_policy = ProgramPolicy(
        program_id="bad-scheme",
        program_name="Bad Scheme Policy",
        policy_url="https://example.com/policy",
        eligible_assets=["ftp://ftp.example.com/*"],
        prohibited_methods=["None"],
    )
    with pytest.raises(ScopeIntegrityError) as exc_4:
        manager.add_policy(bad_scheme_policy)
    assert "unauthorized scheme 'ftp'" in str(exc_4.value)


# ---------------------------------------------------------------------------
# 4. Policy Expiry and Stale Verification
# ---------------------------------------------------------------------------

def test_policy_expiry_and_stale_verification():
    manager = ProgramPolicyManager()
    policy = create_sample_fictional_policy()
    manager.add_policy(policy)

    # 1. Fresh verification
    fresh_date = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    manager.verify_policy(
        program_id=policy.program_id,
        reviewer_name="Auditor A",
        verification_notes="Fresh verification",
        verification_date=fresh_date,
    )
    assert policy.is_stale() is False
    manager.enable_policy(policy.program_id)
    assert policy.is_enabled is True

    # 2. Expired / Stale verification (> 90 days old)
    stale_date = (datetime.datetime.utcnow() - datetime.timedelta(days=120)).strftime("%Y-%m-%d %H:%M:%S UTC")
    policy.verification_date = stale_date
    policy.policy_retrieval_date = stale_date
    policy.is_enabled = False  # Try to re-enable after becoming stale

    assert policy.is_stale(max_age_days=90) is True

    with pytest.raises(PolicyStaleError) as exc_stale:
        manager.enable_policy(policy.program_id)
    assert "stale or expired" in str(exc_stale.value)

    # Authorization check must fail closed when policy is stale
    assert manager.is_asset_authorized("https://app.acmefintech.example.com/test", program_id=policy.program_id) is False


def test_scope_change_revokes_verification():
    manager = ProgramPolicyManager()
    policy = create_sample_fictional_policy()
    manager.add_policy(policy)

    manager.verify_policy(
        program_id=policy.program_id,
        reviewer_name="Auditor A",
        verification_notes="Scope certified.",
    )
    manager.enable_policy(policy.program_id)
    assert policy.is_verified is True
    assert policy.is_enabled is True

    # Mutate scope boundary (e.g. adding new asset)
    updated_policy = ProgramPolicy.from_dict(policy.to_dict())
    updated_policy.eligible_assets.append("https://newservice.acmefintech.example.com/*")
    
    manager.update_policy(updated_policy)
    retrieved = manager.get_policy(policy.program_id)

    # Must be automatically revoked to mandate renewed human review!
    assert retrieved.is_verified is False
    assert retrieved.is_enabled is False
    assert "[SCOPE MODIFIED - REVIEW REQUIRED]" in retrieved.verification_notes


# ---------------------------------------------------------------------------
# 5. Workflow Execution Modes (OFFLINE, LOCAL_LAB, AUTHORIZED_PREPARATION)
# ---------------------------------------------------------------------------

def test_workflow_mode_offline_blocks_network():
    config = TargetConfig(base_url="http://127.0.0.1:5000")
    client = SafeHTTPClient(config, mode=WorkflowMode.OFFLINE)

    with pytest.raises(NetworkDisabledInOfflineModeError) as exc:
        client.fetch("/api/test")
    assert "OFFLINE mode" in str(exc.value)


def test_workflow_mode_preparation_blocks_active_scans():
    config = TargetConfig(base_url="http://127.0.0.1:5000")
    client = SafeHTTPClient(config, mode=WorkflowMode.AUTHORIZED_PROGRAM_PREPARATION)

    with pytest.raises(ActiveTestingDisabledInPrepModeError) as exc:
        client.fetch("/api/test")
    assert "Mode C (Authorized Program Preparation)" in str(exc.value)


# ---------------------------------------------------------------------------
# 6. Secret, Credential, and PII Redaction
# ---------------------------------------------------------------------------

def test_evidence_sanitization_secrets_and_pii():
    raw_leak = (
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: session_id=s3cr3t_s3ss10n_t0k3n_12345; Path=/\r\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0\r\n"
        "\r\n"
        "user_email=researcher.jane@company.com&phone=555-867-5309&ssn=123-45-6789&password=SuperSecretPassword99!\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y3yZ...FAKESTKEY...X==\n"
        "-----END RSA PRIVATE KEY-----\n"
    )

    sanitized = sanitize_evidence_text(raw_leak)

    assert "s3cr3t_s3ss10n_t0k3n" not in sanitized
    assert "[REDACTED_SESSION]" in sanitized or "[REDACTED_COOKIE]" in sanitized or "[REDACTED_TOKEN]" in sanitized
    assert "eyJhbGciOiJI" not in sanitized
    assert "[REDACTED_CREDENTIALS]" in sanitized
    assert "SuperSecretPassword99!" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized
    assert "researcher.jane@company.com" not in sanitized
    assert "[REDACTED_EMAIL]" in sanitized
    assert "555-867-5309" not in sanitized
    assert "[REDACTED_PHONE]" in sanitized
    assert "123-45-6789" not in sanitized
    assert "[REDACTED_SSN]" in sanitized
    assert "BEGIN RSA PRIVATE KEY" not in sanitized
    assert "[REDACTED_PRIVATE_KEY]" in sanitized


# ---------------------------------------------------------------------------
# 7. Research Task Manager, Evidence Completeness, and Report Readiness
# ---------------------------------------------------------------------------

def test_evidence_completeness_and_missing_evidence():
    policy_mgr = ProgramPolicyManager()
    research_mgr = ResearchManager(policy_mgr)

    # Incomplete finding (missing steps, evidence, impact)
    incomplete_finding = VulnerabilityFinding(
        finding_id="F-INC-001",
        title="Potential Information Leak",
        category="Information Disclosure",
        severity=SeverityLevel.LOW,
        target_url="http://127.0.0.1:5000/info",
        description="Endpoint leaks server info",
        impact="",
        evidence="",
        remediation="",
        reproduction_steps=[],
    )

    score, missing = research_mgr.calculate_evidence_completeness(incomplete_finding)
    assert score < 0.70
    assert any("reproduction steps" in m.lower() for m in missing)
    assert any("evidence" in m.lower() for m in missing)
    assert any("impact" in m.lower() for m in missing)

    # Complete finding
    complete_finding = VulnerabilityFinding(
        finding_id="F-COMP-001",
        title="Missing Content-Security-Policy on Authentication Endpoint",
        category="Security Headers",
        severity=SeverityLevel.MEDIUM,
        target_url="http://127.0.0.1:5000/auth/login",
        description="The endpoint returns HTTP 200 without a Content-Security-Policy header.",
        impact="Increases exposure to cross-site scripting (XSS) and data injection attacks.",
        evidence="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Login</html>",
        remediation="Configure a robust Content-Security-Policy header restricting script-src and object-src.",
        priority_rationale="Medium severity defense-in-depth weakness on sensitive authentication route.",
        reproduction_steps=[
            "1. Send GET request to /auth/login: curl -i -s http://127.0.0.1:5000/auth/login",
            "2. Inspect HTTP response headers and confirm absence of Content-Security-Policy.",
        ],
        minimal_response_evidence="HTTP/1.1 200 OK\r\nServer: MockServer\r\nContent-Type: text/html",
    )

    score_comp, missing_comp = research_mgr.calculate_evidence_completeness(complete_finding)
    assert score_comp >= 0.80
    assert len(missing_comp) == 0


def test_report_readiness_blocks_out_of_scope_and_missing_evidence():
    policy_mgr = ProgramPolicyManager()
    policy = create_sample_fictional_policy()
    policy_mgr.add_policy(policy)
    policy_mgr.verify_policy(policy.program_id, "Researcher", "Verified")
    policy_mgr.enable_policy(policy.program_id)

    research_mgr = ResearchManager(policy_mgr)

    # Finding on an EXCLUDED asset
    excluded_finding = VulnerabilityFinding(
        finding_id="F-EXCL-001",
        title="Admin Interface Exposed",
        category="Access Control",
        severity=SeverityLevel.HIGH,
        target_url="https://internal.acmefintech.example.com/admin",
        description="Internal admin console exposed.",
        impact="Unauthorized administrative access.",
        evidence="HTTP/1.1 200 OK\r\n\r\nWelcome Admin",
        remediation="Restrict access to internal VPN.",
        reproduction_steps=["1. Curl URL", "2. View dashboard"],
    )

    task = research_mgr.create_task_from_finding(
        program_id=policy.program_id,
        finding=excluded_finding,
    )

    is_ready, blockers = research_mgr.check_report_readiness(task.task_id)
    assert is_ready is False
    assert any("EXPLICITLY EXCLUDED" in b for b in blockers)

    # Attempting to set READY_FOR_REVIEW must be rejected
    with pytest.raises(ReportReadinessError):
        research_mgr.update_task_status(task.task_id, ResearchStatus.READY_FOR_REVIEW)


# ---------------------------------------------------------------------------
# 8. Research Status Transitions & Human Confirmation Requirements
# ---------------------------------------------------------------------------

def test_human_confirmation_required_for_submissions_and_outcomes():
    policy_mgr = ProgramPolicyManager()
    research_mgr = ResearchManager(policy_mgr)

    finding = VulnerabilityFinding(
        finding_id="F-STAT-001",
        title="Missing Referrer-Policy",
        category="Security Headers",
        severity=SeverityLevel.LOW,
        target_url="http://127.0.0.1:5000/info",
        description="Missing Referrer-Policy header.",
        impact="May leak referrer URL on outbound navigation.",
        evidence="HTTP/1.1 200 OK",
        remediation="Add Referrer-Policy: strict-origin-when-cross-origin",
        priority_rationale="Low severity hygiene issue.",
        reproduction_steps=["1. Curl http://127.0.0.1:5000/info", "2. Check headers"],
        minimal_response_evidence="HTTP/1.1 200 OK\r\nContent-Type: text/plain",
    )

    task = research_mgr.create_task_from_finding(
        program_id="local-lab-vdp",
        finding=finding,
    )
    assert task.status == ResearchStatus.NEW_OBSERVATION

    # Verification workflow
    research_mgr.update_task_status(task.task_id, ResearchStatus.NEEDS_VERIFICATION)
    research_mgr.update_task_status(task.task_id, ResearchStatus.VERIFIED_BY_RESEARCHER, notes="Independently verified in local lab.")

    # Duplicate flagging
    research_mgr.flag_suspected_duplicate(task.task_id, "Checking against prior submission F-OLD-001")
    assert task.status == ResearchStatus.DUPLICATE_SUSPECTED

    # Duplicate resolution
    research_mgr.resolve_duplicate_review(task.task_id, is_duplicate=False, notes="Distinct endpoint path")
    assert task.status == ResearchStatus.NEEDS_VERIFICATION

    # Ready for review
    task = research_mgr.update_task_status(task.task_id, ResearchStatus.READY_FOR_REVIEW)
    assert task.status == ResearchStatus.READY_FOR_REVIEW

    # CRITICAL: Attempting to mark SUBMITTED_BY_RESEARCHER without human confirmation MUST FAIL
    with pytest.raises(HumanConfirmationRequiredError):
        research_mgr.update_task_status(task.task_id, ResearchStatus.SUBMITTED_BY_RESEARCHER, user_confirmed=False)

    # Confirmed submission
    task = research_mgr.record_submission(
        task_id=task.task_id,
        submission_reference="ACME-SUB-2026-9041",
        submission_destination="https://bounty.acmefintech-security.example.com/submit",
        user_confirmed=True,
    )
    assert task.status == ResearchStatus.SUBMITTED_BY_RESEARCHER
    assert task.submission_reference == "ACME-SUB-2026-9041"
    assert task.submitted_date is not None

    # CRITICAL: Recording outcome without human confirmation MUST FAIL
    with pytest.raises(HumanConfirmationRequiredError):
        research_mgr.record_outcome(task.task_id, ResearchStatus.ACCEPTED, notes="Rewarded", user_confirmed=False)

    # Confirmed outcome
    task = research_mgr.record_outcome(
        task_id=task.task_id,
        outcome_status=ResearchStatus.ACCEPTED,
        notes="Validated and accepted by program security engineering team.",
        user_confirmed=True,
    )
    assert task.status == ResearchStatus.ACCEPTED
    assert task.outcome == "ACCEPTED"
    assert task.outcome_date is not None


# ---------------------------------------------------------------------------
# 9. Policy-Aware Report Generation and Human Export Sign-Off
# ---------------------------------------------------------------------------

def test_policy_report_generator_and_human_review_export(tmp_path):
    policy_mgr = ProgramPolicyManager()
    sample_policy = create_sample_fictional_policy()
    policy_mgr.add_policy(sample_policy)
    policy_mgr.verify_policy(sample_policy.program_id, "Senior AppSec Lead", "Policy authorized.")
    policy_mgr.enable_policy(sample_policy.program_id)

    research_mgr = ResearchManager(policy_mgr)

    finding = VulnerabilityFinding(
        finding_id="F-REP-001",
        title="IDOR in User Profile Resource Access",
        category="Access Control",
        severity=SeverityLevel.HIGH,
        target_url="https://app.acmefintech.example.com/api/v1/users/42",
        description="Unauthenticated retrieval of sensitive profile metadata across user accounts.",
        impact="Confidential customer personal data exposure.",
        evidence="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"user_id\": 42, \"email\": \"victim@company.com\", \"ssn\": \"123-45-6789\"}",
        remediation="Enforce server-side authorization checks verifying request context matches subject identity.",
        priority_rationale="High severity due to unauthenticated direct access to customer records.",
        confidence=ConfidenceLevel.CONFIRMED,
        confidence_explanation="Reproduced with distinct non-privileged synthetic session tokens.",
        finding_tier=FindingTier.INDEPENDENTLY_VERIFIED,
        reproduction_steps=[
            "1. Send GET request to https://app.acmefintech.example.com/api/v1/users/42 with researcher token.",
            "2. Observe full JSON user record returned without access denial.",
        ],
        minimal_request_evidence="GET /api/v1/users/42 HTTP/1.1\r\nHost: app.acmefintech.example.com\r\nAuthorization: Bearer test_token",
        minimal_response_evidence="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"user_id\": 42, \"name\": \"Jane Doe\"}",
        ai_triage={
            "summary": "Verified IDOR vulnerability leaking customer profiles.",
            "reproduction_verification": "Direct endpoint invocation with non-privileged identifier reproduces exposure.",
        },
    )

    task = research_mgr.create_task_from_finding(
        program_id=sample_policy.program_id,
        finding=finding,
    )
    research_mgr.update_task_status(task.task_id, ResearchStatus.VERIFIED_BY_RESEARCHER, notes="Reproduced")
    task = research_mgr.update_task_status(task.task_id, ResearchStatus.READY_FOR_REVIEW)
    assert task.report_ready is True

    generator = PolicyReportGenerator()

    # 1. Preview draft without confirmation has warning banner
    draft_md = generator.generate_markdown(task, finding, sample_policy, researcher_review_confirmed=False)
    assert "PRELIMINARY REPORT DRAFT - NOT YET APPROVED BY RESEARCHER" in draft_md
    assert "Preconditions" in draft_md
    assert "Minimal Reproduction Steps" in draft_md
    assert "Expected vs. Observed Behavior" in draft_md
    assert "Realistic Impact Assessment" in draft_md
    assert "Bounty & Reward Clarification" in draft_md
    assert "No bounty amounts or payouts are guaranteed" in draft_md
    assert "AI-Assisted Triage Context" in draft_md

    # 2. Export MUST FAIL without explicit researcher review confirmation
    out_file = tmp_path / "report.md"
    with pytest.raises(ResearcherReviewRequiredError):
        generator.export_report(
            task=task,
            finding=finding,
            policy=sample_policy,
            output_path=str(out_file),
            researcher_review_confirmed=False,
        )

    # 3. Export succeeds with researcher confirmation and redacts PII/secrets
    generator.export_report(
        task=task,
        finding=finding,
        policy=sample_policy,
        output_path=str(out_file),
        researcher_review_confirmed=True,
    )

    assert out_file.exists()
    content = out_file.read_text()
    assert "PRELIMINARY REPORT DRAFT" not in content
    assert "123-45-6789" not in content  # SSN must be redacted!
    assert "victim@company.com" not in content  # Email must be redacted!
    assert "[REDACTED_SSN]" in content or "[REDACTED_SECRET]" in content
    assert "Official Reporting Destination:" in content
