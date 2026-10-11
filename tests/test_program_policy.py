"""
Unit tests for Program Policy Manager.

Verifies:
- Recording official VDP and bug bounty policies.
- Fail-closed target validation (never assumes public targets are authorized).
- Mandatory manual scope verification before a policy can be enabled.
- Policy enablement and disablement lifecycle.
- Asset pattern and wildcard matching.
- JSON persistence.
"""

import os
import tempfile
import pytest

from appsec_assistant.models import ProgramPolicy
from appsec_assistant.policy import (
    ProgramPolicyManager,
    PolicyError,
    PolicyVerificationError,
    UnauthorizedTargetError,
)


def test_default_policy_loaded_and_verified():
    mgr = ProgramPolicyManager()
    policies = mgr.list_policies()
    assert len(policies) >= 1
    default_p = mgr.get_policy("local-lab-vdp")
    assert default_p is not None
    assert default_p.is_verified is True
    assert default_p.is_enabled is True
    assert "http://127.0.0.1:5000/*" in default_p.authorized_assets


def test_public_targets_not_assumed_authorized_fail_closed():
    mgr = ProgramPolicyManager()
    public_targets = [
        "https://google.com",
        "https://example.com/api",
        "https://target-company.com/v1/users",
        "http://api.production.internal",
    ]
    for target in public_targets:
        assert mgr.is_asset_authorized(target) is False
        with pytest.raises(UnauthorizedTargetError) as exc_info:
            mgr.validate_target_authorization(target)
        assert "NOT in the explicitly authorized scope" in str(exc_info.value)


def test_new_policy_requires_manual_verification_before_enablement():
    mgr = ProgramPolicyManager()
    new_policy = ProgramPolicy(
        program_id="acme-corp-vdp",
        program_name="Acme Corporation VDP",
        policy_url="https://acme.example/security",
        organization="Acme Corp",
        authorized_assets=["http://127.0.0.1:8000/*"],
        prohibited_methods=["DoS", "Automated Fuzzing"],
        rate_limit_rps=2.0,
        is_verified=False,
        is_enabled=False,
    )
    mgr.add_policy(new_policy)

    # Attempting to enable without manual verification must fail closed
    with pytest.raises(PolicyVerificationError) as exc_info:
        mgr.enable_policy("acme-corp-vdp")
    assert "manual scope verification is required first" in str(exc_info.value)
    assert mgr.get_policy("acme-corp-vdp").is_enabled is False

    # Attempting verification with empty name or notes must fail
    with pytest.raises(PolicyVerificationError):
        mgr.verify_policy("acme-corp-vdp", reviewer_name="", verification_notes="Scope verified")
    with pytest.raises(PolicyVerificationError):
        mgr.verify_policy("acme-corp-vdp", reviewer_name="Alice", verification_notes="   ")

    # Valid manual verification allows enablement
    mgr.verify_policy(
        "acme-corp-vdp",
        reviewer_name="Alice Security Researcher",
        verification_notes="Verified policy terms and authorized local training port 8000.",
    )
    policy_after_verify = mgr.get_policy("acme-corp-vdp")
    assert policy_after_verify.is_verified is True
    assert policy_after_verify.verified_by == "Alice Security Researcher"

    # Now enablement succeeds
    mgr.enable_policy("acme-corp-vdp")
    assert policy_after_verify.is_enabled is True
    assert mgr.is_asset_authorized("http://127.0.0.1:8000/api", program_id="acme-corp-vdp") is True


def test_policy_disablement_revokes_authorization():
    mgr = ProgramPolicyManager()
    assert mgr.is_asset_authorized("http://127.0.0.1:5000/test", program_id="local-lab-vdp") is True
    mgr.disable_policy("local-lab-vdp")
    assert mgr.is_asset_authorized("http://127.0.0.1:5000/test", program_id="local-lab-vdp") is False
    with pytest.raises(UnauthorizedTargetError):
        mgr.validate_target_authorization("http://127.0.0.1:5000/test", program_id="local-lab-vdp")


def test_policy_json_persistence():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_path = tf.name

    try:
        mgr1 = ProgramPolicyManager(storage_path=temp_path)
        new_policy = ProgramPolicy(
            program_id="test-persist",
            program_name="Test Persist VDP",
            policy_url="http://127.0.0.1:9000/terms",
            organization="Test Org",
            authorized_assets=["http://127.0.0.1:9000/*"],
            prohibited_methods=["Brute Force"],
            is_verified=True,
            verified_by="Auditor Bob",
            verification_notes="Verified",
            is_enabled=True,
        )
        mgr1.add_policy(new_policy)
        mgr1.save_to_file(temp_path)

        # Reload in fresh manager
        mgr2 = ProgramPolicyManager(storage_path=temp_path)
        loaded = mgr2.get_policy("test-persist")
        assert loaded is not None
        assert loaded.organization == "Test Org"
        assert loaded.is_verified is True
        assert loaded.verified_by == "Auditor Bob"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
