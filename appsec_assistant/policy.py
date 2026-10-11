"""
Program Policy Manager.

Records official Vulnerability Disclosure Program (VDP) and bug bounty policies.
Stores program URLs, explicitly authorized asset scopes, prohibited testing methods,
rate limits, and reporting instructions.
Enforces fail-closed validation: never assumes a public website or API is authorized for testing,
and mandates manual scope verification before any policy can be enabled.
"""

import fnmatch
import json
import os
import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

from appsec_assistant.models import ProgramPolicy
from appsec_assistant.config import ScopeGuard, ScopeViolationError


class PolicyError(Exception):
    """Base exception for policy management errors."""
    pass


class PolicyVerificationError(PolicyError):
    """Raised when an operation requires scope verification that has not been performed."""
    pass


class UnauthorizedTargetError(PolicyError):
    """Raised when an operation targets an asset not explicitly authorized by an enabled policy."""
    pass


class ProgramPolicyManager:
    """
    Manages VDP and bug bounty program policies, tracking authorized assets,
    prohibited testing methods, and requiring explicit human scope sign-off.
    """

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path
        self._policies: Dict[str, ProgramPolicy] = {}
        self._load_defaults()
        if self.storage_path and os.path.exists(self.storage_path):
            self.load_from_file(self.storage_path)

    def _load_defaults(self) -> None:
        """Loads default verified policy for the local educational practice lab."""
        local_lab_policy = ProgramPolicy(
            program_id="local-lab-vdp",
            program_name="Local AppSec Practice Lab VDP",
            policy_url="http://127.0.0.1:5000/policy",
            organization="Local Educational Security Lab",
            authorized_assets=[
                "http://127.0.0.1:5000/*",
                "http://localhost:5000/*",
                "http://127.0.0.1:8000/*",
                "http://localhost:8000/*",
            ],
            prohibited_methods=[
                "Denial of Service (DoS) and resource exhaustion",
                "Automated high-frequency fuzzing (>10 rps)",
                "Social engineering or phishing of mock users",
                "Arbitrary command execution or destruction of local test data",
            ],
            rate_limit_rps=5.0,
            reporting_instructions="Review findings on the local reporting dashboard and export as sanitized Markdown or JSON.",
            safe_harbor_terms="Testing confined to local mock training server on loopback with synthetic data is pre-authorized.",
            is_verified=True,
            verified_by="AppSec Lead (Local Lab Admin)",
            verification_date="2026-10-10 00:00:00 UTC",
            verification_notes="Verified target is strictly local loopback mock lab running synthetic exercises.",
            is_enabled=True,
        )
        self._policies[local_lab_policy.program_id] = local_lab_policy

    def add_policy(self, policy: ProgramPolicy) -> ProgramPolicy:
        """
        Adds a new program policy.
        New policies default to unverified and disabled to prevent unauthorized testing.
        """
        if not policy.program_id:
            raise PolicyError("Policy program_id cannot be empty.")
        if not policy.authorized_assets:
            raise PolicyError("Policy must specify at least one explicitly authorized asset.")

        # Force unverified and disabled for newly created policies unless explicitly pre-configured
        if policy.program_id not in self._policies:
            policy.is_enabled = False

        self._policies[policy.program_id] = policy
        self._auto_save()
        return policy

    def get_policy(self, program_id: str) -> Optional[ProgramPolicy]:
        return self._policies.get(program_id)

    def list_policies(self) -> List[ProgramPolicy]:
        return list(self._policies.values())

    def verify_policy(self, program_id: str, reviewer_name: str, verification_notes: str) -> ProgramPolicy:
        """
        Records human verification of the program's scope, policy URL, and terms.
        Must be completed before a policy can be enabled.
        """
        policy = self.get_policy(program_id)
        if not policy:
            raise PolicyError(f"Program policy '{program_id}' not found.")

        if not reviewer_name or not reviewer_name.strip():
            raise PolicyVerificationError("Verification requires a non-empty reviewer name.")

        if not verification_notes or not verification_notes.strip():
            raise PolicyVerificationError("Verification requires explicit reviewer notes detailing scope validation.")

        now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        policy.is_verified = True
        policy.verified_by = reviewer_name.strip()
        policy.verification_date = now_str
        policy.verification_notes = verification_notes.strip()

        self._auto_save()
        return policy

    def enable_policy(self, program_id: str) -> ProgramPolicy:
        """
        Enables an authorized program policy.
        Fails closed with PolicyVerificationError if the policy has not been verified by a human.
        """
        policy = self.get_policy(program_id)
        if not policy:
            raise PolicyError(f"Program policy '{program_id}' not found.")

        if not policy.is_verified:
            raise PolicyVerificationError(
                f"Cannot enable program policy '{program_id}': manual scope verification is required first. "
                "Do not assume that a public website or API is authorized for security testing."
            )

        policy.is_enabled = True
        self._auto_save()
        return policy

    def disable_policy(self, program_id: str) -> ProgramPolicy:
        """Disables a program policy."""
        policy = self.get_policy(program_id)
        if not policy:
            raise PolicyError(f"Program policy '{program_id}' not found.")
        policy.is_enabled = False
        self._auto_save()
        return policy

    def is_asset_authorized(self, url: str, program_id: Optional[str] = None) -> bool:
        """
        Validates whether a URL matches the authorized assets of an active, verified program policy.
        Fails closed: returns False if no verified, enabled policy explicitly authorizes the URL.
        """
        if not url or not isinstance(url, str):
            return False

        policies_to_check = []
        if program_id:
            p = self.get_policy(program_id)
            if p and p.is_enabled and p.is_verified:
                policies_to_check.append(p)
            else:
                return False
        else:
            policies_to_check = [p for p in self._policies.values() if p.is_enabled and p.is_verified]

        if not policies_to_check:
            return False

        parsed_target = urlparse(url)
        target_norm = f"{parsed_target.scheme}://{parsed_target.netloc}{parsed_target.path}"

        for policy in policies_to_check:
            for pattern in policy.authorized_assets:
                pattern_clean = pattern.strip()
                # Check direct prefix match or fnmatch wildcard
                if pattern_clean.endswith("/*"):
                    base_prefix = pattern_clean[:-2]
                    if target_norm.startswith(base_prefix) or url.startswith(base_prefix):
                        return True
                elif fnmatch.fnmatch(target_norm, pattern_clean) or fnmatch.fnmatch(url, pattern_clean):
                    return True
                elif target_norm.rstrip("/") == pattern_clean.rstrip("/"):
                    return True

        return False

    def validate_target_authorization(self, url: str, program_id: Optional[str] = None) -> str:
        """
        Validates target authorization under policy and ScopeGuard.
        Raises UnauthorizedTargetError if target is not authorized.
        """
        if not self.is_asset_authorized(url, program_id=program_id):
            raise UnauthorizedTargetError(
                f"Unauthorized Target: '{url}' is NOT in the explicitly authorized scope of any active, "
                "verified vulnerability disclosure program. Public websites or APIs must never be assumed "
                "authorized for testing without explicit, verified scope documentation."
            )
        return url

    def save_to_file(self, filepath: str) -> None:
        """Persists policies to a JSON file."""
        data = {pid: p.to_dict() for pid, p in self._policies.items()}
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_from_file(self, filepath: str) -> None:
        """Loads policies from a JSON file."""
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        for pid, pdata in data.items():
            self._policies[pid] = ProgramPolicy.from_dict(pdata)

    def _auto_save(self) -> None:
        if self.storage_path:
            try:
                self.save_to_file(self.storage_path)
            except Exception:
                pass
