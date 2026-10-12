"""
Program Policy Manager.

Records official Vulnerability Disclosure Program (VDP) and bug bounty policies.
Stores program URLs, explicitly authorized asset scopes, explicitly excluded assets,
prohibited testing methods, rate limits, testing restrictions, and reporting instructions.
Enforces fail-closed validation: never assumes a public website or API is authorized for testing,
and mandates manual scope verification before any policy can be enabled.
Detects stale or expired policies, rejects ambiguous or contradictory scopes, and treats scope
modifications as requiring renewed human review.
"""

import fnmatch
import json
import os
import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from appsec_assistant.models import ProgramPolicy


class PolicyError(Exception):
    """Base exception for policy management errors."""
    pass


class PolicyVerificationError(PolicyError):
    """Raised when an operation requires scope verification that has not been performed."""
    pass


class PolicyStaleError(PolicyVerificationError):
    """Raised when an operation attempts to use an expired or stale verified policy."""
    pass


class ScopeIntegrityError(PolicyError):
    """Raised when a policy contains ambiguous, invalid, or contradictory scope definitions."""
    pass


class UnauthorizedTargetError(PolicyError):
    """Raised when an operation targets an asset not explicitly authorized by an enabled policy."""
    pass


def _match_asset_pattern(url: str, pattern: str) -> bool:
    """
    Evaluates whether a target URL matches an asset pattern.
    Supports exact matches, path wildcards (/*), domain wildcards (*.domain.com),
    and scheme-host patterns.
    """
    if not url or not pattern:
        return False

    url_clean = url.strip()
    pattern_clean = pattern.strip()

    parsed_target = urlparse(url_clean)
    target_norm = f"{parsed_target.scheme}://{parsed_target.netloc}{parsed_target.path}"

    # If pattern has scheme: e.g. https://example.com/*
    if pattern_clean.startswith("http://") or pattern_clean.startswith("https://"):
        parsed_pat = urlparse(pattern_clean)
        if parsed_target.scheme != parsed_pat.scheme:
            return False

        # Host matching (supports *.domain.com)
        pat_host = parsed_pat.netloc
        tar_host = parsed_target.netloc
        if pat_host.startswith("*."):
            domain_suffix = pat_host[2:]
            if not (tar_host == domain_suffix or tar_host.endswith("." + domain_suffix)):
                return False
        elif pat_host != tar_host:
            if not fnmatch.fnmatch(tar_host, pat_host):
                return False

        # Path matching
        pat_path = parsed_pat.path
        if pat_path.endswith("/*"):
            base_prefix = pat_path[:-2]
            return parsed_target.path.startswith(base_prefix) or parsed_target.path == base_prefix.rstrip("/")
        elif pat_path:
            return fnmatch.fnmatch(parsed_target.path, pat_path) or parsed_target.path.rstrip("/") == pat_path.rstrip("/")
        return True

    # Domain-only pattern without scheme: e.g. *.example.com or app.example.com
    tar_host = parsed_target.netloc.split(":")[0]
    pat_host = pattern_clean.split("/")[0].split(":")[0]
    if pat_host.startswith("*."):
        suffix = pat_host[2:]
        if tar_host == suffix or tar_host.endswith("." + suffix):
            return True
    elif fnmatch.fnmatch(tar_host, pat_host):
        return True

    # Fallback to direct fnmatch
    if fnmatch.fnmatch(target_norm, pattern_clean) or fnmatch.fnmatch(url_clean, pattern_clean):
        return True

    return False


class ProgramPolicyManager:
    """
    Manages VDP and bug bounty program policies, tracking authorized assets,
    excluded assets, prohibited testing methods, and requiring explicit human scope sign-off.
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
            company_name="Local Educational Security Lab",
            policy_url="http://127.0.0.1:5000/policy",
            organization="Local Educational Security Lab",
            authorized_assets=[
                "http://127.0.0.1:5000/*",
                "http://localhost:5000/*",
                "http://127.0.0.1:8000/*",
                "http://localhost:8000/*",
            ],
            eligible_assets=[
                "http://127.0.0.1:5000/*",
                "http://localhost:5000/*",
                "http://127.0.0.1:8000/*",
                "http://localhost:8000/*",
            ],
            excluded_assets=[],
            permitted_vulnerability_categories=[
                "Broken Access Control",
                "IDOR Heuristics",
                "Security Headers",
                "Insecure Cookies",
                "Input Validation Reflections",
            ],
            prohibited_methods=[
                "Denial of Service (DoS) and resource exhaustion",
                "Automated high-frequency fuzzing (>10 rps)",
                "Social engineering or phishing of mock users",
                "Arbitrary command execution or destruction of local test data",
            ],
            rate_limit_rps=5.0,
            reporting_instructions="Review findings on the local reporting dashboard and export as sanitized Markdown or JSON.",
            required_evidence=[
                "Affected local lab endpoint",
                "Reproduction steps",
                "Captured HTTP headers and body snippet",
            ],
            safe_harbor_terms="Testing confined to local mock training server on loopback with synthetic data is pre-authorized.",
            is_verified=True,
            verified_by="AppSec Lead (Local Lab Admin)",
            verification_date=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            verification_notes="Verified target is strictly local loopback mock lab running synthetic exercises.",
            policy_retrieval_date=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            is_enabled=True,
        )
        self._policies[local_lab_policy.program_id] = local_lab_policy

    def validate_scope_integrity(self, policy: ProgramPolicy) -> List[str]:
        """
        Validates the scope integrity of a policy.
        Fails closed on ambiguous wildcards, invalid schemes, and contradictory definitions.
        Raises ScopeIntegrityError if violations exist.
        """
        violations: List[str] = []

        if not policy.program_id or not policy.program_id.strip():
            violations.append("Program ID cannot be empty.")

        if not policy.policy_url or not policy.policy_url.strip():
            violations.append("Official policy URL cannot be empty.")
        else:
            parsed_url = urlparse(policy.policy_url)
            if parsed_url.scheme not in ("http", "https"):
                violations.append(f"Policy URL scheme '{parsed_url.scheme}' is invalid. Must be http or https.")

        all_eligible = policy.eligible_assets or policy.authorized_assets
        if not all_eligible:
            violations.append("Policy must specify at least one explicitly authorized asset.")

        # Check for overly broad or ambiguous wildcards
        ambiguous_wildcards = {"*", "*.*", "http://*", "https://*", "*/*", "http://*/*", "https://*/*"}
        for pat in all_eligible:
            clean_pat = pat.strip()
            if clean_pat in ambiguous_wildcards:
                violations.append(f"Ambiguous scope pattern '{clean_pat}' is too broad and cannot be authorized.")
            parsed_pat = urlparse(clean_pat)
            if parsed_pat.scheme and parsed_pat.scheme not in ("http", "https"):
                violations.append(f"Asset pattern '{clean_pat}' uses unauthorized scheme '{parsed_pat.scheme}'.")

        # Contradiction check: asset cannot be both eligible and excluded
        for elig in all_eligible:
            elig_clean = elig.strip().rstrip("/")
            for excl in policy.excluded_assets:
                excl_clean = excl.strip().rstrip("/")
                if elig_clean == excl_clean:
                    violations.append(
                        f"Contradictory scope definition: asset '{elig_clean}' is listed in both eligible and excluded assets."
                    )

        if violations:
            raise ScopeIntegrityError("; ".join(violations))

        return violations

    def add_policy(self, policy: ProgramPolicy) -> ProgramPolicy:
        """
        Adds a new program policy after validating scope integrity.
        New policies default to unverified and disabled to prevent unauthorized testing.
        """
        self.validate_scope_integrity(policy)

        # Force unverified and disabled for newly created policies unless explicitly pre-configured
        if policy.program_id not in self._policies:
            policy.is_enabled = False

        self._policies[policy.program_id] = policy
        self._auto_save()
        return policy

    def update_policy(self, policy: ProgramPolicy) -> ProgramPolicy:
        """
        Updates an existing policy.
        If scope boundaries (assets, exclusions, prohibitions) changed,
        verification is automatically revoked to mandate renewed human review.
        """
        existing = self.get_policy(policy.program_id)
        if not existing:
            raise PolicyError(f"Program policy '{policy.program_id}' not found.")

        self.validate_scope_integrity(policy)

        scope_changed = (
            set(policy.eligible_assets) != set(existing.eligible_assets)
            or set(policy.excluded_assets) != set(existing.excluded_assets)
            or set(policy.prohibited_methods) != set(existing.prohibited_methods)
            or policy.rate_limit_rps != existing.rate_limit_rps
        )

        if scope_changed:
            # Mandate renewed review: revoke verification and disable policy
            policy.is_verified = False
            policy.is_enabled = False
            policy.verified_by = None
            policy.verification_date = None
            policy.verification_notes = f"[SCOPE MODIFIED - REVIEW REQUIRED] Previous: {existing.verification_notes}"

        self._policies[policy.program_id] = policy
        self._auto_save()
        return policy

    def get_policy(self, program_id: str) -> Optional[ProgramPolicy]:
        return self._policies.get(program_id)

    def list_policies(self) -> List[ProgramPolicy]:
        return list(self._policies.values())

    def verify_policy(
        self,
        program_id: str,
        reviewer_name: str,
        verification_notes: str,
        policy_version: Optional[str] = None,
        verification_date: Optional[str] = None,
    ) -> ProgramPolicy:
        """
        Records human verification of the program's scope, policy URL, and terms.
        Must be completed before a policy can be enabled.
        """
        policy = self.get_policy(program_id)
        if not policy:
            raise PolicyError(f"Program policy '{program_id}' not found.")

        # Re-check scope integrity before certifying
        self.validate_scope_integrity(policy)

        if not reviewer_name or not reviewer_name.strip():
            raise PolicyVerificationError("Verification requires a non-empty reviewer name.")

        if not verification_notes or not verification_notes.strip():
            raise PolicyVerificationError("Verification requires explicit reviewer notes detailing scope validation.")

        now_str = verification_date or datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        policy.is_verified = True
        policy.verified_by = reviewer_name.strip()
        policy.verification_date = now_str
        policy.policy_retrieval_date = now_str
        policy.verification_notes = verification_notes.strip()
        policy.reviewer_notes = verification_notes.strip()
        if policy_version:
            policy.policy_version = policy_version

        self._auto_save()
        return policy

    def enable_policy(self, program_id: str) -> ProgramPolicy:
        """
        Enables an authorized program policy.
        Fails closed with PolicyVerificationError if the policy has not been verified by a human,
        or PolicyStaleError if the verification is expired.
        """
        policy = self.get_policy(program_id)
        if not policy:
            raise PolicyError(f"Program policy '{program_id}' not found.")

        if not policy.is_verified:
            raise PolicyVerificationError(
                f"Cannot enable program policy '{program_id}': manual scope verification is required first. "
                "Do not assume that a public website or API is authorized for security testing."
            )

        if policy.is_stale():
            raise PolicyStaleError(
                f"Cannot enable program policy '{program_id}': scope verification is stale or expired "
                f"(max freshness: {policy.max_policy_age_days} days). Renewed manual policy review is required."
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
        Validates whether a URL matches the authorized assets of an active, verified, non-stale program policy.
        Fails closed:
        1. Returns False if no verified, enabled, non-stale policy authorizes the asset.
        2. Returns False immediately if the URL matches ANY explicitly excluded asset pattern.
        """
        if not url or not isinstance(url, str):
            return False

        policies_to_check: List[ProgramPolicy] = []
        if program_id:
            p = self.get_policy(program_id)
            if p and p.is_enabled and p.is_verified and not p.is_stale():
                policies_to_check.append(p)
            else:
                return False
        else:
            policies_to_check = [
                p for p in self._policies.values()
                if p.is_enabled and p.is_verified and not p.is_stale()
            ]

        if not policies_to_check:
            return False

        for policy in policies_to_check:
            # 1. Exclusion check takes absolute priority: fail closed
            for excl_pattern in policy.excluded_assets:
                if _match_asset_pattern(url, excl_pattern):
                    return False

            # 2. Inclusion check
            all_eligible = list(policy.eligible_assets) + [a for a in policy.authorized_assets if a not in policy.eligible_assets]
            for elig_pattern in all_eligible:
                if _match_asset_pattern(url, elig_pattern):
                    return True

        return False

    def validate_target_authorization(self, url: str, program_id: Optional[str] = None) -> str:
        """
        Validates target authorization under policy rules.
        Raises UnauthorizedTargetError if target is excluded or not authorized.
        """
        # Specific check for exclusion diagnosis
        if program_id:
            policy = self.get_policy(program_id)
            if policy:
                for excl in policy.excluded_assets:
                    if _match_asset_pattern(url, excl):
                        raise UnauthorizedTargetError(
                            f"Target '{url}' is EXPLICITLY EXCLUDED by policy '{program_id}' (rule: '{excl}'). "
                            "Testing against explicitly excluded assets is strictly prohibited."
                        )
                if policy.is_stale():
                    raise PolicyStaleError(
                        f"Policy '{program_id}' verification has expired. Renewed review is required."
                    )

        if not self.is_asset_authorized(url, program_id=program_id):
            raise UnauthorizedTargetError(
                f"Unauthorized Target: '{url}' is NOT in the explicitly authorized scope of any active, "
                "verified vulnerability disclosure program. Public websites or APIs must never be assumed "
                "authorized for testing without explicit, verified scope documentation."
            )
        return url

    def import_policy_from_dict(self, data: Dict[str, Any]) -> ProgramPolicy:
        """Imports and validates a program policy from dictionary data."""
        policy = ProgramPolicy.from_dict(data)
        return self.add_policy(policy)

    def import_policy_from_json(self, json_str: str) -> ProgramPolicy:
        """Imports and validates a program policy from JSON string."""
        data = json.loads(json_str)
        return self.import_policy_from_dict(data)

    def import_policy_from_file(self, filepath: str) -> ProgramPolicy:
        """Imports and validates a program policy from a JSON file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return self.import_policy_from_dict(data)

    def export_policy_to_json(self, program_id: str, indent: int = 2) -> str:
        """Exports a policy definition to JSON string."""
        policy = self.get_policy(program_id)
        if not policy:
            raise PolicyError(f"Program policy '{program_id}' not found.")
        return json.dumps(policy.to_dict(), indent=indent)

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


def create_sample_fictional_policy() -> ProgramPolicy:
    """
    Creates a realistic fictional bug bounty program policy for testing and demonstration.
    Uses completely fictional domains under .example.com to avoid real-world references.
    """
    return ProgramPolicy(
        program_id="acme-fintech-bounty",
        program_name="Acme FinTech Public Bug Bounty Program",
        company_name="Acme Financial Services Inc.",
        policy_url="https://bounty.acmefintech-security.example.com/policy",
        organization="Acme Financial Services Inc.",
        eligible_assets=[
            "https://app.acmefintech.example.com/*",
            "https://api.acmefintech.example.com/v1/*",
            "https://auth.acmefintech.example.com/*",
        ],
        authorized_assets=[
            "https://app.acmefintech.example.com/*",
            "https://api.acmefintech.example.com/v1/*",
            "https://auth.acmefintech.example.com/*",
        ],
        excluded_assets=[
            "https://internal.acmefintech.example.com/*",
            "https://admin.acmefintech.example.com/internal-billing/*",
            "https://*.corp.acmefintech.example.com/*",
        ],
        permitted_vulnerability_categories=[
            "OWASP Top 10 (Access Control, Injection, SSRF, Misconfiguration)",
            "Authentication and Session Management Flaws",
            "Business Logic Flaws in Payment Checkout",
            "Missing Security Headers and Weak Cookie Attributes",
        ],
        prohibited_methods=[
            "Denial of Service (DoS/DDoS) and resource exhaustion attacks",
            "Social engineering, phishing, or vishing of employees/customers",
            "Physical attacks against Acme facilities or data centers",
            "Automated scanning tools with request rates exceeding 2 requests per second",
            "Accessing or modifying non-researcher customer data",
        ],
        rate_limit_rps=2.0,
        testing_restrictions=[
            "Testing must be conducted using accounts created with the +bounty research tag.",
            "Zero destructive testing; do not execute DELETE or account wipe actions.",
            "All testing traffic must originate with User-Agent header containing 'AcmeResearcher-'.",
        ],
        reporting_instructions="Submit reports via https://bounty.acmefintech-security.example.com/submit or email security-reports@acmefintech.example.com with PGP encryption.",
        required_evidence=[
            "Target URL and affected endpoint",
            "Minimal HTTP request and response evidence",
            "Step-by-step reproduction instructions",
            "Realistic business impact assessment",
        ],
        disclosure_requirements="Coordinated disclosure: 90 days after acknowledgment before public release. Do not disclose details publicly prior to Acme approval.",
        safe_harbor_terms="Acme will not initiate legal action against researchers acting in good faith compliance with this policy.",
        research_status="ACTIVE_RESEARCH",
        policy_version="2.4",
        policy_retrieval_date="2026-10-01 00:00:00 UTC",
        is_verified=False,
        is_enabled=False,
    )
