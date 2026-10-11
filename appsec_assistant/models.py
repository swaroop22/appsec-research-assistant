"""
Data models for the security analysis assistant.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime


class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def color(self) -> str:
        colors = {
            "INFO": "blue",
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "bright_red",
            "CRITICAL": "bold red on white",
        }
        return colors.get(self.value, "white")

    @property
    def rank(self) -> int:
        ranks = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return ranks.get(self.value, 0)


class ConfidenceLevel(str, Enum):
    """
    Indicates certainty that an issue is genuine and reproducible,
    separate from its potential security severity.
    """
    CONFIRMED = "CONFIRMED"   # Verified through reproducible supporting evidence
    HIGH = "HIGH"             # Direct deterministic observation (e.g. missing header/cookie attribute)
    MEDIUM = "MEDIUM"         # Probable issue based on strong indicators
    LOW = "LOW"               # Low certainty, possible false positive
    HEURISTIC = "HEURISTIC"   # Pattern or naming heuristic; unverified without cross-context validation

    @property
    def rank(self) -> int:
        ranks = {
            "HEURISTIC": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CONFIRMED": 4,
        }
        return ranks.get(self.value, 0)


class FindingType(str, Enum):
    """Distinguishes confirmed vulnerabilities from heuristic indicators."""
    VERIFIED = "VERIFIED"     # Confirmed vulnerability with reproducible evidence
    HEURISTIC = "HEURISTIC"   # Architectural or pattern observation (e.g., IDOR indicator)


class FindingTier(str, Enum):
    """
    Explicitly classifies findings into four verification tiers:
    1. OBSERVATION: Contextual or informational discovery (e.g., banner, technology stack).
    2. HEURISTIC_INDICATOR: Pattern/naming clue suggesting potential weakness without authorization proof.
    3. SUSPECTED_VULNERABILITY: Missing defensive control or probable flaw requiring further verification.
    4. INDEPENDENTLY_VERIFIED: Confirmed vulnerability with reproducible proof of security impact.
    """
    OBSERVATION = "OBSERVATION"
    HEURISTIC_INDICATOR = "HEURISTIC_INDICATOR"
    SUSPECTED_VULNERABILITY = "SUSPECTED_VULNERABILITY"
    INDEPENDENTLY_VERIFIED = "INDEPENDENTLY_VERIFIED"

    @property
    def label(self) -> str:
        labels = {
            "OBSERVATION": "Observation",
            "HEURISTIC_INDICATOR": "Heuristic Indicator",
            "SUSPECTED_VULNERABILITY": "Suspected Vulnerability",
            "INDEPENDENTLY_VERIFIED": "Independently Verified",
        }
        return labels.get(self.value, self.value)

    @property
    def rank(self) -> int:
        ranks = {
            "OBSERVATION": 0,
            "HEURISTIC_INDICATOR": 1,
            "SUSPECTED_VULNERABILITY": 2,
            "INDEPENDENTLY_VERIFIED": 3,
        }
        return ranks.get(self.value, 0)


def sanitize_evidence_text(text: str) -> str:
    """
    Sanitizes raw evidence text by redacting sensitive secrets, tokens, and credentials.
    Prevents accidental leakage of active session tokens or passwords in reports.
    """
    if not text:
        return ""
    import re
    sanitized = text
    # Redact Bearer JWTs / tokens
    sanitized = re.sub(r"(Bearer\s+)[A-Za-z0-9_\-\.]{15,}", r"\1[REDACTED_TOKEN]", sanitized, flags=re.IGNORECASE)
    # Redact common cookie session values
    sanitized = re.sub(r"((?:session_id|session|token|auth_token|jwt)=)[A-Za-z0-9_\-\.]{6,}", r"\1[REDACTED_SESSION]", sanitized, flags=re.IGNORECASE)
    # Redact passwords in query or form bodies
    sanitized = re.sub(r"((?:password|passwd|secret|api_key)=)[^&\s]+", r"\1[REDACTED_SECRET]", sanitized, flags=re.IGNORECASE)
    # Redact Authorization header values
    sanitized = re.sub(r"(Authorization:\s*)[^\r\n]+", r"\1[REDACTED_CREDENTIALS]", sanitized, flags=re.IGNORECASE)
    return sanitized


@dataclass
class VulnerabilityFinding:
    """Represents a discovered security finding with evidence and remediation."""
    finding_id: str
    title: str
    category: str
    severity: SeverityLevel
    target_url: str
    description: str
    impact: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    priority_rationale: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    confidence_explanation: str = ""
    finding_type: FindingType = FindingType.VERIFIED
    finding_tier: FindingTier = FindingTier.SUSPECTED_VULNERABILITY
    affected_urls: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    sanitized_evidence: str = ""
    human_reviewed: bool = False
    reviewed_by: Optional[str] = None
    review_date: Optional[str] = None
    review_notes: str = ""
    references: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )

    def __post_init__(self):
        if not self.affected_urls and self.target_url:
            self.affected_urls = [self.target_url]
        if not self.sanitized_evidence and self.evidence:
            self.sanitized_evidence = sanitize_evidence_text(self.evidence)
        if not self.reproduction_steps:
            self.reproduction_steps = [
                f"1. Send an HTTP request to the target: curl -i -s '{self.target_url}'",
                f"2. Inspect the returned HTTP response headers and body content.",
                f"3. Verify whether the expected security control or header is absent or misconfigured.",
            ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "priority_rationale": self.priority_rationale,
            "confidence": self.confidence.value,
            "confidence_explanation": self.confidence_explanation,
            "finding_type": self.finding_type.value,
            "finding_tier": self.finding_tier.value,
            "target_url": self.target_url,
            "affected_urls": self.affected_urls,
            "reproduction_steps": self.reproduction_steps,
            "description": self.description,
            "impact": self.impact,
            "evidence": self.evidence,
            "sanitized_evidence": self.sanitized_evidence,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "human_reviewed": self.human_reviewed,
            "reviewed_by": self.reviewed_by,
            "review_date": self.review_date,
            "review_notes": self.review_notes,
            "references": self.references,
            "timestamp": self.timestamp,
        }


@dataclass
class HTTPTransaction:
    """Represents an captured HTTP request/response transaction for auditing."""
    url: str
    method: str
    request_headers: Dict[str, str]
    status_code: int
    response_headers: Dict[str, str]
    response_body: str
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )


@dataclass
class TargetConfig:
    """Configuration for an authorized local training target."""
    base_url: str
    allowed_hosts: List[str] = field(
        default_factory=lambda: ["localhost", "127.0.0.1", "::1"]
    )
    rate_limit_delay: float = 0.2  # 200ms delay between requests to prevent aggressive traffic
    timeout: float = 5.0
    user_agent: str = "AppSec-Research-Assistant/1.0 (Educational/Defensive-Audit)"


@dataclass
class ProgramPolicy:
    """
    Represents an official Vulnerability Disclosure Program (VDP) or Bug Bounty policy.
    Requires explicit manual scope verification by an authorized security researcher before enablement.
    """
    program_id: str
    program_name: str
    policy_url: str
    organization: str
    authorized_assets: List[str]  # Glob or URL patterns explicitly in scope
    prohibited_methods: List[str] # Prohibited techniques (DoS, automated brute force, social engineering)
    rate_limit_rps: float = 2.0   # Enforced maximum requests per second
    reporting_instructions: str = ""
    safe_harbor_terms: str = ""
    is_verified: bool = False     # Manual verification flag
    verified_by: Optional[str] = None
    verification_date: Optional[str] = None
    verification_notes: str = ""
    is_enabled: bool = False      # Must be verified before enabling
    created_at: str = field(
        default_factory=lambda: datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program_id": self.program_id,
            "program_name": self.program_name,
            "policy_url": self.policy_url,
            "organization": self.organization,
            "authorized_assets": self.authorized_assets,
            "prohibited_methods": self.prohibited_methods,
            "rate_limit_rps": self.rate_limit_rps,
            "reporting_instructions": self.reporting_instructions,
            "safe_harbor_terms": self.safe_harbor_terms,
            "is_verified": self.is_verified,
            "verified_by": self.verified_by,
            "verification_date": self.verification_date,
            "verification_notes": self.verification_notes,
            "is_enabled": self.is_enabled,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProgramPolicy":
        return cls(
            program_id=data["program_id"],
            program_name=data["program_name"],
            policy_url=data.get("policy_url", ""),
            organization=data.get("organization", ""),
            authorized_assets=data.get("authorized_assets", []),
            prohibited_methods=data.get("prohibited_methods", []),
            rate_limit_rps=float(data.get("rate_limit_rps", 2.0)),
            reporting_instructions=data.get("reporting_instructions", ""),
            safe_harbor_terms=data.get("safe_harbor_terms", ""),
            is_verified=bool(data.get("is_verified", False)),
            verified_by=data.get("verified_by"),
            verification_date=data.get("verification_date"),
            verification_notes=data.get("verification_notes", ""),
            is_enabled=bool(data.get("is_enabled", False)),
            created_at=data.get("created_at", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")),
        )
