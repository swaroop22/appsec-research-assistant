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
    Sanitizes raw evidence text by redacting sensitive secrets, tokens, credentials, and PII.
    Prevents accidental leakage of active session tokens, passwords, or personal data in reports.
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
    # Redact private key blocks
    sanitized = re.sub(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]", sanitized)
    # Redact email addresses (PII)
    sanitized = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]", sanitized)
    # Redact phone numbers (PII)
    sanitized = re.sub(r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b", "[REDACTED_PHONE]", sanitized)
    # Redact Social Security Numbers (SSN)
    sanitized = re.sub(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", "[REDACTED_SSN]", sanitized)
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
class WorkflowMode(str, Enum):
    """
    Operational workflow modes ensuring safety and authorization boundaries.
    Mode A: OFFLINE - Analysis of saved HTTP responses/evidence, zero network calls.
    Mode B: LOCAL_LAB - Active tests strictly confined to loopback (127.0.0.1 / localhost).
    Mode C: AUTHORIZED_PROGRAM_PREPARATION - Review program scope, notes, finding mapping, report drafts; no active automated scans.
    """
    OFFLINE = "OFFLINE"
    LOCAL_LAB = "LOCAL_LAB"
    AUTHORIZED_PROGRAM_PREPARATION = "AUTHORIZED_PROGRAM_PREPARATION"


class ResearchStatus(str, Enum):
    """
    Granular workflow states for bug bounty research findings.
    Never auto-promotes to submitted or accepted without explicit human recording.
    """
    NEW_OBSERVATION = "NEW_OBSERVATION"
    NEEDS_VERIFICATION = "NEEDS_VERIFICATION"
    VERIFIED_BY_RESEARCHER = "VERIFIED_BY_RESEARCHER"
    DUPLICATE_SUSPECTED = "DUPLICATE_SUSPECTED"
    REPORT_DRAFT = "REPORT_DRAFT"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    SUBMITTED_BY_RESEARCHER = "SUBMITTED_BY_RESEARCHER"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    DUPLICATE = "DUPLICATE"
    RESOLVED = "RESOLVED"


@dataclass
class VulnerabilityFinding:
    """Represents a discovered security observation, heuristic indicator, or verified vulnerability."""
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
    ai_triage: Optional[Dict[str, Any]] = None
    affected_authorized_asset: Optional[str] = None
    http_method: str = "GET"
    http_status: Optional[int] = None
    minimal_request_evidence: str = ""
    minimal_response_evidence: str = ""
    research_task_id: Optional[str] = None

    def __post_init__(self):
        if not self.affected_urls and self.target_url:
            self.affected_urls = [self.target_url]
        if not self.affected_authorized_asset and self.target_url:
            self.affected_authorized_asset = self.target_url
        if not self.sanitized_evidence and self.evidence:
            self.sanitized_evidence = sanitize_evidence_text(self.evidence)
        if self.minimal_request_evidence:
            self.minimal_request_evidence = sanitize_evidence_text(self.minimal_request_evidence)
        if self.minimal_response_evidence:
            self.minimal_response_evidence = sanitize_evidence_text(self.minimal_response_evidence)
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
            "affected_authorized_asset": self.affected_authorized_asset,
            "reproduction_steps": self.reproduction_steps,
            "description": self.description,
            "impact": self.impact,
            "evidence": self.evidence,
            "sanitized_evidence": self.sanitized_evidence,
            "http_method": self.http_method,
            "http_status": self.http_status,
            "minimal_request_evidence": self.minimal_request_evidence,
            "minimal_response_evidence": self.minimal_response_evidence,
            "research_task_id": self.research_task_id,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "human_reviewed": self.human_reviewed,
            "reviewed_by": self.reviewed_by,
            "review_date": self.review_date,
            "review_notes": self.review_notes,
            "references": self.references,
            "timestamp": self.timestamp,
            "ai_triage": self.ai_triage,
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
    Never assumes a publicly accessible website is authorized for testing.
    """
    program_id: str
    program_name: str
    policy_url: str
    organization: str = ""
    company_name: str = ""
    authorized_assets: List[str] = field(default_factory=list)
    eligible_assets: List[str] = field(default_factory=list)
    excluded_assets: List[str] = field(default_factory=list)
    permitted_vulnerability_categories: List[str] = field(default_factory=list)
    prohibited_methods: List[str] = field(default_factory=list)
    rate_limit_rps: float = 2.0
    testing_restrictions: List[str] = field(default_factory=list)
    reporting_instructions: str = ""
    required_evidence: List[str] = field(default_factory=list)
    disclosure_requirements: str = ""
    safe_harbor_terms: str = ""
    is_verified: bool = False
    verified_by: Optional[str] = None
    verification_date: Optional[str] = None
    verification_notes: str = ""
    reviewer_notes: str = ""
    research_status: str = "ACTIVE_RESEARCH"
    policy_retrieval_date: Optional[str] = None
    policy_version: str = "1.0"
    max_policy_age_days: int = 90
    is_enabled: bool = False
    created_at: str = field(
        default_factory=lambda: datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )

    def __post_init__(self):
        # Synchronize organization and company_name
        if not self.company_name and self.organization:
            self.company_name = self.organization
        elif not self.organization and self.company_name:
            self.organization = self.company_name

        # Synchronize eligible_assets and authorized_assets
        if not self.eligible_assets and self.authorized_assets:
            self.eligible_assets = self.authorized_assets
        elif not self.authorized_assets and self.eligible_assets:
            self.authorized_assets = self.eligible_assets
        elif self.authorized_assets and self.eligible_assets:
            for a in self.authorized_assets:
                if a not in self.eligible_assets:
                    self.eligible_assets.append(a)
            self.authorized_assets = self.eligible_assets

        # Synchronize reviewer_notes and verification_notes
        if not self.reviewer_notes and self.verification_notes:
            self.reviewer_notes = self.verification_notes
        elif not self.verification_notes and self.reviewer_notes:
            self.verification_notes = self.reviewer_notes

        # Default policy_retrieval_date if verification_date is set
        if not self.policy_retrieval_date and self.verification_date:
            self.policy_retrieval_date = self.verification_date

    def is_stale(self, max_age_days: Optional[int] = None) -> bool:
        """
        Determines whether the verified policy has become stale/expired.
        Fails closed: if unverified or no valid verification date exists, returns True.
        """
        if not self.is_verified:
            return True

        date_str = self.verification_date or self.policy_retrieval_date
        if not date_str:
            return True

        limit_days = max_age_days if max_age_days is not None else self.max_policy_age_days

        # Attempt to parse date string
        parsed_dt = None
        cleaned_date = date_str.replace(" UTC", "").strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed_dt = datetime.datetime.strptime(cleaned_date, fmt)
                break
            except ValueError:
                continue

        if not parsed_dt:
            # Cannot safely establish freshness: fail closed
            return True

        age = (datetime.datetime.utcnow() - parsed_dt).total_seconds() / 86400.0
        return age > limit_days

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program_id": self.program_id,
            "program_name": self.program_name,
            "policy_url": self.policy_url,
            "organization": self.organization,
            "company_name": self.company_name,
            "authorized_assets": self.authorized_assets,
            "eligible_assets": self.eligible_assets,
            "excluded_assets": self.excluded_assets,
            "permitted_vulnerability_categories": self.permitted_vulnerability_categories,
            "prohibited_methods": self.prohibited_methods,
            "rate_limit_rps": self.rate_limit_rps,
            "testing_restrictions": self.testing_restrictions,
            "reporting_instructions": self.reporting_instructions,
            "required_evidence": self.required_evidence,
            "disclosure_requirements": self.disclosure_requirements,
            "safe_harbor_terms": self.safe_harbor_terms,
            "is_verified": self.is_verified,
            "verified_by": self.verified_by,
            "verification_date": self.verification_date,
            "verification_notes": self.verification_notes,
            "reviewer_notes": self.reviewer_notes,
            "research_status": self.research_status,
            "policy_retrieval_date": self.policy_retrieval_date,
            "policy_version": self.policy_version,
            "max_policy_age_days": self.max_policy_age_days,
            "is_enabled": self.is_enabled,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProgramPolicy":
        org = data.get("organization", "") or data.get("company_name", "")
        company = data.get("company_name", "") or org
        auth_assets = data.get("authorized_assets") or data.get("eligible_assets") or []
        elig_assets = data.get("eligible_assets") or auth_assets
        v_notes = data.get("verification_notes", "") or data.get("reviewer_notes", "")
        r_notes = data.get("reviewer_notes", "") or v_notes

        return cls(
            program_id=data["program_id"],
            program_name=data["program_name"],
            policy_url=data.get("policy_url", ""),
            organization=org,
            company_name=company,
            authorized_assets=list(auth_assets),
            eligible_assets=list(elig_assets),
            excluded_assets=data.get("excluded_assets", []),
            permitted_vulnerability_categories=data.get("permitted_vulnerability_categories", []),
            prohibited_methods=data.get("prohibited_methods", []),
            rate_limit_rps=float(data.get("rate_limit_rps", 2.0)),
            testing_restrictions=data.get("testing_restrictions", []),
            reporting_instructions=data.get("reporting_instructions", ""),
            required_evidence=data.get("required_evidence", []),
            disclosure_requirements=data.get("disclosure_requirements", ""),
            safe_harbor_terms=data.get("safe_harbor_terms", ""),
            is_verified=bool(data.get("is_verified", False)),
            verified_by=data.get("verified_by"),
            verification_date=data.get("verification_date"),
            verification_notes=v_notes,
            reviewer_notes=r_notes,
            research_status=data.get("research_status", "ACTIVE_RESEARCH"),
            policy_retrieval_date=data.get("policy_retrieval_date") or data.get("verification_date"),
            policy_version=data.get("policy_version", "1.0"),
            max_policy_age_days=int(data.get("max_policy_age_days", 90)),
            is_enabled=bool(data.get("is_enabled", False)),
            created_at=data.get("created_at", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")),
        )


@dataclass
class ResearchTask:
    """
    Research Task tracking an authorized bug bounty finding and report preparation lifecycle.
    """
    task_id: str
    program_id: str
    finding_id: str
    title: str
    affected_asset: str
    status: ResearchStatus = ResearchStatus.NEW_OBSERVATION
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    severity: SeverityLevel = SeverityLevel.LOW
    evidence_completeness_score: float = 0.0
    duplicate_suspected: bool = False
    duplicate_notes: str = ""
    next_manual_verification_step: str = ""
    report_ready: bool = False
    report_readiness_notes: str = ""
    researcher_notes: str = ""
    submitted_date: Optional[str] = None
    submission_reference: Optional[str] = None
    submission_destination: str = ""
    outcome: Optional[str] = None
    outcome_date: Optional[str] = None
    outcome_notes: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    updated_at: str = field(
        default_factory=lambda: datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "program_id": self.program_id,
            "finding_id": self.finding_id,
            "title": self.title,
            "affected_asset": self.affected_asset,
            "status": self.status.value if isinstance(self.status, ResearchStatus) else self.status,
            "confidence": self.confidence.value if isinstance(self.confidence, ConfidenceLevel) else self.confidence,
            "severity": self.severity.value if isinstance(self.severity, SeverityLevel) else self.severity,
            "evidence_completeness_score": self.evidence_completeness_score,
            "duplicate_suspected": self.duplicate_suspected,
            "duplicate_notes": self.duplicate_notes,
            "next_manual_verification_step": self.next_manual_verification_step,
            "report_ready": self.report_ready,
            "report_readiness_notes": self.report_readiness_notes,
            "researcher_notes": self.researcher_notes,
            "submitted_date": self.submitted_date,
            "submission_reference": self.submission_reference,
            "submission_destination": self.submission_destination,
            "outcome": self.outcome,
            "outcome_date": self.outcome_date,
            "outcome_notes": self.outcome_notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResearchTask":
        raw_status = data.get("status", ResearchStatus.NEW_OBSERVATION.value)
        try:
            status = ResearchStatus(raw_status)
        except Exception:
            status = ResearchStatus.NEW_OBSERVATION

        raw_conf = data.get("confidence", ConfidenceLevel.LOW.value)
        try:
            confidence = ConfidenceLevel(raw_conf)
        except Exception:
            confidence = ConfidenceLevel.LOW

        raw_sev = data.get("severity", SeverityLevel.LOW.value)
        try:
            severity = SeverityLevel(raw_sev)
        except Exception:
            severity = SeverityLevel.LOW

        return cls(
            task_id=data["task_id"],
            program_id=data["program_id"],
            finding_id=data["finding_id"],
            title=data.get("title", ""),
            affected_asset=data.get("affected_asset", ""),
            status=status,
            confidence=confidence,
            severity=severity,
            evidence_completeness_score=float(data.get("evidence_completeness_score", 0.0)),
            duplicate_suspected=bool(data.get("duplicate_suspected", False)),
            duplicate_notes=data.get("duplicate_notes", ""),
            next_manual_verification_step=data.get("next_manual_verification_step", ""),
            report_ready=bool(data.get("report_ready", False)),
            report_readiness_notes=data.get("report_readiness_notes", ""),
            researcher_notes=data.get("researcher_notes", ""),
            submitted_date=data.get("submitted_date"),
            submission_reference=data.get("submission_reference"),
            submission_destination=data.get("submission_destination", ""),
            outcome=data.get("outcome"),
            outcome_date=data.get("outcome_date"),
            outcome_notes=data.get("outcome_notes", ""),
            created_at=data.get("created_at", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")),
            updated_at=data.get("updated_at", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")),
        )

