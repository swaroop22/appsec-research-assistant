"""
Data models for the AI-assisted triage layer.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

from appsec_assistant.models import (
    SeverityLevel,
    ConfidenceLevel,
    FindingTier,
    VulnerabilityFinding,
)


class PriorityLevel(str, Enum):
    """
    Indicates recommended priority for manual review and investigation.
    Distinct from Severity (potential impact) and Confidence (evidence certainty).
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

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

    @property
    def badge_color(self) -> str:
        colors = {
            "CRITICAL": "#991B1B",  # Deep Red
            "HIGH": "#DC2626",      # Red
            "MEDIUM": "#D97706",    # Amber
            "LOW": "#16A34A",       # Green
            "INFO": "#2563EB",      # Blue
        }
        return colors.get(self.value, "#64748B")


@dataclass
class AITriageResult:
    """
    Structured, evidence-grounded AI triage outcome for a security finding.
    Source of truth remains the deterministic finding.
    """
    finding_id: str
    plain_english_explanation: str
    observed_evidence: str
    why_evidence_matters: str
    realistic_potential_impact: str
    alternative_explanations: str
    missing_information: str
    recommended_next_steps: List[str]
    suggested_remediation: str
    confidence_rationale: str
    severity_rationale: str
    recommended_priority: PriorityLevel
    recommended_priority_rationale: str
    finding_tier: FindingTier
    potential_false_positive: bool = False
    false_positive_explanation: str = ""
    needs_manual_verification: bool = True
    evidence_references: List[str] = field(default_factory=list)
    provider_name: str = "mock"
    analyzed_at: str = field(
        default_factory=lambda: datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "plain_english_explanation": self.plain_english_explanation,
            "observed_evidence": self.observed_evidence,
            "why_evidence_matters": self.why_evidence_matters,
            "realistic_potential_impact": self.realistic_potential_impact,
            "alternative_explanations": self.alternative_explanations,
            "missing_information": self.missing_information,
            "recommended_next_steps": self.recommended_next_steps,
            "suggested_remediation": self.suggested_remediation,
            "confidence_rationale": self.confidence_rationale,
            "severity_rationale": self.severity_rationale,
            "recommended_priority": self.recommended_priority.value,
            "recommended_priority_rationale": self.recommended_priority_rationale,
            "finding_tier": self.finding_tier.value,
            "potential_false_positive": self.potential_false_positive,
            "false_positive_explanation": self.false_positive_explanation,
            "needs_manual_verification": self.needs_manual_verification,
            "evidence_references": self.evidence_references,
            "provider_name": self.provider_name,
            "analyzed_at": self.analyzed_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AITriageResult":
        tier_val = data.get("finding_tier", FindingTier.SUSPECTED_VULNERABILITY.value)
        try:
            tier = FindingTier(tier_val)
        except (ValueError, KeyError):
            tier = FindingTier.SUSPECTED_VULNERABILITY

        prio_val = data.get("recommended_priority", PriorityLevel.MEDIUM.value)
        try:
            prio = PriorityLevel(prio_val)
        except (ValueError, KeyError):
            prio = PriorityLevel.MEDIUM

        return cls(
            finding_id=data["finding_id"],
            plain_english_explanation=data.get("plain_english_explanation", ""),
            observed_evidence=data.get("observed_evidence", ""),
            why_evidence_matters=data.get("why_evidence_matters", ""),
            realistic_potential_impact=data.get("realistic_potential_impact", ""),
            alternative_explanations=data.get("alternative_explanations", ""),
            missing_information=data.get("missing_information", "Needs manual verification"),
            recommended_next_steps=data.get("recommended_next_steps", []),
            suggested_remediation=data.get("suggested_remediation", ""),
            confidence_rationale=data.get("confidence_rationale", ""),
            severity_rationale=data.get("severity_rationale", ""),
            recommended_priority=prio,
            recommended_priority_rationale=data.get("recommended_priority_rationale", ""),
            finding_tier=tier,
            potential_false_positive=bool(data.get("potential_false_positive", False)),
            false_positive_explanation=data.get("false_positive_explanation", ""),
            needs_manual_verification=bool(data.get("needs_manual_verification", True)),
            evidence_references=data.get("evidence_references", []),
            provider_name=data.get("provider_name", "mock"),
            analyzed_at=data.get("analyzed_at", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")),
        )


@dataclass
class DuplicateSuggestion:
    """
    Suggested semantic duplicate between two findings for human researcher review.
    Never automatically merged without explicit human approval.
    """
    suggestion_id: str
    primary_finding_id: str
    duplicate_finding_id: str
    similarity_score: float  # Range 0.0 to 1.0
    similarity_rationale: str
    shared_root_cause: str
    is_approved: bool = False
    reviewed_by: Optional[str] = None
    review_date: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "suggestion_id": self.suggestion_id,
            "primary_finding_id": self.primary_finding_id,
            "duplicate_finding_id": self.duplicate_finding_id,
            "similarity_score": self.similarity_score,
            "similarity_rationale": self.similarity_rationale,
            "shared_root_cause": self.shared_root_cause,
            "is_approved": self.is_approved,
            "reviewed_by": self.reviewed_by,
            "review_date": self.review_date,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DuplicateSuggestion":
        return cls(
            suggestion_id=data["suggestion_id"],
            primary_finding_id=data["primary_finding_id"],
            duplicate_finding_id=data["duplicate_finding_id"],
            similarity_score=float(data.get("similarity_score", 0.0)),
            similarity_rationale=data.get("similarity_rationale", ""),
            shared_root_cause=data.get("shared_root_cause", ""),
            is_approved=bool(data.get("is_approved", False)),
            reviewed_by=data.get("reviewed_by"),
            review_date=data.get("review_date"),
        )


@dataclass
class AIProviderConfig:
    """Configuration and credentials for an AI triage provider."""
    provider_type: str = "mock"  # "mock", "openai", "anthropic", "gemini", "local"
    api_key: Optional[str] = None
    model_name: Optional[str] = None
    endpoint_url: Optional[str] = None
    timeout: float = 15.0
    consent_given: bool = False  # Explicit user consent required for external calls

    def to_dict(self, mask_key: bool = True) -> Dict[str, Any]:
        key_display = "[CONFIGURED]" if (self.api_key and mask_key) else (self.api_key or "")
        return {
            "provider_type": self.provider_type,
            "api_key": key_display,
            "model_name": self.model_name,
            "endpoint_url": self.endpoint_url,
            "timeout": self.timeout,
            "consent_given": self.consent_given,
        }
