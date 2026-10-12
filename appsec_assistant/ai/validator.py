"""
Validation and safety enforcement for AI triage outputs.

Enforces:
1. Strict JSON Schema validation.
2. Grounded evidence checking (prevents invented URLs or fabricated responses).
3. No heuristic-to-verified promotion without independent reproducible proof.
4. Input sanitization to defend against prompt injection inside HTTP responses/HTML.
5. Strict execution sandbox: no tool calls, network calls, shell execution, or scope changes.
"""

import json
import re
from typing import Dict, Any, List, Optional, Tuple
import jsonschema

from appsec_assistant.models import (
    VulnerabilityFinding,
    FindingTier,
    SeverityLevel,
    ConfidenceLevel,
)
from appsec_assistant.ai.models import PriorityLevel, AITriageResult


TRIAGE_JSON_SCHEMA = {
    "type": "object",
    "required": [
        "finding_id",
        "plain_english_explanation",
        "observed_evidence",
        "why_evidence_matters",
        "realistic_potential_impact",
        "alternative_explanations",
        "missing_information",
        "recommended_next_steps",
        "suggested_remediation",
        "confidence_rationale",
        "severity_rationale",
        "recommended_priority",
        "recommended_priority_rationale",
        "finding_tier",
    ],
    "properties": {
        "finding_id": {"type": "string"},
        "plain_english_explanation": {"type": "string", "minLength": 5},
        "observed_evidence": {"type": "string"},
        "why_evidence_matters": {"type": "string"},
        "realistic_potential_impact": {"type": "string"},
        "alternative_explanations": {"type": "string"},
        "missing_information": {"type": "string"},
        "recommended_next_steps": {
            "type": "array",
            "items": {"type": "string"},
        },
        "suggested_remediation": {"type": "string"},
        "confidence_rationale": {"type": "string"},
        "severity_rationale": {"type": "string"},
        "recommended_priority": {
            "type": "string",
            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        },
        "recommended_priority_rationale": {"type": "string"},
        "finding_tier": {
            "type": "string",
            "enum": [
                "OBSERVATION",
                "HEURISTIC_INDICATOR",
                "SUSPECTED_VULNERABILITY",
                "INDEPENDENTLY_VERIFIED",
            ],
        },
        "potential_false_positive": {"type": "boolean"},
        "false_positive_explanation": {"type": "string"},
        "needs_manual_verification": {"type": "boolean"},
        "evidence_references": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "additionalProperties": False,
}


class TriageValidationError(Exception):
    """Raised when an AI response fails schema or ground-truth validation."""
    pass


class TriageSchemaValidator:
    """Validates and enforces guardrails on AI-generated triage content."""

    @staticmethod
    def wrap_untrusted_input(content: str) -> str:
        """
        Wraps untrusted input (e.g. response headers, body, parameters)
        in defensive delimiter blocks to neutralize prompt injection.
        """
        if not content:
            return ""
        # Neutralize common prompt-escape tags or directive spoofing
        cleaned = re.sub(r"<\/?(?:system|instruction|prompt|ai)[^>]*>", "[STRIPPED_TAG]", content, flags=re.IGNORECASE)
        # Wrap within explicit inert data boundaries
        return f"<untrusted_data_boundary>\n{cleaned}\n</untrusted_data_boundary>"

    @classmethod
    def validate_and_clean_payload(
        cls,
        raw_output: Any,
        source_finding: VulnerabilityFinding,
        provider_name: str = "mock",
    ) -> AITriageResult:
        """
        Validates the raw output against the strict JSON schema and enforces
        grounding, tier promotion limits, and evidence references.
        """
        # 1. Parse JSON if string
        if isinstance(raw_output, str):
            try:
                # Strip markdown code fences if model enclosed in ```json ... ```
                cleaned_str = raw_output.strip()
                if cleaned_str.startswith("```"):
                    cleaned_str = re.sub(r"^```(?:json)?\s*", "", cleaned_str)
                    cleaned_str = re.sub(r"\s*```$", "", cleaned_str)
                data = json.loads(cleaned_str)
            except Exception as e:
                raise TriageValidationError(f"Malformed JSON returned by provider '{provider_name}': {e}")
        elif isinstance(raw_output, dict):
            data = dict(raw_output)
        else:
            raise TriageValidationError(f"Expected JSON object or string from AI provider, got: {type(raw_output)}")

        # 2. Schema validation
        try:
            jsonschema.validate(instance=data, schema=TRIAGE_JSON_SCHEMA)
        except jsonschema.ValidationError as ve:
            raise TriageValidationError(f"Schema validation error in AI triage output: {ve.message}")

        # 3. Grounding Verification: finding_id must match
        if data["finding_id"] != source_finding.finding_id:
            data["finding_id"] = source_finding.finding_id

        # 4. CRITICAL GUARDRAIL: Never promote a heuristic or suspected issue to INDEPENDENTLY_VERIFIED
        claimed_tier_str = data.get("finding_tier", source_finding.finding_tier.value)
        try:
            claimed_tier = FindingTier(claimed_tier_str)
        except ValueError:
            claimed_tier = source_finding.finding_tier

        # Tier clamping rule:
        if (
            source_finding.finding_tier != FindingTier.INDEPENDENTLY_VERIFIED
            and claimed_tier == FindingTier.INDEPENDENTLY_VERIFIED
        ):
            # Clamp back to source finding tier
            claimed_tier = source_finding.finding_tier
            data["needs_manual_verification"] = True
            guardrail_note = (
                " [GUARDRAIL: Tier promotion to INDEPENDENTLY_VERIFIED rejected; "
                "AI cannot confirm vulnerabilities without independent reproducible evidence.]"
            )
            data["confidence_rationale"] = (data.get("confidence_rationale", "") + guardrail_note).strip()

        data["finding_tier"] = claimed_tier.value

        # 5. Evidence Grounding: verify evidence references against actual finding
        source_evidence_lower = (source_finding.evidence + " " + source_finding.sanitized_evidence + " " + source_finding.target_url).lower()
        verified_refs: List[str] = []
        for ref in data.get("evidence_references", []):
            if not ref or not ref.strip():
                continue
            ref_clean = ref.strip()
            # If the reference cites a specific header/URL/keyword, check relevance
            words = [w for w in re.split(r"[\s,;:'\"]+", ref_clean.lower()) if len(w) > 3]
            if not words or any(w in source_evidence_lower for w in words):
                verified_refs.append(ref_clean)
            else:
                # Discard completely ungrounded or fabricated evidence reference
                continue

        data["evidence_references"] = verified_refs

        # 6. Check for Insufficient Evidence -> Must declare "Needs manual verification"
        if (
            not source_finding.evidence
            or claimed_tier in (FindingTier.HEURISTIC_INDICATOR, FindingTier.OBSERVATION)
            or source_finding.confidence in (ConfidenceLevel.LOW, ConfidenceLevel.HEURISTIC)
        ):
            data["needs_manual_verification"] = True
            missing_info = data.get("missing_information", "").strip()
            if not missing_info or "needs manual verification" not in missing_info.lower():
                data["missing_information"] = (
                    "Needs manual verification: " + (missing_info if missing_info else "Proof of cross-account impact or reproducible execution required.")
                )

        # 7. Construct and return typed AITriageResult
        return AITriageResult.from_dict({
            **data,
            "provider_name": provider_name,
        })
