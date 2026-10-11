"""
CSV Report Generator for Vulnerability Findings.
"""

import csv
import io
from typing import List
from appsec_assistant.models import VulnerabilityFinding


class CSVReporter:
    """Generates structured CSV reports from vulnerability findings."""

    FIELDNAMES = [
        "finding_id",
        "severity",
        "priority_rationale",
        "confidence",
        "confidence_explanation",
        "finding_type",
        "finding_tier",
        "title",
        "category",
        "cwe_id",
        "owasp_category",
        "target_url",
        "affected_urls",
        "human_reviewed",
        "reviewed_by",
        "reproduction_steps",
        "sanitized_evidence",
        "description",
        "impact",
        "remediation",
        "evidence",
        "timestamp",
    ]

    @classmethod
    def generate(cls, findings: List[VulnerabilityFinding]) -> str:
        """Serializes vulnerability findings into a CSV formatted string."""
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=cls.FIELDNAMES, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()

        for f in findings:
            repro_steps_str = "; ".join(getattr(f, "reproduction_steps", []))
            writer.writerow({
                "finding_id": f.finding_id,
                "severity": f.severity.value,
                "priority_rationale": f.priority_rationale,
                "confidence": f.confidence.value,
                "confidence_explanation": f.confidence_explanation,
                "finding_type": f.finding_type.value,
                "finding_tier": f.finding_tier.value if hasattr(f, "finding_tier") else "SUSPECTED_VULNERABILITY",
                "title": f.title,
                "category": f.category,
                "cwe_id": f.cwe_id or "N/A",
                "owasp_category": f.owasp_category or "N/A",
                "target_url": f.target_url,
                "affected_urls": "; ".join(f.affected_urls) if f.affected_urls else f.target_url,
                "human_reviewed": "YES" if getattr(f, "human_reviewed", False) else "NO",
                "reviewed_by": getattr(f, "reviewed_by", "") or "N/A",
                "reproduction_steps": repro_steps_str,
                "sanitized_evidence": getattr(f, "sanitized_evidence", "") or f.evidence,
                "description": f.description,
                "impact": f.impact,
                "remediation": f.remediation,
                "evidence": f.evidence,
                "timestamp": f.timestamp,
            })

        return output.getvalue()

    @classmethod
    def save_to_file(cls, findings: List[VulnerabilityFinding], filepath: str) -> None:
        """Writes the generated CSV report directly to the given filepath."""
        content = cls.generate(findings)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
