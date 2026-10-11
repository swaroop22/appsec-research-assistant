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
        "title",
        "category",
        "cwe_id",
        "owasp_category",
        "target_url",
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
            writer.writerow({
                "finding_id": f.finding_id,
                "severity": f.severity.value,
                "priority_rationale": f.priority_rationale,
                "title": f.title,
                "category": f.category,
                "cwe_id": f.cwe_id or "N/A",
                "owasp_category": f.owasp_category or "N/A",
                "target_url": f.target_url,
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
