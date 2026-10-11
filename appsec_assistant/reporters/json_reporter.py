"""
JSON Vulnerability Report Generator.

Exports audit findings to structured JSON for automation, CI/CD, or integration.
"""

import json
import datetime
from typing import List
from appsec_assistant.models import VulnerabilityFinding


class JSONReporter:
    """Generates structured JSON reports from vulnerability findings."""

    @staticmethod
    def generate(
        findings: List[VulnerabilityFinding],
        target_url: str,
        audit_name: str = "Local Web Application Security Audit",
    ) -> str:
        reviewed_count = sum(1 for f in findings if getattr(f, "human_reviewed", False))
        report_data = {
            "audit_name": audit_name,
            "target_url": target_url,
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_findings": len(findings),
            "human_reviewed_count": reviewed_count,
            "human_review_complete": (reviewed_count == len(findings) and len(findings) > 0),
            "mandatory_notice": "Human review and reproducible verification are required before external disclosure submission.",
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(report_data, indent=2)

    @classmethod
    def save_to_file(cls, findings: List[VulnerabilityFinding], target_url: str, output_path: str) -> None:
        content = cls.generate(findings, target_url)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
