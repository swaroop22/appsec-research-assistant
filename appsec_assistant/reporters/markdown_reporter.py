"""
Markdown Vulnerability Report Generator.

Exports security findings in an industry-standard, clean markdown format
with executive summaries, confidence ratings, finding breakdowns, evidence snippets, and remediations.
"""

import datetime
from typing import List, Dict
from appsec_assistant.models import VulnerabilityFinding, SeverityLevel


class MarkdownReporter:
    """Generates structured Markdown reports from security audit findings."""

    @staticmethod
    def generate(
        findings: List[VulnerabilityFinding],
        target_url: str,
        audit_name: str = "Local Web Application Security Audit",
    ) -> str:
        now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Calculate severity statistics
        stats: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        for f in findings:
            stats[f.severity.value] = stats.get(f.severity.value, 0) + 1

        total_findings = len(findings)

        # Build Markdown document
        lines = [
            f"# {audit_name}",
            "",
            "> **Defensive Application Security Assessment Report**",
            "> *Confidential - Educational & Remediation Purpose Only*",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Target Application:** `{target_url}`",
            f"- **Assessment Date:** {now_str}",
            f"- **Total Findings:** {total_findings}",
            f"- **Assessor Tool:** AppSec Research Assistant v2.0 (Phase 2)",
            "",
            "### Severity Distribution",
            "",
            "| Severity | Count | Risk Level |",
            "| :--- | :---: | :--- |",
            f"| 🔴 **CRITICAL** | {stats['CRITICAL']} | Immediate remediation required |",
            f"| 🟠 **HIGH**     | {stats['HIGH']}     | High business/security impact |",
            f"| 🟡 **MEDIUM**   | {stats['MEDIUM']}   | Defensive mitigation recommended |",
            f"| 🟢 **LOW**      | {stats['LOW']}      | Security best practice hygiene |",
            f"| 🔵 **INFO**     | {stats['INFO']}     | Informational observation |",
            "",
            "---",
            "",
            "## 2. Table of Findings",
            "",
            "| ID | Title | Category | Severity | Confidence | Type | CWE |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        # Sort findings by severity rank descending
        sorted_findings = sorted(findings, key=lambda x: x.severity.rank, reverse=True)

        for f in sorted_findings:
            sev_badge = {
                "CRITICAL": "🔴 Critical",
                "HIGH": "🟠 High",
                "MEDIUM": "🟡 Medium",
                "LOW": "🟢 Low",
                "INFO": "🔵 Info",
            }.get(f.severity.value, f.severity.value)
            conf_str = f.confidence.value
            type_str = f.finding_type.value
            lines.append(
                f"| `{f.finding_id}` | {f.title} | {f.category} | {sev_badge} | {conf_str} | `{type_str}` | `{f.cwe_id or 'N/A'}` |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 3. Detailed Vulnerability Analyses",
            "",
        ])

        if not sorted_findings:
            lines.append("*No security findings recorded for this target.*")
        else:
            for idx, f in enumerate(sorted_findings, start=1):
                affected_str = ", ".join(f.affected_urls) if f.affected_urls else f.target_url
                lines.extend([
                    f"### 3.{idx}. [{f.finding_id}] {f.title}",
                    "",
                    f"- **Severity:** **{f.severity.value}**",
                    f"- **Confidence:** **{f.confidence.value}** ({f.confidence_explanation})",
                    f"- **Finding Type:** `{f.finding_type.value}`",
                    f"- **Category:** {f.category}",
                    f"- **Affected URL:** `{f.target_url}`",
                    f"- **Endpoints Evaluated:** `{affected_str}`",
                    f"- **OWASP Classification:** {f.owasp_category or 'N/A'}",
                    f"- **CWE Identifier:** {f.cwe_id or 'N/A'}",
                    "",
                    "#### Priority Rationale",
                    f.priority_rationale,
                    "",
                    "#### Description",
                    f.description,
                    "",
                    "#### Security Impact",
                    f.impact,
                    "",
                    "#### Evidence & Reproduction Artifact",
                    "```text",
                    f.evidence.strip(),
                    "```",
                    "",
                    "#### Recommended Remediation",
                    f.remediation,
                    "",
                ])
                if f.references:
                    lines.append("#### References & Standards")
                    for ref in f.references:
                        lines.append(f"- [{ref}]({ref})")
                    lines.append("")
                lines.append("---")
                lines.append("")

        return "\n".join(lines)

    @classmethod
    def save_to_file(cls, findings: List[VulnerabilityFinding], target_url: str, output_path: str) -> None:
        content = cls.generate(findings, target_url)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
