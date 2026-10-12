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

        # Calculate severity and finding tier statistics
        stats: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        tier_stats: Dict[str, int] = {
            "OBSERVATION": 0,
            "HEURISTIC_INDICATOR": 0,
            "SUSPECTED_VULNERABILITY": 0,
            "INDEPENDENTLY_VERIFIED": 0,
        }
        reviewed_count = 0
        for f in findings:
            stats[f.severity.value] = stats.get(f.severity.value, 0) + 1
            tier_val = f.finding_tier.value if hasattr(f, "finding_tier") else "SUSPECTED_VULNERABILITY"
            tier_stats[tier_val] = tier_stats.get(tier_val, 0) + 1
            if getattr(f, "human_reviewed", False):
                reviewed_count += 1

        total_findings = len(findings)
        review_status = "✅ Verified by Human Auditor" if (reviewed_count == total_findings and total_findings > 0) else f"⚠️ Pending Human Review ({reviewed_count}/{total_findings} reviewed)"

        # Build Markdown document
        lines = [
            f"# {audit_name}",
            "",
            "> **Controlled Application Security Assessment Report**",
            "> *Confidential - Educational & Defensive Remediation Only*",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Target Application:** `{target_url}`",
            f"- **Assessment Date:** {now_str}",
            f"- **Total Findings:** {total_findings}",
            f"- **Assessor Tool:** AppSec Research Assistant (Phase 3)",
            f"- **Human Review Status:** **{review_status}**",
            "",
            "### Verification Tier Breakdown",
            "",
            "| Verification Tier | Count | Description |",
            "| :--- | :---: | :--- |",
            f"| 🛡️ **Independently Verified** | {tier_stats['INDEPENDENTLY_VERIFIED']} | Confirmed vulnerabilities with reproducible supporting evidence |",
            f"| ⚠️ **Suspected Vulnerability**   | {tier_stats['SUSPECTED_VULNERABILITY']}   | Missing defensive controls or probable flaws awaiting verification |",
            f"| 🧭 **Heuristic Indicator**       | {tier_stats['HEURISTIC_INDICATOR']}       | Pattern/naming indicators (e.g. IDOR heuristic) unverified without cross-account proof |",
            f"| 🔍 **Observation**               | {tier_stats['OBSERVATION']}               | Contextual technical observations (banners, endpoints, versions) |",
            "",
            "### Severity Distribution",
            "",
            "| Severity | Count | Risk Level |",
            "| :--- | :---: | :--- |",
            f"| 🔴 **CRITICAL** | {stats['CRITICAL']} | Immediate remediation required (Never inferred from status code alone) |",
            f"| 🟠 **HIGH**     | {stats['HIGH']}     | High business/security impact |",
            f"| 🟡 **MEDIUM**   | {stats['MEDIUM']}   | Defensive mitigation recommended |",
            f"| 🟢 **LOW**      | {stats['LOW']}      | Security best practice hygiene |",
            f"| 🔵 **INFO**     | {stats['INFO']}     | Informational observation |",
            "",
            "> ⚠️ **Mandatory Review Notice:** In accordance with responsible disclosure policies, human review and reproducible verification are strictly required before any finding is submitted to an external program.",
            "",
            "---",
            "",
            "## 2. Table of Findings",
            "",
            "| ID | Title | Tier | Severity | Confidence | Human Reviewed |",
            "| :--- | :--- | :--- | :--- | :--- | :---: |",
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
            tier_label = f.finding_tier.label if hasattr(f, "finding_tier") else "Suspected"
            hr_mark = "✅ Yes" if getattr(f, "human_reviewed", False) else "⏳ Pending"
            lines.append(
                f"| `{f.finding_id}` | {f.title} | `{tier_label}` | {sev_badge} | {conf_str} | {hr_mark} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 3. Detailed Vulnerability Analyses & Reproduction Workflows",
            "",
        ])

        if not sorted_findings:
            lines.append("*No security findings recorded for this target.*")
        else:
            for idx, f in enumerate(sorted_findings, start=1):
                affected_str = ", ".join(f.affected_urls) if f.affected_urls else f.target_url
                tier_label = f.finding_tier.label if hasattr(f, "finding_tier") else "Suspected Vulnerability"
                lines.extend([
                    f"### 3.{idx}. [{f.finding_id}] {f.title}",
                    "",
                    f"- **Verification Tier:** **`{tier_label}`**",
                    f"- **Severity:** **{f.severity.value}**",
                    f"- **Confidence:** **{f.confidence.value}** ({f.confidence_explanation})",
                    f"- **Target URL:** `{f.target_url}`",
                    f"- **Affected Endpoints:** `{affected_str}`",
                    f"- **CWE Identifier:** {f.cwe_id or 'N/A'}",
                    f"- **OWASP Category:** {f.owasp_category or 'N/A'}",
                    f"- **Human Review:** {'✅ Approved by ' + str(f.reviewed_by) + ' (' + str(f.review_date) + ')' if getattr(f, 'human_reviewed', False) else '⏳ Pending Review'}",
                ])
                if getattr(f, "review_notes", ""):
                    lines.append(f"- **Auditor Notes:** {f.review_notes}")

                lines.extend([
                    "",
                    "#### Severity & Priority Rationale",
                    f.priority_rationale,
                    "",
                    "#### Description",
                    f.description,
                    "",
                    "#### Security Impact",
                    f.impact,
                    "",
                    "#### Step-by-Step Reproduction Guide",
                ])
                repro_steps = getattr(f, "reproduction_steps", [])
                if repro_steps:
                    for step in repro_steps:
                        lines.append(f"- {step}")
                else:
                    lines.append(f"- Query target using curl: `curl -i -s '{f.target_url}'`")
                    lines.append("- Inspect response headers and body content for the reported misconfiguration.")

                lines.extend([
                    "",
                    "#### Sanitized Evidence (Tokens & Secrets Redacted)",
                    "```text",
                    (getattr(f, "sanitized_evidence", "") or f.evidence).strip(),
                    "```",
                    "",
                    "#### Remediation Guidance",
                    f.remediation,
                    "",
                ])
                ai_data = getattr(f, "ai_triage", None)
                if ai_data:
                    lines.extend([
                        "#### 🤖 AI-Assisted Triage Analysis",
                        f"- **Triage Provider:** `{ai_data.get('provider_name', 'mock')}` (Analyzed at {ai_data.get('analyzed_at', 'N/A')})",
                        f"- **Plain-English Explanation:** {ai_data.get('plain_english_explanation', '')}",
                        f"- **Why Evidence Matters:** {ai_data.get('why_evidence_matters', '')}",
                        f"- **Realistic Potential Impact:** {ai_data.get('realistic_potential_impact', '')}",
                        f"- **Alternative Explanations:** {ai_data.get('alternative_explanations', '')}",
                        f"- **Missing Information:** {ai_data.get('missing_information', '')}",
                        f"- **Recommended Review Priority:** **`{ai_data.get('recommended_priority', 'MEDIUM')}`** ({ai_data.get('recommended_priority_rationale', '')})",
                        f"- **Potential False Positive:** {'⚠️ Likely False Positive: ' + ai_data.get('false_positive_explanation', '') if ai_data.get('potential_false_positive') else '✅ Low False Positive Risk'}",
                        "",
                    ])
                if f.references:
                    lines.append("#### References & Security Standards")
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
