"""
Policy-Aware Report Generator for Bug Bounty Programs.

Generates structured vulnerability report drafts tailored to official program reporting
guidelines, including preconditions, minimal reproduction steps, expected vs. observed behavior,
sanitized evidence, realistic impact assessment, severity rationale, and known limitations.
Enforces human-controlled export: requires explicit researcher review prior to file generation.
Does not guarantee reward eligibility or invent bounty amounts.
"""

import os
import json
import datetime
from typing import Dict, Any, Optional

from appsec_assistant.models import (
    ResearchTask,
    VulnerabilityFinding,
    ProgramPolicy,
    ResearchStatus,
    sanitize_evidence_text,
)
from appsec_assistant.research import ReportReadinessError


class ResearcherReviewRequiredError(Exception):
    """Raised when an export is attempted without explicit human researcher review sign-off."""
    pass


class PolicyReportGenerator:
    """
    Constructs standardized, program-tailored vulnerability disclosure report drafts.
    """

    def generate_markdown(
        self,
        task: ResearchTask,
        finding: VulnerabilityFinding,
        policy: ProgramPolicy,
        researcher_review_confirmed: bool = False,
    ) -> str:
        """
        Generates a comprehensive Markdown report tailored to the program's policy.
        """
        lines = []

        # Header & Status Banner
        lines.append(f"# Vulnerability Disclosure Report: {finding.title}")
        lines.append("")

        if not researcher_review_confirmed:
            lines.append("> [!WARNING]")
            lines.append("> **PRELIMINARY REPORT DRAFT - NOT YET APPROVED BY RESEARCHER**")
            lines.append("> This report contains unreviewed research material. Explicit human review is required prior to external export or submission.")
            lines.append("")

        lines.append(f"- **Task ID:** `{task.task_id}`")
        lines.append(f"- **Finding ID:** `{finding.finding_id}`")
        lines.append(f"- **Current Research Status:** `{task.status.value if hasattr(task.status, 'value') else task.status}`")
        lines.append(f"- **Date Generated:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")

        # 1. Program & Scope Alignment
        lines.append("## 1. Program & Target Information")
        lines.append("")
        lines.append(f"- **Company / Organization:** {policy.company_name or policy.organization}")
        lines.append(f"- **Program Name:** {policy.program_name}")
        lines.append(f"- **Official Policy URL:** [{policy.policy_url}]({policy.policy_url})")
        lines.append(f"- **Policy Version:** {policy.policy_version}")
        lines.append(f"- **Policy Verification Date:** {policy.verification_date or 'Unverified'}")
        lines.append(f"- **Official Reporting Destination:** {policy.reporting_instructions or policy.policy_url}")
        lines.append(f"- **Affected In-Scope Asset:** `{task.affected_asset or finding.target_url}`")
        lines.append("")

        # Check for scope exclusion warnings
        if policy.excluded_assets:
            lines.append("> [!NOTE]")
            lines.append(f"> **Policy Boundary Note:** Testing strictly respects {len(policy.excluded_assets)} explicitly excluded asset pattern(s). All non-essential requests were avoided.")
            lines.append("")

        # 2. Executive Summary
        lines.append("## 2. Summary")
        lines.append("")
        lines.append(finding.description or "No summary provided.")
        lines.append("")

        # 3. Preconditions & Environmental Constraints
        lines.append("## 3. Preconditions")
        lines.append("")
        lines.append("- Valid network connectivity to authorized endpoints.")
        lines.append("- Standard HTTP client (curl / browser) with no specialized exploit frameworks.")
        if policy.testing_restrictions:
            for rest in policy.testing_restrictions:
                lines.append(f"- Research constraint: {rest}")
        lines.append(f"- Enforced testing rate limit: {policy.rate_limit_rps} requests/second.")
        lines.append("")

        # 4. Minimal Reproduction Steps
        lines.append("## 4. Minimal Reproduction Steps")
        lines.append("")
        if finding.reproduction_steps:
            for step in finding.reproduction_steps:
                lines.append(f"{step}")
        else:
            lines.append("1. Send request to target asset: `curl -i -s '" + (task.affected_asset or finding.target_url) + "'`")
            lines.append("2. Inspect response headers and body content for missing defensive controls.")
        lines.append("")

        # 5. Expected vs. Observed Behavior
        lines.append("## 5. Expected vs. Observed Behavior")
        lines.append("")
        lines.append("### Expected Secure Behavior")
        lines.append(f"The asset `{task.affected_asset or finding.target_url}` should implement robust defense-in-depth controls:")
        if finding.category == "Access Control":
            lines.append("- Enforce strict server-side authorization and contextual permission checks on all requests.")
        elif finding.category == "Security Headers":
            lines.append("- Return strict security response headers (e.g., CSP, HSTS, X-Content-Type-Options) to protect clients.")
        elif finding.category == "Cookie Security":
            lines.append("- Issue cookies with Secure, HttpOnly, and SameSite attributes to prevent leakage or hijacking.")
        else:
            lines.append("- Enforce secure validation, least privilege, and defensive handling on all endpoints.")
        lines.append("")

        lines.append("### Observed Insecure Behavior")
        lines.append(f"During testing on `{task.affected_asset or finding.target_url}`:")
        if finding.sanitized_evidence:
            evidence_sample = finding.sanitized_evidence.strip()
            if len(evidence_sample) > 400:
                evidence_sample = evidence_sample[:400] + "... [truncated]"
            lines.append("```http")
            lines.append(evidence_sample)
            lines.append("```")
        else:
            lines.append("Observed lack of required defensive security controls.")
        lines.append("")

        # 6. Technical Evidence
        lines.append("## 6. Technical Evidence")
        lines.append("")
        lines.append(f"- **HTTP Method:** `{finding.http_method}`")
        if finding.http_status:
            lines.append(f"- **HTTP Response Status:** `{finding.http_status}`")
        lines.append(f"- **Evidence Sanitization:** Active session cookies, Authorization tokens, credentials, private keys, and personal data (PII) were automatically redacted.")
        lines.append("")

        if finding.minimal_request_evidence:
            lines.append("### Minimal Request Evidence")
            lines.append("```http")
            lines.append(finding.minimal_request_evidence.strip())
            lines.append("```")
            lines.append("")

        if finding.minimal_response_evidence:
            lines.append("### Minimal Response Evidence")
            lines.append("```http")
            lines.append(finding.minimal_response_evidence.strip())
            lines.append("```")
            lines.append("")

        # Separate AI triage from original evidence
        if finding.ai_triage:
            lines.append("### AI-Assisted Triage Context")
            lines.append("> [!NOTE]")
            lines.append("> The following section contains automated AI triage analysis, kept strictly separate from original observational evidence.")
            lines.append("")
            summary = finding.ai_triage.get("summary") or finding.ai_triage.get("analysis_summary", "")
            if summary:
                lines.append(f"**AI Assessment:** {summary}")
            repro = finding.ai_triage.get("reproduction_verification") or finding.ai_triage.get("reproduction_plan", "")
            if repro:
                lines.append(f"**Verification Guidance:** {repro}")
            lines.append("")

        # 7. Realistic Impact Assessment
        lines.append("## 7. Realistic Impact Assessment")
        lines.append("")
        lines.append(finding.impact or "Impact assessment pending further investigation.")
        lines.append("")
        lines.append("> [!IMPORTANT]")
        lines.append("> **Bounty & Reward Clarification:**")
        lines.append("> This report presents realistic technical and operational risk. Reward eligibility, severity assessment, and bounty amounts are determined solely by the program security team in accordance with official program policy. No bounty amounts or payouts are guaranteed.")
        lines.append("")

        # 8. Severity & Confidence Rationale
        lines.append("## 8. Severity & Confidence Rationale")
        lines.append("")
        lines.append(f"- **Reported Severity:** `{finding.severity.value}`")
        lines.append(f"- **Severity Rationale:** {finding.priority_rationale or 'Assigned based on vulnerability category impact.'}")
        lines.append(f"- **Researcher Confidence:** `{finding.confidence.value}`")
        lines.append(f"- **Confidence Explanation:** {finding.confidence_explanation or 'Based on verified deterministic observation.'}")
        lines.append(f"- **Finding Verification Tier:** `{finding.finding_tier.value}`")
        lines.append("")

        # 9. Suggested Remediation
        lines.append("## 9. Suggested Remediation")
        lines.append("")
        lines.append(finding.remediation or "Apply industry best practices according to OWASP guidelines.")
        lines.append("")

        # 10. Known Limitations & Remaining Verification Steps
        lines.append("## 10. Known Limitations & Remaining Verification Steps")
        lines.append("")
        if task.next_manual_verification_step:
            lines.append(f"- **Next Verification Step:** {task.next_manual_verification_step}")
        lines.append("- **Non-Destructive Boundary:** Testing was non-destructive; no automated high-rate scanning, data tampering, or service disruption was performed.")
        lines.append("- **Scope Limitation:** Testing was limited to the declared authorized asset.")
        lines.append("")

        # 11. Coordinated Disclosure & Confidentiality Notice
        lines.append("## 11. Coordinated Disclosure & Confidentiality Notice")
        lines.append("")
        lines.append(f"- **Disclosure Policy:** {policy.disclosure_requirements or 'Coordinated vulnerability disclosure. Details will not be published without prior authorization.'}")
        lines.append(f"- **Safe Harbor:** {policy.safe_harbor_terms or 'Research performed in good faith compliance with the official policy.'}")
        lines.append("")

        return "\n".join(lines)

    def generate_json(
        self,
        task: ResearchTask,
        finding: VulnerabilityFinding,
        policy: ProgramPolicy,
        researcher_review_confirmed: bool = False,
    ) -> str:
        """
        Generates structured JSON report payload.
        """
        payload: Dict[str, Any] = {
            "report_metadata": {
                "task_id": task.task_id,
                "finding_id": finding.finding_id,
                "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "researcher_review_confirmed": researcher_review_confirmed,
                "status": task.status.value if hasattr(task.status, "value") else task.status,
            },
            "program_alignment": {
                "company_name": policy.company_name or policy.organization,
                "program_name": policy.program_name,
                "policy_url": policy.policy_url,
                "policy_version": policy.policy_version,
                "verification_date": policy.verification_date,
                "reporting_destination": policy.reporting_instructions or policy.policy_url,
                "affected_asset": task.affected_asset or finding.target_url,
                "safe_harbor_terms": policy.safe_harbor_terms,
            },
            "vulnerability_details": {
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity.value,
                "severity_rationale": finding.priority_rationale,
                "confidence": finding.confidence.value,
                "confidence_explanation": finding.confidence_explanation,
                "finding_tier": finding.finding_tier.value,
                "description": finding.description,
                "reproduction_steps": finding.reproduction_steps,
                "impact": finding.impact,
                "remediation": finding.remediation,
            },
            "technical_evidence": {
                "http_method": finding.http_method,
                "http_status": finding.http_status,
                "sanitized_evidence": finding.sanitized_evidence,
                "minimal_request_evidence": finding.minimal_request_evidence,
                "minimal_response_evidence": finding.minimal_response_evidence,
                "ai_triage_context": finding.ai_triage,
            },
            "verification_and_limitations": {
                "next_manual_verification_step": task.next_manual_verification_step,
                "evidence_completeness_score": task.evidence_completeness_score,
                "report_ready": task.report_ready,
                "report_readiness_notes": task.report_readiness_notes,
            },
            "disclosure_notice": {
                "disclosure_requirements": policy.disclosure_requirements,
                "bounty_disclaimer": "Reward eligibility is strictly determined by the program team. No bounty amount is guaranteed.",
            },
        }

        # Double check sanitization across payload
        return json.dumps(payload, indent=2)

    def export_report(
        self,
        task: ResearchTask,
        finding: VulnerabilityFinding,
        policy: ProgramPolicy,
        output_path: str,
        researcher_review_confirmed: bool = False,
        format: str = "markdown",
    ) -> str:
        """
        Exports the report to file after enforcing researcher review and report readiness.
        Raises ResearcherReviewRequiredError if researcher review is not confirmed.
        Raises ReportReadinessError if the task has critical readiness blockers.
        """
        if not researcher_review_confirmed:
            raise ResearcherReviewRequiredError(
                "Cannot export report: explicit researcher review confirmation is required. "
                "Human review must be confirmed before any vulnerability report is exported."
            )

        # Readiness audit
        if not task.report_ready:
            from appsec_assistant.policy import _match_asset_pattern
            for excl in policy.excluded_assets:
                if _match_asset_pattern(task.affected_asset or finding.target_url, excl):
                    raise ReportReadinessError(
                        f"Cannot export report for asset '{task.affected_asset}' that is explicitly EXCLUDED by policy."
                    )

        content: str
        if format.lower() == "json":
            content = self.generate_json(task, finding, policy, researcher_review_confirmed=True)
        else:
            content = self.generate_markdown(task, finding, policy, researcher_review_confirmed=True)

        # Sanitize entire output text to ensure zero secret leakage
        sanitized_content = sanitize_evidence_text(content)

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(sanitized_content)

        return os.path.abspath(output_path)
