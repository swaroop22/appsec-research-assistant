"""
AppSec Research Assistant - Phase 3 Controlled Vulnerability Research Workflow.

A defensive web application security research and learning tool built with Streamlit.
Includes:
- Program Policy Manager with manual scope verification and fail-closed validation.
- Local Guided Security Exercises with synthetic accounts.
- Finding Verification Review Screen separating Observations, Heuristics, Suspected Flaws, and Verified Findings.
- Human Auditor Sign-Off Workflow and Sanitized Reporting (Markdown, JSON, CSV).
"""

import streamlit as st
import pandas as pd
import datetime
from typing import List, Dict, Any, Optional

from appsec_assistant.models import (
    VulnerabilityFinding,
    SeverityLevel,
    ConfidenceLevel,
    FindingType,
    FindingTier,
    TargetConfig,
    ProgramPolicy,
)
from appsec_assistant.response_parser import parse_raw_http_response
from appsec_assistant.analyzers.headers_analyzer import HeadersAnalyzer
from appsec_assistant.analyzers.cookies_analyzer import CookiesAnalyzer
from appsec_assistant.analyzers.access_control_analyzer import AccessControlAnalyzer
from appsec_assistant.knowledge_base import VulnerabilityKnowledgeBase, GuidedExercise
from appsec_assistant.policy import ProgramPolicyManager, PolicyVerificationError, UnauthorizedTargetError
from appsec_assistant.engine import AuditEngine
from appsec_assistant.lab_server import LocalLabServer, SYNTHETIC_ACCOUNTS
from appsec_assistant.reporters.csv_reporter import CSVReporter
from appsec_assistant.reporters.json_reporter import JSONReporter
from appsec_assistant.reporters.markdown_reporter import MarkdownReporter
from appsec_assistant.samples import SAMPLE_PRESETS


# Configure Streamlit page
st.set_page_config(
    page_title="AppSec Research Assistant | Phase 3",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #4B5563;
        margin-bottom: 1.5rem;
    }
    .badge-verified {
        background-color: #DCFCE7;
        color: #15803D;
        padding: 3px 10px;
        border-radius: 4px;
        font-weight: 700;
        border: 1px solid #86EFAC;
    }
    .badge-suspected {
        background-color: #FEF3C7;
        color: #B45309;
        padding: 3px 10px;
        border-radius: 4px;
        font-weight: 700;
        border: 1px solid #FDE68A;
    }
    .badge-heuristic {
        background-color: #E0F2FE;
        color: #0369A1;
        padding: 3px 10px;
        border-radius: 4px;
        font-weight: 700;
        border: 1px solid #BAE6FD;
    }
    .badge-observation {
        background-color: #F1F5F9;
        color: #475569;
        padding: 3px 10px;
        border-radius: 4px;
        font-weight: 700;
        border: 1px solid #CBD5E1;
    }
    .review-box {
        background-color: #F8FAFC;
        border-left: 4px solid #3B82F6;
        padding: 12px 16px;
        margin-bottom: 15px;
        border-radius: 0 8px 8px 0;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Session State
if "findings" not in st.session_state:
    st.session_state.findings = []
if "current_transaction" not in st.session_state:
    st.session_state.current_transaction = None
if "policy_manager" not in st.session_state:
    st.session_state.policy_manager = ProgramPolicyManager()
if "target_url" not in st.session_state:
    st.session_state.target_url = "http://127.0.0.1:5000"


def analyze_http_response(raw_text: str, target_url: str) -> tuple:
    """Parses transaction and executes passive header, cookie, and access-control analyzers."""
    transaction = parse_raw_http_response(raw_text, default_url=target_url)
    
    headers_analyzer = HeadersAnalyzer()
    cookies_analyzer = CookiesAnalyzer()
    access_analyzer = AccessControlAnalyzer()

    findings: List[VulnerabilityFinding] = []
    findings.extend(headers_analyzer.analyze(transaction))
    findings.extend(cookies_analyzer.analyze(transaction))
    findings.extend(access_analyzer.analyze(transaction))

    sorted_findings = sorted(findings, key=lambda x: (x.severity.rank, x.confidence.rank), reverse=True)
    return transaction, sorted_findings


def main():
    st.markdown('<div class="main-header">🛡️ AppSec Research Assistant — Phase 3</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">'
        'Controlled Vulnerability Research Workflow: Program Policy Verification, Guided Practice Lab Exercises, '
        'Tiered Finding Verification, and Human-Reviewed Reporting.'
        '</div>',
        unsafe_allow_html=True
    )

    # Sidebar: Scope & Policy Context
    with st.sidebar:
        st.header("⚙️ Boundary & Scope Guard")
        st.info("🔒 **Loopback Confinement Active**\nAll active requests are strictly verified against local loopback (localhost / 127.0.0.1) and authorized program policies. Ambient proxies and external redirects are blocked.")

        active_policies = [p for p in st.session_state.policy_manager.list_policies() if p.is_enabled and p.is_verified]
        if active_policies:
            st.success(f"✅ **Active Program:** {active_policies[0].program_name}")
            st.caption(f"**Authorized Assets:** {', '.join(active_policies[0].authorized_assets[:2])}")
        else:
            st.warning("⚠️ No program policy currently enabled.")

        st.markdown("---")
        st.markdown("### 🧭 Verification Tiers")
        st.markdown("""
        - 🛡️ **Independently Verified**: Confirmed with reproducible proof.
        - ⚠️ **Suspected Vulnerability**: Missing defensive control.
        - 🧭 **Heuristic Indicator**: Pattern clue (e.g. IDOR).
        - 🔍 **Observation**: Contextual technical fact.
        """)
        st.markdown("---")
        st.markdown("### ⚠️ Policy Safeguard")
        st.caption("Public targets are NEVER assumed authorized. Testing is strictly restricted to verified local scopes.")

    # Main Tabs
    tab_audit, tab_exercises, tab_review, tab_policy, tab_export = st.tabs([
        "🔬 Security Analysis & Audit",
        "🎓 Guided Lab Exercises",
        "📋 Finding Review & Human Sign-Off",
        "📜 Program Policy Manager",
        "💾 Export Verified Reports",
    ])

    # -------------------------------------------------------------
    # TAB 1: Security Analysis & Audit
    # -------------------------------------------------------------
    with tab_audit:
        st.subheader("📥 Passive Response Analysis & Sample Presets")
        st.caption("Inspect raw HTTP responses offline or evaluate local test responses.")

        col_preset, col_url = st.columns([1, 1])
        with col_preset:
            preset_options = ["Custom Input"] + list(SAMPLE_PRESETS.keys())
            selected_preset = st.selectbox(
                "Select Sample Preset:",
                preset_options,
                index=1,
                help="Choose a pre-configured realistic HTTP response.",
            )
        with col_url:
            target_url_input = st.text_input(
                "Target URL Context:",
                value=st.session_state.target_url,
                help="Scoped context for analysis.",
            )
            st.session_state.target_url = target_url_input

        preset_content = ""
        if selected_preset != "Custom Input":
            preset_info = SAMPLE_PRESETS[selected_preset]
            st.caption(f"**Scenario:** {preset_info['description']} | **Expected:** {preset_info['expected_issues']}")
            preset_content = preset_info["content"]

        http_input = st.text_area(
            label="HTTP Response Text",
            value=preset_content if selected_preset != "Custom Input" else "",
            height=200,
            placeholder="HTTP/1.1 200 OK\nContent-Type: text/html\nSet-Cookie: session_id=abc; Path=/\n...",
        )

        if st.button("🔍 Run Passive Analysis", type="primary"):
            if http_input.strip():
                transaction, findings = analyze_http_response(http_input, st.session_state.target_url)
                st.session_state.current_transaction = transaction
                st.session_state.findings = findings
                st.success(f"Analysis complete! Discovered {len(findings)} findings. Proceed to the 'Finding Review' tab.")
            else:
                st.warning("Please paste an HTTP response or select a sample preset.")

        if st.session_state.findings:
            st.markdown("#### Discovered Findings Overview")
            rows = []
            for f in st.session_state.findings:
                rows.append({
                    "ID": f.finding_id,
                    "Tier": f.finding_tier.label,
                    "Severity": f.severity.value,
                    "Confidence": f.confidence.value,
                    "Title": f.title,
                    "Human Reviewed": "✅ Yes" if f.human_reviewed else "⏳ Pending",
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    # -------------------------------------------------------------
    # TAB 2: Guided Lab Exercises
    # -------------------------------------------------------------
    with tab_exercises:
        st.subheader("🎓 Guided Local Educational Exercises")
        st.caption("Practice defensive research across 6 core web security domains using synthetic data in the local training lab.")

        exercises = VulnerabilityKnowledgeBase.list_exercises()
        ex_options = {f"{e.exercise_id}: {e.title}": e for e in exercises}
        selected_ex_key = st.selectbox("Select Guided Security Exercise:", list(ex_options.keys()))
        selected_ex: GuidedExercise = ex_options[selected_ex_key]

        col_ex_info, col_ex_act = st.columns([2, 1])
        with col_ex_info:
            st.markdown(f"### {selected_ex.title}")
            st.markdown(f"**Category:** `{selected_ex.category}` | **Target Endpoint:** `{selected_ex.target_endpoint}` | **Expected Tier:** `{selected_ex.expected_tier.label}`")
            st.write(selected_ex.learning_context)

            st.markdown("#### 🎯 Exercise Objective")
            st.info(selected_ex.objective)

            st.markdown("#### 🧪 Synthetic Test Accounts & Data")
            if selected_ex.test_accounts:
                st.json(selected_ex.test_accounts)
            else:
                st.write("No authenticated account required (anonymous audit).")

            st.markdown("#### 📝 Step-by-Step Reproduction Guide")
            for step in selected_ex.reproduction_steps:
                st.markdown(f"- {step}")

            st.markdown("#### 🛡️ Defensive Remediation Summary")
            st.success(selected_ex.remediation_summary)

        with col_ex_act:
            st.markdown("### 🚀 Execute Exercise")
            st.write("Run this exercise safely against the local practice lab on loopback.")
            if st.button(f"Run {selected_ex.exercise_id} Against Lab", type="primary", use_container_width=True):
                # Start temporary local lab instance to execute exercise
                lab = LocalLabServer(port=5000)
                try:
                    lab.start()
                    config = TargetConfig(base_url="http://127.0.0.1:5000")
                    engine = AuditEngine(config, policy_manager=st.session_state.policy_manager)
                    discovered = engine.audit_exercise(selected_ex)
                    st.session_state.findings = discovered
                    st.session_state.target_url = f"http://127.0.0.1:5000{selected_ex.target_endpoint}"
                    st.success(f"Exercise executed! Captured {len(discovered)} findings for `{selected_ex.target_endpoint}`.")
                finally:
                    lab.stop()

                st.markdown("#### Discovered Findings for Exercise")
                for f in st.session_state.findings:
                    st.markdown(f"- **[{f.finding_tier.label}]** `{f.finding_id}` — {f.title} ({f.severity.value})")

    # -------------------------------------------------------------
    # TAB 3: Finding Review & Human Sign-Off
    # -------------------------------------------------------------
    with tab_review:
        st.subheader("📋 Finding Review & Human Verification Screen")
        st.caption("Inspect reproduction steps, sanitized evidence, and sign off as a human security auditor before report generation.")

        st.warning(
            "⚠️ **Responsible Disclosure Requirement:** Human review is strictly required before any report is submitted externally. "
            "Never claim a vulnerability is confirmed without reproducible supporting evidence."
        )

        if not st.session_state.findings:
            st.info("No findings currently loaded. Run an analysis from Tab 1 or an exercise from Tab 2.")
        else:
            reviewed_count = sum(1 for f in st.session_state.findings if f.human_reviewed)
            total_count = len(st.session_state.findings)
            st.progress(reviewed_count / total_count if total_count > 0 else 0)
            st.caption(f"**Review Progress:** {reviewed_count} of {total_count} findings verified by human auditor.")

            for idx, f in enumerate(st.session_state.findings):
                tier_badge_class = {
                    FindingTier.INDEPENDENTLY_VERIFIED: "badge-verified",
                    FindingTier.SUSPECTED_VULNERABILITY: "badge-suspected",
                    FindingTier.HEURISTIC_INDICATOR: "badge-heuristic",
                    FindingTier.OBSERVATION: "badge-observation",
                }.get(f.finding_tier, "badge-observation")

                header_str = f"[{f.severity.value}] [{f.finding_tier.label}] {f.title} ({f.finding_id})"
                with st.expander(header_str, expanded=(not f.human_reviewed)):
                    st.markdown(
                        f"<span class='{tier_badge_class}'>{f.finding_tier.label}</span> &nbsp;&nbsp;|&nbsp;&nbsp; "
                        f"**Severity:** `{f.severity.value}` &nbsp;&nbsp;|&nbsp;&nbsp; "
                        f"**Confidence:** `{f.confidence.value}` &nbsp;&nbsp;|&nbsp;&nbsp; "
                        f"**Human Status:** {'✅ Verified' if f.human_reviewed else '⏳ Pending Review'}",
                        unsafe_allow_html=True
                    )

                    st.markdown("#### 🎯 Priority & Severity Rationale")
                    st.write(f.priority_rationale)

                    st.markdown("#### 🔬 Step-by-Step Reproduction Guide")
                    for step in f.reproduction_steps:
                        st.markdown(f"- {step}")

                    st.markdown("#### 🛡️ Sanitized Evidence (Tokens & Secrets Redacted)")
                    st.code(f.sanitized_evidence or f.evidence, language="http")

                    st.markdown("#### 🛠️ Recommended Defensive Remediation")
                    st.markdown(f.remediation)

                    st.markdown("---")
                    st.markdown("#### ✍️ Human Auditor Sign-Off")
                    col_rev_name, col_rev_notes = st.columns([1, 2])
                    with col_rev_name:
                        rev_name = st.text_input(f"Reviewer Name (#{idx}):", value=f.reviewed_by or "Security Researcher", key=f"rev_name_{idx}")
                    with col_rev_notes:
                        rev_notes = st.text_input(f"Review Notes (#{idx}):", value=f.review_notes or "Evidence verified; does not violate program policy.", key=f"rev_notes_{idx}")

                    col_chk, col_btn = st.columns([3, 1])
                    with col_chk:
                        confirmed_chk = st.checkbox(
                            "I have verified the evidence, confirmed reproducible steps, and validated scope authorization.",
                            value=f.human_reviewed,
                            key=f"chk_{idx}"
                        )
                    with col_btn:
                        if st.button("Save Verification", key=f"btn_save_{idx}", type="secondary"):
                            f.human_reviewed = confirmed_chk
                            f.reviewed_by = rev_name
                            f.review_notes = rev_notes
                            f.review_date = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                            st.success(f"Updated review status for {f.finding_id}!")
                            st.rerun()

    # -------------------------------------------------------------
    # TAB 4: Program Policy Manager
    # -------------------------------------------------------------
    with tab_policy:
        st.subheader("📜 Vulnerability Disclosure Program Policy Manager")
        st.caption("Manage program URLs, authorized scopes, rate limits, and prohibited methods. Requires manual scope sign-off before enablement.")

        policies = st.session_state.policy_manager.list_policies()

        st.markdown("### Configured Program Policies")
        for p in policies:
            with st.container():
                st.markdown(f"#### {p.program_name} (`{p.program_id}`)")
                col_p1, col_p2, col_p3 = st.columns(3)
                col_p1.markdown(f"**Organization:** {p.organization}")
                col_p2.markdown(f"**Status:** {'✅ ENABLED' if p.is_enabled else '⏸️ DISABLED'}")
                col_p3.markdown(f"**Verified:** {'✅ YES' if p.is_verified else '❌ NO'}")

                st.markdown(f"**Policy URL:** [{p.policy_url}]({p.policy_url})")
                st.markdown(f"**Authorized Asset Scopes:** `{', '.join(p.authorized_assets)}`")
                st.markdown(f"**Prohibited Methods:** {', '.join(p.prohibited_methods)}")
                st.markdown(f"**Rate Limit:** `{p.rate_limit_rps}` req/sec")

                if p.is_verified:
                    st.info(f"Verified by **{p.verified_by}** on {p.verification_date}: {p.verification_notes}")
                else:
                    st.warning("⚠️ Scope not yet manually verified. Policy cannot be enabled until verified.")

                col_b1, col_b2 = st.columns(2)
                with col_b1:
                    if not p.is_verified:
                        with st.popover("✍️ Verify Program Scope"):
                            st.write(f"Record human verification for `{p.program_id}`:")
                            v_name = st.text_input("Reviewer Name:", value="Security Engineer", key=f"v_name_{p.program_id}")
                            v_notes = st.text_area("Verification Notes:", value="Verified that policy URL is authentic and scope assets match local training target.", key=f"v_notes_{p.program_id}")
                            if st.button("Confirm Verification & Enable", key=f"v_btn_{p.program_id}"):
                                try:
                                    st.session_state.policy_manager.verify_policy(p.program_id, v_name, v_notes)
                                    st.session_state.policy_manager.enable_policy(p.program_id)
                                    st.success(f"Verified and enabled {p.program_id}!")
                                    st.rerun()
                                except PolicyVerificationError as pve:
                                    st.error(str(pve))
                with col_b2:
                    if p.is_enabled:
                        if st.button("Disable Policy", key=f"dis_{p.program_id}"):
                            st.session_state.policy_manager.disable_policy(p.program_id)
                            st.rerun()
                    elif p.is_verified:
                        if st.button("Enable Policy", key=f"en_{p.program_id}"):
                            st.session_state.policy_manager.enable_policy(p.program_id)
                            st.rerun()

                st.markdown("---")

    # -------------------------------------------------------------
    # TAB 5: Export Verified Reports
    # -------------------------------------------------------------
    with tab_export:
        st.subheader("💾 Export Verified Assessment Reports")
        st.caption("Generate publication-ready Markdown, JSON, and CSV reports containing reproduction steps and sanitized evidence.")

        findings_to_export = st.session_state.findings
        total = len(findings_to_export)
        reviewed_total = sum(1 for f in findings_to_export if f.human_reviewed)

        if total > 0 and reviewed_total < total:
            st.warning(
                f"⚠️ **Notice:** {total - reviewed_total} of {total} findings are still pending human auditor review. "
                "Ensure findings are independently verified before external dissemination."
            )

        col_md, col_json, col_csv = st.columns(3)

        md_content = MarkdownReporter.generate(findings_to_export, st.session_state.target_url)
        with col_md:
            st.download_button(
                label="📥 Download Markdown Report",
                data=md_content,
                file_name="verified_appsec_report.md",
                mime="text/markdown",
                use_container_width=True,
            )
            st.caption("Full report with executive summary, tier breakdown, reproduction steps, and auditor sign-off.")

        json_content = JSONReporter.generate(findings_to_export, st.session_state.target_url)
        with col_json:
            st.download_button(
                label="📥 Download JSON Report",
                data=json_content,
                file_name="verified_appsec_report.json",
                mime="application/json",
                use_container_width=True,
            )
            st.caption("Structured JSON with verification tiers, reproduction steps, and review metadata.")

        csv_content = CSVReporter.generate(findings_to_export)
        with col_csv:
            st.download_button(
                label="📥 Download CSV Report",
                data=csv_content,
                file_name="verified_appsec_report.csv",
                mime="text/csv",
                use_container_width=True,
            )
            st.caption("Spreadsheet-ready CSV table including finding tiers, review status, and sanitized evidence.")

        with st.expander("👁️ Preview Generated Markdown Report"):
            st.markdown(md_content)


if __name__ == "__main__":
    main()
