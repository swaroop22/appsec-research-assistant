"""
AppSec Research Assistant - Phase 5 Authorized Bug Bounty Research Workflow.

A defensive, program-aware web application security research and learning tool built with Streamlit.
Includes:
- Safe Workflow Modes (Mode A: Offline, Mode B: Local Lab, Mode C: Authorized Program Preparation).
- Program Policy Registry with eligible/excluded asset management, stale detection, and import/export.
- Local Guided Security Exercises with synthetic accounts.
- AI-Assisted Finding Triage Layer (Mock, OpenAI, Anthropic, Gemini, Local).
- Grounded Evidence Verification (Observation, Heuristic, Suspected, Verified).
- Research Task Dashboard with lifecycle status, evidence completeness auditing, and duplicate reviews.
- Policy-Aware Report Generator with preconditions, expected vs observed, impact, and sanitized export.
- Human-Controlled Submission and Outcome Tracking.
"""

import os
import json
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
    WorkflowMode,
    ResearchStatus,
    ResearchTask,
    TargetConfig,
    ProgramPolicy,
    sanitize_evidence_text,
)
from appsec_assistant.response_parser import parse_raw_http_response
from appsec_assistant.analyzers.headers_analyzer import HeadersAnalyzer
from appsec_assistant.analyzers.cookies_analyzer import CookiesAnalyzer
from appsec_assistant.analyzers.access_control_analyzer import AccessControlAnalyzer
from appsec_assistant.knowledge_base import VulnerabilityKnowledgeBase, GuidedExercise
from appsec_assistant.policy import (
    ProgramPolicyManager,
    PolicyVerificationError,
    PolicyStaleError,
    ScopeIntegrityError,
    UnauthorizedTargetError,
    create_sample_fictional_policy,
)
from appsec_assistant.engine import AuditEngine
from appsec_assistant.lab_server import LocalLabServer, SYNTHETIC_ACCOUNTS
from appsec_assistant.research import (
    ResearchManager,
    ReportReadinessError,
    HumanConfirmationRequiredError,
)
from appsec_assistant.reporters.csv_reporter import CSVReporter
from appsec_assistant.reporters.json_reporter import JSONReporter
from appsec_assistant.reporters.markdown_reporter import MarkdownReporter
from appsec_assistant.reporters.policy_report_generator import (
    PolicyReportGenerator,
    ResearcherReviewRequiredError,
)
from appsec_assistant.samples import SAMPLE_PRESETS

from appsec_assistant.ai import (
    AIService,
    AIProviderConfig,
    AITriageResult,
    PriorityLevel,
    DuplicateSuggestion,
    ConsentRequiredError,
)


# Configure Streamlit page
st.set_page_config(
    page_title="AppSec Research Assistant | Phase 5",
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
    .badge-mode {
        background-color: #EDE9FE;
        color: #5B21B6;
        padding: 4px 12px;
        border-radius: 6px;
        font-weight: 700;
        border: 1px solid #C4B5FD;
        display: inline-block;
        margin-bottom: 8px;
    }
    .card-task {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .ai-box {
        background-color: #F0FDF4;
        border-left: 4px solid #10B981;
        padding: 12px 16px;
        margin-bottom: 12px;
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
if "research_manager" not in st.session_state:
    st.session_state.research_manager = ResearchManager(st.session_state.policy_manager)
if "target_url" not in st.session_state:
    st.session_state.target_url = "http://127.0.0.1:5000"
if "workflow_mode" not in st.session_state:
    st.session_state.workflow_mode = WorkflowMode.LOCAL_LAB
if "ai_config" not in st.session_state:
    st.session_state.ai_config = AIProviderConfig(provider_type="mock")
if "ai_enabled" not in st.session_state:
    st.session_state.ai_enabled = True
if "ai_duplicates" not in st.session_state:
    st.session_state.ai_duplicates = []


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
    st.markdown('<div class="main-header">🛡️ AppSec Research Assistant — Phase 5</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">'
        'Authorized Bug Bounty Research Workflow: Program Registry, Scope Verification, Safe Modes, '
        'Research Task Dashboard, Evidence Completeness, and Policy-Aware Reporting.'
        '</div>',
        unsafe_allow_html=True
    )

    # Sidebar: Workflow Mode & Policy Context
    with st.sidebar:
        st.header("🚦 Safe Workflow Mode")
        mode_choice = st.selectbox(
            "Select Execution Mode:",
            [
                "Mode B: Local Lab (Loopback Training)",
                "Mode A: Offline Analysis (Zero Network)",
                "Mode C: Authorized Program Preparation",
            ],
            index=0,
            help="Strict boundary modes ensuring authorization compliance.",
        )

        if "Mode A" in mode_choice:
            st.session_state.workflow_mode = WorkflowMode.OFFLINE
            st.markdown("<span class='badge-mode'>MODE A: OFFLINE</span>", unsafe_allow_html=True)
            st.info("🔌 **Network Disabled:** Analyze saved HTTP responses and existing reports. Zero outbound network calls permitted.")
        elif "Mode B" in mode_choice:
            st.session_state.workflow_mode = WorkflowMode.LOCAL_LAB
            st.markdown("<span class='badge-mode'>MODE B: LOCAL LAB</span>", unsafe_allow_html=True)
            st.success("🔒 **Loopback Confinement:** Active testing strictly confined to loopback training lab (127.0.0.1 / localhost).")
        else:
            st.session_state.workflow_mode = WorkflowMode.AUTHORIZED_PROGRAM_PREPARATION
            st.markdown("<span class='badge-mode'>MODE C: PROGRAM PREPARATION</span>", unsafe_allow_html=True)
            st.warning("📋 **Preparation Only:** Scope review, research notes, finding mapping, and report drafts. Automated scanning is disabled.")

        st.markdown("---")
        st.header("⚙️ Boundary & Scope Guard")
        active_policies = [p for p in st.session_state.policy_manager.list_policies() if p.is_enabled and p.is_verified and not p.is_stale()]
        if active_policies:
            st.success(f"✅ **Active Program:** {active_policies[0].program_name}")
            st.caption(f"**Eligible Assets:** {', '.join(active_policies[0].eligible_assets[:2])}")
            if active_policies[0].excluded_assets:
                st.caption(f"**Excluded Assets ({len(active_policies[0].excluded_assets)}):** {', '.join(active_policies[0].excluded_assets[:2])}")
        else:
            st.warning("⚠️ No verified, non-stale program policy currently enabled.")

        st.markdown("---")
        st.markdown("### 🤖 AI Triage Status")
        st.write(f"**Provider:** `{st.session_state.ai_config.provider_type.upper()}`")
        st.write(f"**Status:** {'🟢 Enabled' if st.session_state.ai_enabled else '⏸️ Disabled'}")
        st.write(f"**External Consent:** {'✅ Granted' if st.session_state.ai_config.consent_given else '🔒 Local Only'}")

        st.markdown("---")
        st.markdown("### 🧭 Verification Tiers")
        st.markdown("""
        - 🛡️ **Independently Verified**: Confirmed with reproducible proof.
        - ⚠️ **Suspected Vulnerability**: Missing defensive control.
        - 🧭 **Heuristic Indicator**: Pattern clue (e.g. IDOR).
        - 🔍 **Observation**: Contextual technical fact.
        """)

    # Main Tabs
    tab_audit, tab_exercises, tab_triage, tab_review, tab_policy, tab_research, tab_export = st.tabs([
        "🔬 Security Analysis & Audit",
        "🎓 Guided Lab Exercises",
        "🤖 AI Triage & Analysis",
        "📋 Finding Review & Sign-Off",
        "📜 Program Policy Registry",
        "🎯 Bug Bounty Research Tasks",
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

        if selected_preset != "Custom Input":
            default_text = SAMPLE_PRESETS[selected_preset]
        else:
            default_text = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Test</body></html>"

        raw_response_input = st.text_area(
            "Raw HTTP Response Data:",
            value=default_text,
            height=180,
            help="Paste HTTP headers and body.",
        )

        if st.button("🚀 Analyze Response", type="primary"):
            tx, findings = analyze_http_response(raw_response_input, target_url_input)
            st.session_state.current_transaction = tx
            st.session_state.findings = findings
            st.success(f"Audit Complete! Identified {len(findings)} security observations/findings.")

        if st.session_state.findings:
            st.markdown("### 📋 Audit Findings Overview")
            df = pd.DataFrame([{
                "ID": f.finding_id,
                "Tier": f.finding_tier.label,
                "Severity": f.severity.value,
                "Confidence": f.confidence.value,
                "Category": f.category,
                "Title": f.title,
                "Reviewed": "✅ Yes" if f.human_reviewed else "⏳ Pending",
            } for f in st.session_state.findings])
            st.dataframe(df, use_container_width=True)

    # -------------------------------------------------------------
    # TAB 2: Guided Lab Exercises
    # -------------------------------------------------------------
    with tab_exercises:
        st.subheader("🎓 Guided Local Practice Lab")
        st.caption("Hands-on exercises executing strictly against local synthetic accounts on loopback.")

        if st.session_state.workflow_mode == WorkflowMode.OFFLINE:
            st.warning("⚠️ **Mode Notice:** Active training lab is disabled in OFFLINE mode. Switch to Mode B in sidebar.")
        else:
            exercises = VulnerabilityKnowledgeBase.list_exercises()
            ex_options = {f"{ex.category}: {ex.title}": ex for ex in exercises}
            selected_ex_label = st.selectbox("Select Guided Exercise:", list(ex_options.keys()))
            selected_ex = ex_options[selected_ex_label]

            st.markdown(f"**Exercise Description:** {selected_ex.description}")
            st.markdown(f"**Target Local Route:** `{selected_ex.endpoint}` ({selected_ex.http_method})")
            st.markdown(f"**Defensive Goal:** {selected_ex.remediation_summary}")

            if st.button("▶️ Execute Guided Exercise in Local Lab", type="secondary"):
                with st.spinner("Starting local lab container on port 5000..."):
                    lab = LocalLabServer(port=5000)
                    lab.start()
                    try:
                        cfg = TargetConfig(base_url="http://127.0.0.1:5000")
                        engine = AuditEngine(cfg, policy_manager=st.session_state.policy_manager)
                        ex_findings = engine.audit_exercise(selected_ex)
                        st.session_state.findings = ex_findings
                        st.success(f"Exercise complete! Captured {len(ex_findings)} findings.")
                    finally:
                        lab.stop()
                    st.rerun()

    # -------------------------------------------------------------
    # TAB 3: AI Triage & Analysis
    # -------------------------------------------------------------
    with tab_triage:
        st.subheader("🤖 AI-Assisted Finding Triage & Analysis")
        st.caption("Deterministic findings enriched with false positive analysis, reproduction steps, and duplicate detection.")

        if not st.session_state.findings:
            st.info("No findings currently loaded. Analyze a response in Tab 1 or run an exercise in Tab 2.")
        else:
            col_ai_run, col_dup_run = st.columns(2)
            with col_ai_run:
                if st.button("🧠 Run AI Triage Across Findings", type="primary"):
                    with st.spinner("Running AI triage service..."):
                        service = AIService(st.session_state.ai_config, fallback_to_mock=True)
                        service.triage_all(st.session_state.findings)
                        st.success("AI Triage complete!")
                        st.rerun()
            with col_dup_run:
                if st.button("🔍 Detect Semantic Duplicates", type="secondary"):
                    with st.spinner("Analyzing semantic similarity..."):
                        service = AIService(st.session_state.ai_config, fallback_to_mock=True)
                        st.session_state.ai_duplicates = service.detect_duplicates(st.session_state.findings)
                        st.info(f"Detected {len(st.session_state.ai_duplicates)} duplicate suggestion(s).")
                        st.rerun()

            for f in st.session_state.findings:
                if f.ai_triage:
                    with st.expander(f"AI Triage: {f.title} ({f.finding_id})", expanded=False):
                        st.markdown(f"**Recommended Priority:** `{f.ai_triage.get('recommended_priority', 'MEDIUM')}`")
                        st.markdown(f"**Summary:** {f.ai_triage.get('summary', '')}")
                        st.markdown(f"**Verification Plan:** {f.ai_triage.get('reproduction_verification', '')}")

    # -------------------------------------------------------------
    # TAB 4: Finding Review & Sign-Off
    # -------------------------------------------------------------
    with tab_review:
        st.subheader("📋 Finding Review & Human Auditor Sign-Off")
        st.caption("Inspect reproduction steps, sanitized evidence, and sign off as a human security auditor before report generation.")

        if not st.session_state.findings:
            st.info("No findings currently loaded.")
        else:
            reviewed_count = sum(1 for f in st.session_state.findings if f.human_reviewed)
            total_count = len(st.session_state.findings)
            st.progress(reviewed_count / total_count if total_count > 0 else 0)
            st.caption(f"**Review Progress:** {reviewed_count} of {total_count} findings verified by human auditor.")

            for idx, f in enumerate(st.session_state.findings):
                with st.expander(f"[{f.severity.value}] {f.title} ({f.finding_id})", expanded=(not f.human_reviewed)):
                    st.markdown(f"**Finding Tier:** `{f.finding_tier.label}` | **Confidence:** `{f.confidence.value}`")
                    st.markdown("#### 🔬 Step-by-Step Reproduction Guide")
                    for step in f.reproduction_steps:
                        st.markdown(f"- {step}")

                    st.markdown("#### 🛡️ Sanitized Evidence (Secrets & PII Redacted)")
                    st.code(f.sanitized_evidence or f.evidence, language="http")

                    st.markdown("#### ✍️ Human Auditor Sign-Off")
                    col_r1, col_r2 = st.columns([1, 2])
                    with col_r1:
                        r_name = st.text_input(f"Auditor Name (#{idx}):", value=f.reviewed_by or "Lead Researcher", key=f"aud_name_{idx}")
                    with col_r2:
                        r_notes = st.text_input(f"Auditor Notes (#{idx}):", value=f.review_notes or "Evidence verified; does not violate program policy.", key=f"aud_notes_{idx}")

                    col_chk, col_btn = st.columns([3, 1])
                    with col_chk:
                        chk_val = st.checkbox(
                            "I have verified the evidence, confirmed reproducible steps, and validated scope authorization.",
                            value=f.human_reviewed,
                            key=f"aud_chk_{idx}",
                        )
                    with col_btn:
                        if st.button("Save Sign-Off", key=f"aud_btn_{idx}", type="secondary"):
                            f.human_reviewed = chk_val
                            f.reviewed_by = r_name
                            f.review_notes = r_notes
                            f.review_date = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                            st.success("Sign-off saved!")
                            st.rerun()

    # -------------------------------------------------------------
    # TAB 5: Program Policy Registry
    # -------------------------------------------------------------
    with tab_policy:
        st.subheader("📜 Bug Bounty Program Policy Registry")
        st.caption("Store company policies, eligible asset allowlists, excluded asset boundaries, rate limits, and reporting requirements.")

        col_top1, col_top2 = st.columns(2)
        with col_top1:
            if st.button("📥 Load Acme FinTech Sample Bounty Policy", type="secondary"):
                sample = create_sample_fictional_policy()
                st.session_state.policy_manager.add_policy(sample)
                st.success("Loaded Acme FinTech sample policy into registry!")
                st.rerun()
        with col_top2:
            with st.popover("📤 Import Policy Document (JSON)"):
                uploaded_file = st.file_uploader("Upload Policy JSON:", type=["json"])
                if uploaded_file is not None:
                    try:
                        content = uploaded_file.read().decode("utf-8")
                        imported = st.session_state.policy_manager.import_policy_from_json(content)
                        st.success(f"Imported policy '{imported.program_name}'!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Import failed: {e}")

        st.markdown("---")
        policies = st.session_state.policy_manager.list_policies()

        for p in policies:
            with st.container():
                st.markdown(f"### {p.program_name} (`{p.program_id}`)")
                col_p1, col_p2, col_p3 = st.columns(3)
                col_p1.markdown(f"**Company:** {p.company_name or p.organization}")
                col_p2.markdown(f"**Policy Version:** `{p.policy_version}`")
                stale_status = "⚠️ STALE (>90d)" if p.is_stale() else "🟢 FRESH"
                col_p3.markdown(f"**Verification:** {'✅ YES' if p.is_verified else '❌ NO'} ({stale_status})")

                st.markdown(f"- **Official Policy URL:** [{p.policy_url}]({p.policy_url})")
                st.markdown(f"- **Eligible Assets Allowlist ({len(p.eligible_assets)}):** `{', '.join(p.eligible_assets)}`")
                if p.excluded_assets:
                    st.markdown(f"- **Explicitly Excluded Assets ({len(p.excluded_assets)}):** `{', '.join(p.excluded_assets)}`")
                st.markdown(f"- **Prohibited Methods:** {', '.join(p.prohibited_methods)}")
                st.markdown(f"- **Rate Limit:** `{p.rate_limit_rps}` requests/sec")
                if p.testing_restrictions:
                    st.markdown(f"- **Testing Restrictions:** {', '.join(p.testing_restrictions)}")
                st.markdown(f"- **Reporting Instructions:** {p.reporting_instructions or p.policy_url}")

                if p.is_verified:
                    st.info(f"Verified by **{p.verified_by}** on {p.verification_date}: {p.verification_notes}")
                else:
                    st.warning("⚠️ Scope unverified. Must be manually verified by a researcher before enablement.")

                col_b1, col_b2, col_b3 = st.columns(3)
                with col_b1:
                    with st.popover("✍️ Verify Program Scope"):
                        st.write(f"Record human verification for `{p.program_id}`:")
                        v_name = st.text_input("Reviewer Name:", value="Security Engineer", key=f"pv_name_{p.program_id}")
                        v_notes = st.text_area("Verification Notes:", value="Verified policy URL is authentic, scope matches declared boundaries.", key=f"pv_notes_{p.program_id}")
                        if st.button("Confirm Verification & Enable", key=f"pv_btn_{p.program_id}"):
                            try:
                                st.session_state.policy_manager.verify_policy(p.program_id, v_name, v_notes)
                                st.session_state.policy_manager.enable_policy(p.program_id)
                                st.success(f"Verified and enabled {p.program_id}!")
                                st.rerun()
                            except Exception as ex:
                                st.error(str(ex))
                with col_b2:
                    if p.is_enabled:
                        if st.button("Disable Policy", key=f"pdis_{p.program_id}"):
                            st.session_state.policy_manager.disable_policy(p.program_id)
                            st.rerun()
                    elif p.is_verified and not p.is_stale():
                        if st.button("Enable Policy", key=f"pen_{p.program_id}"):
                            st.session_state.policy_manager.enable_policy(p.program_id)
                            st.rerun()
                with col_b3:
                    policy_json = st.session_state.policy_manager.export_policy_to_json(p.program_id)
                    st.download_button(
                        "💾 Export Policy JSON",
                        data=policy_json,
                        file_name=f"{p.program_id}_policy.json",
                        mime="application/json",
                        key=f"pdl_{p.program_id}",
                    )
                st.markdown("---")

    # -------------------------------------------------------------
    # TAB 6: Bug Bounty Research Tasks Dashboard
    # -------------------------------------------------------------
    with tab_research:
        st.subheader("🎯 Bug Bounty Research Task Manager")
        st.caption("Manage research tasks, evidence completeness, duplicate reviews, report readiness gates, and submission tracking.")

        policies = st.session_state.policy_manager.list_policies()
        policy_ids = [p.program_id for p in policies]

        if not policy_ids:
            st.warning("No policies configured in registry.")
        else:
            col_sel_p, col_conv = st.columns([2, 1])
            with col_sel_p:
                selected_pid = st.selectbox("Select Target Bug Bounty Program:", policy_ids)
            with col_conv:
                if st.button("➕ Convert Current Findings to Tasks", type="primary"):
                    created_count = 0
                    for f in st.session_state.findings:
                        if not f.research_task_id:
                            st.session_state.research_manager.create_task_from_finding(
                                program_id=selected_pid,
                                finding=f,
                            )
                            created_count += 1
                    st.success(f"Created {created_count} research tasks under '{selected_pid}'!")
                    st.rerun()

            tasks = st.session_state.research_manager.list_tasks(program_id=selected_pid)

            if not tasks:
                st.info(f"No research tasks recorded for '{selected_pid}'. Use button above to convert findings.")
            else:
                st.markdown(f"### Active Research Tasks ({len(tasks)})")

                for t in tasks:
                    with st.container():
                        st.markdown(f"#### [{t.status.value}] {t.title} (`{t.task_id}`)")
                        col_t1, col_t2, col_t3 = st.columns(3)
                        col_t1.markdown(f"**Affected Asset:** `{t.affected_asset}`")
                        col_t2.markdown(f"**Severity:** `{t.severity.value}` | **Confidence:** `{t.confidence.value}`")
                        col_t3.markdown(f"**Report Ready:** {'✅ YES' if t.report_ready else '❌ NO'}")

                        # Evidence Completeness Progress Bar
                        st.markdown(f"**Evidence Completeness Score:** `{t.evidence_completeness_score:.2f}` / `1.00`")
                        st.progress(t.evidence_completeness_score)
                        if not t.report_ready:
                            st.caption(f"**Readiness Audit Notes:** {t.report_readiness_notes}")

                        # Next Verification Step
                        st.markdown(f"**Next Manual Verification Step:** {t.next_manual_verification_step or 'None recorded.'}")

                        # Status and Action Controls
                        col_act1, col_act2, col_act3 = st.columns(3)
                        with col_act1:
                            all_statuses = [s.value for s in ResearchStatus]
                            current_idx = all_statuses.index(t.status.value)
                            new_st_val = st.selectbox("Update Status:", all_statuses, index=current_idx, key=f"st_sel_{t.task_id}")
                            if new_st_val != t.status.value:
                                try:
                                    # Human confirmation for submitted or terminal states
                                    requires_conf = new_st_val in [
                                        ResearchStatus.SUBMITTED_BY_RESEARCHER.value,
                                        ResearchStatus.ACCEPTED.value,
                                        ResearchStatus.REJECTED.value,
                                        ResearchStatus.DUPLICATE.value,
                                        ResearchStatus.RESOLVED.value,
                                    ]
                                    st.session_state.research_manager.update_task_status(
                                        task_id=t.task_id,
                                        new_status=ResearchStatus(new_st_val),
                                        user_confirmed=requires_conf,
                                    )
                                    st.success(f"Status updated to {new_st_val}!")
                                    st.rerun()
                                except Exception as err:
                                    st.error(str(err))

                        with col_act2:
                            with st.popover("📤 Record Official Submission"):
                                st.write("Record manual submission to program team:")
                                sub_dest = st.text_input("Reporting Destination:", value=t.submission_destination, key=f"sdest_{t.task_id}")
                                sub_ref = st.text_input("Report Reference / Ticket #:", value="H1-REPORT-12345", key=f"sref_{t.task_id}")
                                conf_chk = st.checkbox("I confirm I have manually submitted this report to the program destination.", key=f"cchk_{t.task_id}")
                                if st.button("Confirm Submission", key=f"sbtn_{t.task_id}"):
                                    if not conf_chk:
                                        st.error("Human confirmation checkbox required.")
                                    else:
                                        try:
                                            st.session_state.research_manager.record_submission(
                                                task_id=t.task_id,
                                                submission_reference=sub_ref,
                                                submission_destination=sub_dest,
                                                user_confirmed=True,
                                            )
                                            st.success("Submission recorded!")
                                            st.rerun()
                                        except Exception as e_sub:
                                            st.error(str(e_sub))

                        with col_act3:
                            with st.popover("🏁 Record Program Outcome"):
                                st.write("Record program response / triage outcome:")
                                out_choice = st.selectbox("Outcome:", [ResearchStatus.ACCEPTED.value, ResearchStatus.REJECTED.value, ResearchStatus.DUPLICATE.value, ResearchStatus.RESOLVED.value], key=f"out_sel_{t.task_id}")
                                out_notes = st.text_input("Outcome Notes:", value="Accepted by security team.", key=f"onotes_{t.task_id}")
                                conf_out = st.checkbox("I confirm this outcome was communicated by the program.", key=f"c_out_{t.task_id}")
                                if st.button("Save Outcome", key=f"out_btn_{t.task_id}"):
                                    if not conf_out:
                                        st.error("Human confirmation required.")
                                    else:
                                        st.session_state.research_manager.record_outcome(
                                            task_id=t.task_id,
                                            outcome_status=ResearchStatus(out_choice),
                                            notes=out_notes,
                                            user_confirmed=True,
                                        )
                                        st.success("Outcome recorded!")
                                        st.rerun()

                        st.markdown("---")

    # -------------------------------------------------------------
    # TAB 7: Export Verified Reports
    # -------------------------------------------------------------
    with tab_export:
        st.subheader("💾 Export Verified Assessment & Bug Bounty Reports")
        st.caption("Generate publication-ready Markdown, JSON, and CSV reports. Includes policy-aware bug bounty draft generator.")

        # Standard assessment reports
        st.markdown("### 1. General Assessment Reports")
        findings_to_export = st.session_state.findings
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

        json_content = JSONReporter.generate(findings_to_export, st.session_state.target_url)
        with col_json:
            st.download_button(
                label="📥 Download JSON Report",
                data=json_content,
                file_name="verified_appsec_report.json",
                mime="application/json",
                use_container_width=True,
            )

        csv_content = CSVReporter.generate(findings_to_export)
        with col_csv:
            st.download_button(
                label="📥 Download CSV Report",
                data=csv_content,
                file_name="verified_appsec_report.csv",
                mime="text/csv",
                use_container_width=True,
            )

        st.markdown("---")
        # Policy-aware report generator
        st.markdown("### 2. Program-Tailored Bug Bounty Report Draft")
        st.caption("Structures findings into official disclosure format with preconditions, expected vs observed, impact, and sanitized evidence.")

        tasks = st.session_state.research_manager.list_tasks()
        if not tasks:
            st.info("No research tasks recorded. Convert findings to research tasks in Tab 6 first.")
        else:
            task_options = {f"{t.task_id}: {t.title} ({t.status.value})": t for t in tasks}
            sel_t_label = st.selectbox("Select Research Task for Report Generation:", list(task_options.keys()))
            sel_task = task_options[sel_t_label]
            sel_finding = st.session_state.research_manager.get_finding_for_task(sel_task.task_id)
            sel_policy = st.session_state.policy_manager.get_policy(sel_task.program_id)

            if not sel_finding or not sel_policy:
                st.error("Missing finding or policy data for selected task.")
            else:
                rep_gen = PolicyReportGenerator()
                col_exp_chk, col_exp_btn = st.columns([3, 1])

                with col_exp_chk:
                    review_confirmed = st.checkbox(
                        "✍️ I explicitly certify that I have reviewed this report, verified reproducible evidence, and approved it for export.",
                        value=False,
                    )
                    st.caption("Active session cookies, Authorization headers, tokens, private keys, passwords, and PII are automatically redacted.")

                # Generate reports
                tailored_md = rep_gen.generate_markdown(sel_task, sel_finding, sel_policy, researcher_review_confirmed=review_confirmed)
                tailored_json = rep_gen.generate_json(sel_task, sel_finding, sel_policy, researcher_review_confirmed=review_confirmed)

                with col_exp_btn:
                    if review_confirmed:
                        st.download_button(
                            "📥 Download Policy Report (MD)",
                            data=tailored_md,
                            file_name=f"{sel_task.task_id}_disclosure_report.md",
                            mime="text/markdown",
                            use_container_width=True,
                        )
                        st.download_button(
                            "📥 Download Policy Report (JSON)",
                            data=tailored_json,
                            file_name=f"{sel_task.task_id}_disclosure_report.json",
                            mime="application/json",
                            use_container_width=True,
                        )
                    else:
                        st.warning("Confirm researcher review above to enable export.")

                with st.expander("👁️ Preview Policy-Tailored Report Draft", expanded=True):
                    st.markdown(tailored_md)


if __name__ == "__main__":
    main()
