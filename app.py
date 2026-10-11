"""
AppSec Research Assistant - Phase 1 Web Application.

A passive HTTP response security analyzer built with Streamlit for defensive
web application security analysis and education.
"""

import streamlit as st
import pandas as pd
from typing import List

from appsec_assistant.models import VulnerabilityFinding, SeverityLevel
from appsec_assistant.response_parser import parse_raw_http_response
from appsec_assistant.analyzers.headers_analyzer import HeadersAnalyzer
from appsec_assistant.analyzers.cookies_analyzer import CookiesAnalyzer
from appsec_assistant.reporters.csv_reporter import CSVReporter
from appsec_assistant.reporters.json_reporter import JSONReporter
from appsec_assistant.samples import SAMPLE_PRESETS


# Configure page settings
st.set_page_config(
    page_title="AppSec Response Analyzer | Phase 1",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for polished interface
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
    .metric-card {
        background-color: #F8FAFC;
        border-radius: 8px;
        padding: 12px 16px;
        border: 1px solid #E2E8F0;
    }
    .badge-high {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-medium {
        background-color: #FEF3C7;
        color: #92400E;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-low {
        background-color: #DCFCE7;
        color: #166534;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-info {
        background-color: #DBEAFE;
        color: #1E40AF;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


def analyze_http_response(raw_text: str, target_url: str) -> tuple:
    """Parses transaction and executes passive header and cookie analyzers."""
    transaction = parse_raw_http_response(raw_text, default_url=target_url)
    
    headers_analyzer = HeadersAnalyzer()
    cookies_analyzer = CookiesAnalyzer()

    findings: List[VulnerabilityFinding] = []
    findings.extend(headers_analyzer.analyze(transaction))
    findings.extend(cookies_analyzer.analyze(transaction))

    # Sort findings by severity rank descending
    sorted_findings = sorted(findings, key=lambda x: x.severity.rank, reverse=True)
    return transaction, sorted_findings


def main():
    st.markdown('<div class="main-header">🛡️ AppSec Research Assistant — Phase 1</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">'
        'Passive Defensive HTTP Response Analyzer for Educational Security Research & Hardening. '
        'Inspects missing security headers and cookie flags without sending external network traffic.'
        '</div>',
        unsafe_allow_html=True
    )

    # Sidebar: Presets & Controls
    with st.sidebar:
        st.header("⚙️ Configuration & Samples")
        
        st.info("🔒 **Scope Safeguard Active**\nPhase 1 performs purely offline, passive inspection of provided HTTP response text. No outbound requests are dispatched.")

        preset_options = ["Custom Input"] + list(SAMPLE_PRESETS.keys())
        selected_preset = st.selectbox(
            "Select Sample HTTP Response:",
            preset_options,
            index=1,  # Default to Insecure Legacy App
            help="Choose a pre-configured realistic HTTP response to instantly evaluate analyzers.",
        )

        preset_content = ""
        if selected_preset != "Custom Input":
            preset_info = SAMPLE_PRESETS[selected_preset]
            st.caption(f"**Scenario:** {preset_info['description']}")
            st.caption(f"**Expected Focus:** {preset_info['expected_issues']}")
            preset_content = preset_info["content"]

        target_url = st.text_input(
            "Target URL Context:",
            value="http://localhost:5000/",
            help="Used for scoping checks such as HSTS enforcement (HTTPS vs HTTP).",
        )

        st.markdown("---")
        st.markdown("### 📚 Standards Covered")
        st.markdown("""
        - **Content-Security-Policy** (CSP)
        - **Strict-Transport-Security** (HSTS)
        - **X-Content-Type-Options** (`nosniff`)
        - **Referrer-Policy**
        - **X-Frame-Options** (Clickjacking)
        - **Cookie Attributes** (`HttpOnly`, `Secure`, `SameSite`)
        - **Information Disclosure** (`Server`, `X-Powered-By`)
        """)

    # Main input area
    st.subheader("📥 Captured HTTP Response Input")
    st.caption("Paste a raw HTTP response (status line, headers, and body) or header block captured from your local test app.")

    # Manage input text via session state or preset
    default_text = preset_content if selected_preset != "Custom Input" else ""
    http_input = st.text_area(
        label="HTTP Response Text",
        value=default_text,
        height=220,
        placeholder="HTTP/1.1 200 OK\nContent-Type: text/html\nSet-Cookie: session_id=abc; Path=/\n...",
        label_visibility="collapsed",
    )

    col_btn, _ = st.columns([1, 4])
    with col_btn:
        run_analysis = st.button("🔍 Analyze Response", type="primary", use_container_width=True)

    if http_input.strip() and (run_analysis or selected_preset != "Custom Input"):
        transaction, findings = analyze_http_response(http_input, target_url)

        st.markdown("---")
        st.subheader("📊 Analysis Findings & Scorecard")

        # Metric counts
        count_high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        count_med = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
        count_low = sum(1 for f in findings if f.severity == SeverityLevel.LOW)
        count_info = sum(1 for f in findings if f.severity == SeverityLevel.INFO)
        total = len(findings)

        # Priority Rule Banner
        st.markdown(
            "> ℹ️ **Priority Policy:** Missing defensive headers are prioritized as **Medium**, **Low**, or **Informational** based on attack surface and defense-in-depth criteria. A missing header is never automatically classified as Critical, as exploitation requires an accompanying vulnerability or interaction."
        )

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total Findings", total)
        m2.metric("High Priority", count_high)
        m3.metric("Medium Priority", count_med)
        m4.metric("Low Priority", count_low)
        m5.metric("Informational", count_info)

        # Tabs for Findings, Parsed Headers/Cookies, and Export
        tab_findings, tab_parsed, tab_export = st.tabs([
            "📋 Findings Table & Details",
            "🔍 Parsed Headers & Cookies",
            "💾 Export Reports (JSON / CSV)"
        ])

        with tab_findings:
            if not findings:
                st.success("🎉 **Outstanding! No security configuration weaknesses detected.** The response enforces modern security headers and hardened cookie flags.")
            else:
                # Severity filter
                sev_options = ["All"] + [s.value for s in SeverityLevel if s.value != "CRITICAL"]
                selected_filter = st.selectbox("Filter Findings by Priority:", sev_options, index=0)

                filtered_findings = findings
                if selected_filter != "All":
                    filtered_findings = [f for f in findings if f.severity.value == selected_filter]

                # Tabular view
                table_rows = []
                for f in filtered_findings:
                    table_rows.append({
                        "ID": f.finding_id,
                        "Priority": f.severity.value,
                        "Title": f.title,
                        "Category": f.category,
                        "CWE": f.cwe_id or "N/A",
                        "OWASP": f.owasp_category or "N/A",
                    })

                df = pd.DataFrame(table_rows)
                st.dataframe(df, use_container_width=True, hide_index=True)

                st.markdown("### 🔎 Detailed Explanations & Actionable Remediations")
                for f in filtered_findings:
                    badge_color = {
                        SeverityLevel.HIGH: "badge-high",
                        SeverityLevel.MEDIUM: "badge-medium",
                        SeverityLevel.LOW: "badge-low",
                        SeverityLevel.INFO: "badge-info",
                    }.get(f.severity, "badge-info")

                    header_label = f"[{f.severity.value}] {f.title} ({f.finding_id})"
                    with st.expander(header_label, expanded=(f.severity == SeverityLevel.HIGH)):
                        st.markdown(f"**Priority:** <span class='{badge_color}'>{f.severity.value}</span> &nbsp;&nbsp;|&nbsp;&nbsp; **Category:** `{f.category}` &nbsp;&nbsp;|&nbsp;&nbsp; **CWE:** `{f.cwe_id or 'N/A'}`", unsafe_allow_html=True)
                        
                        st.markdown(f"**Why this Priority?**\n{f.priority_rationale}")

                        col_desc, col_imp = st.columns(2)
                        with col_desc:
                            st.markdown("#### 📖 Plain English Explanation")
                            st.write(f.description)
                        with col_imp:
                            st.markdown("#### ⚠️ Potential Security Impact")
                            st.write(f.impact)

                        st.markdown("#### 🔬 Observed Evidence")
                        st.code(f.evidence, language="http")

                        st.markdown("#### 🛠️ Recommended Remediation")
                        st.markdown(f.remediation)

                        if f.references:
                            st.markdown("#### 🔗 References & Guidelines")
                            for ref in f.references:
                                st.markdown(f"- [{ref}]({ref})")

        with tab_parsed:
            col_h, col_c = st.columns(2)
            with col_h:
                st.markdown("#### Response Headers")
                st.caption(f"Status Code: `{transaction.status_code}`")
                if transaction.response_headers:
                    h_df = pd.DataFrame([
                        {"Header Name": k, "Header Value": v}
                        for k, v in transaction.response_headers.items()
                    ])
                    st.dataframe(h_df, use_container_width=True, hide_index=True)
                else:
                    st.write("No headers parsed.")

            with col_c:
                st.markdown("#### Parsed Cookies & Security Attributes")
                if transaction.cookies:
                    cookie_data = []
                    for c in transaction.cookies:
                        cookie_data.append({
                            "Cookie Name": c.get("name", ""),
                            "Value": c.get("value", "")[:20] + "..." if len(c.get("value", "")) > 20 else c.get("value", ""),
                            "HttpOnly": "✅ Yes" if c.get("httponly") else "❌ No",
                            "Secure": "✅ Yes" if c.get("secure") else "❌ No",
                            "SameSite": c.get("samesite") or "❌ Missing",
                            "Path": c.get("path", "/"),
                        })
                    c_df = pd.DataFrame(cookie_data)
                    st.dataframe(c_df, use_container_width=True, hide_index=True)
                else:
                    st.info("No `Set-Cookie` headers found in this response.")

        with tab_export:
            st.markdown("### 💾 Export Vulnerability Assessment Reports")
            st.write("Export findings as structured reports for documentation, ticket tracking, and developer handoff.")

            col_csv, col_json = st.columns(2)

            csv_data = CSVReporter.generate(findings)
            with col_csv:
                st.download_button(
                    label="📥 Download CSV Report",
                    data=csv_data,
                    file_name="appsec_findings_report.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
                st.caption("Includes all finding columns, severity rationale, CWEs, and remediation steps formatted for spreadsheets.")

            json_data = JSONReporter.generate(findings, target_url)
            with col_json:
                st.download_button(
                    label="📥 Download JSON Report",
                    data=json_data,
                    file_name="appsec_findings_report.json",
                    mime="application/json",
                    use_container_width=True,
                )
                st.caption("Machine-readable JSON schema suitable for CI/CD integration and security automation pipelines.")

            with st.expander("Preview JSON Export"):
                st.code(json_data, language="json")


if __name__ == "__main__":
    main()
