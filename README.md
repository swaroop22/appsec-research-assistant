# 🛡️ AppSec Research Assistant

A modular, defensive web application security analysis assistant written in Python for educational security research, vulnerability analysis, and remediation engineering.

- **Phase 1**: Passive offline HTTP response security analysis via interactive **Streamlit Web Interface**, header and cookie inspection, and CSV/JSON export.
- **Phase 2**: High-fidelity vulnerability analysis quality, confidence scoring, explicit distinction of heuristic indicators from verified vulnerabilities, false positive prevention, sitewide finding deduplication, and loopback scope boundary protection.
- **Phase 3**: Controlled vulnerability research workflow, including:
  - **Program Policy Manager (VDP Scope Control)**: Enforces manual scope verification, safe harbor tracking, authorized assets, rate limits, and fail-closed authorization.
  - **Local Security Testing Workflow**: 6 guided exercises integrating the educational knowledge base and local mock lab using synthetic test accounts and strictly loopback-confined endpoints.
  - **Tiered Finding Verification**: Four distinct verification tiers (`OBSERVATION`, `HEURISTIC_INDICATOR`, `SUSPECTED_VULNERABILITY`, `INDEPENDENTLY_VERIFIED`), reproducible evidence requirements, and status code 200 rule (never inferring critical severity from status code alone).
  - **Human Review & Reporting Workflow**: Comprehensive finding review interface, severity rationales, reproduction steps, automated evidence sanitization (redacting tokens, sessions, passwords), and multi-format exports (Markdown, JSON, CSV) requiring human sign-off before external disclosure.
  - **Hardened Security & Boundary Safeguards**: Proxy leak prevention (`trust_env=False`), local proxy validation, malformed userinfo rejection (`@`), hop-by-hop redirect validation, and fail-closed boundary enforcement with qualified security claims.

---

## 📋 Phase 3 Core Capabilities

### A. Program Policy Manager (`appsec_assistant/policy.py`)
- **Authorized Scope Recording**: Records vulnerability disclosure program (VDP) policies, official program URLs, explicitly authorized target assets, prohibited testing methods, rate limits (requests/sec), reporting instructions, and safe harbor terms.
- **Mandatory Manual Verification**: Program policies are created in an unverified state (`is_verified=False`, `is_enabled=False`). A security researcher must manually review scope and execute `verify_policy(policy_id, reviewer, notes)` before any testing against that program can be enabled.
- **Fail-Closed Authorization**: Targets are never assumed authorized simply because they are public or have a policy entry. Target URLs must pass both `ScopeGuard` loopback boundary checks and `ProgramPolicyManager` scope matching.

### B. Guided Local Security Testing Workflow (`appsec_assistant/knowledge_base.py` & `lab_server.py`)
Integrated hands-on educational exercises restricted strictly to the local mock lab (`http://127.0.0.1:5000`):
1. **`EX-AC-01` (Broken Access Control)**: Unauthenticated access to administrative controls on `/admin`. Demonstrates verified vulnerability proof requirements.
2. **`EX-IDOR-01` (IDOR)**: Direct object reference on `/api/Users/1`. Demonstrates heuristic indicator classification and cross-account evidence requirements.
3. **`EX-AUTH-01` (Authentication)**: Session fixation and weak cookie issuance on `/auth/login`. Uses synthetic test accounts (`Bob`, `Alice`, `Charlie`).
4. **`EX-HDR-01` (Security Headers)**: Missing baseline defensive headers (CSP, HSTS, X-Content-Type-Options) on root `/`.
5. **`EX-CK-01` (Insecure Cookies)**: Missing HttpOnly, Secure, and SameSite attributes on session cookies.
6. **`EX-INP-01` (Input Validation)**: Parameter reflection on `/search?q=query` demonstrating passive observation without automated payload execution.

### C. Finding Verification & Four-Tier Evidence Model
Findings are organized into four explicit, verifiable tiers:
- **`OBSERVATION`**: Contextual technical observations (server banners, reflected parameters, exposed endpoint paths).
- **`HEURISTIC_INDICATOR`**: Architectural patterns or naming conventions (e.g. sequential IDs `/Users/1`) that suggest potential risk but lack cross-account verification proof.
- **`SUSPECTED_VULNERABILITY`**: Absence of defensive controls (missing CSP, unflagged cookies) or probable flaws awaiting multi-step reproduction.
- **`INDEPENDENTLY_VERIFIED`**: Vulnerabilities substantiated with reproducible, end-to-end evidence (e.g. unauthenticated administrative data exposure).

> ⚠️ **Status Code 200 Rule**: The analyzer **never** infers a Critical severity from an HTTP 200 status code alone. Status code 200 responses to sensitive endpoints are checked for login challenges (`OBSERVATION`), then verified privileged content/controls (`INDEPENDENTLY_VERIFIED`, `CRITICAL`), and fall back to low-severity heuristics (`HEURISTIC_INDICATOR`, `LOW`) if the response is neutral.

### D. Human Review & Sanitized Reporting Workflow
- **Review Screen & Sign-Off**: Streamlit tab and CLI flags allow human analysts to review findings, inspect confidence and severity rationales, examine reproduction steps, and sign off (`reviewed_by`, timestamp, notes).
- **Automated Evidence Sanitization**: Sensitive authentication tokens, Bearer JWTs, session IDs, and credentials in headers and response bodies are automatically redacted (`[REDACTED_TOKEN]`, `[REDACTED_SESSION]`, `[REDACTED_SECRET]`) before reporting.
- **Multi-Format Exports**: Exports complete audit reports in **Markdown**, **JSON**, and **CSV** formats, including human review attestation banners and mandatory external submission warnings.

### E. Security Boundary & Quality Hardening
- **Loopback Enforcement**: Active scanning is restricted strictly to loopback interfaces (`localhost`, `127.0.0.1`, `::1`, and RFC 6761 `*.localhost`).
- **Alternate IP Representation Defense**: Automatically decodes and evaluates alternate IP encodings (octal `0177.0.0.1`, hexadecimal `0x7f000001`, dword integers `2130706433`, abbreviated IPv4 `127.1`, and IPv4-mapped IPv6 `[::ffff:127.0.0.1]`).
- **Strict Redirect & Hop Validation**: `SafeHTTPClient` disables automatic redirects and validates every redirect hop (`Location` header). Redirects to external or non-loopback addresses are aborted immediately.
- **Proxy Boundary Hardening**: `SafeHTTPClient` sets `trust_env = False` to prevent ambient environment proxy leakage (`HTTP_PROXY`, `HTTPS_PROXY`), validates configured proxies to ensure they resolve to loopback, and rejects external proxies.
- **Malformed URL Resistance**: Rejects userinfo credential bypasses (`http://localhost@attacker.com`), backslash path traversal tricks (`http://localhost\attacker.com`), out-of-range ports, control characters, and unsupported schemes.
- **Defensible Claims**: Recognizes that application-layer boundaries operate within Python runtime constraints; claims are qualified and tested rather than asserted as absolute.

---

## 📂 Project Structure

```
appsec-research-assistant/
├── app.py                             # 🌐 Streamlit Web Application (5 Phase 3 Tabs)
├── requirements.txt                   # Complete dependencies
├── README.md                          # Full documentation guide
├── sample_audit_report.md             # Example generated markdown audit report
├── .streamlit/
│   └── config.toml                    # Streamlit server and telemetry configurations
├── appsec_assistant/                  # Core package
│   ├── __init__.py
│   ├── models.py                      # FindingTier, ProgramPolicy, VulnerabilityFinding, Evidence Sanitizer
│   ├── policy.py                      # ProgramPolicyManager (VDP scope verification & enforcement)
│   ├── config.py                      # Hardened ScopeGuard (Alternate IPs, DNS, Malformed URLs)
│   ├── client.py                      # SafeHTTPClient with proxy & redirect hop validation
│   ├── engine.py                      # Audit orchestrator with policy enforcement & exercise audit
│   ├── response_parser.py             # Passive HTTP response & cookie parser
│   ├── samples.py                     # Realistic sample HTTP responses for testing
│   ├── knowledge_base.py              # Educational vulnerability encyclopedia & 6 Guided Exercises
│   ├── lab_server.py                  # Local mock practice lab server with synthetic accounts
│   ├── cli.py                         # Rich interactive terminal interface with Phase 3 flags
│   ├── analyzers/                     # Modular security analyzers
│   │   ├── __init__.py
│   │   ├── base.py                    # BaseAnalyzer interface
│   │   ├── headers_analyzer.py        # Audits CSP, HSTS, XCTO, Referrer-Policy, CORS, banners
│   │   ├── cookies_analyzer.py        # Audits Secure, HttpOnly, SameSite, cookie prefixes
│   │   └── access_control_analyzer.py # Access control & IDOR with heuristic vs verified logic
│   └── reporters/                     # Structured reporting
│       ├── __init__.py
│       ├── csv_reporter.py            # CSV reporter with finding tier & review metadata
│       ├── json_reporter.py           # JSON reporter with finding tier & review metadata
│       └── markdown_reporter.py       # Formatted markdown reporter with tier summary & sign-off
└── tests/                             # Automated test suite (58 tests, 100% passing)
    ├── __init__.py
    ├── test_program_policy.py         # Tests VDP policy manager, scope verification, fail-closed
    ├── test_guided_exercises.py       # Tests 6 guided exercises & synthetic lab endpoints
    ├── test_finding_verification_tiers.py # Tests 4-tier model, evidence sanitization, status code 200 rule
    ├── test_security_boundary_deep.py # Deep tests for redirects, DNS, IP normalization, proxies, URLs
    ├── test_scope_guard_hardening.py  # Tests alternate IPs, DNS rebinding, malformed URLs
    ├── test_redirect_boundary.py      # Tests redirect validation & boundary containment
    ├── test_false_positives.py        # Tests login portal false positive prevention & IDOR heuristic
    ├── test_deduplication.py          # Tests sitewide header deduplication
    ├── test_headers_analyzer.py       # Tests security headers
    ├── test_cookies_analyzer.py       # Tests cookie flags
    ├── test_access_control_analyzer.py# Tests access control
    ├── test_response_parser.py        # Tests HTTP response parsing
    ├── test_csv_reporter.py           # Tests CSV export
    ├── test_reporters.py              # Tests markdown and JSON exports
    ├── test_knowledge_base.py         # Tests encyclopedia queries
    └── test_scope_guard.py            # Tests baseline scope validation
```

---

## 🚀 Quickstart & Verification

### 1. Run Automated Unit & Regression Tests (58 Tests)
```bash
pytest tests/
```
Output:
```text
============================== 58 passed in 2.58s ==============================
```

### 2. Launch Streamlit Web Application
```bash
streamlit run app.py
```
Open **`http://localhost:8501`** in your browser to access the 5 workflow tabs:
1. **🔍 Security Analysis & Audit**: Passive response inspection and live local target auditing.
2. **🎓 Guided Lab Exercises**: Run guided exercises with synthetic accounts Bob, Alice, and Charlie.
3. **📋 Finding Review & Human Sign-Off**: Review findings, inspect reproduction steps and sanitized evidence, and sign off with human auditor notes.
4. **📜 Program Policy Manager**: Inspect and manually verify vulnerability disclosure program policies.
5. **📤 Export Verified Reports**: Generate and download human-reviewed audit reports in Markdown, JSON, and CSV formats.

### 3. CLI Workflow Commands
```bash
# List configured VDP policies and scope verification status
python -m appsec_assistant.cli --policies

# List guided educational security exercises
python -m appsec_assistant.cli --exercises

# Execute a specific guided exercise against the practice lab
python -m appsec_assistant.cli --run-exercise EX-AC-01

# Run practice lab audit, apply human review, and export multi-format reports
python -m appsec_assistant.cli --lab --review-all --export-md report.md --export-json report.json
```

---

## ⚠️ Known Limitations & Responsible Use

1. **Defensive & Local Scope Only**: All active testing capabilities are intentionally hardwired to the local loopback boundary (`localhost` / `127.0.0.1`). Scanning remote internet targets is strictly disabled.
2. **No Automated Exploit Execution**: The assistant identifies security vulnerabilities and provides reproducible steps and remediation advice; it does not contain offensive weaponization or automated exploit payloads.
3. **Application-Layer Boundary Caveat**: While `ScopeGuard` and `SafeHTTPClient` defend against alternate IP encodings, DNS rebinding aliases, userinfo tricks, and ambient proxy leaks, application-level Python guards operate inside standard process limits. Defense-in-depth network firewalls and container isolation should be used in production environments.

