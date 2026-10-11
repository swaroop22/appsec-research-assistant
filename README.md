# 🛡️ AppSec Research Assistant

A modular, defensive web application security analysis assistant written in Python for educational security research, vulnerability analysis, and remediation engineering.

- **Phase 1**: Passive offline HTTP response security analysis via interactive **Streamlit Web Interface**, header and cookie inspection, and CSV/JSON export.
- **Phase 2**: High-fidelity vulnerability analysis quality, confidence scoring, explicit distinction of heuristic indicators from verified vulnerabilities, false positive prevention, sitewide finding deduplication, and an unbypassable loopback scope boundary with redirect and alternate IP defense.

---

## 🔒 Scope Safeguards & Boundary Containment (Phase 2 Hardened)

This assistant is engineered exclusively for **defensive application security research and education**:
- **Loopback Enforcement**: Active scanning is restricted strictly to loopback interfaces (`localhost`, `127.0.0.1`, `::1`, and RFC 6761 `*.localhost`).
- **Alternate IP Representation Defense**: Automatically decodes and evaluates alternate IP encodings (octal `0177.0.0.1`, hexadecimal `0x7f000001`, dword integers `2130706433`, abbreviated IPv4 `127.1`, and IPv4-mapped IPv6 `[::ffff:127.0.0.1]`). Non-loopback representations (such as cloud metadata `169.254.169.254`, `0251.0376.0251.0376`, private subnets `10.0.0.1`, `192.168.1.1`, or `0.0.0.0`) are strictly blocked.
- **DNS Rebinding & Public Alias Protection**: Public hostnames (e.g. `localtest.me` or `127.0.0.1.nip.io`) are disallowed even if their public DNS resolves to loopback, preventing DNS rebinding and eliminating external network DNS leakage.
- **Strict Redirect Validation**: `SafeHTTPClient` disables automatic redirects and evaluates every redirect hop (`Location` header). Any attempt to redirect to an external or out-of-scope host (e.g. `https://example.com/` or `http://169.254.169.254/`) is intercepted and aborted with a `ScopeViolationError`.
- **Malformed URL Resistance**: Rejects userinfo credential bypasses (`http://localhost@attacker.com`), backslash path traversal tricks (`http://localhost\attacker.com`), out-of-range ports, control characters, and unsupported schemes.

---

## 🎯 Vulnerability Analysis Quality (Phase 2)

### 1. Confidence Scores (Separate from Severity)
Findings are rated with two independent metrics:
- **Severity**: Potential business and technical impact if present (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Confidence**: Certainty and reproducibility of the finding:
  - **`CONFIRMED`**: Verified through reproducible supporting evidence (e.g., unauthenticated access to admin data returning HTTP 200).
  - **`HIGH`**: Deterministic observation (e.g., missing security headers or missing cookie flags directly inspected in response).
  - **`MEDIUM`**: Probable vulnerability requiring contextual review.
  - **`LOW`**: Low certainty, potential edge case.
  - **`HEURISTIC`**: Architectural pattern or design observation (e.g., sequential resource ID).

### 2. Heuristic Indicators vs. Verified Vulnerabilities
- **IDOR Pattern Detection**: Seeing `/api/Users/1` or `/rest/basket/5` is classified as a **Heuristic Indicator** (`FindingType.HEURISTIC`, `ConfidenceLevel.HEURISTIC`, `SeverityLevel.LOW`). The report explicitly clarifies that sequential IDs are a design indicator, not confirmed unauthorized access without multi-account proof.
- **Administrative Access**:
  - If `/admin` returns HTTP 200 with privileged data/controls and no login challenge: flagged as **Verified Vulnerability** (`FindingType.VERIFIED`, `ConfidenceLevel.CONFIRMED`, `SeverityLevel.CRITICAL`).
  - If `/admin` or `/admin/login` returns an HTML login form (`<input type="password">`): identified as an **Authentication Portal**, preventing false positives.
  - If `/admin` returns HTTP 401 or 403: access control is confirmed intact; no finding is emitted.
- **Static Asset Exclusions**: Files like `/items/1.png` or `/users/avatar.jpg` are filtered out from IDOR checks.

### 3. Report Deduplication & Evidence Quality
- **Sitewide Header Consolidation**: When auditing multi-page applications or suites, sitewide missing headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Server banners) are consolidated into a single finding tracking all `affected_urls`, eliminating report bloat.
- **Reproducible Evidence**: Evidence includes HTTP method, response status, header excerpts, and body snippets proving the condition.

---

## 📂 Project Structure

```
appsec-research-assistant/
├── app.py                             # 🌐 Streamlit Web Application (Phase 1 & 2 UI)
├── requirements.txt                   # Complete dependencies
├── README.md                          # Full documentation guide
├── sample_audit_report.md             # Example generated markdown audit report
├── .streamlit/
│   └── config.toml                    # Streamlit server and telemetry configurations
├── appsec_assistant/                  # Core package
│   ├── __init__.py
│   ├── models.py                      # Data models: ConfidenceLevel, FindingType, SeverityLevel
│   ├── config.py                      # Hardened ScopeGuard (Alternate IPs, DNS, Malformed URLs)
│   ├── client.py                      # SafeHTTPClient with redirect hop validation
│   ├── engine.py                      # Audit orchestrator with sitewide deduplication
│   ├── response_parser.py             # Passive HTTP response & cookie parser
│   ├── samples.py                     # Realistic sample HTTP responses for testing
│   ├── knowledge_base.py              # Educational vulnerability encyclopedia
│   ├── lab_server.py                  # Local mock practice lab server with test endpoints
│   ├── cli.py                         # Rich interactive terminal interface
│   ├── analyzers/                     # Modular security analyzers
│   │   ├── __init__.py
│   │   ├── base.py                    # BaseAnalyzer interface
│   │   ├── headers_analyzer.py        # Audits CSP, HSTS, XCTO, Referrer-Policy, CORS, banners
│   │   ├── cookies_analyzer.py        # Audits Secure, HttpOnly, SameSite, cookie prefixes
│   │   └── access_control_analyzer.py # Access control & IDOR with heuristic vs verified logic
│   └── reporters/                     # Structured reporting
│       ├── __init__.py
│       ├── csv_reporter.py            # CSV report generator with confidence scores
│       ├── json_reporter.py           # JSON report generator with confidence scores
│       └── markdown_reporter.py       # Formatted markdown report generator
└── tests/                             # Automated test suite (35 tests, 100% passing)
    ├── __init__.py
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

### 1. Run Automated Unit Tests (35 Tests)
```bash
pytest tests/
```
Output:
```text
============================== 35 passed in 0.90s ==============================
```

### 2. Launch Streamlit Web Application
```bash
streamlit run app.py
```
Open **`http://localhost:8501`** in your browser:
- Test sample presets or paste captured responses.
- Review findings table with **Priority**, **Confidence**, and **Finding Type** columns.
- Download reports as **CSV** or **JSON**.

### 3. Run Practice Lab Audit via CLI
```bash
python -m appsec_assistant.cli --lab
```
Executes against the built-in mock lab (`http://127.0.0.1:5000`), demonstrating sitewide header deduplication, verified admin access on `/admin`, login portal handling on `/admin/login`, and IDOR heuristic classification.
