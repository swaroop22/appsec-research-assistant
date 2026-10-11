# 🛡️ AppSec Research Assistant

A modular, defensive web application security analysis assistant written in Python for educational security research, vulnerability analysis, and remediation engineering.

Phase 1 features a **Streamlit Web Interface** for **passive offline HTTP response security analysis**. It accepts HTTP responses captured from local test applications or practice labs, analyzes them for missing security headers and cookie flags, explains each finding in plain English, provides actionable remediation snippets, and exports findings to **CSV** or **JSON**.

---

## 🔒 Scope Safeguards & Safety Boundaries

This assistant is engineered exclusively for **defensive application security research and education**:
- **Purely Passive Offline Analysis**: In Phase 1, no requests are dispatched to external websites or remote endpoints. All analysis occurs locally against captured HTTP response text.
- **Strict Loopback Boundary**: For active audits in subsequent modules, the assistant enforces local loopback restrictions (`localhost`, `127.0.0.1`, `::1`). External targets are strictly blocked.
- **Proportional Priority Assignment**: Missing defensive headers are prioritized as **Medium**, **Low**, or **Informational** with clear explanations. A missing header is **never automatically labeled as a Critical vulnerability**, as exploitation requires an accompanying injection flaw or active adversary.

---

## 📂 Project Structure

```
appsec-research-assistant/
├── app.py                         # 🌐 Streamlit Web Application (Phase 1 UI)
├── requirements.txt               # Project dependencies
├── README.md                      # Complete installation & user guide
├── sample_audit_report.md         # Example generated audit report
├── .streamlit/
│   └── config.toml                # Headless & telemetry configurations
├── appsec_assistant/              # Core package
│   ├── __init__.py
│   ├── models.py                  # Models: VulnerabilityFinding, HTTPTransaction, SeverityLevel
│   ├── response_parser.py         # HTTP response & cookie parser (raw text, headers, JSON)
│   ├── samples.py                 # Realistic sample HTTP responses & presets for testing
│   ├── config.py                  # Scope guard & boundary validation
│   ├── client.py                  # Safe HTTP client with scope enforcement
│   ├── engine.py                  # Audit orchestrator & finding aggregation
│   ├── knowledge_base.py          # Educational encyclopedia (IDOR, XSS, SQLi, Auth, BAC)
│   ├── lab_server.py              # Zero-dependency local mock lab server (port 5000)
│   ├── cli.py                     # Rich interactive console & CLI tool
│   ├── analyzers/                 # Modular security analyzers
│   │   ├── __init__.py
│   │   ├── base.py                # BaseAnalyzer abstract interface
│   │   ├── headers_analyzer.py    # Audits CSP, HSTS, XCTO, Referrer-Policy, XFO, CORS, banners
│   │   ├── cookies_analyzer.py    # Audits Secure, HttpOnly, SameSite flags, __Host- prefixes
│   │   └── access_control_analyzer.py # Audits IDOR indicators & unauthenticated admin routes
│   └── reporters/                 # Vulnerability reporting engine
│       ├── __init__.py
│       ├── csv_reporter.py        # Structured CSV report generator
│       ├── json_reporter.py       # Structured JSON report generator
│       └── markdown_reporter.py   # Formatted markdown report generator
└── tests/                         # Automated unit test suite (100% passing)
    ├── __init__.py
    ├── test_response_parser.py    # Tests raw HTTP & JSON parser
    ├── test_csv_reporter.py       # Tests CSV export formatting
    ├── test_headers_analyzer.py   # Tests headers (CSP, HSTS, XCTO, Referrer-Policy)
    ├── test_cookies_analyzer.py   # Tests cookie attributes (Secure, HttpOnly, SameSite)
    ├── test_access_control_analyzer.py
    ├── test_knowledge_base.py
    ├── test_reporters.py
    └── test_scope_guard.py
```

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
- Python 3.7+ installed.

### 2. Setup Virtual Environment
```bash
# Clone the repository (or navigate into the directory)
cd appsec-research-assistant

# Create a Python virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate       # On Linux/macOS
# or: .venv\Scripts\activate   # On Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🌐 Running Phase 1 (Streamlit Web Interface)

To launch the web interface:

```bash
streamlit run app.py
```

The application will start locally at **`http://localhost:8501`**.

### Features in the Web Interface:
1. **Sample HTTP Response Presets**: Use the sidebar dropdown to instantly load realistic presets:
   - *Insecure Legacy App (PHP/Apache)*: Missing all security headers; cookies lack `HttpOnly`, `Secure`, and `SameSite`.
   - *Express API with CORS & Cookie Flaws*: Wildcard CORS origin `*`, JWT cookie missing `HttpOnly`.
   - *Partially Configured App*: Contains weak CSP directives (`'unsafe-inline'`, `'unsafe-eval'`) and permissive Referrer-Policy.
   - *Fully Hardened Enterprise App*: Enforces strict CSP with nonces, HSTS preload, strict-origin Referrer-Policy, and `__Host-` prefixed cookies.
2. **Custom Input**: Paste any raw HTTP response (status line, headers, and body) or header block captured from your local app, proxy, or DevTools.
3. **Interactive Findings Scorecard**: View total issues categorized by High, Medium, Low, and Informational priority.
4. **Detailed Vulnerability Cards**: Expand each finding to review:
   - Plain English description
   - Potential impact and threat model
   - Observed evidence snippet
   - Copyable defensive remediation code blocks
   - Rationale explaining the assigned priority
   - OWASP Top 10 and CWE references
5. **Parsed Headers & Cookies Table**: Inspect all parsed headers and cookie security flags in clean tabular format.
6. **One-Click Report Export**: Download findings as **CSV** (for spreadsheets and tickets) or **JSON** (for automation and pipelines).

---

## 🎯 Security Standards Evaluated (Phase 1)

### 1. Security Headers
| Header | Default Severity | CWE | Defense-in-Depth Rationale |
| :--- | :--- | :--- | :--- |
| **Content-Security-Policy (CSP)** | **MEDIUM** | CWE-1021 | Mitigates Cross-Site Scripting (XSS) and data injection by restricting executable script contexts. Not Critical alone without an injection flaw. |
| **X-Content-Type-Options: nosniff** | **LOW** | CWE-16 | Prevents MIME-confusion attacks and executable file-upload misinterpretation. |
| **Strict-Transport-Security (HSTS)** | **MEDIUM / LOW** | CWE-523 | Protects against SSL stripping and man-in-the-middle downgrades on HTTPS. |
| **Referrer-Policy** | **LOW** | CWE-116 | Prevents browsers from leaking private path tokens in HTTP `Referer` headers to external domains. |
| **X-Frame-Options / frame-ancestors** | **MEDIUM** | CWE-1021 | Defends against Clickjacking (UI Redressing) by controlling iframing permissions. |
| **Permissions-Policy** | **INFORMATIONAL** | CWE-16 | Proactively restricts browser device APIs (camera, microphone, geolocation). |
| **Server / X-Powered-By Banners** | **LOW** | CWE-200 | Eliminates software version leakage that assists attacker reconnaissance. |

### 2. Cookie Security Flags
| Attribute | Priority | CWE | Defensive Purpose |
| :--- | :--- | :--- | :--- |
| **HttpOnly** | **HIGH** *(sensitive)* / **MEDIUM** | CWE-1004 | Blocks JavaScript access (`document.cookie`) to prevent session theft via XSS. |
| **Secure** | **MEDIUM** *(sensitive)* / **LOW** | CWE-614 | Ensures cookie is only transmitted over encrypted TLS (HTTPS) channels. |
| **SameSite** | **MEDIUM** | CWE-1275 | Restricts cross-site transmission to defend against Cross-Site Request Forgery (CSRF). |
| **Prefixes (`__Host-`)** | **INFORMATIONAL** | CWE-16 | Prevents cookie tossing and subdomain spoofing. |

---

## 🧪 Running Automated Unit Tests

Run the full pytest suite locally:

```bash
pytest tests/
```

All 22 unit tests run offline in memory in under 1 second without making network calls.

---

## 💻 Alternative Terminal Interface (CLI & Mock Lab)

The project also includes a terminal CLI tool with a built-in offline lab server:

```bash
# Run audit against the offline practice lab
python -m appsec_assistant.cli --lab

# Run interactive terminal menu
python -m appsec_assistant.cli

# Query educational vulnerability knowledge base
python -m appsec_assistant.cli --guide idor
python -m appsec_assistant.cli --guide xss
```
