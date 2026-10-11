# 🛡️ AppSec Research Assistant

A modular, defensive web application security analysis assistant written in Python for educational security research, vulnerability analysis, and remediation engineering.

The tool audits HTTP request/response traffic against local training environments (such as **OWASP Juice Shop** or the built-in offline practice lab), identifies security weaknesses, explains the underlying vulnerability mechanisms, and generates professional vulnerability reports.

---

## 🔒 Scope Safeguards & Safety Boundaries

This assistant is engineered exclusively for **defensive application security research and education**. It features an automated `ScopeGuard`:
- **Strict Loopback Boundary**: All active HTTP audits are enforced to run only against authorized loopback targets (`localhost`, `127.0.0.1`, `::1`).
- **External Domain Block**: Any attempt to target public or external domains (e.g. `example.com`, production APIs) is automatically blocked with a `ScopeViolationError`.
- **Deliberate Rate Limiting**: Built-in request pacing prevents aggressive or destabilizing traffic bursts.

---

## 📂 Project Structure

```
appsec-research-assistant/
├── README.md                      # Beginner-friendly documentation & guide
├── requirements.txt               # Project dependencies
├── sample_audit_report.md         # Example generated audit report
├── appsec_assistant/              # Core package
│   ├── __init__.py
│   ├── config.py                  # Scope guard & boundary validation
│   ├── models.py                  # Data models (VulnerabilityFinding, SeverityLevel, etc.)
│   ├── client.py                  # Safe HTTP client with scope enforcement
│   ├── engine.py                  # Audit orchestrator & finding aggregation
│   ├── knowledge_base.py          # Educational encyclopedia (IDOR, XSS, SQLi, Auth, BAC)
│   ├── lab_server.py              # Zero-dependency local mock lab server (port 5000)
│   ├── cli.py                     # Rich interactive console & CLI tool
│   ├── analyzers/                 # Modular security analyzers
│   │   ├── __init__.py
│   │   ├── base.py                # BaseAnalyzer abstract interface
│   │   ├── headers_analyzer.py    # Audits CSP, HSTS, XFO, nosniff, CORS, server banners
│   │   ├── cookies_analyzer.py    # Audits Secure, HttpOnly, SameSite cookie flags
│   │   └── access_control_analyzer.py # Audits IDOR indicators & unauthenticated admin routes
│   └── reporters/                 # Vulnerability reporting engine
│       ├── __init__.py
│       ├── markdown_reporter.py   # Formatted markdown report generator
│       └── json_reporter.py       # Structured JSON report generator
└── tests/                         # Automated unit test suite
    ├── __init__.py
    ├── test_scope_guard.py
    ├── test_headers_analyzer.py
    ├── test_cookies_analyzer.py
    ├── test_access_control_analyzer.py
    ├── test_knowledge_base.py
    └── test_reporters.py
```

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
- Python 3.7+ installed.

### 2. Setup Virtual Environment & Dependencies
```bash
cd appsec-research-assistant

# Create a local virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

### 1. Interactive Menu (Recommended)
Launch the interactive terminal interface:
```bash
python -m appsec_assistant.cli
```

The interactive menu lets you:
1. **Audit Built-in Practice Lab** (`http://127.0.0.1:5000`): Runs immediately without needing Docker or external software.
2. **Audit OWASP Juice Shop** (`http://localhost:3000`): Audits your local Juice Shop container or instance.
3. **Audit Custom Local Endpoint**: Inspect any custom endpoint on `localhost`.
4. **View Findings & Evidence**: Browse discovered issues with reproduction steps, severity, and CWE codes.
5. **Export Report**: Export a vulnerability assessment report to Markdown or JSON.
6. **Explore Knowledge Base**: Read deep-dive guides explaining IDOR, XSS, SQLi, Authentication Flaws, and Broken Access Control with code-level fixes.
7. **Test Scope Guard**: Verify that safeguards block attempts to scan external domains.

---

### 2. Command-Line Options (Scripted Mode)

#### Run against the built-in practice lab and export Markdown report:
```bash
python -m appsec_assistant.cli --lab --export-md my_lab_report.md
```

#### Run against a running local OWASP Juice Shop:
```bash
python -m appsec_assistant.cli --target http://localhost:3000 --export-md juice_shop_report.md
```

#### Query the educational vulnerability knowledge base:
```bash
python -m appsec_assistant.cli --guide idor
python -m appsec_assistant.cli --guide xss
python -m appsec_assistant.cli --guide sqli
python -m appsec_assistant.cli --guide auth
python -m appsec_assistant.cli --guide broken_access_control
```

---

## 🧃 Running with OWASP Juice Shop

To test the assistant against OWASP Juice Shop:

1. **Start Juice Shop using Docker**:
   ```bash
   docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
   ```
   *(Or using Node.js: clone [juice-shop](https://github.com/juice-shop/juice-shop) and run `npm start`)*

2. **Verify Juice Shop is running**:
   Open `http://localhost:3000` in your browser.

3. **Run the Audit**:
   ```bash
   python -m appsec_assistant.cli --target http://localhost:3000 --export-md juice_shop_audit.md
   ```

---

## 🧪 Running Unit Tests

Run the comprehensive unit test suite:
```bash
pytest tests/
```

All tests run locally in memory without making external network calls.

---

## 📚 Vulnerability Concepts Covered

| Vulnerability | OWASP Top 10 | CWE | Detection / Defensive Focus |
| :--- | :--- | :--- | :--- |
| **Insecure Direct Object References (IDOR)** | A01:2021 | CWE-639 | Predictable sequential IDs in URLs/APIs, object ownership verification |
| **Broken Access Control** | A01:2021 | CWE-284, CWE-306 | Unauthenticated administrative endpoints, role-based access control |
| **Security Headers Misconfiguration** | A05:2021 | CWE-1021, CWE-16 | Missing or weak CSP, X-Frame-Options (Clickjacking), X-Content-Type-Options |
| **Cookie State Flaws** | A05:2021 | CWE-1004, CWE-614, CWE-1275 | Missing `HttpOnly`, `Secure`, and `SameSite` flags on session tokens |
| **Cross-Site Scripting (XSS)** | A03:2021 | CWE-79 | Reflected, Stored, DOM XSS, context-aware encoding, nonce-based CSP |
| **SQL Injection (SQLi)** | A03:2021 | CWE-89 | Query concatenation vs Parameterized Queries / Prepared Statements |
| **Authentication & Session Flaws** | A07:2021 | CWE-287 | Session fixation, brute force exposure, token entropy & lifecycle |

---

## ⚖️ Defensive & Ethical Research Guidelines

- **Authorization First**: Never test an application or API without explicit, authorized permission.
- **Local Labs**: Always learn and validate security concepts on intentionally vulnerable applications (e.g. OWASP Juice Shop, WebGoat, DVWA, or the built-in practice lab).
- **Constructive Remediation**: Professional security researchers focus on providing reproducible evidence, accurate risk assessments, and actionable engineering fixes to help developers secure their code.
