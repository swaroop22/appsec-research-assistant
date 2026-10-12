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
- **Phase 4**: AI-Assisted Vulnerability Triage Layer, including:
  - **Modular AI Provider Abstraction**: Pluggable providers (`mock`, `openai`, `anthropic`, `gemini`, `local`) with secure credential loading from environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`) or in-app configuration.
  - **Mandatory User Consent & Privacy**: External providers are blocked from receiving finding data unless explicit user consent is given (`consent_given=True`). Fails closed or safely defaults to the offline deterministic mock provider.
  - **Evidence-Grounded Finding Analysis**: Explains findings in plain English, extracts observed evidence, analyzes why evidence matters, estimates realistic impact, considers alternative explanations (e.g. dev proxy, CDN offloading), flags missing info, and provides verification steps.
  - **Distinct Metrics (Confidence vs. Severity vs. Priority)**:
    - **Confidence**: Strength and certainty of observed evidence.
    - **Severity**: Potential technical and business impact if vulnerability is real.
    - **Priority**: Recommended order in which a researcher should investigate findings.
  - **Strict Safety Guardrails & Tier Clamp**: The AI model is strictly prohibited from promoting heuristics or observations to `INDEPENDENTLY_VERIFIED` without reproducible execution proof.
  - **Fabrication Defense**: Validates evidence references against the original finding and strips hallucinated URLs or credentials.
  - **Prompt-Injection Defense**: Untrusted finding content, HTML, and HTTP bodies are isolated within explicit `<untrusted_data_boundary>` delimiters with directive neutralization.
  - **Semantic Duplicate Detection**: Identifies findings sharing underlying root causes (e.g. multi-endpoint cookies or sequential IDs), presenting similarity rationales with human approval required before merging.
  - **Preserved Finding Context**: Merging approved duplicates preserves all affected URLs, full evidence, timestamps, and analyzer identifiers.

---

## 🤖 Phase 4 AI-Assisted Triage Architecture

```
                                  ┌─────────────────────────────┐
                                  │   Deterministic Findings    │
                                  │  (Headers, Cookies, Access) │
                                  └──────────────┬──────────────┘
                                                 │
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                   AIService Orchestrator                                │
│                                                                                         │
│  [Consent Guard] ──► Requires explicit consent before calling external LLMs            │
│  [Provider Router] ──► Mock (Offline) | OpenAI | Anthropic | Gemini | Local (Loopback)  │
│  [Untrusted Boundary] ──► Neutralizes prompt injection in headers/HTML payloads         │
│  [Schema Validator] ──► Enforces JSON Schema, strips hallucinated URLs & fake evidence  │
│  [Tier Guardrail] ──► Clamps heuristic-to-verified promotion attempts                   │
└────────────────────────────────────────┬────────────────────────────────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
┌──────────────────────────────────┐            ┌──────────────────────────────────┐
│     Evidence-Grounded Triage     │            │    Semantic Duplicate Review     │
│ - Plain-English explanation      │            │ - Identifies shared root causes  │
│ - Why evidence matters           │            │ - Similarity scores & rationales │
│ - Realistic potential impact     │            │ - Human approval required        │
│ - Alternative explanations       │            │ - Preserves all affected URLs    │
│ - Missing verification info      │            │ - Preserves all evidence         │
│ - Recommended review priority    │            └──────────────────────────────────┘
│ - Potential false positive flag  │
└──────────────────────────────────┘
```

---

## 📂 Project Structure

```
appsec-research-assistant/
├── app.py                             # 🌐 Streamlit Web Application (6 Phase 4 Tabs)
├── requirements.txt                   # Complete dependencies
├── README.md                          # Full documentation guide
├── sample_audit_report.md             # Example generated markdown audit report with AI triage
├── .streamlit/
│   └── config.toml                    # Streamlit server and telemetry configurations
├── appsec_assistant/                  # Core package
│   ├── __init__.py
│   ├── models.py                      # FindingTier, ProgramPolicy, VulnerabilityFinding, ai_triage field
│   ├── policy.py                      # ProgramPolicyManager (VDP scope verification & enforcement)
│   ├── config.py                      # Hardened ScopeGuard (Alternate IPs, DNS, Malformed URLs)
│   ├── client.py                      # SafeHTTPClient with proxy & redirect hop validation
│   ├── engine.py                      # Audit orchestrator with policy enforcement & exercise audit
│   ├── response_parser.py             # Passive HTTP response & cookie parser
│   ├── samples.py                     # Realistic sample HTTP responses for testing
│   ├── knowledge_base.py              # Educational vulnerability encyclopedia & 6 Guided Exercises
│   ├── lab_server.py                  # Local mock practice lab server with synthetic accounts
│   ├── cli.py                         # Rich interactive terminal interface with AI triage flags
│   ├── ai/                            # 🤖 AI-Assisted Triage Layer (Phase 4)
│   │   ├── __init__.py
│   │   ├── models.py                  # PriorityLevel, AITriageResult, DuplicateSuggestion, AIProviderConfig
│   │   ├── validator.py               # JSON schema validation, grounding, tier clamping, injection defense
│   │   ├── providers.py               # Modular providers: Mock, OpenAI, Anthropic, Gemini, Local
│   │   └── service.py                 # AIService orchestrator, consent enforcement, duplicate merge
│   ├── analyzers/                     # Modular security analyzers
│   │   ├── __init__.py
│   │   ├── base.py                    # BaseAnalyzer interface
│   │   ├── headers_analyzer.py        # Audits CSP, HSTS, XCTO, Referrer-Policy, CORS, banners
│   │   ├── cookies_analyzer.py        # Audits Secure, HttpOnly, SameSite, cookie prefixes
│   │   └── access_control_analyzer.py # Access control & IDOR with heuristic vs verified logic
│   └── reporters/                     # Structured reporting
│       ├── __init__.py
│       ├── csv_reporter.py            # CSV reporter with AI priority and false positive columns
│       ├── json_reporter.py           # JSON reporter with complete AI triage serialization
│       └── markdown_reporter.py       # Formatted markdown reporter with AI triage analysis blocks
└── tests/                             # Automated test suite (76 tests, 100% passing)
    ├── __init__.py
    ├── test_ai_provider_abstraction.py # Tests providers, credential handling, timeouts, consent
    ├── test_ai_triage_validation.py   # Tests JSON schema, tier clamp, evidence grounding, injection
    ├── test_ai_duplicate_detection.py # Tests semantic similarity, human approval, evidence preservation
    ├── test_ai_service_integration.py # Tests end-to-end audit with AI triage and report formats
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

### 1. Run Automated Unit & Regression Tests (76 Tests)
```bash
pytest tests/
```
Output:
```text
============================== 76 passed in 2.76s ==============================
```

### 2. Launch Streamlit Web Application
```bash
streamlit run app.py
```
Open **`http://localhost:8501`** in your browser to access the 6 workflow tabs:
1. **🔬 Security Analysis & Audit**: Passive response inspection, local auditing, and instant AI triage.
2. **🎓 Guided Lab Exercises**: 6 guided exercises using synthetic test accounts Bob, Alice, and Charlie.
3. **🤖 AI Triage & Analysis**: Evidence-grounded explanations, false positive detection, review prioritization, and semantic duplicate reviews.
4. **📋 Finding Review & Human Sign-Off**: Review findings, inspect reproduction steps and sanitized evidence, and sign off as a human auditor.
5. **📜 Program Policy Manager**: Inspect and manually verify vulnerability disclosure program policies.
6. **💾 Export Verified Reports**: Download verified Markdown, JSON, and CSV reports.

### 3. CLI Workflow Commands
```bash
# Run local lab audit with AI triage and semantic duplicate analysis
python -m appsec_assistant.cli --lab --ai-triage --ai-duplicates

# Run audit, mark human review, and export multi-format reports
python -m appsec_assistant.cli --lab --ai-triage --review-all --export-md report.md --export-json report.json

# Execute specific guided exercise (e.g. Broken Access Control)
python -m appsec_assistant.cli --run-exercise EX-AC-01

# List configured VDP policies
python -m appsec_assistant.cli --policies
```

---

## ⚠️ Known Limitations & Responsible Use

1. **Defensive & Local Scope Only**: All active testing capabilities are intentionally hardwired to the local loopback boundary (`localhost` / `127.0.0.1`). Scanning remote internet targets is strictly disabled.
2. **AI Decision-Support Only**: The AI triage layer is designed strictly for assistance, summarization, and prioritization. It never makes autonomous network requests, executes exploits, modifies scopes, or confirms vulnerabilities without reproducible proof.
3. **External Consent Required**: Data is never sent to third-party language models without explicit configuration and consent. The deterministic mock provider functions entirely offline.
4. **Application-Layer Boundary Caveat**: While `ScopeGuard` and `SafeHTTPClient` defend against alternate IP encodings, DNS rebinding aliases, userinfo tricks, and ambient proxy leaks, application-level Python guards operate inside standard process limits. Defense-in-depth network firewalls and container isolation should be used in production environments.

