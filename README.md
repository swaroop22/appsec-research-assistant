# 🛡️ AppSec Research Assistant

A modular, defensive web application security analysis assistant written in Python for educational security research, vulnerability analysis, and remediation engineering.

- **Phase 1**: Passive offline HTTP response security analysis via interactive **Streamlit Web Interface**, header and cookie inspection, and CSV/JSON export.
- **Phase 2**: High-fidelity vulnerability analysis quality, confidence scoring, explicit distinction of heuristic indicators from verified vulnerabilities, false positive prevention, sitewide finding deduplication, and loopback scope boundary protection.
- **Phase 3**: Controlled vulnerability research workflow (Program policy manager, 6 guided exercises, 4 verification tiers, sanitized evidence, human sign-off).
- **Phase 4**: AI-Assisted vulnerability triage layer (Modular providers: Mock, OpenAI, Anthropic, Gemini, Local; user consent gates, evidence grounding, tier promotion clamping, prompt-injection defense, semantic duplicate detection).
- **Phase 5**: **Authorized Bug Bounty Research Workflow**:
  - **Program Registry**: Stores company and program names, official policy URLs, eligible assets allowlist, explicitly excluded assets, permitted vulnerability categories, prohibited methods, rate limits, testing restrictions, reporting instructions, required evidence, and disclosure requirements.
  - **Policy & Scope Verification**: Mandates explicit researcher scope review; validates scheme, hostname, and path restrictions; detects stale/expired policies (> 90 days); fails closed on ambiguous (`*`, `https://*`) or contradictory scopes; and revokes verification upon scope modifications.
  - **Safe Workflow Modes**:
    - **Mode A (OFFLINE)**: Analyzes saved HTTP responses and supplied evidence with zero network transmission (`NetworkDisabledInOfflineModeError`).
    - **Mode B (LOCAL LAB)**: Active testing strictly restricted to the loopback training lab (`localhost`, `127.0.0.1`, `::1`).
    - **Mode C (AUTHORIZED PROGRAM PREPARATION)**: Scope review, note organization, finding mapping, and report drafts. Automated scanning is disabled (`ActiveTestingDisabledInPrepModeError`).
  - **Research Task Dashboard**: Tracks finding status (`NEW_OBSERVATION`, `NEEDS_VERIFICATION`, `VERIFIED_BY_RESEARCHER`, `DUPLICATE_SUSPECTED`, `REPORT_DRAFT`, `READY_FOR_REVIEW`, `SUBMITTED_BY_RESEARCHER`, `ACCEPTED`, `REJECTED`, `DUPLICATE`, `RESOLVED`), evidence completeness score (`0.0` to `1.0`), duplicate review status, next manual verification steps, report readiness gates, and submission tracking.
  - **Evidence Management**: Stores affected authorized assets, minimal request/response evidence, timestamps, and severity/confidence rationales. Automatically redacts session cookies, authorization headers, access tokens, passwords, private keys, and personal data (PII: emails, phone numbers, SSNs).
  - **Policy-Aware Report Generator**: Drafts structured disclosure reports tailored to official program reporting guidelines (preconditions, minimal reproduction steps, expected vs. observed behavior, sanitized evidence, realistic impact, severity rationale, remediation, limitations).
  - **Human-Controlled Submission Workflow**: Enforces explicit human confirmation before marking reports as submitted or accepted, and requires researcher sign-off before exporting reports. Never submits reports automatically.

---

## 🏗️ Phase 5 Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 Safe Workflow Modes                                    │
│   [Mode A: OFFLINE]              [Mode B: LOCAL LAB]             [Mode C: PREPARATION] │
│   No network traffic;            Strictly confined to            Scope review, notes,  │
│   saved responses only           127.0.0.1 loopback lab          drafting; no scanning │
└──────────────┬───────────────────────────┬─────────────────────────────────┬───────────┘
               │                           │                                 │
               ▼                           ▼                                 ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              Program Policy Registry                                   │
│  - Eligible Asset Allowlists (Inclusion)   - Explicit Excluded Assets (Priority Gate)  │
│  - Stale Verification Check (>90 days)     - Scope Integrity & Contradiction Defense   │
│  - Permitted Categories & Prohibitions     - Scope Modification Re-Verification Reset  │
└──────────────────────────────────────────┬─────────────────────────────────────────────┘
                                           │
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                           Research Task Manager & Dashboard                            │
│  - 11-State Research Lifecycle Status      - Duplicate Review & Clearing Workflow      │
│  - Evidence Completeness Score (0.0-1.0)   - Report Readiness Blockers Audit           │
│  - Manual Next Verification Steps Tracker  - Human Confirmation Gates (Submit/Outcome) │
└──────────────────────────────────────────┬─────────────────────────────────────────────┘
                                           │
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                           Policy-Aware Report Generator                                │
│  - Program-Aligned Sections (Preconditions, Expected vs. Observed, Realistic Impact)   │
│  - Sanitized Evidence: Automated PII & Secret Redaction (Cookies, Auth, Keys, Emails)  │
│  - Strict Separation of Original Evidence from AI-Generated Triage Interpretation      │
│  - Mandatory Researcher Review Sign-Off Prior to Markdown / JSON Report Export         │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```
appsec-research-assistant/
├── app.py                             # 🌐 Streamlit Web Application (7 Phase 5 Tabs & Mode Selector)
├── requirements.txt                   # Complete dependencies
├── README.md                          # Full documentation guide & manual checklist
├── sample_data/
│   └── fictional_program_policy.json  # Fictional Acme FinTech sample bug bounty policy
├── appsec_assistant/                  # Core package
│   ├── __init__.py
│   ├── models.py                      # WorkflowMode, ResearchStatus, ResearchTask, ProgramPolicy, FindingTier
│   ├── policy.py                      # ProgramPolicyManager (scope integrity, staleness, exclusion precedence)
│   ├── research.py                    # ResearchManager (task lifecycle, completeness score, readiness audit)
│   ├── config.py                      # ScopeGuard (Alternate IPs, DNS rebinding, malformed URLs)
│   ├── client.py                      # SafeHTTPClient with mode enforcement, proxy & redirect hop isolation
│   ├── engine.py                      # Audit orchestrator with policy enforcement & exercise audit
│   ├── response_parser.py             # Passive HTTP response & cookie parser
│   ├── samples.py                     # Realistic sample HTTP responses for testing
│   ├── knowledge_base.py              # Educational vulnerability encyclopedia & 6 Guided Exercises
│   ├── lab_server.py                  # Local mock practice lab server with synthetic accounts
│   ├── cli.py                         # Rich interactive terminal interface with Phase 5 flags
│   ├── ai/                            # AI-Assisted Triage Layer (Phase 4)
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
│       ├── markdown_reporter.py       # Formatted markdown reporter with AI triage analysis blocks
│       └── policy_report_generator.py # Policy-aware bug bounty draft generator with human sign-off
└── tests/                             # Automated test suite (89 tests, 100% passing)
    ├── __init__.py
    ├── test_authorized_bug_bounty_workflow.py # Phase 5 tests (scope, stale, modes, readiness, redaction)
    ├── test_ai_provider_abstraction.py        # Tests providers, credential handling, timeouts, consent
    ├── test_ai_triage_validation.py          # Tests JSON schema, tier clamp, evidence grounding, injection
    ├── test_ai_duplicate_detection.py        # Tests semantic similarity, human approval, evidence preservation
    ├── test_ai_service_integration.py        # Tests end-to-end audit with AI triage and report formats
    ├── test_program_policy.py                # Tests VDP policy manager, scope verification, fail-closed
    ├── test_guided_exercises.py              # Tests 6 guided exercises & synthetic lab endpoints
    ├── test_finding_verification_tiers.py    # Tests 4-tier model, evidence sanitization, status code 200 rule
    ├── test_security_boundary_deep.py        # Deep tests for redirects, DNS, IP normalization, proxies
    ├── test_scope_guard_hardening.py         # Tests alternate IPs, DNS rebinding, malformed URLs
    ├── test_redirect_boundary.py             # Tests redirect validation & boundary containment
    ├── test_false_positives.py               # Tests login portal false positive prevention & IDOR heuristic
    ├── test_deduplication.py                 # Tests sitewide header deduplication
    ├── test_headers_analyzer.py              # Tests security headers
    ├── test_cookies_analyzer.py              # Tests cookie flags
    ├── test_access_control_analyzer.py       # Tests access control
    ├── test_response_parser.py               # Tests HTTP response parsing
    ├── test_csv_reporter.py                  # Tests CSV export
    ├── test_reporters.py                     # Tests markdown and JSON exports
    ├── test_knowledge_base.py                # Tests encyclopedia queries
    └── test_scope_guard.py                   # Tests baseline scope validation
```

---

## 🚀 Quickstart & Verification

### 1. Run Automated Unit & Regression Tests (89 Tests)
```bash
pytest -v tests/
```
Output:
```text
============================== 89 passed in 2.76s ==============================
```

### 2. Launch Streamlit Web Application
```bash
streamlit run app.py
```
Open **`http://localhost:8501`** in your browser to access the 7 workflow tabs:
1. **🔬 Security Analysis & Audit**: Passive response inspection, local auditing, and instant AI triage.
2. **🎓 Guided Lab Exercises**: 6 guided exercises using synthetic test accounts Bob, Alice, and Charlie.
3. **🤖 AI Triage & Analysis**: Evidence-grounded explanations, false positive detection, review prioritization, and semantic duplicate reviews.
4. **📋 Finding Review & Sign-Off**: Review findings, inspect reproduction steps and sanitized evidence, and sign off as a human auditor.
5. **📜 Program Policy Registry**: Inspect, verify, import/export policies, and manage eligible/excluded asset scopes.
6. **🎯 Bug Bounty Research Tasks**: Research task manager with 11 lifecycle states, completeness progress, readiness blockers audit, duplicate reviews, and submission tracking.
7. **💾 Export Verified Reports**: Download verified Markdown, JSON, and CSV reports, plus policy-tailored bug bounty disclosure drafts requiring researcher sign-off.

### 3. CLI Workflow Commands
```bash
# List configured bug bounty policies
python -m appsec_assistant.cli --policies

# Import a program policy document
python -m appsec_assistant.cli --import-policy sample_data/fictional_program_policy.json

# Manually verify and enable a policy
python -m appsec_assistant.cli --verify-policy acme-fintech-bounty --reviewer "Lead Researcher"

# Run local lab audit in Mode B
python -m appsec_assistant.cli --mode LOCAL_LAB --lab --ai-triage --export-md report.md
```

---

## 🔒 Policy & Scope Verification Guarantees

| Requirement | Implementation Safeguard | Fail-Closed Behavior |
| :--- | :--- | :--- |
| **Asset Allowlist** | Target URL must match pattern in `eligible_assets` / `authorized_assets`. | Returns `UnauthorizedTargetError` if not in allowlist. |
| **Asset Exclusion Priority** | Excluded patterns in `excluded_assets` take absolute precedence over inclusions. | Immediately returns `UnauthorizedTargetError` even if asset matched a broad wildcard. |
| **Ambiguous Scope Defense** | Disallows overly broad wildcards like `*`, `*.*`, `http://*`, `https://*`. | Raises `ScopeIntegrityError` during policy creation or import. |
| **Contradictory Scope Defense** | Assets cannot appear simultaneously in both eligible and excluded lists. | Raises `ScopeIntegrityError` during policy validation. |
| **Policy Freshness / Expiry** | Verifies `is_stale()` against `max_policy_age_days` (default: 90 days). | Raises `PolicyStaleError`; disallows policy enablement until re-verified. |
| **Scope Mutation Guard** | Modifying assets or prohibitions revokes verification. | Resets `is_verified=False` and `is_enabled=False`, mandating renewed human review. |
| **Mode Isolation** | Mode A blocks all network calls; Mode C blocks automated scans. | Mode A raises `NetworkDisabledInOfflineModeError`; Mode C raises `ActiveTestingDisabledInPrepModeError`. |
| **PII & Secret Redaction** | `sanitize_evidence_text` strips tokens, passwords, private keys, emails, phones, SSNs. | Replaces sensitive patterns with standardized `[REDACTED_*]` placeholders before export. |
| **Submission Safety** | Status transitions to `SUBMITTED` or terminal states require human confirmation. | Raises `HumanConfirmationRequiredError` if user confirmation is missing. |

---

## 📋 Manual Verification Checklist

Before exporting or preparing any vulnerability disclosure report:
- [ ] **Policy Authenticity**: Verified that the policy URL points to an official program disclosure page.
- [ ] **Scope Allowlist**: Verified that the target hostname and path reside in `eligible_assets`.
- [ ] **Exclusion Check**: Confirmed that the target asset does not match any pattern in `excluded_assets`.
- [ ] **Policy Freshness**: Confirmed that the policy verification date is within the last 90 days.
- [ ] **Method Compliance**: Confirmed that no prohibited testing methods (DoS, social engineering, destructive calls) were used.
- [ ] **Evidence Grounding**: Verified that the finding is supported by minimal request and response snippets.
- [ ] **Evidence Sanitization**: Confirmed that session tokens, authorization headers, private keys, passwords, and PII are redacted.
- [ ] **Separation of Concerns**: Kept original observational evidence strictly separate from automated AI interpretations.
- [ ] **Realistic Impact**: Formulated realistic technical and business risk without speculative claims.
- [ ] **Bounty Disclaimer**: Ensured no reward amounts or bounty eligibility are invented or guaranteed.
- [ ] **Human Sign-Off**: Confirmed that a qualified researcher has reviewed the reproduction steps and approved export.
- [ ] **Official Destination**: Identified and confirmed the program's official submission portal or secure disclosure address.
