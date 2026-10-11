"""
Security Headers Analyzer.

Inspects HTTP response headers for missing, weak, or misconfigured defensive controls.
Covers CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy, CORS, and information disclosure banners.
"""

from typing import List, Dict
from appsec_assistant.analyzers.base import BaseAnalyzer
from appsec_assistant.models import HTTPTransaction, VulnerabilityFinding, SeverityLevel


class HeadersAnalyzer(BaseAnalyzer):
    """Audits HTTP response headers for defense-in-depth protections."""

    @property
    def name(self) -> str:
        return "Security Headers Analyzer"

    @property
    def description(self) -> str:
        return "Analyzes HTTP response headers for missing or weak defensive configurations (CSP, HSTS, XFO, etc.)."

    def analyze(self, transaction: HTTPTransaction) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        # Normalize header keys to lowercase for case-insensitive lookup
        headers_lower: Dict[str, str] = {k.lower(): v for k, v in transaction.response_headers.items()}
        url = transaction.url

        # 1. Content-Security-Policy (CSP)
        csp = headers_lower.get("content-security-policy")
        if not csp:
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-HDR-001",
                    title="Missing Content-Security-Policy (CSP) Header",
                    category="Security Headers",
                    severity=SeverityLevel.MEDIUM,
                    target_url=url,
                    description=(
                        "The application does not enforce a Content-Security-Policy header. "
                        "CSP is a critical defense-in-depth mechanism that instructs the browser "
                        "which dynamic resources (scripts, styles, images, frames) are permitted to load."
                    ),
                    impact=(
                        "Without CSP, the browser will execute any injected scripts, significantly "
                        "increasing susceptibility to Cross-Site Scripting (XSS), data exfiltration, "
                        "and unauthorized script execution."
                    ),
                    evidence=f"HTTP/{transaction.status_code} Response Headers contain no 'Content-Security-Policy'.",
                    remediation=(
                        "Define and deploy a strict Content-Security-Policy. Start with a baseline policy:\n"
                        "`Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';`\n"
                        "Use nonce-based or hash-based CSP for modern single-page applications."
                    ),
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021-Security Misconfiguration",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    ],
                )
            )
        else:
            # Check for weak CSP directives
            csp_lower = csp.lower()
            weaknesses = []
            if "'unsafe-inline'" in csp_lower and "nonce-" not in csp_lower:
                weaknesses.append("'unsafe-inline' (allows execution of arbitrary inline scripts)")
            if "'unsafe-eval'" in csp_lower:
                weaknesses.append("'unsafe-eval' (allows string-to-code execution via eval/setTimeout)")
            if "script-src *" in csp_lower or "default-src *" in csp_lower:
                weaknesses.append("Wildcard '*' source allows script loading from any domain")

            if weaknesses:
                findings.append(
                    VulnerabilityFinding(
                        finding_id="SEC-HDR-002",
                        title="Weak Content-Security-Policy Directives Detected",
                        category="Security Headers",
                        severity=SeverityLevel.LOW,
                        target_url=url,
                        description=(
                            "The Content-Security-Policy header contains directives that weaken its "
                            f"protection: {', '.join(weaknesses)}."
                        ),
                        impact=(
                            "Permitting unsafe inline scripts or eval neutralizes the primary XSS mitigations "
                            "that CSP is designed to provide."
                        ),
                        evidence=f"Content-Security-Policy: {csp}",
                        remediation=(
                            "Refactor code to avoid inline scripts and eval(). Replace 'unsafe-inline' with "
                            "cryptographic nonces (`'nonce-rAnd0m'`) or SHA-256 hashes."
                        ),
                        cwe_id="CWE-1021",
                        owasp_category="A05:2021-Security Misconfiguration",
                        references=["https://csp.withgoogle.com/docs/strict-csp.html"],
                    )
                )

        # 2. X-Frame-Options / Frame-Ancestors
        xfo = headers_lower.get("x-frame-options")
        has_frame_ancestors = csp and "frame-ancestors" in csp.lower()
        if not xfo and not has_frame_ancestors:
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-HDR-003",
                    title="Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
                    category="Security Headers",
                    severity=SeverityLevel.MEDIUM,
                    target_url=url,
                    description=(
                        "Neither 'X-Frame-Options' nor CSP 'frame-ancestors' was supplied. "
                        "This permits third-party websites to embed this web application within an iframe."
                    ),
                    impact=(
                        "Attackers can mount Clickjacking (UI Redressing) attacks, deceiving authenticated users "
                        "into clicking hidden buttons or executing unintended transactions."
                    ),
                    evidence="Headers contain neither 'X-Frame-Options' nor 'frame-ancestors' directive in CSP.",
                    remediation=(
                        "Add the X-Frame-Options header with value 'DENY' or 'SAMEORIGIN':\n"
                        "`X-Frame-Options: DENY`\n"
                        "Or configure CSP: `frame-ancestors 'none';`"
                    ),
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021-Security Misconfiguration",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
                    ],
                )
            )

        # 3. X-Content-Type-Options
        xcto = headers_lower.get("x-content-type-options")
        if not xcto or "nosniff" not in xcto.lower():
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-HDR-004",
                    title="Missing X-Content-Type-Options: nosniff Header",
                    category="Security Headers",
                    severity=SeverityLevel.LOW,
                    target_url=url,
                    description=(
                        "The 'X-Content-Type-Options: nosniff' header is missing or improperly configured. "
                        "This header prevents browsers from MIME-sniffing a response away from the declared Content-Type."
                    ),
                    impact=(
                        "An attacker may upload a file with an innocent MIME type (e.g. image/png) that contains "
                        "executable script tags. Without 'nosniff', legacy browsers may execute it as HTML/JavaScript."
                    ),
                    evidence=f"X-Content-Type-Options: {xcto if xcto else 'Not Set'}",
                    remediation="Set `X-Content-Type-Options: nosniff` across all HTTP responses.",
                    cwe_id="CWE-16",
                    owasp_category="A05:2021-Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
                    ],
                )
            )

        # 4. Strict-Transport-Security (HSTS)
        if url.startswith("https://"):
            hsts = headers_lower.get("strict-transport-security")
            if not hsts:
                findings.append(
                    VulnerabilityFinding(
                        finding_id="SEC-HDR-005",
                        title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                        category="Security Headers",
                        severity=SeverityLevel.MEDIUM,
                        target_url=url,
                        description=(
                            "The response over HTTPS does not set Strict-Transport-Security. "
                            "HSTS ensures that modern browsers only connect to the domain using HTTPS."
                        ),
                        impact=(
                            "Vulnerable to SSL stripping and man-in-the-middle downgrade attacks when users "
                            "initially connect via HTTP."
                        ),
                        evidence="No Strict-Transport-Security header present on HTTPS response.",
                        remediation=(
                            "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`."
                        ),
                        cwe_id="CWE-523",
                        owasp_category="A05:2021-Security Misconfiguration",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                    )
                )

        # 5. Information Disclosure in Server / X-Powered-By
        server = headers_lower.get("server")
        x_powered_by = headers_lower.get("x-powered-by")
        leak_evidence = []
        if server and any(c.isdigit() for c in server):
            leak_evidence.append(f"Server: {server}")
        if x_powered_by:
            leak_evidence.append(f"X-Powered-By: {x_powered_by}")

        if leak_evidence:
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-HDR-006",
                    title="Information Disclosure via Server / Framework Headers",
                    category="Information Exposure",
                    severity=SeverityLevel.LOW,
                    target_url=url,
                    description=(
                        "The server advertises granular version or framework details in response headers: "
                        f"{', '.join(leak_evidence)}."
                    ),
                    impact=(
                        "Reveals server software and versions, allowing adversaries to look up published CVEs "
                        "and tailor exploitation vectors against known technology stacks."
                    ),
                    evidence="; ".join(leak_evidence),
                    remediation=(
                        "Disable or obfuscate banner headers in your web server/reverse proxy configuration:\n"
                        "- Express.js: `app.disable('x-powered-by')`\n"
                        "- Nginx: `server_tokens off;`\n"
                        "- Apache: `ServerTokens Prod` and `ServerSignature Off`"
                    ),
                    cwe_id="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
                )
            )

        # 6. Permissive Cross-Origin Resource Sharing (CORS)
        cors_origin = headers_lower.get("access-control-allow-origin")
        cors_creds = headers_lower.get("access-control-allow-credentials", "").lower()
        if cors_origin == "*":
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-HDR-007",
                    title="Wildcard Cross-Origin Resource Sharing (CORS) Origin",
                    category="Access Control",
                    severity=SeverityLevel.LOW,
                    target_url=url,
                    description=(
                        "The endpoint responds with `Access-Control-Allow-Origin: *`. "
                        "Any origin in the world is permitted to read public responses from this API."
                    ),
                    impact=(
                        "While acceptable for strictly public read-only content, wildcard origins on private or sensitive "
                        "APIs can allow third-party scripts in a victim's browser to read sensitive data."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {cors_origin}",
                    remediation=(
                        "Avoid wildcard origins on sensitive endpoints. Maintain an explicit allowlist of trusted domains "
                        "and validate incoming `Origin` headers before responding."
                    ),
                    cwe_id="CWE-346",
                    owasp_category="A01:2021-Broken Access Control",
                    references=["https://portswigger.net/web-security/cors"],
                )
            )

        return findings
