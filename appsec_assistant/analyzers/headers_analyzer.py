"""
Security Headers Analyzer.

Inspects HTTP response headers for missing, weak, or misconfigured defensive controls.
Covers Content-Security-Policy (CSP), X-Content-Type-Options, Strict-Transport-Security (HSTS),
Referrer-Policy, X-Frame-Options (Clickjacking), Permissions-Policy, CORS, and information disclosure banners.
"""

from typing import List, Dict
from appsec_assistant.analyzers.base import BaseAnalyzer
from appsec_assistant.models import (
    HTTPTransaction,
    VulnerabilityFinding,
    SeverityLevel,
    ConfidenceLevel,
    FindingType,
)


class HeadersAnalyzer(BaseAnalyzer):
    """Audits HTTP response headers for defense-in-depth protections."""

    @property
    def name(self) -> str:
        return "Security Headers Analyzer"

    @property
    def description(self) -> str:
        return (
            "Analyzes HTTP response headers for missing or weak defensive configurations "
            "(CSP, HSTS, X-Content-Type-Options, Referrer-Policy, XFO, etc.)."
        )

    def analyze(self, transaction: HTTPTransaction) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        headers_lower: Dict[str, str] = {k.lower(): v for k, v in transaction.response_headers.items()}
        url = transaction.url
        is_https = url.lower().startswith("https://")

        # 1. Content-Security-Policy (CSP)
        csp = headers_lower.get("content-security-policy")
        if not csp:
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-HDR-001",
                    title="Missing Content-Security-Policy (CSP) Header",
                    category="Security Headers",
                    severity=SeverityLevel.MEDIUM,
                    priority_rationale=(
                        "Assigned MEDIUM priority because CSP is a vital defense-in-depth mitigation "
                        "against Cross-Site Scripting (XSS) and data injection. However, a missing header "
                        "is not inherently exploitable by itself unless an underlying injection flaw exists, "
                        "so it is never classified as Critical or High on its own."
                    ),
                    confidence=ConfidenceLevel.HIGH,
                    confidence_explanation=(
                        "Confidence is HIGH: Deterministic inspection of the HTTP response headers "
                        "confirms that no Content-Security-Policy header is configured."
                    ),
                    finding_type=FindingType.VERIFIED,
                    target_url=url,
                    description=(
                        "The application response does not include a Content-Security-Policy (CSP) header. "
                        "CSP instructs client web browsers which sources of content (JavaScript, CSS stylesheets, "
                        "images, fonts, iframes) are legitimate and allowed to execute."
                    ),
                    impact=(
                        "Without CSP, the browser will execute any injected inline scripts or load rogue scripts "
                        "from untrusted domains, significantly increasing susceptibility to Cross-Site Scripting (XSS), "
                        "clickjacking, session token theft, and malicious data exfiltration."
                    ),
                    evidence=(
                        f"GET {url} -> HTTP/{transaction.status_code} response headers contain no 'Content-Security-Policy'. "
                        f"Observed headers ({len(transaction.response_headers)}): {list(transaction.response_headers.keys())[:8]}"
                    ),
                    remediation=(
                        "Implement and enforce a restrictive Content-Security-Policy header. "
                        "Start with a strong baseline:\n"
                        "```http\n"
                        "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';\n"
                        "```\n"
                        "For modern single-page apps, use cryptographic nonces: `script-src 'self' 'nonce-random123'`."
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
            csp_lower = csp.lower()
            weaknesses = []
            if "'unsafe-inline'" in csp_lower and "nonce-" not in csp_lower:
                weaknesses.append("'unsafe-inline' (permits execution of arbitrary inline scripts)")
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
                        priority_rationale=(
                            "Assigned LOW priority because while a CSP header is actively deployed, "
                            "permissive directives ('unsafe-inline' / 'unsafe-eval') weaken its ability to stop script injection."
                        ),
                        confidence=ConfidenceLevel.CONFIRMED,
                        confidence_explanation=(
                            "Confidence is CONFIRMED: Deterministic text analysis of the Content-Security-Policy "
                            "directive value revealed explicit permissive keywords."
                        ),
                        finding_type=FindingType.VERIFIED,
                        target_url=url,
                        description=(
                            f"The Content-Security-Policy header contains permissive directives: {', '.join(weaknesses)}."
                        ),
                        impact=(
                            "Permitting unsafe inline scripts or eval allows attackers with XSS injection capabilities "
                            "to bypass the CSP protections."
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

        # 2. X-Content-Type-Options
        xcto = headers_lower.get("x-content-type-options")
        if not xcto or "nosniff" not in xcto.lower():
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-HDR-004",
                    title="Missing X-Content-Type-Options: nosniff Header",
                    category="Security Headers",
                    severity=SeverityLevel.LOW,
                    priority_rationale=(
                        "Assigned LOW priority because missing MIME-sniffing protection allows certain edge-case "
                        "content type confusion attacks, but requires file upload or user-controlled content to be exploitable."
                    ),
                    confidence=ConfidenceLevel.HIGH,
                    confidence_explanation=(
                        "Confidence is HIGH: Deterministic check verifies the absence of 'nosniff' in the response headers."
                    ),
                    finding_type=FindingType.VERIFIED,
                    target_url=url,
                    description=(
                        "The 'X-Content-Type-Options: nosniff' header is missing. "
                        "This header instructs the browser strictly to trust the declared MIME type in Content-Type "
                        "rather than attempting to 'sniff' or guess the file content based on magic bytes."
                    ),
                    impact=(
                        "An attacker may upload a file with a non-executable MIME type (e.g. image/png or text/plain) "
                        "that contains embedded HTML/JavaScript tags. Without 'nosniff', browsers may execute it as HTML/JS, "
                        "resulting in Cross-Site Scripting."
                    ),
                    evidence=f"X-Content-Type-Options: {xcto if xcto else 'Not Set'}",
                    remediation=(
                        "Configure the web server or reverse proxy to set this header on all responses:\n"
                        "```http\n"
                        "X-Content-Type-Options: nosniff\n"
                        "```"
                    ),
                    cwe_id="CWE-16",
                    owasp_category="A05:2021-Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
                    ],
                )
            )

        # 3. Strict-Transport-Security (HSTS)
        hsts = headers_lower.get("strict-transport-security")
        if not hsts:
            severity = SeverityLevel.MEDIUM if is_https else SeverityLevel.LOW
            priority_note = (
                "Assigned MEDIUM priority for HTTPS applications because HSTS enforces encrypted transport "
                "and prevents SSL stripping attacks. (Not Critical because it requires an active on-path network attacker)."
                if is_https
                else "Assigned LOW priority because the captured response uses HTTP or local testing. "
                "However, HSTS must be configured before deploying this application to production HTTPS."
            )
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-HDR-005",
                    title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                    category="Security Headers",
                    severity=severity,
                    priority_rationale=priority_note,
                    confidence=ConfidenceLevel.HIGH,
                    confidence_explanation=(
                        "Confidence is HIGH: Directly verified absence of Strict-Transport-Security header."
                    ),
                    finding_type=FindingType.VERIFIED,
                    target_url=url,
                    description=(
                        "The response does not specify the 'Strict-Transport-Security' (HSTS) header. "
                        "HSTS forces compatible browsers to establish encrypted TLS (HTTPS) connections exclusively "
                        "for the domain over a designated time period."
                    ),
                    impact=(
                        "Without HSTS, initial user connections over unencrypted HTTP or clicked http:// links "
                        "can be intercepted by on-path network attackers (man-in-the-middle) using SSL stripping tools, "
                        "exposing credentials and session tokens."
                    ),
                    evidence=f"Strict-Transport-Security: Not Set (URL scheme: {'HTTPS' if is_https else 'HTTP'})",
                    remediation=(
                        "Add the Strict-Transport-Security header with a long max-age (at least one year):\n"
                        "```http\n"
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
                        "```\n"
                        "Note: Ensure your domain and all subdomains cleanly support HTTPS before activating preload."
                    ),
                    cwe_id="CWE-523",
                    owasp_category="A05:2021-Security Misconfiguration",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
                    ],
                )
            )

        # 4. Referrer-Policy
        referrer_policy = headers_lower.get("referrer-policy")
        if not referrer_policy:
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-HDR-008",
                    title="Missing Referrer-Policy Header",
                    category="Security Headers",
                    severity=SeverityLevel.LOW,
                    priority_rationale=(
                        "Assigned LOW priority because while an absent Referrer-Policy causes browsers to use default rules "
                        "that can leak URL paths and query parameters to third-party domains, it is not an immediate vulnerability "
                        "unless sensitive data is transmitted within URLs."
                    ),
                    confidence=ConfidenceLevel.HIGH,
                    confidence_explanation=(
                        "Confidence is HIGH: Directly confirmed absence of Referrer-Policy in HTTP response headers."
                    ),
                    finding_type=FindingType.VERIFIED,
                    target_url=url,
                    description=(
                        "The 'Referrer-Policy' header is omitted. This header governs how much referrer information "
                        "(the current URL path and query string) is sent along with navigation requests and resource fetches."
                    ),
                    impact=(
                        "Browsers may transmit sensitive URL paths or query parameters (such as temporary reset tokens, "
                        "session identifiers, or personal identifiers) to external services and third-party links via the HTTP Referer header."
                    ),
                    evidence="Referrer-Policy header is missing from the response headers.",
                    remediation=(
                        "Set a secure Referrer-Policy such as 'strict-origin-when-cross-origin' or 'no-referrer':\n"
                        "```http\n"
                        "Referrer-Policy: strict-origin-when-cross-origin\n"
                        "```\n"
                        "This strips the path and query string when making cross-origin requests, preserving user privacy."
                    ),
                    cwe_id="CWE-116",
                    owasp_category="A05:2021-Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
                    ],
                )
            )
        else:
            ref_lower = referrer_policy.lower().strip()
            if ref_lower in ("unsafe-url", "no-referrer-when-downgrade"):
                findings.append(
                    VulnerabilityFinding(
                        finding_id="SEC-HDR-009",
                        title=f"Weak Referrer-Policy Detected ('{referrer_policy}')",
                        category="Security Headers",
                        severity=SeverityLevel.LOW,
                        priority_rationale=(
                            f"Assigned LOW priority because setting Referrer-Policy to '{referrer_policy}' "
                            "transmits complete URLs across origins or during protocol changes."
                        ),
                        confidence=ConfidenceLevel.CONFIRMED,
                        confidence_explanation=(
                            f"Confidence is CONFIRMED: Observed permissive policy '{referrer_policy}' in headers."
                        ),
                        finding_type=FindingType.VERIFIED,
                        target_url=url,
                        description=(
                            f"The application configures 'Referrer-Policy: {referrer_policy}'. "
                            "This policy sends the full URL (including path and query parameters) to third-party endpoints."
                        ),
                        impact=(
                            "External linked websites or loaded assets can observe sensitive internal URL paths "
                            "or tokenized query strings in their access logs."
                        ),
                        evidence=f"Referrer-Policy: {referrer_policy}",
                        remediation=(
                            "Update the policy to `strict-origin-when-cross-origin` or `same-origin`:\n"
                            "```http\n"
                            "Referrer-Policy: strict-origin-when-cross-origin\n"
                            "```"
                        ),
                        cwe_id="CWE-116",
                        owasp_category="A05:2021-Security Misconfiguration",
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                    )
                )

        # 5. X-Frame-Options / Frame-Ancestors (Clickjacking)
        xfo = headers_lower.get("x-frame-options")
        has_frame_ancestors = csp and "frame-ancestors" in csp.lower()
        if not xfo and not has_frame_ancestors:
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-HDR-003",
                    title="Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
                    category="Security Headers",
                    severity=SeverityLevel.MEDIUM,
                    priority_rationale=(
                        "Assigned MEDIUM priority because missing frame protection allows framing by third parties, "
                        "enabling Clickjacking (UI redressing) attacks against authenticated users. It is not Critical "
                        "because exploitation requires social engineering and interaction."
                    ),
                    confidence=ConfidenceLevel.HIGH,
                    confidence_explanation=(
                        "Confidence is HIGH: Direct inspection verified that neither X-Frame-Options nor "
                        "CSP frame-ancestors is present."
                    ),
                    finding_type=FindingType.VERIFIED,
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
                        "```http\n"
                        "X-Frame-Options: DENY\n"
                        "```\n"
                        "Or configure CSP: `Content-Security-Policy: frame-ancestors 'none';`"
                    ),
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021-Security Misconfiguration",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
                    ],
                )
            )

        # 6. Permissions-Policy / Feature-Policy
        permissions_policy = headers_lower.get("permissions-policy") or headers_lower.get("feature-policy")
        if not permissions_policy:
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-HDR-010",
                    title="Missing Permissions-Policy Header",
                    category="Security Headers",
                    severity=SeverityLevel.INFO,
                    priority_rationale=(
                        "Assigned INFORMATIONAL priority because Permissions-Policy is an advanced hardening header "
                        "that restricts browser hardware features (camera, mic, geolocation). Its absence represents "
                        "a defense-in-depth opportunity rather than a direct risk."
                    ),
                    confidence=ConfidenceLevel.HIGH,
                    confidence_explanation=(
                        "Confidence is HIGH: Verified absence of Permissions-Policy / Feature-Policy headers."
                    ),
                    finding_type=FindingType.VERIFIED,
                    target_url=url,
                    description=(
                        "The 'Permissions-Policy' header is not configured. This header allows web developers "
                        "to selectively enable, disable, and modify the behavior of browser features and APIs (geolocation, camera, microphone, etc.)."
                    ),
                    impact=(
                        "If third-party scripts or embedded iframes are compromised, they may access sensitive device APIs "
                        "if not explicitly restricted."
                    ),
                    evidence="Permissions-Policy header is missing.",
                    remediation=(
                        "Add a Permissions-Policy header disabling unused device capabilities:\n"
                        "```http\n"
                        "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()\n"
                        "```"
                    ),
                    cwe_id="CWE-16",
                    owasp_category="A05:2021-Security Misconfiguration",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
                )
            )

        # 7. Information Disclosure in Server / X-Powered-By
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
                    priority_rationale=(
                        "Assigned LOW priority because software version banners assist attacker reconnaissance, "
                        "but do not directly permit exploitation without an existing software vulnerability."
                    ),
                    confidence=ConfidenceLevel.CONFIRMED,
                    confidence_explanation=(
                        "Confidence is CONFIRMED: Version disclosure string was observed directly in response headers."
                    ),
                    finding_type=FindingType.VERIFIED,
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

        # 8. Permissive Cross-Origin Resource Sharing (CORS)
        cors_origin = headers_lower.get("access-control-allow-origin")
        if cors_origin == "*":
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-HDR-007",
                    title="Wildcard Cross-Origin Resource Sharing (CORS) Origin",
                    category="Access Control",
                    severity=SeverityLevel.LOW,
                    priority_rationale=(
                        "Assigned LOW priority because wildcard CORS is standard for open public APIs, "
                        "but presents a risk if applied to sensitive private resources."
                    ),
                    confidence=ConfidenceLevel.CONFIRMED,
                    confidence_explanation=(
                        "Confidence is CONFIRMED: Observed Access-Control-Allow-Origin: * in response headers."
                    ),
                    finding_type=FindingType.VERIFIED,
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
