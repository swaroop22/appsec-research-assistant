"""
Cookie Security Analyzer.

Audits session cookies and authentication tokens for essential defensive flags:
Secure, HttpOnly, and SameSite attributes, as well as safe prefix conventions.
"""

from typing import List, Dict, Any
from appsec_assistant.analyzers.base import BaseAnalyzer
from appsec_assistant.models import HTTPTransaction, VulnerabilityFinding, SeverityLevel


class CookiesAnalyzer(BaseAnalyzer):
    """Audits HTTP cookies for state management security best practices."""

    @property
    def name(self) -> str:
        return "Cookie Security Analyzer"

    @property
    def description(self) -> str:
        return (
            "Audits cookies for Secure, HttpOnly, and SameSite attributes "
            "to prevent token theft via XSS, network interception, and CSRF."
        )

    def analyze(self, transaction: HTTPTransaction) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        url = transaction.url

        # Check cookies captured from transaction or parse Set-Cookie headers
        cookies_to_audit: List[Dict[str, Any]] = list(transaction.cookies)

        # Parse Set-Cookie headers directly in case requests jar missed any custom headers
        set_cookie_raw = (
            transaction.response_headers.get("Set-Cookie", "")
            or transaction.response_headers.get("set-cookie", "")
        )
        if set_cookie_raw and not cookies_to_audit:
            # Handle possible multiline Set-Cookie
            for cookie_line in set_cookie_raw.splitlines():
                cookie_parts = [c.strip() for c in cookie_line.split(";") if c.strip()]
                if cookie_parts:
                    kv = cookie_parts[0].split("=", 1)
                    name = kv[0]
                    val = kv[1] if len(kv) > 1 else ""
                    attrs = [p.lower() for p in cookie_parts[1:]]
                    cookies_to_audit.append({
                        "name": name,
                        "value": val,
                        "secure": any("secure" in a for a in attrs),
                        "httponly": any("httponly" in a for a in attrs),
                        "samesite": next((p.split("=")[1].strip() for p in attrs if p.startswith("samesite")), None),
                    })

        sensitive_keywords = ["session", "token", "auth", "jwt", "sid", "connect.sid", "user", "id", "csrf", "xsrf"]

        for cookie in cookies_to_audit:
            name = cookie.get("name", "")
            if not name:
                continue

            is_secure = cookie.get("secure", False)
            is_httponly = cookie.get("httponly", False)
            samesite = cookie.get("samesite")
            name_lower = name.lower()

            is_sensitive = any(kw in name_lower for kw in sensitive_keywords)

            # 1. Missing HttpOnly flag
            if not is_httponly:
                severity = SeverityLevel.HIGH if is_sensitive else SeverityLevel.MEDIUM
                rationale = (
                    f"Assigned {'HIGH' if is_sensitive else 'MEDIUM'} priority because '{name}' appears to be a "
                    f"{'sensitive session or authentication token' if is_sensitive else 'state cookie'}. "
                    "Without HttpOnly, client-side scripts can access this cookie via document.cookie. "
                    "If any XSS flaw exists on the domain, an attacker can directly steal it and impersonate the user."
                )
                findings.append(
                    VulnerabilityFinding(
                        finding_id=f"SEC-CK-001-{name}",
                        title=f"Cookie Missing HttpOnly Flag: '{name}'",
                        category="Cookie Security",
                        severity=severity,
                        priority_rationale=rationale,
                        target_url=url,
                        description=(
                            f"The cookie '{name}' was set without the 'HttpOnly' attribute. "
                            "This flag instructs client browsers that the cookie cannot be accessed or read by "
                            "client-side scripts (e.g. `document.cookie`)."
                        ),
                        impact=(
                            "If any Cross-Site Scripting (XSS) vulnerability exists on the application, "
                            f"an attacker can directly read '{name}' from JavaScript and exfiltrate user session tokens, "
                            "leading directly to Account Takeover."
                        ),
                        evidence=f"Cookie: {name}; Attributes: Secure={is_secure}, HttpOnly={is_httponly}, SameSite={samesite or 'Not Set'}",
                        remediation=(
                            f"Set the HttpOnly flag on '{name}'.\n"
                            "Example in Express/Node.js:\n"
                            "```javascript\n"
                            f"res.cookie('{name}', token, {{ httpOnly: true, secure: true, sameSite: 'lax' }});\n"
                            "```\n"
                            "Example in Python (Flask):\n"
                            "```python\n"
                            f"response.set_cookie('{name}', value, httponly=True, secure=True, samesite='Lax')\n"
                            "```"
                        ),
                        cwe_id="CWE-1004",
                        owasp_category="A05:2021-Security Misconfiguration",
                        references=[
                            "https://owasp.org/www-community/HttpOnly",
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies",
                        ],
                    )
                )

            # 2. Missing Secure flag
            if not is_secure:
                severity = SeverityLevel.MEDIUM if is_sensitive else SeverityLevel.LOW
                rationale = (
                    f"Assigned {'MEDIUM' if is_sensitive else 'LOW'} priority because '{name}' lacks the Secure flag. "
                    "Without Secure, the browser may transmit this cookie across unencrypted HTTP connections if "
                    "an insecure link is followed, exposing it to local network eavesdropping."
                )
                findings.append(
                    VulnerabilityFinding(
                        finding_id=f"SEC-CK-002-{name}",
                        title=f"Cookie Missing Secure Flag: '{name}'",
                        category="Cookie Security",
                        severity=severity,
                        priority_rationale=rationale,
                        target_url=url,
                        description=(
                            f"The cookie '{name}' does not include the 'Secure' attribute. "
                            "The Secure flag ensures that the cookie is transmitted only over encrypted TLS (HTTPS) connections."
                        ),
                        impact=(
                            "Without the Secure flag, browsers may transmit the cookie in cleartext if an unencrypted "
                            "HTTP link is followed, allowing passive eavesdroppers on untrusted networks (e.g. public Wi-Fi) "
                            "to intercept the cookie."
                        ),
                        evidence=f"Cookie: {name}; Secure flag is False.",
                        remediation=(
                            f"Add the 'Secure' attribute to '{name}':\n"
                            "```http\n"
                            f"Set-Cookie: {name}=...; Secure; HttpOnly; SameSite=Lax\n"
                            "```"
                        ),
                        cwe_id="CWE-614",
                        owasp_category="A05:2021-Security Misconfiguration",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies_attributes"
                        ],
                    )
                )

            # 3. Missing or weak SameSite attribute
            if not samesite or str(samesite).lower() in ("none", "null"):
                rationale = (
                    f"Assigned MEDIUM priority because '{name}' does not configure a restrictive SameSite policy "
                    f"({samesite or 'omitted'}). The browser may automatically send this cookie with cross-site requests, "
                    "enabling Cross-Site Request Forgery (CSRF) if the application relies on cookies for authentication."
                )
                findings.append(
                    VulnerabilityFinding(
                        finding_id=f"SEC-CK-003-{name}",
                        title=f"Cookie Missing or Weak SameSite Attribute: '{name}'",
                        category="Cookie Security",
                        severity=SeverityLevel.MEDIUM,
                        priority_rationale=rationale,
                        target_url=url,
                        description=(
                            f"The cookie '{name}' either omits the SameSite attribute or sets it to 'None'. "
                            "SameSite dictates whether cookies are sent along with cross-site requests."
                        ),
                        impact=(
                            "Absence of SameSite protection makes the application vulnerable to Cross-Site Request "
                            "Forgery (CSRF), allowing malicious external sites to perform unauthorized authenticated "
                            "actions on behalf of the victim."
                        ),
                        evidence=f"Cookie: {name}; SameSite={samesite or 'Not Set'}",
                        remediation=(
                            f"Set `SameSite=Lax` (standard for web navigation) or `SameSite=Strict` for sensitive API cookies:\n"
                            "```http\n"
                            f"Set-Cookie: {name}=...; SameSite=Lax; Secure; HttpOnly\n"
                            "```"
                        ),
                        cwe_id="CWE-1275",
                        owasp_category="A01:2021-Broken Access Control",
                        references=["https://web.dev/articles/samesite-cookies-explained"],
                    )
                )

            # 4. Informational cookie prefix suggestion for sensitive cookies
            if is_sensitive and not name.startswith("__Host-") and not name.startswith("__Secure-"):
                findings.append(
                    VulnerabilityFinding(
                        finding_id=f"SEC-CK-004-{name}",
                        title=f"Consider Hardening Cookie with '__Host-' Prefix: '{name}'",
                        category="Cookie Security",
                        severity=SeverityLevel.INFO,
                        priority_rationale=(
                            "Assigned INFORMATIONAL priority because cookie name prefixes (__Host-, __Secure-) "
                            "are advanced defense-in-depth controls preventing subdomain cookie tossing, "
                            "rather than a vulnerability indicator."
                        ),
                        target_url=url,
                        description=(
                            f"The sensitive cookie '{name}' does not use browser cookie prefix conventions. "
                            "Cookies with names prefixed with `__Host-` or `__Secure-` receive special browser enforcement, "
                            "such as requiring HTTPS, path=/, and preventing overwrites from sibling subdomains."
                        ),
                        impact=(
                            "A compromised subdomain could overwrite or 'toss' cookies for the parent domain, "
                            "leading to session fixation or spoofing."
                        ),
                        evidence=f"Cookie name '{name}' does not use '__Host-' prefix.",
                        remediation=(
                            f"Rename the cookie to `__Host-{name}` and set attributes:\n"
                            "```http\n"
                            f"Set-Cookie: __Host-{name}=...; Secure; HttpOnly; SameSite=Lax; Path=/\n"
                            "```"
                        ),
                        cwe_id="CWE-16",
                        owasp_category="A05:2021-Security Misconfiguration",
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes"],
                    )
                )

        return findings
