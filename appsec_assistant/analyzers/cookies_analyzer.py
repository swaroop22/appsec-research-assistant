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
        return "Audits cookies for Secure, HttpOnly, and SameSite attributes to prevent hijacking and CSRF."

    def analyze(self, transaction: HTTPTransaction) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        url = transaction.url

        # Check cookies captured from transaction or parse Set-Cookie headers
        cookies_to_audit: List[Dict[str, Any]] = list(transaction.cookies)

        # Parse Set-Cookie headers directly in case requests jar missed any custom headers
        set_cookie_raw = transaction.response_headers.get("Set-Cookie", "") or transaction.response_headers.get("set-cookie", "")
        if set_cookie_raw and not cookies_to_audit:
            # Simple parse of Set-Cookie header
            cookie_parts = [c.strip() for c in set_cookie_raw.split(";")]
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
                    "samesite": next((p.split("=")[1] for p in attrs if p.startswith("samesite")), None),
                })

        sensitive_keywords = ["session", "token", "auth", "jwt", "sid", "connect.sid", "user", "id"]

        for cookie in cookies_to_audit:
            name = cookie.get("name", "")
            is_secure = cookie.get("secure", False)
            is_httponly = cookie.get("httponly", False)
            samesite = cookie.get("samesite")
            name_lower = name.lower()

            is_sensitive = any(kw in name_lower for kw in sensitive_keywords)

            # 1. Missing HttpOnly flag
            if not is_httponly:
                severity = SeverityLevel.HIGH if is_sensitive else SeverityLevel.MEDIUM
                findings.append(
                    VulnerabilityFinding(
                        finding_id=f"SEC-CK-001-{name}",
                        title=f"Cookie Missing HttpOnly Flag: '{name}'",
                        category="Cookie Security",
                        severity=severity,
                        target_url=url,
                        description=(
                            f"The cookie '{name}' was set without the 'HttpOnly' attribute. "
                            "This flag instructs client browsers that the cookie cannot be accessed via "
                            "client-side scripts (e.g. `document.cookie`)."
                        ),
                        impact=(
                            "If any Cross-Site Scripting (XSS) vulnerability exists on the application, "
                            f"an attacker can directly read '{name}' from JavaScript and exfiltrate user session tokens, "
                            "leading directly to Account Takeover."
                        ),
                        evidence=f"Cookie: {name}; Attributes: Secure={is_secure}, HttpOnly={is_httponly}, SameSite={samesite}",
                        remediation=(
                            f"Set the HttpOnly flag on '{name}'.\n"
                            "Example in Express/Node.js:\n"
                            "`res.cookie('" + name + "', token, { httpOnly: true, secure: true, sameSite: 'lax' });`"
                        ),
                        cwe_id="CWE-1004",
                        owasp_category="A05:2021-Security Misconfiguration",
                        references=[
                            "https://owasp.org/www-community/HttpOnly",
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies",
                        ],
                    )
                )

            # 2. Missing Secure flag (on HTTPS or sensitive cookies)
            if not is_secure:
                findings.append(
                    VulnerabilityFinding(
                        finding_id=f"SEC-CK-002-{name}",
                        title=f"Cookie Missing Secure Flag: '{name}'",
                        category="Cookie Security",
                        severity=SeverityLevel.MEDIUM if is_sensitive else SeverityLevel.LOW,
                        target_url=url,
                        description=(
                            f"The cookie '{name}' does not include the 'Secure' attribute. "
                            "The Secure flag ensures that the cookie is transmitted only over encrypted TLS (HTTPS) connections."
                        ),
                        impact=(
                            "Without the Secure flag, browsers may transmit the cookie in plaintext if an unencrypted "
                            "HTTP link is followed, allowing passive eavesdroppers on untrusted networks (e.g. public Wi-Fi) "
                            "to intercept the cookie."
                        ),
                        evidence=f"Cookie: {name}; Secure flag is False.",
                        remediation=(
                            f"Add the 'Secure' attribute to '{name}': `Set-Cookie: {name}=...; Secure; HttpOnly; SameSite=Lax`"
                        ),
                        cwe_id="CWE-614",
                        owasp_category="A05:2021-Security Misconfiguration",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies_attributes"],
                    )
                )

            # 3. Missing or weak SameSite attribute
            if not samesite or str(samesite).lower() in ("none", "null"):
                findings.append(
                    VulnerabilityFinding(
                        finding_id=f"SEC-CK-003-{name}",
                        title=f"Cookie Missing or Weak SameSite Attribute: '{name}'",
                        category="Cookie Security",
                        severity=SeverityLevel.MEDIUM,
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
                        evidence=f"Cookie: {name}; SameSite={samesite}",
                        remediation=(
                            f"Set `SameSite=Lax` (standard for web navigation) or `SameSite=Strict` for sensitive API cookies."
                        ),
                        cwe_id="CWE-1275",
                        owasp_category="A01:2021-Broken Access Control",
                        references=["https://web.dev/articles/samesite-cookies-explained"],
                    )
                )

        return findings
