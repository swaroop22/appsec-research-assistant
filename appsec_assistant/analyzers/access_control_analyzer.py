"""
Access Control and IDOR Pattern Analyzer.

Audits URLs, routes, and responses for Broken Access Control patterns and IDOR indicators.
Explicitly distinguishes heuristic indicators from verified, reproducible vulnerabilities.
"""

import re
from typing import List
from urllib.parse import urlparse
from appsec_assistant.analyzers.base import BaseAnalyzer
from appsec_assistant.models import (
    HTTPTransaction,
    VulnerabilityFinding,
    SeverityLevel,
    ConfidenceLevel,
    FindingType,
    FindingTier,
)


class AccessControlAnalyzer(BaseAnalyzer):
    """Audits endpoint architecture for IDOR patterns and authorization weaknesses."""

    # Static asset extensions that should not be flagged as IDOR
    STATIC_EXTENSIONS = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".js",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".html",
    )

    # Patterns indicating a login form or authentication challenge rather than an unprotected admin panel
    LOGIN_INDICATORS = [
        r'<input[^>]+type=["\']password["\']',
        r'action=["\'][^"\']*login[^"\']*["\']',
        r'name=["\'](?:password|passwd|user_password)["\']',
        r'please\s+(?:sign\s+in|log\s+in|authenticate)',
        r'sign\s+in\s+to\s+your\s+account',
        r'authentication\s+required',
    ]

    # Patterns indicating genuine privileged admin content or data
    ADMIN_CONTENT_INDICATORS = [
        r'"users"\s*:\s*\[',
        r'"admin"\s*:\s*true',
        r'"metrics"\s*:\s*\{',
        r'"jvm"\s*:\s*\{',
        r'"database"\s*:\s*\{',
        r'user\s+management:\s*enabled',
        r'privileged\s+management\s+controls',
        r'privileged\s+access\s+granted',
        r'delete\s+user',
        r'system\s+configuration',
        r'admin\s+(?:portal|dashboard|console|panel)',
    ]

    @property
    def name(self) -> str:
        return "Access Control & IDOR Analyzer"

    @property
    def description(self) -> str:
        return (
            "Analyzes URLs, routing patterns, and response status for IDOR indicators and unauthorized access. "
            "Explicitly separates heuristic pattern observations from verified vulnerabilities."
        )

    def analyze(self, transaction: HTTPTransaction) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        parsed = urlparse(transaction.url)
        path = parsed.path
        url = transaction.url
        body = transaction.response_body or ""
        body_lower = body.lower()

        # -------------------------------------------------------------
        # 1. Sequential Integer Identifier in URL (HEURISTIC INDICATOR)
        # -------------------------------------------------------------
        # Filter out static assets (e.g. /items/1.png)
        is_static_asset = any(path.lower().endswith(ext) for ext in self.STATIC_EXTENSIONS)

        if not is_static_asset:
            # Matches paths like /api/Users/1, /rest/basket/5, /profile/42
            # Avoid matching API versioning segments like /api/v1/users
            idor_match = re.search(
                r"/(users?|baskets?|orders?|accounts?|invoices?|items?|profiles?)/(\d+)(?:/|$|\?)",
                path,
                re.IGNORECASE,
            )
            if idor_match:
                resource_type = idor_match.group(1)
                identifier = idor_match.group(2)
                findings.append(
                    VulnerabilityFinding(
                        finding_id="SEC-AC-001",
                        title=f"Heuristic Indicator: Potential IDOR via Sequential Identifier ('/{resource_type}/{identifier}')",
                        category="Broken Access Control",
                        severity=SeverityLevel.LOW,
                        priority_rationale=(
                            "Assigned LOW severity and HEURISTIC confidence because sequential numeric IDs "
                            "are an architectural design indicator of potential IDOR susceptibility, but do NOT "
                            "confirm unauthorized cross-user access without multi-account authorization testing."
                        ),
                        confidence=ConfidenceLevel.HEURISTIC,
                        confidence_explanation=(
                            "Confidence is HEURISTIC: No cross-user access has been actively verified. "
                            "The presence of a predictable identifier in the route suggests an IDOR pattern, "
                            "but the backend may properly enforce session ownership on this object."
                        ),
                        finding_type=FindingType.HEURISTIC,
                        finding_tier=FindingTier.HEURISTIC_INDICATOR,
                        target_url=url,
                        description=(
                            f"The endpoint references private user resources ('{resource_type}') via a sequential, "
                            f"predictable integer identifier ('{identifier}'). "
                            "This represents an architectural heuristic for Insecure Direct Object References (IDOR). "
                            "If the backend fails to verify that the active session owns the requested resource, "
                            "unauthorized users can access or tamper with other users' data."
                        ),
                        impact=(
                            "If ownership checks are omitted, an attacker can iterate through sequential IDs "
                            "(e.g., 1, 2, 3...) to view, modify, or delete other users' records, orders, or PII."
                        ),
                        evidence=(
                            f"HEURISTIC PATTERN: Route path '{path}' contains sequential identifier '{identifier}' "
                            f"for resource '{resource_type}'. Status: {transaction.status_code}. "
                            "Note: Authorization bypass not verified without second-account differential testing."
                        ),
                        remediation=(
                            "1. Implement server-side authorization checks on every data access call: "
                            "verify `resource.owner_id == session.current_user_id`.\n"
                            "2. Use non-sequential, cryptographically random identifiers (e.g., UUIDv4) "
                            "instead of auto-incrementing primary keys.\n"
                            "3. Derive identity from authenticated session tokens rather than client-supplied route parameters."
                        ),
                        cwe_id="CWE-639",
                        owasp_category="A01:2021-Broken Access Control",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                            "https://portswigger.net/web-security/access-control/idor",
                        ],
                    )
                )

        # -------------------------------------------------------------
        # 2. Administrative Route Analysis (VERIFIED vs FALSE POSITIVE)
        # -------------------------------------------------------------
        admin_patterns = [
            r"^/admin\b",
            r"^/api/admin\b",
            r"^/actuator\b",
            r"^/metrics\b",
            r"^/internal\b",
            r"^/debug\b",
            r"^/management\b",
        ]
        is_admin_path = any(re.search(pat, path, re.IGNORECASE) for pat in admin_patterns)
        has_auth_header = any(
            h.lower() in ("authorization", "x-api-key") for h in transaction.request_headers
        )

        if is_admin_path and transaction.status_code == 200 and not has_auth_header:
            # Check for false positives: does the response display a login/authentication challenge?
            is_login_challenge = any(re.search(pat, body, re.IGNORECASE) for pat in self.LOGIN_INDICATORS)
            has_privileged_content = any(re.search(pat, body, re.IGNORECASE) for pat in self.ADMIN_CONTENT_INDICATORS)

            if is_login_challenge:
                # Edge case / False positive prevention: It's an authentication portal, not unauthenticated admin access!
                findings.append(
                    VulnerabilityFinding(
                        finding_id="SEC-AC-002-INFO",
                        title=f"Informational: Administrative Login Interface Exposed ('{path}')",
                        category="Information Exposure",
                        severity=SeverityLevel.INFO,
                        priority_rationale=(
                            "Assigned INFORMATIONAL severity because the endpoint requires authentication and presents "
                            "a login challenge rather than leaking unauthenticated administrative controls."
                        ),
                        confidence=ConfidenceLevel.HIGH,
                        confidence_explanation=(
                            "Confidence is HIGH that an admin login interface exists, but it is NOT an access control "
                            "bypass because credentials are required to proceed."
                        ),
                        finding_type=FindingType.HEURISTIC,
                        finding_tier=FindingTier.OBSERVATION,
                        target_url=url,
                        description=(
                            f"The administrative route '{path}' responded with HTTP 200 OK containing an authentication "
                            "login challenge or sign-in form."
                        ),
                        impact=(
                            "Publicly exposing administrative login portals permits targeted password brute-forcing "
                            "and credential stuffing if not protected by multi-factor authentication or network allowlisting."
                        ),
                        evidence=(
                            f"GET {path} returned HTTP 200 OK with login challenge HTML form. "
                            f"Form elements observed in response body: {body[:200]}..."
                        ),
                        remediation=(
                            "Restrict administrative interfaces to trusted internal networks or VPNs. "
                            "Enforce Multi-Factor Authentication (MFA) and rate limiting on the login portal."
                        ),
                        cwe_id="CWE-284",
                        owasp_category="A01:2021-Broken Access Control",
                        references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                    )
                )
            elif has_privileged_content:
                # VERIFIED CRITICAL VULNERABILITY: Unauthenticated administrative data/controls exposed with reproducible proof
                findings.append(
                    VulnerabilityFinding(
                        finding_id="SEC-AC-002",
                        title=f"Unauthenticated Access to Administrative Endpoint: '{path}'",
                        category="Broken Access Control",
                        severity=SeverityLevel.CRITICAL,
                        priority_rationale=(
                            "Assigned CRITICAL severity because privileged administrative functionality "
                            "or sensitive system internals were accessed directly without any authentication credentials."
                        ),
                        confidence=ConfidenceLevel.CONFIRMED,
                        confidence_explanation=(
                            "Confidence is CONFIRMED: Reproducible supporting evidence confirms that an unauthenticated "
                            "HTTP GET request returned HTTP 200 with privileged content/telemetry without a login requirement."
                        ),
                        finding_type=FindingType.VERIFIED,
                        finding_tier=FindingTier.INDEPENDENTLY_VERIFIED,
                        target_url=url,
                        description=(
                            f"The sensitive endpoint '{path}' returned HTTP 200 OK without any Authorization header "
                            "or session credentials provided in the request, and exposed administrative data or controls."
                        ),
                        impact=(
                            "Direct administrative access without authentication allows unauthorized users to perform "
                            "privileged operations, access internal metrics/telemetry, or compromise the application."
                        ),
                        evidence=(
                            f"REPRODUCIBLE EVIDENCE: Unauthenticated GET request to '{path}' returned HTTP 200 OK. "
                            f"Privileged response body snippet ({len(body)} bytes): {body[:250]}..."
                        ),
                        remediation=(
                            "Enforce strict authentication and Role-Based Access Control (RBAC) middleware across "
                            "all administrative routes. Ensure access is denied by default (HTTP 401 Unauthorized / "
                            "403 Forbidden) unless an explicit administrative session is validated."
                        ),
                        cwe_id="CWE-306",
                        owasp_category="A01:2021-Broken Access Control",
                        references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                    )
                )
            else:
                # Neutral 200 on admin route: Path matches admin pattern but privileged data not proven
                # Never infer CRITICAL severity from status code alone!
                findings.append(
                    VulnerabilityFinding(
                        finding_id="SEC-AC-002-SUSPECT",
                        title=f"Heuristic Indicator: Accessible Route on Administrative Prefix ('{path}')",
                        category="Broken Access Control",
                        severity=SeverityLevel.LOW,
                        priority_rationale=(
                            "Assigned LOW severity and HEURISTIC confidence because the endpoint matches an administrative "
                            "path prefix and returned HTTP 200 OK, but no privileged controls or data were verified in response."
                        ),
                        confidence=ConfidenceLevel.HEURISTIC,
                        confidence_explanation=(
                            "Confidence is HEURISTIC: Critical severity is not inferred from status code 200 alone. "
                            "The response body lacks explicit privileged administrative data or management controls."
                        ),
                        finding_type=FindingType.HEURISTIC,
                        finding_tier=FindingTier.HEURISTIC_INDICATOR,
                        target_url=url,
                        description=(
                            f"The route '{path}' begins with an administrative prefix and responded with HTTP 200 OK, "
                            "but does not display obvious administrative management controls in the response body."
                        ),
                        impact=(
                            "May expose non-sensitive administrative documentation or empty views. "
                            "Requires manual authenticated differential testing to determine actual impact."
                        ),
                        evidence=(
                            f"GET {path} returned HTTP 200 OK without credentials, but lacks privileged content indicators. "
                            f"Response snippet: {body[:200]}..."
                        ),
                        remediation=(
                            "Audit route authorization policies to ensure all routes beneath /admin require authentication."
                        ),
                        cwe_id="CWE-284",
                        owasp_category="A01:2021-Broken Access Control",
                        references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                    )
                )

        # -------------------------------------------------------------
        # 3. Stack Trace / Database Error String Disclosure (VERIFIED)
        # -------------------------------------------------------------
        error_indicators = [
            "SQL syntax",
            "SequelizeDatabaseError",
            "org.hibernate",
            "Traceback (most recent call last):",
            "at Object.<anonymous>",
            "NullPointerException",
            "SyntaxError: Unexpected token",
        ]
        for indicator in error_indicators:
            if indicator.lower() in body_lower:
                findings.append(
                    VulnerabilityFinding(
                        finding_id="SEC-AC-003",
                        title=f"Detailed Application Stack Trace / Database Error Disclosure: '{indicator}'",
                        category="Information Exposure",
                        severity=SeverityLevel.MEDIUM,
                        priority_rationale=(
                            "Assigned MEDIUM severity because technical error details aid reconnaissance and attack "
                            "tailoring, but do not provide direct remote code execution by themselves."
                        ),
                        confidence=ConfidenceLevel.CONFIRMED,
                        confidence_explanation=(
                            "Confidence is CONFIRMED: A verifiable stack trace or database error string was directly "
                            "observed in the server response body."
                        ),
                        finding_type=FindingType.VERIFIED,
                        finding_tier=FindingTier.INDEPENDENTLY_VERIFIED,
                        target_url=url,
                        description=(
                            f"The server response includes sensitive stack trace or error strings ('{indicator}'). "
                            "This occurs when production debug mode is active or unhandled exceptions bubble to the client."
                        ),
                        impact=(
                            "Exposes underlying database schemas, internal filenames, line numbers, and programming "
                            "frameworks, greatly assisting an attacker in constructing injection attacks."
                        ),
                        evidence=(
                            f"REPRODUCIBLE EVIDENCE: Matched error string '{indicator}' in response body snippet: "
                            f"{body[:250]}..."
                        ),
                        remediation=(
                            "Disable verbose error messages in production. Implement global exception handlers "
                            "that return generic error messages (e.g., 'An internal error occurred') while logging "
                            "full stack traces internally."
                        ),
                        cwe_id="CWE-209",
                        owasp_category="A05:2021-Security Misconfiguration",
                        references=["https://owasp.org/www-community/Improper_Error_Handling"],
                    )
                )
                break  # Don't duplicate for multiple stack strings

        return findings
