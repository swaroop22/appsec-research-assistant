"""
Access Control and IDOR Pattern Analyzer.

Audits URLs, routes, and responses for common Broken Access Control and
Insecure Direct Object Reference (IDOR) architectural patterns.
"""

import re
from typing import List
from urllib.parse import urlparse
from appsec_assistant.analyzers.base import BaseAnalyzer
from appsec_assistant.models import HTTPTransaction, VulnerabilityFinding, SeverityLevel


class AccessControlAnalyzer(BaseAnalyzer):
    """Audits endpoint architecture for IDOR patterns and authorization weaknesses."""

    @property
    def name(self) -> str:
        return "Access Control & IDOR Analyzer"

    @property
    def description(self) -> str:
        return "Analyzes URLs, routing patterns, and response status for IDOR indicators and unauthorized access."

    def analyze(self, transaction: HTTPTransaction) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        parsed = urlparse(transaction.url)
        path = parsed.path
        url = transaction.url

        # 1. Sequential Integer Identifier in URL (IDOR Indicator)
        # Matches paths like /api/Users/1, /rest/basket/5, /profile/42, etc.
        idor_match = re.search(r"/(users?|baskets?|orders?|accounts?|invoices?|items?|profiles?)/(\d+)(?:/|$|\?)", path, re.IGNORECASE)
        if idor_match:
            resource_type = idor_match.group(1)
            identifier = idor_match.group(2)
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-AC-001",
                    title=f"Potential Insecure Direct Object Reference (IDOR) in '/{resource_type}/{identifier}'",
                    category="Broken Access Control",
                    severity=SeverityLevel.HIGH,
                    target_url=url,
                    description=(
                        f"The endpoint references private user resources ('{resource_type}') via sequential, "
                        f"predictable integer identifiers ('{identifier}'). "
                        "If the backend relies solely on the client-supplied identifier without verifying "
                        "that the authenticated user owns this resource, horizontal or vertical privilege escalation occurs."
                    ),
                    impact=(
                        "An attacker can iterate through sequential IDs (e.g., 1, 2, 3...) to view, modify, "
                        "or delete other users' records, orders, or personally identifiable information (PII)."
                    ),
                    evidence=f"Request URL contains predictable resource identifier: {path}",
                    remediation=(
                        "1. Implement server-side authorization checks on every data access call: "
                        "verify `resource.owner_id == session.current_user_id`.\n"
                        "2. Use non-sequential, cryptographically unguessable identifiers (e.g., UUIDv4) "
                        "instead of auto-incrementing database primary keys.\n"
                        "3. Rely on session context rather than client-supplied parameters for user identity."
                    ),
                    cwe_id="CWE-639",
                    owasp_category="A01:2021-Broken Access Control",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                        "https://portswigger.net/web-security/access-control/idor",
                    ],
                )
            )

        # 2. Sensitive Administrative Route Accessible Without Authentication
        admin_patterns = [
            r"^/admin",
            r"^/api/admin",
            r"^/actuator",
            r"^/metrics",
            r"^/internal",
            r"^/debug",
            r"^/management",
        ]
        is_admin_path = any(re.search(pat, path, re.IGNORECASE) for pat in admin_patterns)
        has_auth_header = any(h.lower() in ("authorization", "x-api-key") for h in transaction.request_headers)

        if is_admin_path and transaction.status_code == 200 and not has_auth_header:
            findings.append(
                VulnerabilityFinding(
                    finding_id="SEC-AC-002",
                    title=f"Unauthenticated Access to Administrative Endpoint: '{path}'",
                    category="Broken Access Control",
                    severity=SeverityLevel.CRITICAL,
                    target_url=url,
                    description=(
                        f"The sensitive endpoint '{path}' returned HTTP 200 OK without any Authorization header "
                        "or authentication credentials provided in the request."
                    ),
                    impact=(
                        "Direct administrative access without authentication allows unauthorized users to perform "
                        "privileged operations, view confidential telemetry, or compromise the entire application."
                    ),
                    evidence=f"GET {path} returned HTTP 200 OK without Authorization headers present.",
                    remediation=(
                        "Enforce strict authentication and Role-Based Access Control (RBAC) middleware across "
                        "all administrative routes. Ensure access is denied by default (401/403) unless an explicit "
                        "administrative session is validated."
                    ),
                    cwe_id="CWE-306",
                    owasp_category="A01:2021-Broken Access Control",
                    references=[
                        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                    ],
                )
            )

        # 3. Stack Trace / Detailed Database Error Disclosure
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
            if indicator.lower() in transaction.response_body.lower():
                findings.append(
                    VulnerabilityFinding(
                        finding_id="SEC-AC-003",
                        title=f"Detailed Application Stack Trace / Database Error Disclosure: '{indicator}'",
                        category="Information Exposure",
                        severity=SeverityLevel.MEDIUM,
                        target_url=url,
                        description=(
                            f"The server response includes sensitive stack trace or error strings ('{indicator}'). "
                            "This occurs when production debug mode is active or unhandled exceptions bubble to the client."
                        ),
                        impact=(
                            "Exposes underlying database schemas, internal filenames, line numbers, and programming "
                            "frameworks, greatly assisting an attacker in constructing injection attacks."
                        ),
                        evidence=f"Matched error indicator '{indicator}' in response body snippet: {transaction.response_body[:200]}...",
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
