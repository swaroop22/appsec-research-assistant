from appsec_assistant.analyzers.headers_analyzer import HeadersAnalyzer
from appsec_assistant.models import HTTPTransaction, SeverityLevel


def test_headers_analyzer_detects_missing_headers():
    analyzer = HeadersAnalyzer()
    transaction = HTTPTransaction(
        url="http://localhost:3000/",
        method="GET",
        request_headers={"User-Agent": "Test"},
        status_code=200,
        response_headers={
            "Server": "Express/4.17.1",
            "X-Powered-By": "Express",
            "Access-Control-Allow-Origin": "*",
        },
        response_body="<html><body>Hello</body></html>",
    )

    findings = analyzer.analyze(transaction)
    finding_ids = [f.finding_id for f in findings]

    assert "SEC-HDR-001" in finding_ids  # Missing CSP
    assert "SEC-HDR-003" in finding_ids  # Missing X-Frame-Options
    assert "SEC-HDR-004" in finding_ids  # Missing X-Content-Type-Options
    assert "SEC-HDR-005" in finding_ids  # Missing HSTS
    assert "SEC-HDR-006" in finding_ids  # Info disclosure in Server/X-Powered-By
    assert "SEC-HDR-007" in finding_ids  # Permissive CORS
    assert "SEC-HDR-008" in finding_ids  # Missing Referrer-Policy

    # Requirement 6 validation: Ensure NO missing header is labeled CRITICAL
    for f in findings:
        assert f.severity != SeverityLevel.CRITICAL
        assert f.priority_rationale != ""  # Clear explanation of assigned priority
        assert f.impact != ""
        assert f.remediation != ""


def test_headers_analyzer_detects_weak_referrer_and_csp():
    analyzer = HeadersAnalyzer()
    transaction = HTTPTransaction(
        url="https://localhost:3000/",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "Referrer-Policy": "unsafe-url",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Permissions-Policy": "camera=()",
        },
        response_body="<html><body>Test</body></html>",
    )

    findings = analyzer.analyze(transaction)
    finding_ids = [f.finding_id for f in findings]

    assert "SEC-HDR-002" in finding_ids  # Weak CSP
    assert "SEC-HDR-009" in finding_ids  # Weak Referrer-Policy


def test_headers_analyzer_passes_hardened_response():
    analyzer = HeadersAnalyzer()
    transaction = HTTPTransaction(
        url="https://localhost:3000/",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        },
        response_body="<html><body>Secure Page</body></html>",
    )

    findings = analyzer.analyze(transaction)
    assert len(findings) == 0
