from appsec_assistant.analyzers.cookies_analyzer import CookiesAnalyzer
from appsec_assistant.models import HTTPTransaction, SeverityLevel


def test_cookies_analyzer_detects_insecure_cookie():
    analyzer = CookiesAnalyzer()
    transaction = HTTPTransaction(
        url="http://localhost:3000/login",
        method="POST",
        request_headers={},
        status_code=200,
        response_headers={},
        response_body="{}",
        cookies=[
            {
                "name": "session_id",
                "value": "xyz123",
                "domain": "localhost",
                "path": "/",
                "secure": False,
                "httponly": False,
                "samesite": None,
            }
        ],
    )

    findings = analyzer.analyze(transaction)
    finding_ids = [f.finding_id for f in findings]

    assert "SEC-CK-001-session_id" in finding_ids  # Missing HttpOnly
    assert "SEC-CK-002-session_id" in finding_ids  # Missing Secure
    assert "SEC-CK-003-session_id" in finding_ids  # Missing SameSite

    httponly_f = next(f for f in findings if f.finding_id == "SEC-CK-001-session_id")
    assert httponly_f.severity == SeverityLevel.HIGH  # Sensitive cookie marked HIGH


def test_cookies_analyzer_passes_hardened_cookie():
    analyzer = CookiesAnalyzer()
    transaction = HTTPTransaction(
        url="https://localhost:3000/login",
        method="POST",
        request_headers={},
        status_code=200,
        response_headers={},
        response_body="{}",
        cookies=[
            {
                "name": "secure_session",
                "value": "random_token_456",
                "domain": "localhost",
                "path": "/",
                "secure": True,
                "httponly": True,
                "samesite": "Strict",
            }
        ],
    )

    findings = analyzer.analyze(transaction)
    assert len(findings) == 0
