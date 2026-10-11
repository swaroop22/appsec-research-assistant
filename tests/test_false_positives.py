from appsec_assistant.analyzers.access_control_analyzer import AccessControlAnalyzer
from appsec_assistant.models import (
    HTTPTransaction,
    SeverityLevel,
    ConfidenceLevel,
    FindingType,
)


def test_admin_login_page_is_not_flagged_as_critical_bypass():
    """
    Regression Test: A 200 OK on /admin containing an HTML login form is an
    authentication portal, NOT an unauthenticated admin access bypass.
    """
    analyzer = AccessControlAnalyzer()
    login_transaction = HTTPTransaction(
        url="http://localhost:5000/admin/login",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={"Content-Type": "text/html"},
        response_body="""
        <html>
            <body>
                <h1>Admin Portal Login</h1>
                <form action="/auth/login" method="POST">
                    <label>Username</label><input type="text" name="username" />
                    <label>Password</label><input type="password" name="password" />
                    <button type="submit">Log In</button>
                </form>
            </body>
        </html>
        """,
    )

    findings = analyzer.analyze(login_transaction)
    finding_ids = [f.finding_id for f in findings]

    # Crucial assertion: Must NOT be flagged as Critical SEC-AC-002
    assert "SEC-AC-002" not in finding_ids

    # May only be flagged as Informational login challenge
    if findings:
        info_finding = findings[0]
        assert info_finding.severity == SeverityLevel.INFO
        assert info_finding.finding_type == FindingType.HEURISTIC
        assert "Login Interface" in info_finding.title


def test_verified_admin_exposure_is_confirmed():
    """
    When an admin endpoint returns actual privileged controls without auth,
    it must be explicitly flagged as VERIFIED with CONFIRMED confidence.
    """
    analyzer = AccessControlAnalyzer()
    admin_transaction = HTTPTransaction(
        url="http://localhost:5000/admin",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={"Content-Type": "text/html"},
        response_body="<h1>Admin Dashboard</h1><p>Privileged management controls available.</p><p>user_management: enabled</p>",
    )

    findings = analyzer.analyze(admin_transaction)
    finding_ids = [f.finding_id for f in findings]

    assert "SEC-AC-002" in finding_ids
    f_admin = next(f for f in findings if f.finding_id == "SEC-AC-002")

    assert f_admin.severity == SeverityLevel.CRITICAL
    assert f_admin.confidence == ConfidenceLevel.CONFIRMED
    assert f_admin.finding_type == FindingType.VERIFIED
    assert "REPRODUCIBLE EVIDENCE" in f_admin.evidence
    assert f_admin.confidence_explanation != ""


def test_static_asset_not_flagged_as_idor():
    """
    Regression Test: Static files with numeric IDs (e.g. /items/1.png)
    must NOT be flagged as IDOR.
    """
    analyzer = AccessControlAnalyzer()
    static_transaction = HTTPTransaction(
        url="http://localhost:5000/items/1.png",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={"Content-Type": "image/png"},
        response_body="\x89PNG\r\n\x1a\n...",
    )

    findings = analyzer.analyze(static_transaction)
    assert len(findings) == 0


def test_idor_finding_is_heuristic_indicator():
    """
    IDOR pattern checks must be explicitly marked as HEURISTIC,
    not claimed as verified without differential cross-account proof.
    """
    analyzer = AccessControlAnalyzer()
    idor_transaction = HTTPTransaction(
        url="http://localhost:5000/api/Users/42",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"id": 42, "name": "Alice"}',
    )

    findings = analyzer.analyze(idor_transaction)
    assert len(findings) == 1
    f_idor = findings[0]

    assert f_idor.finding_id == "SEC-AC-001"
    assert f_idor.finding_type == FindingType.HEURISTIC
    assert f_idor.confidence == ConfidenceLevel.HEURISTIC
    assert f_idor.severity == SeverityLevel.LOW
    assert "Heuristic Indicator" in f_idor.title
    assert "No cross-user access has been actively verified" in f_idor.confidence_explanation


def test_admin_route_401_or_403_is_not_flagged():
    """
    If /admin returns 401 or 403, access control is enforced.
    """
    analyzer = AccessControlAnalyzer()
    for status in (401, 403):
        denied_tx = HTTPTransaction(
            url="http://localhost:5000/admin",
            method="GET",
            request_headers={},
            status_code=status,
            response_headers={},
            response_body="Access Denied",
        )
        findings = analyzer.analyze(denied_tx)
        assert len(findings) == 0
