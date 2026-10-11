from appsec_assistant.analyzers.access_control_analyzer import AccessControlAnalyzer
from appsec_assistant.models import HTTPTransaction, SeverityLevel


def test_access_control_detects_idor_indicator():
    analyzer = AccessControlAnalyzer()
    transaction = HTTPTransaction(
        url="http://localhost:3000/api/Users/1",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={},
        response_body='{"id": 1, "email": "user@example.com"}',
    )

    findings = analyzer.analyze(transaction)
    finding_ids = [f.finding_id for f in findings]
    assert "SEC-AC-001" in finding_ids
    assert any("IDOR" in f.title for f in findings)


def test_access_control_detects_unauthenticated_admin():
    analyzer = AccessControlAnalyzer()
    transaction = HTTPTransaction(
        url="http://localhost:3000/admin",
        method="GET",
        request_headers={"User-Agent": "Mozilla"},
        status_code=200,
        response_headers={},
        response_body="<h1>Admin Portal</h1>",
    )

    findings = analyzer.analyze(transaction)
    finding_ids = [f.finding_id for f in findings]
    assert "SEC-AC-002" in finding_ids
    f_admin = next(f for f in findings if f.finding_id == "SEC-AC-002")
    assert f_admin.severity == SeverityLevel.CRITICAL


def test_access_control_detects_stack_trace_leak():
    analyzer = AccessControlAnalyzer()
    transaction = HTTPTransaction(
        url="http://localhost:3000/search?q=test",
        method="GET",
        request_headers={},
        status_code=500,
        response_headers={},
        response_body="Error: SequelizeDatabaseError: SQL syntax error near line 4",
    )

    findings = analyzer.analyze(transaction)
    finding_ids = [f.finding_id for f in findings]
    assert "SEC-AC-003" in finding_ids
