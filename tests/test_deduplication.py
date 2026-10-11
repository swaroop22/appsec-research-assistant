from appsec_assistant.models import HTTPTransaction, TargetConfig
from appsec_assistant.engine import AuditEngine


def test_audit_engine_deduplicates_sitewide_headers():
    engine = AuditEngine(TargetConfig(base_url="http://localhost:5000"))

    # Transaction 1: Root endpoint missing CSP and nosniff
    tx1 = HTTPTransaction(
        url="http://localhost:5000/",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={"Content-Type": "text/html"},
        response_body="<html>Root</html>",
    )

    # Transaction 2: API endpoint on same host missing CSP and nosniff
    tx2 = HTTPTransaction(
        url="http://localhost:5000/api/data",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"status": "ok"}',
    )

    engine.audit_transaction(tx1)
    initial_count = len(engine.findings)

    # Audit second transaction
    new_from_tx2 = engine.audit_transaction(tx2)

    # Verify that sitewide headers (SEC-HDR-001, SEC-HDR-004, etc.) were NOT duplicated
    finding_ids = [f.finding_id for f in engine.findings]
    assert finding_ids.count("SEC-HDR-001") == 1
    assert finding_ids.count("SEC-HDR-004") == 1

    # Verify that affected_urls on the consolidated finding includes both endpoints
    csp_finding = next(f for f in engine.findings if f.finding_id == "SEC-HDR-001")
    assert "http://localhost:5000/" in csp_finding.affected_urls
    assert "http://localhost:5000/api/data" in csp_finding.affected_urls
    assert "Observed across 2 endpoints" in csp_finding.evidence


def test_audit_engine_canonicalizes_trailing_slashes():
    engine = AuditEngine(TargetConfig(base_url="http://localhost:5000"))

    # Endpoint with and without trailing slash
    tx1 = HTTPTransaction(
        url="http://localhost:5000/admin",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={},
        response_body="<h1>Admin Dashboard</h1>",
    )
    tx2 = HTTPTransaction(
        url="http://localhost:5000/admin/",
        method="GET",
        request_headers={},
        status_code=200,
        response_headers={},
        response_body="<h1>Admin Dashboard</h1>",
    )

    engine.audit_transaction(tx1)
    engine.audit_transaction(tx2)

    admin_findings = [f for f in engine.findings if f.finding_id == "SEC-AC-002"]
    assert len(admin_findings) == 1
