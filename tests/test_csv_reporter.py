import csv
import io
from appsec_assistant.models import VulnerabilityFinding, SeverityLevel
from appsec_assistant.reporters.csv_reporter import CSVReporter


def test_csv_reporter_generates_valid_csv():
    findings = [
        VulnerabilityFinding(
            finding_id="SEC-HDR-001",
            title="Missing Content-Security-Policy (CSP) Header",
            category="Security Headers",
            severity=SeverityLevel.MEDIUM,
            priority_rationale="Assigned MEDIUM priority as a defense-in-depth mitigation.",
            target_url="http://localhost/",
            description="The response lacks CSP.",
            impact="Susceptible to XSS execution.",
            evidence="CSP missing.",
            remediation="Add Content-Security-Policy header.",
            cwe_id="CWE-1021",
            owasp_category="A05:2021-Security Misconfiguration",
        ),
        VulnerabilityFinding(
            finding_id="SEC-CK-001-session_id",
            title="Cookie Missing HttpOnly Flag: 'session_id'",
            category="Cookie Security",
            severity=SeverityLevel.HIGH,
            priority_rationale="Assigned HIGH priority because token is readable by scripts.",
            target_url="http://localhost/",
            description="Cookie lacks HttpOnly.",
            impact="Direct token exfiltration via XSS.",
            evidence="Cookie: session_id",
            remediation="Add HttpOnly flag.",
            cwe_id="CWE-1004",
            owasp_category="A05:2021-Security Misconfiguration",
        ),
    ]

    csv_output = CSVReporter.generate(findings)
    assert csv_output is not None

    reader = csv.DictReader(io.StringIO(csv_output))
    rows = list(reader)

    assert len(rows) == 2
    assert rows[0]["finding_id"] == "SEC-HDR-001"
    assert rows[0]["severity"] == "MEDIUM"
    assert "defense-in-depth" in rows[0]["priority_rationale"]
    assert rows[1]["finding_id"] == "SEC-CK-001-session_id"
    assert rows[1]["severity"] == "HIGH"
