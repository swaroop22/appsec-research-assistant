import json
from appsec_assistant.models import VulnerabilityFinding, SeverityLevel
from appsec_assistant.reporters.markdown_reporter import MarkdownReporter
from appsec_assistant.reporters.json_reporter import JSONReporter


def test_markdown_and_json_reporters():
    findings = [
        VulnerabilityFinding(
            finding_id="SEC-TEST-001",
            title="Missing Security Header",
            category="Security Headers",
            severity=SeverityLevel.HIGH,
            target_url="http://localhost:3000/",
            description="Test description.",
            impact="Test impact.",
            evidence="Header missing.",
            remediation="Add header.",
            cwe_id="CWE-1021",
        )
    ]

    # Test Markdown
    md_output = MarkdownReporter.generate(findings, "http://localhost:3000/")
    assert "# Local Web Application Security Audit" in md_output
    assert "SEC-TEST-001" in md_output
    assert "Missing Security Header" in md_output
    assert "CWE-1021" in md_output
    assert "### Severity Distribution" in md_output

    # Test JSON
    json_output = JSONReporter.generate(findings, "http://localhost:3000/")
    data = json.loads(json_output)
    assert data["target_url"] == "http://localhost:3000/"
    assert data["total_findings"] == 1
    assert data["findings"][0]["finding_id"] == "SEC-TEST-001"
    assert data["findings"][0]["severity"] == "HIGH"
