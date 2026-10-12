"""
End-to-End Integration Tests for AI-Assisted Triage and Multi-Format Reporting (Phase 4).
"""

import json
import csv
import io
import pytest

from appsec_assistant.models import (
    VulnerabilityFinding,
    SeverityLevel,
    ConfidenceLevel,
    FindingTier,
    TargetConfig,
)
from appsec_assistant.engine import AuditEngine
from appsec_assistant.lab_server import LocalLabServer
from appsec_assistant.ai import AIService, AIProviderConfig, PriorityLevel
from appsec_assistant.reporters.markdown_reporter import MarkdownReporter
from appsec_assistant.reporters.json_reporter import JSONReporter
from appsec_assistant.reporters.csv_reporter import CSVReporter


@pytest.fixture
def triaged_finding():
    finding = VulnerabilityFinding(
        finding_id="SEC-HDR-001",
        title="Missing Content-Security-Policy (CSP) Header",
        category="Security Headers",
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        confidence_explanation="Evaluated directly from HTTP response headers.",
        finding_tier=FindingTier.SUSPECTED_VULNERABILITY,
        target_url="http://127.0.0.1:5000/",
        description="The HTTP response does not include a Content-Security-Policy header.",
        impact="Increases susceptibility to Cross-Site Scripting (XSS).",
        evidence="HTTP/1.1 200 OK without Content-Security-Policy",
        remediation="Define and configure a strict CSP header.",
    )

    ai_service = AIService()
    ai_service.triage_finding(finding)
    return finding


def test_ai_triage_enriches_finding(triaged_finding):
    """Verifies that AI triage enriches finding data model with all required structured fields."""
    assert triaged_finding.ai_triage is not None
    ai = triaged_finding.ai_triage

    assert "plain_english_explanation" in ai
    assert "observed_evidence" in ai
    assert "why_evidence_matters" in ai
    assert "realistic_potential_impact" in ai
    assert "alternative_explanations" in ai
    assert "missing_information" in ai
    assert "recommended_next_steps" in ai
    assert "suggested_remediation" in ai
    assert "confidence_rationale" in ai
    assert "severity_rationale" in ai
    assert "recommended_priority" in ai
    assert "recommended_priority_rationale" in ai
    assert "potential_false_positive" in ai
    assert "evidence_references" in ai

    # Verify Priority is distinct and present
    assert ai["recommended_priority"] in [p.value for p in PriorityLevel]


def test_markdown_report_includes_ai_triage(triaged_finding):
    """Verifies that generated Markdown reports render AI-assisted triage analysis sections."""
    md = MarkdownReporter.generate([triaged_finding], target_url="http://127.0.0.1:5000/")

    assert "AI-Assisted Triage Analysis" in md
    assert "Plain-English Explanation:" in md
    assert "Why Evidence Matters:" in md
    assert "Realistic Potential Impact:" in md
    assert "Alternative Explanations:" in md
    assert "Recommended Review Priority:" in md


def test_json_report_includes_ai_triage(triaged_finding):
    """Verifies that generated JSON reports serialize complete AI triage metadata."""
    json_str = JSONReporter.generate([triaged_finding], target_url="http://127.0.0.1:5000/")
    data = json.loads(json_str)

    assert "findings" in data
    assert len(data["findings"]) == 1
    f_json = data["findings"][0]

    assert "ai_triage" in f_json
    assert f_json["ai_triage"] is not None
    assert f_json["ai_triage"]["finding_id"] == "SEC-HDR-001"
    assert f_json["ai_triage"]["recommended_priority"] == "MEDIUM"


def test_csv_report_includes_ai_triage(triaged_finding):
    """Verifies that generated CSV reports include ai_priority and ai_explanation columns."""
    csv_str = CSVReporter.generate([triaged_finding])
    reader = csv.DictReader(io.StringIO(csv_str))
    rows = list(reader)

    assert len(rows) == 1
    row = rows[0]
    assert "ai_priority" in row
    assert row["ai_priority"] == "MEDIUM"
    assert "ai_explanation" in row
    assert len(row["ai_explanation"]) > 5
    assert "ai_false_positive_risk" in row
    assert row["ai_false_positive_risk"] in ("YES", "NO")
