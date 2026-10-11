from appsec_assistant.knowledge_base import VulnerabilityKnowledgeBase


def test_knowledge_base_topics():
    topics = VulnerabilityKnowledgeBase.get_all_topics()
    assert "idor" in topics
    assert "xss" in topics
    assert "sqli" in topics
    assert "auth" in topics
    assert "broken_access_control" in topics


def test_knowledge_base_guide_content():
    guide = VulnerabilityKnowledgeBase.get_guide("idor")
    assert guide is not None
    assert "Insecure Direct Object References" in guide.title
    assert "CWE-639" in guide.cwe_id
    assert "remediation" in guide.defensive_remediation.lower() or "control" in guide.defensive_remediation.lower()
    assert "Order.query" in guide.code_example


def test_knowledge_base_search():
    results = VulnerabilityKnowledgeBase.search("injection")
    assert len(results) >= 2  # SQLi and XSS
