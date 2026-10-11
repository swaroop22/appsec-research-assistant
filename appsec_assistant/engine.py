"""
Audit Engine coordinating the client, analyzers, and finding aggregation.
"""

from typing import List, Optional
from appsec_assistant.client import SafeHTTPClient
from appsec_assistant.analyzers.base import BaseAnalyzer
from appsec_assistant.analyzers.headers_analyzer import HeadersAnalyzer
from appsec_assistant.analyzers.cookies_analyzer import CookiesAnalyzer
from appsec_assistant.analyzers.access_control_analyzer import AccessControlAnalyzer
from appsec_assistant.models import HTTPTransaction, VulnerabilityFinding, TargetConfig


class AuditEngine:
    """Orchestrates defensive analysis of target endpoints."""

    def __init__(self, config: TargetConfig, analyzers: Optional[List[BaseAnalyzer]] = None):
        self.config = config
        self.client = SafeHTTPClient(config)
        self.analyzers: List[BaseAnalyzer] = analyzers or [
            HeadersAnalyzer(),
            CookiesAnalyzer(),
            AccessControlAnalyzer(),
        ]
        self._findings: List[VulnerabilityFinding] = []

    @property
    def findings(self) -> List[VulnerabilityFinding]:
        return list(self._findings)

    def clear_findings(self) -> None:
        self._findings.clear()

    def audit_transaction(self, transaction: HTTPTransaction) -> List[VulnerabilityFinding]:
        """Runs all configured analyzers against an already-captured transaction."""
        new_findings: List[VulnerabilityFinding] = []
        for analyzer in self.analyzers:
            results = analyzer.analyze(transaction)
            for res in results:
                # Deduplicate by finding_id and target_url
                if not any(f.finding_id == res.finding_id and f.target_url == res.target_url for f in self._findings):
                    self._findings.append(res)
                    new_findings.append(res)
        return new_findings

    def audit_endpoint(self, endpoint_or_url: str, method: str = "GET") -> List[VulnerabilityFinding]:
        """Fetches the endpoint safely and runs all analyzers against the resulting transaction."""
        transaction = self.client.fetch(endpoint_or_url, method=method)
        return self.audit_transaction(transaction)

    def run_suite(self, endpoints: List[str]) -> List[VulnerabilityFinding]:
        """Executes a defensive audit suite across a list of endpoints."""
        all_new: List[VulnerabilityFinding] = []
        for ep in endpoints:
            try:
                res = self.audit_endpoint(ep)
                all_new.extend(res)
            except Exception as e:
                # Log or handle endpoint fetch errors gracefully
                print(f"[!] Warning: Could not audit endpoint '{ep}': {e}")
        return all_new
