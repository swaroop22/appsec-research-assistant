"""
Data models for the security analysis assistant.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime


class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def color(self) -> str:
        colors = {
            "INFO": "blue",
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "bright_red",
            "CRITICAL": "bold red on white",
        }
        return colors.get(self.value, "white")

    @property
    def rank(self) -> int:
        ranks = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return ranks.get(self.value, 0)


@dataclass
class VulnerabilityFinding:
    """Represents a discovered security finding with evidence and remediation."""
    finding_id: str
    title: str
    category: str
    severity: SeverityLevel
    target_url: str
    description: str
    impact: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    references: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "target_url": self.target_url,
            "description": self.description,
            "impact": self.impact,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "references": self.references,
            "timestamp": self.timestamp,
        }


@dataclass
class HTTPTransaction:
    """Represents an captured HTTP request/response transaction for auditing."""
    url: str
    method: str
    request_headers: Dict[str, str]
    status_code: int
    response_headers: Dict[str, str]
    response_body: str
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )


@dataclass
class TargetConfig:
    """Configuration for an authorized local training target."""
    base_url: str
    allowed_hosts: List[str] = field(
        default_factory=lambda: ["localhost", "127.0.0.1", "::1"]
    )
    rate_limit_delay: float = 0.2  # 200ms delay between requests to prevent aggressive traffic
    timeout: float = 5.0
    user_agent: str = "AppSec-Research-Assistant/1.0 (Educational/Defensive-Audit)"
