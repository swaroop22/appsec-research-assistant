"""
Base interface for all security analyzers.
"""

from abc import ABC, abstractmethod
from typing import List
from appsec_assistant.models import HTTPTransaction, VulnerabilityFinding


class BaseAnalyzer(ABC):
    """Abstract base class that all security analyzers implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Friendly name of the analyzer."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief summary of the checks performed."""
        pass

    @abstractmethod
    def analyze(self, transaction: HTTPTransaction) -> List[VulnerabilityFinding]:
        """
        Performs analysis on a given HTTPTransaction.
        Returns a list of VulnerabilityFinding objects.
        """
        pass
