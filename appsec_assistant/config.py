"""
Scope Guard and Security Configuration.

Enforces strict boundaries so that the assistant only interacts with
authorized local training environments (e.g. OWASP Juice Shop on localhost/127.0.0.1).
"""

import ipaddress
import socket
from typing import List, Optional
from urllib.parse import urlparse


class ScopeViolationError(Exception):
    """Raised when an operation attempts to target an unauthorized or out-of-scope host."""
    pass


class ScopeGuard:
    """
    Guarantees that security analysis is strictly confined to authorized local lab environments.
    Blocks remote, production, or unapproved hostnames and IP addresses.
    """

    DEFAULT_ALLOWED_HOSTS = ["localhost", "127.0.0.1", "::1"]

    def __init__(self, allowed_hosts: Optional[List[str]] = None, allow_private_subnets: bool = False):
        self.allowed_hosts = set(allowed_hosts or self.DEFAULT_ALLOWED_HOSTS)
        self.allow_private_subnets = allow_private_subnets

    def validate_url(self, url: str) -> str:
        """
        Validates that a URL is well-formed and targets strictly within authorized local scope.
        Returns the sanitized URL if valid, or raises ScopeViolationError.
        """
        if not url:
            raise ScopeViolationError("Target URL cannot be empty.")

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolationError(
                f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are permitted."
            )

        hostname = parsed.hostname
        if not hostname:
            raise ScopeViolationError(f"Could not extract a valid hostname from '{url}'.")

        hostname_lower = hostname.lower()

        # Check explicit allowed hostnames
        if hostname_lower in self.allowed_hosts:
            return url

        # Check if the hostname resolves or is a loopback IP
        try:
            ip_obj = ipaddress.ip_address(hostname_lower)
            if ip_obj.is_loopback:
                return url
            if self.allow_private_subnets and ip_obj.is_private:
                return url
            raise ScopeViolationError(
                f"IP address '{hostname}' is not a permitted local training address. "
                "Active testing is strictly restricted to loopback interfaces (localhost/127.0.0.1)."
            )
        except ValueError:
            # It's a hostname, not a raw IP address
            pass

        # Check resolution for localhost aliases
        try:
            resolved_ip = socket.gethostbyname(hostname_lower)
            resolved_obj = ipaddress.ip_address(resolved_ip)
            if resolved_obj.is_loopback:
                return url
        except Exception:
            pass

        raise ScopeViolationError(
            f"Security Boundary Violation: Target '{hostname}' is outside the authorized local lab scope. "
            f"Permitted targets: {sorted(list(self.allowed_hosts))}. "
            "Defensive analysis is intentionally restricted to local training environments like OWASP Juice Shop."
        )

    def is_in_scope(self, url: str) -> bool:
        """Helper returning True/False without raising an exception."""
        try:
            self.validate_url(url)
            return True
        except ScopeViolationError:
            return False
