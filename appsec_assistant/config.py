"""
Scope Guard and Security Configuration.

Enforces strict boundaries so that the assistant only interacts with
authorized local training environments (e.g. OWASP Juice Shop on localhost/127.0.0.1).
Defends against bypasses via alternate IP representations, DNS rebinding,
redirect escapes, and malformed URLs.
"""

import ipaddress
import re
from typing import List, Optional, Set
from urllib.parse import urlparse, unquote


class ScopeViolationError(Exception):
    """Raised when an operation attempts to target an unauthorized or out-of-scope host."""
    pass


def parse_numeric_ip(host_str: str) -> Optional[ipaddress.IPv4Address]:
    """
    Parses IPv4 addresses written in standard, octal, hexadecimal,
    dword (integer), or abbreviated (e.g., 127.1) notation according to inet_aton rules.
    Returns an IPv4Address if valid, or None.
    """
    host = host_str.strip()
    if not host or ":" in host:
        return None

    # Check for single integer/dword or hex value: e.g. 2130706433 or 0x7f000001
    if re.match(r"^0x[0-9a-fA-F]+$", host):
        try:
            val = int(host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            return None

    if re.match(r"^\d+$", host):
        try:
            val = int(host, 10)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            return None

    # Multi-part dotted notation (1 to 4 parts)
    parts = host.split(".")
    if len(parts) > 4:
        return None

    parsed_parts = []
    for part in parts:
        if not part:
            return None
        part_clean = part.strip()
        try:
            if part_clean.startswith("0x") or part_clean.startswith("0X"):
                val = int(part_clean, 16)
            elif part_clean.startswith("0") and len(part_clean) > 1 and all(c in "01234567" for c in part_clean):
                val = int(part_clean, 8)
            else:
                val = int(part_clean, 10)
            parsed_parts.append(val)
        except ValueError:
            return None

    # Reconstruct 32-bit IPv4 integer according to BSD inet_aton rules
    num_parts = len(parsed_parts)
    try:
        if num_parts == 4:
            if any(p > 255 for p in parsed_parts):
                return None
            val = (parsed_parts[0] << 24) | (parsed_parts[1] << 16) | (parsed_parts[2] << 8) | parsed_parts[3]
        elif num_parts == 3:
            # a.b.c -> c is 16-bit
            if parsed_parts[0] > 255 or parsed_parts[1] > 255 or parsed_parts[2] > 0xFFFF:
                return None
            val = (parsed_parts[0] << 24) | (parsed_parts[1] << 16) | parsed_parts[2]
        elif num_parts == 2:
            # a.b -> b is 24-bit (e.g. 127.1 -> 127.0.0.1)
            if parsed_parts[0] > 255 or parsed_parts[1] > 0xFFFFFF:
                return None
            val = (parsed_parts[0] << 24) | parsed_parts[1]
        elif num_parts == 1:
            if parsed_parts[0] > 0xFFFFFFFF:
                return None
            val = parsed_parts[0]
        else:
            return None

        if 0 <= val <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(val)
    except Exception:
        return None

    return None


class ScopeGuard:
    """
    Guarantees that security analysis is strictly confined to authorized local lab environments.
    Blocks remote, production, or unapproved hostnames and IP addresses, including
    alternate numeric IP representations, DNS rebinding vectors, and malformed URLs.
    """

    DEFAULT_ALLOWED_HOSTS = ["localhost", "127.0.0.1", "::1"]

    def __init__(self, allowed_hosts: Optional[List[str]] = None, allow_private_subnets: bool = False):
        self.allowed_hosts: Set[str] = {h.lower() for h in (allowed_hosts or self.DEFAULT_ALLOWED_HOSTS)}
        self.allow_private_subnets = allow_private_subnets

    def validate_url(self, url: str) -> str:
        """
        Validates that a URL is well-formed and targets strictly within authorized local scope.
        Returns the sanitized URL if valid, or raises ScopeViolationError.
        """
        if not url or not isinstance(url, str):
            raise ScopeViolationError("Target URL cannot be empty.")

        url_stripped = url.strip()

        # Reject control characters or null bytes
        if any(ord(c) < 32 or ord(c) == 127 for c in url_stripped):
            raise ScopeViolationError("Target URL contains invalid control characters or null bytes.")

        # Reject backslashes in URL authority/scheme which induce parser discrepancies
        if "\\" in url_stripped:
            raise ScopeViolationError(
                "Target URL contains backslashes ('\\'). URLs must use standard forward slash delimiters."
            )

        parsed = urlparse(url_stripped)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ScopeViolationError(
                f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are permitted."
            )

        # Check for userinfo / credentials in authority: e.g. http://localhost@attacker.com
        if "@" in parsed.netloc:
            # Ensure the actual destination host is scrutinized, or reject userinfo
            userinfo, _, host_part = parsed.netloc.rpartition("@")
            if not host_part:
                raise ScopeViolationError(f"Malformed URL authority in '{url_stripped}'.")

        hostname = parsed.hostname
        if not hostname:
            raise ScopeViolationError(f"Could not extract a valid hostname from '{url_stripped}'.")

        # Validate port range if specified
        try:
            port = parsed.port
            if port is not None and not (1 <= port <= 65535):
                raise ScopeViolationError(f"Invalid port '{port}' specified in URL.")
        except ValueError as ve:
            raise ScopeViolationError(f"Invalid port specified in URL: {ve}")

        hostname_clean = unquote(hostname).strip().lower()

        # Check explicit allowed hostnames: localhost and RFC 6761 .localhost domains
        if hostname_clean in self.allowed_hosts:
            return url_stripped

        if hostname_clean.endswith(".localhost"):
            return url_stripped

        # Check IPv6 literal (e.g. [::1] or [0:0:0:0:0:0:0:1])
        if ":" in hostname_clean:
            clean_ipv6 = hostname_clean.strip("[]")
            try:
                ip6_obj = ipaddress.ip_address(clean_ipv6)
                if isinstance(ip6_obj, ipaddress.IPv6Address):
                    # Check if it is a standard loopback
                    if ip6_obj.is_loopback:
                        return url_stripped
                    # Check if IPv4-mapped IPv6 address: ::ffff:127.0.0.1
                    if ip6_obj.ipv4_mapped:
                        mapped_v4 = ip6_obj.ipv4_mapped
                        if mapped_v4.is_loopback:
                            return url_stripped
                        if self.allow_private_subnets and mapped_v4.is_private:
                            return url_stripped
                    raise ScopeViolationError(
                        f"IPv6 address '{hostname}' is not a permitted loopback interface (::1)."
                    )
            except ValueError:
                pass

        # Check standard and alternate numeric IPv4 representations (octal, hex, dword, abbreviated)
        v4_obj = parse_numeric_ip(hostname_clean)
        if v4_obj:
            # 0.0.0.0 is non-routable / unspecified; block to prevent ambiguous interface binding
            if v4_obj.is_unspecified:
                raise ScopeViolationError(
                    f"Target address '{hostname}' (0.0.0.0) is non-routable. "
                    "Testing is strictly confined to loopback addresses (127.0.0.1 / localhost)."
                )
            if v4_obj.is_loopback:
                return url_stripped
            if self.allow_private_subnets and v4_obj.is_private:
                return url_stripped

            raise ScopeViolationError(
                f"Resolved IP address '{v4_obj}' from '{hostname}' is outside authorized local loopback scope. "
                "Active testing is strictly restricted to loopback interfaces (localhost / 127.0.0.1)."
            )

        # Standard IPv4 dotted address check if parse_numeric_ip didn't catch it
        try:
            raw_ip = ipaddress.ip_address(hostname_clean)
            if raw_ip.is_loopback:
                return url_stripped
            if self.allow_private_subnets and raw_ip.is_private:
                return url_stripped
            raise ScopeViolationError(
                f"IP address '{hostname}' is not a permitted local training address."
            )
        except ValueError:
            pass

        # Any external hostname that does not match allowed hosts or .localhost is rejected
        # (DNS resolution of arbitrary public domains is intentionally disabled to eliminate DNS rebinding risks)
        raise ScopeViolationError(
            f"Security Boundary Violation: Target '{hostname}' is outside the authorized local lab scope. "
            f"Permitted targets: {sorted(list(self.allowed_hosts))}. "
            "Defensive analysis is strictly restricted to local training environments like OWASP Juice Shop."
        )

    def is_in_scope(self, url: str) -> bool:
        """Helper returning True/False without raising an exception."""
        try:
            self.validate_url(url)
            return True
        except ScopeViolationError:
            return False
