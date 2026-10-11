import pytest
from appsec_assistant.config import ScopeGuard, ScopeViolationError


def test_alternate_ip_loopback_representations_allowed():
    guard = ScopeGuard()
    # Canonical loopback
    assert guard.is_in_scope("http://127.0.0.1:5000") is True
    assert guard.is_in_scope("http://127.0.0.2:5000") is True
    # Octal loopback (0177 = 127)
    assert guard.is_in_scope("http://0177.0.0.1:5000") is True
    # Hex loopback (0x7f000001 = 127.0.0.1)
    assert guard.is_in_scope("http://0x7f000001:5000") is True
    # Dword / integer loopback (2130706433 = 127.0.0.1)
    assert guard.is_in_scope("http://2130706433:5000") is True
    # Abbreviated IPv4 loopback (127.1 = 127.0.0.1)
    assert guard.is_in_scope("http://127.1:5000") is True
    # IPv6 loopback
    assert guard.is_in_scope("http://[::1]:5000") is True
    # IPv4-mapped IPv6 loopback
    assert guard.is_in_scope("http://[::ffff:127.0.0.1]:5000") is True
    # RFC 6761 reserved .localhost domain
    assert guard.is_in_scope("http://sub.localhost:5000") is True


def test_alternate_ip_non_loopback_representations_blocked():
    guard = ScopeGuard()
    blocked_targets = [
        # Non-routable 0.0.0.0
        "http://0.0.0.0:5000",
        "http://0:5000",
        "http://0x00000000:5000",
        # Cloud metadata service (169.254.169.254) in various encodings
        "http://169.254.169.254/latest/meta-data",
        "http://0251.0376.0251.0376/latest/meta-data",  # Octal
        "http://0xa9fea9fe/latest/meta-data",           # Hex
        "http://2852039166/latest/meta-data",           # Dword integer
        "http://[::ffff:169.254.169.254]/",             # IPv4-mapped IPv6 metadata
        # Private internal subnets
        "http://10.0.0.1:8080",
        "http://172.16.0.1:8080",
        "http://192.168.1.1:8080",
        # Public internet IPs
        "http://8.8.8.8",
        "http://1.1.1.1",
        "http://142.250.190.46",
    ]
    for target in blocked_targets:
        with pytest.raises(ScopeViolationError):
            guard.validate_url(target)
        assert guard.is_in_scope(target) is False


def test_dns_rebinding_and_public_domain_aliases_blocked():
    guard = ScopeGuard()
    # Even if public domains resolve to 127.0.0.1 via public DNS, they must be rejected
    # to eliminate DNS rebinding attacks and prevent external network traffic escape
    rebinding_domains = [
        "http://localtest.me:5000",
        "http://127.0.0.1.nip.io:5000",
        "http://customer.localtest.me",
        "http://spoof.127.0.0.1.sslip.io",
        "https://google.com",
        "https://example.com",
    ]
    for target in rebinding_domains:
        with pytest.raises(ScopeViolationError):
            guard.validate_url(target)
        assert guard.is_in_scope(target) is False


def test_malformed_urls_and_parser_bypass_attempts_blocked():
    guard = ScopeGuard()
    malformed_urls = [
        # Userinfo credential bypass attempting to target attacker.com
        "http://localhost@attacker.com:5000",
        "http://admin:pass@google.com/test",
        # Backslash parser discrepancy
        "http://localhost\\attacker.com",
        "http://127.0.0.1\\evil.com",
        # Invalid port specifications
        "http://localhost:99999",
        "http://localhost:0",
        # Unsupported schemes
        "gopher://127.0.0.1:70",
        "dict://127.0.0.1:2628",
        "file:///etc/passwd",
        # Control characters
        "http://localhost\r\nHeader: Value",
        "http://localhost\x00/",
    ]
    for url in malformed_urls:
        with pytest.raises(ScopeViolationError):
            guard.validate_url(url)
        assert guard.is_in_scope(url) is False
