"""
Deep security boundary and quality tests for ScopeGuard, SafeHTTPClient, and Policy containment.

Verifies:
- Proxy isolation: trust_env=False prevents ambient proxy leakage; external proxy configurations are blocked.
- Hop-by-hop redirect boundary enforcement.
- IP normalization across octal, hex, dword, abbreviated dotted, and IPv6 encodings.
- DNS resolution and rebinding prevention.
- Malformed URLs and parser discrepancy handling.
- Connection boundary enforcement and fail-closed validation.
"""

import os
import pytest

from appsec_assistant.models import TargetConfig
from appsec_assistant.config import ScopeGuard, ScopeViolationError
from appsec_assistant.client import SafeHTTPClient
from appsec_assistant.policy import ProgramPolicyManager, UnauthorizedTargetError
from appsec_assistant.lab_server import LocalLabServer


@pytest.fixture(scope="module")
def boundary_lab():
    server = LocalLabServer(host="127.0.0.1", port=5004)
    server.start()
    yield server
    server.stop()


def test_proxy_environment_isolation_and_scope_validation():
    # 1. Ambient proxy environment variables must not be trusted
    os.environ["HTTP_PROXY"] = "http://external-ambient-proxy.com:8080"
    os.environ["HTTPS_PROXY"] = "https://external-ambient-proxy.com:8080"

    try:
        config = TargetConfig(base_url="http://127.0.0.1:5000")
        client = SafeHTTPClient(config)
        assert client.session.trust_env is False

        # 2. External proxy URL explicitly passed must raise ScopeViolationError
        with pytest.raises(ScopeViolationError):
            SafeHTTPClient(config, proxy_url="http://evil-proxy.com:8080")

        # 3. Local loopback proxy (e.g. local Burp or ZAP on 127.0.0.1:8080) is permitted
        loopback_client = SafeHTTPClient(config, proxy_url="http://127.0.0.1:8080")
        assert loopback_client.session.proxies.get("http") == "http://127.0.0.1:8080"
    finally:
        os.environ.pop("HTTP_PROXY", None)
        os.environ.pop("HTTPS_PROXY", None)


def test_redirect_boundary_hop_by_hop_containment(boundary_lab):
    config = TargetConfig(base_url=boundary_lab.url)
    client = SafeHTTPClient(config)

    # Permitted loopback redirect succeeds
    tx = client.fetch("/redirect-internal")
    assert tx.status_code == 200
    assert "Hardened Endpoint" in tx.response_body

    # Out-of-scope redirect attempts must be blocked immediately before following
    with pytest.raises(ScopeViolationError) as exc_info:
        client.fetch("/redirect-out-of-scope")
    assert "Redirect Boundary Escape Blocked" in str(exc_info.value)


def test_ip_normalization_all_encodings():
    guard = ScopeGuard()

    # Supported loopback encodings
    valid_loopbacks = [
        "http://127.0.0.1:5000",
        "http://127.0.0.2:5000",
        "http://0177.0.0.1:5000",       # Octal
        "http://0x7f000001:5000",       # Hex
        "http://2130706433:5000",       # Dword
        "http://127.1:5000",            # Abbreviated
        "http://[::1]:5000",            # IPv6 loopback
        "http://[::ffff:127.0.0.1]:5000", # IPv4-mapped IPv6 loopback
        "http://localhost:5000",        # RFC 6761
        "http://test.localhost:5000",   # RFC 6761 subdomain
    ]
    for url in valid_loopbacks:
        assert guard.is_in_scope(url) is True

    # Blocked external and non-loopback addresses
    blocked_addresses = [
        "http://0.0.0.0:5000",
        "http://169.254.169.254/latest/meta-data", # AWS/GCP metadata IP
        "http://0251.0376.0251.0376/meta",        # Octal metadata
        "http://0xa9fea9fe/meta",                 # Hex metadata
        "http://2852039166/meta",                 # Dword metadata
        "http://10.0.0.1:8080",                   # Private RFC 1918
        "http://172.16.0.1:8080",
        "http://192.168.1.1:8080",
        "http://8.8.8.8",                         # Public IP
    ]
    for url in blocked_addresses:
        assert guard.is_in_scope(url) is False
        with pytest.raises(ScopeViolationError):
            guard.validate_url(url)


def test_dns_resolution_rebinding_blocked():
    guard = ScopeGuard()
    # Reject arbitrary public hostnames to prevent DNS rebinding
    for host in ["http://localtest.me", "http://127.0.0.1.nip.io", "https://google.com"]:
        assert guard.is_in_scope(host) is False
        with pytest.raises(ScopeViolationError):
            guard.validate_url(host)


def test_malformed_urls_fail_closed():
    guard = ScopeGuard()
    malformed = [
        "",
        None,
        "   ",
        "http://",
        "ftp://localhost:21",
        "file:///etc/passwd",
        "http://user:pass@localhost:5000",
        "http://localhost\\evil.com",
        "http://localhost:99999",
        "http://localhost:0",
        "http://localhost\x00/",
    ]
    for m in malformed:
        assert guard.is_in_scope(m) is False
        with pytest.raises(ScopeViolationError):
            guard.validate_url(m)


def test_client_policy_integration_boundary_enforcement(boundary_lab):
    # SafeHTTPClient coupled with ProgramPolicyManager enforces policy scope in addition to loopback
    policy_mgr = ProgramPolicyManager()
    policy_mgr.get_policy("local-lab-vdp").authorized_assets.append(f"{boundary_lab.url}/*")
    config = TargetConfig(base_url=boundary_lab.url)
    client = SafeHTTPClient(config, policy_manager=policy_mgr)

    # Permitted within local-lab-vdp policy
    tx = client.fetch("/")
    assert tx.status_code == 200

    # Target outside enabled policy authorized_assets raises UnauthorizedTargetError
    with pytest.raises(UnauthorizedTargetError):
        client.fetch("http://127.0.0.1:9999/unauthorized-endpoint")
