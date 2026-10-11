import pytest
from appsec_assistant.config import ScopeGuard, ScopeViolationError


def test_scope_guard_permits_localhost():
    guard = ScopeGuard()
    assert guard.validate_url("http://localhost:3000") == "http://localhost:3000"
    assert guard.validate_url("http://127.0.0.1:5000/api/Users/1") == "http://127.0.0.1:5000/api/Users/1"
    assert guard.validate_url("https://localhost/rest/basket") == "https://localhost/rest/basket"
    assert guard.is_in_scope("http://127.0.0.1:8080") is True


def test_scope_guard_blocks_external_domains():
    guard = ScopeGuard()
    external_urls = [
        "https://google.com",
        "https://example.com/api",
        "http://meta.com",
        "https://instagram.com/graphql",
        "http://8.8.8.8/test",
    ]
    for url in external_urls:
        with pytest.raises(ScopeViolationError):
            guard.validate_url(url)
        assert guard.is_in_scope(url) is False


def test_scope_guard_blocks_invalid_schemes():
    guard = ScopeGuard()
    with pytest.raises(ScopeViolationError):
        guard.validate_url("ftp://localhost:21")
    with pytest.raises(ScopeViolationError):
        guard.validate_url("file:///etc/passwd")
    with pytest.raises(ScopeViolationError):
        guard.validate_url("")
