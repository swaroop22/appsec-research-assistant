import pytest
from appsec_assistant.models import TargetConfig
from appsec_assistant.client import SafeHTTPClient
from appsec_assistant.config import ScopeViolationError
from appsec_assistant.lab_server import LocalLabServer


@pytest.fixture(scope="module")
def mock_lab():
    lab = LocalLabServer(host="127.0.0.1", port=5005)
    lab.start()
    yield lab
    lab.stop()


def test_safe_http_client_follows_internal_redirect(mock_lab):
    config = TargetConfig(base_url=mock_lab.url)
    client = SafeHTTPClient(config)

    # /redirect-internal redirects to /hardened on loopback
    tx = client.fetch("/redirect-internal")
    assert tx.status_code == 200
    assert "Hardened Endpoint" in tx.response_body


def test_safe_http_client_blocks_out_of_scope_redirect(mock_lab):
    config = TargetConfig(base_url=mock_lab.url)
    client = SafeHTTPClient(config)

    # /redirect-out-of-scope attempts to redirect to https://example.com/escaped
    with pytest.raises(ScopeViolationError) as exc_info:
        client.fetch("/redirect-out-of-scope")

    assert "Redirect Boundary Escape Blocked" in str(exc_info.value)
    assert "example.com" in str(exc_info.value)
