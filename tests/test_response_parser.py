from appsec_assistant.response_parser import parse_raw_http_response, parse_cookie_header
from appsec_assistant.samples import SAMPLE_INSECURE_PHP, SAMPLE_API_EXPRESS


def test_parse_cookie_header():
    raw_cookie = "session_id=abc123xyz; Path=/; Secure; HttpOnly; SameSite=Lax"
    parsed = parse_cookie_header(raw_cookie)

    assert parsed["name"] == "session_id"
    assert parsed["value"] == "abc123xyz"
    assert parsed["path"] == "/"
    assert parsed["secure"] is True
    assert parsed["httponly"] is True
    assert parsed["samesite"] == "Lax"


def test_parse_raw_http_response_full_message():
    tx = parse_raw_http_response(SAMPLE_INSECURE_PHP)

    assert tx.status_code == 200
    assert "Server" in tx.response_headers
    assert "Apache/2.4.41" in tx.response_headers["Server"]
    assert "X-Powered-By" in tx.response_headers
    assert len(tx.cookies) == 2

    # Check parsed cookies
    names = [c["name"] for c in tx.cookies]
    assert "PHPSESSID" in names
    assert "user_role" in names


def test_parse_raw_http_response_json_format():
    json_input = """{
        "status_code": 201,
        "headers": {
            "Content-Type": "application/json",
            "X-Content-Type-Options": "nosniff"
        },
        "cookies": [
            {
                "name": "token",
                "value": "xyz",
                "secure": true,
                "httponly": true,
                "samesite": "Strict"
            }
        ]
    }"""
    tx = parse_raw_http_response(json_input)
    assert tx.status_code == 201
    assert tx.response_headers.get("X-Content-Type-Options") == "nosniff"
    assert len(tx.cookies) == 1
    assert tx.cookies[0]["name"] == "token"


def test_parse_raw_http_response_header_only():
    headers_only = """Server: nginx/1.18.0
Content-Type: text/html
Set-Cookie: app_pref=compact; Path=/
"""
    tx = parse_raw_http_response(headers_only)
    assert tx.status_code == 200  # Default fallback
    assert tx.response_headers["Server"] == "nginx/1.18.0"
    assert len(tx.cookies) == 1
    assert tx.cookies[0]["name"] == "app_pref"


def test_parse_empty_input():
    tx = parse_raw_http_response("")
    assert tx.status_code == 200
    assert tx.response_headers == {}
    assert tx.cookies == []
