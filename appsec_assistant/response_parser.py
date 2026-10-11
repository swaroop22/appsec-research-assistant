"""
HTTP Response Parser Module.

Parses captured raw HTTP response strings, header blocks, and JSON representations
into structured HTTPTransaction objects and parsed cookie collections for passive security analysis.
"""

import re
import json
from typing import Dict, List, Any, Tuple, Optional
from appsec_assistant.models import HTTPTransaction


def parse_cookie_header(cookie_str: str) -> Dict[str, Any]:
    """
    Parses a single Set-Cookie header value into its name, value, and attributes.
    """
    parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
    if not parts:
        return {}

    # First component is Name=Value
    first_part = parts[0]
    if "=" in first_part:
        name, value = first_part.split("=", 1)
    else:
        name = first_part
        value = ""

    parsed: Dict[str, Any] = {
        "name": name.strip(),
        "value": value.strip(),
        "secure": False,
        "httponly": False,
        "samesite": None,
        "path": "/",
        "domain": None,
        "raw": cookie_str.strip(),
    }

    # Inspect remaining attributes
    for attribute in parts[1:]:
        attr_lower = attribute.lower()
        if attr_lower == "secure":
            parsed["secure"] = True
        elif attr_lower == "httponly":
            parsed["httponly"] = True
        elif attr_lower.startswith("samesite"):
            if "=" in attribute:
                parsed["samesite"] = attribute.split("=", 1)[1].strip()
            else:
                parsed["samesite"] = "Default"
        elif attr_lower.startswith("path="):
            parsed["path"] = attribute.split("=", 1)[1].strip()
        elif attr_lower.startswith("domain="):
            parsed["domain"] = attribute.split("=", 1)[1].strip()

    return parsed


def parse_raw_http_response(
    raw_text: str, default_url: str = "http://localhost/"
) -> HTTPTransaction:
    """
    Parses raw HTTP response text (or JSON) into an HTTPTransaction.
    Supports full HTTP messages (status line + headers + body) or header-only blocks.
    """
    raw_text = raw_text.strip()
    if not raw_text:
        return HTTPTransaction(
            url=default_url,
            method="GET",
            request_headers={},
            status_code=200,
            response_headers={},
            response_body="",
            cookies=[],
        )

    # 1. Attempt JSON parsing if it looks like a JSON object
    if raw_text.startswith("{") and raw_text.endswith("}"):
        try:
            data = json.loads(raw_text)
            status_code = int(data.get("status_code", 200))
            headers = data.get("headers", {})
            # Normalize headers dict
            headers_dict = {str(k): str(v) for k, v in headers.items()}
            body = data.get("body", "")
            cookies = data.get("cookies", [])
            # Also parse Set-Cookie in headers if present
            for k, v in headers_dict.items():
                if k.lower() == "set-cookie":
                    cookies.append(parse_cookie_header(v))
            url = data.get("url", default_url)
            return HTTPTransaction(
                url=url,
                method="GET",
                request_headers={},
                status_code=status_code,
                response_headers=headers_dict,
                response_body=body,
                cookies=cookies,
            )
        except Exception:
            pass  # Fall through to raw text parsing

    # 2. Split headers and body
    # Standard HTTP uses \r\n\r\n or \n\n
    if "\r\n\r\n" in raw_text:
        header_part, body_part = raw_text.split("\r\n\r\n", 1)
    elif "\n\n" in raw_text:
        header_part, body_part = raw_text.split("\n\n", 1)
    else:
        header_part = raw_text
        body_part = ""

    lines = header_part.splitlines()
    status_code = 200
    headers_dict: Dict[str, str] = {}
    parsed_cookies: List[Dict[str, Any]] = []

    if not lines:
        return HTTPTransaction(
            url=default_url,
            method="GET",
            request_headers={},
            status_code=status_code,
            response_headers={},
            response_body=body_part,
            cookies=[],
        )

    # 3. Check for HTTP Status line: e.g. "HTTP/1.1 200 OK"
    first_line = lines[0].strip()
    status_match = re.match(r"^HTTP/\d+(?:\.\d+)?\s+(\d{3})(?:\s+.*)?$", first_line, re.IGNORECASE)
    if status_match:
        status_code = int(status_match.group(1))
        header_lines = lines[1:]
    else:
        # Check if first line is a header like "Status: 200 OK" or simply regular header
        if first_line.lower().startswith("status:"):
            code_match = re.search(r"\b(\d{3})\b", first_line)
            if code_match:
                status_code = int(code_match.group(1))
            header_lines = lines[1:]
        else:
            header_lines = lines

    # 4. Parse header lines
    for line in header_lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue
        if ":" in line_clean:
            key, val = line_clean.split(":", 1)
            key_clean = key.strip()
            val_clean = val.strip()

            if key_clean.lower() == "set-cookie":
                # Save cookie
                parsed_cookies.append(parse_cookie_header(val_clean))
                # Store in headers dictionary (combine if already exists)
                if "Set-Cookie" in headers_dict:
                    headers_dict["Set-Cookie"] += f"\n{val_clean}"
                else:
                    headers_dict["Set-Cookie"] = val_clean
            else:
                headers_dict[key_clean] = val_clean

    # Determine URL
    target_url = default_url
    if "Host" in headers_dict:
        proto = "https" if default_url.startswith("https") else "http"
        target_url = f"{proto}://{headers_dict['Host']}/"

    return HTTPTransaction(
        url=target_url,
        method="GET",
        request_headers={},
        status_code=status_code,
        response_headers=headers_dict,
        response_body=body_part,
        cookies=parsed_cookies,
    )
