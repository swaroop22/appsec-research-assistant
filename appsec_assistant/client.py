"""
Safe HTTP Client for local security auditing.

Enforces scope protection, rate limiting, and captures full request/response
transactions for passive and defensive vulnerability analysis.
"""

import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import requests
from requests.cookies import RequestsCookieJar

from appsec_assistant.config import ScopeGuard, ScopeViolationError
from appsec_assistant.models import HTTPTransaction, TargetConfig


class SafeHTTPClient:
    """
    A controlled HTTP client that guarantees all requests conform to local scope safeguards
    and logs detailed transactions for defensive security analysis.
    """

    def __init__(self, config: TargetConfig):
        self.config = config
        self.scope_guard = ScopeGuard(allowed_hosts=config.allowed_hosts)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.user_agent})
        self._history: List[HTTPTransaction] = []
        self._last_request_time: float = 0.0

    @property
    def history(self) -> List[HTTPTransaction]:
        return list(self._history)

    def clear_history(self) -> None:
        self._history.clear()

    def _apply_rate_limit(self) -> None:
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.config.rate_limit_delay:
            time.sleep(self.config.rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    def fetch(
        self,
        endpoint_or_url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
    ) -> HTTPTransaction:
        """
        Executes a controlled HTTP request after validating scope boundaries.
        Returns a captured HTTPTransaction.
        """
        # Resolve full URL if relative endpoint provided
        if endpoint_or_url.startswith("http://") or endpoint_or_url.startswith("https://"):
            full_url = endpoint_or_url
        else:
            base = self.config.base_url.rstrip("/")
            endpoint = endpoint_or_url.lstrip("/")
            full_url = f"{base}/{endpoint}"

        # 1. Enforce Scope Guard (Raises ScopeViolationError if unauthorized)
        self.scope_guard.validate_url(full_url)

        # 2. Enforce deliberate rate limit
        self._apply_rate_limit()

        # 3. Execute request safely
        req_headers = dict(self.session.headers)
        if headers:
            req_headers.update(headers)

        response = self.session.request(
            method=method.upper(),
            url=full_url,
            headers=headers,
            data=data,
            json=json_data,
            timeout=self.config.timeout,
            allow_redirects=True,
        )

        # 4. Extract detailed cookie metadata specifically for this response
        cookies_meta: List[Dict[str, Any]] = []
        for cookie in response.cookies:
            # Inspect cookie attributes
            samesite = getattr(cookie, "samesite", None)
            if samesite is None:
                # Some cookies store samesite in _rest
                samesite = cookie._rest.get("SameSite", cookie._rest.get("samesite", "None"))

            cookies_meta.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": bool(cookie.secure),
                "httponly": bool(cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")),
                "samesite": samesite,
            })

        # Also inspect Set-Cookie headers directly from response headers if raw cookies available
        raw_set_cookie = response.headers.get("Set-Cookie", "")

        # 5. Capture transaction
        transaction = HTTPTransaction(
            url=full_url,
            method=method.upper(),
            request_headers=req_headers,
            status_code=response.status_code,
            response_headers=dict(response.headers),
            response_body=response.text[:10000],  # Capture preview up to 10KB
            cookies=cookies_meta,
        )

        self._history.append(transaction)
        return transaction
