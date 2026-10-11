"""
Safe HTTP Client for local security auditing.

Enforces scope protection, rate limiting, redirect validation, and captures full request/response
transactions for passive and defensive vulnerability analysis.
"""

import time
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
import requests

from appsec_assistant.config import ScopeGuard, ScopeViolationError
from appsec_assistant.models import HTTPTransaction, TargetConfig
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from appsec_assistant.policy import ProgramPolicyManager


class SafeHTTPClient:
    """
    A controlled HTTP client that guarantees all requests conform to local scope safeguards,
    validates every redirect hop to prevent boundary escapes, disallows ambient proxy leakage,
    and logs detailed transactions.
    """

    MAX_REDIRECTS = 5

    def __init__(
        self,
        config: TargetConfig,
        policy_manager: Optional["ProgramPolicyManager"] = None,
        proxy_url: Optional[str] = None,
    ):
        self.config = config
        self.policy_manager = policy_manager
        self.scope_guard = ScopeGuard(
            allowed_hosts=config.allowed_hosts,
        )
        self.session = requests.Session()
        # CRITICAL: Prevent ambient environment variables (HTTP_PROXY, HTTPS_PROXY)
        # from silently hijacking loopback traffic or redirecting requests outside scope
        self.session.trust_env = False
        self.session.headers.update({"User-Agent": config.user_agent})

        if proxy_url:
            # Proxies must strictly reside on authorized loopback hosts (e.g., local ZAP or Burp proxy)
            self.scope_guard.validate_url(proxy_url)
            self.session.proxies = {"http": proxy_url, "https": proxy_url}

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
        Validates every redirect hop to prevent requests escaping local loopback.
        Returns a captured HTTPTransaction.
        """
        # Resolve full URL if relative endpoint provided
        if endpoint_or_url.startswith("http://") or endpoint_or_url.startswith("https://"):
            current_url = endpoint_or_url
        else:
            base = self.config.base_url.rstrip("/")
            endpoint = endpoint_or_url.lstrip("/")
            current_url = f"{base}/{endpoint}"

        # 1. Enforce initial Scope Guard & Policy validation
        self.scope_guard.validate_url(current_url)
        if self.policy_manager:
            self.policy_manager.validate_target_authorization(current_url)

        req_headers = dict(self.session.headers)
        if headers:
            req_headers.update(headers)

        redirect_count = 0
        final_response = None
        current_method = method.upper()

        while True:
            # 2. Enforce deliberate rate limit
            self._apply_rate_limit()

            # 3. Execute request without automatic redirects
            response = self.session.request(
                method=current_method,
                url=current_url,
                headers=req_headers,
                data=data if redirect_count == 0 else None,
                json=json_data if redirect_count == 0 else None,
                timeout=self.config.timeout,
                allow_redirects=False,
            )

            # Check for redirect status codes (301, 302, 303, 307, 308)
            if response.is_redirect and "Location" in response.headers:
                redirect_count += 1
                if redirect_count > self.MAX_REDIRECTS:
                    raise ScopeViolationError(
                        f"Excessive redirects encountered (>{self.MAX_REDIRECTS}) for target '{endpoint_or_url}'."
                    )

                raw_location = response.headers["Location"]
                # Resolve relative or absolute redirect destination
                next_url = urljoin(current_url, raw_location)

                # CRITICAL: Validate the redirect destination against the scope guard and policy BEFORE following!
                try:
                    self.scope_guard.validate_url(next_url)
                    if self.policy_manager:
                        self.policy_manager.validate_target_authorization(next_url)
                except Exception as sve:
                    raise ScopeViolationError(
                        f"Redirect Boundary Escape Blocked: Server at '{current_url}' attempted to redirect "
                        f"to unauthorized out-of-scope destination '{next_url}': {sve}"
                    )

                current_url = next_url
                # Standard redirect behavior: 303 always turns into GET; 301/302 typically turn to GET
                if response.status_code in (301, 302, 303):
                    current_method = "GET"
                continue

            final_response = response
            break

        # 4. Extract detailed cookie metadata
        cookies_meta: List[Dict[str, Any]] = []
        for cookie in final_response.cookies:
            samesite = getattr(cookie, "samesite", None)
            if samesite is None:
                samesite = cookie._rest.get("SameSite", cookie._rest.get("samesite", None))

            cookies_meta.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": bool(cookie.secure),
                "httponly": bool(cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")),
                "samesite": samesite,
            })

        # 5. Capture transaction
        transaction = HTTPTransaction(
            url=current_url,
            method=current_method,
            request_headers=req_headers,
            status_code=final_response.status_code,
            response_headers=dict(final_response.headers),
            response_body=final_response.text[:10000],  # Capture preview up to 10KB
            cookies=cookies_meta,
        )

        self._history.append(transaction)
        return transaction
