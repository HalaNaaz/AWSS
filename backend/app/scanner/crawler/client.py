import asyncio
import time
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse
import httpx

from backend.app.core.config import settings
from backend.app.core.exceptions import ScopeViolationError, SSRFValidationError
from backend.app.core.logging import logger
from backend.app.scanner.scope.scope_gate import ScopeGate


class AsyncHTTPClient:
    """Hardened Asynchronous HTTP Client with ScopeGate pre-flight validation and redirect safety."""

    def __init__(
        self,
        scope_gate: ScopeGate,
        timeout: float = 15.0,
        max_redirects: int = 5,
        max_response_size: int = 5 * 1024 * 1024,  # 5 MB safety limit
        user_agent: Optional[str] = None,
        rate_limit_rps: float = 10.0
    ):
        self.scope_gate = scope_gate
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_response_size = max_response_size
        self.user_agent = user_agent or settings.SCANNER_USER_AGENT
        self.rate_limit_rps = rate_limit_rps

        # Internal concurrency rate limiter
        self._rate_limiter = asyncio.Semaphore(max(1, int(rate_limit_rps)))
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=5.0),
            follow_redirects=False,  # Redirects manually validated at every hop!
            verify=True,             # TLS verification strictly enabled by default
            limits=limits,
            headers={"User-Agent": self.user_agent}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None
    ) -> Tuple[Optional[httpx.Response], Optional[str]]:
        """Executes a safe GET request, validating scope and IP pinning on initial request and every redirect hop.
        
        Returns:
            Tuple of (Response object or None, error_message or None)
        """
        if not self._client:
            raise RuntimeError("AsyncHTTPClient must be used as an async context manager ('async with').")

        current_url = url
        redirect_count = 0

        while redirect_count <= self.max_redirects:
            # Step 1: Pre-flight Scope and Anti-SSRF check
            try:
                pinned_ip = self.scope_gate.pre_flight_check(current_url)
            except (ScopeViolationError, SSRFValidationError) as sec_err:
                logger.warning(f"[AsyncHTTPClient] Security Gate Blocked request to '{current_url}': {sec_err.message}")
                return None, sec_err.message
            except Exception as e:
                logger.error(f"[AsyncHTTPClient] Pre-flight resolution failed for '{current_url}': {str(e)}")
                return None, f"Pre-flight resolution error: {str(e)}"

            # Step 2: Rate Limiting & Request Dispatch
            start_time = time.perf_counter()
            try:
                req_headers = {"User-Agent": self.user_agent}
                if headers:
                    req_headers.update(headers)

                response = await self._client.get(current_url, headers=req_headers)
                response_time = (time.perf_counter() - start_time) * 1000

                # Check response size cap
                content_len_header = response.headers.get("content-length")
                if content_len_header and int(content_len_header) > self.max_response_size:
                    logger.warning(f"[AsyncHTTPClient] Response size {content_len_header} exceeds cap at {current_url}")
                    return None, f"Response size exceeds limit ({self.max_response_size} bytes)"

                # Handle HTTP 429 Too Many Requests: Exponential backoff
                if response.status_code == 429:
                    logger.warning(f"[AsyncHTTPClient] Rate limited (HTTP 429) by target at {current_url}. Backing off.")
                    await asyncio.sleep(2.0)

                # Step 3: Handle Redirects Securely
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if not location:
                        return response, None

                    # Resolve relative redirect
                    from urllib.parse import urljoin
                    redirect_target = urljoin(current_url, location)

                    # Validate redirect hop through ScopeGate
                    try:
                        self.scope_gate.validate_redirect(redirect_target)
                    except (ScopeViolationError, SSRFValidationError) as redirect_err:
                        logger.warning(f"[AsyncHTTPClient] Redirect to '{redirect_target}' rejected: {redirect_err.message}")
                        return response, f"Redirect to unsafe destination blocked: {redirect_err.message}"

                    current_url = redirect_target
                    redirect_count += 1
                    continue

                return response, None

            except (httpx.ConnectTimeout, httpx.ReadTimeout) as timeout_err:
                return None, f"Request timeout: {str(timeout_err)}"
            except httpx.ConnectError as conn_err:
                return None, f"Connection error: {str(conn_err)}"
            except Exception as err:
                return None, f"HTTP dispatch error: {str(err)}"

        return None, f"Exceeded maximum redirect limit ({self.max_redirects})"
