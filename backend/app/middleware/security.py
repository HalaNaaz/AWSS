import ipaddress
import secrets
import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from backend.app.core.config import settings


def _is_loopback_host(host: str) -> bool:
    """Returns True only for localhost/loopback client identifiers."""
    if not host:
        return False
    normalized = host.strip().lower()
    if normalized in {"localhost", "testclient"}:
        return True
    try:
        ip_obj = ipaddress.ip_address(normalized)
        if ip_obj.is_loopback:
            return True
        v4_mapped = getattr(ip_obj, "ipv4_mapped", None)
        return bool(v4_mapped and v4_mapped.is_loopback)
    except ValueError:
        return False


class LocalBoundaryAndAuthMiddleware(BaseHTTPMiddleware):
    """Enforces API bearer/key token auth when configured, or strict loopback-only boundary."""

    EXEMPT_PATHS = {"/healthz", "/api/v1/healthz", "/api/v1/readyz"}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method == "OPTIONS" or request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        configured_token = (settings.API_AUTH_TOKEN or "").strip()
        if configured_token:
            auth_header = request.headers.get("Authorization", "")
            bearer_token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
            api_key_token = request.headers.get("X-API-Key", "").strip()
            provided = bearer_token or api_key_token
            if not provided or not secrets.compare_digest(provided, configured_token):
                return JSONResponse(
                    status_code=401,
                    content={
                        "success": False,
                        "error_code": "UNAUTHORIZED",
                        "message": "Valid Bearer or X-API-Key authentication token required.",
                    },
                )
            return await call_next(request)

        if settings.ENFORCE_LOCAL_BOUNDARY:
            client_host = request.client.host if request.client else ""
            forwarded_for = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            if not _is_loopback_host(client_host) or (forwarded_for and not _is_loopback_host(forwarded_for)):
                return JSONResponse(
                    status_code=403,
                    content={
                        "success": False,
                        "error_code": "LOCAL_BOUNDARY_VIOLATION",
                        "message": "Remote unauthenticated API access is blocked. Configure API_AUTH_TOKEN for non-local access.",
                    },
                )

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforces strict defensive security headers on all API responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Assigns or propagates request correlation IDs for end-to-end observability."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        start_time = time.perf_counter()
        
        response = await call_next(request)
        
        process_time = time.perf_counter() - start_time
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Process-Time"] = f"{process_time:.4f}s"
        return response
