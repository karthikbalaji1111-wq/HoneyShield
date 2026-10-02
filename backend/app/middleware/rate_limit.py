"""ASGI middleware for API-wide rate limiting and admission control (F-011)."""
from __future__ import annotations

import hashlib
import json
from typing import Optional

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import get_settings
from app.core.ip_trust import extract_client_ip
from app.core.rate_limit import api_limiter


EXEMPT_PATHS = frozenset({
    "/",
    "/health",
    "/ready",
    "/api/v1/health",
    "/api/v1/ready",
    "/docs",
    "/redoc",
    "/openapi.json",
})

# Ingestion paths are handled by specialized forensic rate limiting in the ingestion router
INGESTION_PREFIXES = ("/t/", "/px/", "/collect/")


class ApiRateLimitMiddleware:
    """Enforces API-wide fixed-window rate limiting across authenticated and public routes.

    Design:
    - Health and readiness endpoints are completely exempt to protect deployment uptime.
    - Public HoneyToken ingestion endpoints pass through to dedicated forensic abuse control.
    - Login route (/auth/login) is primarily protected by the tighter login_limiter.
    - Authenticated API requests: rate-limited by user/token identifier.
    - Public API requests: rate-limited by client IP address.
    - Exceeded limits return HTTP 429 with 'Retry-After' header and structured ErrorResponse.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = get_settings()
        if not settings.rate_limit_enabled:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # 1. Exempt health, readiness, and documentation endpoints
        if path in EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        # 2. Ingestion paths have specialized forensic abuse control
        if any(path.startswith(prefix) for prefix in INGESTION_PREFIXES):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        request_id = headers.get("x-request-id", "-")

        # 3. Determine identity and applicable rate limit
        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            # Authenticated client: key by hashed token
            token_val = auth_header[7:].strip()
            token_hash = hashlib.sha256(token_val.encode("utf-8")).hexdigest()[:16]
            rate_key = f"auth_user:{token_hash}"
            limit = settings.rate_limit_per_minute_authenticated
        else:
            # Unauthenticated client: extract trusted client IP
            # Build a lightweight request-like object for IP extraction
            client_host = scope.get("client", (None, None))[0] if scope.get("client") else None
            client_ip = self._resolve_ip(client_host, headers, settings)
            rate_key = f"public_ip:{client_ip}"
            limit = settings.rate_limit_per_minute_public

        # 4. Check admission control
        allowed, retry_after = api_limiter.check_and_increment(
            key=rate_key,
            limit=limit,
            global_limit=settings.rate_limit_global_per_minute,
            window_seconds=60,
        )

        if not allowed:
            await self._send_429_response(send, retry_after, request_id)
            return

        await self.app(scope, receive, send)

    def _resolve_ip(self, client_host: Optional[str], headers: Headers, settings) -> str:
        """Resolve client IP using the trusted proxy model."""
        import ipaddress
        from app.core.ip_trust import is_ip_in_trusted_proxies

        if not client_host:
            return "127.0.0.1"

        if client_host in ("testclient", "localhost"):
            peer_ip = "127.0.0.1"
        else:
            try:
                peer_ip = str(ipaddress.ip_address(client_host.strip()))
            except ValueError:
                return "127.0.0.1"

        # Check if direct peer is trusted
        if not is_ip_in_trusted_proxies(peer_ip, settings.trusted_proxies):
            return peer_ip

        # Peer is trusted: inspect X-Forwarded-For or X-Real-IP
        xff = headers.get("x-forwarded-for")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            for p in parts:
                try:
                    return str(ipaddress.ip_address(p))
                except ValueError:
                    continue

        x_real = headers.get("x-real-ip")
        if x_real:
            try:
                return str(ipaddress.ip_address(x_real.strip()))
            except ValueError:
                pass

        return peer_ip

    async def _send_429_response(self, send: Send, retry_after: int, request_id: str) -> None:
        """Send standard HTTP 429 Too Many Requests response."""
        body = json.dumps({
            "detail": "API rate limit exceeded. Please try again later.",
            "request_id": request_id,
        }).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 429,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"retry-after", str(retry_after).encode("ascii")),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        })
