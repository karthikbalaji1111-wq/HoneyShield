"""Security headers hardening middleware (Finding F-015 / Phase 10)."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import get_settings
from app.core.ip_trust import is_ip_in_trusted_proxies

if TYPE_CHECKING:
    from app.core.config import Settings

logger = logging.getLogger(__name__)


def set_header_if_absent(headers: MutableHeaders, key: str, value: str) -> None:
    """Set an HTTP response header if not already present, case-insensitively.

    Guarantees:
    - Never duplicates an existing header regardless of case.
    - Preserves existing custom endpoint headers (e.g. Cache-Control on SSE streams).
    - Emits strictly lowercased ASCII header names in accordance with ASGI specification.
    """
    set_key = key.lower().encode("latin-1")
    set_val = value.encode("latin-1")
    for k, _ in headers.raw:
        k_lower = k.lower() if isinstance(k, bytes) else k.lower().encode("latin-1")
        if k_lower == set_key:
            return
    headers.raw.append((set_key, set_val))


class SecurityHeadersMiddleware:
    """Enforces centralized HTTP response security headers at the ASGI boundary (F-015).

    Headers enforced:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY (or configured)
    - Referrer-Policy: no-referrer (or configured)
    - Content-Security-Policy: default-src 'none'; frame-ancestors 'none' (or configured)
    - Permissions-Policy: accelerometer=(), camera=(), ... (or configured)
    - Cache-Control: no-store (for sensitive responses when not already set)
    - Strict-Transport-Security: Emitted ONLY when explicitly enabled AND request is HTTPS.
    """

    def __init__(
        self,
        app: ASGIApp,
        settings: Optional[Settings] = None,
    ) -> None:
        self.app = app
        self._settings = settings

    @property
    def settings(self) -> Settings:
        return self._settings or get_settings()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Non-HTTP scopes (e.g. WebSocket) are passed through without modification
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = self.settings
        if not settings.security_headers_enabled:
            await self.app(scope, receive, send)
            return

        is_https = self._is_https_request(scope, settings)

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                headers = MutableHeaders(scope=message)

                # Core Security Headers
                if settings.security_headers_x_content_type_options:
                    set_header_if_absent(
                        headers,
                        "x-content-type-options",
                        settings.security_headers_x_content_type_options,
                    )

                if settings.security_headers_x_frame_options:
                    set_header_if_absent(
                        headers,
                        "x-frame-options",
                        settings.security_headers_x_frame_options,
                    )

                if settings.security_headers_referrer_policy:
                    set_header_if_absent(
                        headers,
                        "referrer-policy",
                        settings.security_headers_referrer_policy,
                    )

                if settings.security_headers_csp:
                    set_header_if_absent(
                        headers,
                        "content-security-policy",
                        settings.security_headers_csp,
                    )

                if settings.security_headers_permissions_policy:
                    set_header_if_absent(
                        headers,
                        "permissions-policy",
                        settings.security_headers_permissions_policy,
                    )

                if settings.security_headers_cache_control:
                    set_header_if_absent(
                        headers,
                        "cache-control",
                        settings.security_headers_cache_control,
                    )

                # Strict-Transport-Security (HSTS): Only emitted if enabled AND connection is verified HTTPS
                if settings.security_headers_hsts_enabled and is_https:
                    hsts_parts = [f"max-age={settings.security_headers_hsts_max_age}"]
                    if settings.security_headers_hsts_include_subdomains:
                        hsts_parts.append("includeSubDomains")
                    if settings.security_headers_hsts_preload:
                        hsts_parts.append("preload")
                    set_header_if_absent(
                        headers,
                        "strict-transport-security",
                        "; ".join(hsts_parts),
                    )

            await send(message)

        await self.app(scope, receive, send_with_security_headers)

    def _is_https_request(self, scope: Scope, settings: Settings) -> bool:
        """Verify whether the request is transmitted over HTTPS."""
        if scope.get("scheme") == "https":
            return True

        # Check X-Forwarded-Proto only if peer is trusted proxy
        client = scope.get("client")
        peer_ip = client[0] if client else None
        trusted_proxies = (
            settings.trusted_proxies
            if isinstance(settings.trusted_proxies, list)
            else [p.strip() for p in settings.trusted_proxies.split(",") if p.strip()]
        )
        if peer_ip and is_ip_in_trusted_proxies(peer_ip, trusted_proxies):
            headers = Headers(scope=scope)
            forwarded_proto = headers.get("x-forwarded-proto", "").lower().strip()
            if forwarded_proto == "https":
                return True

        return False
