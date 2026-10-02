"""Focused security tests for Security Headers Hardening (Finding F-015 / Phase 10).

Covers:
- Configuration validation (X-Frame-Options, Referrer-Policy, CSP unsafe directives, HSTS limits)
- Presence of all core security headers on successful API responses (200, 204)
- Presence of all core security headers on error responses (401, 403, 404, 413, 429, 500)
- Case-insensitive deduplication and zero duplicate headers
- Endpoint-specific header preservation (e.g. Cache-Control: no-cache on SSE streams)
- Strict HSTS safety invariants:
  - Absent on plain HTTP
  - Absent when disabled (default)
  - Present only when enabled AND verified HTTPS (direct scheme or verified trusted proxy)
  - Spoofed X-Forwarded-Proto from untrusted peer rejected
  - Preload directive support
- Global disable switch (security_headers_enabled=False)
- Coexistence with Phase 11 CORS headers (preflight OPTIONS, simple requests, error responses)
- Public HoneyToken ingestion endpoints under security headers
- WebSocket non-HTTP scope pass-through
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from starlette.middleware.cors import CORSMiddleware

from app.core.config import Settings
from app.core.rate_limit import reset_all_limiters
from app.main import app
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.models.enums import HoneyTokenType
from app.models.honey_token import HoneyToken
from app.models.project import Project
from app.models.user import User
from tests.conftest import auth_headers


@pytest.fixture(autouse=True)
def _reset_limiters():
    reset_all_limiters()
    yield
    reset_all_limiters()


# ===========================================================================
# 1. Configuration Validation Tests
# ===========================================================================


class TestSecurityHeadersConfigurationValidation:
    """Validate Settings configuration parsing, defaults, and security constraints."""

    def test_default_security_headers_settings_are_secure(self):
        """Default settings must enable security headers with secure baselines."""
        settings = Settings(jwt_secret_key="a" * 32)
        assert settings.security_headers_enabled is True
        assert settings.security_headers_x_content_type_options == "nosniff"
        assert settings.security_headers_x_frame_options == "DENY"
        assert settings.security_headers_referrer_policy == "no-referrer"
        assert settings.security_headers_csp == "default-src 'none'; frame-ancestors 'none'"
        assert "camera=()" in settings.security_headers_permissions_policy
        assert "microphone=()" in settings.security_headers_permissions_policy
        assert "geolocation=()" in settings.security_headers_permissions_policy
        assert settings.security_headers_cache_control == "no-store"
        assert settings.security_headers_hsts_enabled is False
        assert settings.security_headers_hsts_max_age == 31536000
        assert settings.security_headers_hsts_include_subdomains is True
        assert settings.security_headers_hsts_preload is False

    def test_x_frame_options_validation_valid(self):
        """X-Frame-Options must accept DENY and SAMEORIGIN (case-insensitive)."""
        s1 = Settings(jwt_secret_key="a" * 32, security_headers_x_frame_options="DENY")
        assert s1.security_headers_x_frame_options == "DENY"

        s2 = Settings(jwt_secret_key="a" * 32, security_headers_x_frame_options="sameorigin")
        assert s2.security_headers_x_frame_options == "SAMEORIGIN"

    def test_x_frame_options_validation_invalid(self):
        """X-Frame-Options must reject insecure or invalid values like ALLOWALL."""
        with pytest.raises(ValueError, match="must be DENY or SAMEORIGIN"):
            Settings(jwt_secret_key="a" * 32, security_headers_x_frame_options="ALLOW-FROM https://evil.com")

        with pytest.raises(ValueError, match="must be DENY or SAMEORIGIN"):
            Settings(jwt_secret_key="a" * 32, security_headers_x_frame_options="ALLOWALL")

    def test_referrer_policy_validation_valid(self):
        """Referrer-Policy must accept valid standard policies."""
        valid_policies = [
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url",
        ]
        for pol in valid_policies:
            s = Settings(jwt_secret_key="a" * 32, security_headers_referrer_policy=pol)
            assert s.security_headers_referrer_policy == pol

    def test_referrer_policy_validation_invalid(self):
        """Referrer-Policy must reject unknown values."""
        with pytest.raises(ValueError, match="Invalid Referrer-Policy"):
            Settings(jwt_secret_key="a" * 32, security_headers_referrer_policy="none")

    def test_csp_validation_prohibits_unsafe_directives(self):
        """CSP validator must reject unsafe-inline and unsafe-eval."""
        with pytest.raises(ValueError, match="Unsafe CSP directives"):
            Settings(jwt_secret_key="a" * 32, security_headers_csp="default-src 'self' 'unsafe-inline'")

        with pytest.raises(ValueError, match="Unsafe CSP directives"):
            Settings(jwt_secret_key="a" * 32, security_headers_csp="default-src 'self'; script-src 'unsafe-eval'")

    def test_csp_validation_prohibits_empty(self):
        """CSP validator must reject empty string."""
        with pytest.raises(ValueError, match="must not be empty"):
            Settings(jwt_secret_key="a" * 32, security_headers_csp="   ")

    def test_hsts_max_age_bounds(self):
        """HSTS max age must be within valid range [0, 63072000]."""
        with pytest.raises(ValueError):
            Settings(jwt_secret_key="a" * 32, security_headers_hsts_max_age=-1)
        with pytest.raises(ValueError):
            Settings(jwt_secret_key="a" * 32, security_headers_hsts_max_age=100000000)


# ===========================================================================
# 2. Security Headers on Successful Responses
# ===========================================================================


class TestSecurityHeadersOnSuccess:
    """Validate emission of all standard security headers on successful endpoints."""

    def test_health_endpoint_has_all_security_headers(self, client: TestClient):
        """GET /health must include all core security headers."""
        resp = client.get("/health")
        assert resp.status_code == 200
        headers = resp.headers

        assert headers.get("x-content-type-options") == "nosniff"
        assert headers.get("x-frame-options") == "DENY"
        assert headers.get("referrer-policy") == "no-referrer"
        assert headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"
        assert "camera=()" in headers.get("permissions-policy", "")
        assert "microphone=()" in headers.get("permissions-policy", "")
        assert "geolocation=()" in headers.get("permissions-policy", "")
        assert headers.get("cache-control") == "no-store"
        # Plain HTTP request must NOT have HSTS
        assert "strict-transport-security" not in headers

    def test_root_service_endpoint_has_all_security_headers(self, client: TestClient):
        """GET / must include all core security headers."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"
        assert resp.headers.get("cache-control") == "no-store"

    def test_v1_health_endpoint_has_all_security_headers(self, client: TestClient):
        """GET /api/v1/health must include all core security headers."""
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"
        assert resp.headers.get("cache-control") == "no-store"

    def test_authenticated_endpoint_has_all_security_headers(
        self, client: TestClient, admin_headers_a: dict[str, str]
    ):
        """GET /api/v1/tenants with admin credentials must include all security headers."""
        resp = client.get("/api/v1/tenants", headers=admin_headers_a)
        assert resp.status_code == 200
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"
        assert resp.headers.get("cache-control") == "no-store"


# ===========================================================================
# 3. Security Headers on Error Responses
# ===========================================================================


class TestSecurityHeadersOnErrorResponses:
    """Validate that security headers are uniformly applied to all error status codes."""

    def test_401_unauthorized_has_security_headers(self, client: TestClient):
        """401 responses must include all security headers."""
        resp = client.get("/api/v1/tenants")
        assert resp.status_code == 401
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"
        assert resp.headers.get("cache-control") == "no-store"

    def test_403_forbidden_has_security_headers(
        self, client: TestClient, user_a: User
    ):
        """403 responses must include all security headers."""
        user_headers = auth_headers(user_a)
        resp = client.post(
            "/api/v1/projects",
            json={"name": "Forbidden Project", "domain": "forbidden.example.com"},
            headers=user_headers,
        )
        assert resp.status_code == 403
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"
        assert resp.headers.get("cache-control") == "no-store"

    def test_404_not_found_has_security_headers(self, client: TestClient):
        """404 responses must include all security headers."""
        resp = client.get("/api/v1/nonexistent-route-12345")
        assert resp.status_code == 404
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"
        assert resp.headers.get("cache-control") == "no-store"

    def test_413_payload_too_large_has_security_headers(self, client: TestClient):
        """413 responses from RequestBodySizeMiddleware must include all security headers."""
        huge_payload = "A" * (1024 * 1024 + 100)
        resp = client.post(
            "/api/v1/auth/login",
            content=huge_payload,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 413
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"
        assert resp.headers.get("cache-control") == "no-store"

    def test_429_rate_limit_has_security_headers(self, client: TestClient):
        """429 responses from ApiRateLimitMiddleware must include all security headers."""
        from app.core.config import get_settings
        settings = get_settings()

        for _ in range(settings.rate_limit_per_minute_public + 5):
            resp = client.get("/api/v1/auth/login")
            if resp.status_code == 429:
                break

        assert resp.status_code == 429
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"
        assert resp.headers.get("cache-control") == "no-store"
        assert "retry-after" in resp.headers

    def test_500_internal_error_has_security_headers(self, client: TestClient):
        """500 responses caught by GlobalExceptionMiddleware must include all security headers."""
        unhandled_client = TestClient(client.app, raise_server_exceptions=False)
        with patch("app.main.health_payload", side_effect=RuntimeError("Simulated unhandled crash")):
            resp = unhandled_client.get("/health")
            assert resp.status_code == 500
            assert resp.headers.get("x-content-type-options") == "nosniff"
            assert resp.headers.get("x-frame-options") == "DENY"
            assert resp.headers.get("referrer-policy") == "no-referrer"
            assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"
            assert resp.headers.get("cache-control") == "no-store"


# ===========================================================================
# 4. Zero Duplicate Headers & Case-Insensitive Deduplication
# ===========================================================================


class TestDeduplicationAndHeaderIntegrity:
    """Verify headers are not duplicated and exist exactly once."""

    def test_zero_duplicate_headers(self, client: TestClient):
        """Inspect raw response headers to guarantee no duplicates."""
        resp = client.get("/health")
        assert resp.status_code == 200

        # In httpx, resp.headers.raw is a list of (bytes, bytes)
        raw_header_names = [name.lower().decode("latin-1") for name, _ in resp.headers.raw]
        for header_name in [
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "content-security-policy",
            "permissions-policy",
            "cache-control",
        ]:
            count = raw_header_names.count(header_name)
            assert count == 1, f"Header '{header_name}' appeared {count} times (expected exactly 1)"


# ===========================================================================
# 5. Endpoint-Specific Header Preservation (SSE, Streaming)
# ===========================================================================


class TestEndpointSpecificHeaderPreservation:
    """Verify endpoint-specific headers (e.g. Cache-Control on SSE) are preserved."""

    @patch("asyncio.wait_for", side_effect=asyncio.CancelledError)
    def test_sse_endpoint_preserves_custom_cache_control(
        self, mock_wait_for, client: TestClient, admin_a: User
    ):
        """SSE stream response specifies Cache-Control: no-cache, which must NOT be replaced with no-store."""
        from app.core.security import create_access_token
        token = create_access_token(subject=str(admin_a.id))

        # Open SSE stream and read response
        with client.stream("GET", f"/api/v1/events/stream/sse?token={token}") as resp:
            assert resp.status_code == 200
            headers = resp.headers
            # Cache-Control must be preserved as no-cache
            assert headers.get("cache-control") == "no-cache"
            # Core security headers must still be present
            assert headers.get("x-content-type-options") == "nosniff"
            assert headers.get("x-frame-options") == "DENY"
            assert headers.get("referrer-policy") == "no-referrer"
            assert headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"


# ===========================================================================
# 6. Strict HSTS Invariants
# ===========================================================================


class TestHSTSInvariants:
    """Verify strict transport security safety properties."""

    def test_hsts_absent_by_default_on_plain_http(self, client: TestClient):
        """HSTS must NOT be emitted on plain HTTP requests."""
        resp = client.get("/health")
        assert "strict-transport-security" not in resp.headers

    def test_hsts_absent_on_http_even_when_enabled(self, client: TestClient):
        """HSTS must NOT be emitted on plain HTTP even if security_headers_hsts_enabled is True."""
        curr = client.app.middleware_stack
        sec_mw = None
        while curr is not None:
            if isinstance(curr, SecurityHeadersMiddleware):
                sec_mw = curr
                break
            curr = getattr(curr, "app", None)

        assert sec_mw is not None, "SecurityHeadersMiddleware must be in middleware stack"
        orig_enabled = sec_mw.settings.security_headers_hsts_enabled
        try:
            sec_mw.settings.security_headers_hsts_enabled = True
            resp = client.get("/health")  # Plain HTTP
            assert "strict-transport-security" not in resp.headers
        finally:
            sec_mw.settings.security_headers_hsts_enabled = orig_enabled

    def test_hsts_present_when_enabled_and_direct_https(self, client: TestClient):
        """HSTS must be emitted when enabled AND request is HTTPS."""
        curr = client.app.middleware_stack
        sec_mw = None
        while curr is not None:
            if isinstance(curr, SecurityHeadersMiddleware):
                sec_mw = curr
                break
            curr = getattr(curr, "app", None)

        assert sec_mw is not None
        orig_enabled = sec_mw.settings.security_headers_hsts_enabled
        try:
            sec_mw.settings.security_headers_hsts_enabled = True
            resp = client.get("https://testserver/health")
            assert resp.status_code == 200
            hsts = resp.headers.get("strict-transport-security")
            assert hsts is not None
            assert f"max-age={sec_mw.settings.security_headers_hsts_max_age}" in hsts
            assert "includeSubDomains" in hsts
        finally:
            sec_mw.settings.security_headers_hsts_enabled = orig_enabled

    def test_hsts_present_when_enabled_and_trusted_proxy_forwarded_https(self, client: TestClient):
        """HSTS must be emitted when enabled AND X-Forwarded-Proto: https from trusted proxy."""
        curr = client.app.middleware_stack
        sec_mw = None
        while curr is not None:
            if isinstance(curr, SecurityHeadersMiddleware):
                sec_mw = curr
                break
            curr = getattr(curr, "app", None)

        assert sec_mw is not None
        orig_enabled = sec_mw.settings.security_headers_hsts_enabled
        try:
            sec_mw.settings.security_headers_hsts_enabled = True
            # TestClient peer is 127.0.0.1 (trusted proxy by default)
            resp = client.get("/health", headers={"X-Forwarded-Proto": "https"})
            assert resp.status_code == 200
            hsts = resp.headers.get("strict-transport-security")
            assert hsts is not None
            assert "max-age=" in hsts
        finally:
            sec_mw.settings.security_headers_hsts_enabled = orig_enabled

    def test_hsts_absent_when_forwarded_https_from_untrusted_peer(self):
        """HSTS must NOT be emitted if X-Forwarded-Proto: https comes from an untrusted peer."""
        custom_settings = Settings(
            jwt_secret_key="a" * 32,
            security_headers_hsts_enabled=True,
            trusted_proxies=["10.0.0.1"],  # 127.0.0.1 is NOT trusted here
        )
        mw = SecurityHeadersMiddleware(app, settings=custom_settings)
        # Mock scope with untrusted peer
        scope = {
            "type": "http",
            "scheme": "http",
            "client": ("198.51.100.1", 50000),
            "headers": [(b"x-forwarded-proto", b"https")],
        }
        assert mw._is_https_request(scope, custom_settings) is False

    def test_hsts_preload_directive(self, client: TestClient):
        """HSTS with preload enabled must append '; preload' directive."""
        curr = client.app.middleware_stack
        sec_mw = None
        while curr is not None:
            if isinstance(curr, SecurityHeadersMiddleware):
                sec_mw = curr
                break
            curr = getattr(curr, "app", None)

        assert sec_mw is not None
        orig_enabled = sec_mw.settings.security_headers_hsts_enabled
        orig_preload = sec_mw.settings.security_headers_hsts_preload
        try:
            sec_mw.settings.security_headers_hsts_enabled = True
            sec_mw.settings.security_headers_hsts_preload = True
            resp = client.get("https://testserver/health")
            hsts = resp.headers.get("strict-transport-security")
            assert hsts is not None
            assert "preload" in hsts
        finally:
            sec_mw.settings.security_headers_hsts_enabled = orig_enabled
            sec_mw.settings.security_headers_hsts_preload = orig_preload


# ===========================================================================
# 7. Security Headers Global Disable Switch
# ===========================================================================


class TestSecurityHeadersDisableSwitch:
    """Verify security_headers_enabled=False bypasses middleware injection."""

    def test_headers_omitted_when_disabled(self, client: TestClient):
        """When security_headers_enabled is False, headers are not injected."""
        curr = client.app.middleware_stack
        sec_mw = None
        while curr is not None:
            if isinstance(curr, SecurityHeadersMiddleware):
                sec_mw = curr
                break
            curr = getattr(curr, "app", None)

        assert sec_mw is not None
        orig_enabled = sec_mw.settings.security_headers_enabled
        try:
            sec_mw.settings.security_headers_enabled = False
            resp = client.get("/health")
            assert resp.status_code == 200
            assert "x-content-type-options" not in resp.headers
            assert "x-frame-options" not in resp.headers
            assert "content-security-policy" not in resp.headers
            assert "permissions-policy" not in resp.headers
        finally:
            sec_mw.settings.security_headers_enabled = orig_enabled


# ===========================================================================
# 8. Coexistence with Phase 11 CORS Headers
# ===========================================================================


class TestCoexistenceWithCORS:
    """Verify SecurityHeadersMiddleware and CORSMiddleware operate harmoniously."""

    @pytest.fixture()
    def cors_client(self, client: TestClient):
        """TestClient fixture with explicit trusted origins on CORSMiddleware."""
        curr = client.app.middleware_stack
        cors_mw = None
        while curr is not None:
            if isinstance(curr, CORSMiddleware):
                cors_mw = curr
                break
            curr = getattr(curr, "app", None)

        assert cors_mw is not None
        original_origins = cors_mw.allow_origins
        cors_mw.allow_origins = ["https://app.honeyshield.test"]
        try:
            yield client
        finally:
            cors_mw.allow_origins = original_origins

    def test_preflight_options_receives_both_cors_and_security_headers(self, cors_client: TestClient):
        """OPTIONS preflight for trusted origin must receive both CORS and security headers."""
        headers = {
            "Origin": "https://app.honeyshield.test",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        }
        resp = cors_client.options("/api/v1/health", headers=headers)
        assert resp.status_code == 200

        # CORS headers
        assert resp.headers.get("access-control-allow-origin") == "https://app.honeyshield.test"

        # Security headers
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"
        assert resp.headers.get("cache-control") == "no-store"

    def test_simple_cross_origin_request_receives_both_cors_and_security_headers(
        self, cors_client: TestClient
    ):
        """Simple cross-origin GET must include both CORS and security headers."""
        resp = cors_client.get(
            "/api/v1/health",
            headers={"Origin": "https://app.honeyshield.test"},
        )
        assert resp.status_code == 200
        # CORS
        assert resp.headers.get("access-control-allow-origin") == "https://app.honeyshield.test"
        # Security
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"

    def test_untrusted_cross_origin_request_receives_security_headers(
        self, cors_client: TestClient
    ):
        """Untrusted cross-origin GET omits CORS headers but retains security headers."""
        resp = cors_client.get(
            "/api/v1/health",
            headers={"Origin": "https://evil.attacker.com"},
        )
        assert resp.status_code == 200
        # CORS omitted
        assert "access-control-allow-origin" not in resp.headers
        # Security present
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"


# ===========================================================================
# 9. Public HoneyToken Ingestion Endpoints
# ===========================================================================


class TestPublicIngestionSecurityHeaders:
    """Verify public deception ingestion endpoints return security headers."""

    def test_honeytoken_redirect_has_security_headers(
        self, client: TestClient, token_a: HoneyToken
    ):
        """GET /t/{token} (URL token ingestion) must include all security headers."""
        resp = client.get(f"/t/{token_a.token_value}", follow_redirects=False)
        assert resp.status_code in (200, 204, 302)
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"
        assert resp.headers.get("cache-control") == "no-store"

    def test_pixel_ingestion_has_security_headers(
        self, client: TestClient, token_a: HoneyToken
    ):
        """GET /px/{token}.gif (Pixel token ingestion) must include security headers."""
        resp = client.get(f"/px/{token_a.token_value}.gif")
        assert resp.status_code == 200
        assert resp.headers.get("content-type") == "image/gif"
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert resp.headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'"


# ===========================================================================
# 10. WebSocket Non-HTTP Scope Pass-Through
# ===========================================================================


class TestWebSocketNonHttpScopePassThrough:
    """Verify WebSocket connections pass through SecurityHeadersMiddleware cleanly."""

    def test_websocket_connection_unaffected(self, client: TestClient):
        """WebSocket connection handshake must pass through without HTTP header errors."""
        with client.websocket_connect("/api/v1/events/stream/ws") as ws:
            ws.send_json({"type": "invalid"})
            data = ws.receive()
            assert data["type"] == "websocket.close"
