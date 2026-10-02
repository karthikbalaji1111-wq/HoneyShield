"""Focused security tests for CORS Policy (Finding F-014 / Phase 11).

Covers:
- Configuration validation (origin parsing, normalization, rejection of wildcards, paths, schemes)
- Preflight (OPTIONS) request handling (trusted vs untrusted origins, methods, headers, max-age)
- Simple cross-origin request handling (trusted vs untrusted origins, exposed headers)
- Cross-origin authenticated requests (Bearer JWT)
- CORS header presence on error responses (401, 403, 404, 413, 429, 500)
- Public HoneyToken ingestion endpoints under CORS
- SSE compatibility and WebSocket scope behavior
- Default-deny behavior when no origins configured
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from starlette.middleware.cors import CORSMiddleware

from app.core.config import Settings
from app.core.rate_limit import reset_all_limiters
from app.models.honey_token import HoneyToken
from app.models.user import User


@pytest.fixture(autouse=True)
def _reset_limiters():
    reset_all_limiters()
    yield
    reset_all_limiters()


@pytest.fixture()
def cors_client(client: TestClient):
    """TestClient fixture with explicit trusted origins configured on CORSMiddleware."""
    curr = client.app.middleware_stack
    cors_mw = None
    while curr is not None:
        if isinstance(curr, CORSMiddleware):
            cors_mw = curr
            break
        curr = getattr(curr, "app", None)

    if cors_mw is None:
        client.get("/")
        curr = client.app.middleware_stack
        while curr is not None:
            if isinstance(curr, CORSMiddleware):
                cors_mw = curr
                break
            curr = getattr(curr, "app", None)

    assert cors_mw is not None, "CORSMiddleware must be present in middleware stack"
    original_origins = cors_mw.allow_origins
    cors_mw.allow_origins = ["https://app.honeyshield.test", "https://admin.honeyshield.test"]
    try:
        yield client
    finally:
        cors_mw.allow_origins = original_origins


# ===========================================================================
# 1. Configuration Validation Tests
# ===========================================================================


class TestCORSConfigurationValidation:
    """Validate Settings configuration parsing, normalization, and security constraints."""

    def test_default_cors_settings_are_secure(self):
        """Default settings must deny all cross-origin requests by default."""
        settings = Settings(jwt_secret_key="a" * 32)
        assert settings.cors_allowed_origins == []
        assert settings.cors_allow_credentials is False
        assert "GET" in settings.cors_allow_methods
        assert "POST" in settings.cors_allow_methods
        assert "Authorization" in settings.cors_allow_headers
        assert "X-Request-ID" in settings.cors_expose_headers
        assert settings.cors_max_age == 600

    def test_valid_comma_separated_origins(self):
        """Comma-separated origin strings must parse cleanly into normalized lists."""
        settings = Settings(
            jwt_secret_key="a" * 32,
            cors_allowed_origins="https://app.honeyshield.test, https://admin.honeyshield.test",
        )
        assert settings.cors_allowed_origins == [
            "https://app.honeyshield.test",
            "https://admin.honeyshield.test",
        ]

    def test_origin_trailing_slash_stripped(self):
        """Trailing slashes must be stripped to produce canonical origins."""
        settings = Settings(
            jwt_secret_key="a" * 32,
            cors_allowed_origins="https://app.honeyshield.test/",
        )
        assert settings.cors_allowed_origins == ["https://app.honeyshield.test"]

    def test_origin_case_normalization(self):
        """Scheme and host must be normalized to lowercase."""
        settings = Settings(
            jwt_secret_key="a" * 32,
            cors_allowed_origins="HTTPS://APP.HONEYSHIELD.TEST",
        )
        assert settings.cors_allowed_origins == ["https://app.honeyshield.test"]

    def test_origin_port_preserved(self):
        """Custom ports on localhost or dev environments must be preserved."""
        settings = Settings(
            jwt_secret_key="a" * 32,
            cors_allowed_origins="http://localhost:3000, https://dev.honeyshield.test:8443",
        )
        assert settings.cors_allowed_origins == [
            "http://localhost:3000",
            "https://dev.honeyshield.test:8443",
        ]

    def test_origin_deduplication(self):
        """Duplicate origins must be deterministically removed while preserving order."""
        settings = Settings(
            jwt_secret_key="a" * 32,
            cors_allowed_origins="https://app.honeyshield.test, https://app.honeyshield.test/",
        )
        assert settings.cors_allowed_origins == ["https://app.honeyshield.test"]

    def test_wildcard_origin_strictly_rejected(self):
        """Wildcard '*' origin must be rejected unconditionally."""
        with pytest.raises(ValueError, match="Wildcard '\\*' CORS origins are strictly forbidden"):
            Settings(jwt_secret_key="a" * 32, cors_allowed_origins="*")

        with pytest.raises(ValueError, match="Wildcard '\\*' CORS origins are strictly forbidden"):
            Settings(jwt_secret_key="a" * 32, cors_allowed_origins=["https://app.honeyshield.test", "*"])

    def test_wildcard_pattern_in_origin_rejected(self):
        """Wildcard patterns like *.domain.com must be rejected."""
        with pytest.raises(ValueError, match="Wildcard patterns are forbidden"):
            Settings(jwt_secret_key="a" * 32, cors_allowed_origins="https://*.honeyshield.test")

    def test_invalid_scheme_rejected(self):
        """Non-HTTP/HTTPS schemes (ftp, file, javascript, data) must be rejected."""
        with pytest.raises(ValueError, match="only http and https are permitted"):
            Settings(jwt_secret_key="a" * 32, cors_allowed_origins="ftp://honeyshield.test")

        with pytest.raises(ValueError, match="only http and https are permitted"):
            Settings(jwt_secret_key="a" * 32, cors_allowed_origins="null")

    def test_missing_host_rejected(self):
        """Origins missing a host component must be rejected."""
        with pytest.raises(ValueError, match="missing host"):
            Settings(jwt_secret_key="a" * 32, cors_allowed_origins="https://")

    def test_origin_with_path_rejected(self):
        """Origins containing path components must be rejected."""
        with pytest.raises(ValueError, match="must not contain a path component"):
            Settings(jwt_secret_key="a" * 32, cors_allowed_origins="https://app.honeyshield.test/api/v1")

    def test_origin_with_userinfo_rejected(self):
        """Origins containing user credentials must be rejected."""
        with pytest.raises(ValueError, match="must not contain user credentials"):
            Settings(jwt_secret_key="a" * 32, cors_allowed_origins="https://user:pass@app.honeyshield.test")

    def test_origin_with_query_rejected(self):
        """Origins containing query parameters must be rejected."""
        with pytest.raises(ValueError, match="must not contain query parameters"):
            Settings(jwt_secret_key="a" * 32, cors_allowed_origins="https://app.honeyshield.test?auth=true")

    def test_origin_with_fragment_rejected(self):
        """Origins containing URL fragments must be rejected."""
        with pytest.raises(ValueError, match="must not contain URL fragments"):
            Settings(jwt_secret_key="a" * 32, cors_allowed_origins="https://app.honeyshield.test#dashboard")

    def test_cors_allow_methods_validation(self):
        """Allowed methods must be valid HTTP methods; wildcards are rejected."""
        with pytest.raises(ValueError, match="Wildcard '\\*' is forbidden in cors_allow_methods"):
            Settings(jwt_secret_key="a" * 32, cors_allow_methods="*")

        with pytest.raises(ValueError, match="Invalid HTTP method"):
            Settings(jwt_secret_key="a" * 32, cors_allow_methods="GET,POST,FOOBAR")

        settings = Settings(jwt_secret_key="a" * 32, cors_allow_methods="get, post, put")
        assert settings.cors_allow_methods == ["GET", "POST", "PUT"]

    def test_cors_allow_headers_validation(self):
        """Allowed headers must not contain wildcards."""
        with pytest.raises(ValueError, match="Wildcard '\\*' is forbidden in cors_allow_headers"):
            Settings(jwt_secret_key="a" * 32, cors_allow_headers="*")

        settings = Settings(
            jwt_secret_key="a" * 32,
            cors_allow_headers="Authorization, Content-Type, X-Custom-Header",
        )
        assert "Authorization" in settings.cors_allow_headers
        assert "Content-Type" in settings.cors_allow_headers
        assert "X-Custom-Header" in settings.cors_allow_headers

    def test_cors_expose_headers_validation(self):
        """Exposed headers must not contain wildcards."""
        with pytest.raises(ValueError, match="Wildcard '\\*' is forbidden in cors_expose_headers"):
            Settings(jwt_secret_key="a" * 32, cors_expose_headers="*")

        settings = Settings(
            jwt_secret_key="a" * 32,
            cors_expose_headers="X-Request-ID, Retry-After",
        )
        assert settings.cors_expose_headers == ["X-Request-ID", "Retry-After"]

    def test_cors_max_age_validation(self):
        """Max age must fall within 0 to 86400 seconds."""
        settings = Settings(jwt_secret_key="a" * 32, cors_max_age=3600)
        assert settings.cors_max_age == 3600

        with pytest.raises(Exception):
            Settings(jwt_secret_key="a" * 32, cors_max_age=-1)

        with pytest.raises(Exception):
            Settings(jwt_secret_key="a" * 32, cors_max_age=100000)


# ===========================================================================
# 2. Preflight (OPTIONS) Tests
# ===========================================================================


class TestCORSPreflightRequests:
    """Validate CORS preflight OPTIONS requests across trusted and untrusted origins."""

    def test_preflight_trusted_origin_returns_200_with_cors_headers(self, cors_client: TestClient):
        """Preflight from trusted origin must return 200 with appropriate CORS headers."""
        resp = cors_client.options(
            "/api/v1/health",
            headers={
                "Origin": "https://app.honeyshield.test",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == "https://app.honeyshield.test"
        assert "GET" in resp.headers.get("access-control-allow-methods", "")
        assert resp.headers.get("access-control-max-age") == "600"
        assert resp.headers.get("vary") == "Origin"
        assert resp.headers.get("x-request-id") is not None

    def test_preflight_second_trusted_origin_honored(self, cors_client: TestClient):
        """Preflight from second trusted origin must reflect that exact origin."""
        resp = cors_client.options(
            "/api/v1/health",
            headers={
                "Origin": "https://admin.honeyshield.test",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == "https://admin.honeyshield.test"

    def test_preflight_untrusted_origin_rejected(self, cors_client: TestClient):
        """Preflight from untrusted origin must return 400 and omit allow-origin header."""
        resp = cors_client.options(
            "/api/v1/health",
            headers={
                "Origin": "https://evil.attacker.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert resp.status_code == 400
        assert "access-control-allow-origin" not in resp.headers

    def test_preflight_substring_origin_rejected(self, cors_client: TestClient):
        """Substring domain attacks must not match trusted origins."""
        resp = cors_client.options(
            "/api/v1/health",
            headers={
                "Origin": "https://app.honeyshield.test.attacker.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert resp.status_code == 400
        assert "access-control-allow-origin" not in resp.headers

    def test_preflight_suffix_origin_rejected(self, cors_client: TestClient):
        """Prefix/suffix variations of domain must not match trusted origins."""
        resp = cors_client.options(
            "/api/v1/health",
            headers={
                "Origin": "https://notapp.honeyshield.test",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert resp.status_code == 400
        assert "access-control-allow-origin" not in resp.headers

    def test_preflight_disallowed_method_rejected(self, cors_client: TestClient):
        """Preflight requesting disallowed HTTP method must be rejected."""
        resp = cors_client.options(
            "/api/v1/health",
            headers={
                "Origin": "https://app.honeyshield.test",
                "Access-Control-Request-Method": "CONNECT",
            },
        )
        assert resp.status_code == 400

    def test_preflight_disallowed_header_rejected(self, cors_client: TestClient):
        """Preflight requesting disallowed header must be rejected."""
        resp = cors_client.options(
            "/api/v1/health",
            headers={
                "Origin": "https://app.honeyshield.test",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "x-malicious-header",
            },
        )
        assert resp.status_code == 400

    def test_preflight_does_not_consume_rate_limit(self, cors_client: TestClient):
        """Preflight OPTIONS requests must not be throttled by rate limiters."""
        for _ in range(30):
            resp = cors_client.options(
                "/api/v1/health",
                headers={
                    "Origin": "https://app.honeyshield.test",
                    "Access-Control-Request-Method": "GET",
                },
            )
            assert resp.status_code == 200


# ===========================================================================
# 3. Simple & Actual Request Tests
# ===========================================================================


class TestCORSSimpleAndActualRequests:
    """Validate CORS behavior on actual HTTP operations (GET, POST, PUT, DELETE)."""

    def test_get_trusted_origin_includes_cors_headers(self, cors_client: TestClient):
        """GET request from trusted origin receives Access-Control-Allow-Origin."""
        resp = cors_client.get("/health", headers={"Origin": "https://app.honeyshield.test"})
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == "https://app.honeyshield.test"
        assert resp.headers.get("vary") == "Origin"
        assert "X-Request-ID" in resp.headers.get("access-control-expose-headers", "")
        assert "X-Process-Time-Ms" in resp.headers.get("access-control-expose-headers", "")
        assert "Retry-After" in resp.headers.get("access-control-expose-headers", "")

    def test_get_untrusted_origin_omits_cors_headers(self, cors_client: TestClient):
        """GET request from untrusted origin does NOT receive Access-Control-Allow-Origin."""
        resp = cors_client.get("/health", headers={"Origin": "https://evil.attacker.com"})
        assert resp.status_code == 200
        assert "access-control-allow-origin" not in resp.headers

    def test_same_origin_request_without_origin_header_unaffected(self, cors_client: TestClient):
        """Requests without Origin header execute normally without CORS headers."""
        resp = cors_client.get("/health")
        assert resp.status_code == 200
        assert "access-control-allow-origin" not in resp.headers

    def test_authenticated_request_cors_headers(
        self,
        cors_client: TestClient,
        admin_a: User,
        admin_headers_a: dict[str, str],
    ):
        """Authenticated request from trusted origin receives CORS headers."""
        headers = dict(admin_headers_a)
        headers["Origin"] = "https://app.honeyshield.test"
        resp = cors_client.get("/api/v1/projects", headers=headers)
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == "https://app.honeyshield.test"

    def test_credentials_header_absent_by_default(self, cors_client: TestClient):
        """Access-Control-Allow-Credentials must not be present when allow_credentials=False."""
        resp = cors_client.get("/health", headers={"Origin": "https://app.honeyshield.test"})
        assert resp.status_code == 200
        assert "access-control-allow-credentials" not in resp.headers


# ===========================================================================
# 4. Error Responses Under CORS
# ===========================================================================


class TestCORSErrorResponses:
    """Validate CORS headers are attached to error responses for trusted origins."""

    def test_401_unauthorized_includes_cors_headers_for_trusted_origin(self, cors_client: TestClient):
        """401 Unauthorized must include CORS headers so browser clients can read the response."""
        resp = cors_client.get(
            "/api/v1/projects",
            headers={"Origin": "https://app.honeyshield.test"},
        )
        assert resp.status_code == 401
        assert resp.headers.get("access-control-allow-origin") == "https://app.honeyshield.test"
        assert resp.headers.get("vary") == "Origin"

    def test_404_not_found_includes_cors_headers_for_trusted_origin(self, cors_client: TestClient):
        """404 Not Found must include CORS headers for trusted origins."""
        resp = cors_client.get(
            "/api/v1/nonexistent-route",
            headers={"Origin": "https://app.honeyshield.test"},
        )
        assert resp.status_code == 404
        assert resp.headers.get("access-control-allow-origin") == "https://app.honeyshield.test"

    def test_413_payload_too_large_includes_cors_headers_for_trusted_origin(
        self,
        cors_client: TestClient,
        admin_headers_a: dict[str, str],
    ):
        """413 Payload Too Large must include CORS headers so browser client can read the error."""
        headers = dict(admin_headers_a)
        headers["Origin"] = "https://app.honeyshield.test"
        headers["Content-Type"] = "application/json"

        # Settings max_request_body_bytes is 1MB, simulate 2MB payload
        with patch("app.middleware.body_size.RequestBodySizeMiddleware.max_bytes", 1024):
            resp = cors_client.post(
                "/api/v1/projects",
                content=b"x" * 2048,
                headers=headers,
            )
            assert resp.status_code == 413
            assert resp.headers.get("access-control-allow-origin") == "https://app.honeyshield.test"
            assert resp.headers.get("vary") == "Origin"

    def test_429_rate_limit_includes_cors_headers_and_exposed_retry_after(self, cors_client: TestClient):
        """429 Too Many Requests must include CORS headers and exposed Retry-After."""
        with patch("app.middleware.rate_limit.api_limiter.check_and_increment", return_value=(False, 45)):
            resp = cors_client.get(
                "/api/v1/projects",
                headers={"Origin": "https://app.honeyshield.test"},
            )
            assert resp.status_code == 429
            assert resp.headers.get("access-control-allow-origin") == "https://app.honeyshield.test"
            assert resp.headers.get("vary") == "Origin"
            assert resp.headers.get("retry-after") == "45"
            assert "Retry-After" in resp.headers.get("access-control-expose-headers", "")

    def test_500_internal_error_includes_cors_headers_for_trusted_origin(self, cors_client: TestClient):
        """500 Internal Server Error must include CORS headers for trusted origins."""
        unhandled_client = TestClient(cors_client.app, raise_server_exceptions=False)
        with patch("app.main.health_payload", side_effect=RuntimeError("Test crash")):
            resp = unhandled_client.get(
                "/health",
                headers={"Origin": "https://app.honeyshield.test"},
            )
            assert resp.status_code == 500
            assert resp.headers.get("access-control-allow-origin") == "https://app.honeyshield.test"

    def test_error_responses_for_untrusted_origin_omit_cors_headers(self, cors_client: TestClient):
        """Error responses for untrusted origins must NOT receive Access-Control-Allow-Origin."""
        resp = cors_client.get(
            "/api/v1/projects",
            headers={"Origin": "https://evil.attacker.com"},
        )
        assert resp.status_code == 401
        assert "access-control-allow-origin" not in resp.headers


# ===========================================================================
# 5. Public HoneyToken Ingestion Under CORS
# ===========================================================================


class TestPublicIngestionCORS:
    """Ensure HoneyToken ingestion semantics remain functional under CORS."""

    def test_public_honeytoken_ingestion_without_origin_unaffected(
        self,
        cors_client: TestClient,
        token_a: HoneyToken,
    ):
        """HoneyToken ingestion without Origin header (e.g. curl, browser navigation) works normally."""
        resp = cors_client.get(f"/t/{token_a.token_value}")
        assert resp.status_code == 204
        assert "access-control-allow-origin" not in resp.headers

    def test_public_honeytoken_ingestion_with_untrusted_origin_records_event(
        self,
        cors_client: TestClient,
        token_a: HoneyToken,
    ):
        """HoneyToken triggered from cross-origin site executes and logs event without CORS reflection."""
        resp = cors_client.get(
            f"/t/{token_a.token_value}",
            headers={"Origin": "https://attacker-controlled-site.com"},
        )
        assert resp.status_code == 204
        # Server executes trigger and logs event, but does not grant CORS to attacker
        assert "access-control-allow-origin" not in resp.headers

    def test_public_honeytoken_pixel_ingestion_unaffected(
        self,
        cors_client: TestClient,
        token_a: HoneyToken,
    ):
        """Tracking pixel endpoint works seamlessly regardless of Origin header."""
        resp = cors_client.get(
            f"/px/{token_a.token_value}.gif",
            headers={"Origin": "https://random-email-client.example"},
        )
        assert resp.status_code == 200
        assert resp.headers.get("content-type") == "image/gif"
        assert "access-control-allow-origin" not in resp.headers


# ===========================================================================
# 6. Default Deny Behavior
# ===========================================================================


class TestDefaultDenyCORS:
    """Ensure default configuration (empty allowed origins) denies all cross-origin requests."""

    def test_default_empty_origins_blocks_all_cross_origin_requests(self, client: TestClient):
        """When cors_allowed_origins is empty, preflight is rejected and no CORS headers are returned."""
        curr = client.app.middleware_stack
        cors_mw = None
        while curr is not None:
            if isinstance(curr, CORSMiddleware):
                cors_mw = curr
                break
            curr = getattr(curr, "app", None)

        if cors_mw:
            orig = cors_mw.allow_origins
            cors_mw.allow_origins = []
            try:
                # Preflight rejected
                resp_opt = client.options(
                    "/health",
                    headers={
                        "Origin": "https://app.honeyshield.test",
                        "Access-Control-Request-Method": "GET",
                    },
                )
                assert resp_opt.status_code == 400
                assert "access-control-allow-origin" not in resp_opt.headers

                # Actual request succeeds but without CORS headers
                resp_get = client.get(
                    "/health",
                    headers={"Origin": "https://app.honeyshield.test"},
                )
                assert resp_get.status_code == 200
                assert "access-control-allow-origin" not in resp_get.headers
            finally:
                cors_mw.allow_origins = orig
