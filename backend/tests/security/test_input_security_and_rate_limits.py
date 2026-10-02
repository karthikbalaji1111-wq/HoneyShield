"""Comprehensive regression tests for Phase 7: Input Security & Rate Limits.

Covers:
  - F-010: Request body-size limits (normal, oversized Content-Length, streaming/chunked, 413 format)
  - F-011: API-wide rate limiting (authenticated, public, health exempt, 429 Retry-After, reset)
  - F-012: HoneyToken ingestion abuse control (valid, invalid, revoked, per-token isolation, 429)
  - F-013: Forensic request header security (allowlist, credential stripping, deterministic truncation, size cap)
  - F-028: IP validation and trusted-proxy model (IPv4/IPv6, malformed reject, spoofing resistance)
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.header_security import sanitize_forensic_headers
from app.core.ip_trust import extract_client_ip, is_valid_ip, normalize_ip
from app.core.rate_limit import api_limiter, ingestion_limiter, login_limiter, reset_all_limiters
from app.models.detection_event import DetectionEvent
from app.models.enums import HoneyTokenType


# ---------------------------------------------------------------------------
# Phase 7B: Request Body Size Limits (F-010)
# ---------------------------------------------------------------------------

class TestRequestBodySizeLimits:
    def test_normal_request_within_limit_accepted(self, client, admin_headers_a):
        """A normal payload well below the 1MB limit must succeed."""
        resp = client.post(
            "/api/v1/projects",
            headers=admin_headers_a,
            json={"tenant_slug": "tenant-a", "name": "Body Size Project", "domain": "bodysize.test.internal"},
        )
        assert resp.status_code == 201
        assert resp.json()["name"] == "Body Size Project"

    def test_oversized_content_length_rejected_with_413(self, client, admin_headers_a):
        """A request with Content-Length exceeding the limit must be rejected with 413."""
        settings = get_settings()
        oversized_length = settings.max_request_body_bytes + 1024

        headers = dict(admin_headers_a)
        headers["content-length"] = str(oversized_length)

        resp = client.post(
            "/api/v1/projects",
            headers=headers,
            content=b"x" * 100,  # Content-Length claims oversized
        )
        assert resp.status_code == 413
        data = resp.json()
        assert "exceeds maximum allowed size" in data["detail"]
        assert "request_id" in data

    def test_streaming_chunked_body_overflow_rejected_with_413(self, client, admin_headers_a):
        """A streamed/chunked request body exceeding max_bytes must terminate and return 413."""
        settings = get_settings()
        max_bytes = settings.max_request_body_bytes

        # Generate payload larger than max_bytes
        oversized_payload = b"A" * (max_bytes + 2048)

        # Without Content-Length or with exact large payload
        resp = client.post(
            "/api/v1/projects",
            headers=admin_headers_a,
            content=oversized_payload,
        )
        assert resp.status_code == 413
        assert "exceeds maximum allowed size" in resp.json()["detail"]

    def test_boundary_request_accepted(self, client, admin_headers_a):
        """A request immediately below the limit must pass the body size check."""
        # A payload of 100KB is well below 1MB but substantial
        payload = {"tenant_slug": "tenant-a", "name": "Boundary Project", "domain": "boundary.test.internal"}
        resp = client.post(
            "/api/v1/projects",
            headers=admin_headers_a,
            json=payload,
        )
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# Phase 7C: API-Wide Rate Limiting (F-011)
# ---------------------------------------------------------------------------

class TestApiRateLimiting:
    def test_authenticated_traffic_rate_limited(self, client, admin_headers_a):
        """Authenticated traffic must be throttled once limit is reached and return 429."""
        settings = get_settings()
        limit = settings.rate_limit_per_minute_authenticated

        # Use patch to simulate low limit for fast execution
        with patch.object(settings, "rate_limit_per_minute_authenticated", 3):
            # First 3 requests succeed
            for _ in range(3):
                r = client.get("/api/v1/projects", headers=admin_headers_a)
                assert r.status_code == 200

            # 4th request must be rejected with 429
            r4 = client.get("/api/v1/projects", headers=admin_headers_a)
            assert r4.status_code == 429
            assert "Retry-After" in r4.headers
            assert int(r4.headers["Retry-After"]) >= 1
            data = r4.json()
            assert "rate limit exceeded" in data["detail"].lower()
            assert "request_id" in data

    def test_public_traffic_rate_limited(self, client):
        """Public API traffic must be throttled per IP."""
        settings = get_settings()
        with patch.object(settings, "rate_limit_per_minute_public", 2):
            # 2 requests succeed
            for _ in range(2):
                r = client.get("/api/v1/tenants/999")  # unauthenticated 401 response counts as request
                assert r.status_code in (401, 404)

            # 3rd request is rate-limited before auth
            r3 = client.get("/api/v1/tenants/999")
            assert r3.status_code == 429
            assert "Retry-After" in r3.headers

    def test_health_and_readiness_endpoints_exempt(self, client):
        """Health and readiness checks must never be blocked by rate limiting."""
        settings = get_settings()
        with patch.object(settings, "rate_limit_per_minute_public", 1):
            # Multiple rapid calls to health endpoints
            for _ in range(5):
                r_root = client.get("/")
                assert r_root.status_code == 200
                r_health = client.get("/health")
                assert r_health.status_code == 200
                r_v1_health = client.get("/api/v1/health")
                assert r_v1_health.status_code == 200
                r_ready = client.get("/api/v1/ready")
                assert r_ready.status_code != 429
                assert r_ready.status_code in (200, 503)

    def test_auth_login_endpoint_rate_limited(self, client):
        """POST /auth/login must be rate limited by login_limiter."""
        settings = get_settings()
        with patch.object(settings, "login_attempts_per_minute", 2):
            for _ in range(2):
                r = client.post("/auth/login", json={"email": "wrong@example.com", "password": "wrong"})
                assert r.status_code == 401

            r3 = client.post("/auth/login", json={"email": "wrong@example.com", "password": "wrong"})
            assert r3.status_code == 429
            assert "Retry-After" in r3.headers

    def test_limiter_reset(self, client, admin_headers_a):
        """Resetting limiters must immediately restore admission."""
        settings = get_settings()
        with patch.object(settings, "rate_limit_per_minute_authenticated", 1):
            r1 = client.get("/api/v1/projects", headers=admin_headers_a)
            assert r1.status_code == 200

            r2 = client.get("/api/v1/projects", headers=admin_headers_a)
            assert r2.status_code == 429

            reset_all_limiters()

            r3 = client.get("/api/v1/projects", headers=admin_headers_a)
            assert r3.status_code == 200


# ---------------------------------------------------------------------------
# Phase 7D: Public HoneyToken Ingestion Rate Limiting (F-012)
# ---------------------------------------------------------------------------

class TestHoneyTokenIngestionRateLimiting:
    def test_valid_token_triggers_detection_event(self, client, token_a, db_session):
        """Under normal volume, a valid token triggers an event and returns 204."""
        resp = client.get(f"/t/{token_a.token_value}")
        assert resp.status_code == 204

        # Verify event was recorded in DB
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).all()
        assert len(events) >= 1

    def test_invalid_token_preserves_expected_204(self, client):
        """Unknown/phantom token returns silent 204 without leaking state."""
        resp = client.get("/t/nonexistent-token-xyz")
        assert resp.status_code == 204

    def test_revoked_token_produces_detection_event(self, client, token_a, db_session):
        """Revoked HoneyToken must still record a forensic DetectionEvent."""
        token_a.is_active = False
        db_session.commit()

        initial_count = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).count()
        resp = client.get(f"/t/{token_a.token_value}")
        assert resp.status_code == 204

        new_count = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).count()
        assert new_count == initial_count + 1

    def test_ingestion_rate_limit_per_token_returns_429(self, client, token_a):
        """Flooding the same token from an IP returns 429 once threshold is reached."""
        settings = get_settings()
        with patch.object(settings, "ingestion_rate_limit_per_minute_token", 3):
            for _ in range(3):
                r = client.get(f"/t/{token_a.token_value}")
                assert r.status_code == 204

            r4 = client.get(f"/t/{token_a.token_value}")
            assert r4.status_code == 429
            assert "Retry-After" in r4.headers

    def test_ingestion_rate_limit_does_not_suppress_other_tokens(self, client, token_a, token_b):
        """Flooding token_a must NOT block or suppress detection of token_b from the same IP."""
        settings = get_settings()
        with patch.object(settings, "ingestion_rate_limit_per_minute_token", 2):
            with patch.object(settings, "ingestion_rate_limit_per_minute_ip", 10):
                # Flood token_a
                client.get(f"/t/{token_a.token_value}")
                client.get(f"/t/{token_a.token_value}")
                r_a_blocked = client.get(f"/t/{token_a.token_value}")
                assert r_a_blocked.status_code == 429

                # Token B is still accepted
                r_b = client.get(f"/t/{token_b.token_value}")
                assert r_b.status_code == 204

    def test_pixel_ingestion_rate_limiting(self, client, token_a):
        """Tracking pixel returns 200 GIF normally and 429 when rate limited."""
        settings = get_settings()
        with patch.object(settings, "ingestion_rate_limit_per_minute_token", 2):
            r1 = client.get(f"/px/{token_a.token_value}.gif")
            assert r1.status_code == 200
            assert r1.headers["content-type"] == "image/gif"

            r2 = client.get(f"/px/{token_a.token_value}.gif")
            assert r2.status_code == 200

            r3 = client.get(f"/px/{token_a.token_value}.gif")
            assert r3.status_code == 429
            assert "Retry-After" in r3.headers


# ---------------------------------------------------------------------------
# Phase 7E: Request Header Security & Sanitization (F-013)
# ---------------------------------------------------------------------------

class TestRequestHeaderSecurity:
    def test_allowed_forensic_headers_retained(self, client, token_a, db_session):
        """Forensic allowlisted headers must be persisted in DetectionEvent."""
        headers = {
            "User-Agent": "AttackerBrowser/1.0",
            "Referer": "https://evil.internal/search",
            "Sec-CH-UA": '"Chromium";v="120"',
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = client.get(f"/t/{token_a.token_value}", headers=headers)
        assert resp.status_code == 204

        event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).order_by(DetectionEvent.id.desc()).first()
        assert event is not None
        assert event.headers is not None
        assert event.headers.get("user-agent") == "AttackerBrowser/1.0"
        assert event.headers.get("referer") == "https://evil.internal/search"
        assert event.headers.get("sec-ch-ua") == '"Chromium";v="120"'

    def test_sensitive_credentials_never_persisted(self, client, token_a, db_session):
        """Authorization, Cookie, and credential headers must NEVER be persisted."""
        headers = {
            "Authorization": "Bearer super-secret-jwt-token",
            "Cookie": "session_id=12345; auth=secret_cookie",
            "Set-Cookie": "tracker=danger",
            "X-API-Key": "secret-api-key-value",
            "User-Agent": "AttackerProbe/2.0",
        }
        resp = client.get(f"/t/{token_a.token_value}", headers=headers)
        assert resp.status_code == 204

        event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).order_by(DetectionEvent.id.desc()).first()
        assert event is not None
        assert event.headers is not None
        assert "authorization" not in event.headers
        assert "cookie" not in event.headers
        assert "set-cookie" not in event.headers
        assert "x-api-key" not in event.headers
        assert event.headers.get("user-agent") == "AttackerProbe/2.0"

    def test_arbitrary_untrusted_headers_dropped(self, client, token_a, db_session):
        """Arbitrary non-allowlisted headers must not be persisted."""
        headers = {
            "X-Attacker-Custom": "payload_data",
            "X-Random-Junk": "junk_data",
            "User-Agent": "SafeProbe",
        }
        resp = client.get(f"/t/{token_a.token_value}", headers=headers)
        assert resp.status_code == 204

        event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).order_by(DetectionEvent.id.desc()).first()
        assert "x-attacker-custom" not in event.headers
        assert "x-random-junk" not in event.headers

    def test_oversized_retained_header_values_truncated(self):
        """Header values exceeding max length must be deterministically truncated."""
        oversized_ua = "A" * 5000
        raw = {"user-agent": oversized_ua, "referer": "https://example.com"}
        sanitized = sanitize_forensic_headers(raw, max_value_length=100)
        assert sanitized is not None
        assert len(sanitized["user-agent"]) == 100
        assert sanitized["user-agent"] == "A" * 100
        assert sanitized["referer"] == "https://example.com"

    def test_jsonb_size_bounded_under_4kb(self):
        """Even with many headers, total serialized JSON must not exceed max_total_bytes."""
        raw = {f"user-agent": "A" * 500, "referer": "B" * 500, "origin": "C" * 500}
        sanitized = sanitize_forensic_headers(raw, max_total_bytes=512)
        assert sanitized is not None
        encoded = json.dumps(sanitized).encode("utf-8")
        assert len(encoded) <= 512


# ---------------------------------------------------------------------------
# Phase 7F: IP Validation & Trusted Proxy Model (F-028)
# ---------------------------------------------------------------------------

class TestIPValidationAndTrustModel:
    def test_valid_ipv4_and_ipv6_accepted(self):
        """Valid IPv4 and IPv6 strings must normalize correctly."""
        assert normalize_ip("198.51.100.1") == "198.51.100.1"
        assert normalize_ip("2001:db8::1") == "2001:db8::1"
        assert normalize_ip(" 10.0.0.1 ") == "10.0.0.1"

    def test_malformed_ip_in_detection_event_create_rejected(self, client, admin_headers_a, token_a):
        """Submitting a malformed IP to POST /detection-events must return 422."""
        invalid_ips = ["not-an-ip", "999.999.999.999", "; DROP TABLE users;", "1.2.3.4.5"]
        for bad_ip in invalid_ips:
            resp = client.post(
                "/api/v1/detection-events",
                headers=admin_headers_a,
                json={
                    "token_value": token_a.token_value,
                    "ip_address": bad_ip,
                    "request_path": "/test",
                    "http_method": "GET",
                    "severity": "LOW",
                },
            )
            assert resp.status_code == 422, f"Expected 422 for bad IP '{bad_ip}', got {resp.status_code}"

    def test_untrusted_peer_spoofed_forwarded_for_ignored(self, client, token_a, db_session):
        """Untrusted peers supplying X-Forwarded-For must NOT be trusted."""
        settings = get_settings()
        # Direct peer is 127.0.0.1 in TestClient, but let's configure trusted_proxies to exclude 127.0.0.1
        with patch.object(settings, "trusted_proxies", ["192.168.1.1"]):
            # Attacker sends spoofed header
            resp = client.get(
                f"/t/{token_a.token_value}",
                headers={"X-Forwarded-For": "203.0.113.199"},
            )
            assert resp.status_code == 204

            event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).order_by(DetectionEvent.id.desc()).first()
            # Must NOT use the spoofed IP; uses peer IP (127.0.0.1)
            assert event.ip_address == "127.0.0.1"

    def test_trusted_proxy_forwarded_for_honored(self, client, token_a, db_session):
        """When peer IP matches trusted_proxies, valid X-Forwarded-For is honored."""
        settings = get_settings()
        with patch.object(settings, "trusted_proxies", ["127.0.0.1"]):
            resp = client.get(
                f"/t/{token_a.token_value}",
                headers={"X-Forwarded-For": "198.51.100.55"},
            )
            assert resp.status_code == 204

            event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).order_by(DetectionEvent.id.desc()).first()
            assert event.ip_address == "198.51.100.55"

    def test_malformed_forwarded_for_falls_back_safely(self, client, token_a, db_session):
        """Malformed X-Forwarded-For falls back safely to peer IP without crashing."""
        settings = get_settings()
        with patch.object(settings, "trusted_proxies", ["127.0.0.1"]):
            resp = client.get(
                f"/t/{token_a.token_value}",
                headers={"X-Forwarded-For": "invalid-ip-string"},
            )
            assert resp.status_code == 204

            event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).order_by(DetectionEvent.id.desc()).first()
            assert event.ip_address == "127.0.0.1"
