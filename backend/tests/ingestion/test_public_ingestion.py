"""Public ingestion regression tests.

Verifies that the three public ingestion endpoints:
  GET  /t/{token_value}
  GET  /px/{token_value}.gif
  POST /collect/{token_value}

remain:
  1. Publicly accessible — no JWT required.
  2. Silently successful for valid tokens.
  3. Silently no-op for invalid/unknown tokens.
  4. Return stable, predictable responses that reveal no resource information.
"""
from __future__ import annotations

import pytest


class TestUrlIngestionEndpoint:
    def test_valid_token_no_auth_returns_204(self, client, token_a):
        """Valid token without any Authorization header must return 204."""
        resp = client.get(f"/t/{token_a.token_value}")
        assert resp.status_code == 204

    def test_invalid_token_no_auth_returns_204(self, client):
        """Unknown token must silently return 204 — not 404."""
        resp = client.get("/t/completely-unknown-token-value")
        assert resp.status_code == 204

    def test_url_endpoint_does_not_require_jwt(self, client, token_a):
        """No Authorization header must be needed."""
        resp = client.get(f"/t/{token_a.token_value}", headers={})
        assert resp.status_code == 204


class TestPixelIngestionEndpoint:
    def test_valid_pixel_token_returns_gif(self, client, token_a):
        resp = client.get(f"/px/{token_a.token_value}.gif")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "image/gif"
        # Must be the 43-byte transparent GIF
        assert len(resp.content) == 43

    def test_invalid_pixel_token_still_returns_gif(self, client):
        """Unknown pixel token must still return the transparent GIF — no 404."""
        resp = client.get("/px/phantom-token.gif")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "image/gif"

    def test_pixel_endpoint_does_not_require_jwt(self, client, token_a):
        resp = client.get(f"/px/{token_a.token_value}.gif", headers={})
        assert resp.status_code == 200


class TestCollectIngestionEndpoint:
    def test_valid_token_no_auth_returns_204(self, client, token_a):
        resp = client.post(f"/collect/{token_a.token_value}")
        assert resp.status_code == 204

    def test_invalid_token_returns_204(self, client):
        """Unknown token must silently return 204 — not 404."""
        resp = client.post("/collect/phantom-token-value")
        assert resp.status_code == 204

    def test_collect_endpoint_does_not_require_jwt(self, client, token_a):
        resp = client.post(f"/collect/{token_a.token_value}", headers={})
        assert resp.status_code == 204


class TestIngestionResponseSecurity:
    def test_invalid_token_does_not_leak_existence(self, client, token_b):
        """Ingestion for any token (valid cross-tenant or phantom) returns same 204.

        The ingestion endpoint must never distinguish between:
          - a token that exists in another tenant
          - a token that does not exist at all
        Both must return identical 204 responses.
        """
        # Tenant B token accessed without auth (cross-tenant ingestion path)
        resp_cross = client.get(f"/t/{token_b.token_value}")
        # Completely phantom token
        resp_phantom = client.get("/t/absolutely-does-not-exist")
        assert resp_cross.status_code == resp_phantom.status_code == 204
