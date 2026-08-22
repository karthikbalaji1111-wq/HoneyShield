"""Authentication regression tests.

Verifies:
  - Valid JWT is accepted and resolves the correct user.
  - Missing Authorization header returns 401.
  - Malformed bearer token returns 401.
  - Expired JWT returns 401.
  - JWT for a non-existent user returns 404 (UserNotFoundError → 404).
  - Inactive user account returns 401.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.core.security import create_access_token

from tests.conftest import auth_headers


# Any protected endpoint works; use GET /api/v1/tenants as the probe.
_PROTECTED = "/api/v1/tenants"


class TestAuthenticationAccepted:
    def test_valid_jwt_accepted(self, client, admin_a):
        """A valid JWT returns 200, not 401/403."""
        resp = client.get(_PROTECTED, headers=auth_headers(admin_a))
        assert resp.status_code == 200

    def test_system_admin_jwt_accepted(self, client, system_admin):
        resp = client.get(_PROTECTED, headers=auth_headers(system_admin))
        assert resp.status_code == 200


class TestAuthenticationRejected:
    def test_missing_authorization_header_returns_401(self, client, tenant_a):
        resp = client.get(_PROTECTED)
        assert resp.status_code == 401

    def test_malformed_bearer_prefix_returns_401(self, client):
        resp = client.get(_PROTECTED, headers={"Authorization": "Token abc123"})
        assert resp.status_code == 401

    def test_garbage_token_returns_401(self, client):
        resp = client.get(_PROTECTED, headers={"Authorization": "Bearer not.a.jwt"})
        assert resp.status_code == 401

    def test_expired_token_returns_401(self, client, admin_a):
        expired = create_access_token(subject=str(admin_a.id), expires_delta=timedelta(seconds=-1))
        resp = client.get(_PROTECTED, headers={"Authorization": f"Bearer {expired}"})
        assert resp.status_code == 401

    def test_nonexistent_user_id_in_jwt_returns_404(self, client):
        """JWT with a user_id that has no DB row must not succeed."""
        ghost_token = create_access_token(subject="999999")
        resp = client.get(_PROTECTED, headers={"Authorization": f"Bearer {ghost_token}"})
        assert resp.status_code == 404

    def test_inactive_user_returns_401(self, client, inactive_user):
        """Disabled accounts must be rejected even with a valid JWT."""
        resp = client.get(_PROTECTED, headers=auth_headers(inactive_user))
        assert resp.status_code == 401


class TestJwtPayloadStructure:
    def test_jwt_contains_only_sub_and_exp(self, admin_a):
        """JWT payload must contain only 'sub' and 'exp' — no roles, no tenant_id."""
        import jwt as pyjwt
        from app.core.config import get_settings
        settings = get_settings()
        token = create_access_token(subject=str(admin_a.id))
        payload = pyjwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        assert set(payload.keys()) == {"sub", "exp"}
        assert payload["sub"] == str(admin_a.id)
