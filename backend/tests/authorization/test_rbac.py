"""RBAC authorization regression tests.

Verifies that role-based access control is enforced correctly at the API layer.

Roles under test:
  SYSTEM_ADMIN  — global access
  TENANT_ADMIN  — tenant-scoped management
  TENANT_USER   — read-only within their tenant
"""
from __future__ import annotations

import pytest

from tests.conftest import auth_headers


class TestSystemAdminAccess:
    """SYSTEM_ADMIN must reach all tenant-management operations."""

    def test_system_admin_can_list_tenants(self, client, system_admin, tenant_a, tenant_b):
        resp = client.get("/api/v1/tenants", headers=auth_headers(system_admin))
        assert resp.status_code == 200
        slugs = [t["slug"] for t in resp.json()]
        assert "tenant-a" in slugs
        assert "tenant-b" in slugs

    def test_system_admin_can_read_any_tenant(self, client, system_admin, tenant_b):
        resp = client.get(f"/api/v1/tenants/{tenant_b.slug}", headers=auth_headers(system_admin))
        assert resp.status_code == 200

    def test_system_admin_can_list_all_projects(self, client, system_admin, project_a, project_b):
        resp = client.get("/api/v1/projects", headers=auth_headers(system_admin))
        assert resp.status_code == 200
        domains = [p["domain"] for p in resp.json()]
        assert "alpha.example.com" in domains
        assert "beta.example.com" in domains


class TestTenantAdminAccess:
    """TENANT_ADMIN can manage their own tenant resources."""

    def test_tenant_admin_can_list_own_projects(self, client, admin_a, project_a):
        resp = client.get("/api/v1/projects", headers=auth_headers(admin_a))
        assert resp.status_code == 200
        domains = [p["domain"] for p in resp.json()]
        assert "alpha.example.com" in domains

    def test_tenant_admin_cannot_access_another_tenant(self, client, admin_a, tenant_b):
        """TENANT_ADMIN of Tenant A must not see Tenant B."""
        resp = client.get(f"/api/v1/tenants/{tenant_b.slug}", headers=auth_headers(admin_a))
        # Must be 404, not 200 or 403.
        assert resp.status_code == 404

    def test_tenant_admin_cannot_create_tenant(self, client, admin_a):
        """Only SYSTEM_ADMIN may create tenants."""
        resp = client.post(
            "/api/v1/tenants",
            json={"name": "Rogue Tenant", "slug": "rogue"},
            headers=auth_headers(admin_a),
        )
        assert resp.status_code == 403

    def test_tenant_admin_cannot_delete_another_tenant(self, client, admin_a, tenant_b):
        resp = client.delete(f"/api/v1/tenants/{tenant_b.slug}", headers=auth_headers(admin_a))
        assert resp.status_code in (403, 404)


class TestTenantUserAccess:
    """TENANT_USER has read-only access within their own tenant."""

    def test_tenant_user_can_list_own_projects(self, client, user_a, project_a):
        resp = client.get("/api/v1/projects", headers=auth_headers(user_a))
        assert resp.status_code == 200
        domains = [p["domain"] for p in resp.json()]
        assert "alpha.example.com" in domains

    def test_tenant_user_cannot_create_project(self, client, user_a, tenant_a):
        resp = client.post(
            "/api/v1/projects",
            json={"tenant_slug": tenant_a.slug, "name": "Rogue Project", "domain": "rogue.com"},
            headers=auth_headers(user_a),
        )
        assert resp.status_code == 403

    def test_tenant_user_cannot_delete_project(self, client, user_a, project_a):
        resp = client.delete(
            f"/api/v1/projects/{project_a.domain}",
            headers=auth_headers(user_a),
        )
        assert resp.status_code == 403

    def test_tenant_user_cannot_revoke_token(self, client, user_a, token_a):
        resp = client.post(
            "/api/v1/honey-tokens/revoke",
            json={"token_value": token_a.token_value},
            headers=auth_headers(user_a),
        )
        assert resp.status_code == 403
