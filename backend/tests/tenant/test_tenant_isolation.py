"""Tenant isolation regression tests.

Verifies that authenticated users from Tenant A cannot access, enumerate,
or modify resources belonging to Tenant B.

Key invariants:
  1. Cross-tenant read → 404 (not 403, not 200)
  2. Cross-tenant write → 404 (not 403, not 200)
  3. Cross-tenant list → only own-tenant results returned (empty, not 403)
  4. SYSTEM_ADMIN → 200 for all tenants
"""
from __future__ import annotations

import pytest

from tests.conftest import auth_headers


# ---------------------------------------------------------------------------
# Tenant slug enumeration
# ---------------------------------------------------------------------------

class TestTenantSlugIsolation:
    def test_tenant_a_cannot_read_tenant_b(self, client, admin_a, tenant_b):
        """Cross-tenant read must return 404, not 403."""
        resp = client.get(f"/api/v1/tenants/{tenant_b.slug}", headers=auth_headers(admin_a))
        assert resp.status_code == 404

    def test_tenant_a_nonexistent_slug_returns_404(self, client, admin_a):
        resp = client.get("/api/v1/tenants/does-not-exist", headers=auth_headers(admin_a))
        assert resp.status_code == 404

    def test_cross_tenant_and_nonexistent_are_indistinguishable(self, client, admin_a, tenant_b):
        """Tenant B slug and a random slug must both return 404 — same status."""
        resp_cross = client.get(f"/api/v1/tenants/{tenant_b.slug}", headers=auth_headers(admin_a))
        resp_missing = client.get("/api/v1/tenants/no-such-slug", headers=auth_headers(admin_a))
        assert resp_cross.status_code == 404
        assert resp_missing.status_code == 404

    def test_system_admin_can_read_any_tenant(self, client, system_admin, tenant_b):
        resp = client.get(f"/api/v1/tenants/{tenant_b.slug}", headers=auth_headers(system_admin))
        assert resp.status_code == 200
        assert resp.json()["slug"] == "tenant-b"

    def test_tenant_list_scoped_to_own_tenant(self, client, admin_a, tenant_a, tenant_b):
        """Non-admin list must only return own tenant."""
        resp = client.get("/api/v1/tenants", headers=auth_headers(admin_a))
        assert resp.status_code == 200
        slugs = [t["slug"] for t in resp.json()]
        assert "tenant-a" in slugs
        assert "tenant-b" not in slugs


# ---------------------------------------------------------------------------
# Project domain enumeration
# ---------------------------------------------------------------------------

class TestProjectIsolation:
    def test_tenant_a_cannot_read_tenant_b_project(self, client, admin_a, project_b):
        """Cross-tenant project read must return 404, not 403."""
        resp = client.get(f"/api/v1/projects/{project_b.domain}", headers=auth_headers(admin_a))
        assert resp.status_code == 404

    def test_tenant_a_nonexistent_project_returns_404(self, client, admin_a):
        resp = client.get("/api/v1/projects/no-such-domain.com", headers=auth_headers(admin_a))
        assert resp.status_code == 404

    def test_cross_tenant_project_and_nonexistent_indistinguishable(self, client, admin_a, project_b):
        resp_cross = client.get(f"/api/v1/projects/{project_b.domain}", headers=auth_headers(admin_a))
        resp_missing = client.get("/api/v1/projects/phantom.com", headers=auth_headers(admin_a))
        assert resp_cross.status_code == 404
        assert resp_missing.status_code == 404

    def test_tenant_a_cannot_delete_tenant_b_project(self, client, admin_a, project_b):
        resp = client.delete(f"/api/v1/projects/{project_b.domain}", headers=auth_headers(admin_a))
        assert resp.status_code == 404

    def test_project_list_scoped_to_own_tenant(self, client, admin_a, project_a, project_b):
        resp = client.get("/api/v1/projects", headers=auth_headers(admin_a))
        assert resp.status_code == 200
        domains = [p["domain"] for p in resp.json()]
        assert "alpha.example.com" in domains
        assert "beta.example.com" not in domains

    def test_system_admin_sees_all_projects(self, client, system_admin, project_a, project_b):
        resp = client.get("/api/v1/projects", headers=auth_headers(system_admin))
        assert resp.status_code == 200
        domains = [p["domain"] for p in resp.json()]
        assert "alpha.example.com" in domains
        assert "beta.example.com" in domains

    def test_tenant_a_cannot_create_project_under_tenant_b(self, client, admin_a, tenant_b):
        resp = client.post(
            "/api/v1/projects",
            json={"tenant_slug": tenant_b.slug, "name": "Rogue", "domain": "rogue.example.com"},
            headers=auth_headers(admin_a),
        )
        # Cross-tenant create must be denied — 404 (tenant masked) not 200
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Honey token enumeration
# ---------------------------------------------------------------------------

class TestHoneyTokenIsolation:
    def test_tenant_a_cannot_list_tenant_b_tokens(self, client, admin_a, token_a, token_b):
        """Token list must not include Tenant B tokens."""
        resp = client.get("/api/v1/honey-tokens", headers=auth_headers(admin_a))
        assert resp.status_code == 200
        values = [t["token_value"] for t in resp.json()]
        assert "token-alpha-secret-value" in values
        assert "token-beta-secret-value" not in values

    def test_system_admin_sees_all_tokens(self, client, system_admin, token_a, token_b):
        resp = client.get("/api/v1/honey-tokens", headers=auth_headers(system_admin))
        assert resp.status_code == 200
        values = [t["token_value"] for t in resp.json()]
        assert "token-alpha-secret-value" in values
        assert "token-beta-secret-value" in values

    def test_tenant_a_cannot_revoke_tenant_b_token(self, client, admin_a, token_b):
        resp = client.post(
            "/api/v1/honey-tokens/revoke",
            json={"token_value": token_b.token_value},
            headers=auth_headers(admin_a),
        )
        assert resp.status_code == 404

    def test_nonexistent_token_revoke_returns_404(self, client, admin_a):
        resp = client.post(
            "/api/v1/honey-tokens/revoke",
            json={"token_value": "phantom-token-value"},
            headers=auth_headers(admin_a),
        )
        assert resp.status_code == 404

    def test_cross_tenant_and_nonexistent_token_indistinguishable(self, client, admin_a, token_b):
        """Tenant B token and a phantom token must both return 404."""
        resp_cross = client.post(
            "/api/v1/honey-tokens/revoke",
            json={"token_value": token_b.token_value},
            headers=auth_headers(admin_a),
        )
        resp_phantom = client.post(
            "/api/v1/honey-tokens/revoke",
            json={"token_value": "totally-random-phantom-value"},
            headers=auth_headers(admin_a),
        )
        assert resp_cross.status_code == 404
        assert resp_phantom.status_code == 404

    def test_tenant_a_cannot_rotate_tenant_b_token(self, client, admin_a, token_b):
        resp = client.post(
            "/api/v1/honey-tokens/rotate",
            json={"old_token_value": token_b.token_value, "new_token_value": "hijack-attempt"},
            headers=auth_headers(admin_a),
        )
        assert resp.status_code == 404

    def test_tenant_a_cannot_generate_token_for_tenant_b_project(self, client, admin_a, project_b):
        resp = client.post(
            f"/api/v1/projects/{project_b.domain}/honey-tokens/generate",
            json={"token_type": "API_KEY"},
            headers=auth_headers(admin_a),
        )
        assert resp.status_code == 404

    def test_tenant_a_cannot_filter_tokens_by_tenant_b_project(self, client, admin_a, project_b):
        resp = client.get(
            f"/api/v1/honey-tokens?project_domain={project_b.domain}",
            headers=auth_headers(admin_a),
        )
        assert resp.status_code == 404



# ---------------------------------------------------------------------------
# Detection event isolation
# ---------------------------------------------------------------------------

class TestDetectionEventIsolation:
    def test_tenant_a_cannot_record_event_for_tenant_b_token(self, client, admin_a, token_b):
        """Cross-tenant administrative event recording must be denied with 404."""
        resp = client.post(
            "/api/v1/detection-events",
            json={
                "token_value": token_b.token_value,
                "ip_address": "198.51.100.1",
                "request_path": "/admin",
                "http_method": "GET",
                "severity": "HIGH",
            },
            headers=auth_headers(admin_a),
        )
        assert resp.status_code == 404

    def test_system_admin_can_record_event_for_any_token(self, client, system_admin, token_b):
        """SYSTEM_ADMIN can administratively record events for any token."""
        resp = client.post(
            "/api/v1/detection-events",
            json={
                "token_value": token_b.token_value,
                "ip_address": "198.51.100.2",
                "request_path": "/api/v1/admin",
                "http_method": "POST",
                "severity": "CRITICAL",
            },
            headers=auth_headers(system_admin),
        )
        assert resp.status_code == 201
        assert resp.json()["ip_address"] == "198.51.100.2"

    def test_detection_event_listing_scopes_to_own_tenant(self, client, admin_a, admin_b, token_a, token_b, system_admin):
        """Tenant A listing must only contain Tenant A events, not Tenant B."""
        # Record 1 event for Tenant A and 1 event for Tenant B via system admin
        client.post(
            "/api/v1/detection-events",
            json={"token_value": token_a.token_value, "ip_address": "10.0.0.1", "request_path": "/a", "http_method": "GET", "severity": "LOW"},
            headers=auth_headers(system_admin),
        )
        client.post(
            "/api/v1/detection-events",
            json={"token_value": token_b.token_value, "ip_address": "10.0.0.2", "request_path": "/b", "http_method": "GET", "severity": "LOW"},
            headers=auth_headers(system_admin),
        )

        resp_a = client.get("/api/v1/detection-events", headers=auth_headers(admin_a))
        assert resp_a.status_code == 200
        events_a = resp_a.json()
        assert all(e["ip_address"] == "10.0.0.1" for e in events_a)
        assert not any(e["ip_address"] == "10.0.0.2" for e in events_a)

        resp_b = client.get("/api/v1/detection-events", headers=auth_headers(admin_b))
        assert resp_b.status_code == 200
        events_b = resp_b.json()
        assert all(e["ip_address"] == "10.0.0.2" for e in events_b)
        assert not any(e["ip_address"] == "10.0.0.1" for e in events_b)

        # System admin sees both
        resp_sa = client.get("/api/v1/detection-events", headers=auth_headers(system_admin))
        assert resp_sa.status_code == 200
        ips = {e["ip_address"] for e in resp_sa.json()}
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    def test_statistics_and_count_today_scope_to_own_tenant(self, client, admin_a, admin_b, token_a, token_b, system_admin):
        """Statistics and today counts must strictly count only the authenticated tenant's events."""
        # Create 2 events for Tenant A and 1 event for Tenant B
        client.post(
            "/api/v1/detection-events",
            json={"token_value": token_a.token_value, "ip_address": "10.1.1.1", "request_path": "/1", "http_method": "GET", "severity": "LOW"},
            headers=auth_headers(system_admin),
        )
        client.post(
            "/api/v1/detection-events",
            json={"token_value": token_a.token_value, "ip_address": "10.1.1.2", "request_path": "/2", "http_method": "GET", "severity": "LOW"},
            headers=auth_headers(system_admin),
        )
        client.post(
            "/api/v1/detection-events",
            json={"token_value": token_b.token_value, "ip_address": "10.1.1.3", "request_path": "/3", "http_method": "GET", "severity": "LOW"},
            headers=auth_headers(system_admin),
        )

        # Tenant A stats
        stats_a = client.get("/api/v1/detection-events/statistics", headers=auth_headers(admin_a)).json()
        assert stats_a["total_events"] == 2
        assert stats_a["today_events"] == 2

        # Tenant B stats
        stats_b = client.get("/api/v1/detection-events/statistics", headers=auth_headers(admin_b)).json()
        assert stats_b["total_events"] == 1
        assert stats_b["today_events"] == 1

        # SYSTEM_ADMIN stats sees global total (3)
        stats_sa = client.get("/api/v1/detection-events/statistics", headers=auth_headers(system_admin)).json()
        assert stats_sa["total_events"] == 3
        assert stats_sa["today_events"] == 3
