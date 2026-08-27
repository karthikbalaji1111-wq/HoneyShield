import pytest

from app.models.enums import Role
from app.models.user import User

def auth_headers(user: User) -> dict[str, str]:
    from app.core.security import create_access_token
    token = create_access_token(subject=user.id)
    return {"Authorization": f"Bearer {token}"}

class TestUserManagement:
    def test_unauthenticated_request_returns_401(self, client):
        resp = client.get("/api/v1/users")
        assert resp.status_code == 401

    def test_tenant_user_denied(self, client, user_a):
        resp = client.get("/api/v1/users", headers=auth_headers(user_a))
        assert resp.status_code == 403

    def test_system_admin_list_global(self, client, system_admin, admin_a, admin_b):
        resp = client.get("/api/v1/users", headers=auth_headers(system_admin))
        assert resp.status_code == 200
        emails = [u["email"] for u in resp.json()]
        assert system_admin.email in emails
        assert admin_a.email in emails
        assert admin_b.email in emails

    def test_tenant_admin_list_own_tenant(self, client, admin_a, admin_b, user_a):
        resp = client.get("/api/v1/users", headers=auth_headers(admin_a))
        assert resp.status_code == 200
        emails = [u["email"] for u in resp.json()]
        assert admin_a.email in emails
        assert user_a.email in emails
        assert admin_b.email not in emails

    def test_tenant_admin_cannot_read_another_tenant_user(self, client, admin_a, admin_b):
        resp = client.get(f"/api/v1/users/{admin_b.id}", headers=auth_headers(admin_a))
        assert resp.status_code == 404
        
    def test_cross_tenant_query_masks_existence(self, client, admin_a, admin_b):
        resp1 = client.get(f"/api/v1/users/{admin_b.id}", headers=auth_headers(admin_a))
        resp2 = client.get("/api/v1/users/999999", headers=auth_headers(admin_a))
        assert resp1.status_code == 404
        assert resp2.status_code == 404
        assert resp1.json()["detail"] == resp2.json()["detail"]

    def test_system_admin_create_any(self, client, system_admin, tenant_b):
        payload = {
            "email": "new_sys_user@test.com",
            "password": "Password123!",
            "role": Role.TENANT_ADMIN,
            "tenant_id": tenant_b.id
        }
        resp = client.post("/api/v1/users", json=payload, headers=auth_headers(system_admin))
        assert resp.status_code == 201
        assert resp.json()["email"] == payload["email"]
        assert resp.json()["tenant_id"] == tenant_b.id
        assert "hashed_password" not in resp.json()
        assert "password" not in resp.json()

    def test_tenant_admin_create_own_tenant(self, client, admin_a, tenant_a):
        payload = {
            "email": "new_tenant_user@test.com",
            "password": "Password123!",
            "role": Role.TENANT_USER
        }
        resp = client.post("/api/v1/users", json=payload, headers=auth_headers(admin_a))
        assert resp.status_code == 201
        assert resp.json()["email"] == payload["email"]
        assert resp.json()["tenant_id"] == tenant_a.id

    def test_tenant_admin_cannot_create_system_admin(self, client, admin_a):
        payload = {
            "email": "evil_sys_admin@test.com",
            "password": "Password123!",
            "role": Role.SYSTEM_ADMIN
        }
        resp = client.post("/api/v1/users", json=payload, headers=auth_headers(admin_a))
        assert resp.status_code == 409

    def test_tenant_admin_cannot_create_in_another_tenant(self, client, admin_a, tenant_b):
        payload = {
            "email": "evil_cross_tenant@test.com",
            "password": "Password123!",
            "role": Role.TENANT_USER,
            "tenant_id": tenant_b.id
        }
        resp = client.post("/api/v1/users", json=payload, headers=auth_headers(admin_a))
        assert resp.status_code == 409
        
    def test_duplicate_email(self, client, admin_a):
        payload = {
            "email": admin_a.email,
            "password": "Password123!",
            "role": Role.TENANT_USER
        }
        resp = client.post("/api/v1/users", json=payload, headers=auth_headers(admin_a))
        assert resp.status_code == 409

    def test_tenant_admin_cannot_move_user_between_tenants(self, client, admin_a, user_a, tenant_b):
        payload = {
            "tenant_id": tenant_b.id
        }
        resp = client.patch(f"/api/v1/users/{user_a.id}", json=payload, headers=auth_headers(admin_a))
        assert resp.status_code == 409
        
    def test_tenant_admin_cannot_update_another_tenant_user(self, client, admin_a, admin_b):
        payload = {
            "is_active": False
        }
        resp = client.patch(f"/api/v1/users/{admin_b.id}", json=payload, headers=auth_headers(admin_a))
        assert resp.status_code == 404

    def test_tenant_admin_cannot_deactivate_another_tenant_user(self, client, admin_a, admin_b):
        resp = client.post(f"/api/v1/users/{admin_b.id}/deactivate", headers=auth_headers(admin_a))
        assert resp.status_code == 404
        
    def test_deactivated_user_cannot_authenticate(self, client, admin_a, user_a):
        # 1. Deactivate
        resp = client.post(f"/api/v1/users/{user_a.id}/deactivate", headers=auth_headers(admin_a))
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False
        
        # 2. Authenticate
        resp2 = client.get("/api/v1/users", headers=auth_headers(user_a))
        assert resp2.status_code == 401
