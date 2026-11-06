from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.core.config import get_settings
from app.core.security import create_access_token, get_password_hash, verify_password
from app.models.enums import Role
from app.models.user import User
from tests.conftest import auth_headers


def test_role_is_enum_after_identity_map_is_cleared(db_session, admin_a):
    user_id = admin_a.id
    db_session.expunge_all()
    assert isinstance(db_session.get(User, user_id).role, Role)


def test_missing_exp_is_rejected(client, admin_a):
    token = jwt.encode({"sub": str(admin_a.id), "ver": 0}, get_settings().jwt_secret_key, algorithm="HS256")
    assert client.get("/api/v1/tenants", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_system_admin_cannot_be_bound_to_tenant(client, system_admin, tenant_a):
    response = client.patch(f"/api/v1/users/{system_admin.id}", headers=auth_headers(system_admin), json={"tenant_id": tenant_a.id})
    assert response.status_code == 409


def test_tenant_admin_cannot_target_corrupt_system_admin(client, db_session, admin_a, system_admin):
    # Simulate legacy corrupt storage, independently of the new DB constraint.
    db_session.execute(text("PRAGMA ignore_check_constraints=ON"))
    system_admin.tenant_id = admin_a.tenant_id
    db_session.flush()
    db_session.execute(text("PRAGMA ignore_check_constraints=OFF"))
    response = client.patch(f"/api/v1/users/{system_admin.id}", headers=auth_headers(admin_a), json={"password": "attacker-password"})
    assert response.status_code == 404


def test_null_tenant_user_cannot_be_persisted(db_session):
    db_session.add(User(email="invalid@example.org", role=Role.TENANT_USER, tenant_id=None, hashed_password="unused"))
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_inactive_tenant_denies_member_but_not_global_admin(client, db_session, tenant_a, admin_a, system_admin):
    tenant_a.is_active = False
    db_session.flush()
    assert client.get("/api/v1/users", headers=auth_headers(admin_a)).status_code == 401
    assert client.get("/api/v1/users", headers=auth_headers(system_admin)).status_code == 200


def test_password_reset_invalidates_old_token(client, admin_a):
    old_headers = auth_headers(admin_a)
    assert client.patch(f"/api/v1/users/{admin_a.id}", headers=old_headers, json={"password": "replacement-password"}).status_code == 200
    assert client.get("/api/v1/users", headers=old_headers).status_code == 401
    login = client.post("/auth/login", json={"email": admin_a.email, "password": "replacement-password"})
    assert login.status_code == 200
    assert client.get("/api/v1/users", headers={"Authorization": "Bearer " + login.json()["access_token"]}).status_code == 200


@pytest.mark.parametrize("password", ["a" * 73, "é" * 37])
def test_password_utf8_over_limit_rejected(password):
    with pytest.raises(ValueError):
        get_password_hash(password)


def test_password_boundary_is_exact():
    hashed = get_password_hash("é" * 36)
    assert verify_password("é" * 36, hashed)
    assert not verify_password("é" * 36 + "x", hashed)


def test_login_rate_limit_at_http_boundary(client, monkeypatch):
    import importlib
    from app.core.rate_limit import FixedWindowLimiter
    router = importlib.import_module("app.api.auth.router")
    monkeypatch.setattr(router, "login_limiter", FixedWindowLimiter())
    monkeypatch.setattr(get_settings(), "login_attempts_per_minute", 2)
    body = {"email": "absent@example.org", "password": "wrong-password"}
    assert client.post("/auth/login", json=body).status_code == 401
    assert client.post("/auth/login", json=body).status_code == 401
    assert client.post("/auth/login", json=body).status_code == 429


def test_limiter_bounds_cardinality_and_resets():
    from app.core.rate_limit import FixedWindowLimiter
    now = [0]
    limiter = FixedWindowLimiter(max_keys=2, clock=lambda: now[0])
    assert limiter.allow("a", 2, 3)
    assert limiter.allow("b", 2, 3)
    assert not limiter.allow("c", 2, 3)
    assert limiter.allow("a", 2, 3)
    assert not limiter.allow("b", 2, 3)
    now[0] = 60
    assert limiter.allow("c", 2, 3)


def test_unknown_critical_jwt_header_is_rejected(client, admin_a):
    token = jwt.encode({"sub": str(admin_a.id), "ver": 0,
                        "exp": datetime.now(timezone.utc) + timedelta(minutes=1)},
                       get_settings().jwt_secret_key, algorithm="HS256",
                       headers={"crit": ["unsupported-policy"], "unsupported-policy": True})
    assert client.get("/api/v1/tenants", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_corrupt_null_tenant_user_cannot_open_global_stream(client, db_session, user_a):
    from starlette.websockets import WebSocketDisconnect
    db_session.execute(text("PRAGMA ignore_check_constraints=ON"))
    user_a.tenant_id = None
    db_session.flush()
    db_session.execute(text("PRAGMA ignore_check_constraints=OFF"))
    with pytest.raises(WebSocketDisconnect) as caught:
        with client.websocket_connect("/api/v1/events/stream/ws") as ws:
            ws.send_json({"type": "auth", "token": create_access_token(str(user_a.id))})
            ws.receive_json()
    assert caught.value.code == 1008
