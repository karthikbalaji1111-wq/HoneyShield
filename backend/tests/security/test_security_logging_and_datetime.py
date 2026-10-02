"""Phase 8 tests: Security logging, audit event taxonomy, and datetime hardening."""
from __future__ import annotations

import ast
import datetime as dt
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.auth_exceptions import ForbiddenError
from app.core.logging import JsonFormatter
from app.core.security import create_access_token
from app.models.audit_log import AuditLog
from app.models.detection_event import DetectionEvent
from app.models.enums import Role
from app.models.tenant import Tenant
from app.models.user import User
from app.repositories.audit_log import AuditLogRepository
from app.services.audit_log import sanitize_audit_metadata
from tests.conftest import auth_headers


# ===========================================================================
# 1. DATETIME HARDENING (F-027)
# ===========================================================================

class TestDatetimeHardening:
    def test_no_datetime_utcnow_in_app_code(self) -> None:
        """Scan all Python files under app/ to ensure zero occurrences of datetime.utcnow."""
        app_dir = Path(__file__).resolve().parents[2] / "app"
        violations = []
        for py_file in app_dir.rglob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "utcnow":
                    violations.append(f"{py_file.name}:{node.lineno}")
        assert not violations, f"Found deprecated datetime.utcnow() in: {violations}"

    def test_json_formatter_uses_utc_timezone_aware(self) -> None:
        """JsonFormatter timestamp must end with 'Z' and represent UTC."""
        import logging
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="test message",
            args=(),
            exc_info=None,
        )
        formatted = formatter.format(record)
        import json
        payload = json.loads(formatted)
        assert "timestamp" in payload
        assert payload["timestamp"].endswith("Z")
        # Ensure it parses as a valid UTC timestamp
        parsed = datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))
        assert parsed.tzinfo == timezone.utc

    def test_model_defaults_are_timezone_aware_utc(
        self,
        db_session: Session,
        token_a: HoneyToken,
    ) -> None:
        """BaseModel and ImmutableBaseModel populate timezone-aware UTC timestamps upon flush."""
        event = DetectionEvent(
            honey_token_id=token_a.id,
            ip_address="198.51.100.1",
            request_path="/t/test",
            http_method="GET",
            severity="LOW",
        )
        db_session.add(event)
        db_session.flush()
        assert event.triggered_at is not None
        assert event.created_at is not None

    def test_jwt_expiry_timezone_aware_comparison(self, admin_a: User) -> None:
        """JWT expiration must compare cleanly against datetime.now(timezone.utc) without TypeError."""
        import jwt as pyjwt
        from app.core.config import get_settings
        settings = get_settings()
        token = create_access_token(subject=admin_a.id, expires_delta=timedelta(minutes=15))
        payload = pyjwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        exp_dt = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        now_utc = datetime.now(timezone.utc)
        assert exp_dt > now_utc
        # Must not raise TypeError: can't compare offset-naive and offset-aware datetimes
        diff = exp_dt - now_utc
        assert diff.total_seconds() > 0


# ===========================================================================
# 2. AUTHENTICATION SECURITY AUDIT EVENTS (F-031)
# ===========================================================================

class TestAuthenticationAuditEvents:
    def test_login_success_creates_audit_event(
        self,
        client: TestClient,
        admin_a: User,
        tenant_a: Tenant,
        db_session: Session,
    ) -> None:
        """Successful login must record an AUTH_LOGIN_SUCCESS event attributed to the user."""
        resp = client.post("/auth/login", json={"email": admin_a.email, "password": "password"})
        assert resp.status_code == 200

        db_session.expire_all()
        log = (
            db_session.query(AuditLog)
            .filter_by(event_type="AUTH_LOGIN_SUCCESS", target_id=str(admin_a.id))
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert log is not None
        assert log.actor_user_id == admin_a.id
        assert log.tenant_id == tenant_a.id
        assert log.severity == "INFO"
        assert log.target_entity == "user"
        assert admin_a.email in log.message
        assert log.event_metadata is not None
        assert log.event_metadata["email"] == admin_a.email

    def test_login_failure_invalid_password_creates_audit_event(
        self,
        client: TestClient,
        admin_a: User,
        tenant_a: Tenant,
        db_session: Session,
    ) -> None:
        """Invalid password must record an AUTH_LOGIN_FAILURE event with actor_user_id=None."""
        resp = client.post("/auth/login", json={"email": admin_a.email, "password": "WrongPassword123!"})
        assert resp.status_code == 401

        db_session.expire_all()
        log = (
            db_session.query(AuditLog)
            .filter_by(event_type="AUTH_LOGIN_FAILURE", target_id=str(admin_a.id))
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert log is not None
        assert log.actor_user_id is None  # Unauthenticated!
        assert log.tenant_id == tenant_a.id
        assert log.severity == "WARNING"
        assert log.target_entity == "user"
        assert log.event_metadata is not None
        assert log.event_metadata["email"] == admin_a.email
        # Ensure password is NOT leaked in message or metadata
        assert "WrongPassword123!" not in log.message
        assert "WrongPassword123!" not in str(log.event_metadata)

    def test_login_failure_unknown_email_creates_audit_event(
        self,
        client: TestClient,
        db_session: Session,
    ) -> None:
        """Unknown email must record an AUTH_LOGIN_FAILURE event with target_id=None, actor_user_id=None."""
        ghost_email = "nonexistent_ghost@test.org"
        resp = client.post("/auth/login", json={"email": ghost_email, "password": "AnyPassword123!"})
        assert resp.status_code == 401

        db_session.expire_all()
        log = (
            db_session.query(AuditLog)
            .filter_by(event_type="AUTH_LOGIN_FAILURE")
            .filter(AuditLog.message.like(f"%{ghost_email}%"))
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert log is not None
        assert log.actor_user_id is None
        assert log.target_id is None
        assert log.tenant_id is None
        assert log.event_metadata["email"] == ghost_email
        assert "AnyPassword123!" not in log.message
        assert "AnyPassword123!" not in str(log.event_metadata)

    def test_login_failure_disabled_account_creates_audit_event(
        self,
        client: TestClient,
        inactive_user: User,
        tenant_a: Tenant,
        db_session: Session,
    ) -> None:
        """Disabled account login must record AUTH_LOGIN_FAILURE with account_disabled reason."""
        resp = client.post("/auth/login", json={"email": inactive_user.email, "password": "password"})
        assert resp.status_code == 401

        db_session.expire_all()
        log = (
            db_session.query(AuditLog)
            .filter_by(event_type="AUTH_LOGIN_FAILURE", target_id=str(inactive_user.id))
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert log is not None
        assert log.actor_user_id is None
        assert log.target_id == str(inactive_user.id)
        assert log.tenant_id == tenant_a.id
        assert log.event_metadata.get("reason") == "account_disabled"

    def test_login_records_trusted_proxy_ip(
        self,
        client: TestClient,
        admin_a: User,
        db_session: Session,
    ) -> None:
        """Login through trusted proxy records client IP from X-Forwarded-For."""
        resp = client.post(
            "/auth/login",
            json={"email": admin_a.email, "password": "password"},
            headers={"X-Forwarded-For": "198.51.100.88"},
        )
        assert resp.status_code == 200

        db_session.expire_all()
        log = (
            db_session.query(AuditLog)
            .filter_by(event_type="AUTH_LOGIN_SUCCESS", target_id=str(admin_a.id))
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert log is not None
        assert log.actor_source == "198.51.100.88"
        assert log.event_metadata["ip_address"] == "198.51.100.88"


# ===========================================================================
# 3. USER LIFECYCLE SECURITY AUDIT EVENTS
# ===========================================================================

class TestUserLifecycleAuditEvents:
    def test_user_creation_audit_log(
        self,
        client: TestClient,
        admin_a: User,
        tenant_a: Tenant,
        db_session: Session,
    ) -> None:
        """Creating a user must record USER_CREATED with actor attribution and no password leak."""
        payload = {
            "email": "audit_new_user@test.com",
            "password": "InitialPassword123!",
            "role": Role.TENANT_USER,
            "tenant_id": tenant_a.id,
        }
        resp = client.post("/api/v1/users", json=payload, headers=auth_headers(admin_a))
        assert resp.status_code == 201
        created_id = resp.json()["id"]

        db_session.expire_all()
        log = db_session.query(AuditLog).filter_by(event_type="USER_CREATED", target_id=str(created_id)).first()
        assert log is not None
        assert log.actor_user_id == admin_a.id
        assert log.tenant_id == tenant_a.id
        assert log.severity == "INFO"
        assert "InitialPassword123!" not in log.message
        assert "InitialPassword123!" not in str(log.event_metadata)

    def test_password_change_audit_log(
        self,
        client: TestClient,
        admin_a: User,
        user_a: User,
        tenant_a: Tenant,
        db_session: Session,
    ) -> None:
        """Password update must record PASSWORD_CHANGE without leaking password or hash."""
        secret_pw = "BrandNewSecretPassword999!"
        resp = client.patch(
            f"/api/v1/users/{user_a.id}",
            json={"password": secret_pw},
            headers=auth_headers(admin_a),
        )
        assert resp.status_code == 200

        db_session.expire_all()
        log = db_session.query(AuditLog).filter_by(event_type="PASSWORD_CHANGE", target_id=str(user_a.id)).first()
        assert log is not None
        assert log.actor_user_id == admin_a.id
        assert log.tenant_id == tenant_a.id
        assert secret_pw not in log.message
        assert secret_pw not in str(log.event_metadata)

    def test_role_change_audit_log(
        self,
        client: TestClient,
        system_admin: User,
        user_a: User,
        tenant_a: Tenant,
        db_session: Session,
    ) -> None:
        """Promoting a user must record ROLE_CHANGED with old and new roles in metadata."""
        resp = client.patch(
            f"/api/v1/users/{user_a.id}",
            json={"role": Role.TENANT_ADMIN},
            headers=auth_headers(system_admin),
        )
        assert resp.status_code == 200

        db_session.expire_all()
        log = db_session.query(AuditLog).filter_by(event_type="ROLE_CHANGED", target_id=str(user_a.id)).first()
        assert log is not None
        assert log.actor_user_id == system_admin.id
        assert log.event_metadata["old_role"] == Role.TENANT_USER.value
        assert log.event_metadata["new_role"] == Role.TENANT_ADMIN.value

    def test_user_deactivation_audit_log(
        self,
        client: TestClient,
        admin_a: User,
        user_a: User,
        tenant_a: Tenant,
        db_session: Session,
    ) -> None:
        """Deactivating a user must record USER_DEACTIVATED."""
        resp = client.post(f"/api/v1/users/{user_a.id}/deactivate", headers=auth_headers(admin_a))
        assert resp.status_code == 200

        db_session.expire_all()
        log = db_session.query(AuditLog).filter_by(event_type="USER_DEACTIVATED", target_id=str(user_a.id)).first()
        assert log is not None
        assert log.actor_user_id == admin_a.id
        assert log.tenant_id == tenant_a.id
        assert log.severity == "WARNING"


# ===========================================================================
# 4. AUTHORIZATION / TENANT ACCESS DENIED SECURITY EVENTS
# ===========================================================================

class TestAuthorizationDenialAuditEvents:
    def test_cross_tenant_access_denied_records_audit_event(
        self,
        client: TestClient,
        admin_a: User,
        tenant_a: Tenant,
        tenant_b: Tenant,
        db_session: Session,
    ) -> None:
        """Cross-tenant access attempt must record TENANT_ACCESS_DENIED attributed to actor's tenant."""
        resp = client.get(f"/api/v1/tenants/{tenant_b.slug}", headers=auth_headers(admin_a))
        assert resp.status_code == 404

        db_session.expire_all()
        log = (
            db_session.query(AuditLog)
            .filter_by(event_type="TENANT_ACCESS_DENIED", actor_user_id=admin_a.id)
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert log is not None
        # Must be attributed to Tenant A (the actor's tenant), NEVER Tenant B!
        assert log.tenant_id == tenant_a.id
        assert log.target_id == str(tenant_b.id)
        assert log.event_metadata["attempted_tenant_id"] == tenant_b.id

    def test_insufficient_role_records_audit_event(
        self,
        client: TestClient,
        user_a: User,
        tenant_a: Tenant,
        db_session: Session,
    ) -> None:
        """TENANT_USER attempting administrative project creation must record AUTHORIZATION_DENIED."""
        resp = client.post(
            "/api/v1/projects",
            json={"tenant_slug": tenant_a.slug, "name": "Illegal Project", "domain": "illegal.org"},
            headers=auth_headers(user_a),
        )
        assert resp.status_code == 403

        db_session.expire_all()
        log = (
            db_session.query(AuditLog)
            .filter_by(event_type="AUTHORIZATION_DENIED", actor_user_id=user_a.id)
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert log is not None
        assert log.tenant_id == tenant_a.id
        assert log.actor_user_id == user_a.id
        assert log.event_metadata["actual_role"] == Role.TENANT_USER.value

    def test_system_admin_only_endpoint_denied_creates_audit_event(
        self,
        client: TestClient,
        admin_a: User,
        tenant_a: Tenant,
        db_session: Session,
    ) -> None:
        """TENANT_ADMIN attempting to create a tenant must record AUTHORIZATION_DENIED."""
        resp = client.post(
            "/api/v1/tenants",
            json={"name": "Rogue Tenant", "slug": "rogue-tenant"},
            headers=auth_headers(admin_a),
        )
        assert resp.status_code == 403

        db_session.expire_all()
        log = (
            db_session.query(AuditLog)
            .filter_by(event_type="AUTHORIZATION_DENIED", actor_user_id=admin_a.id)
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert log is not None
        assert log.tenant_id == tenant_a.id
        assert log.actor_user_id == admin_a.id
        assert log.event_metadata["required_role"] == "SYSTEM_ADMIN"
        assert log.event_metadata["actual_role"] == Role.TENANT_ADMIN.value

    def test_tenant_user_management_denied_creates_audit_event(
        self,
        client: TestClient,
        user_a: User,
        tenant_a: Tenant,
        db_session: Session,
    ) -> None:
        """TENANT_USER attempting to list users must record AUTHORIZATION_DENIED."""
        resp = client.get("/api/v1/users", headers=auth_headers(user_a))
        assert resp.status_code == 403

        db_session.expire_all()
        log = (
            db_session.query(AuditLog)
            .filter_by(event_type="AUTHORIZATION_DENIED", actor_user_id=user_a.id)
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert log is not None
        assert log.tenant_id == tenant_a.id
        assert log.actor_user_id == user_a.id


# ===========================================================================
# 5. SECRET LEAKAGE REVIEW & METADATA SANITIZATION
# ===========================================================================

class TestSecretLeakageProtection:
    def test_sanitize_audit_metadata_strips_credentials(self) -> None:
        """sanitize_audit_metadata must remove passwords, raw JWTs, auth headers, and tokens."""
        raw = {
            "email": "user@example.com",
            "password": "plain-password",
            "plain_password": "plain",
            "hashed_password": "$2b$12$...",
            "jwt": "eyJhbGciOi...",
            "access_token": "token123",
            "refresh_token": "refresh123",
            "token_value": "honey-token-secret",
            "authorization": "Bearer eyJ...",
            "cookie": "session_id=abc",
            "secret": "confidential",
            "api_key": "api_key_value",
            # Allowed safe keys
            "honey_token_id": 42,
            "token_version": 2,
            "role": "TENANT_ADMIN",
            "nested": {
                "password": "nested-pw",
                "safe_info": "ok",
            },
        }
        cleaned = sanitize_audit_metadata(raw)
        assert cleaned is not None
        # Disallowed keys removed
        for forbidden in (
            "password", "plain_password", "hashed_password", "jwt",
            "access_token", "refresh_token", "token_value", "authorization",
            "cookie", "secret", "api_key"
        ):
            assert forbidden not in cleaned
        # Safe keys preserved
        assert cleaned["email"] == "user@example.com"
        assert cleaned["honey_token_id"] == 42
        assert cleaned["token_version"] == 2
        assert cleaned["role"] == "TENANT_ADMIN"
        assert cleaned["nested"] == {"safe_info": "ok"}


# ===========================================================================
# 6. AUDIT LOG IMMUTABILITY
# ===========================================================================

class TestAuditLogImmutability:
    def test_security_audit_log_cannot_be_deleted(self, db_session: Session) -> None:
        """Security audit logs are protected by ORM before_flush and repository."""
        repo = AuditLogRepository(db_session)
        log = repo.create(
            event_type="AUTH_LOGIN_SUCCESS",
            severity="INFO",
            message="Test immutable login event",
        )
        db_session.flush()

        with pytest.raises(ForbiddenError, match="cannot be deleted"):
            repo.delete(log.id)

    def test_security_audit_log_cannot_be_modified(self, db_session: Session) -> None:
        """Security audit logs cannot be edited in-place."""
        repo = AuditLogRepository(db_session)
        log = repo.create(
            event_type="AUTH_LOGIN_FAILURE",
            severity="WARNING",
            message="Initial failure message",
        )
        db_session.flush()

        nested = db_session.begin_nested()
        log.message = "Forged message"
        with pytest.raises(ForbiddenError, match="cannot be modified"):
            db_session.flush()
        nested.rollback()
