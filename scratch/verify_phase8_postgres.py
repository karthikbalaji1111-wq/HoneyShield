"""PostgreSQL 16 E2E Verification Script for Phase 8 (Security Logging & Datetime Hardening).

Executes all Part 10 verification criteria against a real migrated PostgreSQL database.
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

# Configure environment for real PostgreSQL
PG_URL = "postgresql+psycopg2://honeyshield:honeyshield_phase8_pass@localhost:5438/honeyshield_test"
os.environ["DATABASE_URL"] = PG_URL
os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-honeyshield-at-least-32-bytes"

from app.core.rate_limit import reset_all_limiters
from app.core.security import create_access_token, get_password_hash
from app.db.session import get_db
from app.main import app
from app.models.audit_log import AuditLog
from app.models.detection_event import DetectionEvent
from app.models.enums import HoneyTokenType, Role
from app.models.honey_token import HoneyToken
from app.models.project import Project
from app.models.tenant import Tenant
from app.models.user import User
from app.repositories.audit_log import AuditLogRepository

engine = create_engine(PG_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=True)


def verify_all() -> None:
    print("=" * 60)
    print("STARTING PHASE 8 REAL POSTGRESQL VERIFICATION")
    print("=" * 60)

    # 1. Verify PostgreSQL version and Alembic migration
    with engine.connect() as conn:
        ver = conn.execute(text("SELECT version();")).scalar()
        rev = conn.execute(text("SELECT version_num FROM alembic_version;")).scalar()
        print(f"[OK] Connected to PostgreSQL: {ver[:60]}...")
        print(f"[OK] Current Alembic Migration Revision: {rev}")
        assert rev == "20261002_01", f"Expected head revision 20261002_01, got {rev}"

    # 2. Seed test tenants, projects, users, and tokens
    suffix = uuid.uuid4().hex[:8]
    tenant_a_slug = f"tenant-a-{suffix}"
    tenant_b_slug = f"tenant-b-{suffix}"
    token_val = f"token-pg-p8-{suffix}"

    with SessionLocal() as db:
        tenant_a = Tenant(name="Tenant A", slug=tenant_a_slug, is_active=True)
        tenant_b = Tenant(name="Tenant B", slug=tenant_b_slug, is_active=True)
        db.add_all([tenant_a, tenant_b])
        db.flush()

        admin_a = User(
            email=f"admin-a-{suffix}@example.com",
            hashed_password=get_password_hash("ValidPass123!"),
            role=Role.TENANT_ADMIN,
            tenant_id=tenant_a.id,
            is_active=True,
        )
        user_a = User(
            email=f"user-a-{suffix}@example.com",
            hashed_password=get_password_hash("ValidPass123!"),
            role=Role.TENANT_USER,
            tenant_id=tenant_a.id,
            is_active=True,
        )
        inactive_a = User(
            email=f"inactive-a-{suffix}@example.com",
            hashed_password=get_password_hash("ValidPass123!"),
            role=Role.TENANT_USER,
            tenant_id=tenant_a.id,
            is_active=False,
        )
        admin_b = User(
            email=f"admin-b-{suffix}@example.com",
            hashed_password=get_password_hash("ValidPass123!"),
            role=Role.TENANT_ADMIN,
            tenant_id=tenant_b.id,
            is_active=True,
        )
        db.add_all([admin_a, user_a, inactive_a, admin_b])
        db.flush()

        project_a = Project(
            name="Project A",
            domain=f"project-a-{suffix}.internal",
            tenant_id=tenant_a.id,
            is_active=True,
        )
        db.add(project_a)
        db.flush()

        token = HoneyToken(
            project_id=project_a.id,
            token_type=HoneyTokenType.URL,
            token_value=token_val,
            label="Phase 8 Token",
            is_active=True,
        )
        db.add(token)
        db.commit()

        tenant_a_id = tenant_a.id
        tenant_b_id = tenant_b.id
        admin_a_id = admin_a.id
        user_a_id = user_a.id
        inactive_a_id = inactive_a.id
        admin_b_id = admin_b.id
        admin_a_email = admin_a.email
        inactive_a_email = inactive_a.email

    reset_all_limiters()

    def get_test_db():
        with SessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = get_test_db
    client = TestClient(app)

    print("\n--- Criteria 2: Authentication Events Persist ---")
    resp = client.post("/auth/login", json={"email": admin_a_email, "password": "ValidPass123!"})
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    token_jwt = resp.json()["access_token"]
    assert token_jwt is not None

    with SessionLocal() as db:
        success_log = (
            db.query(AuditLog)
            .filter_by(event_type="AUTH_LOGIN_SUCCESS", target_id=str(admin_a_id))
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert success_log is not None, "AUTH_LOGIN_SUCCESS row not found in PostgreSQL"
        assert success_log.actor_user_id == admin_a_id
        assert success_log.tenant_id == tenant_a_id
        assert success_log.severity == "INFO"
        assert admin_a_email in success_log.message
        print(f"[OK] Persisted AUTH_LOGIN_SUCCESS in PostgreSQL (id={success_log.id}, actor={success_log.actor_user_id}, tenant={success_log.tenant_id})")

    print("\n--- Criteria 3: Failed Authentication Events Persist ---")
    # 3a. Invalid password
    resp_bad_pw = client.post("/auth/login", json={"email": admin_a_email, "password": "WrongPassword999!"})
    assert resp_bad_pw.status_code == 401

    with SessionLocal() as db:
        fail_pw_log = (
            db.query(AuditLog)
            .filter_by(event_type="AUTH_LOGIN_FAILURE", target_id=str(admin_a_id))
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert fail_pw_log is not None, "AUTH_LOGIN_FAILURE (bad password) not found in PostgreSQL"
        assert fail_pw_log.actor_user_id is None, "Failed login must have actor_user_id=NULL"
        assert fail_pw_log.tenant_id == tenant_a_id
        assert fail_pw_log.severity == "WARNING"
        print(f"[OK] Persisted AUTH_LOGIN_FAILURE for bad password (id={fail_pw_log.id}, actor={fail_pw_log.actor_user_id})")

    # 3b. Unknown email
    ghost_email = f"unknown-{suffix}@domain.test"
    resp_unknown = client.post("/auth/login", json={"email": ghost_email, "password": "Password123!"})
    assert resp_unknown.status_code == 401

    with SessionLocal() as db:
        fail_ghost_log = (
            db.query(AuditLog)
            .filter_by(event_type="AUTH_LOGIN_FAILURE")
            .filter(AuditLog.message.like(f"%{ghost_email}%"))
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert fail_ghost_log is not None, "AUTH_LOGIN_FAILURE (unknown email) not found in PostgreSQL"
        assert fail_ghost_log.actor_user_id is None
        assert fail_ghost_log.target_id is None
        assert fail_ghost_log.tenant_id is None
        print(f"[OK] Persisted AUTH_LOGIN_FAILURE for unknown email (id={fail_ghost_log.id}, target_id=NULL, tenant_id=NULL)")

    # 3c. Disabled account
    resp_disabled = client.post("/auth/login", json={"email": inactive_a_email, "password": "ValidPass123!"})
    assert resp_disabled.status_code == 401

    with SessionLocal() as db:
        fail_dis_log = (
            db.query(AuditLog)
            .filter_by(event_type="AUTH_LOGIN_FAILURE", target_id=str(inactive_a_id))
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert fail_dis_log is not None, "AUTH_LOGIN_FAILURE (disabled user) not found in PostgreSQL"
        assert fail_dis_log.actor_user_id is None
        assert fail_dis_log.event_metadata.get("reason") == "account_disabled"
        print(f"[OK] Persisted AUTH_LOGIN_FAILURE for disabled account (id={fail_dis_log.id}, reason=account_disabled)")

    print("\n--- Criteria 4: Timestamps Persist Correctly (UTC Timezone-Aware) ---")
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT id, created_at, created_at::text, timezone('UTC', created_at) FROM audit_logs WHERE id = :id"),
            {"id": success_log.id}
        ).fetchone()
        created_at_val = row[1]
        print(f"[OK] PostgreSQL Column created_at: {created_at_val} (tzinfo={created_at_val.tzinfo})")
        assert created_at_val.tzinfo is not None, "Database timestamp must be timezone-aware"

    print("\n--- Criteria 5 & 6: Actor Attribution & Tenant Isolation ---")
    # Test cross-tenant access denial
    headers_a = {"Authorization": f"Bearer {token_jwt}"}
    resp_cross = client.get(f"/api/v1/tenants/{tenant_b_slug}", headers=headers_a)
    assert resp_cross.status_code == 404

    with SessionLocal() as db:
        denial_log = (
            db.query(AuditLog)
            .filter_by(event_type="TENANT_ACCESS_DENIED", actor_user_id=admin_a_id)
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert denial_log is not None, "TENANT_ACCESS_DENIED log not found in PostgreSQL"
        # Crucial check: attributed to Tenant A (the actor's tenant), NEVER Tenant B!
        assert denial_log.tenant_id == tenant_a_id
        assert denial_log.target_id == str(tenant_b_id)
        assert denial_log.event_metadata["attempted_tenant_id"] == tenant_b_id
        print(f"[OK] Cross-tenant denial correctly attributed to actor's tenant: tenant_id={denial_log.tenant_id}, target_id={denial_log.target_id}")

    print("\n--- Criteria 7: Security Metadata Contains Zero Secrets ---")
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT id, event_type, metadata::text FROM audit_logs WHERE metadata IS NOT NULL")).fetchall()
        for r_id, r_type, r_meta in rows:
            for forbidden in ("password", "plain_password", "hashed_password", "jwt", "access_token", "Bearer"):
                assert forbidden.lower() not in r_meta.lower(), f"Secret '{forbidden}' leaked in row {r_id} ({r_type}): {r_meta}"
        print(f"[OK] Inspected {len(rows)} PostgreSQL audit log metadata payloads: 0 secrets found.")

    print("\n--- Criteria 8: Audit Immutability Enforced ---")
    with SessionLocal() as db:
        repo = AuditLogRepository(db)
        test_immut_log = repo.create(
            event_type="AUTH_LOGIN_SUCCESS",
            severity="INFO",
            message="Immutability probe",
        )
        db.flush()
        immut_id = test_immut_log.id

        # Deletion rejected
        try:
            repo.delete(immut_id)
            assert False, "Expected ForbiddenError on delete"
        except Exception as e:
            assert "cannot be deleted" in str(e)
            print(f"[OK] AuditLog delete rejected: {e}")

        # Modification rejected
        nested = db.begin_nested()
        test_immut_log.message = "Mutated message"
        try:
            db.flush()
            assert False, "Expected ForbiddenError on modification"
        except Exception as e:
            assert "cannot be modified" in str(e)
            print(f"[OK] AuditLog in-place modification rejected: {e}")
        nested.rollback()

    print("\n--- Criteria 9: Existing DetectionEvent Behavior Intact ---")
    resp_ingest = client.get(
        f"/t/{token_val}",
        headers={
            "User-Agent": "PostgresVerificationProbe/1.0",
            "Authorization": "Bearer secret_probe_token",
            "Cookie": "session=secret_cookie",
        },
    )
    assert resp_ingest.status_code == 204

    with SessionLocal() as db:
        event = db.query(DetectionEvent).filter_by(request_path=f"/t/{token_val}").first()
        assert event is not None, "DetectionEvent not recorded in PostgreSQL"
        assert event.triggered_at.tzinfo is not None, "DetectionEvent triggered_at must be timezone-aware"
        assert "authorization" not in (event.headers or {})
        assert "cookie" not in (event.headers or {})
        print(f"[OK] DetectionEvent persisted in PostgreSQL with timezone-aware timestamp ({event.triggered_at}) and sanitized headers")

    print("\n" + "=" * 60)
    print("ALL PHASE 8 REAL POSTGRESQL VERIFICATION CRITERIA PASSED!")
    print("=" * 60)


if __name__ == "__main__":
    verify_all()
