"""Explicit fresh-session PostgreSQL gate. Requires an isolated migrated DB."""

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from app.core.security import get_password_hash
from app.db.session import get_db
from app.main import app
from app.models.enums import Role
from app.models.tenant import Tenant
from app.models.user import User


@pytest.mark.parametrize("role", list(Role))
def test_postgres_role_survives_fresh_session_and_authorizes(role):
    url = make_url(os.environ["HONEYSHIELD_TEST_DATABASE_URL"])
    assert url.host in {"127.0.0.1", "localhost"}
    assert url.database.startswith("remediation_"), "Refuse a non-test database"
    engine = create_engine(url)
    sessions = sessionmaker(engine)
    suffix = uuid.uuid4().hex
    user_id = tenant_id = None
    try:
        with sessions() as session:
            tenant = Tenant(name="Integration tenant", slug="integration-" + suffix)
            session.add(tenant)
            session.flush()
            tenant_id = tenant.id
            user = User(email=suffix + "@example.org", hashed_password=get_password_hash("integration-password"),
                        role=role, tenant_id=None if role == Role.SYSTEM_ADMIN else tenant_id)
            session.add(user)
            session.commit()
            user_id = user.id
        with sessions() as fresh:
            restored = fresh.get(User, user_id)
            assert restored.role is role

        def test_db():
            with sessions() as session:
                yield session

        app.dependency_overrides[get_db] = test_db
        with TestClient(app) as client:
            login = client.post("/auth/login", json={"email": suffix + "@example.org", "password": "integration-password"})
            assert login.status_code == 200
            headers = {"Authorization": "Bearer " + login.json()["access_token"]}
            response = client.get("/api/v1/tenants", headers=headers)
            assert response.status_code == 200
            if role != Role.SYSTEM_ADMIN:
                assert [t["id"] for t in response.json()] == [tenant_id]
            assert client.get("/api/v1/users", headers=headers).status_code == (403 if role == Role.TENANT_USER else 200)
    finally:
        app.dependency_overrides.clear()
        with sessions() as session:
            if user_id is not None:
                session.execute(delete(User).where(User.id == user_id))
            if tenant_id is not None:
                session.execute(delete(Tenant).where(Tenant.id == tenant_id))
            session.commit()
        engine.dispose()


@pytest.mark.parametrize("role,has_tenant", [("SYSTEM_ADMIN", True), ("TENANT_ADMIN", False), ("TENANT_USER", False), ("UNKNOWN", False)])
def test_postgres_rejects_invalid_role_scope(role, has_tenant):
    url = make_url(os.environ["HONEYSHIELD_TEST_DATABASE_URL"])
    assert url.host in {"127.0.0.1", "localhost"} and url.database.startswith("remediation_")
    engine = create_engine(url)
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            tenant_id = connection.scalar(text("INSERT INTO tenants (name, slug, is_active) VALUES ('constraint-test', :slug, true) RETURNING id"), {"slug": uuid.uuid4().hex})
            with pytest.raises(IntegrityError) as caught:
                connection.execute(text("INSERT INTO users (email, hashed_password, role, tenant_id, is_active) VALUES (:email, 'unused', :role, :tenant, true)"),
                                   {"email": uuid.uuid4().hex + "@example.org", "role": role, "tenant": tenant_id if has_tenant else None})
            assert caught.value.orig.pgcode == "23514"
        finally:
            transaction.rollback()
    engine.dispose()


def test_identity_migration_refuses_invalid_legacy_rows(monkeypatch):
    from alembic import command
    from alembic.config import Config
    from app.core.config import get_settings
    from sqlalchemy.exc import DBAPIError
    url = make_url(os.environ["HONEYSHIELD_TEST_DATABASE_URL"])
    assert url.host in {"127.0.0.1", "localhost"} and url.database.startswith("remediation_")
    schema = "migration_test_" + uuid.uuid4().hex
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped_url = url.update_query_dict({"options": "-csearch_path=" + schema})
    scoped_engine = create_engine(scoped_url)
    monkeypatch.setattr(get_settings(), "database_url", scoped_url.render_as_string(hide_password=False))
    try:
        command.upgrade(Config("alembic.ini"), "0214dbf0f07f")
        with scoped_engine.begin() as connection:
            connection.execute(text("INSERT INTO users (email, hashed_password, role, tenant_id, is_active) VALUES ('legacy@example.org', 'unused', 'TENANT_USER', NULL, true)"))
        with pytest.raises(DBAPIError, match="Invalid user role/tenant rows"):
            command.upgrade(Config("alembic.ini"), "20260918_01")
        with scoped_engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM users")) == 1
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0214dbf0f07f"
    finally:
        scoped_engine.dispose()
        # Only the uniquely named schema created by this test is removed.
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
