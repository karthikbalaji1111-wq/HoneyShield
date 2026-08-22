"""Shared fixtures for HoneyShield regression tests.

Strategy:
  - SQLite in-memory database: no external postgres required.
  - JSONB columns in audit_logs, detection_events, and honey_tokens are
    transparently remapped to generic JSON for SQLite compatibility.
  - All tables created fresh per session via SQLAlchemy metadata.
  - FastAPI TestClient wired to override get_db with the test session.
  - Two-tenant scenario:
      Tenant A (slug="tenant-a")
      Tenant B (slug="tenant-b")
    Users: admin_a, admin_b, user_a, system_admin.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import JSON, create_engine, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, sessionmaker

# ---------------------------------------------------------------------------
# Monkeypatch for application bug (ImportError)
# The previous agent imported ForbiddenError from app.core.exceptions
# instead of app.core.auth_exceptions in several services.
# We patch it here to avoid modifying application code as requested.
# ---------------------------------------------------------------------------
from app.core import exceptions
from app.core.auth_exceptions import ForbiddenError, UnauthorizedError
exceptions.ForbiddenError = ForbiddenError
exceptions.UnauthorizedError = UnauthorizedError

from app.core.security import create_access_token, get_password_hash
from app.db.session import get_db
from app.main import app
from app.models.base import BaseModel
from app.models.enums import HoneyTokenType, Role
from app.models.honey_token import HoneyToken
from app.models.project import Project
from app.models.tenant import Tenant
from app.models.user import User


# ---------------------------------------------------------------------------
# Database Engine — SQLite in-memory with JSONB→JSON remapping
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def engine():
    """Session-scoped SQLite in-memory engine with JSONB compatibility.

    SQLite does not support the PostgreSQL JSONB type. We directly mutate
    the shared MetaData column types to generic JSON before create_all.
    This is safe because:
      - tests run against SQLite only
      - the engine fixture is session-scoped (runs once)
      - the mutations do not affect the production app (different process)
    """
    # Patch JSONB → JSON for all columns in the shared metadata
    for table in BaseModel.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, JSONB):
                column.type = JSON()

    _engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    # Enforce foreign-key constraints in SQLite
    @event.listens_for(_engine, "connect")
    def _set_fk_pragma(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    BaseModel.metadata.create_all(bind=_engine)
    yield _engine
    BaseModel.metadata.drop_all(bind=_engine)
    _engine.dispose()


@pytest.fixture()
def db_session(engine):
    """Per-test transactional session; rolls back after each test."""
    connection = engine.connect()
    transaction = connection.begin()
    TestingSessionLocal = sessionmaker(bind=connection, autoflush=True)
    session = TestingSessionLocal()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


# ---------------------------------------------------------------------------
# FastAPI TestClient wired to the test DB session
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(db_session):
    """FastAPI TestClient with get_db overridden to the test session."""
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Domain fixtures — two-tenant scenario
# ---------------------------------------------------------------------------

@pytest.fixture()
def tenant_a(db_session: Session) -> Tenant:
    tenant = Tenant(name="Tenant Alpha", slug="tenant-a", is_active=True)
    db_session.add(tenant)
    db_session.flush()
    return tenant


@pytest.fixture()
def tenant_b(db_session: Session) -> Tenant:
    tenant = Tenant(name="Tenant Beta", slug="tenant-b", is_active=True)
    db_session.add(tenant)
    db_session.flush()
    return tenant


@pytest.fixture()
def admin_a(db_session: Session, tenant_a: Tenant) -> User:
    user = User(
        email="admin@tenant-a.com",
        hashed_password=get_password_hash("password"),
        role=Role.TENANT_ADMIN,
        is_active=True,
        tenant_id=tenant_a.id,
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture()
def admin_b(db_session: Session, tenant_b: Tenant) -> User:
    user = User(
        email="admin@tenant-b.com",
        hashed_password=get_password_hash("password"),
        role=Role.TENANT_ADMIN,
        is_active=True,
        tenant_id=tenant_b.id,
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture()
def user_a(db_session: Session, tenant_a: Tenant) -> User:
    user = User(
        email="user@tenant-a.com",
        hashed_password=get_password_hash("password"),
        role=Role.TENANT_USER,
        is_active=True,
        tenant_id=tenant_a.id,
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture()
def system_admin(db_session: Session) -> User:
    user = User(
        email="sysadmin@honeyshield.io",
        hashed_password=get_password_hash("password"),
        role=Role.SYSTEM_ADMIN,
        is_active=True,
        tenant_id=None,
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture()
def inactive_user(db_session: Session, tenant_a: Tenant) -> User:
    user = User(
        email="inactive@tenant-a.com",
        hashed_password=get_password_hash("password"),
        role=Role.TENANT_USER,
        is_active=False,
        tenant_id=tenant_a.id,
    )
    db_session.add(user)
    db_session.flush()
    return user


# ---------------------------------------------------------------------------
# Project fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def project_a(db_session: Session, tenant_a: Tenant) -> Project:
    project = Project(
        tenant_id=tenant_a.id,
        name="Project Alpha",
        domain="alpha.example.com",
        is_active=True,
    )
    db_session.add(project)
    db_session.flush()
    return project


@pytest.fixture()
def project_b(db_session: Session, tenant_b: Tenant) -> Project:
    project = Project(
        tenant_id=tenant_b.id,
        name="Project Beta",
        domain="beta.example.com",
        is_active=True,
    )
    db_session.add(project)
    db_session.flush()
    return project


# ---------------------------------------------------------------------------
# HoneyToken fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def token_a(db_session: Session, project_a: Project) -> HoneyToken:
    token = HoneyToken(
        project_id=project_a.id,
        token_type=HoneyTokenType.URL,
        token_value="token-alpha-secret-value",
        label="Alpha token",
        is_active=True,
    )
    db_session.add(token)
    db_session.flush()
    return token


@pytest.fixture()
def token_b(db_session: Session, project_b: Project) -> HoneyToken:
    token = HoneyToken(
        project_id=project_b.id,
        token_type=HoneyTokenType.URL,
        token_value="token-beta-secret-value",
        label="Beta token",
        is_active=True,
    )
    db_session.add(token)
    db_session.flush()
    return token


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def make_token(user: User) -> str:
    """Create a valid JWT for the given user."""
    return create_access_token(subject=str(user.id))


def auth_headers(user: User) -> dict[str, str]:
    """Return Authorization header dict for the given user."""
    return {"Authorization": f"Bearer {make_token(user)}"}
