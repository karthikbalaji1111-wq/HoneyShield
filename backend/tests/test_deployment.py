
"""Deployment contracts exercised independently of Docker availability."""
from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy.engine import make_url

from app.core.config import Settings


def test_database_credentials_round_trip_reserved_characters(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    settings = Settings(
        _env_file=None,
        jwt_secret_key="test-only-signing-key-with-at-least-32-characters",
        postgres_user="user@name",
        postgres_password="password@host:/?#%",
    )
    url = make_url(settings.sqlalchemy_database_uri)
    assert url.username == "user@name"
    assert url.password == "password@host:/?#%"
    assert url.host == "localhost"


def test_production_rejects_default_database_password():
    with pytest.raises(ValidationError, match="POSTGRES_PASSWORD must be explicitly configured"):
        Settings(
            _env_file=None,
            app_env="production",
            jwt_secret_key="test-only-signing-key-with-at-least-32-characters",
            postgres_password="honeyshield_dev_password",
        )


def test_production_accepts_explicit_password():
    settings = Settings(
        _env_file=None,
        app_env="production",
        jwt_secret_key="test-only-signing-key-with-at-least-32-characters",
        postgres_password="secure-production-database-password",
    )
    assert settings.postgres_password == "secure-production-database-password"


@pytest.mark.parametrize("secret", ["", "short", " " * 40])
def test_reject_unsafe_signing_secret(secret):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_secret_key=secret)


def test_readiness_is_distinct_from_liveness(client):
    assert client.get("/health").status_code == 200
    # Fixture metadata has no Alembic version: an unmigrated DB isn't ready.
    assert client.get("/api/v1/ready").status_code == 503


def test_missing_signing_secret_fails(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_bootstrap_first_admin_and_refuse_repeat(db_session):
    from app.bootstrap import create_first_admin
    from app.models.audit_log import AuditLog
    from app.models.enums import Role
    from sqlalchemy import select

    user = create_first_admin(db_session, "bootstrap@example.org", "safe-test-password")
    assert user.role == Role.SYSTEM_ADMIN
    assert user.tenant_id is None
    actor = db_session.scalars(select(AuditLog)).one()
    assert actor.actor_user_id == user.id
    with pytest.raises(ValueError, match="empty users table"):
        create_first_admin(db_session, "second@example.org", "safe-test-password")


@pytest.mark.parametrize("password", ["short", "a" * 73, "é" * 37])
def test_bootstrap_rejects_unsafe_password(db_session, password):
    from app.bootstrap import create_first_admin
    with pytest.raises(ValueError):
        create_first_admin(db_session, "bootstrap@example.org", password)
