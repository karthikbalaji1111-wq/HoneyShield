"""Explicit, interactive first-administrator provisioning. Never runs at startup."""
from __future__ import annotations

import argparse
import getpass

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.security import get_password_hash
from app.db.session import SessionLocal
from app.models.audit_log import AuditLog
from app.models.enums import Role
from app.models.user import User
from app.schemas.user import UserCreate


def create_first_admin(session: Session, email: str, password: str) -> User:
    """Own a single bootstrap transaction; refuse all subsequent bootstrap attempts."""
    payload = UserCreate(email=email, password=password, role=Role.SYSTEM_ADMIN)
    if not 12 <= len(password.encode("utf-8")) <= 72:
        raise ValueError("Bootstrap password must contain 12 through 72 UTF-8 bytes")
    try:
        if session.get_bind().dialect.name == "postgresql":
            # Serialize concurrent bootstrap commands without a permanent table.
            session.execute(text("SELECT pg_advisory_xact_lock(724190315)"))
        if session.scalar(select(func.count()).select_from(User)):
            raise ValueError("Bootstrap requires an empty users table; use authorized user management")
        user = User(email=payload.email, hashed_password=get_password_hash(password),
                    role=Role.SYSTEM_ADMIN, tenant_id=None, is_active=True)
        session.add(user)
        session.flush()
        session.add(AuditLog(event_type="SYSTEM_ADMIN_BOOTSTRAPPED", severity="WARNING",
                            message="First system administrator provisioned interactively",
                            actor_source="bootstrap", actor_user_id=user.id,
                            target_entity="user", target_id=str(user.id)))
        session.commit()
        return user
    except Exception:
        session.rollback()
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True)
    args = parser.parse_args()
    password = getpass.getpass("New administrator password: ")
    if password != getpass.getpass("Confirm password: "):
        parser.error("Passwords do not match")
    with SessionLocal() as session:
        create_first_admin(session, args.email, password)
    print("First administrator created. No credentials are printed.")


if __name__ == "__main__":
    main()
