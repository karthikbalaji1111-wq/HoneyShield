"""Authentication service — identity verification and token issuance."""
from __future__ import annotations


from typing import TYPE_CHECKING, Optional

from sqlalchemy.orm import Session

from app.core.auth_exceptions import AuthenticationError, InactiveUserError
from app.core.security import create_access_token, verify_password, get_password_hash, require_active_identity
from app.models.user import User
from app.repositories.user_repository import UserRepository

if TYPE_CHECKING:
    from app.services.audit_log import AuditLogService

# Same bcrypt cost for absent users; this is not a real account credential.
_DUMMY_HASH = get_password_hash("dummy-password-not-used-by-any-account")


class AuthService:
    """Authenticate users and issue JWT access tokens."""

    def __init__(self, session: Session, audit_service: Optional["AuditLogService"] = None) -> None:
        """Initialise the service with a request-scoped database session.

        Args:
            session: SQLAlchemy session used for user lookups.
            audit_service: Optional audit service for recording security events.
        """
        self.session = session
        self.audit_service = audit_service
        self._user_repo = UserRepository(session)

    def authenticate(self, email: str, password: str, source_ip: str | None = None) -> User:
        """Verify credentials and return the active User.

        Args:
            email: The user-supplied email address.
            password: The user-supplied plaintext password.
            source_ip: Optional client IP address for forensic auditing.

        Returns:
            The authenticated, active User object.

        Raises:
            AuthenticationError: If the email does not exist or the
                password does not match the stored hash.
            InactiveUserError: If the user account is disabled.
        """
        user = self._user_repo.get_by_email(email)

        # Intentionally identical error for unknown email and wrong password
        # to prevent user enumeration.
        verified = verify_password(password, user.hashed_password if user else _DUMMY_HASH)
        if user is None or not verified:
            if self.audit_service:
                try:
                    self.audit_service.record_action(
                        event_type="AUTH_LOGIN_FAILURE",
                        severity="WARNING",
                        message=f"Failed login attempt for email '{email}'",
                        actor_source=source_ip or "api",
                        target_entity="user",
                        target_id=str(user.id) if user else None,
                        tenant_id=user.tenant_id if user else None,
                        event_metadata={"email": email, "ip_address": source_ip} if source_ip else {"email": email},
                    )
                    self.session.commit()
                except Exception:
                    try:
                        self.session.rollback()
                    except Exception:
                        pass
            raise AuthenticationError("Invalid email or password")

        try:
            require_active_identity(user)
        except Exception:
            if self.audit_service:
                try:
                    self.audit_service.record_action(
                        event_type="AUTH_LOGIN_FAILURE",
                        severity="WARNING",
                        message=f"Failed login attempt for disabled account '{email}'",
                        actor_source=source_ip or "api",
                        target_entity="user",
                        target_id=str(user.id),
                        tenant_id=user.tenant_id,
                        event_metadata={"email": email, "ip_address": source_ip, "reason": "account_disabled"} if source_ip else {"email": email, "reason": "account_disabled"},
                    )
                    self.session.commit()
                except Exception:
                    try:
                        self.session.rollback()
                    except Exception:
                        pass
            raise

        if self.audit_service:
            try:
                self.audit_service.record_action(
                    event_type="AUTH_LOGIN_SUCCESS",
                    severity="INFO",
                    message=f"User '{user.email}' logged in successfully",
                    actor_source=source_ip or "api",
                    target_entity="user",
                    target_id=str(user.id),
                    actor_user_id=user.id,
                    tenant_id=user.tenant_id,
                    event_metadata={"email": user.email, "ip_address": source_ip} if source_ip else {"email": user.email},
                )
                self.session.commit()
            except Exception:
                try:
                    self.session.rollback()
                except Exception:
                    pass

        return user

    def create_token_for_user(self, user: User) -> str:
        """Issue a JWT access token for the given user.

        The JWT payload contains only {sub: user_id, exp: expiry}.

        Args:
            user: A verified, active User object.

        Returns:
            A signed JWT access token string.
        """
        return create_access_token(subject=user.id, token_version=user.token_version)
