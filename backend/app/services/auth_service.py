"""Authentication service — identity verification and token issuance."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.auth_exceptions import AuthenticationError, InactiveUserError
from app.core.security import create_access_token, verify_password
from app.models.user import User
from app.repositories.user_repository import UserRepository


class AuthService:
    """Authenticate users and issue JWT access tokens.

    This service is framework-independent: it does not import FastAPI,
    does not read HTTP headers, and does not commit the session.
    """

    def __init__(self, session: Session) -> None:
        """Initialise the service with a request-scoped database session.

        Args:
            session: SQLAlchemy session used for user lookups.
        """
        self.session = session
        self._user_repo = UserRepository(session)

    def authenticate(self, email: str, password: str) -> User:
        """Verify credentials and return the active User.

        Args:
            email: The user-supplied email address.
            password: The user-supplied plaintext password.

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
        if user is None or not verify_password(password, user.hashed_password):
            raise AuthenticationError("Invalid email or password")

        if not user.is_active:
            raise InactiveUserError("Account is disabled")

        return user

    def create_token_for_user(self, user: User) -> str:
        """Issue a JWT access token for the given user.

        The JWT payload contains only {sub: user_id, exp: expiry}.

        Args:
            user: A verified, active User object.

        Returns:
            A signed JWT access token string.
        """
        return create_access_token(subject=user.id)
