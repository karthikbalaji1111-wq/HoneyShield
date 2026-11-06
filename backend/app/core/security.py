from __future__ import annotations

import bcrypt
import jwt
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.config import get_settings

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed one."""
    if len(plain_password.encode("utf-8")) > 72:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False


def validate_password_bytes(password: str) -> str:
    if len(password.encode("utf-8")) > 72:
        raise ValueError("Password must not exceed 72 UTF-8 bytes")
    return password


def get_password_hash(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    validate_password_bytes(password)
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def create_access_token(subject: str | Any, expires_delta: timedelta | None = None, token_version: int = 0) -> str:
    """Create a JWT access token containing the subject identity."""
    settings = get_settings()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    
    # Version is an invalidation counter, never a role or tenant claim.
    to_encode = {"exp": expire, "sub": str(subject), "ver": token_version}
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT token.
    
    Returns the decoded payload.
    Raises jwt.InvalidTokenError or jwt.ExpiredSignatureError on failure.
    """
    settings = get_settings()
    if len(token) > 4096:
        raise jwt.InvalidTokenError("Token exceeds size limit")
    header = jwt.get_unverified_header(token)
    if "crit" in header:
        raise jwt.InvalidTokenError("Unsupported critical header")
    payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm],
                         options={"require": ["sub", "exp", "ver"]})
    if not isinstance(payload["sub"], str) or not re.fullmatch(r"[1-9][0-9]*", payload["sub"]):
        raise jwt.InvalidTokenError("Invalid subject")
    if type(payload["ver"]) is not int or payload["ver"] < 0:
        raise jwt.InvalidTokenError("Invalid session version")
    return payload


def require_active_identity(user) -> None:
    from app.core.auth_exceptions import InactiveUserError, InvalidTokenError
    from app.models.enums import Role
    if not user.is_active:
        raise InactiveUserError("Account is disabled")
    if user.role == Role.SYSTEM_ADMIN:
        if user.tenant_id is not None:
            raise InvalidTokenError("Invalid account scope")
    elif user.role in (Role.TENANT_ADMIN, Role.TENANT_USER):
        if user.tenant_id is None or user.tenant is None or not user.tenant.is_active:
            raise InactiveUserError("Tenant access is unavailable")
    else:
        raise InvalidTokenError("Invalid account role")


def resolve_access_token(token, session):
    from app.core.auth_exceptions import InvalidTokenError, UserNotFoundError
    from app.repositories.user_repository import UserRepository
    try:
        payload = decode_access_token(token)
    except jwt.InvalidTokenError:
        raise InvalidTokenError("Invalid or expired authentication token") from None
    user = UserRepository(session).get_by_id(int(payload["sub"]))
    if user is None:
        raise UserNotFoundError("Authenticated user no longer exists")
    require_active_identity(user)
    if user.token_version != payload["ver"]:
        raise InvalidTokenError("Authentication session has been revoked")
    return user
