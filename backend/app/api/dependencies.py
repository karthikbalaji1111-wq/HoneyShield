"""FastAPI dependency providers for application services."""

from typing import Annotated

from fastapi import Depends, Header
from sqlalchemy.orm import Session

from app.core.auth_exceptions import InvalidTokenError, UserNotFoundError, InactiveUserError
from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.user import User
from app.repositories.audit_log import AuditLogRepository
from app.repositories.detection_event import DetectionEventRepository
from app.repositories.honey_token import HoneyTokenRepository
from app.repositories.project import ProjectRepository
from app.repositories.tenant import TenantRepository
from app.repositories.user_repository import UserRepository
from app.services.audit_log import AuditLogService
from app.services.detection_event import DetectionEventService
from app.services.honey_token import HoneyTokenService
from app.services.project import ProjectService
from app.services.tenant import TenantService
from app.services.threat_intelligence import ThreatIntelligenceService

SessionDependency = Annotated[Session, Depends(get_db)]
def get_current_user(
    session: SessionDependency,
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    """Resolve the authenticated User from the Bearer JWT in the Authorization header.

    Flow:
        1. Extract token from "Authorization: Bearer <token>" header.
        2. Decode and verify JWT signature and expiry.
        3. Extract user_id from ``sub`` claim.
        4. Load User from the database by primary key.
        5. Verify the user account is active.

    The JWT payload contains only ``sub`` (user_id as str) and ``exp``.
    No role or tenant data is read from the token — authorization is
    always derived from the live database state.

    Raises:
        InvalidTokenError: If the header is absent, malformed, or the JWT is invalid/expired.
        UserNotFoundError: If the user_id from the token has no matching database record.
        InactiveUserError: If the matched user account is disabled.
    """
    import jwt as pyjwt

    if not authorization or not authorization.lower().startswith("bearer "):
        raise InvalidTokenError("Missing or malformed Authorization header")

    raw_token = authorization[len("bearer "):].strip()

    try:
        payload = decode_access_token(raw_token)
    except pyjwt.ExpiredSignatureError:
        raise InvalidTokenError("Token has expired")
    except pyjwt.InvalidTokenError:
        raise InvalidTokenError("Token is invalid")

    user_id_str: str | None = payload.get("sub")
    if not user_id_str:
        raise InvalidTokenError("Token is missing subject claim")

    try:
        user_id = int(user_id_str)
    except (ValueError, TypeError):
        raise InvalidTokenError("Token subject is not a valid user identifier")

    user = UserRepository(session).get_by_id(user_id)
    if user is None:
        raise UserNotFoundError("Authenticated user no longer exists")

    if not user.is_active:
        raise InactiveUserError("Account is disabled")

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*allowed_roles: "Role") -> "Callable[[User], User]":
    """Return a FastAPI dependency that enforces role membership.

    The returned dependency resolves the current user via ``get_current_user``
    and then asserts that the user's role is one of ``allowed_roles``.

    Args:
        *allowed_roles: One or more ``Role`` enum values that are permitted.

    Returns:
        A FastAPI-compatible dependency callable that returns the ``User``
        when authorised, or raises ``ForbiddenError`` otherwise.

    Example::

        SystemAdminOnly = Depends(require_roles(Role.SYSTEM_ADMIN))
    """
    from app.core.auth_exceptions import ForbiddenError
    from app.models.enums import Role

    def _check(user: CurrentUser) -> User:  # type: ignore[valid-type]
        if user.role not in allowed_roles:
            raise ForbiddenError("Insufficient permissions for this operation")
        return user

    return _check


def _require_system_admin(user: CurrentUser) -> User:  # type: ignore[valid-type]
    """Dependency: allow only SYSTEM_ADMIN users.

    SYSTEM_ADMIN has global scope (tenant_id = NULL) and full access to
    all tenant management operations.

    Raises:
        ForbiddenError: If the authenticated user is not a SYSTEM_ADMIN.
    """
    from app.core.auth_exceptions import ForbiddenError
    from app.models.enums import Role

    if user.role != Role.SYSTEM_ADMIN:
        raise ForbiddenError("This operation requires SYSTEM_ADMIN privileges")
    return user


def _require_tenant_admin_or_above(user: CurrentUser) -> User:  # type: ignore[valid-type]
    """Dependency: allow SYSTEM_ADMIN or TENANT_ADMIN users.

    Used for tenant-scoped management operations such as creating projects
    and managing honey tokens within a tenant's scope.

    Raises:
        ForbiddenError: If the authenticated user is a TENANT_USER.
    """
    from app.core.auth_exceptions import ForbiddenError
    from app.models.enums import Role

    if user.role not in (Role.SYSTEM_ADMIN, Role.TENANT_ADMIN):
        raise ForbiddenError("This operation requires TENANT_ADMIN privileges or above")
    return user


# Typed dependency aliases for use in router signatures
from typing import Callable  # noqa: E402 — kept at bottom to avoid circular imports

SystemAdminRequired = Annotated[User, Depends(_require_system_admin)]
TenantAdminRequired = Annotated[User, Depends(_require_tenant_admin_or_above)]

def get_optional_user(
    session: SessionDependency,
    authorization: Annotated[str | None, Header()] = None,
) -> User | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    try:
        return get_current_user(session, authorization)
    except (InvalidTokenError, UserNotFoundError, InactiveUserError):
        return None

OptionalUser = Annotated[User | None, Depends(get_optional_user)]



def get_audit_log_service(session: SessionDependency, current_user: OptionalUser = None) -> AuditLogService:
    """Provide an audit-log service using the request-scoped session."""
    return AuditLogService(session=session, current_user=current_user, audit_repo=AuditLogRepository(session))


def get_tenant_service(session: SessionDependency, current_user: OptionalUser = None) -> TenantService:
    """Provide a tenant service using the request-scoped database session."""
    return TenantService(
        session=session, 
        current_user=current_user,
        tenant_repo=TenantRepository(session),
        audit_service=get_audit_log_service(session, current_user)
    )


def get_project_service(session: SessionDependency, current_user: OptionalUser = None) -> ProjectService:
    """Provide a project service using the request-scoped database session."""
    return ProjectService(
        session=session,
        current_user=current_user,
        project_repo=ProjectRepository(session),
        tenant_repo=TenantRepository(session),
        audit_service=get_audit_log_service(session, current_user)
    )


def get_honey_token_service(session: SessionDependency, current_user: OptionalUser = None) -> HoneyTokenService:
    """Provide a honey-token service using the request-scoped session."""
    return HoneyTokenService(
        session=session,
        current_user=current_user,
        token_repo=HoneyTokenRepository(session),
        project_repo=ProjectRepository(session),
        audit_service=get_audit_log_service(session, current_user)
    )


def get_detection_event_service(session: SessionDependency, current_user: OptionalUser = None) -> DetectionEventService:
    """Provide a detection-event service using the request-scoped session."""
    return DetectionEventService(
        session=session,
        current_user=current_user,
        event_repo=DetectionEventRepository(session),
        token_repo=HoneyTokenRepository(session),
    )


def get_threat_intelligence_service(
    session: SessionDependency,
    current_user: OptionalUser = None,
) -> ThreatIntelligenceService:
    """Provide a threat-intelligence service using the request-scoped session."""
    return ThreatIntelligenceService(
        session=session,
        current_user=current_user,
        event_repo=DetectionEventRepository(session),
    )


