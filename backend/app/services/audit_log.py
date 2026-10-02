"""Service operations for administrative audit logging."""
from __future__ import annotations


from typing import Any

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.repositories.audit_log import AuditLogRepository
from app.services.base import BaseService


_DISALLOWED_EXACT_KEYS = {
    "password",
    "plain_password",
    "hashed_password",
    "token",
    "access_token",
    "jwt",
    "refresh_token",
    "token_value",
    "authorization",
    "cookie",
    "set-cookie",
    "secret",
    "secret_key",
    "api_key",
    "x-api-key",
}

_SAFE_TOKEN_KEYS = {"token_id", "honey_token_id", "token_type", "token_version"}


def sanitize_audit_metadata(metadata: dict[str, Any] | None) -> dict[str, Any] | None:
    """Recursively scrub credentials, raw tokens, and secret headers from metadata."""
    if not metadata:
        return None
    cleaned: dict[str, Any] = {}
    for k, v in metadata.items():
        k_str = str(k).lower().strip()
        if k_str in _DISALLOWED_EXACT_KEYS:
            continue
        if any(sensitive in k_str for sensitive in ("password", "secret", "cookie", "auth_token")):
            continue
        if "token" in k_str and k_str not in _SAFE_TOKEN_KEYS:
            continue
        if isinstance(v, dict):
            cleaned[k] = sanitize_audit_metadata(v)
        else:
            cleaned[k] = v
    return cleaned


class AuditLogService(BaseService):
    """Securely records administrative and security actions for forensic auditing."""

    def __init__(self, session: Session, audit_repo: AuditLogRepository, current_user: "User" | None = None) -> None:
        """Initialize the service.

        Args:
            session: The request-scoped SQLAlchemy session (owned by caller).
            audit_repo: Repository used to persist audit logs.
        """
        super().__init__(session, current_user=current_user)
        self.audit_repo = audit_repo

    def record_action(
        self,
        event_type: str,
        severity: str,
        message: str,
        actor_source: str | None = None,
        target_entity: str | None = None,
        target_id: str | int | None = None,
        tenant_id: int | None = None,
        project_id: int | None = None,
        actor_user_id: int | None = None,
        event_metadata: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Record an administrative or security action.

        This method MUST participate in the caller's transaction and does not
        commit independently unless committed by caller.

        Args:
            event_type: The type of event (e.g., 'AUTH_LOGIN_SUCCESS', 'TENANT_CREATED').
            severity: The severity of the event ('INFO', 'WARNING', 'CRITICAL').
            message: A human-readable description of the event.
            actor_source: The source of the action (e.g., client IP, 'api', 'SYSTEM', 'USER').
            target_entity: The entity being acted upon (e.g., 'user', 'tenant', 'project').
            target_id: The identifier of the target entity.
            tenant_id: The relevant tenant ID context.
            project_id: The relevant project ID context.
            actor_user_id: Optional ID of the user performing the action.
            event_metadata: Additional safe structured context.

        Returns:
            The uncommitted AuditLog entity.
        """
        self._validate_required_fields(
            ("Event type", event_type),
            ("Severity", severity),
            ("Message", message),
        )

        if target_id is not None:
            target_id = str(target_id)

        # Attribute authenticated actor if available and not explicitly provided
        resolved_actor_user_id = actor_user_id
        if resolved_actor_user_id is None and self.current_user:
            resolved_actor_user_id = self.current_user.id

        # Derive actor source if not provided
        resolved_actor_source = actor_source
        if resolved_actor_source is None:
            resolved_actor_source = "USER" if self.current_user else "SYSTEM"

        # Sanitize metadata to defend against secret/credential leakage
        sanitized_metadata = sanitize_audit_metadata(event_metadata)

        return self.audit_repo.create(
            event_type=event_type,
            severity=severity,
            message=message,
            actor_source=resolved_actor_source,
            target_entity=target_entity,
            target_id=target_id,
            tenant_id=tenant_id,
            project_id=project_id,
            actor_user_id=resolved_actor_user_id,
            event_metadata=sanitized_metadata,
        )
