"""Service operations for administrative audit logging."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.repositories.audit_log import AuditLogRepository
from app.services.base import BaseService


class AuditLogService(BaseService):
    """Securely records administrative actions for forensic auditing."""

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
        event_metadata: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Record an administrative action.

        This method MUST participate in the caller's transaction and does not
        commit independently.

        Args:
            event_type: The type of event (e.g., 'TENANT_CREATED').
            severity: The severity of the event.
            message: A human-readable description of the event.
            actor_source: The source of the action (e.g., 'api', 'system').
            target_entity: The entity being acted upon (e.g., 'tenant').
            target_id: The identifier of the target entity.
            tenant_id: The relevant tenant ID context.
            project_id: The relevant project ID context.
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
            
        # Ensure metadata is safe from leaking raw honey token secrets
        if event_metadata and "token_value" in event_metadata:
            event_metadata = event_metadata.copy()
            event_metadata.pop("token_value", None)

        return self.audit_repo.create(
            event_type=event_type,
            severity=severity,
            message=message,
            actor_source=actor_source,
            target_entity=target_entity,
            target_id=target_id,
            tenant_id=tenant_id,
            project_id=project_id,
            event_metadata=event_metadata,
        )
