"""Shared service-layer functionality."""
from __future__ import annotations


from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from app.core.exceptions import ValidationError

if TYPE_CHECKING:
    from app.models.user import User
    from app.services.audit_log import AuditLogService


class BaseService:
    """Provide shared dependencies and validation for domain services."""

    def __init__(
        self,
        session: Session,
        current_user: "User" | None = None,
        audit_service: "AuditLogService" | None = None,
    ) -> None:
        """Initialize the service with its transaction session and user context.

        Args:
            session: The SQLAlchemy session shared by the service repositories.
            current_user: The authenticated user making the request.
            audit_service: Service used to persist audit logs.

        Returns:
            None.
        """
        self.session = session
        self.current_user = current_user
        self.audit_service = audit_service

    def _authorize_tenant_access(self, tenant_id: int | None) -> None:
        """Verify the current user has access to the specified tenant.
        
        Args:
            tenant_id: The ID of the tenant to check against.
            
        Raises:
            ForbiddenError: If the user lacks permission.
            UnauthorizedError: If no user is authenticated.
        """
        from app.core.auth_exceptions import ForbiddenError, UnauthorizedError
        from app.models.enums import Role
        
        if not self.current_user:
            raise UnauthorizedError("Authentication required")
            
        if self.current_user.role == Role.SYSTEM_ADMIN:
            return
            
        if self.current_user.tenant_id != tenant_id:
            if hasattr(self, "audit_service") and self.audit_service:
                try:
                    self.audit_service.record_action(
                        event_type="TENANT_ACCESS_DENIED",
                        severity="WARNING",
                        message="Access denied to requested tenant resources",
                        actor_source="api",
                        actor_user_id=self.current_user.id,
                        tenant_id=self.current_user.tenant_id,
                        target_entity="tenant",
                        target_id=str(tenant_id) if tenant_id is not None else None,
                        event_metadata={"attempted_tenant_id": tenant_id},
                    )
                    self.session.commit()
                except Exception:
                    try:
                        self.session.rollback()
                    except Exception:
                        pass
            raise ForbiddenError("Access denied to requested tenant resources")

    @staticmethod
    def _validate_required_fields(*fields: tuple[str, str | None]) -> None:
        """Raise a validation error when named string fields are blank.

        Args:
            fields: Pairs containing a display name and its string value.

        Returns:
            None.

        Raises:
            ValidationError: If one or more field values are blank.
        """
        missing_fields = [
            field_name
            for field_name, value in fields
            if value is None or not value.strip()
        ]
        if not missing_fields:
            return

        verb = "is" if len(missing_fields) == 1 else "are"
        field_names = " and ".join(missing_fields)
        raise ValidationError(f"{field_names} {verb} required")
