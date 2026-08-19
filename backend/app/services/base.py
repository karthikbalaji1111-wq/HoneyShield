"""Shared service-layer functionality."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.exceptions import ValidationError


class BaseService:
    """Provide shared dependencies and validation for domain services."""

    def __init__(self, session: Session, current_user: "User" | None = None) -> None:
        """Initialize the service with its transaction session and user context.

        Args:
            session: The SQLAlchemy session shared by the service repositories.
            current_user: The authenticated user making the request.

        Returns:
            None.
        """
        self.session = session
        self.current_user = current_user

    def _authorize_tenant_access(self, tenant_id: int | None) -> None:
        """Verify the current user has access to the specified tenant.
        
        Args:
            tenant_id: The ID of the tenant to check against.
            
        Raises:
            ForbiddenError: If the user lacks permission.
            UnauthorizedError: If no user is authenticated.
        """
        from app.core.exceptions import ForbiddenError, UnauthorizedError
        from app.models.enums import Role
        
        if not self.current_user:
            raise UnauthorizedError("Authentication required")
            
        if self.current_user.role == Role.SYSTEM_ADMIN:
            return
            
        if self.current_user.tenant_id != tenant_id:
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
