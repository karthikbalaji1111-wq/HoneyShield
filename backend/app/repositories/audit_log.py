from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.auth_exceptions import ForbiddenError
from app.models.audit_log import AuditLog
from app.repositories.base import BaseRepository


class AuditLogRepository(BaseRepository[AuditLog]):
    """Persistence operations for administrative audit logs."""

    def __init__(self, session: Session) -> None:
        """Initialize the repository.

        Args:
            session: The request-scoped SQLAlchemy session.
        """
        super().__init__(session, AuditLog)

    def delete(self, id: int) -> None:
        """Prevent deletion of immutable audit logs."""
        raise ForbiddenError(
            "AuditLog records are immutable forensic evidence and cannot be deleted"
        )
