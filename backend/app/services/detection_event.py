"""Detection-event service operations."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.exceptions import HoneyTokenNotFoundError, ValidationError
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity
from app.repositories.detection_event import DetectionEventRepository
from app.repositories.honey_token import HoneyTokenRepository
from app.services.base import BaseService


class DetectionEventService(BaseService):
    """Coordinate immutable detection-event recording and retrieval."""

    def __init__(
        self,
        session: Session,
        event_repo: DetectionEventRepository,
        token_repo: HoneyTokenRepository,
        current_user: "User" | None = None,
    ) -> None:
        """Initialize the service with event and token repositories.

        Args:
            session: The transaction session for event operations.
            event_repo: Repository used to persist and retrieve events.
            token_repo: Repository used to resolve honey tokens.

        Returns:
            None.
        """
        super().__init__(session, current_user=current_user)
        self.event_repo = event_repo
        self.token_repo = token_repo

    def _resolve_token_id(self, token_value: str | None) -> int | None:
        """Resolve an optional token value to its database identifier.

        Args:
            token_value: Optional globally unique honey token value.

        Returns:
            The token identifier, or None when no token filter is supplied.

        Raises:
            ValidationError: If a supplied token value is blank.
            HoneyTokenNotFoundError: If no matching token exists.
        """
        if token_value is None:
            return None

        self._validate_required_fields(("Token value", token_value))
        token = self.token_repo.get_by_token(token_value)
        if not token:
            raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")
        return token.id

    def record_event(
        self,
        token_value: str,
        ip_address: str,
        request_path: str,
        http_method: str,
        severity: EventSeverity,
        user_agent: str | None = None,
        headers: dict[str, Any] | None = None,
    ) -> DetectionEvent:
        """Record an immutable event for an existing honey token.

        Args:
            token_value: Globally unique honey token value that was triggered.
            ip_address: Source IP address of the request.
            request_path: Request path observed during the event.
            http_method: HTTP method observed during the event.
            severity: Classified severity of the event.
            user_agent: Optional request user-agent value.
            headers: Optional captured request headers.

        Returns:
            The persisted detection event.

        Raises:
            ValidationError: If a required value is blank.
            HoneyTokenNotFoundError: If the referenced token does not exist.
        """
        self._validate_required_fields(
            ("Token value", token_value),
            ("IP address", ip_address),
            ("Request path", request_path),
            ("HTTP method", http_method),
        )

        try:
            token_id = self._resolve_token_id(token_value)
            if token_id is None:
                raise ValidationError("Token value is required for recording events")

            event = self.event_repo.create(
                honey_token_id=token_id,
                ip_address=ip_address,
                request_path=request_path,
                http_method=http_method,
                severity=severity,
                user_agent=user_agent,
                headers=headers,
            )
            self.session.commit()
            return event
        except Exception:
            try:
                self.session.rollback()
            except Exception:
                pass
            raise

    def list_recent_events(
        self,
        token_value: str | None = None,
        limit: int = 100,
    ) -> list[DetectionEvent]:
        """List recent events globally or for a specific honey token.

        Args:
            token_value: Optional honey token value used to scope results.
            limit: Maximum number of recent events to return.

        Returns:
            Detection events ordered from newest to oldest.

        Raises:
            ValidationError: If the limit is invalid or token value is blank.
            HoneyTokenNotFoundError: If a supplied token does not exist.
        """
        if limit < 1:
            raise ValidationError("Limit must be at least 1")

        honey_token_id = self._resolve_token_id(token_value)
        if honey_token_id is not None:
            token = self.token_repo.get_by_token(token_value)
            if token:
                from app.core.exceptions import ForbiddenError
                try:
                    self._authorize_tenant_access(token.project.tenant_id)
                except ForbiddenError:
                    raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")
                
        events = self.event_repo.list_recent(
            honey_token_id=honey_token_id,
            limit=limit,
        )
        if self.current_user and self.current_user.role.name != "SYSTEM_ADMIN" and honey_token_id is None:
            return [e for e in events if e.honey_token.project.tenant_id == self.current_user.tenant_id]
        return events

    def count_today(self, token_value: str | None = None) -> int:
        """Count events recorded since the current UTC day began.

        Args:
            token_value: Optional honey token value used to scope the count.

        Returns:
            Number of matching detection events recorded today.

        Raises:
            ValidationError: If a supplied token value is blank.
            HoneyTokenNotFoundError: If a supplied token does not exist.
        """
        honey_token_id = self._resolve_token_id(token_value)
        if honey_token_id is not None:
            token = self.token_repo.get_by_token(token_value)
            if token:
                from app.core.exceptions import ForbiddenError
                try:
                    self._authorize_tenant_access(token.project.tenant_id)
                except ForbiddenError:
                    raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")
        
        if self.current_user and self.current_user.role.name != "SYSTEM_ADMIN" and honey_token_id is None:
            import datetime
            events = self.event_repo.list_recent(limit=100000)
            now = datetime.datetime.now(datetime.timezone.utc)
            start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
            return len([e for e in events if e.honey_token.project.tenant_id == self.current_user.tenant_id and e.triggered_at >= start_of_day])
            
        return self.event_repo.count_today(honey_token_id=honey_token_id)

    def get_statistics(self) -> dict[str, int]:
        """Return global detection-event totals.

        Args:
            None.

        Returns:
            A mapping containing total and current-day event counts.
        """
        if self.current_user and self.current_user.role.name != "SYSTEM_ADMIN":
            events = self.event_repo.list_recent(limit=1000000)
            tenant_events = [e for e in events if e.honey_token.project.tenant_id == self.current_user.tenant_id]
            import datetime
            today = datetime.datetime.now(datetime.timezone.utc).date()
            today_events = len([e for e in tenant_events if e.triggered_at.date() == today])
            return {
                "total_events": len(tenant_events),
                "today_events": today_events,
            }

        total_events = self.event_repo.count()
        today_events = self.event_repo.count_today()

        return {
            "total_events": total_events,
            "today_events": today_events,
        }
