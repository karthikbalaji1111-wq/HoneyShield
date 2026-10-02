"""Detection-event service operations."""
from __future__ import annotations


import logging
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

    @property
    def _scoped_tenant_id(self) -> int | None:
        if self.current_user and self.current_user.role.name != "SYSTEM_ADMIN":
            return self.current_user.tenant_id
        return None

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
            token = self.token_repo.get_by_token(token_value)
            if not token:
                raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")

            # Administrative cross-tenant guard:
            # If current_user is authenticated and tenant-scoped, verify token ownership.
            # Mask cross-tenant unauthorized access as 404 (HoneyTokenNotFoundError).
            if self._scoped_tenant_id is not None:
                from app.core.auth_exceptions import ForbiddenError
                try:
                    self._authorize_tenant_access(token.project.tenant_id)
                except ForbiddenError:
                    raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")

            token_id = token.id

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

            # Publish to real-time subscribers (fire-and-forget after commit).
            # A broadcast failure must never roll back the persisted event.
            try:
                self._publish_realtime_event(event)
            except Exception:
                logging.getLogger(__name__).warning(
                    "Failed to broadcast detection event %s",
                    event.id,
                    exc_info=True,
                )

            return event
        except Exception:
            try:
                self.session.rollback()
            except Exception:
                pass
            raise

    def _publish_realtime_event(self, event: DetectionEvent) -> None:
        """Publish a committed detection event to real-time subscribers.

        Serialises the event into a minimal payload suitable for live
        security feeds (no raw headers, no token secrets) and sends it
        to tenant-matched subscribers via the in-process broadcaster.

        Args:
            event: The persisted, committed detection event.
        """
        from app.services.event_broadcaster import get_broadcaster

        tenant_id = event.honey_token.project.tenant_id

        event_data = {
            "event_type": "detection_event",
            "event_id": event.id,
            "honey_token_id": event.honey_token_id,
            "severity": event.severity.value,
            "ip_address": event.ip_address,
            "request_path": event.request_path,
            "http_method": event.http_method,
            "user_agent": event.user_agent,
            "triggered_at": event.triggered_at.isoformat()
            if event.triggered_at
            else None,
        }

        get_broadcaster().publish(event_data, tenant_id)


    def list_recent_events(
        self,
        token_value: str | None = None,
        limit: int = 100,
        offset: int = 0,
        cursor: int | None = None,
    ) -> list[DetectionEvent]:
        """List recent events globally or for a specific honey token.

        Args:
            token_value: Optional honey token value used to scope results.
            limit: Maximum number of recent events to return (capped at 1000).
            offset: Number of items to skip for offset-based pagination.
            cursor: Optional event ID cursor for keyset pagination.

        Returns:
            Detection events ordered from newest to oldest.

        Raises:
            ValidationError: If the limit or offset is invalid or token value is blank.
            HoneyTokenNotFoundError: If a supplied token does not exist.
        """
        if limit < 1:
            raise ValidationError("Limit must be at least 1")
        if limit > 1000:
            raise ValidationError("Limit cannot exceed 1000")
        if offset < 0:
            raise ValidationError("Offset cannot be negative")

        honey_token_id = None
        if token_value is not None:
            token = self.token_repo.get_by_token(token_value)
            if not token:
                raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")
            if self._scoped_tenant_id is not None:
                from app.core.auth_exceptions import ForbiddenError
                try:
                    self._authorize_tenant_access(token.project.tenant_id)
                except ForbiddenError:
                    raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")
            honey_token_id = token.id

        scoped_tenant = self._scoped_tenant_id if honey_token_id is None else None
        return self.event_repo.list_recent(
            honey_token_id=honey_token_id,
            limit=limit,
            offset=offset,
            cursor=cursor,
            tenant_id=scoped_tenant,
        )

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
        honey_token_id = None
        if token_value is not None:
            token = self.token_repo.get_by_token(token_value)
            if not token:
                raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")
            if self._scoped_tenant_id is not None:
                from app.core.auth_exceptions import ForbiddenError
                try:
                    self._authorize_tenant_access(token.project.tenant_id)
                except ForbiddenError:
                    raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")
            honey_token_id = token.id

        scoped_tenant = self._scoped_tenant_id if honey_token_id is None else None
        return self.event_repo.count_today(
            honey_token_id=honey_token_id,
            tenant_id=scoped_tenant,
        )

    def get_statistics(self) -> dict[str, int]:
        """Return global or tenant-scoped detection-event totals in a single SQL pass (F-002).

        Args:
            None.

        Returns:
            A mapping containing total and current-day event counts.
        """
        tenant_id = self._scoped_tenant_id
        total_events, today_events = self.event_repo.count_summary(tenant_id=tenant_id)

        return {
            "total_events": total_events,
            "today_events": today_events,
        }
