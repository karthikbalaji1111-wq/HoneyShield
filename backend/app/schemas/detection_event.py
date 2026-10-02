"""Detection-event request and response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.models.enums import EventSeverity
from app.schemas.base import SchemaBase


class DetectionEventCreate(SchemaBase):
    """Request payload used to record a detection event."""

    token_value: str = Field(
        min_length=1,
        max_length=512,
        description="Globally unique honey-token value that was triggered.",
    )
    ip_address: str = Field(
        min_length=1,
        max_length=45,
        description="Source IP address observed for the event.",
    )
    request_path: str = Field(
        min_length=1,
        description="Request path observed during the event.",
    )
    http_method: str = Field(
        min_length=1,
        max_length=10,
        description="HTTP method observed during the event.",
    )
    severity: EventSeverity = Field(description="Classified event severity.")
    user_agent: str | None = Field(
        default=None,
        description="Optional request user-agent value.",
    )
    headers: dict[str, Any] | None = Field(
        default=None,
        description="Optional captured request headers.",
    )

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        """Validate that ip_address is a valid IPv4 or IPv6 format (F-028)."""
        from app.core.ip_trust import normalize_ip
        try:
            return normalize_ip(value)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address format: '{value}'") from exc

    @field_validator("headers")
    @classmethod
    def validate_and_sanitize_headers(cls, value: dict[str, Any] | None) -> dict[str, str] | None:
        """Sanitize, filter, and bound request headers before persistence (F-013)."""
        from app.core.header_security import sanitize_forensic_headers
        return sanitize_forensic_headers(value)


class DetectionEventResponse(SchemaBase):
    """Detection-event representation returned by the API."""

    id: int = Field(description="Detection-event database identifier.")
    honey_token_id: int = Field(description="Identifier of the triggered honey token.")
    ip_address: str = Field(description="Source IP address observed for the event.")
    user_agent: str | None = Field(description="Optional request user-agent value.")
    request_path: str = Field(description="Request path observed during the event.")
    http_method: str = Field(description="HTTP method observed during the event.")
    headers: dict[str, Any] | None = Field(description="Captured request headers.")
    severity: EventSeverity = Field(description="Classified event severity.")
    triggered_at: datetime = Field(description="Time at which the event was triggered.")
    created_at: datetime = Field(description="Event persistence timestamp.")


class DetectionEventStatisticsResponse(SchemaBase):
    """Aggregated detection-event counts."""

    total_events: int = Field(description="Total number of recorded events.")
    today_events: int = Field(description="Number of events recorded today in UTC.")
