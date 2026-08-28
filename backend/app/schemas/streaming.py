"""Real-time event streaming schemas.

These schemas define the minimal event representations sent over
WebSocket and SSE connections.  They deliberately exclude raw captured
request headers and honey-token secret values to avoid leaking
attacker-controlled or sensitive data over persistent streaming
connections.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.models.enums import EventSeverity
from app.schemas.base import SchemaBase


class RealtimeDetectionEvent(SchemaBase):
    """Minimal detection-event representation for real-time streaming.

    Excluded fields (compared to ``DetectionEventResponse``):

    * ``headers`` — raw captured request headers; attacker-controlled
      data that should not be broadcast over persistent connections.
    * ``created_at`` — internal persistence timestamp; ``triggered_at``
      is the semantically relevant timestamp for live feeds.
    """

    event_type: str = Field(
        default="detection_event",
        description="Event category identifier for stream consumers.",
    )
    event_id: int = Field(
        description="Detection-event database identifier.",
    )
    honey_token_id: int = Field(
        description="Identifier of the triggered honey token.",
    )
    severity: EventSeverity = Field(
        description="Classified event severity.",
    )
    ip_address: str = Field(
        description="Source IP address observed for the event.",
    )
    request_path: str = Field(
        description="Request path observed during the event.",
    )
    http_method: str = Field(
        description="HTTP method observed during the event.",
    )
    user_agent: str | None = Field(
        default=None,
        description="Request user-agent value, if available.",
    )
    triggered_at: datetime = Field(
        description="Time at which the event was triggered.",
    )
