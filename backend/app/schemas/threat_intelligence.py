"""Threat-intelligence response schemas."""

from datetime import datetime

from pydantic import Field

from app.schemas.base import SchemaBase
from app.schemas.detection_event import DetectionEventResponse


class IPProfileResponse(SchemaBase):
    """Threat-intelligence profile returned for one source IP address."""

    ip_address: str = Field(description="Observed source IP address.")
    total_events: int = Field(description="Total events observed from the IP address.")
    first_seen: datetime = Field(description="Timestamp of the first observed event.")
    last_seen: datetime = Field(description="Timestamp of the most recent observed event.")
    distinct_honey_tokens: int = Field(
        description="Number of unique honey tokens triggered."
    )
    distinct_projects: int = Field(
        description="Number of unique projects reached through honey tokens."
    )
    distinct_user_agents: int = Field(
        description="Number of distinct non-null user-agent values observed."
    )
    threat_score: int = Field(
        ge=0,
        le=100,
        description="Deterministic threat score calculated from observed activity.",
    )


class TimelineResponse(SchemaBase):
    """Chronological detection-event timeline for one source IP address."""

    ip_address: str = Field(description="Observed source IP address.")
    events: list[DetectionEventResponse] = Field(
        description="Most recent matching events ordered from oldest to newest."
    )


class ThreatSummaryResponse(SchemaBase):
    """Aggregate threat-intelligence metrics returned by the API."""

    total_events: int = Field(description="Total persisted detection events.")
    distinct_ip_addresses: int = Field(
        description="Number of source IP addresses with observed events."
    )
    highest_threat_score: int = Field(
        ge=0,
        le=100,
        description="Highest deterministic threat score among observed IP addresses.",
    )
