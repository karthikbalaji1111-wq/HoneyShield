"""Threat-intelligence service operations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.exceptions import DetectionEventNotFoundError
from app.models.detection_event import DetectionEvent
from app.repositories.detection_event import (
    DetectionEventRepository,
    IPActivityAggregation,
)
from app.services.base import BaseService


@dataclass(frozen=True)
class IPProfile:
    """Threat-intelligence profile for one observed source IP address."""

    ip_address: str
    total_events: int
    first_seen: datetime
    last_seen: datetime
    distinct_honey_tokens: int
    distinct_projects: int
    distinct_user_agents: int
    threat_score: int


@dataclass(frozen=True)
class EventTimeline:
    """Chronological detection-event timeline for one source IP address."""

    ip_address: str
    events: list[DetectionEvent]


@dataclass(frozen=True)
class ThreatSummary:
    """Aggregate threat-intelligence summary across all observed IP addresses."""

    total_events: int
    distinct_ip_addresses: int
    highest_threat_score: int


class ThreatIntelligenceService(BaseService):
    """Analyze persisted detection events without owning new persistence behavior."""

    _REPEAT_EVENT_POINTS = 4
    _MAX_REPEAT_EVENTS = 10
    _TOKEN_POINTS = 5
    _MAX_TOKENS = 5
    _PROJECT_POINTS = 5
    _MAX_PROJECTS = 4
    _CURRENT_DAY_EVENT_POINTS = 3
    _MAX_CURRENT_DAY_EVENTS = 5
    _TOP_ATTACKER_COUNT = 10

    def __init__(self, session: Session, event_repo: DetectionEventRepository) -> None:
        """Initialize the service with its event repository.

        Args:
            session: The request-scoped SQLAlchemy session.
            event_repo: Repository used to retrieve detection-event activity.

        Returns:
            None.
        """
        super().__init__(session)
        self.event_repo = event_repo

    def get_ip_profile(self, ip_address: str) -> IPProfile:
        """Build a threat-intelligence profile for one source IP address.

        Args:
            ip_address: Source IP address to analyze.

        Returns:
            The matching IP profile and deterministic threat score.

        Raises:
            ValidationError: If the IP address is blank.
            DetectionEventNotFoundError: If no matching events exist.
        """
        self._validate_required_fields(("IP address", ip_address))
        aggregates = self.event_repo.aggregate_by_ip(ip_address=ip_address)
        if not aggregates:
            raise DetectionEventNotFoundError(
                f"No detection events found for IP address '{ip_address}'"
            )
        return self._build_ip_profile(aggregates[0])

    def calculate_threat_score(
        self,
        total_events: int,
        distinct_honey_tokens: int,
        distinct_projects: int,
        events_today: int,
    ) -> int:
        """Calculate a deterministic 0-100 score from observed event activity.

        Args:
            total_events: Total detection events observed for the IP address.
            distinct_honey_tokens: Unique honey tokens triggered by the IP address.
            distinct_projects: Unique projects reached by the IP address.
            events_today: Matching events recorded since the current UTC day began.

        Returns:
            A score from 0 through 100.

        Notes:
            Repeats contribute 4 points each after the first event, capped at 40.
            Tokens contribute 5 points each, capped at 25. Projects contribute 5
            points each, capped at 20. Current-UTC-day events contribute 3 points
            each, capped at 15.
        """
        repeated_events = max(total_events - 1, 0)
        repeated_event_score = min(repeated_events, self._MAX_REPEAT_EVENTS) * (
            self._REPEAT_EVENT_POINTS
        )
        token_score = min(max(distinct_honey_tokens, 0), self._MAX_TOKENS) * (
            self._TOKEN_POINTS
        )
        project_score = min(max(distinct_projects, 0), self._MAX_PROJECTS) * (
            self._PROJECT_POINTS
        )
        current_day_score = min(
            max(events_today, 0), self._MAX_CURRENT_DAY_EVENTS
        ) * self._CURRENT_DAY_EVENT_POINTS

        return min(
            100,
            repeated_event_score + token_score + project_score + current_day_score,
        )

    def get_event_timeline(self, ip_address: str) -> EventTimeline:
        """Return the most recent event timeline in chronological order.

        Args:
            ip_address: Source IP address whose events should be retrieved.

        Returns:
            A timeline containing up to 100 events ordered oldest to newest.

        Raises:
            ValidationError: If the IP address is blank.
            DetectionEventNotFoundError: If no matching events exist.
        """
        self._validate_required_fields(("IP address", ip_address))
        events = self.event_repo.find_by_ip(ip_address=ip_address)
        if not events:
            raise DetectionEventNotFoundError(
                f"No detection events found for IP address '{ip_address}'"
            )
        return EventTimeline(ip_address=ip_address, events=list(reversed(events)))

    def get_top_attackers(self) -> list[IPProfile]:
        """Return the ten highest-scoring observed source IP addresses.

        Returns:
            Up to ten IP profiles ordered by descending score and event count.
        """
        profiles = [
            self._build_ip_profile(aggregation)
            for aggregation in self.event_repo.aggregate_by_ip()
        ]
        return sorted(
            profiles,
            key=lambda profile: (
                -profile.threat_score,
                -profile.total_events,
                profile.ip_address,
            ),
        )[: self._TOP_ATTACKER_COUNT]

    def get_summary(self) -> ThreatSummary:
        """Return aggregate threat intelligence across all observed IP addresses.

        Returns:
            Total events, distinct source IPs, and the highest calculated score.
        """
        profiles = [
            self._build_ip_profile(aggregation)
            for aggregation in self.event_repo.aggregate_by_ip()
        ]
        return ThreatSummary(
            total_events=sum(profile.total_events for profile in profiles),
            distinct_ip_addresses=len(profiles),
            highest_threat_score=max(
                (profile.threat_score for profile in profiles),
                default=0,
            ),
        )

    def _build_ip_profile(self, aggregation: IPActivityAggregation) -> IPProfile:
        """Convert one repository aggregate into a scored IP profile."""
        return IPProfile(
            ip_address=aggregation.ip_address,
            total_events=aggregation.total_events,
            first_seen=aggregation.first_seen,
            last_seen=aggregation.last_seen,
            distinct_honey_tokens=aggregation.distinct_honey_tokens,
            distinct_projects=aggregation.distinct_projects,
            distinct_user_agents=aggregation.distinct_user_agents,
            threat_score=self.calculate_threat_score(
                total_events=aggregation.total_events,
                distinct_honey_tokens=aggregation.distinct_honey_tokens,
                distinct_projects=aggregation.distinct_projects,
                events_today=aggregation.events_today,
            ),
        )
