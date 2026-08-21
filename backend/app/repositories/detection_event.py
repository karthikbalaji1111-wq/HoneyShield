from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.detection_event import DetectionEvent
from app.models.honey_token import HoneyToken
from app.repositories.base import BaseRepository


@dataclass(frozen=True)
class IPActivityAggregation:
    """SQL aggregate values describing one source IP's event activity."""

    ip_address: str
    total_events: int
    first_seen: datetime
    last_seen: datetime
    distinct_honey_tokens: int
    distinct_projects: int
    distinct_user_agents: int
    events_today: int


class DetectionEventRepository(BaseRepository[DetectionEvent]):
    def __init__(self, session: Session) -> None:
        super().__init__(session, DetectionEvent)

    def list_recent(self, honey_token_id: int | None = None, limit: int = 100) -> list[DetectionEvent]:
        stmt = select(DetectionEvent)
        if honey_token_id is not None:
            stmt = stmt.where(DetectionEvent.honey_token_id == honey_token_id)
        stmt = stmt.order_by(DetectionEvent.triggered_at.desc()).limit(limit)
        return list(self.session.scalars(stmt).all())

    def list_between(
        self, honey_token_id: int, start_time: datetime, end_time: datetime
    ) -> list[DetectionEvent]:
        stmt = (
            select(DetectionEvent)
            .where(DetectionEvent.honey_token_id == honey_token_id)
            .where(DetectionEvent.triggered_at >= start_time)
            .where(DetectionEvent.triggered_at <= end_time)
            .order_by(DetectionEvent.triggered_at.desc())
        )
        return list(self.session.scalars(stmt).all())

    def find_by_ip(self, ip_address: str, limit: int = 100, tenant_id: int | None = None) -> list[DetectionEvent]:
        from app.models.honey_token import HoneyToken
        from app.models.project import Project
        stmt = select(DetectionEvent).where(DetectionEvent.ip_address == ip_address)
        if tenant_id is not None:
            stmt = stmt.join(HoneyToken, DetectionEvent.honey_token_id == HoneyToken.id).join(Project, HoneyToken.project_id == Project.id).where(Project.tenant_id == tenant_id)
        stmt = stmt.order_by(DetectionEvent.triggered_at.desc()).limit(limit)
        return list(self.session.scalars(stmt).all())

    def aggregate_by_ip(
        self,
        ip_address: str | None = None,
        tenant_id: int | None = None,
    ) -> list[IPActivityAggregation]:
        """Aggregate detection-event activity by source IP address.

        Args:
            ip_address: Optional source IP address used to scope the aggregation.

        Returns:
            One aggregate result per matching source IP address.
        """
        now = datetime.now(timezone.utc)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        events_today = func.count(DetectionEvent.id).filter(
            DetectionEvent.triggered_at >= start_of_day
        )
        from app.models.project import Project
        stmt = (
            select(
                DetectionEvent.ip_address.label("ip_address"),
                func.count(DetectionEvent.id).label("total_events"),
                func.min(DetectionEvent.triggered_at).label("first_seen"),
                func.max(DetectionEvent.triggered_at).label("last_seen"),
                func.count(
                    func.distinct(DetectionEvent.honey_token_id)
                ).label("distinct_honey_tokens"),
                func.count(func.distinct(HoneyToken.project_id)).label(
                    "distinct_projects"
                ),
                func.count(func.distinct(DetectionEvent.user_agent)).label(
                    "distinct_user_agents"
                ),
                events_today.label("events_today"),
            )
            .join(HoneyToken, DetectionEvent.honey_token_id == HoneyToken.id)
        )
        if tenant_id is not None:
            stmt = stmt.join(Project, HoneyToken.project_id == Project.id).where(Project.tenant_id == tenant_id)
        stmt = stmt.group_by(DetectionEvent.ip_address).order_by(DetectionEvent.ip_address)
        if ip_address is not None:
            stmt = stmt.where(DetectionEvent.ip_address == ip_address)

        rows = self.session.execute(stmt)
        return [
            IPActivityAggregation(
                ip_address=row.ip_address,
                total_events=row.total_events,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                distinct_honey_tokens=row.distinct_honey_tokens,
                distinct_projects=row.distinct_projects,
                distinct_user_agents=row.distinct_user_agents,
                events_today=row.events_today,
            )
            for row in rows
        ]

    def count_today(self, honey_token_id: int | None = None) -> int:
        now = datetime.now(timezone.utc)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        stmt = (
            select(func.count())
            .select_from(DetectionEvent)
            .where(DetectionEvent.triggered_at >= start_of_day)
        )
        if honey_token_id is not None:
            stmt = stmt.where(DetectionEvent.honey_token_id == honey_token_id)
        return self.session.scalar(stmt) or 0
