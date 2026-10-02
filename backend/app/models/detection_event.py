from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import ImmutableBaseModel
from app.models.enums import EventSeverity


class DetectionEvent(ImmutableBaseModel):
    __tablename__ = "detection_events"
    __table_args__ = (
        Index("ix_detection_events_honey_token_id_triggered_at", "honey_token_id", "triggered_at"),
    )

    honey_token_id: Mapped[int] = mapped_column(Integer, ForeignKey("honey_tokens.id"), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_path: Mapped[str] = mapped_column(Text, nullable=False)
    http_method: Mapped[str] = mapped_column(String(10), nullable=False)
    headers: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    severity: Mapped[EventSeverity] = mapped_column(
        Enum(EventSeverity, native_enum=False, validate_strings=True, length=50),
        nullable=False,
        index=True,
    )
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        index=True,
    )

    honey_token: Mapped["HoneyToken"] = relationship(
        "HoneyToken",
        back_populates="detection_events",
    )
