from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.models.enums import HoneyTokenType


class HoneyToken(BaseModel):
    __tablename__ = "honey_tokens"

    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    token_type: Mapped[HoneyTokenType] = mapped_column(
        Enum(HoneyTokenType, native_enum=False, validate_strings=True, length=50),
        nullable=False,
        index=True,
    )
    token_value: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    token_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column("metadata", JSONB, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    project: Mapped["Project"] = relationship(
        "Project",
        back_populates="honey_tokens",
    )
    detection_events: Mapped[list["DetectionEvent"]] = relationship(
        "DetectionEvent",
        back_populates="honey_token",
        passive_deletes=True,
    )
