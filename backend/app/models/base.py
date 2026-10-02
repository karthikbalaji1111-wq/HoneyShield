from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, Integer, event, func
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.core.auth_exceptions import ForbiddenError
from app.db.base import Base


class BaseModel(Base):
    __abstract__ = True

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        onupdate=func.now(),
    )


class ImmutableBaseModel(Base):
    """Abstract base for append-only records. No updated_at by design."""

    __abstract__ = True

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )


@event.listens_for(Session, "before_flush")
def _enforce_immutable_records(session: Session, flush_context: Any, instances: Any) -> None:
    """Prevent deletion or in-place modification of immutable forensic models."""
    for obj in session.deleted:
        if isinstance(obj, ImmutableBaseModel):
            raise ForbiddenError(
                f"Immutable forensic record '{obj.__class__.__name__}' cannot be deleted"
            )
    for obj in session.dirty:
        if isinstance(obj, ImmutableBaseModel) and session.is_modified(obj):
            raise ForbiddenError(
                f"Immutable forensic record '{obj.__class__.__name__}' cannot be modified"
            )
