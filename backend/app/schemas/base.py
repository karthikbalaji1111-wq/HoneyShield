"""Base Pydantic schema configuration."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class SchemaBase(BaseModel):
    """Base schema with SQLAlchemy ORM attribute support."""

    model_config = ConfigDict(from_attributes=True)
