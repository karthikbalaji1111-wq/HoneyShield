"""Schemas for honey token generation."""
from __future__ import annotations

from typing import Any

from pydantic import Field

from app.schemas.base import SchemaBase


class GeneratedTokenData(SchemaBase):
    """Data Transfer Object containing fabricated token information."""

    token_value: str = Field(description="The unique generated token value.")
    label: str | None = Field(default=None, description="Optional human-readable label.")
    metadata: dict[str, Any] | None = Field(
        default=None, description="Optional generated metadata."
    )
