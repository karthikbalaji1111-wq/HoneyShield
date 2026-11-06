"""Error response schemas."""
from __future__ import annotations

from pydantic import Field

from app.schemas.base import SchemaBase


class ErrorResponse(SchemaBase):
    """Safe error payload returned by API exception handlers."""

    detail: str = Field(description="Safe human-readable error message.")
    request_id: str = Field(description="Identifier used to correlate request logs.")
