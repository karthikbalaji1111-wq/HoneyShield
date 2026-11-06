"""Health endpoint response schemas."""
from __future__ import annotations

from pydantic import Field

from app.schemas.base import SchemaBase


class HealthResponse(SchemaBase):
    """Service health response."""

    status: str = Field(description="Current service health status.")
