"""Project request and response schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.schemas.base import SchemaBase


class ProjectCreate(SchemaBase):
    """Request payload used to create a project."""

    tenant_slug: str = Field(
        min_length=1,
        max_length=100,
        description="Slug of the tenant that owns the project.",
    )
    name: str = Field(
        min_length=1,
        max_length=255,
        description="Human-readable project name.",
    )
    domain: str = Field(
        min_length=1,
        max_length=253,
        description="Domain associated with the project.",
    )


class ProjectResponse(SchemaBase):
    """Project representation returned by the API."""

    id: int = Field(description="Project database identifier.")
    tenant_id: int = Field(description="Identifier of the owning tenant.")
    name: str = Field(description="Human-readable project name.")
    domain: str = Field(description="Domain associated with the project.")
    is_active: bool = Field(description="Whether the project is active.")
    created_at: datetime = Field(description="Project creation timestamp.")
    updated_at: datetime = Field(description="Project last-update timestamp.")
