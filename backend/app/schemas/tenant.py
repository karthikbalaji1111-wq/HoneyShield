"""Tenant request and response schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.schemas.base import SchemaBase


class TenantCreate(SchemaBase):
    """Request payload used to create a tenant."""

    name: str = Field(
        min_length=1,
        max_length=255,
        description="Human-readable tenant name.",
    )
    slug: str = Field(
        min_length=1,
        max_length=100,
        description="Unique tenant identifier.",
    )


class TenantResponse(SchemaBase):
    """Tenant representation returned by the API."""

    id: int = Field(description="Tenant database identifier.")
    name: str = Field(description="Human-readable tenant name.")
    slug: str = Field(description="Unique tenant identifier.")
    is_active: bool = Field(description="Whether the tenant is active.")
    created_at: datetime = Field(description="Tenant creation timestamp.")
    updated_at: datetime = Field(description="Tenant last-update timestamp.")
