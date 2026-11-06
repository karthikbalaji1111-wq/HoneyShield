"""User schemas (DTOs)."""
from __future__ import annotations

from datetime import datetime

from typing import Annotated
from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from app.core.security import validate_password_bytes

Password = Annotated[str, AfterValidator(validate_password_bytes)]

from app.models.enums import Role


class UserCreate(BaseModel):
    """Payload for creating a new user."""

    email: str = Field(..., pattern="^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", title="Email", description="User's email address.")
    password: Password = Field(..., min_length=8, title="Password", description="Plaintext password, at most 72 UTF-8 bytes.")
    role: Role = Field(..., title="Role", description="User's role within the system.")
    tenant_id: int | None = Field(None, title="Tenant ID", description="Tenant to bind the user to. System admins can leave this null.")


class UserUpdate(BaseModel):
    """Payload for updating an existing user.

    Fields omitted from the request body remain unchanged. Fields explicitly
    provided (including null) are validated against RBAC and tenant invariants.
    """

    email: str | None = Field(None, pattern="^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", title="Email", description="New email address.")
    password: Password | None = Field(None, min_length=8, title="Password", description="New plaintext password, at most 72 UTF-8 bytes.")
    role: Role | None = Field(None, title="Role", description="New role.")
    is_active: bool | None = Field(None, title="Is Active", description="Account active status.")
    tenant_id: int | None = Field(
        default=None,
        title="Tenant ID",
        description="Target tenant ID. Omit to preserve current tenant. Explicit null unbinds tenant scope (SYSTEM_ADMIN only).",
    )


class UserResponse(BaseModel):
    """User representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., title="Id", description="User database identifier.")
    email: str = Field(..., pattern="^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", title="Email", description="User's email address.")
    role: Role = Field(..., title="Role", description="User's role.")
    is_active: bool = Field(..., title="Is Active", description="Whether the user account is active.")
    tenant_id: int | None = Field(None, title="Tenant Id", description="Identifier of the owning tenant.")
    created_at: datetime = Field(..., title="Created At", description="User creation timestamp.")
    updated_at: datetime = Field(..., title="Updated At", description="User last-update timestamp.")
