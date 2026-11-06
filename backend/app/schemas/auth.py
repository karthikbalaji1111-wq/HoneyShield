"""Auth schemas for login request and token response."""
from __future__ import annotations

from pydantic import Field, field_validator
from app.core.security import validate_password_bytes

from app.schemas.base import SchemaBase


class LoginRequest(SchemaBase):
    """Credentials submitted by the client for authentication."""

    email: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str

    @field_validator("password")
    @classmethod
    def bounded_password(cls, value):
        return validate_password_bytes(value)


class TokenResponse(SchemaBase):
    """JWT token returned upon successful authentication."""

    access_token: str
    token_type: str = "bearer"
