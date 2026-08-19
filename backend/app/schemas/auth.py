"""Auth schemas for login request and token response."""

from pydantic import Field

from app.schemas.base import SchemaBase


class LoginRequest(SchemaBase):
    """Credentials submitted by the client for authentication."""

    email: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str


class TokenResponse(SchemaBase):
    """JWT token returned upon successful authentication."""

    access_token: str
    token_type: str = "bearer"
