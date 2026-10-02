"""Auth router — login endpoint only."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.auth import LoginRequest, TokenResponse
from app.services.auth_service import AuthService
from app.core.config import get_settings
from app.core.rate_limit import login_limiter

router = APIRouter(prefix="/auth", tags=["auth"])

SessionDependency = Annotated[Session, Depends(get_db)]


def _get_auth_service(session: SessionDependency) -> AuthService:
    """Provide an AuthService bound to the request-scoped session."""
    return AuthService(session=session)


AuthServiceDependency = Annotated[AuthService, Depends(_get_auth_service)]


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate and obtain a JWT access token",
    description=(
        "Accepts email and password credentials. "
        "Returns a Bearer JWT token on success. "
        "Returns HTTP 401 for invalid credentials or disabled accounts."
    ),
)
def login(body: LoginRequest, auth_service: AuthServiceDependency, request: Request) -> TokenResponse:
    """Authenticate the user and return a JWT access token.

    All credential verification and token creation is delegated to AuthService.
    This endpoint performs no database access and contains no security logic.
    """
    settings = get_settings()
    from app.core.ip_trust import extract_client_ip
    source = extract_client_ip(request, settings)
    allowed, retry_after = login_limiter.check_and_increment(
        source,
        settings.login_attempts_per_minute,
        settings.login_global_attempts_per_minute,
        window_seconds=60,
    )
    if not allowed:
        raise HTTPException(status_code=429, detail="Login rate limit exceeded", headers={"Retry-After": str(retry_after)})
    user = auth_service.authenticate(email=body.email, password=body.password)
    token = auth_service.create_token_for_user(user)
    return TokenResponse(access_token=token)
