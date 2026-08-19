"""Auth router — login endpoint only."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.auth import LoginRequest, TokenResponse
from app.services.auth_service import AuthService

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
def login(body: LoginRequest, auth_service: AuthServiceDependency) -> TokenResponse:
    """Authenticate the user and return a JWT access token.

    All credential verification and token creation is delegated to AuthService.
    This endpoint performs no database access and contains no security logic.
    """
    user = auth_service.authenticate(email=body.email, password=body.password)
    token = auth_service.create_token_for_user(user)
    return TokenResponse(access_token=token)
