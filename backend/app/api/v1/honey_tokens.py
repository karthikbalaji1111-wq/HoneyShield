"""Version 1 honey-token API routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import CurrentUser, TenantAdminRequired, get_honey_token_service
from app.schemas.error import ErrorResponse
from app.schemas.honey_token import (
    HoneyTokenCreate,
    HoneyTokenResponse,
    HoneyTokenRevoke,
    HoneyTokenRotate,
)
from app.services.honey_token import HoneyTokenService

router = APIRouter(prefix="/honey-tokens", tags=["honey-tokens"])


@router.post(
    "",
    response_model=HoneyTokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a honey token",
    description="Creates a honey token for an existing project.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "TENANT_ADMIN role or above required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Owning project does not exist.",
        },
        status.HTTP_409_CONFLICT: {
            "model": ErrorResponse,
            "description": "Honey-token value already exists.",
        },
        status.HTTP_422_UNPROCESSABLE_ENTITY: {
            "model": ErrorResponse,
            "description": "Request or domain validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def create_honey_token(
    payload: HoneyTokenCreate,
    service: Annotated[HoneyTokenService, Depends(get_honey_token_service)],
    _: TenantAdminRequired,
) -> HoneyTokenResponse:
    """Create and serialize a honey token. Requires TENANT_ADMIN or above."""
    return service.create_token(
        project_domain=payload.project_domain,
        token_type=payload.token_type,
        token_value=payload.token_value,
        label=payload.label,
        metadata=payload.metadata,
    )


@router.get(
    "",
    response_model=list[HoneyTokenResponse],
    status_code=status.HTTP_200_OK,
    summary="List honey tokens",
    description="Lists honey tokens with optional project and activity filters.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Supplied project does not exist.",
        },
        status.HTTP_422_UNPROCESSABLE_ENTITY: {
            "model": ErrorResponse,
            "description": "Request or domain validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def list_honey_tokens(
    service: Annotated[HoneyTokenService, Depends(get_honey_token_service)],
    _: CurrentUser,
    project_domain: Annotated[
        str | None,
        Query(
            max_length=253,
            description="Optional project domain used to scope results.",
        ),
    ] = None,
    active_only: Annotated[
        bool,
        Query(description="Whether to exclude revoked tokens."),
    ] = True,
) -> list[HoneyTokenResponse]:
    """List and serialize honey tokens. Requires authentication."""
    return service.list_tokens(
        project_domain=project_domain,
        active_only=active_only,
    )


@router.post(
    "/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a honey token",
    description="Marks an existing honey token as inactive.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "TENANT_ADMIN role or above required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Honey token does not exist.",
        },
        status.HTTP_422_UNPROCESSABLE_ENTITY: {
            "model": ErrorResponse,
            "description": "Request or domain validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def revoke_honey_token(
    payload: HoneyTokenRevoke,
    service: Annotated[HoneyTokenService, Depends(get_honey_token_service)],
    _: TenantAdminRequired,
) -> None:
    """Revoke a honey token. Requires TENANT_ADMIN or above."""
    service.revoke_token(token_value=payload.token_value)


@router.post(
    "/rotate",
    response_model=HoneyTokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate a honey token",
    description="Atomically revokes a token and creates its replacement.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "TENANT_ADMIN role or above required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Existing honey token does not exist.",
        },
        status.HTTP_409_CONFLICT: {
            "model": ErrorResponse,
            "description": "Replacement honey-token value already exists.",
        },
        status.HTTP_422_UNPROCESSABLE_ENTITY: {
            "model": ErrorResponse,
            "description": "Request or domain validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def rotate_honey_token(
    payload: HoneyTokenRotate,
    service: Annotated[HoneyTokenService, Depends(get_honey_token_service)],
    _: TenantAdminRequired,
) -> HoneyTokenResponse:
    """Rotate and serialize a honey token. Requires TENANT_ADMIN or above."""
    return service.rotate_token(
        old_token_value=payload.old_token_value,
        new_token_value=payload.new_token_value,
    )
