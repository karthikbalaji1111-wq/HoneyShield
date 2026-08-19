"""Version 1 tenant API routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, status

from app.api.dependencies import CurrentUser, SystemAdminRequired, get_tenant_service
from app.schemas.error import ErrorResponse
from app.schemas.tenant import TenantCreate, TenantResponse
from app.services.tenant import TenantService

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.post(
    "",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a tenant",
    description="Creates a tenant through the tenant service.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "SYSTEM_ADMIN role required.",
        },
        status.HTTP_409_CONFLICT: {
            "model": ErrorResponse,
            "description": "Tenant slug already exists.",
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
def create_tenant(
    payload: TenantCreate,
    service: Annotated[TenantService, Depends(get_tenant_service)],
    _: SystemAdminRequired,
) -> TenantResponse:
    """Create and serialize a tenant. Requires SYSTEM_ADMIN."""
    return service.create_tenant(name=payload.name, slug=payload.slug)


@router.get(
    "",
    response_model=list[TenantResponse],
    status_code=status.HTTP_200_OK,
    summary="List tenants",
    description="Lists tenants, optionally limited to active records.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def list_tenants(
    service: Annotated[TenantService, Depends(get_tenant_service)],
    _: CurrentUser,
    active_only: Annotated[
        bool,
        Query(description="Whether to exclude inactive tenants."),
    ] = True,
) -> list[TenantResponse]:
    """List and serialize tenants. Requires authentication."""
    return service.list_tenants(active_only=active_only)


@router.get(
    "/{slug}",
    response_model=TenantResponse,
    status_code=status.HTTP_200_OK,
    summary="Get a tenant",
    description="Retrieves one tenant by its unique slug.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Tenant does not exist.",
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
def get_tenant(
    slug: Annotated[
        str,
        Path(
            min_length=1,
            max_length=100,
            description="Unique tenant slug.",
        ),
    ],
    service: Annotated[TenantService, Depends(get_tenant_service)],
    _: CurrentUser,
) -> TenantResponse:
    """Retrieve and serialize a tenant. Requires authentication."""
    return service.get_tenant(slug=slug)


@router.delete(
    "/{slug}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a tenant",
    description="Deletes a tenant through the tenant service.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "SYSTEM_ADMIN role required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Tenant does not exist.",
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
def delete_tenant(
    slug: Annotated[
        str,
        Path(
            min_length=1,
            max_length=100,
            description="Unique tenant slug.",
        ),
    ],
    service: Annotated[TenantService, Depends(get_tenant_service)],
    _: SystemAdminRequired,
) -> None:
    """Delete a tenant. Requires SYSTEM_ADMIN."""
    service.delete_tenant(slug=slug)
