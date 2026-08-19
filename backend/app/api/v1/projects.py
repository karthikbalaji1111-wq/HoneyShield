"""Version 1 project API routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, status

from app.api.dependencies import CurrentUser, TenantAdminRequired, get_honey_token_service, get_project_service
from app.schemas.error import ErrorResponse
from app.schemas.honey_token import HoneyTokenGenerate, HoneyTokenResponse
from app.schemas.project import ProjectCreate, ProjectResponse
from app.services.honey_token import HoneyTokenService
from app.services.project import ProjectService

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post(
    "",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a project",
    description="Creates a project for an existing tenant.",
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
            "description": "Owning tenant does not exist.",
        },
        status.HTTP_409_CONFLICT: {
            "model": ErrorResponse,
            "description": "Project domain already exists.",
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
def create_project(
    payload: ProjectCreate,
    service: Annotated[ProjectService, Depends(get_project_service)],
    _: TenantAdminRequired,
) -> ProjectResponse:
    """Create and serialize a project. Requires TENANT_ADMIN or above."""
    return service.create_project(
        tenant_slug=payload.tenant_slug,
        name=payload.name,
        domain=payload.domain,
    )


@router.get(
    "",
    response_model=list[ProjectResponse],
    status_code=status.HTTP_200_OK,
    summary="List projects",
    description="Lists projects with optional tenant and activity filters.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Supplied tenant does not exist.",
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
def list_projects(
    service: Annotated[ProjectService, Depends(get_project_service)],
    _: CurrentUser,
    tenant_slug: Annotated[
        str | None,
        Query(
            max_length=100,
            description="Optional tenant slug used to scope results.",
        ),
    ] = None,
    active_only: Annotated[
        bool,
        Query(description="Whether to exclude inactive projects."),
    ] = True,
) -> list[ProjectResponse]:
    """List and serialize projects. Requires authentication."""
    return service.list_projects(
        tenant_slug=tenant_slug,
        active_only=active_only,
    )


@router.get(
    "/{domain}",
    response_model=ProjectResponse,
    status_code=status.HTTP_200_OK,
    summary="Get a project",
    description="Retrieves one project by its domain.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Project does not exist.",
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
def get_project(
    domain: Annotated[
        str,
        Path(
            min_length=1,
            max_length=253,
            description="Project domain identifier.",
        ),
    ],
    service: Annotated[ProjectService, Depends(get_project_service)],
    _: CurrentUser,
) -> ProjectResponse:
    """Retrieve and serialize a project. Requires authentication."""
    return service.get_project(domain=domain)


@router.delete(
    "/{domain}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a project",
    description="Deletes a project through the project service.",
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
            "description": "Project does not exist.",
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
def delete_project(
    domain: Annotated[
        str,
        Path(
            min_length=1,
            max_length=253,
            description="Project domain identifier.",
        ),
    ],
    service: Annotated[ProjectService, Depends(get_project_service)],
    _: TenantAdminRequired,
) -> None:
    """Delete a project. Requires TENANT_ADMIN or above."""
    service.delete_project(domain=domain)


@router.post(
    "/{domain}/honey-tokens/generate",
    response_model=HoneyTokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a honey token",
    description="Algorithmically generates and persists a realistic honey token.",
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
            "description": "Failed to generate a unique token after retries.",
        },
        status.HTTP_422_UNPROCESSABLE_ENTITY: {
            "model": ErrorResponse,
            "description": "Request, domain, or parameter validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def generate_honey_token(
    domain: Annotated[
        str,
        Path(
            min_length=1,
            max_length=253,
            description="Project domain identifier.",
        ),
    ],
    payload: HoneyTokenGenerate,
    service: Annotated[HoneyTokenService, Depends(get_honey_token_service)],
    _: TenantAdminRequired,
) -> HoneyTokenResponse:
    """Generate and serialize a honey token. Requires TENANT_ADMIN or above."""
    return service.generate_token(
        project_domain=domain,
        token_type=payload.token_type,
        params=payload.generator_params,
    )
