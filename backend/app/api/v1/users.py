"""User management endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.dependencies import TenantAdminRequired, get_user_service
from app.schemas.user import UserCreate, UserResponse, UserUpdate
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["users"])

UserServiceDep = Annotated[UserService, Depends(get_user_service)]


@router.get(
    "",
    response_model=list[UserResponse],
    status_code=status.HTTP_200_OK,
    summary="List users",
    description="List users. SYSTEM_ADMIN retrieves all users; TENANT_ADMIN retrieves users in their tenant.",
)
def list_users(
    _admin: TenantAdminRequired,
    user_service: UserServiceDep,
) -> list[UserResponse]:
    """Retrieve all accessible users."""
    return user_service.list_users()


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get user",
    description="Retrieve a single user. Returns 404 if the user doesn't exist or belongs to another tenant.",
)
def get_user(
    user_id: int,
    _admin: TenantAdminRequired,
    user_service: UserServiceDep,
) -> UserResponse:
    """Retrieve a single user."""
    return user_service.get_user(user_id)


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user",
    description="Create a new user. TENANT_ADMIN can only create users within their own tenant.",
)
def create_user(
    body: UserCreate,
    _admin: TenantAdminRequired,
    user_service: UserServiceDep,
) -> UserResponse:
    """Create a new user."""
    return user_service.create_user(body)


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update user",
    description="Update an existing user.",
)
def update_user(
    user_id: int,
    body: UserUpdate,
    _admin: TenantAdminRequired,
    user_service: UserServiceDep,
) -> UserResponse:
    """Update an existing user."""
    return user_service.update_user(user_id, body)


@router.post(
    "/{user_id}/deactivate",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Deactivate user",
    description="Deactivate a user account, instantly blocking their authentication.",
)
def deactivate_user(
    user_id: int,
    _admin: TenantAdminRequired,
    user_service: UserServiceDep,
) -> UserResponse:
    """Deactivate a user."""
    return user_service.deactivate_user(user_id)
