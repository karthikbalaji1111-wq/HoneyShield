"""User service operations."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.exceptions import (
    BusinessRuleViolationError,
    DuplicateEmailError,
)
from app.core.auth_exceptions import UserNotFoundError
from app.core.security import get_password_hash
from app.models.enums import Role
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.services.base import BaseService
from app.schemas.user import UserCreate, UserUpdate


class UserService(BaseService):
    """Coordinate user lifecycle and management operations."""

    def __init__(
        self,
        session: Session,
        user_repo: UserRepository,
        current_user: "User" | None = None,
    ) -> None:
        """Initialize the service with user repository.

        Args:
            session: The transaction session for user operations.
            user_repo: Repository used to persist and retrieve users.
            current_user: The authenticated user making the request.
        """
        super().__init__(session, current_user=current_user)
        self.user_repo = user_repo

    def list_users(self) -> list[User]:
        """List users based on role scope.
        
        SYSTEM_ADMIN gets all.
        TENANT_ADMIN gets users in their own tenant.
        """
        if self.current_user.role == Role.SYSTEM_ADMIN:
            return self.user_repo.list()
        
        return self.user_repo.list_by_tenant(self.current_user.tenant_id)

    def get_user(self, user_id: int) -> User:
        """Get a user by ID, respecting tenant isolation.
        
        Returns 404 for nonexistent OR cross-tenant to prevent enumeration.
        """
        user = self.user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError("User not found")
            
        from app.core.auth_exceptions import ForbiddenError
        try:
            self._authorize_tenant_access(user.tenant_id)
        except ForbiddenError:
            raise UserNotFoundError("User not found")
            
        return user

    def create_user(self, payload: UserCreate) -> User:
        """Create a new user.
        
        SYSTEM_ADMIN can create any user, including other SYSTEM_ADMINs.
        TENANT_ADMIN is restricted to creating users in their own tenant,
        and cannot create SYSTEM_ADMINs.
        """
        email = payload.email
        password = payload.password
        role = payload.role
        tenant_id = payload.tenant_id

        if self.current_user.role == Role.TENANT_ADMIN:
            if role == Role.SYSTEM_ADMIN:
                raise BusinessRuleViolationError("Cannot create SYSTEM_ADMIN users")
            if tenant_id is not None and tenant_id != self.current_user.tenant_id:
                raise BusinessRuleViolationError("Cannot create users for other tenants")
            # Force bind to the tenant admin's tenant
            tenant_id = self.current_user.tenant_id
        
        if role == Role.SYSTEM_ADMIN:
            tenant_id = None
        elif tenant_id is None:
            raise BusinessRuleViolationError("tenant_id is required for tenant-scoped users")
        
        existing_user = self.user_repo.get_by_email(email)
        if existing_user:
            raise DuplicateEmailError(f"Email '{email}' is already registered")

        hashed = get_password_hash(password)
        
        try:
            user = self.user_repo.create(
                email=email,
                hashed_password=hashed,
                role=role,
                tenant_id=tenant_id,
            )
            self.session.flush()
            self.session.commit()
            return user
        except Exception:
            try:
                self.session.rollback()
            except Exception:
                pass
            raise

    def update_user(self, user_id: int, payload: UserUpdate) -> User:
        """Update an existing user."""
        user = self.get_user(user_id)
        
        if self.current_user.role == Role.TENANT_ADMIN:
            if payload.role == Role.SYSTEM_ADMIN:
                raise BusinessRuleViolationError("Cannot promote user to SYSTEM_ADMIN")

        if payload.email is not None and payload.email != user.email:
            existing_user = self.user_repo.get_by_email(payload.email)
            if existing_user:
                raise DuplicateEmailError(f"Email '{payload.email}' is already registered")
            user.email = payload.email

        if payload.password is not None:
            user.hashed_password = get_password_hash(payload.password)


        if payload.tenant_id is not None:
            if self.current_user.role == Role.TENANT_ADMIN:
                raise BusinessRuleViolationError("Cannot move users between tenants")
            user.tenant_id = payload.tenant_id

        if payload.role is not None:
            user.role = payload.role
            if user.role == Role.SYSTEM_ADMIN:
                user.tenant_id = None
        
        if user.role != Role.SYSTEM_ADMIN and user.tenant_id is None:
            raise BusinessRuleViolationError("tenant_id is required for tenant-scoped users")


        if payload.is_active is not None:
            user.is_active = payload.is_active

        try:
            self.session.flush()
            self.session.commit()
            return user
        except Exception:
            try:
                self.session.rollback()
            except Exception:
                pass
            raise

    def deactivate_user(self, user_id: int) -> User:
        """Deactivate a user account."""
        user = self.get_user(user_id)
        user.is_active = False
        
        try:
            self.session.flush()
            self.session.commit()
            return user
        except Exception:
            try:
                self.session.rollback()
            except Exception:
                pass
            raise
