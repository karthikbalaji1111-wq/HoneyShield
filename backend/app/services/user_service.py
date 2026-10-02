"""User service operations."""
from __future__ import annotations


from sqlalchemy.orm import Session

from app.core.exceptions import (
    BusinessRuleViolationError,
    DuplicateEmailError,
)
from app.core.auth_exceptions import UserNotFoundError, ForbiddenError
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

    def _require_manager(self) -> None:
        if self.current_user is None or self.current_user.role not in (Role.SYSTEM_ADMIN, Role.TENANT_ADMIN):
            raise ForbiddenError("User management requires administrator privileges")

    def list_users(self, limit: int | None = None, offset: int = 0) -> list[User]:
        """List users based on role scope with deterministic pagination.
        
        SYSTEM_ADMIN gets all.
        TENANT_ADMIN gets users in their own tenant.
        """
        self._require_manager()
        if self.current_user.role == Role.SYSTEM_ADMIN:
            return self.user_repo.list(limit=limit, offset=offset)
        
        return self.user_repo.list_by_tenant(self.current_user.tenant_id, limit=limit, offset=offset)

    def get_user(self, user_id: int) -> User:
        """Get a user by ID, respecting tenant isolation.
        
        Returns 404 for nonexistent OR cross-tenant to prevent enumeration.
        """
        self._require_manager()
        user = self.user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError("User not found")
        if self.current_user.role != Role.SYSTEM_ADMIN and user.role == Role.SYSTEM_ADMIN:
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
        self._require_manager()
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
            if tenant_id is not None:
                raise BusinessRuleViolationError("SYSTEM_ADMIN cannot be tenant-bound")
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
        new_role = payload.role if payload.role is not None else user.role
        tenant_supplied = "tenant_id" in payload.model_fields_set
        new_tenant = payload.tenant_id if tenant_supplied else user.tenant_id
        if self.current_user.role == Role.TENANT_ADMIN and tenant_supplied:
            raise BusinessRuleViolationError("Cannot move users between tenants")
        if new_role == Role.SYSTEM_ADMIN:
            if tenant_supplied and new_tenant is not None:
                raise BusinessRuleViolationError("SYSTEM_ADMIN cannot be tenant-bound")
            new_tenant = None
        elif new_tenant is None:
            raise BusinessRuleViolationError("tenant_id is required for tenant-scoped users")
        security_change = (
            payload.password is not None or new_role != user.role or new_tenant != user.tenant_id
            or (payload.is_active is not None and payload.is_active != user.is_active)
        )
        
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


        user.role = new_role
        user.tenant_id = new_tenant
        if security_change:
            user.token_version = User.token_version + 1


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
        user.token_version = User.token_version + 1
        
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
