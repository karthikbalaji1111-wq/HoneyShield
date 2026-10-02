"""Tenant service operations."""
from __future__ import annotations


from sqlalchemy.orm import Session

from app.core.exceptions import (
    DuplicateTenantError,
    TenantNotFoundError,
)
from app.models.tenant import Tenant
from app.repositories.tenant import TenantRepository
from app.services.audit_log import AuditLogService
from app.services.base import BaseService


class TenantService(BaseService):
    """Coordinate tenant lifecycle operations."""

    def __init__(self, session: Session, tenant_repo: TenantRepository, audit_service: AuditLogService | None = None, current_user: "User" | None = None) -> None:
        """Initialize the service with tenant persistence dependencies.

        Args:
            session: The transaction session for tenant operations.
            tenant_repo: Repository used to persist and retrieve tenants.
            audit_service: Service used to record audit events.
        """
        super().__init__(session, current_user=current_user)
        self.tenant_repo = tenant_repo
        self.audit_service = audit_service

    def create_tenant(self, name: str, slug: str) -> Tenant:
        """Create a tenant with a unique slug.

        Args:
            name: Human-readable tenant name.
            slug: Unique tenant identifier.

        Returns:
            The persisted tenant.

        Raises:
            ValidationError: If a required value is blank.
            DuplicateTenantError: If the slug is already in use.
        """
        self._validate_required_fields(("Name", name), ("Slug", slug))

        try:
            if self.tenant_repo.slug_exists(slug):
                raise DuplicateTenantError(
                    f"Tenant with slug '{slug}' already exists"
                )

            tenant = self.tenant_repo.create(name=name, slug=slug)
            self.session.flush()
            
            if self.audit_service:
                self.audit_service.record_action(
                    event_type="TENANT_CREATED",
                    severity="INFO",
                    message=f"Created tenant '{name}' with slug '{slug}'",
                    actor_source="api",
                    target_entity="tenant",
                    target_id=tenant.id,
                    tenant_id=tenant.id,
                )
                
            self.session.commit()
            return tenant
        except Exception:
            try:
                self.session.rollback()
            except Exception:
                pass
            raise

    def get_tenant(self, slug: str) -> Tenant:
        """Retrieve a tenant by its slug.

        Args:
            slug: Unique tenant identifier.

        Returns:
            The matching tenant.

        Raises:
            ValidationError: If the slug is blank.
            TenantNotFoundError: If no matching tenant exists.
        """
        self._validate_required_fields(("Slug", slug))
        tenant = self.tenant_repo.get_by_slug(slug)
        if not tenant:
            raise TenantNotFoundError(f"Tenant '{slug}' not found")
        
        from app.core.auth_exceptions import ForbiddenError
        try:
            self._authorize_tenant_access(tenant.id)
        except ForbiddenError:
            raise TenantNotFoundError(f"Tenant '{slug}' not found")
            
        return tenant

    def list_tenants(
        self,
        active_only: bool = True,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Tenant]:
        """List tenants, optionally limited to active records with pagination.

        Args:
            active_only: Whether to exclude inactive tenants.
            limit: Optional maximum number of records to return.
            offset: Number of records to skip.

        Returns:
            Tenant records matching the requested activity filter.
        """
        if self.current_user and self.current_user.role.name != "SYSTEM_ADMIN":
            tenant = self.tenant_repo.get_by_id(self.current_user.tenant_id)
            if not tenant or (active_only and not tenant.is_active):
                return []
            return [tenant] if offset == 0 else []

        if active_only:
            return self.tenant_repo.list_active(limit=limit, offset=offset)
        return self.tenant_repo.list(limit=limit, offset=offset)

    def delete_tenant(self, slug: str) -> None:
        """Deactivate a tenant and its cascade-managed dependents while preserving forensic records.

        Args:
            slug: Unique tenant identifier.

        Returns:
            None.

        Raises:
            ValidationError: If the slug is blank.
            TenantNotFoundError: If no matching active tenant exists.
        """
        try:
            tenant = self.get_tenant(slug)
            if not tenant.is_active:
                raise TenantNotFoundError(f"Tenant with slug '{slug}' not found")

            tenant.is_active = False
            for project in tenant.projects:
                project.is_active = False
                for token in project.honey_tokens:
                    token.is_active = False
            self.session.flush()

            if self.audit_service:
                self.audit_service.record_action(
                    event_type="TENANT_DELETED",
                    severity="WARNING",
                    message=f"Deleted tenant '{tenant.name}' with slug '{slug}'",
                    actor_source="api",
                    target_entity="tenant",
                    target_id=tenant.id,
                    tenant_id=tenant.id,
                )

            self.session.commit()
        except Exception:
            try:
                self.session.rollback()
            except Exception:
                pass
            raise
