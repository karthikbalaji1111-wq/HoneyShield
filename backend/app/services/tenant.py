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

    def __init__(self, session: Session, tenant_repo: TenantRepository, audit_service: AuditLogService | None = None) -> None:
        """Initialize the service with tenant persistence dependencies.

        Args:
            session: The transaction session for tenant operations.
            tenant_repo: Repository used to persist and retrieve tenants.
            audit_service: Service used to record audit events.
        """
        super().__init__(session)
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
        return tenant

    def list_tenants(self, active_only: bool = True) -> list[Tenant]:
        """List tenants, optionally limited to active records.

        Args:
            active_only: Whether to exclude inactive tenants.

        Returns:
            Tenant records matching the requested activity filter.
        """
        if active_only:
            return self.tenant_repo.list_active()
        return self.tenant_repo.list()

    def delete_tenant(self, slug: str) -> None:
        """Delete a tenant and its cascade-managed dependents.

        Args:
            slug: Unique tenant identifier.

        Returns:
            None.

        Raises:
            ValidationError: If the slug is blank.
            TenantNotFoundError: If no matching tenant exists.
        """
        try:
            tenant = self.get_tenant(slug)
            self.tenant_repo.delete(tenant.id)
            
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
