"""Project service operations."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.exceptions import (
    DuplicateDomainError,
    ProjectNotFoundError,
    TenantNotFoundError,
)
from app.models.project import Project
from app.repositories.project import ProjectRepository
from app.repositories.tenant import TenantRepository
from app.services.audit_log import AuditLogService
from app.services.base import BaseService


class ProjectService(BaseService):
    """Coordinate project lifecycle operations within tenants."""

    def __init__(
        self,
        session: Session,
        project_repo: ProjectRepository,
        tenant_repo: TenantRepository,
        audit_service: AuditLogService | None = None,
    ) -> None:
        """Initialize the service with project and tenant repositories.

        Args:
            session: The transaction session for project operations.
            project_repo: Repository used to persist and retrieve projects.
            tenant_repo: Repository used to resolve owning tenants.
            audit_service: Service used to record audit events.
        """
        super().__init__(session)
        self.project_repo = project_repo
        self.tenant_repo = tenant_repo
        self.audit_service = audit_service

    def create_project(self, tenant_slug: str, name: str, domain: str) -> Project:
        """Create a project for an existing tenant.

        Args:
            tenant_slug: Unique slug of the owning tenant.
            name: Human-readable project name.
            domain: Project domain identifier.

        Returns:
            The persisted project.

        Raises:
            ValidationError: If a required value is blank.
            TenantNotFoundError: If the owning tenant does not exist.
            DuplicateDomainError: If the domain is already in use.
        """
        self._validate_required_fields(
            ("Tenant slug", tenant_slug),
            ("Name", name),
            ("Domain", domain),
        )

        try:
            tenant = self.tenant_repo.get_by_slug(tenant_slug)
            if not tenant:
                raise TenantNotFoundError(f"Tenant '{tenant_slug}' not found")

            existing_project = self.project_repo.get_by_domain(domain)
            if existing_project:
                raise DuplicateDomainError(
                    f"Project with domain '{domain}' already exists"
                )

            project = self.project_repo.create(
                tenant_id=tenant.id,
                name=name,
                domain=domain,
            )
            self.session.flush()
            
            if self.audit_service:
                self.audit_service.record_action(
                    event_type="PROJECT_CREATED",
                    severity="INFO",
                    message=f"Created project '{name}' with domain '{domain}'",
                    actor_source="api",
                    target_entity="project",
                    target_id=project.id,
                    tenant_id=tenant.id,
                    project_id=project.id,
                )

            self.session.commit()
            return project
        except Exception:
            try:
                self.session.rollback()
            except Exception:
                pass
            raise

    def get_project(self, domain: str) -> Project:
        """Retrieve a project by its domain.

        Args:
            domain: Project domain identifier.

        Returns:
            The matching project.

        Raises:
            ValidationError: If the domain is blank.
            ProjectNotFoundError: If no matching project exists.
        """
        self._validate_required_fields(("Domain", domain))
        project = self.project_repo.get_by_domain(domain)
        if not project:
            raise ProjectNotFoundError(f"Project for domain '{domain}' not found")
        return project

    def list_projects(
        self,
        tenant_slug: str | None = None,
        active_only: bool = True,
    ) -> list[Project]:
        """List projects with optional tenant and activity filters.

        Args:
            tenant_slug: Optional slug limiting results to one tenant.
            active_only: Whether to exclude inactive projects.

        Returns:
            Project records matching the requested filters.

        Raises:
            ValidationError: If a supplied tenant slug is blank.
            TenantNotFoundError: If a supplied tenant does not exist.
        """
        tenant_id = None
        if tenant_slug is not None:
            self._validate_required_fields(("Tenant slug", tenant_slug))
            tenant = self.tenant_repo.get_by_slug(tenant_slug)
            if not tenant:
                raise TenantNotFoundError(f"Tenant '{tenant_slug}' not found")
            tenant_id = tenant.id

        if active_only:
            return self.project_repo.list_active(tenant_id=tenant_id)

        if tenant_id is not None:
            return self.project_repo.list_by_tenant(tenant_id)
        return self.project_repo.list()

    def delete_project(self, domain: str) -> None:
        """Delete a project and its cascade-managed dependents.

        Args:
            domain: Project domain identifier.

        Returns:
            None.

        Raises:
            ValidationError: If the domain is blank.
            ProjectNotFoundError: If no matching project exists.
        """
        try:
            project = self.get_project(domain)
            self.project_repo.delete(project.id)
            
            if self.audit_service:
                self.audit_service.record_action(
                    event_type="PROJECT_DELETED",
                    severity="WARNING",
                    message=f"Deleted project '{project.name}' with domain '{domain}'",
                    actor_source="api",
                    target_entity="project",
                    target_id=project.id,
                    tenant_id=project.tenant_id,
                    project_id=project.id,
                )
                
            self.session.commit()
        except Exception:
            try:
                self.session.rollback()
            except Exception:
                pass
            raise
