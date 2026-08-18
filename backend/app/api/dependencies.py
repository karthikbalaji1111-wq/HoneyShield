"""FastAPI dependency providers for application services."""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.repositories.audit_log import AuditLogRepository
from app.repositories.detection_event import DetectionEventRepository
from app.repositories.honey_token import HoneyTokenRepository
from app.repositories.project import ProjectRepository
from app.repositories.tenant import TenantRepository
from app.services.audit_log import AuditLogService
from app.services.detection_event import DetectionEventService
from app.services.honey_token import HoneyTokenService
from app.services.project import ProjectService
from app.services.tenant import TenantService
from app.services.threat_intelligence import ThreatIntelligenceService

SessionDependency = Annotated[Session, Depends(get_db)]


def get_audit_log_service(session: SessionDependency) -> AuditLogService:
    """Provide an audit-log service using the request-scoped session."""
    return AuditLogService(session=session, audit_repo=AuditLogRepository(session))


def get_tenant_service(session: SessionDependency) -> TenantService:
    """Provide a tenant service using the request-scoped database session."""
    return TenantService(
        session=session, 
        tenant_repo=TenantRepository(session),
        audit_service=get_audit_log_service(session)
    )


def get_project_service(session: SessionDependency) -> ProjectService:
    """Provide a project service using the request-scoped database session."""
    return ProjectService(
        session=session,
        project_repo=ProjectRepository(session),
        tenant_repo=TenantRepository(session),
        audit_service=get_audit_log_service(session)
    )


def get_honey_token_service(session: SessionDependency) -> HoneyTokenService:
    """Provide a honey-token service using the request-scoped session."""
    return HoneyTokenService(
        session=session,
        token_repo=HoneyTokenRepository(session),
        project_repo=ProjectRepository(session),
        audit_service=get_audit_log_service(session)
    )


def get_detection_event_service(session: SessionDependency) -> DetectionEventService:
    """Provide a detection-event service using the request-scoped session."""
    return DetectionEventService(
        session=session,
        event_repo=DetectionEventRepository(session),
        token_repo=HoneyTokenRepository(session),
    )


def get_threat_intelligence_service(
    session: SessionDependency,
) -> ThreatIntelligenceService:
    """Provide a threat-intelligence service using the request-scoped session."""
    return ThreatIntelligenceService(
        session=session,
        event_repo=DetectionEventRepository(session),
    )

