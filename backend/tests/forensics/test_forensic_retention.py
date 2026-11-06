"""Comprehensive forensic data integrity, retention, and immutability tests.

Tests verify:
1. Project deletion preserves historical DetectionEvents and keeps them queryable.
2. HoneyToken revocation preserves historical DetectionEvents.
3. HoneyToken rotation preserves historical DetectionEvents.
4. DetectionEvent cannot be modified in-place (ORM/Session immutability -> ForbiddenError).
5. DetectionEvent cannot be deleted (ORM/Session/Repo immutability -> ForbiddenError).
6. AuditLog cannot be modified or deleted (ORM/Session/Repo immutability -> ForbiddenError).
7. Administrative actions correctly populate actor_user_id with the acting user's ID.
8. Public ingestion does not fabricate an authenticated actor (actor_user_id is None).
9. Tenant isolation remains strictly intact for preserved forensic records.
10. SYSTEM_ADMIN forensic visibility remains global, explicit, and correct.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.auth_exceptions import ForbiddenError
from app.models.audit_log import AuditLog
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, HoneyTokenType, Role
from app.models.honey_token import HoneyToken
from app.models.project import Project
from app.models.tenant import Tenant
from app.models.user import User
from app.repositories.audit_log import AuditLogRepository
from app.repositories.detection_event import DetectionEventRepository
from app.repositories.honey_token import HoneyTokenRepository
from app.repositories.project import ProjectRepository
from app.services.audit_log import AuditLogService
from app.services.honey_token import HoneyTokenService
from app.services.project import ProjectService
from tests.conftest import auth_headers


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_detection_event(db_session: Session, token_a: HoneyToken) -> DetectionEvent:
    """Create a sample DetectionEvent for token_a."""
    event = DetectionEvent(
        honey_token_id=token_a.id,
        ip_address="198.51.100.42",
        request_path="/t/sample-token",
        http_method="GET",
        severity=EventSeverity.HIGH,
        user_agent="AttackerBot/1.0",
        headers={"Host": "alpha.example.com", "X-Forwarded-For": "198.51.100.42"},
    )
    db_session.add(event)
    db_session.flush()
    return event


# ---------------------------------------------------------------------------
# Scenario 1: Project Deletion Preserves DetectionEvents
# ---------------------------------------------------------------------------

def test_project_deletion_preserves_detection_events(
    db_session: Session,
    project_a: Project,
    token_a: HoneyToken,
    sample_detection_event: DetectionEvent,
    admin_a: User,
    tenant_a: Tenant,
) -> None:
    """Deleting a project deactivates it and its tokens, preserving DetectionEvents."""
    project_repo = ProjectRepository(db_session)
    audit_repo = AuditLogRepository(db_session)
    audit_service = AuditLogService(db_session, audit_repo, current_user=admin_a)
    project_service = ProjectService(
        session=db_session,
        current_user=admin_a,
        project_repo=project_repo,
        tenant_repo=None,
        audit_service=audit_service,
    )

    event_id = sample_detection_event.id
    token_id = token_a.id

    # Execute project deletion
    project_service.delete_project(project_a.domain)

    # 1. Project must be marked inactive (soft-deleted), not physically removed
    db_session.expire_all()
    reloaded_project = project_repo.get_by_id(project_a.id)
    assert reloaded_project is not None
    assert reloaded_project.is_active is False

    # 2. Associated token must be marked inactive
    token_repo = HoneyTokenRepository(db_session)
    reloaded_token = token_repo.get_by_id(token_id)
    assert reloaded_token is not None
    assert reloaded_token.is_active is False

    # 3. DetectionEvent MUST still exist in database
    event_repo = DetectionEventRepository(db_session)
    reloaded_event = event_repo.get_by_id(event_id)
    assert reloaded_event is not None
    assert reloaded_event.id == event_id
    assert reloaded_event.honey_token_id == token_id

    # 4. Tenant-scoped listing must still return the event
    tenant_events = event_repo.list_recent(tenant_id=tenant_a.id)
    assert any(e.id == event_id for e in tenant_events)

    # 5. Audit log must record the deletion with actor attribution
    audit_logs = db_session.query(AuditLog).filter_by(
        event_type="PROJECT_DELETED",
        target_entity="project",
        target_id=str(project_a.id),
    ).all()
    assert len(audit_logs) >= 1
    assert audit_logs[0].actor_user_id == admin_a.id


# ---------------------------------------------------------------------------
# Scenario 2: HoneyToken Revocation Preserves DetectionEvents
# ---------------------------------------------------------------------------

def test_honey_token_revocation_preserves_detection_events(
    db_session: Session,
    token_a: HoneyToken,
    sample_detection_event: DetectionEvent,
    admin_a: User,
) -> None:
    """Revoking a HoneyToken marks it inactive without affecting past DetectionEvents."""
    token_repo = HoneyTokenRepository(db_session)
    project_repo = ProjectRepository(db_session)
    audit_repo = AuditLogRepository(db_session)
    audit_service = AuditLogService(db_session, audit_repo, current_user=admin_a)
    token_service = HoneyTokenService(
        session=db_session,
        current_user=admin_a,
        token_repo=token_repo,
        project_repo=project_repo,
        audit_service=audit_service,
    )

    event_id = sample_detection_event.id

    # Revoke the token
    token_service.revoke_token(token_a.token_value)

    # 1. Token is inactive
    db_session.expire_all()
    reloaded_token = token_repo.get_by_id(token_a.id)
    assert reloaded_token is not None
    assert reloaded_token.is_active is False

    # 2. Historical DetectionEvent is preserved
    event_repo = DetectionEventRepository(db_session)
    reloaded_event = event_repo.get_by_id(event_id)
    assert reloaded_event is not None
    assert reloaded_event.id == event_id

    # 3. Audit log contains actor attribution
    audit_logs = db_session.query(AuditLog).filter_by(
        event_type="HONEY_TOKEN_REVOKED",
        target_id=str(token_a.id),
    ).all()
    assert len(audit_logs) >= 1
    assert audit_logs[0].actor_user_id == admin_a.id


# ---------------------------------------------------------------------------
# Scenario 3: HoneyToken Rotation Preserves DetectionEvents
# ---------------------------------------------------------------------------

def test_honey_token_rotation_preserves_detection_events(
    db_session: Session,
    token_a: HoneyToken,
    sample_detection_event: DetectionEvent,
    admin_a: User,
    tenant_a: Tenant,
) -> None:
    """Rotating a HoneyToken preserves old token's events and attributes new token."""
    token_repo = HoneyTokenRepository(db_session)
    project_repo = ProjectRepository(db_session)
    audit_repo = AuditLogRepository(db_session)
    audit_service = AuditLogService(db_session, audit_repo, current_user=admin_a)
    token_service = HoneyTokenService(
        session=db_session,
        current_user=admin_a,
        token_repo=token_repo,
        project_repo=project_repo,
        audit_service=audit_service,
    )

    old_token_val = token_a.token_value
    new_token_val = "new-rotated-token-secret-val"
    event_id = sample_detection_event.id

    new_token = token_service.rotate_token(old_token_val, new_token_val)

    # 1. Old token deactivated, new token active
    db_session.expire_all()
    old_token = token_repo.get_by_id(token_a.id)
    assert old_token.is_active is False
    assert new_token.is_active is True

    # 2. DetectionEvent remains bound to old token and intact
    event_repo = DetectionEventRepository(db_session)
    reloaded_event = event_repo.get_by_id(event_id)
    assert reloaded_event is not None
    assert reloaded_event.honey_token_id == token_a.id

    # 3. Preserved event is still queryable under tenant
    tenant_events = event_repo.list_recent(tenant_id=tenant_a.id)
    assert any(e.id == event_id for e in tenant_events)


# ---------------------------------------------------------------------------
# Scenario 4: DetectionEvent Cannot Be Modified (ORM Immutability)
# ---------------------------------------------------------------------------

def test_detection_event_cannot_be_modified(
    db_session: Session,
    sample_detection_event: DetectionEvent,
) -> None:
    """DetectionEvent records are immutable; modifications must raise ForbiddenError."""
    # Attempt to tamper with forensic properties inside a savepoint
    nested = db_session.begin_nested()
    sample_detection_event.ip_address = "10.0.0.99"
    sample_detection_event.severity = EventSeverity.LOW

    with pytest.raises(ForbiddenError, match="cannot be modified"):
        db_session.flush()

    nested.rollback()

    # Verify original values were untouched
    event_repo = DetectionEventRepository(db_session)
    original = event_repo.get_by_id(sample_detection_event.id)
    assert original is not None
    assert original.ip_address == "198.51.100.42"
    assert original.severity == EventSeverity.HIGH


# ---------------------------------------------------------------------------
# Scenario 5: DetectionEvent Cannot Be Deleted (ORM & Repo Immutability)
# ---------------------------------------------------------------------------

def test_detection_event_cannot_be_deleted_via_session(
    db_session: Session,
    sample_detection_event: DetectionEvent,
) -> None:
    """Session.delete() on a DetectionEvent must raise ForbiddenError."""
    nested = db_session.begin_nested()
    db_session.delete(sample_detection_event)

    with pytest.raises(ForbiddenError, match="cannot be deleted"):
        db_session.flush()

    nested.rollback()

    event_repo = DetectionEventRepository(db_session)
    assert event_repo.get_by_id(sample_detection_event.id) is not None


def test_detection_event_cannot_be_deleted_via_repository(
    db_session: Session,
    sample_detection_event: DetectionEvent,
) -> None:
    """DetectionEventRepository.delete() must raise ForbiddenError."""
    event_repo = DetectionEventRepository(db_session)

    with pytest.raises(ForbiddenError, match="cannot be deleted"):
        event_repo.delete(sample_detection_event.id)


# ---------------------------------------------------------------------------
# Scenario 6: AuditLog Cannot Be Modified or Deleted
# ---------------------------------------------------------------------------

def test_audit_log_cannot_be_modified(db_session: Session) -> None:
    """AuditLog records are immutable; in-place edits must raise ForbiddenError."""
    audit_log = AuditLog(
        event_type="SECURITY_ALERT",
        severity="HIGH",
        message="Suspicious activity detected",
    )
    db_session.add(audit_log)
    db_session.flush()

    nested = db_session.begin_nested()
    audit_log.message = "Nothing happened"

    with pytest.raises(ForbiddenError, match="cannot be modified"):
        db_session.flush()

    nested.rollback()


def test_audit_log_cannot_be_deleted_via_session(db_session: Session) -> None:
    """Session.delete() on an AuditLog must raise ForbiddenError."""
    audit_log = AuditLog(
        event_type="SECURITY_ALERT",
        severity="HIGH",
        message="Suspicious activity detected",
    )
    db_session.add(audit_log)
    db_session.flush()

    nested = db_session.begin_nested()
    db_session.delete(audit_log)

    with pytest.raises(ForbiddenError, match="cannot be deleted"):
        db_session.flush()

    nested.rollback()


def test_audit_log_cannot_be_deleted_via_repository(db_session: Session) -> None:
    """AuditLogRepository.delete() must raise ForbiddenError."""
    audit_repo = AuditLogRepository(db_session)
    audit_log = audit_repo.create(
        event_type="TEST_EVENT",
        severity="INFO",
        message="Audit record for delete test",
    )
    db_session.flush()

    with pytest.raises(ForbiddenError, match="cannot be deleted"):
        audit_repo.delete(audit_log.id)


# ---------------------------------------------------------------------------
# Scenario 7: Administrative Actions Correctly Attribute actor_user_id
# ---------------------------------------------------------------------------

def test_administrative_actions_attribute_actor_user_id(
    client: TestClient,
    admin_a: User,
    tenant_a: Tenant,
    db_session: Session,
) -> None:
    """Administrative API actions must log AuditLog entries with actor_user_id set."""
    headers = auth_headers(admin_a)

    # 1. Create a project via API
    resp = client.post(
        "/api/v1/projects",
        json={"name": "Audit Test Project", "domain": "audit-test.com", "tenant_slug": tenant_a.slug},
        headers=headers,
    )
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    # 2. Verify AuditLog for PROJECT_CREATED has actor_user_id
    db_session.expire_all()
    created_log = db_session.query(AuditLog).filter_by(
        event_type="PROJECT_CREATED",
        target_id=str(project_id),
    ).first()
    assert created_log is not None
    assert created_log.actor_user_id == admin_a.id
    assert created_log.tenant_id == tenant_a.id

    # 3. Generate a HoneyToken via API
    token_resp = client.post(
        f"/api/v1/projects/audit-test.com/honey-tokens/generate",
        json={"token_type": "API_KEY", "generator_params": {"key_prefix": "audit_"}},
        headers=headers,
    )
    assert token_resp.status_code == 201
    token_id = token_resp.json()["id"]

    db_session.expire_all()
    gen_log = db_session.query(AuditLog).filter_by(
        event_type="HONEY_TOKEN_GENERATED",
        target_id=str(token_id),
    ).first()
    assert gen_log is not None
    assert gen_log.actor_user_id == admin_a.id

    # 4. Delete the project via API
    del_resp = client.delete(f"/api/v1/projects/audit-test.com", headers=headers)
    assert del_resp.status_code == 204

    db_session.expire_all()
    del_log = db_session.query(AuditLog).filter_by(
        event_type="PROJECT_DELETED",
        target_id=str(project_id),
    ).first()
    assert del_log is not None
    assert del_log.actor_user_id == admin_a.id


# ---------------------------------------------------------------------------
# Scenario 8: Public Ingestion Does Not Fabricate Authenticated Actor
# ---------------------------------------------------------------------------

def test_public_ingestion_does_not_fabricate_actor(
    client: TestClient,
    token_a: HoneyToken,
    db_session: Session,
) -> None:
    """Public ingestion creates DetectionEvent without fabricating user authentication."""
    # Clear any preexisting detection events
    initial_event_count = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).count()

    # Trigger public URL token ingestion (unauthenticated)
    resp = client.get(f"/t/{token_a.token_value}", headers={"User-Agent": "Scanner/2.0"})
    assert resp.status_code == 204

    db_session.expire_all()
    new_event_count = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).count()
    assert new_event_count == initial_event_count + 1

    # Verify no audit log was created with a fabricated actor_user_id
    # Public ingestion events should NOT create user-attributed audit logs
    fabricated_logs = db_session.query(AuditLog).filter(
        AuditLog.event_type.like("%INGEST%"),
        AuditLog.actor_user_id.isnot(None),
    ).all()
    assert len(fabricated_logs) == 0


# ---------------------------------------------------------------------------
# Scenario 9: Tenant Isolation Intact for Preserved Forensic Records
# ---------------------------------------------------------------------------

def test_tenant_isolation_intact_for_preserved_records(
    db_session: Session,
    project_a: Project,
    project_b: Project,
    token_a: HoneyToken,
    token_b: HoneyToken,
    admin_a: User,
    admin_b: User,
    tenant_a: Tenant,
    tenant_b: Tenant,
) -> None:
    """Soft-deleted/preserved events for Tenant A must never appear in Tenant B queries."""
    # Create detection events for both tenants
    event_a = DetectionEvent(
        honey_token_id=token_a.id,
        ip_address="198.51.100.10",
        request_path="/t/token-a",
        http_method="GET",
        severity=EventSeverity.CRITICAL,
    )
    event_b = DetectionEvent(
        honey_token_id=token_b.id,
        ip_address="203.0.113.20",
        request_path="/t/token-b",
        http_method="GET",
        severity=EventSeverity.LOW,
    )
    db_session.add_all([event_a, event_b])
    db_session.flush()

    # Soft delete Project A
    audit_repo = AuditLogRepository(db_session)
    audit_service = AuditLogService(db_session, audit_repo, current_user=admin_a)
    project_service = ProjectService(
        session=db_session,
        current_user=admin_a,
        project_repo=ProjectRepository(db_session),
        tenant_repo=None,
        audit_service=audit_service,
    )
    project_service.delete_project(project_a.domain)

    # Tenant B queries recent events
    event_repo = DetectionEventRepository(db_session)
    events_for_tenant_b = event_repo.list_recent(tenant_id=tenant_b.id)

    # Tenant B must see their own event, but NEVER Tenant A's preserved event
    tenant_b_ids = [e.id for e in events_for_tenant_b]
    assert event_b.id in tenant_b_ids
    assert event_a.id not in tenant_b_ids

    # Tenant A queries recent events -> still sees their preserved event
    events_for_tenant_a = event_repo.list_recent(tenant_id=tenant_a.id)
    tenant_a_ids = [e.id for e in events_for_tenant_a]
    assert event_a.id in tenant_a_ids
    assert event_b.id not in tenant_a_ids


# ---------------------------------------------------------------------------
# Scenario 10: SYSTEM_ADMIN Forensic Visibility Is Global
# ---------------------------------------------------------------------------

def test_system_admin_forensic_visibility_is_global(
    db_session: Session,
    project_a: Project,
    project_b: Project,
    token_a: HoneyToken,
    token_b: HoneyToken,
    system_admin: User,
    admin_a: User,
    tenant_a: Tenant,
) -> None:
    """SYSTEM_ADMIN retains global visibility across all tenants including preserved records."""
    event_a = DetectionEvent(
        honey_token_id=token_a.id,
        ip_address="198.51.100.11",
        request_path="/t/token-a-sys",
        http_method="GET",
        severity=EventSeverity.HIGH,
    )
    event_b = DetectionEvent(
        honey_token_id=token_b.id,
        ip_address="203.0.113.22",
        request_path="/t/token-b-sys",
        http_method="GET",
        severity=EventSeverity.MEDIUM,
    )
    db_session.add_all([event_a, event_b])
    db_session.flush()

    # Soft-delete Project A
    audit_repo = AuditLogRepository(db_session)
    audit_service = AuditLogService(db_session, audit_repo, current_user=admin_a)
    project_service = ProjectService(
        session=db_session,
        current_user=admin_a,
        project_repo=ProjectRepository(db_session),
        tenant_repo=None,
        audit_service=audit_service,
    )
    project_service.delete_project(project_a.domain)

    # System admin query (tenant_id=None)
    event_repo = DetectionEventRepository(db_session)
    global_events = event_repo.list_recent(tenant_id=None)
    global_event_ids = [e.id for e in global_events]

    # Both Tenant A's preserved event and Tenant B's active event must be visible
    assert event_a.id in global_event_ids
    assert event_b.id in global_event_ids

    # Global count check
    total_count = event_repo.count(tenant_id=None)
    assert total_count >= 2
