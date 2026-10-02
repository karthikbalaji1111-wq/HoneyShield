"""Phase 6: Database performance, SQL statistics, pagination, timeout and connection pool tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import set_query_timeout
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, HoneyTokenType, Role
from app.models.honey_token import HoneyToken
from app.models.project import Project
from app.models.tenant import Tenant
from app.models.user import User
from app.repositories.detection_event import DetectionEventRepository
from app.repositories.honey_token import HoneyTokenRepository
from app.services.detection_event import DetectionEventService
from tests.conftest import auth_headers


# ---------------------------------------------------------------------------
# Test 1: Explicit Connection Pool & Statement Timeout Settings (F-017, F-018)
# ---------------------------------------------------------------------------

def test_connection_pool_and_timeout_settings(db_session: Session) -> None:
    """Verify that connection pool policy and statement timeouts are configured as required."""
    settings = get_settings()
    assert settings.db_pool_size == 10
    assert settings.db_max_overflow == 10
    assert settings.db_pool_timeout == 10.0
    assert settings.db_pool_recycle == 1800
    assert settings.db_statement_timeout_ms == 5000
    assert settings.db_analytics_timeout_ms == 15000

    # Test set_query_timeout context manager executes cleanly
    with set_query_timeout(db_session, timeout_ms=settings.db_analytics_timeout_ms):
        # On SQLite dialect, set_query_timeout safely passes through without syntax error
        result = db_session.query(Tenant).all()
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Test 2: Single-Pass SQL Statistics (F-002)
# ---------------------------------------------------------------------------

def test_tenant_statistics_single_pass_sql(
    db_session: Session,
    tenant_a: Tenant,
    tenant_b: Tenant,
    token_a: HoneyToken,
    token_b: HoneyToken,
) -> None:
    """Verify that count_summary computes total and today in a single SQL aggregation."""
    repo = DetectionEventRepository(db_session)
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1, hours=2)

    # Tenant A events: 2 today, 1 yesterday = 3 total
    event_a1 = DetectionEvent(
        honey_token_id=token_a.id,
        ip_address="198.51.100.1",
        request_path="/t/token-a-secret-value",
        http_method="GET",
        severity=EventSeverity.HIGH,
        triggered_at=now,
    )
    event_a2 = DetectionEvent(
        honey_token_id=token_a.id,
        ip_address="198.51.100.2",
        request_path="/t/token-a-secret-value",
        http_method="GET",
        severity=EventSeverity.HIGH,
        triggered_at=now,
    )
    event_a3 = DetectionEvent(
        honey_token_id=token_a.id,
        ip_address="198.51.100.3",
        request_path="/t/token-a-secret-value",
        http_method="GET",
        severity=EventSeverity.LOW,
        triggered_at=yesterday,
    )

    # Tenant B events: 1 today = 1 total
    event_b1 = DetectionEvent(
        honey_token_id=token_b.id,
        ip_address="203.0.113.1",
        request_path="/t/token-b-secret-value",
        http_method="GET",
        severity=EventSeverity.CRITICAL,
        triggered_at=now,
    )

    db_session.add_all([event_a1, event_a2, event_a3, event_b1])
    db_session.flush()

    # Query Tenant A summary
    total_a, today_a = repo.count_summary(tenant_id=tenant_a.id)
    assert total_a == 3
    assert today_a == 2

    # Query Tenant B summary
    total_b, today_b = repo.count_summary(tenant_id=tenant_b.id)
    assert total_b == 1
    assert today_b == 1

    # Verify global summary (SYSTEM_ADMIN)
    total_global, today_global = repo.count_summary(tenant_id=None)
    assert total_global == 4
    assert today_global == 3

    # Verify DetectionEventService.get_statistics uses count_summary
    token_repo = HoneyTokenRepository(db_session)
    service = DetectionEventService(
        session=db_session,
        event_repo=repo,
        token_repo=token_repo,
        current_user=User(
            id=99, email="admin@tenant-a.com", hashed_password="x",
            role=Role.TENANT_ADMIN, is_active=True, tenant_id=tenant_a.id
        ),
    )
    stats = service.get_statistics()
    assert stats["total_events"] == 3
    assert stats["today_events"] == 2


# ---------------------------------------------------------------------------
# Test 3: Tenants Endpoint Pagination (F-016)
# ---------------------------------------------------------------------------

def test_tenants_pagination(
    client: TestClient,
    system_admin: User,
    db_session: Session,
) -> None:
    """Verify limit, offset, and deterministic tie-breaking on /tenants."""
    headers = auth_headers(system_admin)

    # Create additional tenants with deterministic names
    for i in range(5):
        t = Tenant(name=f"Paginated Tenant {i:02d}", slug=f"paginated-tenant-{i:02d}", is_active=True)
        db_session.add(t)
    db_session.flush()

    # Page 1: limit 2, offset 0
    resp1 = client.get("/api/v1/tenants?limit=2&offset=0", headers=headers)
    assert resp1.status_code == 200
    page1 = resp1.json()
    assert len(page1) == 2

    # Page 2: limit 2, offset 2
    resp2 = client.get("/api/v1/tenants?limit=2&offset=2", headers=headers)
    assert resp2.status_code == 200
    page2 = resp2.json()
    assert len(page2) == 2
    # Ensure no overlap between page 1 and page 2
    page1_ids = {item["id"] for item in page1}
    page2_ids = {item["id"] for item in page2}
    assert page1_ids.isdisjoint(page2_ids)

    # Offset past total items
    resp_empty = client.get("/api/v1/tenants?limit=2&offset=9999", headers=headers)
    assert resp_empty.status_code == 200
    assert resp_empty.json() == []

    # Limit exceeding max allowed (100)
    resp_invalid = client.get("/api/v1/tenants?limit=101", headers=headers)
    assert resp_invalid.status_code == 422


# ---------------------------------------------------------------------------
# Test 4: Projects Endpoint Pagination (F-016)
# ---------------------------------------------------------------------------

def test_projects_pagination(
    client: TestClient,
    admin_a: User,
    tenant_a: Tenant,
    db_session: Session,
) -> None:
    """Verify limit, offset, and deterministic tie-breaking on /projects."""
    headers = auth_headers(admin_a)

    for i in range(4):
        p = Project(
            tenant_id=tenant_a.id,
            name=f"Subproject {i:02d}",
            domain=f"sub{i}.tenant-a.com",
            is_active=True,
        )
        db_session.add(p)
    db_session.flush()

    # Page 1: limit 2, offset 0
    resp1 = client.get("/api/v1/projects?limit=2&offset=0", headers=headers)
    assert resp1.status_code == 200
    page1 = resp1.json()
    assert len(page1) == 2

    # Page 2: limit 2, offset 2
    resp2 = client.get("/api/v1/projects?limit=2&offset=2", headers=headers)
    assert resp2.status_code == 200
    page2 = resp2.json()
    assert len(page2) == 2
    assert {p["id"] for p in page1}.isdisjoint({p["id"] for p in page2})

    # Limit validation
    resp_invalid = client.get("/api/v1/projects?limit=101", headers=headers)
    assert resp_invalid.status_code == 422


# ---------------------------------------------------------------------------
# Test 5: HoneyTokens Endpoint Pagination and Tenant Isolation (F-016, F-023)
# ---------------------------------------------------------------------------

def test_honey_tokens_pagination_and_sql_tenant_isolation(
    client: TestClient,
    admin_a: User,
    admin_b: User,
    project_a: Project,
    project_b: Project,
    db_session: Session,
) -> None:
    """Verify HoneyTokens pagination and strict SQL tenant isolation without in-memory leak."""
    headers_a = auth_headers(admin_a)

    # Create 3 tokens for Tenant A and 3 tokens for Tenant B
    for i in range(3):
        t_a = HoneyToken(
            project_id=project_a.id,
            token_type=HoneyTokenType.API_KEY,
            token_value=f"token-a-secret-extra-{i}",
            label=f"Token A {i}",
            is_active=True,
        )
        t_b = HoneyToken(
            project_id=project_b.id,
            token_type=HoneyTokenType.API_KEY,
            token_value=f"token-b-secret-extra-{i}",
            label=f"Token B {i}",
            is_active=True,
        )
        db_session.add_all([t_a, t_b])
    db_session.flush()

    # Tenant A lists tokens with pagination
    resp_a_p1 = client.get("/api/v1/honey-tokens?limit=2&offset=0", headers=headers_a)
    assert resp_a_p1.status_code == 200
    page_a1 = resp_a_p1.json()
    assert len(page_a1) == 2

    # Verify that NONE of Tenant B's tokens leak to Tenant A
    for token in page_a1:
        assert token["project_id"] == project_a.id

    # Tenant A asks for offset past their token count (existing token_a + 3 created = 4)
    resp_a_empty = client.get("/api/v1/honey-tokens?limit=10&offset=4", headers=headers_a)
    assert resp_a_empty.status_code == 200
    assert resp_a_empty.json() == []

    # Limit validation
    resp_invalid = client.get("/api/v1/honey-tokens?limit=101", headers=headers_a)
    assert resp_invalid.status_code == 422


# ---------------------------------------------------------------------------
# Test 6: Users Endpoint Pagination (F-016)
# ---------------------------------------------------------------------------

def test_users_pagination(
    client: TestClient,
    admin_a: User,
    tenant_a: Tenant,
    db_session: Session,
) -> None:
    """Verify limit, offset, and max validation on /users."""
    headers = auth_headers(admin_a)

    for i in range(3):
        u = User(
            email=f"paged-user-{i}@tenant-a.com",
            hashed_password="hash",
            role=Role.TENANT_USER,
            is_active=True,
            tenant_id=tenant_a.id,
        )
        db_session.add(u)
    db_session.flush()

    # Page 1
    resp1 = client.get("/api/v1/users?limit=2&offset=0", headers=headers)
    assert resp1.status_code == 200
    p1 = resp1.json()
    assert len(p1) == 2

    # Page 2
    resp2 = client.get("/api/v1/users?limit=2&offset=2", headers=headers)
    assert resp2.status_code == 200
    p2 = resp2.json()
    assert len(p2) >= 1
    assert {u["id"] for u in p1}.isdisjoint({u["id"] for u in p2})

    # Limit validation
    resp_invalid = client.get("/api/v1/users?limit=101", headers=headers)
    assert resp_invalid.status_code == 422


# ---------------------------------------------------------------------------
# Test 7: Detection Events Keyset Cursor and Offset Pagination (F-016)
# ---------------------------------------------------------------------------

def test_detection_events_keyset_cursor_and_offset_pagination(
    client: TestClient,
    admin_a: User,
    token_a: HoneyToken,
    db_session: Session,
) -> None:
    """Verify offset and keyset cursor pagination on detection events."""
    headers = auth_headers(admin_a)
    now = datetime.now(timezone.utc)

    # Seed 5 detection events with distinct timestamps and deterministic order
    events = []
    for i in range(5):
        e = DetectionEvent(
            honey_token_id=token_a.id,
            ip_address=f"198.51.100.{10 + i}",
            request_path="/t/token-a-secret-value",
            http_method="GET",
            severity=EventSeverity.MEDIUM,
            triggered_at=now - timedelta(minutes=5 - i),
        )
        events.append(e)
    db_session.add_all(events)
    db_session.flush()

    # Page 1 via limit:
    resp1 = client.get(f"/api/v1/detection-events?token_value={token_a.token_value}&limit=2", headers=headers)
    assert resp1.status_code == 200
    p1 = resp1.json()
    assert len(p1) == 2

    # Keyset cursor pagination: fetch next page with cursor = last ID from page 1
    cursor_id = p1[-1]["id"]
    resp_cursor = client.get(
        f"/api/v1/detection-events?token_value={token_a.token_value}&limit=2&cursor={cursor_id}",
        headers=headers,
    )
    assert resp_cursor.status_code == 200
    p2_cursor = resp_cursor.json()
    assert len(p2_cursor) == 2
    # Ensure all events in p2_cursor have id < cursor_id
    for ev in p2_cursor:
        assert ev["id"] < cursor_id

    # Offset pagination: limit 2, offset 2
    resp_offset = client.get(
        f"/api/v1/detection-events?token_value={token_a.token_value}&limit=2&offset=2",
        headers=headers,
    )
    assert resp_offset.status_code == 200
    p2_offset = resp_offset.json()
    assert len(p2_offset) == 2
    assert {e["id"] for e in p1}.isdisjoint({e["id"] for e in p2_offset})

    # Limit validation (max 1000)
    resp_invalid = client.get("/api/v1/detection-events?limit=1001", headers=headers)
    assert resp_invalid.status_code == 422


# ---------------------------------------------------------------------------
# Test 8: Threat Timeline Pagination (F-016)
# ---------------------------------------------------------------------------

def test_threat_timeline_pagination(
    client: TestClient,
    admin_a: User,
    token_a: HoneyToken,
    db_session: Session,
) -> None:
    """Verify limit and offset pagination on /threats/timeline/{ip_address}."""
    headers = auth_headers(admin_a)
    target_ip = "198.51.100.99"
    now = datetime.now(timezone.utc)

    for i in range(4):
        e = DetectionEvent(
            honey_token_id=token_a.id,
            ip_address=target_ip,
            request_path="/t/token-a-secret-value",
            http_method="GET",
            severity=EventSeverity.HIGH,
            triggered_at=now - timedelta(minutes=i),
        )
        db_session.add(e)
    db_session.flush()

    # Timeline page 1: limit 2, offset 0
    resp1 = client.get(f"/api/v1/threats/timeline/{target_ip}?limit=2&offset=0", headers=headers)
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert len(data1["events"]) == 2

    # Timeline page 2: limit 2, offset 2
    resp2 = client.get(f"/api/v1/threats/timeline/{target_ip}?limit=2&offset=2", headers=headers)
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2["events"]) == 2

    # Limit validation (max 500)
    resp_invalid = client.get(f"/api/v1/threats/timeline/{target_ip}?limit=501", headers=headers)
    assert resp_invalid.status_code == 422
