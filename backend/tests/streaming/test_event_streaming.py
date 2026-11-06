"""Tests for real-time WebSocket and SSE event streaming.

Tests cover:
1. Valid WebSocket authentication via initial message
2. Invalid WebSocket authentication rejection
3. Missing WebSocket authentication rejection
4. Valid SSE authentication (header fallback)
5. Tenant isolation (Tenant A does not receive Tenant B events)
6. Event delivery format (no raw headers, correct fields)
7. Broadcast failure handles gracefully (does not affect persistence)
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.enums import EventSeverity
from app.models.honey_token import HoneyToken
from app.models.user import User
from app.services.detection_event import DetectionEventService
from app.services.event_broadcaster import get_broadcaster
from tests.conftest import make_token

# Reset the singleton broadcaster between tests
@pytest.fixture(autouse=True)
def reset_broadcaster():
    broadcaster = get_broadcaster()
    broadcaster.reset()
    yield
    broadcaster.reset()


def test_websocket_auth_success(client: TestClient, admin_a: User):
    """Test WebSocket connects successfully with valid auth message."""
    jwt_token = make_token(admin_a)
    
    with client.websocket_connect("/api/v1/events/stream/ws") as websocket:
        # Initial message authentication
        websocket.send_json({"type": "auth", "token": jwt_token})
        
        # Should receive auth_success
        response = websocket.receive_json()
        assert response == {"type": "auth_success"}
        
        # Broadcaster should have 1 subscriber
        assert get_broadcaster().subscriber_count == 1


def test_websocket_auth_invalid(client: TestClient):
    """Test WebSocket disconnects if auth message is invalid."""
    with pytest.raises(Exception) as exc_info:
        with client.websocket_connect("/api/v1/events/stream/ws") as websocket:
            websocket.send_json({"type": "auth", "token": "invalid.token.here"})
            websocket.receive_json()  # Wait for close
            
    assert exc_info.type.__name__ == "WebSocketDisconnect"
    assert exc_info.value.code == 1008  # Policy Violation
    assert get_broadcaster().subscriber_count == 0


def test_websocket_auth_missing(client: TestClient):
    """Test WebSocket disconnects if auth message is completely missing (timeout)."""
    # The client websocket_connect will block, but we can't easily test timeout 
    # natively with TestClient without mocking asyncio.wait_for. 
    # Instead, send bad format:
    with pytest.raises(Exception) as exc_info:
        with client.websocket_connect("/api/v1/events/stream/ws") as websocket:
            websocket.send_json({"wrong": "format"})
            websocket.receive_json()
            
    assert exc_info.type.__name__ == "WebSocketDisconnect"
    assert exc_info.value.code == 1008
    assert get_broadcaster().subscriber_count == 0


@mock.patch("asyncio.wait_for")
def test_sse_auth_success(mock_wait_for, client: TestClient, admin_a: User):
    """Test SSE connects successfully with query param or header auth."""
    # Force the SSE generator to exit immediately when it waits for an event, cleanly closing the coro
    def _cancel_and_close(coro, timeout=None):
        if hasattr(coro, "close"):
            coro.close()
        raise asyncio.CancelledError()

    mock_wait_for.side_effect = _cancel_and_close
    
    jwt_token = make_token(admin_a)
    
    with client.stream(
        "GET",
        "/api/v1/events/stream/sse",
        headers={"Authorization": f"Bearer {jwt_token}"}
    ) as response:
        assert response.status_code == 200
    
    with client.stream(
        "GET",
        f"/api/v1/events/stream/sse?token={jwt_token}"
    ) as response2:
        assert response2.status_code == 200


def test_sse_auth_invalid(client: TestClient):
    """Test SSE rejects invalid auth."""
    response = client.get(
        "/api/v1/events/stream/sse?token=invalid.jwt",
    )
    assert response.status_code == 401


def test_tenant_isolation(
    client: TestClient, 
    db_session: Session, 
    admin_a: User, 
    admin_b: User, 
    token_a: HoneyToken, 
    token_b: HoneyToken
):
    """Test Tenant A only receives events for Tenant A."""
    jwt_a = make_token(admin_a)
    jwt_b = make_token(admin_b)
    
    from app.repositories.detection_event import DetectionEventRepository
    from app.repositories.honey_token import HoneyTokenRepository
    
    service = DetectionEventService(
        session=db_session,
        event_repo=DetectionEventRepository(db_session),
        token_repo=HoneyTokenRepository(db_session),
    )
    
    with client.websocket_connect("/api/v1/events/stream/ws") as ws_a, \
         client.websocket_connect("/api/v1/events/stream/ws") as ws_b:

        # Authenticate both
        ws_a.send_json({"type": "auth", "token": jwt_a})
        res_a = ws_a.receive_json()
        assert res_a == {"type": "auth_success"}

        ws_b.send_json({"type": "auth", "token": jwt_b})
        res_b = ws_b.receive_json()
        assert res_b == {"type": "auth_success"}

        # Fire event for Tenant A
        service.record_event(
            token_value=token_a.token_value,
            ip_address="1.1.1.1",
            request_path="/test",
            http_method="GET",
            severity=EventSeverity.HIGH,
        )

        # Fire event for Tenant B
        service.record_event(
            token_value=token_b.token_value,
            ip_address="2.2.2.2",
            request_path="/test",
            http_method="GET",
            severity=EventSeverity.HIGH,
        )

        # Tenant A should get ONLY the event for token_a (ip 1.1.1.1)
        event_a = ws_a.receive_json()
        assert event_a["ip_address"] == "1.1.1.1"
        assert event_a["honey_token_id"] == token_a.id
        assert "headers" not in event_a  # Enforce minimal payload constraint

        # Tenant B should get ONLY the event for token_b (ip 2.2.2.2)
        event_b = ws_b.receive_json()
        assert event_b["ip_address"] == "2.2.2.2"
        assert event_b["honey_token_id"] == token_b.id


def test_system_admin_receives_all(
    client: TestClient, 
    db_session: Session, 
    system_admin: User, 
    token_a: HoneyToken, 
    token_b: HoneyToken
):
    """Test SYSTEM_ADMIN receives events from all tenants."""
    jwt_sys = make_token(system_admin)
    
    from app.repositories.detection_event import DetectionEventRepository
    from app.repositories.honey_token import HoneyTokenRepository
    
    service = DetectionEventService(
        session=db_session,
        event_repo=DetectionEventRepository(db_session),
        token_repo=HoneyTokenRepository(db_session),
    )
    
    with client.websocket_connect("/api/v1/events/stream/ws") as ws:
        ws.send_json({"type": "auth", "token": jwt_sys})
        assert ws.receive_json() == {"type": "auth_success"}
        
        service.record_event(
            token_value=token_a.token_value,
            ip_address="1.1.1.1",
            request_path="/test",
            http_method="GET",
            severity=EventSeverity.HIGH,
        )
        
        service.record_event(
            token_value=token_b.token_value,
            ip_address="2.2.2.2",
            request_path="/test",
            http_method="GET",
            severity=EventSeverity.HIGH,
        )
        
        # Sys admin receives both
        event1 = ws.receive_json()
        event2 = ws.receive_json()
        
        ips = {event1["ip_address"], event2["ip_address"]}
        assert ips == {"1.1.1.1", "2.2.2.2"}


def test_broadcast_failure_does_not_rollback(
    db_session: Session, 
    token_a: HoneyToken, 
    caplog: pytest.LogCaptureFixture
):
    """Test that if broadcast throws an exception, the event remains persisted."""
    from app.repositories.detection_event import DetectionEventRepository
    from app.repositories.honey_token import HoneyTokenRepository
    
    service = DetectionEventService(
        session=db_session,
        event_repo=DetectionEventRepository(db_session),
        token_repo=HoneyTokenRepository(db_session),
    )
    
    # Mock publish to throw an error
    with mock.patch("app.services.event_broadcaster.EventBroadcaster.publish", side_effect=ValueError("Simulated broker failure")):
        with caplog.at_level(logging.WARNING):
            event = service.record_event(
                token_value=token_a.token_value,
                ip_address="8.8.8.8",
                request_path="/crash",
                http_method="GET",
                severity=EventSeverity.LOW,
            )
            
    # Event should be safely persisted and returned despite the broadcast exception
    assert event.id is not None
    assert event.ip_address == "8.8.8.8"
    
    # Ensure log captured the warning
    assert "Failed to broadcast detection event" in caplog.text


def test_disconnect_cleanup(client: TestClient, admin_a: User):
    """Test that when a client disconnects, their subscription is removed."""
    jwt_token = make_token(admin_a)
    
    broadcaster = get_broadcaster()
    
    # Connect
    with client.websocket_connect("/api/v1/events/stream/ws") as websocket:
        websocket.send_json({"type": "auth", "token": jwt_token})
        websocket.receive_json()
        assert broadcaster.subscriber_count == 1
        
    # Disconnect
    # FastAPI test client automatically handles disconnect on context manager exit,
    # but the async finally block in our handler needs time to run.
    # The subscriber count should eventually drop to 0.
    
    # NOTE: In test client environments, sometimes background tasks on context exit 
    # take a tiny event loop tick to finish. 
    # By forcing a ping or small sleep in real async we'd check, but test client blocks.
    # However, since TestClient throws WebSocketDisconnect inside the endpoint, the 
    # finally block executes immediately.
    assert broadcaster.subscriber_count == 0


def test_websocket_db_pool_zero_checkout(monkeypatch):
    """F-001: Test that active WebSocket streams do NOT hold checked-out connections in the pool."""
    from sqlalchemy import create_engine
    from sqlalchemy.pool import QueuePool
    from sqlalchemy.orm import sessionmaker
    from app.models.base import BaseModel
    from app.models.enums import Role
    from app.models.tenant import Tenant
    from app.core.security import get_password_hash
    from app.db.session import get_db
    from app.main import app

    qp_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=QueuePool,
        pool_size=2,
        max_overflow=0,
    )
    BaseModel.metadata.create_all(bind=qp_engine)
    TestingSession = sessionmaker(bind=qp_engine, autoflush=True)

    with TestingSession() as seed_session:
        tenant = Tenant(name="Pool Tenant", slug="pool-tenant", is_active=True)
        seed_session.add(tenant)
        seed_session.flush()
        user = User(
            email="pool@tenant.com",
            hashed_password=get_password_hash("password"),
            role=Role.TENANT_ADMIN,
            is_active=True,
            tenant_id=tenant.id,
        )
        seed_session.add(user)
        seed_session.commit()
        user_token = make_token(user)

    def _override():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    monkeypatch.setitem(app.dependency_overrides, get_db, _override)

    with TestClient(app, raise_server_exceptions=False) as tc:
        # Before connect: pool checkedout == 0
        assert qp_engine.pool.checkedout() == 0

        with tc.websocket_connect("/api/v1/events/stream/ws") as ws1, \
             tc.websocket_connect("/api/v1/events/stream/ws") as ws2:
            ws1.send_json({"type": "auth", "token": user_token})
            assert ws1.receive_json() == {"type": "auth_success"}

            ws2.send_json({"type": "auth", "token": user_token})
            assert ws2.receive_json() == {"type": "auth_success"}

            # Both websockets are actively streaming; pool checked-out connections must be 0!
            assert qp_engine.pool.checkedout() == 0

            # Normal DB operations must continue to succeed without pool starvation
            with TestingSession() as s:
                from sqlalchemy import text
                res = s.execute(text("SELECT 1")).scalar()
                assert res == 1

            # And after the query completes, checkedout returns to 0 even though both websockets are still streaming!
            assert qp_engine.pool.checkedout() == 0

            health_res = tc.get("/api/v1/health")
            assert health_res.status_code == 200

        # After disconnect, checkedout is still 0
        assert qp_engine.pool.checkedout() == 0

    qp_engine.dispose()


def test_websocket_rejection_inactive_user(client: TestClient, admin_a: User, db_session: Session):
    """Test WebSocket disconnects if user is inactive at connection time."""
    admin_a.is_active = False
    db_session.commit()
    jwt_token = make_token(admin_a)

    with pytest.raises(Exception) as exc_info:
        with client.websocket_connect("/api/v1/events/stream/ws") as websocket:
            websocket.send_json({"type": "auth", "token": jwt_token})
            websocket.receive_json()
    assert exc_info.type.__name__ == "WebSocketDisconnect"
    assert exc_info.value.code == 1008


def test_websocket_rejection_inactive_tenant(client: TestClient, admin_a: User, tenant_a, db_session: Session):
    """Test WebSocket disconnects if tenant is inactive at connection time."""
    tenant_a.is_active = False
    db_session.commit()
    jwt_token = make_token(admin_a)

    with pytest.raises(Exception) as exc_info:
        with client.websocket_connect("/api/v1/events/stream/ws") as websocket:
            websocket.send_json({"type": "auth", "token": jwt_token})
            websocket.receive_json()
    assert exc_info.type.__name__ == "WebSocketDisconnect"
    assert exc_info.value.code == 1008


def test_sse_rejection_inactive_user(client: TestClient, admin_a: User, db_session: Session):
    """Test SSE rejects inactive user with 401."""
    admin_a.is_active = False
    db_session.commit()
    jwt_token = make_token(admin_a)

    response = client.get(
        f"/api/v1/events/stream/sse?token={jwt_token}",
    )
    assert response.status_code == 401


def test_sse_rejection_inactive_tenant(client: TestClient, admin_a: User, tenant_a, db_session: Session):
    """Test SSE rejects inactive tenant with 401."""
    tenant_a.is_active = False
    db_session.commit()
    jwt_token = make_token(admin_a)

    response = client.get(
        f"/api/v1/events/stream/sse?token={jwt_token}",
    )
    assert response.status_code == 401


def test_websocket_mid_connection_user_deactivation(
    client: TestClient, admin_a: User, db_session: Session, monkeypatch
):
    """F-008: Test that mid-connection user deactivation terminates WebSocket with 1008."""
    import app.api.v1.events_stream as es_mod
    monkeypatch.setattr(es_mod, "REVALIDATION_INTERVAL_SECONDS", 0.05)

    jwt_token = make_token(admin_a)
    with pytest.raises(Exception) as exc_info:
        with client.websocket_connect("/api/v1/events/stream/ws") as websocket:
            websocket.send_json({"type": "auth", "token": jwt_token})
            assert websocket.receive_json() == {"type": "auth_success"}

            # Deactivate user in DB
            admin_a.is_active = False
            db_session.commit()

            # Revalidation should kick in after 50ms and close connection
            websocket.receive_text()

    assert exc_info.type.__name__ == "WebSocketDisconnect"
    assert exc_info.value.code == 1008


def test_websocket_mid_connection_token_revocation(
    client: TestClient, admin_a: User, db_session: Session, monkeypatch
):
    """F-008: Test that token version bump (revocation) terminates WebSocket with 1008."""
    import app.api.v1.events_stream as es_mod
    monkeypatch.setattr(es_mod, "REVALIDATION_INTERVAL_SECONDS", 0.05)

    jwt_token = make_token(admin_a)
    with pytest.raises(Exception) as exc_info:
        with client.websocket_connect("/api/v1/events/stream/ws") as websocket:
            websocket.send_json({"type": "auth", "token": jwt_token})
            assert websocket.receive_json() == {"type": "auth_success"}

            # Bump token version in DB (revocation)
            admin_a.token_version += 1
            db_session.commit()

            websocket.receive_text()

    assert exc_info.type.__name__ == "WebSocketDisconnect"
    assert exc_info.value.code == 1008


def test_websocket_mid_connection_tenant_deactivation(
    client: TestClient, admin_a: User, tenant_a, db_session: Session, monkeypatch
):
    """F-008: Test that tenant deactivation terminates WebSocket with 1008."""
    import app.api.v1.events_stream as es_mod
    monkeypatch.setattr(es_mod, "REVALIDATION_INTERVAL_SECONDS", 0.05)

    jwt_token = make_token(admin_a)
    with pytest.raises(Exception) as exc_info:
        with client.websocket_connect("/api/v1/events/stream/ws") as websocket:
            websocket.send_json({"type": "auth", "token": jwt_token})
            assert websocket.receive_json() == {"type": "auth_success"}

            # Deactivate tenant in DB
            tenant_a.is_active = False
            db_session.commit()

            websocket.receive_text()

    assert exc_info.type.__name__ == "WebSocketDisconnect"
    assert exc_info.value.code == 1008


def test_broadcaster_queue_overflow_drops_oldest(caplog: pytest.LogCaptureFixture):
    """Test that when a subscriber queue overflows, oldest events are dropped, retaining newest."""
    import asyncio
    from app.services.event_broadcaster import _safe_put

    queue: asyncio.Queue = asyncio.Queue(maxsize=3)

    with caplog.at_level(logging.WARNING):
        _safe_put(queue, {"id": 1}, 10)
        _safe_put(queue, {"id": 2}, 10)
        _safe_put(queue, {"id": 3}, 10)
        assert queue.qsize() == 3

        # Put 4th item, queue was full
        _safe_put(queue, {"id": 4}, 10)
        assert queue.qsize() == 3

        # Oldest item (id=1) should have been dropped
        items = [queue.get_nowait() for _ in range(3)]
        assert [item["id"] for item in items] == [2, 3, 4]
        assert "Event queue overflow for subscriber" in caplog.text


def test_broadcaster_graceful_shutdown():
    """F-022: Test that shutdown enqueues shutdown event to subscribers and marks shutting down."""
    import asyncio
    from app.services.event_broadcaster import EventBroadcaster

    broadcaster = EventBroadcaster()
    queue: asyncio.Queue = asyncio.Queue(maxsize=10)
    sub_id = broadcaster.subscribe(tenant_id=1, queue=queue)

    assert broadcaster.subscriber_count == 1
    assert not broadcaster.is_shutting_down

    broadcaster.shutdown()

    assert broadcaster.is_shutting_down
    assert broadcaster.subscriber_count == 0

    # Subscriber queue should have received the shutdown sentinel event
    shutdown_msg = queue.get_nowait()
    assert shutdown_msg["type"] == "shutdown"

    # Further publishes after shutdown should be silently ignored
    broadcaster.publish({"type": "detection_event"}, event_tenant_id=1)
    assert queue.empty()
