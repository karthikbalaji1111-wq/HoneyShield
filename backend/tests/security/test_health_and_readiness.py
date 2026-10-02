"""Focused security tests for Health, Readiness & Deployment Probes (Phase 9).

Covers:
- Liveness contract (independent of database availability)
- Readiness contract (reflects database availability and migration status)
- Failure simulation and recovery (200 -> 503 -> 200)
- Zero sensitive data exposure in health/readiness responses
- Rate-limiting exemptions for orchestrator and balancer probes
- Connection pool safety (no leaked sessions on repeated probes)
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from app.core.config import get_settings
from app.core.rate_limit import reset_all_limiters
from app.db.session import engine, get_db
from app.main import app


@pytest.fixture(autouse=True)
def _reset_limiters():
    reset_all_limiters()
    yield
    reset_all_limiters()


class TestLivenessContract:
    """Test process liveness contract across all canonical endpoints."""

    def test_root_health_returns_200_without_auth(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data == {"status": "healthy"}

    def test_v1_health_returns_200_without_auth(self, client: TestClient):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data == {"status": "healthy"}

    def test_liveness_succeeds_even_when_database_is_down(self, client: TestClient):
        """Liveness probe must remain dependency-independent and return 200 when DB is unavailable."""
        with patch("app.db.session.engine.connect", side_effect=OperationalError("DB down", None, Exception())):
            resp_root = client.get("/health")
            assert resp_root.status_code == 200
            assert resp_root.json() == {"status": "healthy"}

            resp_v1 = client.get("/api/v1/health")
            assert resp_v1.status_code == 200
            assert resp_v1.json() == {"status": "healthy"}

    def test_liveness_exempt_from_rate_limiting(self, client: TestClient):
        """Load balancers and container monitors must never be throttled on liveness."""
        for _ in range(70):
            resp = client.get("/health")
            assert resp.status_code == 200


class TestReadinessContract:
    """Test readiness contract reflecting database dependencies and migrations."""

    def test_readiness_returns_200_when_database_and_migrations_ready(self, client: TestClient):
        """When database is healthy and alembic migration head matches, returns 200 ready."""
        mock_session = MagicMock()
        # Mock SELECT 1 and SELECT version_num
        mock_result = MagicMock()
        mock_result.scalars.return_value = ["20261002_01"]
        mock_session.execute.return_value = mock_result

        def mock_get_db():
            yield mock_session

        app.dependency_overrides[get_db] = mock_get_db
        try:
            with patch("alembic.script.ScriptDirectory.get_heads", return_value=["20261002_01"]):
                resp_v1 = client.get("/api/v1/ready")
                assert resp_v1.status_code == 200
                assert resp_v1.json() == {"status": "ready"}

                resp_root = client.get("/ready")
                assert resp_root.status_code == 200
                assert resp_root.json() == {"status": "ready"}
        finally:
            app.dependency_overrides.pop(get_db, None)

    def test_readiness_returns_503_when_database_is_unavailable(self, client: TestClient):
        """When database connection fails, returns 503 not_ready."""
        mock_session = MagicMock()
        mock_session.execute.side_effect = OperationalError("connection refused", None, Exception("TCP connection failed"))

        def mock_get_db():
            yield mock_session

        app.dependency_overrides[get_db] = mock_get_db
        try:
            resp = client.get("/api/v1/ready")
            assert resp.status_code == 503
            assert resp.json() == {"status": "not_ready"}
            # Ensure no internal error strings or passwords leaked in response body
            body_str = resp.text.lower()
            assert "refused" not in body_str
            assert "exception" not in body_str
            assert "traceback" not in body_str
            assert "postgresql" not in body_str
        finally:
            app.dependency_overrides.pop(get_db, None)

    def test_readiness_returns_503_when_migrations_mismatched(self, client: TestClient):
        """When database is connected but migration head is not applied, returns 503 not_ready."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        # Database has older revision
        mock_result.scalars.return_value = ["20260918_01"]
        mock_session.execute.return_value = mock_result

        def mock_get_db():
            yield mock_session

        app.dependency_overrides[get_db] = mock_get_db
        try:
            with patch("alembic.script.ScriptDirectory.get_heads", return_value=["20261002_01"]):
                resp = client.get("/api/v1/ready")
                assert resp.status_code == 503
                assert resp.json() == {"status": "not_ready"}
        finally:
            app.dependency_overrides.pop(get_db, None)

    def test_readiness_returns_503_on_arbitrary_internal_error(self, client: TestClient):
        """Readiness check must safely translate unexpected exceptions into 503, never 500."""
        mock_session = MagicMock()
        mock_session.execute.side_effect = RuntimeError("Unexpected internal filesystem failure")

        def mock_get_db():
            yield mock_session

        app.dependency_overrides[get_db] = mock_get_db
        try:
            resp = client.get("/api/v1/ready")
            assert resp.status_code == 503
            assert resp.json() == {"status": "not_ready"}
            assert "unexpected" not in resp.text.lower()
        finally:
            app.dependency_overrides.pop(get_db, None)

    def test_readiness_failure_simulation_and_recovery(self, client: TestClient):
        """Simulate A: healthy -> B: failure -> C: restored recovery cycle."""
        mock_session = MagicMock()
        healthy_result = MagicMock()
        healthy_result.scalars.return_value = ["20261002_01"]

        # Phase A: Available
        mock_session.execute.return_value = healthy_result

        def mock_get_db():
            yield mock_session

        app.dependency_overrides[get_db] = mock_get_db
        try:
            with patch("alembic.script.ScriptDirectory.get_heads", return_value=["20261002_01"]):
                # Step A: 200
                resp_a = client.get("/api/v1/ready")
                assert resp_a.status_code == 200
                assert resp_a.json() == {"status": "ready"}

                # Step B: DB down -> 503
                mock_session.execute.side_effect = OperationalError("server disconnected", None, Exception())
                resp_b = client.get("/api/v1/ready")
                assert resp_b.status_code == 503
                assert resp_b.json() == {"status": "not_ready"}

                # Process liveness remains 200 during DB downtime
                assert client.get("/health").status_code == 200

                # Step C: DB restored -> 200
                mock_session.execute.side_effect = None
                mock_session.execute.return_value = healthy_result
                resp_c = client.get("/api/v1/ready")
                assert resp_c.status_code == 200
                assert resp_c.json() == {"status": "ready"}
        finally:
            app.dependency_overrides.pop(get_db, None)

    def test_readiness_exempt_from_rate_limiting(self, client: TestClient):
        """Repeated rapid readiness queries must never return 429."""
        mock_session = MagicMock()
        healthy_result = MagicMock()
        healthy_result.scalars.return_value = ["20261002_01"]
        mock_session.execute.return_value = healthy_result

        def mock_get_db():
            yield mock_session

        app.dependency_overrides[get_db] = mock_get_db
        try:
            with patch("alembic.script.ScriptDirectory.get_heads", return_value=["20261002_01"]):
                for _ in range(70):
                    resp = client.get("/api/v1/ready")
                    assert resp.status_code != 429
                    assert resp.status_code == 200
        finally:
            app.dependency_overrides.pop(get_db, None)


class TestConnectionPoolSafety:
    """Test that readiness checks do not leak connections or exhaust pools."""

    def test_readiness_releases_database_session(self, client: TestClient):
        close_called = []
        rollback_called = []

        class MockSession:
            def execute(self, stmt):
                res = MagicMock()
                res.scalars.return_value = ["20261002_01"]
                return res

            def rollback(self):
                rollback_called.append(True)

            def close(self):
                close_called.append(True)

        def mock_get_db():
            s = MockSession()
            try:
                yield s
            finally:
                s.rollback()
                s.close()

        app.dependency_overrides[get_db] = mock_get_db
        try:
            with patch("alembic.script.ScriptDirectory.get_heads", return_value=["20261002_01"]):
                for _ in range(10):
                    resp = client.get("/api/v1/ready")
                    assert resp.status_code == 200

            assert len(close_called) == 10, "Every readiness request must cleanly close its session"
            assert len(rollback_called) == 10
        finally:
            app.dependency_overrides.pop(get_db, None)
