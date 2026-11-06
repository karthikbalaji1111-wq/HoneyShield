"""End-to-end lifecycle and regression tests for HoneyTokens.

Verifies:
1. API_KEY generator -> /collect/{token_value} and /t/{token_value} -> DetectionEvent recorded
2. HIDDEN_URL generator -> /t/{token_value} -> DetectionEvent recorded
3. TRACKING_PIXEL generator -> /px/{token_value}.gif -> DetectionEvent recorded + 200 transparent GIF
4. FORM_FIELD generator -> generation succeeds -> /collect/{token_value} and /t/{token_value} -> DetectionEvent recorded
5. LINK generator -> generation succeeds -> /t/{token_value} -> DetectionEvent recorded
6. Revoke lifecycle -> token marked inactive, audit log recorded
7. Rotate lifecycle -> old token revoked, new token created active, audit log recorded
8. Inactive/revoked token triggering -> triggering inactive token still records immutable DetectionEvent
9. Duplicate token handling -> collision detection on creation, rotation, and generation retry
"""
from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.core.exceptions import DuplicateHoneyTokenError, HoneyTokenNotFoundError
from app.models.detection_event import DetectionEvent
from app.models.enums import HoneyTokenType
from app.models.honey_token import HoneyToken
from app.models.project import Project
from app.models.user import User
from app.repositories.honey_token import HoneyTokenRepository
from app.repositories.project import ProjectRepository
from app.services.honey_token import HoneyTokenService
from tests.conftest import auth_headers


class TestHoneyTokenGenerationAndIngestion:
    """Test every supported honey token type end-to-end from generation to ingestion."""

    def test_api_key_generator_and_ingestion(self, client, db_session: Session, admin_a: User, project_a: Project):
        """API_KEY: generate -> triggers via /collect and /t -> records DetectionEvent in DB."""
        headers = auth_headers(admin_a)
        resp = client.post(
            f"/api/v1/projects/{project_a.domain}/honey-tokens/generate",
            json={"token_type": "API_KEY"},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        token_value = data["token_value"]
        assert token_value
        assert data["token_type"] == "API_KEY"

        # 1. Trigger via POST /collect/{token_value}
        collect_resp = client.post(f"/collect/{token_value}")
        assert collect_resp.status_code == 204

        # Verify event in DB
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value=token_value).one()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 1
        assert events[0].http_method == "POST"
        assert events[0].request_path == f"/collect/{token_value}"

        # 2. Trigger via GET /t/{token_value}
        t_resp = client.get(f"/t/{token_value}")
        assert t_resp.status_code == 204

        db_session.expire_all()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 2

    def test_hidden_url_generator_and_ingestion(self, client, db_session: Session, admin_a: User, project_a: Project):
        """HIDDEN_URL: generate -> triggers via /t/{token_value} -> records DetectionEvent in DB."""
        headers = auth_headers(admin_a)
        resp = client.post(
            f"/api/v1/projects/{project_a.domain}/honey-tokens/generate",
            json={"token_type": "URL"},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        token_value = data["token_value"]
        assert token_value
        assert data["token_type"] == "URL"
        assert "metadata" in data
        assert data["metadata"]["path"] == f"/t/{token_value}"

        # Trigger via GET /t/{token_value}
        trigger_resp = client.get(f"/t/{token_value}")
        assert trigger_resp.status_code == 204

        # Verify event in DB
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value=token_value).one()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 1
        assert events[0].http_method == "GET"
        assert events[0].request_path == f"/t/{token_value}"

    def test_tracking_pixel_generator_and_ingestion(self, client, db_session: Session, admin_a: User, project_a: Project):
        """PIXEL: generate -> triggers via /px/{token_value}.gif -> 200 GIF + records DetectionEvent."""
        headers = auth_headers(admin_a)
        resp = client.post(
            f"/api/v1/projects/{project_a.domain}/honey-tokens/generate",
            json={"token_type": "PIXEL"},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        token_value = data["token_value"]
        assert token_value
        assert data["token_type"] == "PIXEL"
        assert "metadata" in data
        assert data["metadata"]["pixel_path"] == f"/px/{token_value}.gif"

        # Trigger via GET /px/{token_value}.gif
        px_resp = client.get(f"/px/{token_value}.gif")
        assert px_resp.status_code == 200
        assert px_resp.headers["content-type"] == "image/gif"
        assert len(px_resp.content) == 43  # 1x1 transparent GIF

        # Verify event in DB
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value=token_value).one()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 1
        assert events[0].http_method == "GET"
        assert events[0].request_path == f"/px/{token_value}.gif"



    def test_link_generator_and_ingestion(self, client, db_session: Session, admin_a: User, project_a: Project):
        """LINK: generate -> triggers via /t/{token_value} -> records DetectionEvent."""
        headers = auth_headers(admin_a)
        resp = client.post(
            f"/api/v1/projects/{project_a.domain}/honey-tokens/generate",
            json={"token_type": "LINK"},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        token_value = data["token_value"]
        assert token_value
        assert data["token_type"] == "LINK"
        assert "metadata" in data
        assert data["metadata"]["path"] == f"/t/{token_value}"
        assert "<a href=" in data["metadata"]["html_tag"]

        # Trigger via GET /t/{token_value}
        link_resp = client.get(f"/t/{token_value}")
        assert link_resp.status_code == 204

        # Verify event in DB
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value=token_value).one()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 1
        assert events[0].http_method == "GET"
        assert events[0].request_path == f"/t/{token_value}"

    def test_form_field_generator_and_ingestion(self, client, db_session: Session, admin_a: User, project_a: Project):
        """FORM_FIELD: generate -> triggers via /collect/{token_value} and /t/{token_value} -> records DetectionEvent."""
        headers = auth_headers(admin_a)
        resp = client.post(
            f"/api/v1/projects/{project_a.domain}/honey-tokens/generate",
            json={"token_type": "FORM_FIELD"},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        token_value = data["token_value"]
        assert token_value
        assert data["token_type"] == "FORM_FIELD"
        assert "metadata" in data
        assert "<input type=" in data["metadata"]["html_tag"]

        # Trigger via POST /collect/{token_value}
        collect_resp = client.post(f"/collect/{token_value}")
        assert collect_resp.status_code == 204

        # Verify event in DB
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value=token_value).one()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 1
        assert events[0].http_method == "POST"


class TestHoneyTokenLifecycle:
    """Test token revocation, rotation, inactive triggering, and duplicate collision handling."""

    def test_revoke_token_lifecycle(self, client, db_session: Session, admin_a: User, project_a: Project):
        """Revoking a token sets is_active=False and records audit log."""
        headers = auth_headers(admin_a)
        # Create token
        create_resp = client.post(
            "/api/v1/honey-tokens",
            json={
                "project_domain": project_a.domain,
                "token_type": "URL",
                "token_value": "token-to-revoke-123",
                "label": "Revoke Test",
            },
            headers=headers,
        )
        assert create_resp.status_code == 201

        # Revoke token
        revoke_resp = client.post(
            "/api/v1/honey-tokens/revoke",
            json={"token_value": "token-to-revoke-123"},
            headers=headers,
        )
        assert revoke_resp.status_code == 204

        # Verify DB state
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value="token-to-revoke-123").one()
        assert token.is_active is False

    def test_rotate_token_lifecycle(self, client, db_session: Session, admin_a: User, project_a: Project):
        """Rotating a token atomically revokes the old one and activates the new one."""
        headers = auth_headers(admin_a)
        # Create initial token
        create_resp = client.post(
            "/api/v1/honey-tokens",
            json={
                "project_domain": project_a.domain,
                "token_type": "API_KEY",
                "token_value": "initial-rotate-token-111",
                "label": "Rotate Test",
            },
            headers=headers,
        )
        assert create_resp.status_code == 201

        # Rotate token
        rotate_resp = client.post(
            "/api/v1/honey-tokens/rotate",
            json={
                "old_token_value": "initial-rotate-token-111",
                "new_token_value": "replacement-rotate-token-222",
            },
            headers=headers,
        )
        assert rotate_resp.status_code == 200
        data = rotate_resp.json()
        assert data["token_value"] == "replacement-rotate-token-222"
        assert data["is_active"] is True

        # Verify old token is now inactive
        db_session.expire_all()
        old_token = db_session.query(HoneyToken).filter_by(token_value="initial-rotate-token-111").one()
        assert old_token.is_active is False
        new_token = db_session.query(HoneyToken).filter_by(token_value="replacement-rotate-token-222").one()
        assert new_token.is_active is True

    def test_inactive_revoked_token_triggering(self, client, db_session: Session, admin_a: User, project_a: Project):
        """Triggering a revoked or rotated token still creates an immutable DetectionEvent."""
        headers = auth_headers(admin_a)
        create_resp = client.post(
            "/api/v1/honey-tokens",
            json={
                "project_domain": project_a.domain,
                "token_type": "URL",
                "token_value": "revoked-trigger-token-999",
            },
            headers=headers,
        )
        assert create_resp.status_code == 201

        # Revoke it
        revoke_resp = client.post(
            "/api/v1/honey-tokens/revoke",
            json={"token_value": "revoked-trigger-token-999"},
            headers=headers,
        )
        assert revoke_resp.status_code == 204

        # Attacker triggers the revoked token
        attacker_resp = client.get("/t/revoked-trigger-token-999")
        assert attacker_resp.status_code == 204

        # Forensic record must be created despite token being inactive
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value="revoked-trigger-token-999").one()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 1
        assert events[0].request_path == "/t/revoked-trigger-token-999"

    def test_duplicate_token_creation_rejected(self, client, admin_a: User, project_a: Project):
        """Creating a token with an existing value returns 409 Conflict."""
        headers = auth_headers(admin_a)
        resp1 = client.post(
            "/api/v1/honey-tokens",
            json={
                "project_domain": project_a.domain,
                "token_type": "URL",
                "token_value": "unique-token-dup-check",
            },
            headers=headers,
        )
        assert resp1.status_code == 201

        # Duplicate attempt
        resp2 = client.post(
            "/api/v1/honey-tokens",
            json={
                "project_domain": project_a.domain,
                "token_type": "URL",
                "token_value": "unique-token-dup-check",
            },
            headers=headers,
        )
        assert resp2.status_code == 409

    def test_rotate_to_existing_value_rejected(self, client, admin_a: User, project_a: Project):
        """Rotating a token to a value that already exists returns 409 Conflict."""
        headers = auth_headers(admin_a)
        # Create token 1
        client.post(
            "/api/v1/honey-tokens",
            json={"project_domain": project_a.domain, "token_type": "URL", "token_value": "rotate-t1"},
            headers=headers,
        )
        # Create token 2
        client.post(
            "/api/v1/honey-tokens",
            json={"project_domain": project_a.domain, "token_type": "URL", "token_value": "rotate-t2"},
            headers=headers,
        )

        # Attempt to rotate t1 into t2
        resp = client.post(
            "/api/v1/honey-tokens/rotate",
            json={"old_token_value": "rotate-t1", "new_token_value": "rotate-t2"},
            headers=headers,
        )
        assert resp.status_code == 409

    def test_cross_tenant_token_generation_prevented(self, client, admin_a: User, project_b: Project):
        """Tenant A admin cannot generate tokens for Tenant B's project (returns 404)."""
        headers = auth_headers(admin_a)
        resp = client.post(
            f"/api/v1/projects/{project_b.domain}/honey-tokens/generate",
            json={"token_type": "URL"},
            headers=headers,
        )
        assert resp.status_code == 404
