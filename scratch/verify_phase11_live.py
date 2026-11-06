"""E2E Verification Script for Phase 11: CORS Policy Hardening (Finding F-014).

Executes live HTTP TCP socket tests against running Docker container (port 8004)
connected to real PostgreSQL 16 container (port 5440).

Verifies:
1. Service liveness & readiness over TCP
2. CORS Preflight (OPTIONS) requests (trusted vs untrusted, substring, suffix, invalid methods/headers)
3. Simple cross-origin GET requests (origin reflection, exposed headers, Vary header)
4. Cross-origin authenticated login and Bearer token requests
5. Error responses (401, 404) with CORS headers for trusted origins and absence for untrusted
6. Public HoneyToken ingestion (/t/ and /px/) execution, zero CORS reflection, and PostgreSQL detection event persistence
7. Docker container status, non-root user, and resource health
"""
from __future__ import annotations

import json
import subprocess
import time
import urllib.request
import urllib.error
import http.client

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from app.core.security import get_password_hash
from app.models.enums import HoneyTokenType, Role
from app.models.honey_token import HoneyToken
from app.models.project import Project
from app.models.tenant import Tenant
from app.models.user import User
from app.models.detection_event import DetectionEvent

BASE_URL = "http://127.0.0.1:8004"
PG_URL = "postgresql+psycopg2://honeyshield:honeyshield_phase11_secure_password@localhost:5440/honeyshield_dev"
TRUSTED_ORIGIN_APP = "https://app.honeyshield.test"
TRUSTED_ORIGIN_ADMIN = "https://admin.honeyshield.test"
UNTRUSTED_ORIGIN = "https://evil.attacker.com"
SUBSTRING_ORIGIN = "https://app.honeyshield.test.attacker.com"
SUFFIX_ORIGIN = "https://notapp.honeyshield.test"


def make_request(
    path: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, data=body, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp_headers, resp.read()
    except urllib.error.HTTPError as e:
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        return e.code, resp_headers, e.read()


def verify_all():
    print("=" * 70)
    print("STARTING PHASE 11 E2E LIVE CORS VERIFICATION")
    print(f"Backend Target: {BASE_URL}")
    print(f"Database Target: {PG_URL}")
    print("=" * 70)

    # -----------------------------------------------------------------------
    # 1. Basic Liveness and Readiness
    # -----------------------------------------------------------------------
    print("\n--- [1] Checking Liveness & Readiness via HTTP TCP ---")
    status, _, body = make_request("/health")
    assert status == 200, f"Expected 200, got {status}"
    assert json.loads(body.decode("utf-8")) == {"status": "healthy"}
    print("[OK] GET /health returned 200 healthy")

    status, _, body = make_request("/ready")
    assert status == 200, f"Expected 200, got {status}"
    assert json.loads(body.decode("utf-8")) == {"status": "ready"}
    print("[OK] GET /ready returned 200 ready (PostgreSQL 16 connection verified)")

    # -----------------------------------------------------------------------
    # 2. CORS Preflight (OPTIONS)
    # -----------------------------------------------------------------------
    print("\n--- [2] Checking CORS Preflight (OPTIONS) Requests ---")

    # 2.1 Trusted Origin (App)
    status, headers, _ = make_request(
        "/api/v1/health",
        method="OPTIONS",
        headers={
            "Origin": TRUSTED_ORIGIN_APP,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert status == 200, f"Expected 200, got {status}"
    assert headers.get("access-control-allow-origin") == TRUSTED_ORIGIN_APP
    assert "GET" in headers.get("access-control-allow-methods", "")
    assert headers.get("access-control-max-age") == "600"
    assert headers.get("vary") == "Origin"
    assert "x-request-id" in headers
    print(f"[OK] Preflight for {TRUSTED_ORIGIN_APP}: 200 with matching Allow-Origin, Methods, Max-Age 600, Vary Origin")

    # 2.2 Second Trusted Origin (Admin)
    status, headers, _ = make_request(
        "/auth/login",
        method="OPTIONS",
        headers={
            "Origin": TRUSTED_ORIGIN_ADMIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert status == 200, f"Expected 200, got {status}"
    assert headers.get("access-control-allow-origin") == TRUSTED_ORIGIN_ADMIN
    assert "POST" in headers.get("access-control-allow-methods", "")
    print(f"[OK] Preflight for second trusted origin {TRUSTED_ORIGIN_ADMIN}: 200 with Allow-Origin")

    # 2.3 Untrusted Origin
    status, headers, _ = make_request(
        "/api/v1/health",
        method="OPTIONS",
        headers={
            "Origin": UNTRUSTED_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert status == 400, f"Expected 400, got {status}"
    assert "access-control-allow-origin" not in headers
    print(f"[OK] Preflight for untrusted origin {UNTRUSTED_ORIGIN}: 400 Bad Request, no Allow-Origin")

    # 2.4 Substring Origin Attack
    status, headers, _ = make_request(
        "/api/v1/health",
        method="OPTIONS",
        headers={
            "Origin": SUBSTRING_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert status == 400, f"Expected 400, got {status}"
    assert "access-control-allow-origin" not in headers
    print(f"[OK] Preflight for substring attack {SUBSTRING_ORIGIN}: 400 Bad Request, no Allow-Origin")

    # 2.5 Suffix Origin Attack
    status, headers, _ = make_request(
        "/api/v1/health",
        method="OPTIONS",
        headers={
            "Origin": SUFFIX_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert status == 400, f"Expected 400, got {status}"
    assert "access-control-allow-origin" not in headers
    print(f"[OK] Preflight for suffix attack {SUFFIX_ORIGIN}: 400 Bad Request, no Allow-Origin")

    # 2.6 Disallowed Method
    status, _, _ = make_request(
        "/api/v1/health",
        method="OPTIONS",
        headers={
            "Origin": TRUSTED_ORIGIN_APP,
            "Access-Control-Request-Method": "CONNECT",
        },
    )
    assert status == 400, f"Expected 400 for CONNECT, got {status}"
    print("[OK] Preflight with disallowed method CONNECT rejected with 400")

    # 2.7 Disallowed Header
    status, _, _ = make_request(
        "/api/v1/health",
        method="OPTIONS",
        headers={
            "Origin": TRUSTED_ORIGIN_APP,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-malicious-header",
        },
    )
    assert status == 400, f"Expected 400 for unknown header, got {status}"
    print("[OK] Preflight with disallowed header rejected with 400")

    # -----------------------------------------------------------------------
    # 3. Simple Cross-Origin GET & Response Headers
    # -----------------------------------------------------------------------
    print("\n--- [3] Checking Simple Cross-Origin Requests & Headers ---")

    # 3.1 Trusted origin
    status, headers, _ = make_request(
        "/health",
        headers={"Origin": TRUSTED_ORIGIN_APP},
    )
    assert status == 200
    assert headers.get("access-control-allow-origin") == TRUSTED_ORIGIN_APP
    assert headers.get("vary") == "Origin"
    exposed = headers.get("access-control-expose-headers", "")
    assert "x-request-id" in exposed.lower()
    assert "x-process-time-ms" in exposed.lower()
    assert "retry-after" in exposed.lower()
    assert "x-request-id" in headers
    assert "x-process-time-ms" in headers
    print(f"[OK] GET /health with trusted origin: Allow-Origin={TRUSTED_ORIGIN_APP}, Expose-Headers={exposed}")

    # 3.2 Untrusted origin
    status, headers, _ = make_request(
        "/health",
        headers={"Origin": UNTRUSTED_ORIGIN},
    )
    assert status == 200
    assert "access-control-allow-origin" not in headers
    print(f"[OK] GET /health with untrusted origin: 200 OK, no Access-Control-Allow-Origin")

    # 3.3 No origin header
    status, headers, _ = make_request("/health")
    assert status == 200
    assert "access-control-allow-origin" not in headers
    print("[OK] GET /health without Origin: 200 OK, no Access-Control-Allow-Origin")

    # -----------------------------------------------------------------------
    # 4. Database Seed & Cross-Origin Authentication
    # -----------------------------------------------------------------------
    print("\n--- [4] Seeding Database & Testing Cross-Origin Authentication ---")
    engine = create_engine(PG_URL)
    with Session(engine) as session:
        # Check or create test admin user
        admin_user = session.execute(
            select(User).where(User.email == "phase11_admin@honeyshield.test")
        ).scalar_one_or_none()
        if not admin_user:
            admin_user = User(
                email="phase11_admin@honeyshield.test",
                hashed_password=get_password_hash("Phase11_TestPassword_Secure!"),
                role=Role.SYSTEM_ADMIN,
                tenant_id=None,
                is_active=True,
            )
            session.add(admin_user)
            session.flush()

        # Check or create tenant
        tenant = session.execute(
            select(Tenant).where(Tenant.slug == "tenant-phase11")
        ).scalar_one_or_none()
        if not tenant:
            tenant = Tenant(
                name="Phase 11 Tenant",
                slug="tenant-phase11",
                is_active=True,
            )
            session.add(tenant)
            session.flush()

        # Check or create project
        project = session.execute(
            select(Project).where(Project.tenant_id == tenant.id)
        ).scalar_one_or_none()
        if not project:
            project = Project(
                tenant_id=tenant.id,
                name="Phase 11 Project",
                domain="phase11.honeyshield.test",
                is_active=True,
            )
            session.add(project)
            session.flush()

        # Check or create honey token
        token_val = "p11-token-live-verify-token-val"
        token = session.execute(
            select(HoneyToken).where(HoneyToken.token_value == token_val)
        ).scalar_one_or_none()
        if not token:
            token = HoneyToken(
                project_id=project.id,
                token_type=HoneyTokenType.URL,
                token_value=token_val,
                label="Phase 11 Live Token",
                is_active=True,
            )
            session.add(token)
            session.flush()

        saved_token_id = token.id
        session.commit()
        print("[OK] Database seeded with tenant, project, and HoneyToken in PostgreSQL 16.")

    # 4.1 Login POST with trusted origin
    login_payload = json.dumps({
        "email": "phase11_admin@honeyshield.test",
        "password": "Phase11_TestPassword_Secure!",
    }).encode("utf-8")

    status, headers, body = make_request(
        "/auth/login",
        method="POST",
        headers={
            "Origin": TRUSTED_ORIGIN_APP,
            "Content-Type": "application/json",
        },
        body=login_payload,
    )
    assert status == 200, f"Expected 200, got {status}: {body.decode()}"
    assert headers.get("access-control-allow-origin") == TRUSTED_ORIGIN_APP
    token_data = json.loads(body.decode("utf-8"))
    jwt_token = token_data["access_token"]
    print(f"[OK] POST /auth/login from {TRUSTED_ORIGIN_APP}: 200 OK with Allow-Origin and JWT token")

    # 4.2 Login POST with untrusted origin
    status, headers, body = make_request(
        "/auth/login",
        method="POST",
        headers={
            "Origin": UNTRUSTED_ORIGIN,
            "Content-Type": "application/json",
        },
        body=login_payload,
    )
    assert status == 200
    assert "access-control-allow-origin" not in headers
    print(f"[OK] POST /auth/login from untrusted origin: 200 OK, no Access-Control-Allow-Origin")

    # -----------------------------------------------------------------------
    # 5. Authenticated Cross-Origin Requests
    # -----------------------------------------------------------------------
    print("\n--- [5] Checking Authenticated Cross-Origin Requests ---")
    auth_header = f"Bearer {jwt_token}"

    # 5.1 GET /api/v1/projects with trusted origin
    status, headers, body = make_request(
        "/api/v1/projects",
        headers={
            "Authorization": auth_header,
            "Origin": TRUSTED_ORIGIN_APP,
        },
    )
    assert status == 200, f"Expected 200, got {status}"
    assert headers.get("access-control-allow-origin") == TRUSTED_ORIGIN_APP
    projects = json.loads(body.decode("utf-8"))
    assert len(projects) >= 1
    print(f"[OK] GET /api/v1/projects with Bearer JWT from {TRUSTED_ORIGIN_APP}: 200 with Allow-Origin")

    # 5.2 GET /api/v1/projects with untrusted origin
    status, headers, _ = make_request(
        "/api/v1/projects",
        headers={
            "Authorization": auth_header,
            "Origin": UNTRUSTED_ORIGIN,
        },
    )
    assert status == 200
    assert "access-control-allow-origin" not in headers
    print(f"[OK] GET /api/v1/projects with Bearer JWT from {UNTRUSTED_ORIGIN}: 200, no Allow-Origin")

    # -----------------------------------------------------------------------
    # 6. Error Responses Under CORS
    # -----------------------------------------------------------------------
    print("\n--- [6] Checking Error Responses Under CORS ---")

    # 6.1 401 Unauthorized for trusted origin
    status, headers, _ = make_request(
        "/api/v1/projects",
        headers={"Origin": TRUSTED_ORIGIN_APP},
    )
    assert status == 401, f"Expected 401, got {status}"
    assert headers.get("access-control-allow-origin") == TRUSTED_ORIGIN_APP
    assert headers.get("vary") == "Origin"
    print(f"[OK] 401 Unauthorized for {TRUSTED_ORIGIN_APP}: received Allow-Origin and Vary: Origin")

    # 6.2 401 Unauthorized for untrusted origin
    status, headers, _ = make_request(
        "/api/v1/projects",
        headers={"Origin": UNTRUSTED_ORIGIN},
    )
    assert status == 401
    assert "access-control-allow-origin" not in headers
    print(f"[OK] 401 Unauthorized for {UNTRUSTED_ORIGIN}: no Access-Control-Allow-Origin")

    # 6.3 404 Not Found for trusted origin
    status, headers, _ = make_request(
        "/api/v1/nonexistent-route-for-phase11",
        headers={"Origin": TRUSTED_ORIGIN_APP},
    )
    assert status == 404
    assert headers.get("access-control-allow-origin") == TRUSTED_ORIGIN_APP
    print(f"[OK] 404 Not Found for {TRUSTED_ORIGIN_APP}: received Allow-Origin")

    # -----------------------------------------------------------------------
    # 7. Public HoneyToken Ingestion & Forensic Persistence
    # -----------------------------------------------------------------------
    print("\n--- [7] Checking Public HoneyToken Ingestion & Forensic Evidence in PostgreSQL ---")

    # Count prior detection events
    with Session(engine) as session:
        initial_count = session.execute(
            select(DetectionEvent).where(DetectionEvent.honey_token_id == saved_token_id)
        ).scalars().all()
        start_count = len(initial_count)

    # 7.1 Ingestion trigger without Origin
    status, headers, _ = make_request(f"/t/{token_val}")
    assert status == 204, f"Expected 204, got {status}"
    assert "access-control-allow-origin" not in headers
    print("[OK] Ingestion GET /t/{token} without Origin: 204 No Content, no CORS headers")

    # 7.2 Ingestion trigger with untrusted Origin
    status, headers, _ = make_request(
        f"/t/{token_val}",
        headers={"Origin": UNTRUSTED_ORIGIN},
    )
    assert status == 204, f"Expected 204, got {status}"
    assert "access-control-allow-origin" not in headers
    print(f"[OK] Ingestion GET /t/{{token}} from {UNTRUSTED_ORIGIN}: 204 No Content, no CORS reflection")

    # 7.3 Ingestion tracking pixel trigger
    status, headers, body = make_request(
        f"/px/{token_val}.gif",
        headers={"Origin": "https://email-client.malicious.test"},
    )
    assert status == 200, f"Expected 200, got {status}"
    assert headers.get("content-type") == "image/gif"
    assert "access-control-allow-origin" not in headers
    print("[OK] Tracking pixel GET /px/{token}.gif: 200 image/gif, no CORS reflection")

    # 7.4 Verify PostgreSQL DetectionEvents
    with Session(engine) as session:
        events = session.execute(
            select(DetectionEvent)
            .where(DetectionEvent.honey_token_id == saved_token_id)
            .order_by(DetectionEvent.created_at.asc())
        ).scalars().all()
        new_events = len(events) - start_count
        assert new_events >= 3, f"Expected at least 3 new events, found {new_events}"

        # Verify evidence recorded
        ev = events[-1]
        assert ev.honey_token_id == saved_token_id
        assert ev.ip_address is not None
        assert ev.triggered_at is not None
        print(f"[OK] PostgreSQL 16 verified: {new_events} detection events successfully persisted in database!")
        print(f"     Latest event: id={ev.id}, honey_token_id={ev.honey_token_id}, ip={ev.ip_address}, severity={ev.severity}")

    # -----------------------------------------------------------------------
    # 8. Container Health & Non-Root Execution
    # -----------------------------------------------------------------------
    print("\n--- [8] Checking Docker Container Security & Process State ---")
    inspect_out = subprocess.check_output(
        ["docker", "inspect", "honeyshield-backend-phase11"],
        text=True,
    )
    inspect_data = json.loads(inspect_out)[0]
    container_state = inspect_data["State"]["Status"]
    assert container_state == "running", f"Container state is {container_state}"

    # Verify non-root user
    user_out = subprocess.check_output(
        ["docker", "exec", "honeyshield-backend-phase11", "id"],
        text=True,
    ).strip()
    assert "uid=10001(honeyshield)" in user_out, f"Expected uid=10001, got {user_out}"
    print(f"[OK] Container running as non-root user: {user_out}")

    print("\n" + "=" * 70)
    print("ALL PHASE 11 LIVE VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    verify_all()
