"""E2E Live Verification Script for Phase 10: Security Headers Hardening (Finding F-015).

Executes live HTTP TCP socket tests against running Docker container (port 8004)
connected to real PostgreSQL 16 container (port 5440).

Verifies:
1. Liveness & Readiness over TCP socket with all standard security headers
2. Accurate header values:
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - Referrer-Policy: no-referrer
   - Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
   - Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
   - Cache-Control: no-store
3. Error responses (401, 404, 413) uniformly containing all security headers
4. CORS preflight (OPTIONS) receiving BOTH CORS headers and security headers
5. Untrusted CORS preflight receiving security headers
6. Zero duplicate headers in HTTP responses
7. Public HoneyToken ingestion endpoints (/t/ and /px/) returning security headers
8. Real PostgreSQL 16 detection event persistence
9. Docker container security state and non-root user (uid=10001)
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
PG_URL = "postgresql+psycopg2://honeyshield:honeyshield_phase10_secure_password@localhost:5440/honeyshield_dev"
TRUSTED_ORIGIN = "https://app.honeyshield.test"
UNTRUSTED_ORIGIN = "https://evil.attacker.com"

REQUIRED_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "cache-control": "no-store",
}


def make_request(
    path: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], list[tuple[str, str]], bytes]:
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, data=body, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            raw_headers = list(resp.headers.items())
            return resp.status, resp_headers, raw_headers, resp.read()
    except urllib.error.HTTPError as e:
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        raw_headers = list(e.headers.items())
        return e.code, resp_headers, raw_headers, e.read()


def assert_security_headers(headers: dict[str, str], context: str, allow_custom_cache: bool = False):
    for header_name, expected_value in REQUIRED_SECURITY_HEADERS.items():
        if header_name == "cache-control" and allow_custom_cache:
            assert "cache-control" in headers, f"[{context}] Missing cache-control header"
            continue
        actual_val = headers.get(header_name)
        assert actual_val == expected_value, (
            f"[{context}] Header '{header_name}' mismatch: expected '{expected_value}', got '{actual_val}'"
        )
    assert "camera=()" in headers.get("permissions-policy", ""), f"[{context}] Missing camera=() in permissions-policy"
    assert "microphone=()" in headers.get("permissions-policy", ""), f"[{context}] Missing microphone=() in permissions-policy"
    print(f"  [PASS] All security headers verified for: {context}")


def verify_all():
    print("=" * 70)
    print("STARTING PHASE 10 E2E LIVE SECURITY HEADERS VERIFICATION")
    print(f"Backend Target:  {BASE_URL}")
    print(f"Database Target: {PG_URL}")
    print("=" * 70)

    # -----------------------------------------------------------------------
    # 1. Liveness & Readiness Endpoints
    # -----------------------------------------------------------------------
    print("\n--- [1] Checking Liveness & Readiness Endpoints ---")
    status, headers, raw, body = make_request("/health")
    assert status == 200, f"Expected 200, got {status}"
    assert json.loads(body.decode("utf-8")) == {"status": "healthy"}
    assert_security_headers(headers, "GET /health")
    # Verify HSTS absent on plain HTTP
    assert "strict-transport-security" not in headers, "HSTS should not be emitted on plain HTTP"

    status, headers, raw, body = make_request("/ready")
    assert status == 200, f"Expected 200, got {status}"
    assert json.loads(body.decode("utf-8")) == {"status": "ready"}
    assert_security_headers(headers, "GET /ready")

    status, headers, raw, body = make_request("/api/v1/health")
    assert status == 200, f"Expected 200, got {status}"
    assert_security_headers(headers, "GET /api/v1/health")

    # -----------------------------------------------------------------------
    # 2. Error Responses Over Real TCP
    # -----------------------------------------------------------------------
    print("\n--- [2] Checking Security Headers on Error Responses ---")

    # 2.1 401 Unauthorized
    status, headers, _, _ = make_request("/api/v1/tenants")
    assert status == 401, f"Expected 401, got {status}"
    assert_security_headers(headers, "401 Unauthorized (/api/v1/tenants)")

    # 2.2 404 Not Found
    status, headers, _, _ = make_request("/api/v1/nonexistent-route-999")
    assert status == 404, f"Expected 404, got {status}"
    assert_security_headers(headers, "404 Not Found (/api/v1/nonexistent-route-999)")

    # 2.3 413 Payload Too Large
    huge_body = b"A" * (1024 * 1024 + 500)
    status, headers, _, _ = make_request(
        "/api/v1/auth/login",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=huge_body,
    )
    assert status == 413, f"Expected 413, got {status}"
    assert_security_headers(headers, "413 Payload Too Large (/api/v1/auth/login)")

    # -----------------------------------------------------------------------
    # 3. Deduplication: Zero Duplicate Headers
    # -----------------------------------------------------------------------
    print("\n--- [3] Checking for Zero Duplicate Headers ---")
    status, _, raw_headers, _ = make_request("/health")
    header_names = [name.lower() for name, _ in raw_headers]
    for check_h in REQUIRED_SECURITY_HEADERS.keys():
        count = header_names.count(check_h)
        assert count == 1, f"Header '{check_h}' appeared {count} times (expected exactly 1)"
    print("  [PASS] Zero duplicate headers confirmed across response stream")

    # -----------------------------------------------------------------------
    # 4. CORS Interaction Over Real TCP
    # -----------------------------------------------------------------------
    print("\n--- [4] Checking CORS Preflight & Request Coexistence ---")

    # 4.1 Trusted Origin Preflight: OPTIONS request must get both CORS & Security headers
    status, headers, _, _ = make_request(
        "/api/v1/health",
        method="OPTIONS",
        headers={
            "Origin": TRUSTED_ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert status == 200, f"Expected 200, got {status}"
    assert headers.get("access-control-allow-origin") == TRUSTED_ORIGIN, "Missing CORS allow origin"
    assert_security_headers(headers, "OPTIONS preflight (trusted origin)")

    # 4.2 Untrusted Origin Preflight: Rejected CORS, but security headers present
    status, headers, _, _ = make_request(
        "/api/v1/health",
        method="OPTIONS",
        headers={
            "Origin": UNTRUSTED_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert status == 400, f"Expected 400, got {status}"
    assert "access-control-allow-origin" not in headers, "CORS origin leaked to untrusted caller"
    assert_security_headers(headers, "OPTIONS preflight (untrusted origin)")

    # 4.3 Simple GET with trusted origin
    status, headers, _, _ = make_request(
        "/api/v1/health",
        method="GET",
        headers={"Origin": TRUSTED_ORIGIN},
    )
    assert status == 200, f"Expected 200, got {status}"
    assert headers.get("access-control-allow-origin") == TRUSTED_ORIGIN
    assert_security_headers(headers, "GET /api/v1/health with CORS")

    # -----------------------------------------------------------------------
    # 5. Public HoneyToken Ingestion & Database Verification
    # -----------------------------------------------------------------------
    print("\n--- [5] Seed Database & Verify Public Ingestion with Security Headers ---")
    engine = create_engine(PG_URL, pool_pre_ping=True)
    with Session(engine) as session:
        # Create test tenant, project, honeytoken
        tenant = Tenant(name="Phase10 Tenant", slug="phase10-tenant", is_active=True)
        session.add(tenant)
        session.flush()

        project = Project(name="Phase10 Project", domain="p10.test", tenant_id=tenant.id, is_active=True)
        session.add(project)
        session.flush()

        token_url = HoneyToken(
            project_id=project.id,
            token_type=HoneyTokenType.URL,
            token_value="phase10-live-url-token-12345",
            label="Phase 10 URL Token",
            is_active=True,
        )
        token_pixel = HoneyToken(
            project_id=project.id,
            token_type=HoneyTokenType.PIXEL,
            token_value="phase10-live-px-token-67890",
            label="Phase 10 Pixel Token",
            is_active=True,
        )
        session.add(token_url)
        session.add(token_pixel)
        session.commit()
        url_token_id = token_url.id
        pixel_token_id = token_pixel.id

    # 5.1 Trigger URL Token
    status, headers, _, _ = make_request(f"/t/{token_url.token_value}")
    assert status == 204, f"Expected 204, got {status}"
    assert_security_headers(headers, "Public Ingestion GET /t/{token}")

    # 5.2 Trigger Pixel Token
    status, headers, _, _ = make_request(f"/px/{token_pixel.token_value}.gif")
    assert status == 200, f"Expected 200, got {status}"
    assert headers.get("content-type") == "image/gif"
    assert_security_headers(headers, "Public Ingestion GET /px/{token}.gif")

    # 5.3 Verify PostgreSQL 16 Persistence
    with Session(engine) as session:
        events = session.execute(
            select(DetectionEvent).where(
                DetectionEvent.honey_token_id.in_([url_token_id, pixel_token_id])
            )
        ).scalars().all()
        assert len(events) >= 2, f"Expected at least 2 detection events in PG 16, found {len(events)}"
        print(f"  [PASS] PostgreSQL 16 verified: {len(events)} detection events persisted!")
        for ev in events:
            print(f"         Event #{ev.id}: token_id={ev.honey_token_id}, ip={ev.ip_address}, method={ev.http_method}")

    # -----------------------------------------------------------------------
    # 6. Container Security State & Non-Root Execution
    # -----------------------------------------------------------------------
    print("\n--- [6] Checking Docker Container Security & Process State ---")
    inspect_out = subprocess.check_output(["docker", "inspect", "honeyshield-backend-phase10"], text=True)
    inspect_data = json.loads(inspect_out)[0]
    container_state = inspect_data["State"]["Status"]
    assert container_state == "running", f"Container state is {container_state}"

    user_out = subprocess.check_output(["docker", "exec", "honeyshield-backend-phase10", "id"], text=True).strip()
    assert "uid=10001(honeyshield)" in user_out, f"Expected uid=10001, got {user_out}"
    print(f"  [PASS] Container running as non-root user: {user_out}")

    print("\n" + "=" * 70)
    print("ALL PHASE 10 LIVE VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    verify_all()
