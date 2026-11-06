"""E2E Verification Script for Phase 9: Health, Readiness & Deployment Probes.

Executes live HTTP TCP socket tests against running Docker container (port 8003)
and simulates PostgreSQL failure (pause/unpause) to verify:
1. Liveness (independent of DB)
2. Readiness (reflects DB availability: 200 -> 503 -> 200)
3. Rate-limiting exemption
4. Response body security (zero leaked credentials / stack traces)
5. Docker container healthcheck
"""
from __future__ import annotations

import json
import subprocess
import time
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8003"
PG_CONTAINER = "honeyshield-pg-phase9"
BACKEND_CONTAINER = "honeyshield-backend-phase9"


def run_cmd(cmd: str) -> str:
    res = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.stdout.strip()


def verify_all():
    print("=" * 60)
    print("STARTING PHASE 9 LIVE VERIFICATION")
    print(f"Target: {BASE_URL}")
    print("=" * 60)

    # 1. Test Liveness Endpoints (Normal)
    print("\n--- [1] Testing Liveness Endpoints ---")
    for path in ("/health", "/api/v1/health"):
        url = f"{BASE_URL}{path}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[OK] GET {path} returned HTTP {resp.status}: {data}")
            assert data == {"status": "healthy"}

    # 2. Test Readiness Endpoints (DB Available)
    print("\n--- [2] Testing Readiness Endpoints (PostgreSQL Available) ---")
    for path in ("/api/v1/ready", "/ready"):
        url = f"{BASE_URL}{path}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[OK] GET {path} returned HTTP {resp.status}: {data}")
            assert data == {"status": "ready"}

    # 3. Test Rate-Limiting Exemption
    print("\n--- [3] Testing Rate-Limiting Exemption on Probes ---")
    for i in range(75):
        url = f"{BASE_URL}/health"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
    print("[OK] Sent 75 rapid requests to /health: 0 rate limits triggered (HTTP 200 throughout).")

    for i in range(75):
        url = f"{BASE_URL}/api/v1/ready"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
    print("[OK] Sent 75 rapid requests to /api/v1/ready: 0 rate limits triggered (HTTP 200 throughout).")

    # 4. Failure Simulation: Stop PostgreSQL Dependency
    print("\n--- [4] Failure Simulation: PostgreSQL Unavailable ---")
    print(f"Stopping PostgreSQL container '{PG_CONTAINER}'...")
    run_cmd(f"docker stop {PG_CONTAINER}")
    time.sleep(1)

    try:
        # A: Liveness must remain 200!
        url_live = f"{BASE_URL}/health"
        req_live = urllib.request.Request(url_live, method="GET")
        with urllib.request.urlopen(req_live, timeout=10) as resp_l:
            assert resp_l.status == 200
            data_l = json.loads(resp_l.read().decode("utf-8"))
            assert data_l == {"status": "healthy"}
            print(f"[OK] GET /health during DB downtime returned HTTP 200: {data_l} (process is alive)")

        # B: Readiness must fail with 503!
        url_ready = f"{BASE_URL}/api/v1/ready"
        req_ready = urllib.request.Request(url_ready, method="GET")
        try:
            urllib.request.urlopen(req_ready, timeout=10)
            assert False, "Expected HTTP 503 on readiness when DB is stopped"
        except urllib.error.HTTPError as e:
            assert e.code == 503, f"Expected 503 Service Unavailable, got {e.code}"
            err_data = json.loads(e.read().decode("utf-8"))
            print(f"[OK] GET /api/v1/ready during DB downtime returned HTTP {e.code}: {err_data}")
            assert err_data == {"status": "not_ready"}

        # C: Root readiness must also fail with 503!
        url_root_ready = f"{BASE_URL}/ready"
        req_root_ready = urllib.request.Request(url_root_ready, method="GET")
        try:
            urllib.request.urlopen(req_root_ready, timeout=10)
            assert False, "Expected HTTP 503 on root /ready when DB is stopped"
        except urllib.error.HTTPError as e:
            assert e.code == 503
            err_data_root = json.loads(e.read().decode("utf-8"))
            print(f"[OK] GET /ready during DB downtime returned HTTP {e.code}: {err_data_root}")
            assert err_data_root == {"status": "not_ready"}

    finally:
        # 5. Restore PostgreSQL Dependency
        print("\n--- [5] Recovery Simulation: Restoring PostgreSQL ---")
        print(f"Starting PostgreSQL container '{PG_CONTAINER}'...")
        run_cmd(f"docker start {PG_CONTAINER}")
        # Wait for PostgreSQL to become ready
        for _ in range(15):
            time.sleep(1)
            try:
                out = run_cmd(f"docker exec {PG_CONTAINER} pg_isready -U honeyshield -d honeyshield_test")
                if "accepting connections" in out:
                    break
            except Exception:
                pass
        time.sleep(1)

    # 6. Verify Recovery
    for path in ("/api/v1/ready", "/ready"):
        url = f"{BASE_URL}{path}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[OK] GET {path} after DB restoration returned HTTP {resp.status}: {data} (recovered!)")
            assert data == {"status": "ready"}

    # 7. Check Docker Container Health Status
    print("\n--- [6] Checking Docker Container Health Status ---")
    # Wait for container healthcheck to record result
    time.sleep(11)
    health_json = run_cmd(f"docker inspect {BACKEND_CONTAINER} --format '{{{{json .State.Health}}}}'")
    health_state = json.loads(health_json)
    status_str = health_state.get("Status")
    print(f"[OK] Docker Container Health Status: '{status_str}'")
    assert status_str == "healthy", f"Expected container health status 'healthy', got '{status_str}'"

    # 8. Check Container Logs for Any Leaks
    print("\n--- [7] Checking Logs for Secrets / Leaks ---")
    logs = run_cmd(f"docker logs {BACKEND_CONTAINER}")
    for secret in ("honeyshield_phase9_pass", "test-secret-key", "postgresql+psycopg2"):
        assert secret not in logs, f"Leaked sensitive token '{secret}' in logs!"
    print("[OK] Container logs inspected: zero secrets or sensitive connection strings leaked.")

    print("\n" + "=" * 60)
    print("ALL PHASE 9 LIVE VERIFICATION CRITERIA PASSED!")
    print("=" * 60)


if __name__ == "__main__":
    verify_all()
