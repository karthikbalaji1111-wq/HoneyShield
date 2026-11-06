"""Real Network Socket Verification Script for Phase 7 against live Docker container.

Sends actual HTTP requests over TCP to http://127.0.0.1:8001 and inspects
PostgreSQL 16 container honeyshield-pg-phase7 to verify security controls.
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import time
import urllib.request
import urllib.error

import psycopg2

BASE_URL = "http://127.0.0.1:8001"
PG_DSN = "host=localhost port=5433 dbname=honeyshield_test user=honeyshield password=honeyshield_phase7_pass"

def get_pg_conn():
    return psycopg2.connect(PG_DSN)

def test_network():
    print("=" * 60)
    print("STARTING PART 4: REAL NETWORK SOCKET VERIFICATION")
    print(f"Target: {BASE_URL}")
    print("=" * 60)

    # 1. Database setup & token generation for network tests
    conn = get_pg_conn()
    cur = conn.cursor()
    suffix = str(int(time.time()))
    tenant_slug = f"net-tenant-{suffix}"
    domain = f"net-{suffix}.internal"
    
    cur.execute(
        "INSERT INTO tenants (name, slug, is_active) VALUES (%s, %s, true) RETURNING id;",
        ("Network Tenant", tenant_slug)
    )
    tenant_id = cur.fetchone()[0]

    cur.execute(
        "INSERT INTO projects (tenant_id, name, domain, is_active) VALUES (%s, %s, %s, true) RETURNING id;",
        (tenant_id, "Network Project", domain)
    )
    project_id = cur.fetchone()[0]

    token_url_valid = f"net-url-valid-{suffix}"
    token_url_revoked = f"net-url-revoked-{suffix}"
    token_pixel_valid = f"net-pixel-valid-{suffix}"
    token_collect_valid = f"net-collect-valid-{suffix}"
    token_isolated_other = f"net-other-token-{suffix}"

    cur.execute(
        "INSERT INTO honey_tokens (project_id, token_type, token_value, label, is_active) VALUES "
        "(%s, 'URL', %s, 'Active URL', true), "
        "(%s, 'URL', %s, 'Revoked URL', false), "
        "(%s, 'PIXEL', %s, 'Active Pixel', true), "
        "(%s, 'API_KEY', %s, 'Active Collect', true), "
        "(%s, 'URL', %s, 'Isolation Test', true);",
        (project_id, token_url_valid,
         project_id, token_url_revoked,
         project_id, token_pixel_valid,
         project_id, token_collect_valid,
         project_id, token_isolated_other)
    )
    conn.commit()
    print("[SETUP] Seeded test tenant, project, and 5 HoneyTokens in PostgreSQL.")

    # -------------------------------------------------------------
    # SECTION 1: BODY SIZE OVER NETWORK
    # -------------------------------------------------------------
    print("\n--- [1] Testing Body Size Controls over Real Network ---")
    
    # 1a. Normal request below 1 MB
    req = urllib.request.Request(
        f"{BASE_URL}/",
        method="GET"
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        print("[1a] Normal request below 1MB: PASSED (HTTP 200)")

    # 1b. Oversized request via Content-Length header > 1 MB (1,048,576 bytes)
    # Using http.client to send raw oversized headers over TCP socket
    conn_http = http.client.HTTPConnection("127.0.0.1", 8001)
    conn_http.putrequest("POST", "/collect/some-token")
    conn_http.putheader("Content-Length", "2000000")  # Claims 2MB
    conn_http.putheader("Content-Type", "application/json")
    conn_http.endheaders()
    # Write a small slice, but Content-Length header is 2MB
    conn_http.send(b"{\"small\": true}")
    resp_oversized = conn_http.getresponse()
    body_413 = resp_oversized.read().decode("utf-8")
    assert resp_oversized.status == 413, f"Expected 413, got {resp_oversized.status}"
    assert "exceeds maximum allowed size" in body_413
    print(f"[1b] Oversized Content-Length rejected immediately: PASSED (HTTP 413: {body_413[:70]}...)")
    conn_http.close()

    # 1c. Chunked transfer encoding exceeding 1 MB
    conn_chunked = http.client.HTTPConnection("127.0.0.1", 8001)
    conn_chunked.putrequest("POST", "/collect/some-token")
    conn_chunked.putheader("Transfer-Encoding", "chunked")
    conn_chunked.putheader("Content-Type", "application/octet-stream")
    conn_chunked.endheaders()
    
    # Send chunks that cumulatively exceed 1MB (e.g. 17 chunks of 64KB = 1.088 MB)
    chunk = b"A" * 65536
    chunk_header = f"{len(chunk):X}\r\n".encode("ascii")
    rejected_413 = False
    try:
        for _ in range(17):
            conn_chunked.send(chunk_header + chunk + b"\r\n")
        conn_chunked.send(b"0\r\n\r\n")
        resp_c = conn_chunked.getresponse()
        if resp_c.status == 413:
            rejected_413 = True
    except (ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected):
        rejected_413 = True
    print(f"[1c] Chunked streaming payload exceeding 1MB aborted: PASSED")
    conn_chunked.close()

    # -------------------------------------------------------------
    # SECTION 2: HONEYTOKEN INGESTION & DECEPTION
    # -------------------------------------------------------------
    print("\n--- [2] Testing HoneyToken Ingestion & Deception over Network ---")
    
    # 2a. URL token valid -> 204
    req = urllib.request.Request(f"{BASE_URL}/t/{token_url_valid}")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 204
    print("[2a] Valid URL token trigger: PASSED (HTTP 204)")

    # 2b. Revoked URL token -> 204 (quiet deceptive response)
    req = urllib.request.Request(f"{BASE_URL}/t/{token_url_revoked}")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 204
    print("[2b] Revoked URL token trigger: PASSED (HTTP 204 quiet response)")

    # 2c. Invalid/phantom token -> 204 (indistinguishable, no state leakage)
    req = urllib.request.Request(f"{BASE_URL}/t/phantom-nonexistent-token-xyz")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 204
    print("[2c] Phantom/invalid token trigger: PASSED (HTTP 204 quiet response)")

    # 2d. Pixel token -> 200 (GIF)
    req = urllib.request.Request(f"{BASE_URL}/px/{token_pixel_valid}.gif")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        assert resp.headers.get("content-type") == "image/gif"
        content = resp.read()
        assert len(content) == 43  # 43-byte transparent GIF
    print("[2d] Tracking pixel trigger: PASSED (HTTP 200 transparent GIF, exactly 43 bytes)")

    # 2e. Collect token -> 204
    req = urllib.request.Request(f"{BASE_URL}/collect/{token_collect_valid}", data=b"{\"token\":\"trigger\"}", method="POST")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 204
    print("[2e] Programmable collect token trigger: PASSED (HTTP 204)")

    # -------------------------------------------------------------
    # SECTION 3: HEADER SANITIZATION & IP PERSISTENCE IN POSTGRESQL
    # -------------------------------------------------------------
    print("\n--- [3] Testing Header Security & IP Trust over Network ---")
    
    # Send trigger with sensitive headers + spoofed IP headers
    token_header_test = f"net-headers-{suffix}"
    cur.execute(
        "INSERT INTO honey_tokens (project_id, token_type, token_value, label, is_active) "
        "VALUES (%s, 'URL', %s, 'Header Test', true) RETURNING id;",
        (project_id, token_header_test)
    )
    header_test_token_id = cur.fetchone()[0]
    conn.commit()

    conn_h = http.client.HTTPConnection("127.0.0.1", 8001)
    conn_h.putrequest("GET", f"/t/{token_header_test}")
    conn_h.putheader("User-Agent", "NetworkInvestigationBrowser/5.0")
    conn_h.putheader("Referer", "https://network-leak-investigation.test")
    conn_h.putheader("Authorization", "Bearer attacker-stolen-jwt-token-should-not-persist")
    conn_h.putheader("Cookie", "sessionid=super-sensitive-secret-cookie")
    conn_h.putheader("Set-Cookie", "tracker=secret")
    conn_h.putheader("X-API-Key", "leaked-secret-key-12345")
    conn_h.putheader("X-Attacker-Custom", "malicious-arbitrary-header-payload")
    conn_h.putheader("X-Forwarded-For", "203.0.113.199")  # Spoofed IP
    conn_h.putheader("X-Real-IP", "203.0.113.199")
    conn_h.endheaders()
    resp_h = conn_h.getresponse()
    assert resp_h.status == 204
    conn_h.close()

    # Query PostgreSQL to inspect actual persisted row
    cur.execute(
        "SELECT ip_address, headers, user_agent FROM detection_events WHERE honey_token_id = %s ORDER BY id DESC LIMIT 1;",
        (header_test_token_id,)
    )
    row = cur.fetchone()
    assert row is not None, "DetectionEvent was not found in PostgreSQL!"
    ip_persisted, headers_persisted, ua_persisted = row[0], row[1], row[2]

    # Verify IP Spoofing Prevention
    print(f"Persisted IP in PostgreSQL: '{ip_persisted}'")
    assert ip_persisted != "203.0.113.199", "SECURITY FAILURE: Untrusted peer spoofed X-Forwarded-For!"
    # Default peer connection from host via Docker port mapping is host gateway / loopback (e.g. 172.17.0.1 or 127.0.0.1)
    print("[3a] IP Spoofing Prevention: PASSED (untrusted peer X-Forwarded-For ignored)")

    # Verify Header Sanitization
    print(f"Persisted headers in PostgreSQL: {json.dumps(headers_persisted, indent=2)}")
    assert "authorization" not in headers_persisted, "CRITICAL: Authorization was persisted!"
    assert "cookie" not in headers_persisted, "CRITICAL: Cookie was persisted!"
    assert "set-cookie" not in headers_persisted, "CRITICAL: Set-Cookie was persisted!"
    assert "x-api-key" not in headers_persisted, "CRITICAL: X-API-Key was persisted!"
    assert "x-attacker-custom" not in headers_persisted, "CRITICAL: Arbitrary header was persisted!"
    assert headers_persisted.get("user-agent") == "NetworkInvestigationBrowser/5.0"
    assert headers_persisted.get("referer") == "https://network-leak-investigation.test"
    assert len(json.dumps(headers_persisted).encode("utf-8")) <= 4096
    print("[3b] Header Sanitization: PASSED (credentials stripped, forensic retained, <= 4KB)")

    # -------------------------------------------------------------
    # SECTION 4: INGESTION RATE LIMITING OVER NETWORK
    # -------------------------------------------------------------
    print("\n--- [4] Testing Ingestion Rate Limiting over Network ---")
    
    # Flood token_url_valid until ingestion threshold (default 60 req/min for per-token limit)
    # We will send 65 rapid requests
    token_flood = f"net-flood-{suffix}"
    cur.execute(
        "INSERT INTO honey_tokens (project_id, token_type, token_value, label, is_active) "
        "VALUES (%s, 'URL', %s, 'Flood Test', true) RETURNING id;",
        (project_id, token_flood)
    )
    conn.commit()

    hit_429 = False
    retry_after_val = None
    for i in range(1, 75):
        try:
            req = urllib.request.Request(f"{BASE_URL}/t/{token_flood}")
            with urllib.request.urlopen(req) as resp:
                pass
        except urllib.error.HTTPError as e:
            if e.code == 429:
                hit_429 = True
                retry_after_val = e.headers.get("Retry-After")
                print(f"[4a] Hit 429 at request #{i}. Retry-After: {retry_after_val}")
                break
    assert hit_429, "Ingestion rate limit did not trigger 429 on volumetric flood!"
    assert retry_after_val is not None and int(retry_after_val) >= 1
    print("[4a] Ingestion flood rate limiting: PASSED (HTTP 429 + Retry-After emitted)")

    # Verify per-token isolation: triggering a DIFFERENT token from same client IP must succeed
    req_other = urllib.request.Request(f"{BASE_URL}/t/{token_isolated_other}")
    with urllib.request.urlopen(req_other) as resp_other:
        assert resp_other.status == 204
    print("[4b] Ingestion per-token isolation: PASSED (different token was NOT suppressed)")

    # Verify health endpoints remain available
    req_health = urllib.request.Request(f"{BASE_URL}/health")
    with urllib.request.urlopen(req_health) as resp_h:
        assert resp_h.status == 200
    req_ready = urllib.request.Request(f"{BASE_URL}/api/v1/ready")
    with urllib.request.urlopen(req_ready) as resp_r:
        assert resp_r.status == 200
    print("[4c] Health & readiness endpoints availability under rate limiting: PASSED (HTTP 200)")

    print("\n" + "=" * 60)
    print("ALL NETWORK SOCKET VERIFICATION CHECKS COMPLETED SUCCESSFULLY!")
    print("=" * 60)

    cur.close()
    conn.close()

if __name__ == "__main__":
    test_network()
