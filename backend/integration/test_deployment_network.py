"""Explicit live-stack gate: pytest integration/test_deployment_network.py.

Requires an isolated migrated stack and bootstrapped administrator. These tests
are separate from tests/ because running them requires explicit network targets,
not because failures are optional. Missing inputs fail; no tests are skipped.
"""

import json
import os
from urllib.parse import urlsplit

import httpx
from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosed


def stack_url():
    url = os.environ["HONEYSHIELD_TEST_BASE_URL"].rstrip("/")
    assert urlsplit(url).hostname in {"127.0.0.1", "localhost"}, "Use an isolated loopback test stack"
    return url


def test_live_proxy_readiness():
    with httpx.Client(base_url=stack_url(), timeout=5, trust_env=False) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/api/v1/ready").status_code == 200


def test_live_websocket_authentication_through_proxy():
    base = stack_url()
    with httpx.Client(base_url=base, timeout=5, trust_env=False) as client:
        response = client.post("/auth/login", json={
            "email": os.environ["HONEYSHIELD_TEST_ADMIN_EMAIL"],
            "password": os.environ["HONEYSHIELD_TEST_ADMIN_PASSWORD"],
        })
        assert response.status_code == 200
        token = response.json()["access_token"]
    ws_url = base.replace("http://", "ws://").replace("https://", "wss://")
    with connect(ws_url + "/api/v1/events/stream/ws", proxy=None, open_timeout=5) as ws:
        ws.send(json.dumps({"type": "auth", "token": token}))
        assert json.loads(ws.recv(timeout=5)) == {"type": "auth_success"}


def test_live_websocket_rejects_invalid_credentials():
    ws_url = stack_url().replace("http://", "ws://").replace("https://", "wss://")
    with connect(ws_url + "/api/v1/events/stream/ws", proxy=None, open_timeout=5) as ws:
        ws.send(json.dumps({"type": "auth", "token": "invalid"}))
        try:
            ws.recv(timeout=5)
        except ConnectionClosed as exc:
            assert exc.rcvd.code == 1008
        else:
            raise AssertionError("Invalid credentials were not rejected")
