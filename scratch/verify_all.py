import urllib.request
import urllib.error
import ssl
import json
import subprocess
import time
import asyncio
import websockets
import httpx
import urllib.parse

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

print("==================================================")
print("6. SETUP USER AND HONEYTOKEN")
print("==================================================")
setup_code = """
import asyncio
from app.db.session import SessionLocal
from app.models.tenant import Tenant
from app.models.user import User
from app.models.honey_token import HoneyToken
from app.core.security import get_password_hash

def setup():
    db = SessionLocal()
    tenant = db.query(Tenant).filter_by(name="TestTenant").first()
    if not tenant:
        tenant = Tenant(name="TestTenant", slug="test-tenant")
        db.add(tenant)
        db.commit()
    user = db.query(User).filter_by(email="test@example.com").first()
    if not user:
        user = User(email="test@example.com", hashed_password=get_password_hash("TestPassword123!"), tenant_id=tenant.id, role="TENANT_ADMIN")
        db.add(user)
        db.commit()
    token = db.query(HoneyToken).filter_by(token="test_token_123").first()
    if not token:
        token = HoneyToken(token="test_token_123", tenant_id=tenant.id, description="test", type="tracking_pixel", status="active")
        db.add(token)
        db.commit()
    token2 = db.query(HoneyToken).filter_by(token="test_token_456").first()
    if not token2:
        token2 = HoneyToken(token="test_token_456", tenant_id=tenant.id, description="test", type="hidden_url", status="active")
        db.add(token2)
        db.commit()
    db.close()
setup()
"""
subprocess.run(["docker", "compose", "exec", "-T", "backend", "python", "-c", setup_code])

print("==================================================")
print("AUTHENTICATION THROUGH HTTPS")
print("==================================================")
req = urllib.request.Request("https://127.0.0.1:8443/auth/login", method="POST")
req.add_header("Content-Type", "application/json")
body = json.dumps({"email": "test@example.com", "password": "TestPassword123!"}).encode('utf-8')
try:
    resp = urllib.request.urlopen(req, data=body, context=context)
    data = json.loads(resp.read().decode())
    token = data["access_token"]
    print("Auth SUCCESS -> Status:", resp.status)
except Exception as e:
    print("Auth failed:", e)
    token = ""

print("\n==================================================")
print("7. HONEYTOKEN INGESTION THROUGH HTTPS")
print("==================================================")
try:
    resp = urllib.request.urlopen(urllib.request.Request("https://127.0.0.1:8443/t/test_token_123"), context=context)
    print("/t/test_token_123 -> Status:", resp.status)
    resp2 = urllib.request.urlopen(urllib.request.Request("https://127.0.0.1:8443/px/test_token_456.gif"), context=context)
    print("/px/test_token_456.gif -> Status:", resp2.status)
    
    check_db = """
from app.db.session import SessionLocal
from app.models.detection_event import DetectionEvent
db = SessionLocal()
count = db.query(DetectionEvent).filter(DetectionEvent.token_identifier.in_(["test_token_123", "test_token_456"])).count()
print(f"Events in DB: {count}")
    """
    res = subprocess.run(["docker", "compose", "exec", "-T", "backend", "python", "-c", check_db], capture_output=True, text=True)
    print(res.stdout.strip())
except Exception as e:
    print("Ingestion failed:", e)

async def test_sse_and_ws():
    print("\n==================================================")
    print("8. SSE THROUGH HTTPS")
    print("==================================================")
    async with httpx.AsyncClient(verify=False) as client:
        try:
            async with client.stream('GET', f'https://127.0.0.1:8443/api/v1/events/stream/sse', headers={'Authorization': f'Bearer {token}'}) as response:
                print(f"SSE Connected. Status: {response.status_code}")
                urllib.request.urlopen(urllib.request.Request("https://127.0.0.1:8443/t/test_token_123"), context=context)
                async for line in response.aiter_lines():
                    if line.startswith("data:"):
                        print("Received SSE Event!")
                        break
        except Exception as e:
            print("SSE test failed:", e)

    print("\n==================================================")
    print("9. WEBSOCKET THROUGH HTTPS")
    print("==================================================")
    ssl_ws = ssl.create_default_context()
    ssl_ws.check_hostname = False
    ssl_ws.verify_mode = ssl.CERT_NONE
    try:
        async with websockets.connect(f"wss://127.0.0.1:8443/api/v1/events/stream/ws", ssl=ssl_ws) as ws:
            print("WebSocket TLS Connected.")
            await ws.send(json.dumps({"type": "auth", "token": token}))
            auth_resp = await ws.recv()
            print("Auth Response:", auth_resp)
            urllib.request.urlopen(urllib.request.Request("https://127.0.0.1:8443/t/test_token_456"), context=context)
            msg = await ws.recv()
            print("Received WS Event!")
    except Exception as e:
        print("WS test failed:", e)

if token:
    asyncio.run(test_sse_and_ws())
