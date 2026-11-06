import asyncio
import httpx
import websockets
import json
import ssl
import time

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.tenant import Tenant
from app.models.user import User
from app.models.honey_token import HoneyToken
from app.models.enums import Role
from app.core.security import get_password_hash, create_access_token

engine = create_engine("postgresql+psycopg2://postgres:postgres@postgres:5432/honeyshield_dev")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def setup_db():
    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter_by(name="Test Tenant").first()
        if not tenant:
            tenant = Tenant(name="Test Tenant")
            db.add(tenant)
            db.commit()
            db.refresh(tenant)
        
        user = db.query(User).filter_by(email="admin@test.com").first()
        if not user:
            user = User(
                email="admin@test.com",
                hashed_password=get_password_hash("password123"),
                tenant_id=tenant.id,
                role=Role.TENANT_ADMIN
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        # HoneyToken
        ht = db.query(HoneyToken).filter_by(name="Test HT").first()
        if not ht:
            ht = HoneyToken(
                name="Test HT",
                tenant_id=tenant.id,
                token_identifier="ht_12345",
                created_by_id=user.id
            )
            db.add(ht)
            db.commit()
            
        token = create_access_token(user.id, tenant.id)
        return token
    finally:
        db.close()

async def run_sse_ws(token):
    # Trigger HT
    async def trigger():
        await asyncio.sleep(2.0) # Wait for connections to establish
        async with httpx.AsyncClient(verify=False) as c:
            r = await c.get("https://nginx:443/t/ht_12345", headers={"Host": "honeyshield.local"})
            print(f"Triggered HT: {r.status_code}")
            
    # SSE
    async def run_sse():
        async with httpx.AsyncClient(verify=False) as c:
            req = c.build_request("GET", "https://nginx:443/api/v1/events/stream/sse", headers={"Host": "honeyshield.local", "Authorization": f"Bearer {token}"})
            response = await c.send(req, stream=True)
            print(f"SSE Status: {response.status_code}")
            print(f"SSE Content-Type: {response.headers.get('content-type')}")
            async for line in response.aiter_lines():
                if line.startswith("data:"):
                    print(f"SSE Received: {line}")
                    break
    
    # WS
    async def run_ws():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        async with websockets.connect("wss://nginx:443/api/v1/events/stream/ws", ssl=ctx, extra_headers={"Host": "honeyshield.local"}) as ws:
            print("WS Handshake Success")
            await ws.send(json.dumps({"type": "auth", "token": token}))
            auth_resp = await ws.recv()
            print(f"WS Auth Resp: {auth_resp}")
            evt = await ws.recv()
            print(f"WS Event: {evt}")
            return
            
    await asyncio.gather(run_sse(), run_ws(), trigger())

if __name__ == "__main__":
    time.sleep(2) # Give DB time just in case
    t = setup_db()
    asyncio.run(run_sse_ws(t))
