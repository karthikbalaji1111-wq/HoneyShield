import asyncio
import httpx
import websockets
import json
import ssl
import sys

async def run_sse_ws(token, ht_val):
    # Trigger HT
    async def trigger():
        await asyncio.sleep(2.0)
        async with httpx.AsyncClient(verify=False) as c:
            r = await c.get(f"https://127.0.0.1:8443/t/{ht_val}", headers={"Host": "honeyshield.local"})
            print(f"Triggered HT: {r.status_code}")
            
    # SSE
    async def run_sse():
        async with httpx.AsyncClient(verify=False) as c:
            req = c.build_request("GET", "https://127.0.0.1:8443/api/v1/events/stream/sse", headers={"Host": "honeyshield.local", "Authorization": f"Bearer {token}"})
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
        async with websockets.connect("wss://127.0.0.1:8443/api/v1/events/stream/ws", ssl=ctx, additional_headers={"Host": "honeyshield.local"}) as ws:
            print("WS Handshake Success")
            await ws.send(json.dumps({"type": "auth", "token": token}))
            auth_resp = await ws.recv()
            print(f"WS Auth Resp: {auth_resp}")
            evt = await ws.recv()
            print(f"WS Event: {evt}")
            return
            
    await asyncio.gather(run_sse(), run_ws(), trigger())

if __name__ == "__main__":
    asyncio.run(run_sse_ws(sys.argv[1], sys.argv[2]))
