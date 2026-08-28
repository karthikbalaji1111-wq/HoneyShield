"""Real-time event streaming endpoints (WebSocket and SSE)."""

import asyncio
import json
from typing import Annotated, Any

import jwt as pyjwt
from fastapi import APIRouter, Depends, Header, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.dependencies import SessionDependency
from app.core.security import decode_access_token
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.services.event_broadcaster import get_broadcaster

router = APIRouter(prefix="/events/stream", tags=["events-stream"])


def _authenticate_token(token: str, session: Session) -> User | None:
    """Validate a JWT and return the active User, or None if invalid."""
    try:
        payload = decode_access_token(token)
        user_id_str = payload.get("sub")
        if not user_id_str:
            return None
        
        user_id = int(user_id_str)
        user = UserRepository(session).get_by_id(user_id)
        
        if user is None or not user.is_active:
            return None
            
        return user
    except (pyjwt.InvalidTokenError, ValueError, TypeError):
        return None


async def get_sse_user(
    session: SessionDependency,
    token: Annotated[str | None, Query(description="JWT token for EventSource clients")] = None,
    authorization: Annotated[str | None, Header(description="Bearer token")] = None,
) -> User:
    """Dependency to authenticate SSE connections.
    
    Checks Authorization header first, then falls back to 'token' query param
    because standard browser EventSource cannot send custom headers.
    """
    from app.core.auth_exceptions import UnauthorizedError
    
    raw_token = None
    if authorization and authorization.lower().startswith("bearer "):
        raw_token = authorization[len("bearer "):].strip()
    elif token:
        raw_token = token
        
    if not raw_token:
        raise UnauthorizedError("Missing authentication token")
        
    user = _authenticate_token(raw_token, session)
    if not user:
        raise UnauthorizedError("Invalid or expired authentication token")
        
    return user


@router.get(
    "/sse",
    summary="Server-Sent Events detection feed",
    description="Streams real-time detection events to authenticated clients.",
    response_class=StreamingResponse,
)
async def sse_stream(
    request: Request,
    user: Annotated[User, Depends(get_sse_user)],
) -> StreamingResponse:
    """Stream real-time detection events using Server-Sent Events."""
    broadcaster = get_broadcaster()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=broadcaster.MAX_QUEUE_SIZE)
    
    # SYSTEM_ADMIN has tenant_id = None
    sub_id = broadcaster.subscribe(tenant_id=user.tenant_id, queue=queue)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                    
                # Wait for an event with a timeout to check disconnects periodically
                try:
                    event_data = await asyncio.wait_for(queue.get(), timeout=15.0)
                    # Yield SSE formatted data
                    yield f"data: {json.dumps(event_data)}\n\n"
                except asyncio.TimeoutError:
                    # Send a keepalive comment
                    yield ": keepalive\n\n"
        finally:
            broadcaster.unsubscribe(sub_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable proxy buffering
        },
    )


@router.websocket("/ws")
async def websocket_stream(
    websocket: WebSocket,
    session: SessionDependency,
) -> None:
    """Stream real-time detection events over WebSocket.
    
    Authentication occurs via an initial message rather than query
    parameters to prevent logging the JWT in server access logs.
    
    Client must send: {"type": "auth", "token": "..."} within 5 seconds.
    """
    await websocket.accept()

    try:
        # 1. Initial-message authentication
        auth_msg = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)
        if not isinstance(auth_msg, dict) or auth_msg.get("type") != "auth" or not auth_msg.get("token"):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid auth message format")
            return
            
        user = _authenticate_token(auth_msg["token"], session)
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication failed")
            return

        # Send an auth success acknowledgement
        await websocket.send_json({"type": "auth_success"})

    except asyncio.TimeoutError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication timeout")
        return
    except Exception:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication error")
        return

    # 2. Subscribe to real-time events
    broadcaster = get_broadcaster()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=broadcaster.MAX_QUEUE_SIZE)
    sub_id = broadcaster.subscribe(tenant_id=user.tenant_id, queue=queue)

    async def send_events() -> None:
        """Continuously drain the queue and send events to the WebSocket."""
        try:
            while True:
                event_data = await queue.get()
                await websocket.send_json(event_data)
        except asyncio.CancelledError:
            pass

    async def receive_messages() -> None:
        """Keep reading to detect disconnects and handle client pings."""
        try:
            while True:
                msg = await websocket.receive_text()
                # Could handle client-sent pings or filters here
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass

    # 3. Run full-duplex communication until the client disconnects
    sender = asyncio.create_task(send_events())
    receiver = asyncio.create_task(receive_messages())

    try:
        done, pending = await asyncio.wait(
            [sender, receiver],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
    finally:
        broadcaster.unsubscribe(sub_id)
        try:
            await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)
        except Exception:
            pass
