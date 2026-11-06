"""Real-time event streaming endpoints (WebSocket and SSE)."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import dataclass
import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import StreamingResponse

from app.core.exceptions import HoneyShieldException
from app.core.security import resolve_access_token
from app.db.session import get_db
from app.services.event_broadcaster import get_broadcaster

router = APIRouter(prefix="/events/stream", tags=["events-stream"])

REVALIDATION_INTERVAL_SECONDS: float = 30.0


@dataclass(frozen=True)
class StreamAuthContext:
    """Detached authorization context for long-lived streams.

    Does NOT retain a SQLAlchemy Session or live ORM object (fixes F-001).
    """

    user_id: int
    tenant_id: int | None
    role: str
    token_version: int
    is_active: bool


@contextmanager
def acquire_db_session():
    """Acquire an isolated, short-lived DB session and cleanly close it on exit.

    Uses app.dependency_overrides when present (e.g. In tests) and defaults
    to get_db() in production, ensuring sessions are closed and connections
    are immediately returned to the pool (fixes F-001).
    """
    from app.main import app
    factory = app.dependency_overrides.get(get_db, get_db)
    gen = factory()
    session = next(gen)
    try:
        yield session
    finally:
        try:
            next(gen)
        except StopIteration:
            pass
        except Exception:
            pass


def authenticate_streaming_token(token: str) -> StreamAuthContext | None:
    """Validate a JWT against the database in a short-lived session, returning a detached auth context.

    The database session is closed immediately after authentication, ensuring that no
    SQLAlchemy session or connection is retained during streaming (fixes F-001).
    """
    from app.models.tenant import Tenant

    with acquire_db_session() as session:
        try:
            user = resolve_access_token(token, session)
            if not user or not user.is_active:
                return None
            if user.tenant_id is not None:
                tenant = session.get(Tenant, user.tenant_id)
                if not tenant or not tenant.is_active:
                    return None
            return StreamAuthContext(
                user_id=user.id,
                tenant_id=user.tenant_id,
                role=user.role.value if hasattr(user.role, "value") else str(user.role),
                token_version=user.token_version,
                is_active=user.is_active,
            )
        except Exception:
            return None


def revalidate_streaming_context(context: StreamAuthContext) -> bool:
    """Check if the user, token version, and tenant remain valid and active (fixes F-008).

    Uses a fast primary-key lookup in an isolated short-lived session that is immediately closed.
    """
    from app.models.tenant import Tenant
    from app.models.user import User

    with acquire_db_session() as session:
        try:
            user = session.get(User, context.user_id)
            if not user or not user.is_active:
                return False
            if user.token_version != context.token_version:
                return False
            if context.tenant_id is not None:
                tenant = session.get(Tenant, context.tenant_id)
                if not tenant or not tenant.is_active:
                    return False
            return True
        except Exception:
            return False


def get_sse_user(
    token: Annotated[str | None, Query(description="JWT token for EventSource clients")] = None,
    authorization: Annotated[str | None, Header(description="Bearer token")] = None,
) -> StreamAuthContext:
    """Authenticate SSE connections in a short-lived DB session and return detached auth context.

    Checks Authorization header first (preferred), then falls back to 'token' query param
    for browser EventSource compatibility (F-009). The DB session is closed immediately.
    """
    from app.core.auth_exceptions import UnauthorizedError

    raw_token = None
    if authorization and authorization.lower().startswith("bearer "):
        raw_token = authorization[len("bearer "):].strip()
    elif token:
        raw_token = token

    if not raw_token:
        raise UnauthorizedError("Missing authentication token")

    auth_ctx = authenticate_streaming_token(raw_token)
    if not auth_ctx:
        raise UnauthorizedError("Invalid or expired authentication token")

    return auth_ctx


@router.get(
    "/sse",
    summary="Server-Sent Events detection feed",
    description="Streams real-time detection events to authenticated clients.",
    response_class=StreamingResponse,
)
async def sse_stream(
    request: Request,
    user: Annotated[StreamAuthContext, Depends(get_sse_user)],
) -> StreamingResponse:
    """Stream real-time detection events using Server-Sent Events."""
    broadcaster = get_broadcaster()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=broadcaster.MAX_QUEUE_SIZE)
    sub_id = broadcaster.subscribe(tenant_id=user.tenant_id, queue=queue)

    async def event_generator():
        last_revalidation = asyncio.get_running_loop().time()
        try:
            while True:
                if await request.is_disconnected():
                    break

                now = asyncio.get_running_loop().time()
                if now - last_revalidation >= REVALIDATION_INTERVAL_SECONDS:
                    is_valid = await asyncio.to_thread(revalidate_streaming_context, user)
                    if not is_valid:
                        yield f"event: error\ndata: {json.dumps({'error': 'Authorization revoked or user inactive'})}\n\n"
                        break
                    last_revalidation = now

                try:
                    event_data = await asyncio.wait_for(queue.get(), timeout=15.0)
                    if event_data.get("type") == "shutdown":
                        yield f"event: shutdown\ndata: {json.dumps({'message': 'Server shutting down'})}\n\n"
                        break
                    yield f"data: {json.dumps(event_data)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            broadcaster.unsubscribe(sub_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.websocket("/ws")
async def websocket_stream(
    websocket: WebSocket,
) -> None:
    """Stream real-time detection events over WebSocket.

    Authentication occurs via an initial message: {"type": "auth", "token": "..."}.
    The database session is used ONLY during authentication, and is immediately closed.
    Zero database connections are retained during streaming (fixes F-001).
    """
    await websocket.accept()

    try:
        # 1. Initial-message authentication
        auth_msg = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)
        if not isinstance(auth_msg, dict) or auth_msg.get("type") != "auth" or not auth_msg.get("token"):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid auth message format")
            return

        auth_ctx = await asyncio.to_thread(authenticate_streaming_token, auth_msg["token"])
        if not auth_ctx:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication failed")
            return

        await websocket.send_json({"type": "auth_success"})

    except asyncio.TimeoutError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication timeout")
        return
    except Exception:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication error")
        return

    # 2. Subscribe to real-time events with detached auth context
    broadcaster = get_broadcaster()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=broadcaster.MAX_QUEUE_SIZE)
    sub_id = broadcaster.subscribe(tenant_id=auth_ctx.tenant_id, queue=queue)

    async def send_events() -> None:
        """Continuously drain queue and send events."""
        try:
            while True:
                event_data = await queue.get()
                if event_data.get("type") == "shutdown":
                    await websocket.close(code=status.WS_1001_GOING_AWAY, reason="Server shutting down")
                    break
                await websocket.send_json(event_data)
        except asyncio.CancelledError:
            pass

    async def receive_messages() -> None:
        """Read client messages, detect disconnects, and handle pings."""
        try:
            while True:
                msg = await websocket.receive_text()
                if msg == "ping":
                    await websocket.send_text("pong")
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass

    async def revalidate_loop() -> None:
        """Periodically revalidate the user's active status, token_version, and tenant status (F-008)."""
        try:
            while True:
                await asyncio.sleep(REVALIDATION_INTERVAL_SECONDS)
                is_valid = await asyncio.to_thread(revalidate_streaming_context, auth_ctx)
                if not is_valid:
                    await websocket.close(
                        code=status.WS_1008_POLICY_VIOLATION,
                        reason="Authorization revoked or user inactive",
                    )
                    break
        except asyncio.CancelledError:
            pass

    # 3. Run full-duplex communication until client disconnects or revalidation fails
    sender = asyncio.create_task(send_events())
    receiver = asyncio.create_task(receive_messages())
    revalidator = asyncio.create_task(revalidate_loop())

    try:
        done, pending = await asyncio.wait(
            [sender, receiver, revalidator],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    finally:
        broadcaster.unsubscribe(sub_id)
        try:
            await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)
        except Exception:
            pass
