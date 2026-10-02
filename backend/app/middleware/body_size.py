"""ASGI middleware to enforce strict request body-size limits (F-010)."""
from __future__ import annotations

import json
from typing import Optional

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import get_settings
from app.core.exceptions import PayloadTooLargeError


class RequestBodySizeMiddleware:
    """Enforces configurable maximum request body size limits at the ASGI boundary.

    Protection Flow:
    1. Inspects the 'Content-Length' header if present. If it exceeds max_bytes,
       rejects the request immediately with HTTP 413 without reading any body bytes.
    2. For chunked, streamed, or missing Content-Length requests, wraps the receive
       callable to count cumulative payload bytes. If the stream exceeds max_bytes,
       raises PayloadTooLargeError immediately, terminating reading and returning HTTP 413.
    3. Normal requests pass through with zero performance degradation.
    """

    def __init__(
        self,
        app: ASGIApp,
        max_bytes: Optional[int] = None,
    ) -> None:
        self.app = app
        self._configured_max_bytes = max_bytes

    @property
    def max_bytes(self) -> int:
        if self._configured_max_bytes is not None:
            return self._configured_max_bytes
        return get_settings().max_request_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        request_id = headers.get("x-request-id", "-")
        content_length_header = headers.get("content-length")
        max_allowed = self.max_bytes

        # 1. Fast Content-Length pre-check: reject before consuming any body into memory
        if content_length_header is not None:
            try:
                content_length = int(content_length_header)
                if content_length > max_allowed:
                    await self._send_413_response(send, max_allowed, request_id)
                    return
            except ValueError:
                await self._send_error_response(send, 400, "Invalid Content-Length header", request_id)
                return

        # 2. Streaming count wrapper for chunked or missing Content-Length
        bytes_received = 0

        async def bounded_receive() -> Message:
            nonlocal bytes_received
            message = await receive()
            if message["type"] == "http.request":
                chunk_len = len(message.get("body", b""))
                bytes_received += chunk_len
                if bytes_received > max_allowed:
                    raise PayloadTooLargeError(
                        f"Request payload exceeds maximum allowed size of {max_allowed} bytes"
                    )
            return message

        try:
            await self.app(scope, bounded_receive, send)
        except PayloadTooLargeError as exc:
            await self._send_413_response(send, max_allowed, request_id)

    async def _send_413_response(self, send: Send, max_bytes: int, request_id: str) -> None:
        """Send standard HTTP 413 Payload Too Large response."""
        body = json.dumps({
            "detail": f"Request payload exceeds maximum allowed size of {max_bytes} bytes",
            "request_id": request_id,
        }).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        })

    async def _send_error_response(self, send: Send, status: int, detail: str, request_id: str) -> None:
        """Send generic JSON error response."""
        body = json.dumps({
            "detail": detail,
            "request_id": request_id,
        }).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        })
