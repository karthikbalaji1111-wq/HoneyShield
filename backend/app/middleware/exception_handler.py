from __future__ import annotations

import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from app.core.exceptions import PayloadTooLargeError, RateLimitExceededError

logger = logging.getLogger(__name__)


class GlobalExceptionMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        try:
            return await call_next(request)
        except PayloadTooLargeError as exc:
            request_id = getattr(request.state, "request_id", "-")
            return JSONResponse(
                status_code=413,
                content={
                    "detail": str(exc),
                    "request_id": request_id,
                },
            )
        except RateLimitExceededError as exc:
            request_id = getattr(request.state, "request_id", "-")
            headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
            return JSONResponse(
                status_code=429,
                content={
                    "detail": exc.detail,
                    "request_id": request_id,
                },
                headers=headers,
            )
        except Exception:
            request_id = getattr(request.state, "request_id", "-")
            logger.exception("Unhandled request exception")
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal server error",
                    "request_id": request_id,
                },
            )
