from __future__ import annotations

from fastapi import FastAPI

from app.middleware.body_size import RequestBodySizeMiddleware
from app.middleware.exception_handler import GlobalExceptionMiddleware
from app.middleware.rate_limit import ApiRateLimitMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.request_timing import RequestTimingMiddleware


def register_middlewares(app: FastAPI) -> None:
    """Register application middlewares in explicit pipeline order.

    Wrapping Order (Outermost to Innermost):
    1. RequestIDMiddleware: Assigns / extracts X-Request-ID header and logging token.
    2. RequestBodySizeMiddleware: Rejects oversized bodies before processing (F-010).
    3. ApiRateLimitMiddleware: Bounded admission control for API traffic (F-011).
    4. RequestTimingMiddleware: Computes execution latency and appends X-Process-Time-Ms.
    5. GlobalExceptionMiddleware: Catch-all fallback for uncaught internal server errors.
    """
    app.add_middleware(GlobalExceptionMiddleware)
    app.add_middleware(RequestTimingMiddleware)
    app.add_middleware(ApiRateLimitMiddleware)
    app.add_middleware(RequestBodySizeMiddleware)
    app.add_middleware(RequestIDMiddleware)
