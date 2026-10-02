"""Public ingestion API routes with forensic abuse control and trusted IP extraction."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request, Response, status

from app.api.dependencies import get_detection_event_service
from app.core.config import get_settings
from app.core.exceptions import HoneyTokenNotFoundError, ValidationError
from app.core.ip_trust import extract_client_ip
from app.core.rate_limit import ingestion_limiter
from app.models.enums import EventSeverity
from app.services.detection_event import DetectionEventService

router = APIRouter(tags=["ingestion"])

# 1x1 transparent GIF (43 bytes)
_TRANSPARENT_GIF = (
    b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00"
    b"\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21"
    b"\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00"
    b"\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44"
    b"\x01\x00\x3b"
)


def _check_ingestion_rate_limit(client_ip: str, token_value: str) -> tuple[bool, int]:
    """Check admission control for ingestion requests.

    Guarantees:
    - Bounded per-IP and per-(IP, token) counters to prevent DB flood.
    - Keying by (IP, token) ensures triggering one token does not suppress evidence of another.
    - Exceeded limits return HTTP 429 with Retry-After.
    """
    settings = get_settings()
    if not settings.rate_limit_enabled:
        return True, 0

    # Check IP-level cap
    allowed_ip, retry_after_ip = ingestion_limiter.check_and_increment(
        key=f"ingest_ip:{client_ip}",
        limit=settings.ingestion_rate_limit_per_minute_ip,
        global_limit=settings.rate_limit_global_per_minute,
        window_seconds=60,
    )
    if not allowed_ip:
        return False, retry_after_ip

    # Check (IP, token) cap
    allowed_token, retry_after_token = ingestion_limiter.check_and_increment(
        key=f"ingest_token:{client_ip}:{token_value}",
        limit=settings.ingestion_rate_limit_per_minute_token,
        global_limit=settings.rate_limit_global_per_minute,
        window_seconds=60,
    )
    if not allowed_token:
        return False, retry_after_token

    return True, 0


@router.get(
    "/t/{token_value}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Trigger a URL honey token",
    description="Public ingestion endpoint for URL and link honey tokens.",
    response_class=Response,
)
def trigger_url_token(
    token_value: Annotated[
        str,
        Path(description="Honey-token value embedded in the URL."),
    ],
    request: Request,
    service: Annotated[DetectionEventService, Depends(get_detection_event_service)],
) -> Response:
    """Accept a URL honey-token trigger."""
    settings = get_settings()
    client_ip = extract_client_ip(request, settings)

    allowed, retry_after = _check_ingestion_rate_limit(client_ip, token_value)
    if not allowed:
        return Response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
        )

    try:
        service.record_event(
            token_value=token_value,
            ip_address=client_ip,
            request_path=request.url.path,
            http_method=request.method,
            severity=EventSeverity.MEDIUM,
            user_agent=request.headers.get("user-agent"),
            headers=dict(request.headers),
        )
    except (HoneyTokenNotFoundError, ValidationError):
        pass
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/px/{token_value}.gif",
    summary="Trigger a tracking pixel honey token",
    description="Public ingestion endpoint for tracking pixel honey tokens.",
    response_class=Response,
)
def trigger_pixel_token(
    token_value: Annotated[
        str,
        Path(description="Honey-token value embedded in the pixel URL."),
    ],
    request: Request,
    service: Annotated[DetectionEventService, Depends(get_detection_event_service)],
) -> Response:
    """Accept a tracking-pixel honey-token trigger and return a transparent GIF."""
    clean_token = token_value[:-4] if token_value.endswith(".gif") else token_value
    settings = get_settings()
    client_ip = extract_client_ip(request, settings)

    allowed, retry_after = _check_ingestion_rate_limit(client_ip, clean_token)
    if not allowed:
        return Response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
        )

    try:
        service.record_event(
            token_value=clean_token,
            ip_address=client_ip,
            request_path=request.url.path,
            http_method=request.method,
            severity=EventSeverity.MEDIUM,
            user_agent=request.headers.get("user-agent"),
            headers=dict(request.headers),
        )
    except (HoneyTokenNotFoundError, ValidationError):
        pass
    return Response(
        content=_TRANSPARENT_GIF,
        media_type="image/gif",
        status_code=status.HTTP_200_OK,
    )


@router.post(
    "/collect/{token_value}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Collect a programmable honey token trigger",
    description="Public ingestion endpoint for API key and programmable honey tokens.",
    response_class=Response,
)
def collect_token(
    token_value: Annotated[
        str,
        Path(description="Honey-token value embedded in the collection URL."),
    ],
    request: Request,
    service: Annotated[DetectionEventService, Depends(get_detection_event_service)],
) -> Response:
    """Accept a programmable honey-token trigger."""
    settings = get_settings()
    client_ip = extract_client_ip(request, settings)

    allowed, retry_after = _check_ingestion_rate_limit(client_ip, token_value)
    if not allowed:
        return Response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
        )

    try:
        service.record_event(
            token_value=token_value,
            ip_address=client_ip,
            request_path=request.url.path,
            http_method=request.method,
            severity=EventSeverity.MEDIUM,
            user_agent=request.headers.get("user-agent"),
            headers=dict(request.headers),
        )
    except (HoneyTokenNotFoundError, ValidationError):
        pass
    return Response(status_code=status.HTTP_204_NO_CONTENT)
