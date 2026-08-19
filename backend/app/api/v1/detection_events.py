"""Version 1 detection-event API routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import CurrentUser, TenantAdminRequired, get_detection_event_service
from app.schemas.detection_event import (
    DetectionEventCreate,
    DetectionEventResponse,
    DetectionEventStatisticsResponse,
)
from app.schemas.error import ErrorResponse
from app.services.detection_event import DetectionEventService

router = APIRouter(prefix="/detection-events", tags=["detection-events"])


@router.post(
    "",
    response_model=DetectionEventResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record a detection event",
    description="Records an immutable event for a triggered honey token.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "TENANT_ADMIN role or above required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Honey token does not exist.",
        },
        status.HTTP_422_UNPROCESSABLE_ENTITY: {
            "model": ErrorResponse,
            "description": "Request or domain validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def create_detection_event(
    payload: DetectionEventCreate,
    service: Annotated[DetectionEventService, Depends(get_detection_event_service)],
    _: TenantAdminRequired,
) -> DetectionEventResponse:
    """Record and serialize a detection event. Requires TENANT_ADMIN or above."""
    return service.record_event(
        token_value=payload.token_value,
        ip_address=payload.ip_address,
        request_path=payload.request_path,
        http_method=payload.http_method,
        severity=payload.severity,
        user_agent=payload.user_agent,
        headers=payload.headers,
    )


@router.get(
    "",
    response_model=list[DetectionEventResponse],
    status_code=status.HTTP_200_OK,
    summary="List recent detection events",
    description="Lists recent events globally or for one honey token.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Supplied honey token does not exist.",
        },
        status.HTTP_422_UNPROCESSABLE_ENTITY: {
            "model": ErrorResponse,
            "description": "Request or domain validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def list_detection_events(
    service: Annotated[
        DetectionEventService,
        Depends(get_detection_event_service),
    ],
    _: CurrentUser,
    token_value: Annotated[
        str | None,
        Query(
            max_length=512,
            description="Optional honey-token value used to scope results.",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(
            ge=1,
            description="Maximum number of recent events to return.",
        ),
    ] = 100,
) -> list[DetectionEventResponse]:
    """List and serialize recent detection events. Requires authentication."""
    return service.list_recent_events(token_value=token_value, limit=limit)


@router.get(
    "/statistics",
    response_model=DetectionEventStatisticsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get detection-event statistics",
    description="Returns global total and current UTC-day event counts.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def get_detection_event_statistics(
    service: Annotated[
        DetectionEventService,
        Depends(get_detection_event_service),
    ],
    _: CurrentUser,
) -> DetectionEventStatisticsResponse:
    """Retrieve and serialize detection-event statistics. Requires authentication."""
    return service.get_statistics()
