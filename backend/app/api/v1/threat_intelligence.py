"""Version 1 threat-intelligence API routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path, status

from app.api.dependencies import get_threat_intelligence_service
from app.schemas.error import ErrorResponse
from app.schemas.threat_intelligence import (
    IPProfileResponse,
    ThreatSummaryResponse,
    TimelineResponse,
)
from app.services.threat_intelligence import ThreatIntelligenceService

router = APIRouter(prefix="/threats", tags=["threat-intelligence"])


@router.get(
    "/ip/{ip_address}",
    response_model=IPProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Get an IP threat profile",
    description="Builds an aggregated threat profile from persisted detection events.",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "No detection events exist for the source IP address.",
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
def get_ip_profile(
    ip_address: Annotated[
        str,
        Path(
            min_length=1,
            max_length=45,
            description="Observed source IP address.",
        ),
    ],
    service: Annotated[
        ThreatIntelligenceService,
        Depends(get_threat_intelligence_service),
    ],
) -> IPProfileResponse:
    """Retrieve and serialize one IP threat profile."""
    return service.get_ip_profile(ip_address=ip_address)


@router.get(
    "/timeline/{ip_address}",
    response_model=TimelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Get an IP event timeline",
    description="Returns the most recent 100 events for an IP in chronological order.",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "No detection events exist for the source IP address.",
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
def get_event_timeline(
    ip_address: Annotated[
        str,
        Path(
            min_length=1,
            max_length=45,
            description="Observed source IP address.",
        ),
    ],
    service: Annotated[
        ThreatIntelligenceService,
        Depends(get_threat_intelligence_service),
    ],
) -> TimelineResponse:
    """Retrieve and serialize one IP event timeline."""
    return service.get_event_timeline(ip_address=ip_address)


@router.get(
    "/summary",
    response_model=ThreatSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get threat intelligence summary",
    description="Returns aggregate intelligence derived from all detection events.",
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def get_threat_summary(
    service: Annotated[
        ThreatIntelligenceService,
        Depends(get_threat_intelligence_service),
    ],
) -> ThreatSummaryResponse:
    """Retrieve and serialize aggregate threat intelligence."""
    return service.get_summary()


@router.get(
    "/top-attackers",
    response_model=list[IPProfileResponse],
    status_code=status.HTTP_200_OK,
    summary="List top attackers",
    description="Returns the ten highest-scoring source IP threat profiles.",
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def get_top_attackers(
    service: Annotated[
        ThreatIntelligenceService,
        Depends(get_threat_intelligence_service),
    ],
) -> list[IPProfileResponse]:
    """Retrieve and serialize the ten highest-scoring attackers."""
    return service.get_top_attackers()
