from __future__ import annotations

from pathlib import Path
from typing import Annotated

from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


import logging

logger = logging.getLogger(__name__)


def health_payload() -> dict[str, str]:
    return {"status": "healthy"}


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Get service health",
    description="Reports whether the HoneyShield API is available.",
)
def health_check() -> HealthResponse:
    """Return the versioned service health payload."""
    return health_payload()


@router.get("/ready", response_model=HealthResponse, responses={503: {"model": HealthResponse}})
def readiness(session: Annotated[Session, Depends(get_db)]):
    """Check connectivity and migration revision; liveness remains DB-free."""
    try:
        # Minimal low-overhead connectivity check (F-017 / Phase 9)
        session.execute(text("SELECT 1"))

        backend = Path(__file__).resolve().parents[3]
        config = Config()
        config.set_main_option("script_location", str(backend / "alembic"))
        expected = set(ScriptDirectory.from_config(config).get_heads())

        actual = set(session.execute(text("SELECT version_num FROM alembic_version")).scalars())
        if actual != expected:
            return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"status": "not_ready"})
    except (SQLAlchemyError, Exception) as exc:
        logger.warning("Readiness probe check failed: %s", type(exc).__name__)
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"status": "not_ready"})
    return {"status": "ready"}
