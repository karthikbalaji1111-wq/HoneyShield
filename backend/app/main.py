from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from app.api.auth.router import router as auth_router
from app.api.exception_handlers import register_exception_handlers
from app.api.v1.health import health_payload, readiness as v1_readiness
from app.api.v1.router import api_router
from app.api.ingestion.router import router as ingestion_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import engine, get_db
from app.middleware import register_middlewares
from app.schemas.health import HealthResponse
from app.services.event_broadcaster import get_broadcaster

settings = get_settings()
configure_logging(settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for graceful shutdown of real-time streaming and database connections."""
    get_broadcaster().reset()
    yield
    get_broadcaster().shutdown()
    try:
        engine.dispose()
    except Exception:
        pass


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Versioned REST API for HoneyShield deception security services.",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "service", "description": "Service availability endpoints."},
        {"name": "health", "description": "Health and readiness endpoints."},
        {"name": "tenants", "description": "Tenant management endpoints."},
        {"name": "projects", "description": "Project management endpoints."},
        {"name": "honey-tokens", "description": "Honey-token lifecycle endpoints."},
        {
            "name": "detection-events",
            "description": "Detection-event recording and retrieval endpoints.",
        },
        {
            "name": "threat-intelligence",
            "description": "Threat intelligence derived from detection-event activity.",
        },
        {
            "name": "events-stream",
            "description": "Real-time event streaming via WebSocket and SSE.",
        },
    ],
)
register_middlewares(app)
register_exception_handlers(app)
app.include_router(auth_router)
app.include_router(api_router, prefix=settings.api_v1_prefix)
app.include_router(ingestion_router)


@app.get(
    "/",
    response_model=dict[str, str],
    status_code=200,
    tags=["service"],
    summary="Get service status",
    description="Reports that the HoneyShield service is running.",
)
def read_root() -> dict[str, str]:
    """Return the service status payload."""
    return {"service": settings.app_name, "status": "running"}


@app.get(
    "/health",
    response_model=HealthResponse,
    status_code=200,
    tags=["health"],
    summary="Get service health",
    description="Reports whether the HoneyShield API is available.",
)
def health_check() -> HealthResponse:
    """Return the Docker-compatible service health payload."""
    return health_payload()


@app.get(
    "/ready",
    response_model=HealthResponse,
    responses={503: {"model": HealthResponse}},
    status_code=200,
    tags=["health"],
    summary="Get service readiness",
    description="Reports whether the HoneyShield service and its dependencies are ready to serve traffic.",
)
def readiness_check(session: Annotated[Session, Depends(get_db)]):
    """Root-level service readiness endpoint (mirrors /api/v1/ready)."""
    return v1_readiness(session=session)
