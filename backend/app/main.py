from fastapi import FastAPI

from app.api.auth.router import router as auth_router
from app.api.exception_handlers import register_exception_handlers
from app.api.v1.health import health_payload
from app.api.v1.router import api_router
from app.api.ingestion.router import router as ingestion_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.middleware import register_middlewares
from app.schemas.health import HealthResponse

settings = get_settings()
configure_logging(settings.log_level)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Versioned REST API for HoneyShield deception security services.",
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
