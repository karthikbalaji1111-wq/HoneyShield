from fastapi import APIRouter

from app.api.v1.detection_events import router as detection_event_router
from app.api.v1.health import router as health_router
from app.api.v1.honey_tokens import router as honey_token_router
from app.api.v1.projects import router as project_router
from app.api.v1.tenants import router as tenant_router
from app.api.v1.threat_intelligence import router as threat_intelligence_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(tenant_router)
api_router.include_router(project_router)
api_router.include_router(honey_token_router)
api_router.include_router(detection_event_router)
api_router.include_router(threat_intelligence_router)
