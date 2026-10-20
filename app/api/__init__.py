from fastapi import APIRouter
from app.api.health import router as health_router
from app.api.webhook import router as webhook_router
from app.companion.routes import companion_router, tasks_api_router, vault_api_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(webhook_router)
api_router.include_router(companion_router)
api_router.include_router(vault_api_router)
api_router.include_router(tasks_api_router)

__all__ = ["api_router"]
