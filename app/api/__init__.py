from fastapi import APIRouter
from app.api.health import router as health_router
from app.api.webhook import router as webhook_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(webhook_router)

__all__ = ["api_router"]

