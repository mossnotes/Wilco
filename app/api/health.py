from fastapi import APIRouter
from app.config import settings

router = APIRouter(tags=["Health"])


@router.get("/health")
async def healthcheck():
    """Service healthcheck endpoint for liveness and readiness probes."""
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "bot_mode": settings.BOT_MODE,
        "bot_configured": settings.is_bot_configured,
        "webhook_url": settings.full_webhook_url if settings.BOT_MODE == "webhook" else None,
    }

