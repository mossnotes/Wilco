import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, HTTPException, Request, status
from aiogram.types import Update

from app.config import settings
from app.bot.setup import get_bot, get_dispatcher

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Telegram Webhook"])


@router.post(settings.WEBHOOK_PATH)
async def telegram_webhook(
    request: Request,
    x_telegram_bot_api_secret_token: Optional[str] = Header(None, alias="X-Telegram-Bot-Api-Secret-Token"),
) -> Dict[str, Any]:
    """
    Handle incoming Telegram webhook updates.
    Validates secret token and dispatches updates to aiogram.
    """
    # 1. Verify webhook secret token if configured
    if settings.TELEGRAM_WEBHOOK_SECRET:
        if not x_telegram_bot_api_secret_token or x_telegram_bot_api_secret_token != settings.TELEGRAM_WEBHOOK_SECRET:
            logger.warning("Rejected webhook request: missing or invalid secret token.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid secret token",
            )

    # 2. Ensure Bot is available
    bot = get_bot()
    if bot is None:
        logger.error("Webhook received but Telegram bot is not configured or initialized.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Telegram bot is not initialized",
        )

    # 3. Parse Update JSON payload
    try:
        raw_data = await request.json()
        update = Update.model_validate(raw_data, context={"bot": bot})
    except Exception as exc:
        logger.warning(f"Failed to parse Telegram update payload: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid update data: {str(exc)}",
        )

    # 4. Dispatch update to aiogram
    dp = get_dispatcher()
    try:
        await dp.feed_update(bot=bot, update=update)
    except Exception as exc:
        logger.exception(f"Error handling Telegram update: {exc}")
        # Note: Return 200 OK to Telegram so it doesn't repeatedly retry failed updates,
        # but log the exception for debugging.
        return {"ok": False, "error": str(exc)}

    return {"ok": True}

