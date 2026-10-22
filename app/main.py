import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.config import settings
from app.api import api_router
from app.bot.setup import get_bot, get_dispatcher
from app.db.engine import close_db, init_db

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wilco")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manage lifecycle of the FastAPI application and Telegram Bot.
    Handles webhook registration or background polling on startup,
    and graceful session cleanup on shutdown.
    """
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} (mode={settings.BOT_MODE})")
    try:
        await init_db()
        logger.info("Database tables initialized successfully.")
    except Exception as exc:
        logger.error(f"Error during database initialization: {exc}")
    bot = get_bot()
    dp = get_dispatcher()
    polling_task = None

    if bot is not None:
        try:
            if settings.BOT_MODE == "webhook":
                if settings.full_webhook_url:
                    logger.info(f"Setting Telegram webhook: {settings.full_webhook_url}")
                    await bot.set_webhook(
                        url=settings.full_webhook_url,
                        secret_token=settings.TELEGRAM_WEBHOOK_SECRET or None,
                        drop_pending_updates=True,
                        allowed_updates=dp.resolve_used_update_types(),
                    )
                    logger.info("Telegram webhook successfully registered.")
                else:
                    logger.warning(
                        "BOT_MODE is 'webhook' but TELEGRAM_WEBHOOK_URL is empty. "
                        "Skipping automated Telegram set_webhook registration."
                    )
            elif settings.BOT_MODE == "polling":
                logger.info("Starting Telegram bot in polling mode for local development...")
                # Delete any existing webhook before polling
                await bot.delete_webhook(drop_pending_updates=True)
                polling_task = asyncio.create_task(dp.start_polling(bot))
        except Exception as exc:
            logger.error(f"Error during bot startup lifecycle: {exc}")
    else:
        logger.info("Telegram bot token not provided; bot integration is idle.")

    try:
        yield
    finally:
        logger.info("Shutting down application...")
        if polling_task and not polling_task.done():
            logger.info("Cancelling background polling task...")
            polling_task.cancel()
            try:
                await polling_task
            except asyncio.CancelledError:
                pass

        if bot is not None:
            try:
                await bot.session.close()
                logger.info("Telegram bot HTTP session closed.")
            except Exception as exc:
                logger.error(f"Error closing bot session: {exc}")

        try:
            await close_db()
            logger.info("Database connection pools closed.")
        except Exception as exc:
            logger.error(f"Error closing database connections: {exc}")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

app.mount(
    "/companion/static",
    StaticFiles(directory=Path(__file__).parent / "companion" / "static"),
    name="companion-static",
)
app.include_router(api_router)


@app.get("/")
async def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health",
    }

