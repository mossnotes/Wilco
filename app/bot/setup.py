import logging
from typing import Optional
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode

from app.config import settings
from app.bot.delivery import MessageDeliveryMiddleware
from app.bot.handlers import router

logger = logging.getLogger(__name__)

_bot: Optional[Bot] = None
_dispatcher: Optional[Dispatcher] = None


def get_bot() -> Optional[Bot]:
    """Retrieve or initialize the singleton Bot instance."""
    global _bot
    if _bot is None and settings.is_bot_configured:
        _bot = Bot(
            token=settings.TELEGRAM_BOT_TOKEN,
            default=DefaultBotProperties(parse_mode=ParseMode.HTML),
        )
        _bot.session.middleware.register(MessageDeliveryMiddleware(
            max_chars=settings.TELEGRAM_MESSAGE_MAX_CHARS,
            chars_per_second=settings.TELEGRAM_TYPING_CHARS_PER_SECOND,
        ))
    return _bot


def set_bot(bot: Optional[Bot]) -> None:
    """Override the singleton Bot instance (useful for testing or mocking)."""
    global _bot
    _bot = bot


def get_dispatcher() -> Dispatcher:
    """Retrieve or initialize the Dispatcher instance with registered routers."""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = Dispatcher()
        _dispatcher.include_router(router)
    return _dispatcher

