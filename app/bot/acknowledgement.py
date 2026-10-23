"""Acknowledge accepted browser work on its originating Telegram message."""

import asyncio
import logging
from contextlib import asynccontextmanager

from aiogram.types import Message, ReactionTypeEmoji

logger = logging.getLogger(__name__)

ACKNOWLEDGEMENT_TIMEOUT_SECONDS = 5


@asynccontextmanager
async def browser_task_acknowledgement(message: Message):
    async def set_reaction(active: bool) -> None:
        async with asyncio.timeout(ACKNOWLEDGEMENT_TIMEOUT_SECONDS):
            await message.bot.set_message_reaction(
                chat_id=message.chat.id,
                message_id=message.message_id,
                reaction=[ReactionTypeEmoji(emoji="👀")] if active else [],
                is_big=False,
            )

    try:
        try:
            await set_reaction(True)
        except Exception:
            logger.warning("Could not react to browser request in chat %s", message.chat.id)
            try:
                async with asyncio.timeout(ACKNOWLEDGEMENT_TIMEOUT_SECONDS):
                    await message.answer("On it.", parse_mode=None)
            except Exception:
                logger.warning("Could not acknowledge browser request in chat %s", message.chat.id)
        yield
    finally:
        # Also clear after cancellation during the initial request: Telegram may
        # have applied the reaction even if its response never reached us.
        try:
            await set_reaction(False)
        except Exception:
            logger.warning("Could not clear browser request reaction in chat %s", message.chat.id)
