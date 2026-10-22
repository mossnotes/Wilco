"""Serialize Telegram delivery and pace short messages with a typing indicator."""

import asyncio
import html
import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

from aiogram import Bot
from aiogram.client.default import Default
from aiogram.client.session.middlewares.base import BaseRequestMiddleware, NextRequestMiddlewareType
from aiogram.enums import ChatAction, ParseMode
from aiogram.exceptions import TelegramAPIError, TelegramRetryAfter
from aiogram.methods import EditMessageReplyMarkup, EditMessageText, SendChatAction, SendMessage, SendPhoto
from aiogram.methods.base import TelegramMethod
from aiogram.utils.text_decorations import html_decoration

logger = logging.getLogger(__name__)


class _HTMLText(HTMLParser):
    """Keep formatting attached to text so every split has balanced HTML tags."""

    def __init__(self, source: str) -> None:
        super().__init__(convert_charrefs=True)
        self.text = ""
        self.runs: list[tuple[int, str, tuple[tuple[str, str], ...]]] = []
        self.tags: list[tuple[str, str]] = []
        self.feed(source)
        self.close()

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        self.tags.append((tag, self.get_starttag_text()))

    def handle_endtag(self, tag: str) -> None:
        if self.tags and self.tags[-1][0] == tag:
            self.tags.pop()

    def handle_data(self, data: str) -> None:
        self.runs.append((len(self.text), data, tuple(self.tags)))
        self.text += data

    def render(self, start: int, end: int) -> str:
        pieces = []
        for offset, text, tags in self.runs:
            fragment = text[max(0, start - offset):max(0, end - offset)]
            if fragment:
                pieces.append(
                    "".join(opening for _, opening in tags)
                    + html.escape(fragment)
                    + "".join(f"</{tag}>" for tag, _ in reversed(tags))
                )
        return "".join(pieces)


def _text_ranges(text: str, limit: int) -> list[tuple[int, int]]:
    """Split paragraphs, then sentences, lines, words, or an unbroken long token."""
    ranges = []
    start = 0
    paragraphs = [match.start() for match in re.finditer(r"\n[ \t]*\n", text)] + [len(text)]
    for paragraph_end in paragraphs:
        while start < paragraph_end:
            while start < paragraph_end and text[start].isspace():
                start += 1
            if start == paragraph_end:
                break
            end = min(start + limit, paragraph_end)
            if end < paragraph_end and not text[end].isspace():
                window = text[start:end]
                boundaries = list(re.finditer(r"[.!?。！？][\"'’”)]*\s+|\n", window))
                boundary = boundaries[-1].end() if boundaries else 0
                if boundary < limit // 3:
                    spaces = list(re.finditer(r"\s+", window))
                    boundary = spaces[-1].start() if spaces else 0
                end = start + (boundary or limit)
            trimmed_end = end
            while trimmed_end > start and text[trimmed_end - 1].isspace():
                trimmed_end -= 1
            if trimmed_end > start:
                ranges.append((start, trimmed_end))
            start = end
    return ranges


def split_message(text: str, limit: int = 320, *, is_html: bool = False) -> list[str]:
    """Bound visible message length without breaking HTML tags or escaped entities."""
    if limit < 1:
        raise ValueError("Message length must be positive")
    document = _HTMLText(text) if is_html else None
    plain_text = document.text if document else text
    return [
        document.render(start, end) if document else text[start:end]
        for start, end in _text_ranges(plain_text, limit)
    ] or [text]


@dataclass
class _ChatQueue:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    users: int = 0


class MessageDeliveryMiddleware(BaseRequestMiddleware):
    """One FIFO queue per chat, shared by replies, browser prompts, and results.

    A batch holds the fair asyncio lock until all its chunks have been sent.
    Waiting callers form the queue; cancellation removes their pending work and
    idle queues are discarded, so no background workers need shutdown handling.
    """

    def __init__(self, max_chars: int = 320, chars_per_second: float = 55) -> None:
        self.max_chars = max_chars
        self.chars_per_second = chars_per_second
        self._queues: dict[tuple[int, int | str], _ChatQueue] = {}

    async def __call__(self, make_request: NextRequestMiddlewareType, bot: Bot, method: TelegramMethod) -> Any:
        if not isinstance(method, (SendMessage, SendPhoto, EditMessageText, EditMessageReplyMarkup)) or method.chat_id is None:
            return await make_request(bot, method)

        key = (bot.id, method.chat_id)
        queue = self._queues.setdefault(key, _ChatQueue())
        queue.users += 1
        try:
            async with queue.lock:
                if isinstance(method, (EditMessageText, EditMessageReplyMarkup)):
                    # Status edits share the queue but do not create new chat bubbles.
                    return await make_request(bot, method)
                return await self._deliver(make_request, bot, method)
        finally:
            queue.users -= 1
            if not queue.users:
                self._queues.pop(key, None)

    async def _deliver(self, make_request: NextRequestMiddlewareType, bot: Bot, method: SendMessage | SendPhoto) -> Any:
        text = method.text if isinstance(method, SendMessage) else method.caption or ""
        entities = method.entities if isinstance(method, SendMessage) else method.caption_entities
        parse_mode = method.parse_mode
        if isinstance(parse_mode, Default):
            parse_mode = bot.default[parse_mode.name]
        if entities:
            text = html_decoration.unparse(text, entities)
            parse_mode = ParseMode.HTML
        limit = min(self.max_chars, 500) if isinstance(method, SendPhoto) else self.max_chars
        chunks = split_message(text, limit, is_html=parse_mode == ParseMode.HTML)
        result = None
        photo_result = None
        for index, chunk in enumerate(chunks):
            if isinstance(method, SendMessage):
                part = method.model_copy(update={
                    "text": chunk, "parse_mode": parse_mode, "entities": None,
                    # A ForceReply / companion button belongs on the last bubble.
                    "reply_markup": method.reply_markup if index == len(chunks) - 1 else None,
                })
            elif index == 0:
                part = method.model_copy(update={"caption": chunk, "parse_mode": parse_mode, "caption_entities": None})
            else:
                part = SendMessage(
                    chat_id=method.chat_id, text=chunk, parse_mode=parse_mode,
                    message_thread_id=method.message_thread_id,
                    business_connection_id=method.business_connection_id,
                    direct_messages_topic_id=method.direct_messages_topic_id,
                    disable_notification=method.disable_notification,
                    protect_content=method.protect_content,
                )
            result = await self._send(make_request, bot, part, chunk, parse_mode == ParseMode.HTML)
            if isinstance(part, SendPhoto):
                photo_result = result
        # Input prompts must track the final bubble carrying ForceReply.
        return photo_result if isinstance(method, SendPhoto) else result

    async def _send(self, make_request: NextRequestMiddlewareType, bot: Bot, method: SendMessage | SendPhoto, text: str, is_html: bool) -> Any:
        visible_length = len(_HTMLText(text).text) if is_html else len(text)
        delay = min(4.0, max(1.0, visible_length / self.chars_per_second))
        for attempt in range(3):
            try:
                # Use the next middleware directly to avoid recursively entering our queue.
                await make_request(bot, SendChatAction(
                    chat_id=method.chat_id, action=ChatAction.TYPING,
                    message_thread_id=method.message_thread_id,
                    business_connection_id=method.business_connection_id,
                ))
            except TelegramAPIError:
                # A failed presence indicator must not discard the user's answer.
                logger.warning("Could not show Telegram typing indicator in chat %s", method.chat_id)
            await asyncio.sleep(delay)
            try:
                return await make_request(bot, method)
            except TelegramRetryAfter as exc:
                if attempt == 2:
                    raise
                await asyncio.sleep(exc.retry_after)
