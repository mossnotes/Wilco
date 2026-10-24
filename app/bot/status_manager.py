import asyncio
import html
import logging
import time
from typing import Optional

from aiogram import Bot
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo

from app.bot.delivery import split_message
from app.config import settings
from app.tasks.state import TaskRecord, TaskState

logger = logging.getLogger(__name__)


def format_status_message(task: TaskRecord) -> str:
    """
    Format a clean, readable HTML status card for Telegram.
    
    This function translates the underlying TaskRecord data into user-friendly
    text with state-specific emoji badges, progress descriptions, and timing info.
    """
    # 1. Choose an emoji and human-readable label based on the current state.
    state_badges = {
        TaskState.RUNNING: "⏳ <b>Status:</b> Running...",
        TaskState.NEEDS_INPUT: "🔒 <b>Status:</b> Action Required",
        TaskState.VERIFYING: "🔍 <b>Status:</b> Verifying Results...",
        TaskState.DONE: "✅ <b>Status:</b> Completed",
        TaskState.FAILED: "❌ <b>Status:</b> Failed",
    }
    badge = state_badges.get(task.state, f"⚙️ <b>Status:</b> {task.state.value.capitalize()}")

    # 2. Calculate elapsed execution time in seconds.
    elapsed = max(0, int((task.updated_at - task.created_at).total_seconds()))

    # 3. Assemble the base message showing the user's prompt and current state.
    lines = [
        f"🎯 <b>Task:</b> <i>\"{html.escape(task.prompt)}\"</i>",
        f"🆔 <code>{task.task_id}</code>",
        badge,
        f"📝 {html.escape(task.status_message)}",
    ]

    # 4. If the task requires user input, give clear guidance on what to do next.
    # Secrets must never be entered in chat, so we direct the user to Vault.
    if task.state == TaskState.NEEDS_INPUT and not task.metadata.get("chat_input_field"):
        lines.append("🔐 <i>Open Vault to provide the required input securely.</i>")

    # 5. If an error occurred, show the failure explanation.
    if task.state == TaskState.FAILED and task.error:
        lines.append(f"⚠️ <b>Error Details:</b> <code>{html.escape(task.error)}</code>")

    # 6. Add execution duration footer.
    lines.append(f"⏱ <i>Elapsed: {elapsed}s</i>")

    return "\n".join(lines)


def credential_input_keyboard(task: TaskRecord) -> Optional[InlineKeyboardMarkup]:
    if task.state != TaskState.NEEDS_INPUT:
        return None
    url = task.metadata.get("companion_url")
    domain = task.metadata.get("target_domain")
    if not url or not domain:
        return None
    label = f"🔐 Enter {domain} credentials"
    # Telegram requires HTTPS for WebApp buttons; keep the local development fallback.
    button = (
        InlineKeyboardButton(text=label, web_app=WebAppInfo(url=url))
        if url.startswith("https://") else InlineKeyboardButton(text=label, url=url)
    )
    return InlineKeyboardMarkup(inline_keyboard=[[button]])


class StatusManager:
    """
    Hide internal progress by default; retain an optional debug status card.
    Required credential prompts and brief failure notices remain visible.

    Why this class is needed (Risk 85 Mitigation):
    Telegram strictly limits message editing frequency (roughly 1 edit per second per chat).
    Autonomous browser agents emit rapid micro-progress events (e.g., clicking, navigating,
    extracting). If we send an edit request on every event, Telegram will block the bot with
    HTTP 429 ("Too Many Requests").

    How this class solves it:
    - Buffers and throttles edits so they occur at most once every `min_interval` seconds (default 1.2s).
    - If updates arrive faster than the interval, only the most recent status is queued.
    - Terminal states (DONE, FAILED) or critical blocks (NEEDS_INPUT) are flushed immediately
      so the user never has to wait to see completion or take action.
    """

    def __init__(self, bot: Bot, min_interval: float = 1.2) -> None:
        """
        Initialize the StatusManager.

        :param bot: The active aiogram Bot instance used to call Telegram API.
        :param min_interval: Minimum number of seconds between edit requests (default 1.2s).
        """
        self.bot = bot
        self.min_interval = min_interval
        self.debug_status = settings.TELEGRAM_DEBUG_STATUS
        self._input_message_id: Optional[int] = None
        self._input_url: Optional[str] = None
        self._failure_sent = False

        # Monotonic timestamp of when the last edit request was completed.
        self._last_edit_time: float = 0.0

        # Stores the latest unrendered text waiting to be sent when the cooldown expires.
        self._pending_text: Optional[str] = None
        self._pending_markup: Optional[InlineKeyboardMarkup] = None

        # Holds a reference to the active background delay task, if one is currently sleeping.
        self._flush_task: Optional[asyncio.Task] = None

        # Lock to prevent race conditions during rapid concurrent state updates.
        self._lock = asyncio.Lock()

    async def send_initial(self, task: TaskRecord) -> Optional[int]:
        """
        Send the very first status message to the Telegram chat.
        
        Records the returned message_id inside the TaskRecord so all subsequent
        progress updates can edit this exact message in place.
        """
        if not self.debug_status:
            return None
        rendered_text = self._render_debug_status(task)
        message = await self.bot.send_message(
            chat_id=task.chat_id,
            text=rendered_text,
            parse_mode="HTML",
            reply_markup=credential_input_keyboard(task),
        )
        task.message_id = message.message_id
        self._last_edit_time = time.monotonic()
        return message.message_id

    async def update(self, task: TaskRecord, force: bool = False) -> None:
        """
        Request a status message update.

        :param task: The current TaskRecord containing updated state or progress text.
        :param force: If True, bypasses throttling and updates Telegram immediately.
                      Terminal states (DONE, FAILED) and NEEDS_INPUT automatically force an update.
        """
        if not self.debug_status:
            await self._notify_user(task)
            return
        if task.message_id is None:
            logger.warning(f"Cannot update status for task {task.task_id}: message_id is not set.")
            return

        rendered_text = self._render_debug_status(task)
        reply_markup = credential_input_keyboard(task)

        # Critical states must appear immediately without waiting for cooldown.
        should_force = force or task.is_terminal or (task.state == TaskState.NEEDS_INPUT)

        async with self._lock:
            # If a background delayed flush is currently waiting, cancel it because we have newer data.
            if self._flush_task and not self._flush_task.done():
                self._flush_task.cancel()
                self._flush_task = None

            now = time.monotonic()
            elapsed_since_last_edit = now - self._last_edit_time

            if should_force or elapsed_since_last_edit >= self.min_interval:
                # We are outside the rate-limit window or forced: send the edit immediately.
                await self._execute_edit(task.chat_id, task.message_id, rendered_text, reply_markup)
                self._pending_text = None
                self._pending_markup = None
            else:
                # We are within the rate-limit cooldown window: buffer the text and schedule a delayed flush.
                self._pending_text = rendered_text
                self._pending_markup = reply_markup
                remaining_wait = self.min_interval - elapsed_since_last_edit
                self._flush_task = asyncio.create_task(
                    self._delayed_flush(task.chat_id, task.message_id, remaining_wait)
                )

    def _render_debug_status(self, task: TaskRecord) -> str:
        # A mutable card must stay in one bubble, even for a very long prompt.
        return split_message(
            format_status_message(task), settings.TELEGRAM_MESSAGE_MAX_CHARS, is_html=True,
        )[0]

    async def _notify_user(self, task: TaskRecord) -> None:
        """Surface only things the user must act on, never internal progress."""
        async with self._lock:
            markup = credential_input_keyboard(task)
            if markup and not task.metadata.get("chat_input_field"):
                url = task.metadata["companion_url"]
                if url != self._input_url:
                    domain = task.metadata["target_domain"]
                    credential = task.metadata.get("credential_type", "credentials").replace("_", " ")
                    text = (
                        f"That password didn't work for {domain}. Update it here."
                        if task.metadata.get("credential_rejected") else
                        f"I need your {credential} for {domain}. Save it to Vault here."
                    )
                    message = await self.bot.send_message(
                        chat_id=task.chat_id,
                        text=text,
                        parse_mode=None, reply_markup=markup,
                    )
                    self._input_message_id = message.message_id
                    self._input_url = url
                return

            if self._input_message_id is not None:
                try:
                    await self.bot.edit_message_reply_markup(
                        chat_id=task.chat_id, message_id=self._input_message_id, reply_markup=None,
                    )
                except Exception:
                    logger.warning("Could not remove an expired credential button")
                self._input_message_id = None
                self._input_url = None

            if task.state == TaskState.FAILED and not self._failure_sent:
                failure = (task.error or task.status_message).lower()
                if "cancel" in failure:
                    return  # The cancellation tool / Vault already acknowledges it.
                text = (
                    "That request timed out. Please try again."
                    if "timed out" in failure or "timeout" in failure
                    else "I couldn't complete that request. Please try again."
                )
                await self.bot.send_message(chat_id=task.chat_id, text=text, parse_mode=None)
                self._failure_sent = True

    async def _delayed_flush(self, chat_id: int, message_id: int, delay_seconds: float) -> None:
        """
        Internal worker that sleeps for the remaining cooldown time, then pushes
        the latest buffered text to Telegram.
        """
        try:
            await asyncio.sleep(delay_seconds)
            async with self._lock:
                if self._pending_text is not None:
                    text_to_send = self._pending_text
                    markup_to_send = self._pending_markup
                    self._pending_text = None
                    self._pending_markup = None
                    await self._execute_edit(chat_id, message_id, text_to_send, markup_to_send)
        except asyncio.CancelledError:
            # Expected when a newer update arrived while we were sleeping.
            pass
        except Exception as exc:
            logger.error(f"Error during delayed status flush: {exc}")

    async def _execute_edit(
        self, chat_id: int, message_id: int, text: str,
        reply_markup: Optional[InlineKeyboardMarkup] = None,
    ) -> None:
        """
        Perform the actual Telegram API edit_message_text call with graceful error handling.
        """
        try:
            await self.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                text=text,
                parse_mode="HTML",
                reply_markup=reply_markup,
            )
            self._last_edit_time = time.monotonic()
        except TelegramRetryAfter as retry_err:
            # Telegram explicitly tells us how many seconds to back off.
            logger.warning(f"Hit Telegram rate limit (429). Retrying after {retry_err.retry_after}s.")
            await asyncio.sleep(retry_err.retry_after)
            try:
                await self.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=message_id,
                    text=text,
                    parse_mode="HTML",
                    reply_markup=reply_markup,
                )
                self._last_edit_time = time.monotonic()
            except Exception as retry_exc:
                logger.error(f"Failed to edit message after rate-limit backoff: {retry_exc}")
        except TelegramBadRequest as bad_req:
            # If the new text is identical to what Telegram already displays, Telegram raises
            # "Bad Request: message is not modified". This is harmless and safe to ignore.
            if "message is not modified" in str(bad_req).lower():
                logger.debug("Suppressed harmless Telegram error: message content was unchanged.")
            else:
                logger.warning(f"TelegramBadRequest when editing status message: {bad_req}")
        except Exception as exc:
            logger.error(f"Unexpected error when editing status message: {exc}")

    async def flush(self, task: TaskRecord) -> None:
        """
        Ensure any pending buffered updates are completely pushed to Telegram.
        Useful when completing or terminating a task run.
        """
        if not self.debug_status:
            await self._notify_user(task)
            return
        async with self._lock:
            if self._flush_task and not self._flush_task.done():
                self._flush_task.cancel()
                self._flush_task = None

            if self._pending_text is not None and task.message_id is not None:
                await self._execute_edit(task.chat_id, task.message_id, self._pending_text, self._pending_markup)
                self._pending_text = None
                self._pending_markup = None

