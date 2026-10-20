import asyncio
import logging
import time
from typing import Optional

from aiogram import Bot
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter

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
        f"🎯 <b>Task:</b> <i>\"{task.prompt}\"</i>",
        f"🆔 <code>{task.task_id}</code>",
        "",
        badge,
        f"📝 {task.status_message}",
    ]

    # 4. If the task requires user input, give clear guidance on what to do next.
    # Secrets must never be entered in chat, so we direct the user to the companion app.
    if task.state == TaskState.NEEDS_INPUT:
        lines.append("")
        lines.append("👉 <i>Please open the Web Companion to provide the required input securely.</i>")

    # 5. If an error occurred, show the failure explanation.
    if task.state == TaskState.FAILED and task.error:
        lines.append("")
        lines.append(f"⚠️ <b>Error Details:</b> <code>{task.error}</code>")

    # 6. Add execution duration footer.
    lines.append("")
    lines.append(f"⏱ <i>Elapsed: {elapsed}s</i>")

    return "\n".join(lines)


class StatusManager:
    """
    Manages in-place editing of a single Telegram status message for a task.

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

        # Monotonic timestamp of when the last edit request was completed.
        self._last_edit_time: float = 0.0

        # Stores the latest unrendered text waiting to be sent when the cooldown expires.
        self._pending_text: Optional[str] = None

        # Holds a reference to the active background delay task, if one is currently sleeping.
        self._flush_task: Optional[asyncio.Task] = None

        # Lock to prevent race conditions during rapid concurrent state updates.
        self._lock = asyncio.Lock()

    async def send_initial(self, task: TaskRecord) -> int:
        """
        Send the very first status message to the Telegram chat.
        
        Records the returned message_id inside the TaskRecord so all subsequent
        progress updates can edit this exact message in place.
        """
        rendered_text = format_status_message(task)
        message = await self.bot.send_message(
            chat_id=task.chat_id,
            text=rendered_text,
            parse_mode="HTML",
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
        if task.message_id is None:
            logger.warning(f"Cannot update status for task {task.task_id}: message_id is not set.")
            return

        rendered_text = format_status_message(task)

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
                await self._execute_edit(task.chat_id, task.message_id, rendered_text)
                self._pending_text = None
            else:
                # We are within the rate-limit cooldown window: buffer the text and schedule a delayed flush.
                self._pending_text = rendered_text
                remaining_wait = self.min_interval - elapsed_since_last_edit
                self._flush_task = asyncio.create_task(
                    self._delayed_flush(task.chat_id, task.message_id, remaining_wait)
                )

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
                    self._pending_text = None
                    await self._execute_edit(chat_id, message_id, text_to_send)
        except asyncio.CancelledError:
            # Expected when a newer update arrived while we were sleeping.
            pass
        except Exception as exc:
            logger.error(f"Error during delayed status flush: {exc}")

    async def _execute_edit(self, chat_id: int, message_id: int, text: str) -> None:
        """
        Perform the actual Telegram API edit_message_text call with graceful error handling.
        """
        try:
            await self.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                text=text,
                parse_mode="HTML",
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
        async with self._lock:
            if self._flush_task and not self._flush_task.done():
                self._flush_task.cancel()
                self._flush_task = None

            if self._pending_text is not None and task.message_id is not None:
                await self._execute_edit(task.chat_id, task.message_id, self._pending_text)
                self._pending_text = None

