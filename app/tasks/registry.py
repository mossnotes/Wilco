import asyncio
import logging
from typing import Any, Dict, Optional, Tuple

from app.config import settings
from app.tasks.state import TaskRecord, TaskState

logger = logging.getLogger(__name__)


class ActiveTaskRegistry:
    """
    Registry for active running tasks.
    Remediates Step 2 Gaps:
    - Gap 1 & 2: Holds strong references to running asyncio.Task objects to prevent garbage collection mid-execution.
    - Gap 4: Tracks tasks by chat_id and task_id to support clean cancellation via /cancel.
    - Gap 5: Provides a global concurrency semaphore (MAX_CONCURRENT_BROWSERS).
    """

    def __init__(self, max_concurrent: Optional[int] = None):
        self._max_concurrent = max_concurrent or settings.MAX_CONCURRENT_BROWSERS
        self._semaphore: Optional[asyncio.Semaphore] = None
        # Mapping chat_id -> (TaskRecord, asyncio.Task, status_manager)
        self._active_by_chat: Dict[int, Tuple[TaskRecord, asyncio.Task, Any]] = {}
        # Mapping task_id -> (TaskRecord, asyncio.Task, status_manager)
        self._active_by_id: Dict[str, Tuple[TaskRecord, asyncio.Task, Any]] = {}

    @property
    def semaphore(self) -> asyncio.Semaphore:
        """Lazy initialization of asyncio.Semaphore inside the active event loop."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrent)
        return self._semaphore

    def register(
        self,
        chat_id: int,
        task: TaskRecord,
        async_task: asyncio.Task,
        status_manager: Any,
    ) -> None:
        """Registers an active task and hooks automatic removal on task completion."""
        entry = (task, async_task, status_manager)
        self._active_by_chat[chat_id] = entry
        self._active_by_id[task.task_id] = entry

        def _cleanup(_: asyncio.Task) -> None:
            self._active_by_chat.pop(chat_id, None)
            self._active_by_id.pop(task.task_id, None)
            logger.debug("Task %s cleaned up from active registry", task.task_id)

        async_task.add_done_callback(_cleanup)

    def get_by_chat(self, chat_id: int) -> Optional[Tuple[TaskRecord, asyncio.Task, Any]]:
        """Returns (TaskRecord, asyncio.Task, status_manager) for chat if currently running."""
        entry = self._active_by_chat.get(chat_id)
        if entry and not entry[1].done():
            return entry
        return None

    def get_by_id(self, task_id: str) -> Optional[Tuple[TaskRecord, asyncio.Task, Any]]:
        """Returns (TaskRecord, asyncio.Task, status_manager) for task_id if currently running."""
        entry = self._active_by_id.get(task_id)
        if entry and not entry[1].done():
            return entry
        return None

    async def cancel_task_by_chat(self, chat_id: int) -> bool:
        """
        Cancels the active task running in chat_id.
        Transitions the task record to FAILED and forces status message update.
        """
        entry = self.get_by_chat(chat_id)
        if not entry:
            return False

        task, async_task, status_manager = entry
        logger.info("Cancelling active task %s in chat %s", task.task_id, chat_id)

        # Cancel the underlying asyncio background task
        async_task.cancel()

        # Update task status in Telegram
        try:
            task.transition_to(
                TaskState.FAILED,
                status_message="❌ Task cancelled by user.",
                error="Cancelled by user via /cancel",
            )
            if status_manager:
                await status_manager.update(task, force=True)
        except Exception as exc:
            logger.warning("Error updating cancelled task status: %s", exc)

        return True


# Global registry singleton
task_registry = ActiveTaskRegistry()

