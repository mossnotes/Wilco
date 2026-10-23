import asyncio
from dataclasses import dataclass, field
import logging
import time
from typing import Any, Dict, Optional, Tuple

from app.config import settings
from app.tasks.chat_input import ChatInputField
from app.tasks.state import TaskRecord, TaskState

logger = logging.getLogger(__name__)


@dataclass
class CredentialInputRequest:
    """In-process rendezvous between the browser action and authenticated WebApp."""

    task: TaskRecord
    domain: str
    deadline: float
    event: asyncio.Event = field(default_factory=asyncio.Event)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def is_pending(self) -> bool:
        return (
            self.task.state == TaskState.NEEDS_INPUT
            and not self.event.is_set()
            and time.time() < self.deadline
        )


@dataclass
class ChatInputRequest:
    """A reply bound to one task, sender, and Telegram prompt; values stay in memory."""

    task: TaskRecord
    field: ChatInputField
    deadline: float
    reply_chat_id: int
    prompt_message_id: Optional[int] = None
    response: Optional[str] = field(default=None, repr=False)
    event: asyncio.Event = field(default_factory=asyncio.Event)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def is_pending(self) -> bool:
        return (
            self.task.state == TaskState.NEEDS_INPUT
            and not self.event.is_set()
            and time.time() < self.deadline
        )


class ActiveTaskRegistry:
    """
    Registry for active running tasks.
    Remediates Step 2 Gaps:
    - Gap 1 & 2: Holds strong references to running asyncio.Task objects to prevent garbage collection mid-execution.
    - Gap 4: Tracks tasks by chat_id and task_id to support owner-bound cancellation.
    - Gap 5: Provides a global concurrency semaphore (MAX_CONCURRENT_BROWSERS).
    """

    def __init__(self, max_concurrent: Optional[int] = None):
        self._max_concurrent = max_concurrent or settings.MAX_CONCURRENT_BROWSERS
        self._semaphore: Optional[asyncio.Semaphore] = None
        # Mapping chat_id -> (TaskRecord, asyncio.Task, status_manager)
        self._active_by_chat: Dict[int, Tuple[TaskRecord, asyncio.Task, Any]] = {}
        # Mapping task_id -> (TaskRecord, asyncio.Task, status_manager)
        self._active_by_id: Dict[str, Tuple[TaskRecord, asyncio.Task, Any]] = {}
        self._credential_inputs: Dict[str, CredentialInputRequest] = {}
        self._chat_inputs: Dict[int, ChatInputRequest] = {}

    def register_chat_input(
        self, task: TaskRecord, field_name: ChatInputField, deadline: float,
        *, reply_chat_id: Optional[int] = None,
    ) -> ChatInputRequest:
        reply_chat_id = reply_chat_id if reply_chat_id is not None else task.chat_id
        chat_ids = {task.chat_id, reply_chat_id}
        if any(chat_id in self._chat_inputs for chat_id in chat_ids):
            raise RuntimeError("A chat input request is already pending in this chat.")
        pending = ChatInputRequest(
            task=task, field=field_name, deadline=deadline, reply_chat_id=reply_chat_id,
        )
        for chat_id in chat_ids:
            self._chat_inputs[chat_id] = pending
        return pending

    def get_chat_input(self, chat_id: int) -> Optional[ChatInputRequest]:
        return self._chat_inputs.get(chat_id)

    def clear_chat_input(self, chat_id: int) -> None:
        pending = self._chat_inputs.get(chat_id)
        if pending:
            for key in {pending.task.chat_id, pending.reply_chat_id}:
                if self._chat_inputs.get(key) is pending:
                    self._chat_inputs.pop(key, None)

    def register_credential_input(self, task: TaskRecord, domain: str, deadline: float) -> CredentialInputRequest:
        if task.task_id in self._credential_inputs:
            raise RuntimeError("A credential request is already pending for this task.")
        pending = CredentialInputRequest(task=task, domain=domain, deadline=deadline)
        self._credential_inputs[task.task_id] = pending
        return pending

    def get_credential_input(self, task_id: str) -> Optional[CredentialInputRequest]:
        return self._credential_inputs.get(task_id)

    def credential_inputs_for(self, telegram_id: int, domain: str, credential_type: str) -> list[CredentialInputRequest]:
        return [
            pending for pending in self._credential_inputs.values()
            if pending.task.user_id == telegram_id and pending.domain == domain
            and pending.task.metadata.get("credential_type", "password") == credential_type
        ]

    def clear_credential_input(self, task_id: str) -> None:
        self._credential_inputs.pop(task_id, None)

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

    async def cancel_task_by_chat(self, chat_id: int, *, user_id: int) -> bool:
        """
        Cancels the owner's task in this chat or awaiting their private reply.
        Transitions the task record to FAILED and forces status message update.
        """
        entry = self.get_by_chat(chat_id)
        if entry is None and chat_id == user_id:
            pending = self.get_chat_input(chat_id)
            if pending and pending.reply_chat_id == chat_id and pending.task.user_id == user_id and pending.is_pending:
                entry = self.get_by_id(pending.task.task_id)
        if not entry or not user_id or entry[0].user_id != user_id or entry[0].is_terminal:
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
                error="Cancelled by user request",
            )
            if status_manager:
                await status_manager.update(task, force=True)
        except Exception as exc:
            logger.warning("Error updating cancelled task status: %s", exc)

        return True


# Global registry singleton
task_registry = ActiveTaskRegistry()

