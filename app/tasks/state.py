from enum import Enum
from datetime import datetime, timezone
from uuid import uuid4
from typing import Any, Dict, Optional, Set
from pydantic import BaseModel, Field


class InvalidTaskStateTransitionError(Exception):
    """Raised when an invalid task state transition is attempted."""
    pass


class TaskState(str, Enum):
    """
    State machine states for Wilco tasks:
    - RUNNING: Task is actively being executed by the browser agent.
    - NEEDS_INPUT: Task is paused waiting for user input or credentials.
    - VERIFYING: Task actions are complete; verifier is validating page state against goal.
    - FAILED: Task encountered an unrecoverable error or verification failed.
    - DONE: Verifier confirmed goal completion; task successfully finished.
    """
    RUNNING = "running"
    NEEDS_INPUT = "needs_input"
    VERIFYING = "verifying"
    FAILED = "failed"
    DONE = "done"


# Defines permissible state transitions
VALID_TRANSITIONS: Dict[TaskState, Set[TaskState]] = {
    TaskState.RUNNING: {
        TaskState.RUNNING,      # Progress message update
        TaskState.NEEDS_INPUT,  # Pausing for user input / 2FA
        TaskState.VERIFYING,    # Actions done, starting verifier
        TaskState.FAILED,       # Unhandled error or abort
    },
    TaskState.NEEDS_INPUT: {
        TaskState.RUNNING,      # Input provided, resuming task
        TaskState.FAILED,       # Cancelled or timed out waiting for input
    },
    TaskState.VERIFYING: {
        TaskState.DONE,         # Verification passed
        TaskState.RUNNING,      # Verification identified missing action, resume work
        TaskState.FAILED,       # Verification failed to satisfy goal
    },
    TaskState.FAILED: {
        TaskState.RUNNING,      # Retry / resume failed task
    },
    TaskState.DONE: set(),      # Terminal state: no further transitions allowed
}


class TaskRecord(BaseModel):
    """
    Represents the persisted state machine and metadata for a task.
    """
    task_id: str = Field(default_factory=lambda: f"task_{uuid4().hex[:12]}")
    user_id: int
    chat_id: int
    prompt: str
    state: TaskState = TaskState.RUNNING
    status_message: str = "Task initialized."
    message_id: Optional[int] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_active(self) -> bool:
        """Returns True if the task is currently active or paused awaiting input."""
        return self.state in {TaskState.RUNNING, TaskState.NEEDS_INPUT, TaskState.VERIFYING}

    @property
    def is_terminal(self) -> bool:
        """Returns True if the task is in a terminal finished state."""
        return self.state in {TaskState.DONE, TaskState.FAILED}

    def can_transition_to(self, new_state: TaskState) -> bool:
        """Check whether transitioning to new_state is allowed from the current state."""
        return new_state in VALID_TRANSITIONS.get(self.state, set())

    def update_status(self, status_message: str) -> None:
        """Update progress message without changing the state."""
        self.status_message = status_message
        self.updated_at = datetime.now(timezone.utc)

    def transition_to(
        self,
        new_state: TaskState,
        status_message: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        """
        Transition the task to a new state if valid.
        Updates state, status_message, error, and updated_at timestamp.
        """
        if not self.can_transition_to(new_state):
            raise InvalidTaskStateTransitionError(
                f"Invalid transition: cannot move task '{self.task_id}' from state '{self.state.value}' to '{new_state.value}'."
            )

        self.state = new_state
        if status_message is not None:
            self.status_message = status_message
        if error is not None:
            self.error = error
        self.updated_at = datetime.now(timezone.utc)

