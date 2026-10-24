import pytest
from app.tasks.state import (
    TaskState,
    TaskRecord,
    InvalidTaskStateTransitionError,
)


def test_task_record_initialization():
    """Verify task initialization defaults and flags."""
    task = TaskRecord(
        user_id=12345,
        chat_id=67890,
        prompt="Log into test site and extract API key",
    )

    assert task.task_id.startswith("task_")
    assert task.user_id == 12345
    assert task.chat_id == 67890
    assert task.state == TaskState.RUNNING
    assert task.is_active is True
    assert task.is_terminal is False
    assert task.created_at is not None
    assert task.updated_at is not None


def test_valid_state_transitions_happy_path():
    """Verify standard happy-path progression: RUNNING -> VERIFYING -> DONE."""
    task = TaskRecord(user_id=1, chat_id=1, prompt="Test Task")

    # 1. RUNNING -> VERIFYING
    task.transition_to(TaskState.VERIFYING, status_message="Verifying results...")
    assert task.state == TaskState.VERIFYING
    assert task.status_message == "Verifying results..."
    assert task.is_active is True
    assert task.is_terminal is False

    # 2. VERIFYING -> DONE
    task.transition_to(TaskState.DONE, status_message="Task successfully verified.")
    assert task.state == TaskState.DONE
    assert task.status_message == "Task successfully verified."
    assert task.is_active is False
    assert task.is_terminal is True


def test_needs_input_pause_and_resume():
    """Verify pausing for user credentials / 2FA and resuming: RUNNING -> NEEDS_INPUT -> RUNNING."""
    task = TaskRecord(user_id=1, chat_id=1, prompt="Test Task")

    task.transition_to(TaskState.NEEDS_INPUT, status_message="Awaiting 2FA token from companion app...")
    assert task.state == TaskState.NEEDS_INPUT
    assert task.is_active is True
    assert task.is_terminal is False

    task.transition_to(TaskState.RUNNING, status_message="Input received; resuming browser execution...")
    assert task.state == TaskState.RUNNING
    assert task.is_active is True


def test_failure_and_retry():
    """Verify task failure and retry/resume transition: RUNNING -> FAILED -> RUNNING."""
    task = TaskRecord(user_id=1, chat_id=1, prompt="Test Task")

    task.transition_to(
        TaskState.FAILED,
        status_message="Failed to connect to page",
        error="ConnectionTimeoutError",
    )
    assert task.state == TaskState.FAILED
    assert task.error == "ConnectionTimeoutError"
    assert task.is_terminal is True

    # Resuming / retrying the failed task
    task.transition_to(TaskState.RUNNING, status_message="Retrying task...")
    assert task.state == TaskState.RUNNING
    assert task.is_active is True


def test_invalid_transitions_raise_error():
    """Verify attempting illegal state jumps raises InvalidTaskStateTransitionError."""
    task = TaskRecord(user_id=1, chat_id=1, prompt="Test Task")

    # Direct jump from RUNNING to DONE (bypassing verification) is not allowed
    # A task must pass through verification before it can be marked done.
    with pytest.raises(InvalidTaskStateTransitionError):
        task.transition_to(TaskState.DONE)

    # Transitioning out of DONE is forbidden (terminal state)
    task.transition_to(TaskState.VERIFYING)
    task.transition_to(TaskState.DONE)
    with pytest.raises(InvalidTaskStateTransitionError):
        task.transition_to(TaskState.RUNNING)


def test_update_status():
    """Verify updating status text without modifying task state."""
    task = TaskRecord(user_id=1, chat_id=1, prompt="Test Task")
    initial_updated_at = task.updated_at

    task.update_status("Opening browser tab...")
    assert task.state == TaskState.RUNNING
    assert task.status_message == "Opening browser tab..."
    assert task.updated_at >= initial_updated_at

