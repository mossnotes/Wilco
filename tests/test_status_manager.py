import asyncio
import time
from unittest.mock import AsyncMock, patch
import pytest

from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter

from app.tasks.state import TaskRecord, TaskState
from app.bot.status_manager import StatusManager, format_status_message
from app.config import settings


@pytest.fixture(autouse=True)
def enable_debug_status(monkeypatch):
    # Existing card/throttling tests exercise the opt-in debug behavior.
    monkeypatch.setattr(settings, "TELEGRAM_DEBUG_STATUS", True)


def test_format_status_message_all_states():
    """Verify that format_status_message renders expected badges and content for all states."""
    task = TaskRecord(
        user_id=123,
        chat_id=456,
        prompt="Check order status",
        status_message="Navigating to shop...",
    )

    # 1. RUNNING
    running_html = format_status_message(task)
    assert "⏳ <b>Status:</b> Running..." in running_html
    assert "Check order status" in running_html
    assert "Navigating to shop..." in running_html

    # 2. NEEDS_INPUT
    task.transition_to(TaskState.NEEDS_INPUT, status_message="2FA required")
    needs_input_html = format_status_message(task)
    assert "🔒 <b>Status:</b> Action Required" in needs_input_html
    assert "Web Companion" in needs_input_html

    # 3. VERIFYING
    task.transition_to(TaskState.RUNNING)
    task.transition_to(TaskState.VERIFYING, status_message="Checking order ID on screen")
    verifying_html = format_status_message(task)
    assert "🔍 <b>Status:</b> Verifying Results..." in verifying_html

    # 4. DONE
    task.transition_to(TaskState.DONE, status_message="Order confirmed")
    done_html = format_status_message(task)
    assert "✅ <b>Status:</b> Completed" in done_html
    assert "Order confirmed" in done_html

    # 5. FAILED
    failed_task = TaskRecord(user_id=1, chat_id=1, prompt="Failed task")
    failed_task.transition_to(
        TaskState.FAILED,
        status_message="Server not reachable",
        error="ConnectionRefusedError: port 80",
    )
    failed_html = format_status_message(failed_task)
    assert "❌ <b>Status:</b> Failed" in failed_html
    assert "ConnectionRefusedError: port 80" in failed_html


@pytest.mark.asyncio
async def test_status_manager_send_initial():
    """Verify that send_initial posts a message and assigns message_id to task."""
    mock_bot = AsyncMock()
    mock_sent_msg = AsyncMock()
    mock_sent_msg.message_id = 999
    mock_bot.send_message.return_value = mock_sent_msg

    manager = StatusManager(bot=mock_bot, min_interval=1.0)
    task = TaskRecord(user_id=1, chat_id=100, prompt="Test prompt")

    msg_id = await manager.send_initial(task)

    assert msg_id == 999
    assert task.message_id == 999
    mock_bot.send_message.assert_called_once()
    call_args = mock_bot.send_message.call_args[1]
    assert call_args["chat_id"] == 100
    assert "Test prompt" in call_args["text"]


@pytest.mark.asyncio
async def test_status_manager_throttling():
    """Verify that rapid updates within min_interval are debounced and only the latest is flushed."""
    mock_bot = AsyncMock()
    manager = StatusManager(bot=mock_bot, min_interval=0.2)
    task = TaskRecord(user_id=1, chat_id=100, prompt="Test prompt")
    task.message_id = 999

    # 1. First update: executed immediately
    await manager.update(task)
    assert mock_bot.edit_message_text.call_count == 1

    # 2. Rapid intermediate updates within 0.2s interval: buffered, not sent immediately
    task.update_status("Step 1 done")
    await manager.update(task)

    task.update_status("Step 2 done")
    await manager.update(task)

    # Edit count should still be 1 because interval has not elapsed
    assert mock_bot.edit_message_text.call_count == 1

    # 3. Wait for cooldown to expire
    await asyncio.sleep(0.25)

    # Delayed worker should have flushed the latest status ("Step 2 done")
    assert mock_bot.edit_message_text.call_count == 2
    latest_call = mock_bot.edit_message_text.call_args[1]
    assert "Step 2 done" in latest_call["text"]


@pytest.mark.asyncio
async def test_status_manager_terminal_state_forces_immediate_flush():
    """Verify that terminal states (DONE, FAILED) bypass throttling and update immediately."""
    mock_bot = AsyncMock()
    manager = StatusManager(bot=mock_bot, min_interval=5.0)  # Long interval
    task = TaskRecord(user_id=1, chat_id=100, prompt="Test prompt")
    task.message_id = 999

    # Initial update consumes immediate slot
    await manager.update(task)
    assert mock_bot.edit_message_text.call_count == 1

    # Move to VERIFYING (normal update, should be delayed because of 5s interval)
    task.transition_to(TaskState.VERIFYING, status_message="Verifying now")
    await manager.update(task)
    assert mock_bot.edit_message_text.call_count == 1

    # Move to DONE (terminal state: should force immediate flush)
    task.transition_to(TaskState.DONE, status_message="Done immediately!")
    await manager.update(task)

    # Should execute immediately despite the 5.0s interval
    assert mock_bot.edit_message_text.call_count == 2
    latest_call = mock_bot.edit_message_text.call_args[1]
    assert "Done immediately!" in latest_call["text"]


@pytest.mark.asyncio
async def test_status_manager_handles_message_not_modified():
    """Verify that Telegram 'message is not modified' error is handled without crashing."""
    mock_bot = AsyncMock()
    # Simulate Telegram BadRequest error
    mock_bot.edit_message_text.side_effect = TelegramBadRequest(
        method=AsyncMock(),
        message="Bad Request: message is not modified: specified new message content and reply markup are exactly the same as a current content",
    )

    manager = StatusManager(bot=mock_bot, min_interval=0.1)
    task = TaskRecord(user_id=1, chat_id=100, prompt="Test prompt")
    task.message_id = 999

    # Should not raise an exception
    await manager.update(task, force=True)
    assert mock_bot.edit_message_text.call_count == 1


@pytest.mark.parametrize("base_url, is_webapp", [("https://wilco.example", True), ("http://localhost:8000", False)])
async def test_debug_credential_button_flushes_immediately_without_countdown(base_url, is_webapp):
    bot = AsyncMock()
    manager = StatusManager(bot, min_interval=60)
    task = TaskRecord(user_id=1, chat_id=1, prompt="Login <example>", message_id=42)
    await manager.update(task)
    task.transition_to(TaskState.NEEDS_INPUT, status_message="Credentials required")
    task.metadata.update({
        "target_domain": "example.com", "companion_url": f"{base_url}/companion/link?token=opaque",
        "credential_input_deadline": time.time() + 150,
    })
    await manager.update(task)
    assert bot.edit_message_text.await_count == 2
    call = bot.edit_message_text.call_args.kwargs
    assert "Time remaining:" not in call["text"]
    assert "&lt;example&gt;" in call["text"]
    button = call["reply_markup"].inline_keyboard[0][0]
    assert "example.com" in button.text
    assert (button.web_app is not None) == is_webapp
    task.transition_to(TaskState.RUNNING)
    await manager.update(task, force=True)
    assert bot.edit_message_text.call_args.kwargs["reply_markup"] is None

