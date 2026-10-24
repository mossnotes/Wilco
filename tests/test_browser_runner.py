import asyncio
from pathlib import Path
import tempfile
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.browser.runner import is_valid_image_bytes, run_browser_task
from app.tasks.state import TaskRecord, TaskState


@pytest.fixture
def sample_task() -> TaskRecord:
    return TaskRecord(
        user_id=12345,
        chat_id=67890,
        prompt="Check python version on python.org",
        status_message="Task received",
    )


@pytest.fixture
def mock_bot() -> MagicMock:
    bot = MagicMock()
    bot.send_photo = AsyncMock()
    bot.send_message = AsyncMock()
    return bot


@pytest.fixture
def mock_status_manager() -> MagicMock:
    sm = MagicMock()
    sm.update = AsyncMock()
    return sm


def test_is_valid_image_bytes():
    """Accept supported image signatures and reject non-image payloads."""
    assert is_valid_image_bytes(None) is False
    assert is_valid_image_bytes(b"") is False
    assert is_valid_image_bytes(b"short") is False
    assert is_valid_image_bytes(b"random-non-image-data-string") is False
    assert is_valid_image_bytes(b"fake-png-test-payload") is False
    assert is_valid_image_bytes(b"test-image-payload") is False
    assert is_valid_image_bytes(b"screenshot-payload") is False

    # Valid PNG header
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
    assert is_valid_image_bytes(png_bytes) is True

    # Valid JPEG header
    jpeg_bytes = b"\xff\xd8\xff\xe0" + b"\x00" * 50
    assert is_valid_image_bytes(jpeg_bytes) is True

    # Valid WebP header
    webp_bytes = b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 50
    assert is_valid_image_bytes(webp_bytes) is True


@pytest.mark.asyncio
async def test_run_browser_task_happy_path(sample_task, mock_bot, mock_status_manager):
    mock_history = MagicMock()
    mock_history.final_result.return_value = "Python 3.14.2 is the latest release."

    mock_agent = MagicMock()
    mock_agent.run = AsyncMock(return_value=mock_history)

    mock_browser = MagicMock()
    # Provide valid PNG bytes
    valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    mock_browser.take_screenshot = AsyncMock(return_value=valid_png)

    with patch("app.browser.runner.browser_session_context") as mock_ctx_factory, \
         patch("app.browser.runner.create_agent", return_value=mock_agent) as mock_create_agent:
        
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_browser
        mock_ctx.__aexit__.return_value = None
        mock_ctx_factory.return_value = mock_ctx

        await run_browser_task(
            task=sample_task,
            status_manager=mock_status_manager,
            bot=mock_bot,
            max_steps=10,
        )

        assert sample_task.state == TaskState.DONE
        assert "Task completed successfully" in sample_task.status_message

        mock_create_agent.assert_called_once()
        mock_ctx_factory.assert_called_once_with(telegram_id=sample_task.user_id, task_prompt=sample_task.prompt)
        _, kwargs = mock_create_agent.call_args
        assert kwargs["task"] == sample_task.prompt
        assert kwargs["browser"] == mock_browser
        assert callable(kwargs["step_callback"])
        assert kwargs["task_record"] is sample_task
        assert kwargs["status_manager"] is mock_status_manager

        mock_browser.take_screenshot.assert_awaited_once_with(full_page=True)

        mock_bot.send_photo.assert_awaited_once()
        _, photo_kwargs = mock_bot.send_photo.call_args
        assert photo_kwargs["chat_id"] == sample_task.chat_id
        assert photo_kwargs["caption"] == "Here's the screenshot of the result."
        mock_bot.send_message.assert_awaited_once_with(
            chat_id=sample_task.chat_id,
            text="Python 3.14.2 is the latest release.",
            parse_mode=None,
        )


@pytest.mark.asyncio
async def test_delivery_typing_wait_does_not_consume_browser_deadline(sample_task, mock_bot, mock_status_manager, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "TASK_TIMEOUT_SECONDS", 0.1)
    history = MagicMock()
    history.final_result.return_value = "The complete result."
    agent = MagicMock()
    agent.run = AsyncMock(return_value=history)
    browser = MagicMock()
    browser.take_screenshot = AsyncMock(return_value=None)
    delivered = []

    async def slow_delivery(**kwargs):
        await asyncio.sleep(0.15)
        delivered.append(kwargs["text"])

    mock_bot.send_message.side_effect = slow_delivery
    with (
        patch("app.browser.runner.browser_session_context") as context_factory,
        patch("app.browser.runner.create_agent", return_value=agent),
    ):
        context = AsyncMock()
        context.__aenter__.return_value = browser
        context_factory.return_value = context
        await run_browser_task(sample_task, mock_status_manager, mock_bot)

    assert delivered == ["The complete result."]
    assert sample_task.state == TaskState.DONE


@pytest.mark.asyncio
async def test_run_browser_task_step_callback(sample_task, mock_bot, mock_status_manager):
    captured_callback = None

    def fake_create_agent(**kwargs):
        nonlocal captured_callback
        captured_callback = kwargs.get("step_callback")
        agent = MagicMock()
        
        async def fake_run(*args, **kw):
            output = MagicMock()
            output.next_goal = "Click download button"
            output.action = []
            await captured_callback(None, output, 1)
            
            history = MagicMock()
            history.final_result.return_value = "Done"
            return history
            
        agent.run = AsyncMock(side_effect=fake_run)
        return agent

    mock_browser = MagicMock()
    valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
    mock_browser.take_screenshot = AsyncMock(return_value=valid_png)

    with patch("app.browser.runner.browser_session_context") as mock_ctx_factory, \
         patch("app.browser.runner.create_agent", side_effect=fake_create_agent):
        
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_browser
        mock_ctx.__aexit__.return_value = None
        mock_ctx_factory.return_value = mock_ctx

        status_updates = []
        async def track_update(task, *args, **kwargs):
            status_updates.append(task.status_message)

        mock_status_manager.update.side_effect = track_update

        await run_browser_task(sample_task, mock_status_manager, mock_bot)

        assert any("Step 1: Click download button" in msg for msg in status_updates)
        assert sample_task.state == TaskState.DONE


@pytest.mark.asyncio
async def test_run_browser_task_screenshot_failure_fallback_to_text(sample_task, mock_bot, mock_status_manager):
    mock_history = MagicMock()
    mock_history.final_result.return_value = "Extracted data successfully."

    mock_agent = MagicMock()
    mock_agent.run = AsyncMock(return_value=mock_history)

    mock_browser = MagicMock()
    mock_browser.take_screenshot = AsyncMock(side_effect=RuntimeError("Screenshot failed"))

    with patch("app.browser.runner.browser_session_context") as mock_ctx_factory, \
         patch("app.browser.runner.create_agent", return_value=mock_agent):
        
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_browser
        mock_ctx.__aexit__.return_value = None
        mock_ctx_factory.return_value = mock_ctx

        await run_browser_task(sample_task, mock_status_manager, mock_bot)

        assert sample_task.state == TaskState.DONE
        mock_bot.send_photo.assert_not_called()
        mock_bot.send_message.assert_awaited_once()
        _, msg_kwargs = mock_bot.send_message.call_args
        assert "Extracted data successfully." in msg_kwargs["text"]


@pytest.mark.asyncio
async def test_run_browser_task_failure_handling(sample_task, mock_bot, mock_status_manager):
    mock_agent = MagicMock()
    mock_agent.run = AsyncMock(side_effect=RuntimeError("Navigation timeout (30s exceeded)"))

    mock_browser = MagicMock()

    with patch("app.browser.runner.browser_session_context") as mock_ctx_factory, \
         patch("app.browser.runner.create_agent", return_value=mock_agent):
        
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_browser
        mock_ctx.__aexit__.return_value = None
        mock_ctx_factory.return_value = mock_ctx

        await run_browser_task(sample_task, mock_status_manager, mock_bot)

        assert sample_task.state == TaskState.FAILED
        assert "Navigation timeout" in sample_task.error
        assert "failed" in sample_task.status_message.lower()
        mock_status_manager.update.assert_awaited_with(sample_task, force=True)


@pytest.mark.asyncio
async def test_run_browser_task_timeout_enforcement(sample_task, mock_bot, mock_status_manager):
    """Verify that execution timeout transitions the task to FAILED."""
    mock_agent = MagicMock()
    mock_agent.run = AsyncMock(side_effect=TimeoutError("Wall-clock deadline reached"))

    mock_browser = MagicMock()

    with patch("app.browser.runner.browser_session_context") as mock_ctx_factory, \
         patch("app.browser.runner.create_agent", return_value=mock_agent):
        
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_browser
        mock_ctx.__aexit__.return_value = None
        mock_ctx_factory.return_value = mock_ctx

        await run_browser_task(sample_task, mock_status_manager, mock_bot)

        assert sample_task.state == TaskState.FAILED
        assert "timed out" in sample_task.error.lower()
        assert "timed out" in sample_task.status_message.lower()
        mock_status_manager.update.assert_awaited_with(sample_task, force=True)


@pytest.mark.asyncio
async def test_run_browser_task_corrupt_screenshot_rejection(sample_task, mock_bot, mock_status_manager):
    """Verify that corrupt screenshot data is rejected and falls back to text."""
    mock_history = MagicMock()
    mock_history.final_result.return_value = "Result with corrupt screenshot."

    mock_agent = MagicMock()
    mock_agent.run = AsyncMock(return_value=mock_history)

    mock_browser = MagicMock()
    # Corrupt / invalid non-image bytes
    mock_browser.take_screenshot = AsyncMock(return_value=b"not-a-valid-image-format-bytes-at-all")

    with patch("app.browser.runner.browser_session_context") as mock_ctx_factory, \
         patch("app.browser.runner.create_agent", return_value=mock_agent):
        
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_browser
        mock_ctx.__aexit__.return_value = None
        mock_ctx_factory.return_value = mock_ctx

        await run_browser_task(sample_task, mock_status_manager, mock_bot)

        assert sample_task.state == TaskState.DONE
        mock_bot.send_photo.assert_not_called()
        mock_bot.send_message.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_browser_task_photo_send_error_fallback(sample_task, mock_bot, mock_status_manager):
    """A failed photo upload must not repeat the text result already delivered."""
    mock_history = MagicMock()
    mock_history.final_result.return_value = "Result after send_photo failure."

    mock_agent = MagicMock()
    mock_agent.run = AsyncMock(return_value=mock_history)

    mock_browser = MagicMock()
    valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
    mock_browser.take_screenshot = AsyncMock(return_value=valid_png)

    # bot.send_photo raises Telegram error
    mock_bot.send_photo = AsyncMock(side_effect=RuntimeError("TelegramBadRequest: PHOTO_INVALID_DIMENSIONS"))

    with patch("app.browser.runner.browser_session_context") as mock_ctx_factory, \
         patch("app.browser.runner.create_agent", return_value=mock_agent):
        
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_browser
        mock_ctx.__aexit__.return_value = None
        mock_ctx_factory.return_value = mock_ctx

        await run_browser_task(sample_task, mock_status_manager, mock_bot)

        assert sample_task.state == TaskState.DONE
        mock_bot.send_photo.assert_called_once()
        mock_bot.send_message.assert_awaited_once_with(
            chat_id=sample_task.chat_id, text="Result after send_photo failure.", parse_mode=None,
        )


@pytest.mark.asyncio
async def test_run_browser_task_temp_artifact_cleanup(sample_task, mock_bot, mock_status_manager):
    """Verify that temporary screenshots are cleaned up on completion."""
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
        valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
        tf.write(valid_png)
        temp_file_path = Path(tf.name)

    assert temp_file_path.exists()

    mock_history = MagicMock()
    mock_history.final_result.return_value = "Result with temp file."
    mock_history.screenshot_paths.return_value = [str(temp_file_path)]

    mock_agent = MagicMock()
    mock_agent.run = AsyncMock(return_value=mock_history)

    mock_browser = MagicMock()
    # Strategy A fails so Strategy B picks up the temp file
    mock_browser.take_screenshot = AsyncMock(return_value=None)

    with patch("app.browser.runner.browser_session_context") as mock_ctx_factory, \
         patch("app.browser.runner.create_agent", return_value=mock_agent):
        
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_browser
        mock_ctx.__aexit__.return_value = None
        mock_ctx_factory.return_value = mock_ctx

        await run_browser_task(sample_task, mock_status_manager, mock_bot)

        assert sample_task.state == TaskState.DONE
        # Temporary file should have been cleaned up
        assert not temp_file_path.exists()


async def test_credential_failure_never_becomes_done(sample_task, mock_bot, mock_status_manager):
    async def fail_credentials(**kwargs):
        sample_task.transition_to(TaskState.NEEDS_INPUT)
        sample_task.transition_to(TaskState.FAILED, error="Credential entry timed out")
        return MagicMock()

    agent = MagicMock()
    agent.run = AsyncMock(side_effect=fail_credentials)
    with patch("app.browser.runner.browser_session_context") as context, \
         patch("app.browser.runner.create_agent", return_value=agent):
        context.return_value = AsyncMock()
        await run_browser_task(sample_task, mock_status_manager, mock_bot)
    assert sample_task.state == TaskState.FAILED
    mock_bot.send_photo.assert_not_awaited()
    mock_bot.send_message.assert_not_awaited()
