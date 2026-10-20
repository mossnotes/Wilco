import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.tasks.state import TaskRecord, TaskState
from app.browser.runner import run_browser_task


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


@pytest.mark.asyncio
async def test_run_browser_task_happy_path(sample_task, mock_bot, mock_status_manager):
    mock_history = MagicMock()
    mock_history.final_result.return_value = "Python 3.14.2 is the latest release."

    mock_agent = MagicMock()
    mock_agent.run = AsyncMock(return_value=mock_history)

    mock_browser = MagicMock()
    mock_browser.take_screenshot = AsyncMock(return_value=b"fake-png-screenshot")

    with patch("app.browser.runner.browser_session_context") as mock_ctx_factory, \
         patch("app.browser.runner.create_agent", return_value=mock_agent) as mock_create_agent:
        
        # Setup async context manager mock
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

        # Verify state transitions: must finish in DONE
        assert sample_task.state == TaskState.DONE
        assert "Task completed successfully" in sample_task.status_message

        # Verify agent was created with correct prompt and browser
        mock_create_agent.assert_called_once()
        _, kwargs = mock_create_agent.call_args
        assert kwargs["task"] == sample_task.prompt
        assert kwargs["browser"] == mock_browser
        assert callable(kwargs["step_callback"])

        # Verify screenshot capture was called
        mock_browser.take_screenshot.assert_awaited_once_with(full_page=True)

        # Verify bot sent photo proof with caption
        mock_bot.send_photo.assert_awaited_once()
        _, photo_kwargs = mock_bot.send_photo.call_args
        assert photo_kwargs["chat_id"] == sample_task.chat_id
        assert "Python 3.14.2 is the latest release" in photo_kwargs["caption"]


@pytest.mark.asyncio
async def test_run_browser_task_step_callback(sample_task, mock_bot, mock_status_manager):
    captured_callback = None

    def fake_create_agent(**kwargs):
        nonlocal captured_callback
        captured_callback = kwargs.get("step_callback")
        agent = MagicMock()
        
        async def fake_run(*args, **kw):
            # Simulate an agent triggering step callback during execution
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
    mock_browser.take_screenshot = AsyncMock(return_value=b"screenshot")

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
    # Screenshot fails
    mock_browser.take_screenshot = AsyncMock(side_effect=RuntimeError("Screenshot failed"))

    with patch("app.browser.runner.browser_session_context") as mock_ctx_factory, \
         patch("app.browser.runner.create_agent", return_value=mock_agent):
        
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_browser
        mock_ctx.__aexit__.return_value = None
        mock_ctx_factory.return_value = mock_ctx

        await run_browser_task(sample_task, mock_status_manager, mock_bot)

        # Task should still succeed
        assert sample_task.state == TaskState.DONE
        # bot.send_photo was not called because screenshot failed
        mock_bot.send_photo.assert_not_called()
        # Fallback to text message
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

        # Verify task transitioned to FAILED
        assert sample_task.state == TaskState.FAILED
        assert "Navigation timeout" in sample_task.error
        assert "failed" in sample_task.status_message.lower()

        # Final status must be flushed with force=True
        mock_status_manager.update.assert_awaited_with(sample_task, force=True)
