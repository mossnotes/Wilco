from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import pytest_asyncio
from aiogram.types import Chat, Message, User as TelegramUser

from app.bot.handlers import handle_cancel, handle_start, handle_text_message
from app.db.engine import async_session_factory, init_db
from app.db.repository import IdentityTokenRepository, UserRepository
from app.tasks.registry import task_registry
from app.tasks.state import TaskRecord, TaskState


@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    await init_db()


def make_mock_message(text: str, user_id: int = 123456, chat_id: int = 789012) -> Message:
    msg = MagicMock(spec=Message)
    msg.text = text
    msg.message_id = 999
    msg.chat = MagicMock(spec=Chat)
    msg.chat.id = chat_id
    msg.from_user = MagicMock(spec=TelegramUser)
    msg.from_user.id = user_id
    msg.from_user.first_name = "Alice"
    msg.answer = AsyncMock()
    msg.delete = AsyncMock()
    msg.bot = MagicMock()
    return msg


@pytest.mark.asyncio
async def test_handle_start_generates_pairing_token():
    msg = make_mock_message("/start", user_id=445566, chat_id=445566)

    await handle_start(msg)

    # Verify answer was sent with inline keyboard
    msg.answer.assert_called_once()
    args, kwargs = msg.answer.call_args
    welcome_text = args[0]
    assert "Alice" in welcome_text
    assert "Zero-Knowledge Security" in welcome_text

    reply_markup = kwargs.get("reply_markup")
    assert reply_markup is not None
    button = reply_markup.inline_keyboard[0][0]
    assert "Companion App" in button.text

    # Verify pairing token exists in database
    async with async_session_factory() as session:
        user = await UserRepository.get_by_telegram_id(session, 445566)
        assert user is not None
        # Check token URL contains a valid token string
        token_str = (button.url or button.web_app.url).split("token=")[-1]
        token_obj = await IdentityTokenRepository.get_token(session, token_str)
        assert token_obj is not None
        assert token_obj.telegram_id == 445566


@pytest.mark.asyncio
async def test_pasted_secret_interceptor_deletes_message():
    secret_text = "Here is my secret API key: sk-ant-api03-abcdef1234567890abcdef1234567890 please login"
    msg = make_mock_message(secret_text, user_id=112233, chat_id=112233)

    await handle_text_message(msg)

    # 1. Message must be immediately deleted
    msg.delete.assert_called_once()

    # 2. Security warning must be sent
    msg.answer.assert_called_once()
    warning_text = msg.answer.call_args[0][0]
    assert "Security Alert: Secret Intercepted!" in warning_text
    assert "passwords, API keys, and OTP seeds must <b>never</b> be sent" in warning_text

    # 3. No task registered in registry
    assert task_registry.get_by_chat(112233) is None


@pytest.mark.asyncio
async def test_cancel_command_with_active_task():
    chat_id = 998877
    msg_cancel = make_mock_message("/cancel", user_id=5566, chat_id=chat_id)

    # Mock an active task registered in registry
    mock_task_record = TaskRecord(
        user_id=5566,
        chat_id=chat_id,
        prompt="Sample active prompt",
        state=TaskState.RUNNING,
    )
    mock_async_task = MagicMock()
    mock_async_task.done.return_value = False
    mock_async_task.cancel = MagicMock()

    mock_status_mgr = MagicMock()
    mock_status_mgr.update = AsyncMock()

    task_registry.register(chat_id, mock_task_record, mock_async_task, mock_status_mgr)

    # Execute /cancel
    await handle_cancel(msg_cancel)

    # Verify background task was cancelled
    mock_async_task.cancel.assert_called_once()
    msg_cancel.answer.assert_called_once()
    assert "Active task cancelled by user" in msg_cancel.answer.call_args[0][0]


@pytest.mark.asyncio
async def test_cancel_command_without_active_task():
    msg_cancel = make_mock_message("/cancel", user_id=123, chat_id=88776655)
    await handle_cancel(msg_cancel)

    msg_cancel.answer.assert_called_once()
    assert "No active task is currently running" in msg_cancel.answer.call_args[0][0]


@pytest.mark.asyncio
async def test_benign_prompt_starts_task():
    chat_id = 44332211
    msg = make_mock_message("Search news on news.ycombinator.com", user_id=999, chat_id=chat_id)

    with patch("app.bot.handlers.run_browser_task", return_value=None) as mock_run:
        with patch("app.bot.handlers.StatusManager.send_initial", new_callable=AsyncMock) as mock_send_init:
            await handle_text_message(msg)

            # Initial status card was posted
            mock_send_init.assert_called_once()

            # Task was registered in active registry
            active_entry = task_registry.get_by_chat(chat_id)
            assert active_entry is not None
            task_rec, _, _ = active_entry
            assert task_rec.prompt == "Search news on news.ycombinator.com"
            assert task_rec.user_id == 999

