from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import pytest_asyncio
from aiogram.types import Chat, Message, User as TelegramUser

from app.bot.handlers import handle_text_message
from app.bot.message_router import MessageDecision
from app.db.engine import init_db
from app.config import settings
from app.tasks.registry import task_registry
from app.tasks.state import TaskRecord, TaskState


@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    await init_db()


@pytest.fixture(autouse=True)
def mock_message_router():
    with patch(
        "app.bot.handlers.route_message",
        new_callable=AsyncMock,
        return_value=MessageDecision(route="browser", reply=""),
    ) as mock_route:
        yield mock_route


def make_mock_message(text: str, user_id: int = 123456, chat_id: int = 789012) -> Message:
    msg = MagicMock(spec=Message)
    msg.text = text
    msg.message_id = 999
    msg.chat = MagicMock(spec=Chat)
    msg.chat.id = chat_id
    msg.chat.type = "private"
    msg.from_user = MagicMock(spec=TelegramUser)
    msg.from_user.id = user_id
    msg.from_user.first_name = "Alice"
    msg.answer = AsyncMock()
    msg.delete = AsyncMock()
    msg.bot = MagicMock()
    msg.bot.set_message_reaction = AsyncMock(return_value=True)
    return msg


@pytest.mark.asyncio
async def test_vault_tool_delivers_stable_account_link(mock_message_router):
    msg = make_mock_message("Open my Vault", user_id=445566, chat_id=445566)
    mock_message_router.return_value = MessageDecision(route="companion")

    with patch("app.db.repository.IdentityTokenRepository.create_token") as create_token:
        await handle_text_message(msg)
    create_token.assert_not_called()

    # Verify answer was sent with inline keyboard
    msg.answer.assert_called_once()
    args, kwargs = msg.answer.call_args
    welcome_text = args[0]
    assert "Here's your Vault." in welcome_text

    reply_markup = kwargs.get("reply_markup")
    assert reply_markup is not None
    button = reply_markup.inline_keyboard[0][0]
    assert button.text == "🔐 Open Vault"
    assert (button.url or button.web_app.url) == f"{settings.VAULT_BASE_URL.rstrip('/')}/vault/accounts"


@pytest.mark.asyncio
async def test_pasted_secret_interceptor_deletes_message(mock_message_router):
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
    mock_message_router.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancel_tool_with_active_task(mock_message_router):
    chat_id = 998877
    msg_cancel = make_mock_message("Stop the current task", user_id=5566, chat_id=chat_id)
    mock_message_router.return_value = MessageDecision(route="cancel")

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

    await handle_text_message(msg_cancel)

    # Verify background task was cancelled
    mock_async_task.cancel.assert_called_once()
    msg_cancel.answer.assert_called_once()
    assert "Stopped your current task" in msg_cancel.answer.call_args[0][0]


@pytest.mark.asyncio
async def test_cancel_tool_without_active_task(mock_message_router):
    mock_message_router.return_value = MessageDecision(route="cancel")
    msg_cancel = make_mock_message("Stop the current task", user_id=123, chat_id=88776655)
    await handle_text_message(msg_cancel)

    msg_cancel.answer.assert_called_once()
    assert "isn't an active task of yours" in msg_cancel.answer.call_args[0][0]


@pytest.mark.asyncio
async def test_benign_prompt_starts_task(mock_message_router):
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
            mock_message_router.assert_awaited_once_with(
                msg.text, request_id=f"telegram:{chat_id}:{msg.message_id}",
            )
            await active_entry[1]
            mock_run.assert_awaited_once_with(task_rec, active_entry[2], msg.bot)


@pytest.mark.asyncio
@pytest.mark.parametrize("browser_active", [False, True])
async def test_direct_reply_does_not_create_browser_task(mock_message_router, browser_active):
    msg = make_mock_message("Explain HTML tags")
    reply = "<b> is an HTML tag; 2 < 3 & 4 > 3."
    mock_message_router.return_value = MessageDecision(route="reply", reply=reply)

    with (
        patch("app.bot.handlers.async_session_factory") as mock_session,
        patch("app.bot.handlers.StatusManager") as mock_status,
        patch("app.bot.handlers.run_browser_task") as mock_run,
        patch.object(task_registry, "get_by_chat", return_value=object() if browser_active else None),
    ):
        await handle_text_message(msg)

    msg.answer.assert_awaited_once_with(reply, parse_mode=None)
    msg.bot.set_message_reaction.assert_not_awaited()
    mock_session.assert_not_called()
    mock_status.assert_not_called()
    mock_run.assert_not_called()


@pytest.mark.asyncio
async def test_browser_route_rejects_an_existing_browser_task(mock_message_router):
    msg = make_mock_message("Check my Vercel deployments")
    with (
        patch.object(task_registry, "get_by_chat", return_value=object()),
        patch("app.bot.handlers.run_browser_task") as mock_run,
    ):
        await handle_text_message(msg)

    assert "A task is already running" in msg.answer.call_args.args[0]
    msg.bot.set_message_reaction.assert_not_awaited()
    mock_message_router.assert_awaited_once()
    mock_run.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [RuntimeError("provider failure"), TimeoutError()])
async def test_routing_failure_reports_error_without_starting_browser(mock_message_router, error):
    mock_message_router.side_effect = error
    msg = make_mock_message("Hello")
    with (
        patch("app.bot.handlers.async_session_factory") as mock_session,
        patch("app.bot.handlers.run_browser_task") as mock_run,
    ):
        await handle_text_message(msg)

    assert "Please try again" in msg.answer.call_args.args[0]
    if isinstance(error, TimeoutError):
        assert "model took too long" in msg.answer.call_args.args[0]
    mock_session.assert_not_called()
    mock_run.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("text", [None, "", "   "])
async def test_empty_messages_skip_routing(mock_message_router, text):
    msg = make_mock_message(text)
    await handle_text_message(msg)
    mock_message_router.assert_not_awaited()
    msg.answer.assert_not_awaited()


@pytest.mark.parametrize("text", ["/start", "/login", "/help", "/cancel", "/unknown"])
async def test_legacy_slash_text_goes_through_main_llm(mock_message_router, text):
    mock_message_router.return_value = MessageDecision(route="reply", reply="Tell me what you need.")
    msg = make_mock_message(text)
    await handle_text_message(msg)
    mock_message_router.assert_awaited_once_with(text, request_id=f"telegram:{msg.chat.id}:{msg.message_id}")
    msg.answer.assert_awaited_once_with("Tell me what you need.", parse_mode=None)

