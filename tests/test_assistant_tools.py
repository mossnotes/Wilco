import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.bot.handlers import handle_text_message, router
from app.bot.message_router import MessageDecision, TOOL_DECLARATIONS
from app.bot.tools import ASSISTANT_TOOLS, execute_assistant_tool
from app.main import app, lifespan
from app.tasks.registry import ActiveTaskRegistry
from app.tasks.state import TaskRecord, TaskState


def message(text="Open my Companion App", *, user_id=123, chat_id=123, chat_type="private"):
    return SimpleNamespace(
        text=text, message_id=55, chat=SimpleNamespace(id=chat_id, type=chat_type),
        from_user=SimpleNamespace(id=user_id) if user_id else None,
        reply_to_message=None, answer=AsyncMock(), delete=AsyncMock(), bot=SimpleNamespace(id=987),
    )


def test_all_main_tools_have_closed_argument_schemas_and_descriptions():
    assert len(ASSISTANT_TOOLS) == 4
    for declaration in TOOL_DECLARATIONS:
        assert len(declaration.description) > 100
        schema = declaration.parameters_json_schema
        assert schema["additionalProperties"] is False
        assert set(schema["properties"]) == ({"request"} if declaration.name == "start_browser_task" else set())
    assert len(router.message.handlers) == 1


@pytest.mark.parametrize("user_id,chat_id,chat_type", [
    (123, -100, "group"), (123, 456, "private"), (None, 123, "private"),
])
async def test_pairing_tool_never_issues_links_outside_owners_private_chat(user_id, chat_id, chat_type):
    msg = message(user_id=user_id, chat_id=chat_id, chat_type=chat_type)
    with patch("app.db.repository.IdentityTokenRepository.create_token") as database:
        await execute_assistant_tool("companion", msg)
    database.assert_not_called()
    assert "privately" in msg.answer.call_args.args[0]
    assert "reply_markup" not in msg.answer.call_args.kwargs


async def test_companion_link_is_stable_and_never_mints_pairing_tokens(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "COMPANION_BASE_URL", "https://wilco.example/companion")
    msg = message()
    with patch("app.db.repository.IdentityTokenRepository.create_token") as database:
        await execute_assistant_tool("companion", msg)
    database.assert_not_called()
    button = msg.answer.call_args.kwargs["reply_markup"].inline_keyboard[0][0]
    assert button.web_app.url == "https://wilco.example/companion/accounts"


async def test_main_companion_always_opens_accounts_separately_from_one_time_input(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "COMPANION_BASE_URL", "https://wilco.example/companion")
    msg = message()
    task = TaskRecord(user_id=123, chat_id=123, prompt="Login", state=TaskState.NEEDS_INPUT)
    task.metadata["companion_url"] = "https://wilco.example/companion/link?token=existing"
    monkeypatch.setattr("app.bot.tools.task_registry.get_by_chat", lambda chat_id: (task, None, None))
    with patch("app.db.repository.IdentityTokenRepository.create_token") as database:
        await execute_assistant_tool("companion", msg)
    database.assert_not_called()
    assert msg.answer.call_args.kwargs["reply_markup"].inline_keyboard[0][0].web_app.url == "https://wilco.example/companion/accounts"


async def test_help_tool_is_read_only_and_uses_natural_language():
    msg = message("How do I use Wilco?")
    with (
        patch("app.db.repository.IdentityTokenRepository.create_token") as database,
        patch("app.bot.tools.task_registry.cancel_task_by_chat", new_callable=AsyncMock) as cancel,
    ):
        await execute_assistant_tool("help", msg)
    database.assert_not_called()
    cancel.assert_not_awaited()
    text = msg.answer.call_args.args[0]
    assert "stop the current task" in text
    assert all(command not in text for command in ("/start", "/login", "/help", "/cancel"))


@pytest.mark.parametrize("requester", [123, 456, None])
async def test_cancellation_is_limited_to_task_owner(monkeypatch, requester):
    registry = ActiveTaskRegistry()
    monkeypatch.setattr("app.bot.tools.task_registry", registry)
    task = TaskRecord(user_id=123, chat_id=-100, prompt="Task")
    running = MagicMock()
    running.done.return_value = False
    status = SimpleNamespace(update=AsyncMock())
    registry.register(-100, task, running, status)
    msg = message("Stop the current task", user_id=requester, chat_id=-100, chat_type="group")

    await execute_assistant_tool("cancel", msg)

    if requester == 123:
        running.cancel.assert_called_once()
        assert task.state == TaskState.FAILED
        assert "Stopped your current task" in msg.answer.call_args.args[0]
    else:
        running.cancel.assert_not_called()
        assert task.state == TaskState.RUNNING
        assert "isn't an active task of yours" in msg.answer.call_args.args[0]


@pytest.mark.parametrize("route", ["browser", "unknown"])
async def test_local_executor_fails_closed_for_unhandled_tools(route):
    msg = message()
    with pytest.raises(ValueError, match="Unsupported"):
        await execute_assistant_tool(route, msg)
    msg.answer.assert_not_awaited()


@pytest.mark.parametrize("field", ["username", "otp", "phone"])
@pytest.mark.parametrize("task_chat_id", [123, -100])
async def test_natural_language_stop_remains_available_during_input_wait(monkeypatch, field, task_chat_id):
    registry = ActiveTaskRegistry()
    monkeypatch.setattr("app.bot.tools.task_registry", registry)
    monkeypatch.setattr("app.bot.handlers.task_registry", registry)
    route = AsyncMock(return_value=MessageDecision(route="cancel"))
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    task = TaskRecord(user_id=123, chat_id=task_chat_id, prompt="Login", state=TaskState.NEEDS_INPUT)
    running = asyncio.create_task(asyncio.Event().wait())
    registry.register(task_chat_id, task, running, SimpleNamespace(update=AsyncMock()))
    pending = registry.register_chat_input(task, field, time.time() + 100, reply_chat_id=123)
    pending.prompt_message_id = 77
    try:
        await handle_text_message(message("Stop the current task"))
        route.assert_awaited_once_with("Stop the current task", request_id="telegram:123:55")
        assert task.state == TaskState.FAILED
        assert pending.response is None
    finally:
        running.cancel()
        await asyncio.gather(running, return_exceptions=True)


@pytest.mark.parametrize("requester", [123, 456, None])
async def test_private_input_cancellation_is_bound_to_the_task_owner(monkeypatch, requester):
    registry = ActiveTaskRegistry()
    monkeypatch.setattr("app.bot.tools.task_registry", registry)
    task = TaskRecord(user_id=123, chat_id=-100, prompt="Login", state=TaskState.NEEDS_INPUT)
    running = MagicMock()
    running.done.return_value = False
    registry.register(-100, task, running, SimpleNamespace(update=AsyncMock()))
    registry.register_chat_input(task, "phone", time.time() + 100, reply_chat_id=123)
    msg = message("Stop the current task", user_id=requester)
    await execute_assistant_tool("cancel", msg)
    if requester == 123:
        running.cancel.assert_called_once()
        assert task.state == TaskState.FAILED
    else:
        running.cancel.assert_not_called()
        assert task.state == TaskState.NEEDS_INPUT


@pytest.mark.parametrize("text", [
    "004291", "AB CD EF", "person@example.com", "cancel",
    "Here is the code 004291", "Use ABCDEF please", "The value is abcdef",
])
async def test_unbound_input_like_values_never_reach_llm(monkeypatch, text):
    registry = ActiveTaskRegistry()
    monkeypatch.setattr("app.bot.handlers.task_registry", registry)
    route = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    task = TaskRecord(user_id=123, chat_id=123, prompt="Login", state=TaskState.NEEDS_INPUT)
    pending = registry.register_chat_input(task, "otp", time.time() + 100)
    pending.prompt_message_id = 77
    await handle_text_message(message(text))
    route.assert_not_awaited()
    assert pending.response is None


async def test_cancel_tool_cannot_claim_to_stop_completed_work(monkeypatch):
    registry = ActiveTaskRegistry()
    monkeypatch.setattr("app.bot.tools.task_registry", registry)
    task = TaskRecord(user_id=123, chat_id=123, prompt="Finished", state=TaskState.DONE)
    running = MagicMock()
    running.done.return_value = False
    registry.register(123, task, running, None)
    msg = message("Stop the current task")
    await execute_assistant_tool("cancel", msg)
    running.cancel.assert_not_called()
    assert task.state == TaskState.DONE
    assert "isn't an active task of yours" in msg.answer.call_args.args[0]


async def test_startup_clears_old_command_menu(monkeypatch):
    bot = AsyncMock()
    monkeypatch.setattr("app.main.get_bot", lambda: bot)
    monkeypatch.setattr("app.main.init_db", AsyncMock())
    monkeypatch.setattr("app.main.close_db", AsyncMock())
    monkeypatch.setattr("app.main.settings.TELEGRAM_WEBHOOK_URL", "")
    async with lifespan(app):
        bot.delete_my_commands.assert_awaited_once_with()
    bot.session.close.assert_awaited_once()
