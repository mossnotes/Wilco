"""Browser tools pause for a single secret or an owner-bound chat reply."""

import asyncio
import logging
import time
import uuid
from html.parser import HTMLParser
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from pydantic import ValidationError
from browser_use.tools.views import InputTextAction

from app.bot.handlers import handle_text_message
from app.bot.status_manager import credential_input_keyboard, format_status_message
from app.browser.controller import SecureController
from app.companion.auth import SESSION_COOKIE_NAME, create_session_token
from app.db.engine import async_session_factory, init_db
from app.db.repository import CredentialRepository, TaskRepository, UserRepository
from app.config import settings
from app.security.vault import decrypt_secret, encrypt_secret
from app.tasks.registry import task_registry
from app.tasks.chat_input import otp_prompt
from app.tasks.state import TaskRecord, TaskState


@pytest_asyncio.fixture(autouse=True)
async def database():
    await init_db()


async def make_context():
    async with async_session_factory() as db:
        user, _ = await UserRepository.get_or_create_by_telegram_id(db, uuid.uuid4().int % 10**12)
        await db.commit()
    task = TaskRecord(user_id=user.telegram_id, chat_id=user.telegram_id, prompt="Login to example.com")
    ready = asyncio.Event()
    bot = SimpleNamespace(send_message=AsyncMock(return_value=SimpleNamespace(message_id=456)))
    status = SimpleNamespace(update=AsyncMock(side_effect=lambda *a, **k: ready.set()), bot=bot)
    browser = SimpleNamespace(get_current_page_url=AsyncMock(return_value="https://example.com/login"))
    controller = SecureController(user_id=user.id, task=task, status_manager=status)
    return user, task, controller, browser, ready


def action(controller, name):
    return controller.registry.registry.actions[name].function


class Inputs(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.fields = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag in ("input", "textarea", "select"):
            self.fields.append(dict(attrs))


@pytest.mark.parametrize("kind,suffix,label", [("password", "pass", "Password"), ("api_key", "api_key", "API key")])
async def test_single_secret_tool_roundtrip(async_client, kind, suffix, label, caplog):
    user, task, controller, browser, ready = await make_context()
    running = asyncio.create_task(action(controller, f"need_{kind}")(domain="example.com", browser_session=browser))
    try:
        await asyncio.wait_for(ready.wait(), 5)
        assert task.metadata["credential_type"] == kind
        assert credential_input_keyboard(task) is not None
        async_client.cookies.set(SESSION_COOKIE_NAME, create_session_token(user.id, user.telegram_id))
        page = await async_client.get(f"/companion/input?task_id={task.task_id}")
        assert page.status_code == 200
        assert page.headers["cache-control"] == "no-store"
        assert f"<h1>{label}</h1>" in page.text
        fields = Inputs(page.text).fields
        assert len(fields) == 1
        assert fields[0]["type"] == "password"
        assert fields[0]["id"] == "secret"
        assert "data-toggle-secret" in page.text
        assert 'aria-pressed="false"' in page.text
        assert 'id="username"' not in page.text

        # Type is bound to the pending task, never chosen freely by the client.
        wrong = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", json={
            "credential_type": "api_key" if kind == "password" else "password", "secret": "wrong",
        })
        assert wrong.status_code == 400
        assert task.state == TaskState.NEEDS_INPUT
        mixed = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", json={
            "credential_type": kind, "secret": "wrong", "username": "unrequested",
        })
        assert mixed.status_code == 400

        secret = "  exact-private-value  "
        response = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", json={
            "credential_type": kind, "secret": secret,
        })
        assert response.status_code == 200
        result = await asyncio.wait_for(running, 5)
        assert result.error is None
        assert f"<secret>example_{suffix}</secret>" in result.extracted_content
        assert secret not in result.model_dump_json() + response.text + caplog.text
        assert controller.sensitive_data["https://*.example.com"][f"example_{suffix}"] == secret
        assert task.state == TaskState.RUNNING
        assert "credential_type" not in task.metadata
        assert task_registry.get_credential_input(task.task_id) is None
        async with async_session_factory() as db:
            credentials = await CredentialRepository.get_credentials_for_user(db, user.id)
            assert len(credentials) == 1
            assert credentials[0].auth_type == kind
            assert decrypt_secret(credentials[0].encrypted_blob, settings.vault_key_bytes) == secret
            saved = await TaskRepository.get_task(db, task.task_id)
            assert secret not in saved.model_dump_json()
    finally:
        if not running.done():
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)


@pytest.mark.parametrize("kind,existing", [("password", "api_key"), ("api_key", "password")])
async def test_request_for_specific_type_is_not_satisfied_by_another(kind, existing, monkeypatch):
    user, _, controller, browser, _ = await make_context()
    async with async_session_factory() as db:
        await CredentialRepository.add_or_update_credential(
            db, user.id, "example.com", existing, encrypt_secret("existing", settings.vault_key_bytes),
        )
        await db.commit()
    wait = AsyncMock(return_value="test stopped before submission")
    monkeypatch.setattr(controller, "_wait_for_credentials", wait)
    result = await action(controller, f"need_{kind}")(domain="example.com", browser_session=browser)
    wait.assert_awaited_once_with("example.com", kind)
    assert result.error == "test stopped before submission"


async def test_cached_password_preserves_other_scoped_placeholders():
    user, _, controller, browser, _ = await make_context()
    async with async_session_factory() as db:
        await CredentialRepository.add_or_update_credential(
            db, user.id, "example.com", "password", encrypt_secret("private", settings.vault_key_bytes),
        )
        await db.commit()
    controller.sensitive_data["https://*.example.com"] = {"example_api_key": "existing"}
    result = await action(controller, "need_password")(domain="example.com", browser_session=browser)
    assert result.error is None
    assert controller.sensitive_data["https://*.example.com"] == {"example_api_key": "existing", "example_pass": "private"}


def message(task, text="person@example.com", *, sender=None, reply_id=456):
    return SimpleNamespace(
        text=text, chat=SimpleNamespace(id=task.chat_id),
        from_user=SimpleNamespace(id=task.user_id if sender is None else sender),
        reply_to_message=SimpleNamespace(message_id=reply_id),
        answer=AsyncMock(), delete=AsyncMock(), message_id=789,
    )


@pytest.mark.parametrize("field,value", [("username", "myusername"), ("email", "person@example.com")])
async def test_chat_reply_resumes_original_browser_task(field, value, monkeypatch):
    _, task, controller, browser, ready = await make_context()
    route = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    running = asyncio.create_task(action(controller, "ask_user")(domain="example.com", field=field, browser_session=browser))
    try:
        await asyncio.wait_for(ready.wait(), 5)
        # Give the tool the next scheduling opportunity to send its Telegram prompt.
        await asyncio.sleep(0)
        pending = task_registry.get_chat_input(task.chat_id)
        assert pending.prompt_message_id == 456
        assert controller.status_manager.bot.send_message.call_args.kwargs["reply_markup"].force_reply
        assert "Web Companion" not in format_status_message(task)
        assert credential_input_keyboard(task) is None
        assert "companion_url" not in task.metadata
        msg = message(task, value)
        await handle_text_message(msg)
        result = await asyncio.wait_for(running, 5)
        assert value in result.extracted_content
        assert result.error is None
        assert task.state == TaskState.RUNNING
        assert task_registry.get_chat_input(task.chat_id) is None
        assert "chat_input_field" not in task.metadata
        route.assert_not_awaited()
        async with async_session_factory() as db:
            saved = await TaskRepository.get_task(db, task.task_id)
            assert saved.state == TaskState.RUNNING
            assert value not in saved.model_dump_json()
    finally:
        if not running.done():
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)


@pytest.mark.parametrize("variant", ["wrong_sender", "wrong_question", "secret", "long", "multiline"])
async def test_invalid_chat_reply_does_not_wake_browser(variant, monkeypatch):
    _, task, _, _, _ = await make_context()
    task.transition_to(TaskState.NEEDS_INPUT)
    pending = task_registry.register_chat_input(task, "email", time.time() + 100)
    pending.prompt_message_id = 456
    msg = message(task)
    if variant == "wrong_sender":
        msg.from_user.id += 1
    elif variant == "wrong_question":
        msg.reply_to_message.message_id = 999
    elif variant == "secret":
        msg.text = "my password is private"
    elif variant == "long":
        msg.text = "x" * 321
    else:
        msg.text = "person@example.com\npassword"
    route = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    try:
        await handle_text_message(msg)
        assert not pending.event.is_set()
        assert task.state == TaskState.NEEDS_INPUT
        assert pending.response is None
        route.assert_not_awaited()
        if variant == "secret":
            msg.delete.assert_awaited_once()
    finally:
        task_registry.clear_chat_input(task.chat_id)


@pytest.mark.parametrize("name", ["ask_user", "need_otp"])
async def test_chat_tool_timeout_cleans_up(monkeypatch, name):
    monkeypatch.setattr("app.browser.controller.CREDENTIAL_INPUT_TIMEOUT", 0.05)
    _, task, controller, browser, _ = await make_context()
    kwargs = {"field": "email"} if name == "ask_user" else {"channel": "sms"}
    result = await action(controller, name)(domain="example.com", browser_session=browser, **kwargs)
    assert "timed out" in result.error
    assert task.state == TaskState.FAILED
    assert task_registry.get_chat_input(task.chat_id) is None
    assert "chat_input_field" not in task.metadata


@pytest.mark.parametrize("name", ["ask_user", "need_otp"])
async def test_chat_tool_cancellation_cleans_up(name):
    _, task, controller, browser, ready = await make_context()
    kwargs = {"field": "username"} if name == "ask_user" else {"channel": "sms"}
    running = asyncio.create_task(action(controller, name)(domain="example.com", browser_session=browser, **kwargs))
    await asyncio.wait_for(ready.wait(), 5)
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    assert task.state == TaskState.FAILED
    assert task_registry.get_chat_input(task.chat_id) is None


@pytest.mark.parametrize("name", ["need_password", "need_api_key", "ask_user", "need_otp"])
async def test_new_tools_reject_wrong_origin(name):
    _, _, controller, browser, _ = await make_context()
    browser.get_current_page_url.return_value = "https://attacker.com"
    kwargs = {"field": "email"} if name == "ask_user" else {}
    result = await action(controller, name)(domain="example.com", browser_session=browser, **kwargs)
    assert "Security violation" in result.error
    controller.status_manager.bot.send_message.assert_not_awaited()
    assert controller.sensitive_data == {}


async def test_chat_tool_rejects_secret_field():
    _, _, controller, browser, _ = await make_context()
    with pytest.raises(ValidationError):
        await action(controller, "ask_user")(domain="example.com", field="otp", browser_session=browser)
    controller.status_manager.bot.send_message.assert_not_awaited()


async def test_new_tools_registered_with_restricted_chat_schema():
    actions = SecureController().registry.registry.actions
    assert {"need_password", "need_api_key", "ask_user", "need_otp"} <= actions.keys()
    schema = actions["ask_user"].param_model.model_json_schema()
    assert schema["properties"]["field"]["enum"] == ["username", "email"]


@pytest.mark.parametrize("channel,hint", [
    ("sms", "SMS messages"), ("whatsapp", "WhatsApp messages"),
    ("email", "inbox and spam"), ("authenticator", "authenticator app"),
    ("unknown", "delivery instructions on the website"),
])
async def test_otp_chat_roundtrip_keeps_code_out_of_model_vault_and_logs(channel, hint, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    user, task, controller, browser, ready = await make_context()
    route = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    running = asyncio.create_task(action(controller, "need_otp")(
        domain="example.com", channel=channel, browser_session=browser,
    ))
    try:
        await asyncio.wait_for(ready.wait(), 5)
        await asyncio.sleep(0)
        prompt = controller.status_manager.bot.send_message.call_args.kwargs
        assert hint in prompt["text"]
        assert "example.com" in prompt["text"]
        pending = task_registry.get_chat_input(task.chat_id)
        assert pending.field == "otp"
        assert credential_input_keyboard(task) is None

        msg = message(task, "00 42-91")
        await handle_text_message(msg)
        result = await asyncio.wait_for(running, 5)
        assert result.error is None
        assert "<secret>example_otp</secret>" in result.extracted_content
        assert controller.sensitive_data["https://*.example.com"]["example_otp"] == "004291"
        assert pending.response is None
        route.assert_not_awaited()
        assert task.state == TaskState.RUNNING
        assert task_registry.get_chat_input(task.chat_id) is None
        assert "004291" not in result.model_dump_json() + task.model_dump_json() + repr(pending) + caplog.text
        for call in msg.answer.call_args_list:
            assert "004291" not in str(call)
        async with async_session_factory() as db:
            assert await CredentialRepository.get_credentials_for_user(db, user.id) == []
            saved = await TaskRepository.get_task(db, task.task_id)
            assert "004291" not in saved.model_dump_json()

        # Ordinary scoped substitution preserves the code, including leading zeros.
        params = InputTextAction(index=1, text="<secret>example_otp</secret>")
        replaced = controller.registry._replace_sensitive_data(params, controller.sensitive_data, "https://example.com/login")
        assert replaced.text == "004291"
        blocked = controller.registry._replace_sensitive_data(params, controller.sensitive_data, "https://attacker.com")
        assert blocked.text == params.text
        assert "004291" not in caplog.text
    finally:
        if not running.done():
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)


@pytest.mark.parametrize("variant", ["wrong_sender", "wrong_question", "invalid_code", "expired"])
async def test_otp_reply_rejects_invalid_or_unmatched_input(variant, monkeypatch):
    _, task, _, _, _ = await make_context()
    task.transition_to(TaskState.NEEDS_INPUT)
    pending = task_registry.register_chat_input(task, "otp", time.time() + 100)
    pending.prompt_message_id = 456
    msg = message(task, "004291")
    if variant == "wrong_sender":
        msg.from_user.id += 1
    elif variant == "wrong_question":
        msg.reply_to_message.message_id = 111
    elif variant == "invalid_code":
        msg.text = "Here is a whole sentence"
    else:
        pending.deadline = time.time() - 1
    route = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    try:
        await handle_text_message(msg)
        assert not pending.event.is_set()
        assert pending.response is None
        assert task.state == TaskState.NEEDS_INPUT
        route.assert_not_awaited()
    finally:
        task_registry.clear_chat_input(task.chat_id)


@pytest.mark.parametrize("split_prompt", [False, True])
async def test_late_otp_reply_is_not_sent_to_router(monkeypatch, split_prompt):
    _, task, _, _, _ = await make_context()
    msg = message(task, "004291")
    msg.bot = SimpleNamespace(id=987)
    prompt = otp_prompt("example.com", "sms")
    if split_prompt:
        from app.bot.delivery import split_message
        prompt = split_message(prompt, 80)[-1]
    msg.reply_to_message.text = prompt
    msg.reply_to_message.from_user = SimpleNamespace(id=987)
    route = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    await handle_text_message(msg)
    route.assert_not_awaited()
    assert "expired" in msg.answer.call_args.args[0]


async def test_otp_origin_is_rechecked_after_human_reply():
    _, task, controller, browser, ready = await make_context()
    browser.get_current_page_url.side_effect = ["https://example.com/login", "https://attacker.com"]
    running = asyncio.create_task(action(controller, "need_otp")(domain="example.com", browser_session=browser))
    try:
        await asyncio.wait_for(ready.wait(), 5)
        await asyncio.sleep(0)
        await handle_text_message(message(task, "004291"))
        result = await asyncio.wait_for(running, 5)
        assert "Page changed origin" in result.error
        assert controller.sensitive_data == {}
        assert "004291" not in result.model_dump_json()
    finally:
        if not running.done():
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)


async def test_otp_tool_channel_contract():
    controller = SecureController()
    schema = controller.registry.registry.actions["need_otp"].param_model.model_json_schema()
    assert schema["properties"]["channel"]["enum"] == ["sms", "whatsapp", "email", "authenticator", "unknown"]
    assert schema["properties"]["channel"]["default"] == "unknown"
    with pytest.raises(ValidationError):
        await action(controller, "need_otp")(domain="example.com", channel="invented")
