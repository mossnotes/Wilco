import asyncio
import logging
import re
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import phonenumbers
import pytest
from aiogram.exceptions import TelegramForbiddenError
from aiogram.methods import SendMessage
from browser_use import ActionResult, Controller
from browser_use.tools.views import InputTextAction

from app.bot.delivery import split_message
from app.bot.handlers import handle_text_message
from app.bot.memory import conversation_memory, sanitize_memory_text
from app.browser.controller import SecureController
from app.browser.credentials_resolver import resolve_task_credentials
from app.config import settings
from app.db.engine import async_session_factory, init_db
from app.db.repository import CredentialRepository, UserRepository
from app.security.account_details import account_placeholders, normalize_country_code, normalize_phone_number
from app.security.vault import decrypt_secret, encrypt_secret
from app.tasks.chat_input import ACCOUNT_PROMPT_PREFIXES, account_input_prompt
from app.tasks.registry import task_registry
from app.tasks.state import TaskRecord, TaskState


@pytest.fixture(autouse=True)
async def database():
    await init_db()


def example_phone(region="GB", kind=phonenumbers.PhoneNumberType.MOBILE):
    return phonenumbers.format_number(phonenumbers.example_number_for_type(region, kind), phonenumbers.PhoneNumberFormat.E164)


async def context(*, group=False, user=None, domain="example.com"):
    if user is None:
        async with async_session_factory() as db:
            user, _ = await UserRepository.get_or_create_by_telegram_id(db, uuid.uuid4().int % 10**12)
            await db.commit()
    task = TaskRecord(user_id=user.telegram_id, chat_id=-user.telegram_id if group else user.telegram_id, prompt=f"Login to {domain}")
    sent = asyncio.Event()

    async def send(**kwargs):
        sent.set()
        return SimpleNamespace(message_id=456)

    bot = SimpleNamespace(send_message=AsyncMock(side_effect=send), id=987)
    status = SimpleNamespace(bot=bot, update=AsyncMock())
    controller = SecureController(user_id=user.id, task=task, status_manager=status)
    browser = SimpleNamespace(get_current_page_url=AsyncMock(return_value=f"https://{domain}/login"))
    return SimpleNamespace(user=user, task=task, bot=bot, controller=controller, browser=browser, sent=sent)


def local_phone(region="GB", kind=phonenumbers.PhoneNumberType.MOBILE):
    number = phonenumbers.example_number_for_type(region, kind)
    return re.sub(r"\D", "", phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL))


def ask(ctx, field, **kwargs):
    action_name = {"phone": "ask_phone_number", "country_code": "ask_country_code"}.get(field, "ask_user")
    params = {} if field in ("phone", "country_code") else {"field": field}
    return ctx.controller.registry.registry.actions[action_name].function(
        domain="example.com", browser_session=ctx.browser, **params, **kwargs,
    )


def reply(ctx, value, *, chat_id=None, sender=None, reply_id=456):
    prompt = ctx.bot.send_message.call_args.kwargs["text"] if ctx.bot.send_message.called else ""
    return SimpleNamespace(
        text=value, chat=SimpleNamespace(id=chat_id if chat_id is not None else ctx.user.telegram_id),
        from_user=SimpleNamespace(id=sender if sender is not None else ctx.user.telegram_id),
        message_id=789, bot=ctx.bot, answer=AsyncMock(), delete=AsyncMock(),
        reply_to_message=SimpleNamespace(message_id=reply_id, text=prompt, from_user=SimpleNamespace(id=ctx.bot.id)),
    )


async def finish(running):
    if not running.done():
        running.cancel()
    await asyncio.gather(running, return_exceptions=True)


@pytest.mark.parametrize("value,expected", [
    ("020 7946 0018", "02079460018"), ("0001234567", "0001234567"), ("123456", "123456"),
])
def test_phone_number_preserves_digits_and_has_only_one_placeholder(value, expected):
    assert account_placeholders("example", "phone", value) == {"example_phone_number": expected}


@pytest.mark.parametrize("value", ["123", "0" * 16, "+447400123456", "not a number", "020\n79460018"])
def test_phone_number_rejects_invalid_or_combined_numbers_without_echoing_them(value):
    with pytest.raises(ValueError) as exc:
        normalize_phone_number(value)
    assert value not in str(exc.value)


@pytest.mark.parametrize("value,expected", [("+1", "+1"), ("44", "+44"), ("+91", "+91")])
def test_country_code_is_validated_independently(value, expected):
    assert normalize_country_code(value) == expected
    assert account_placeholders("example", "country_code", value) == {"example_country_code": expected}


@pytest.mark.parametrize("value", ["+447400123456", "7400123456", "+999", "GB", "00", "+44\n123"])
def test_country_code_cannot_contain_a_phone_number_or_invalid_code(value):
    with pytest.raises(ValueError) as exc:
        normalize_country_code(value)
    assert value not in str(exc.value)


@pytest.mark.parametrize("field", ["username", "email", "phone", "country_code"])
def test_account_question_last_bubble_remains_identifiable(field):
    prompt = account_input_prompt("a" * 60 + ".example.com", field)
    last = split_message(prompt, 80)[-1]
    assert last.startswith(ACCOUNT_PROMPT_PREFIXES)
    assert len(last) <= 80
    if field == "phone":
        assert "without a country code" in prompt
        assert "Include +" not in prompt
    if field == "country_code":
        assert "phone number" not in prompt


@pytest.mark.parametrize("field,value", [
    ("username", "private-user-canary"), ("email", "Private.User+canary@example.com"),
    ("phone", local_phone()),
])
async def test_identifiers_are_encrypted_scoped_and_reused_without_model_values(field, value, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(settings, "CONVERSATION_MEMORY_ENABLED", True)
    route = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    ctx = await context()
    running = asyncio.create_task(ask(ctx, field))
    try:
        await asyncio.wait_for(ctx.sent.wait(), 5)
        await handle_text_message(reply(ctx, value))
        result = await asyncio.wait_for(running, 5)
        assert result.error is None
        assert value not in result.model_dump_json() + ctx.task.model_dump_json() + caplog.text
        slots = account_placeholders("example", field, value)
        assert ctx.controller.sensitive_data["https://*.example.com"] == slots
        assert all(f"<secret>{slot}</secret>" in result.extracted_content for slot in slots)
        route.assert_not_awaited()
        async with async_session_factory() as db:
            saved = await CredentialRepository.get_credentials_for_domain(db, ctx.user.id, "example.com")
            assert len(saved) == 1 and saved[0].auth_type == field
            assert saved[0].username_or_identifier is None
            assert value not in saved[0].encrypted_blob
            assert decrypt_secret(saved[0].encrypted_blob, settings.vault_key_bytes) == value
        memory = await conversation_memory.load(ctx.user.telegram_id, ctx.task.chat_id)
        assert value not in memory.model_dump_json()

        next_ctx = await context(user=ctx.user)
        reused = await ask(next_ctx, field)
        assert reused.error is None and value not in reused.model_dump_json()
        next_ctx.bot.send_message.assert_not_awaited()
        assert next_ctx.controller.sensitive_data["https://*.example.com"] == slots

        # Recreated task credential resolution also loads the saved data.
        preloaded, _ = await resolve_task_credentials(telegram_id=ctx.user.telegram_id, explicit_domain="example.com")
        for slot, secret in slots.items():
            assert preloaded["https://*.example.com"][slot] == secret

        for slot, secret in slots.items():
            params = InputTextAction(index=1, text=f"<secret>{slot}</secret>")
            allowed = ctx.controller.registry._replace_sensitive_data(params, ctx.controller.sensitive_data, "https://example.com/login")
            assert allowed.text == secret
            blocked = ctx.controller.registry._replace_sensitive_data(params, ctx.controller.sensitive_data, "https://attacker.example")
            assert blocked.text == params.text
    finally:
        await finish(running)


@pytest.mark.parametrize("variant", ["wrong_sender", "wrong_question", "combined_number", "invalid_phone"])
async def test_bad_phone_replies_do_not_resume_or_write_to_vault(variant, monkeypatch):
    ctx = await context()
    route = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    running = asyncio.create_task(ask(ctx, "phone"))
    try:
        await asyncio.wait_for(ctx.sent.wait(), 5)
        value = local_phone()
        msg = reply(ctx, value)
        if variant == "wrong_sender":
            msg.from_user.id += 1
        elif variant == "wrong_question":
            msg.reply_to_message.message_id += 1
        elif variant == "combined_number":
            msg.text = example_phone()
        else:
            msg.text = "+123"
        await handle_text_message(msg)
        pending = task_registry.get_chat_input(ctx.task.chat_id)
        assert pending.response is None and not pending.event.is_set()
        if variant == "combined_number":
            assert "country code" in msg.answer.call_args.args[0]
        route.assert_not_awaited()
        async with async_session_factory() as db:
            assert await CredentialRepository.get_credentials_for_user(db, ctx.user.id) == []
    finally:
        await finish(running)


async def test_phone_and_country_code_are_collected_saved_and_typed_separately():
    ctx = await context()
    number = local_phone()
    running = asyncio.create_task(ask(ctx, "phone"))
    try:
        await asyncio.wait_for(ctx.sent.wait(), 5)
        await handle_text_message(reply(ctx, number))
        assert (await asyncio.wait_for(running, 5)).error is None
    finally:
        await finish(running)
    before_code = dict(ctx.controller.sensitive_data["https://*.example.com"])
    assert before_code == {"example_phone_number": number}
    ctx.sent.clear()
    running = asyncio.create_task(ask(ctx, "country_code"))
    try:
        await asyncio.wait_for(ctx.sent.wait(), 5)
        assert task_registry.get_chat_input(ctx.task.chat_id).field == "country_code"
        await handle_text_message(reply(ctx, "+44"))
        result = await asyncio.wait_for(running, 5)
        assert result.error is None and number not in result.model_dump_json()
        scoped = ctx.controller.sensitive_data["https://*.example.com"]
        assert scoped == {**before_code, "example_country_code": "+44"}
        for slot, expected in (("example_phone_number", number), ("example_country_code", "+44")):
            typed = ctx.controller.registry._replace_sensitive_data(
                InputTextAction(index=1, text=f"<secret>{slot}</secret>"),
                ctx.controller.sensitive_data, "https://example.com/login",
            )
            assert typed.text == expected
        async with async_session_factory() as db:
            saved = {item.auth_type: item for item in await CredentialRepository.get_credentials_for_domain(db, ctx.user.id, "example.com")}
            assert set(saved) == {"phone", "country_code"}
            assert decrypt_secret(saved["phone"].encrypted_blob, settings.vault_key_bytes) == number
            assert decrypt_secret(saved["country_code"].encrypted_blob, settings.vault_key_bytes) == "+44"
            assert all(item.username_or_identifier is None for item in saved.values())
    finally:
        await finish(running)
    next_ctx = await context(user=ctx.user)
    phone_result = await ask(next_ctx, "phone")
    assert phone_result.error is None and "+44" not in phone_result.model_dump_json()
    assert next_ctx.controller.sensitive_data["https://*.example.com"] == before_code
    assert (await ask(next_ctx, "country_code")).error is None
    next_ctx.bot.send_message.assert_not_awaited()
    preloaded, _ = await resolve_task_credentials(telegram_id=ctx.user.telegram_id, explicit_domain="example.com")
    assert preloaded["https://*.example.com"] == before_code


@pytest.mark.parametrize("field,invalid", [("phone", "+447400123456"), ("country_code", "7400123456")])
async def test_tools_do_not_accept_each_others_combined_values(field, invalid, monkeypatch):
    ctx = await context()
    route = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    running = asyncio.create_task(ask(ctx, field))
    try:
        await asyncio.wait_for(ctx.sent.wait(), 5)
        await handle_text_message(reply(ctx, invalid))
        pending = task_registry.get_chat_input(ctx.task.chat_id)
        assert pending.response is None and not pending.event.is_set()
        assert ctx.controller.sensitive_data == {}
        route.assert_not_awaited()
        async with async_session_factory() as db:
            assert await CredentialRepository.get_credentials_for_user(db, ctx.user.id) == []
    finally:
        await finish(running)


async def test_old_combined_phone_does_not_block_password_resolution_or_get_preloaded():
    ctx = await context()
    async with async_session_factory() as db:
        for field, value in (("phone", example_phone()), ("password", "existing-password"), ("country_code", "+44")):
            await CredentialRepository.add_or_update_credential(db, ctx.user.id, "example.com", field, encrypt_secret(value, settings.vault_key_bytes))
        await db.commit()
    preloaded, _ = await resolve_task_credentials(telegram_id=ctx.user.telegram_id, explicit_domain="example.com")
    assert preloaded["https://*.example.com"]["example_pass"] == "existing-password"
    assert not any("phone" in slot or "country_code" in slot for slot in preloaded["https://*.example.com"])


@pytest.mark.parametrize("text", [
    "+91<secret>example_phone_number</secret>",
    "<secret>example_country_code</secret><secret>example_phone_number</secret>",
    "<secret>example_phone_number</secret>+91",
    "<secret>example_country_code</secret>7400123456",
])
async def test_browser_input_rejects_attached_country_codes_before_typing(text, monkeypatch):
    ctx = await context()
    native_input = AsyncMock(return_value=ActionResult(extracted_content="Typed"))
    monkeypatch.setattr(Controller, "act", native_input)
    action = SimpleNamespace(model_dump=lambda **kwargs: {"input": {"index": 1, "text": text}})
    result = await ctx.controller.act(action, ctx.browser, sensitive_data=ctx.controller.sensitive_data)
    assert result.error and "placeholder alone" in result.error
    native_input.assert_not_awaited()


@pytest.mark.parametrize("slot", ["example_phone_number", "example_country_code"])
async def test_browser_input_allows_each_separate_value(slot, monkeypatch):
    ctx = await context()
    native_input = AsyncMock(return_value=ActionResult(extracted_content="Typed"))
    monkeypatch.setattr(Controller, "act", native_input)
    action = SimpleNamespace(model_dump=lambda **kwargs: {"input": {"index": 1, "text": f"<secret>{slot}</secret>"}})
    result = await ctx.controller.act(action, ctx.browser, sensitive_data=ctx.controller.sensitive_data)
    assert result.error is None
    native_input.assert_awaited_once()


async def test_refresh_to_phone_number_removes_old_combined_placeholders():
    ctx = await context()
    ctx.controller.sensitive_data["https://*.example.com"] = {
        "example_phone_international": example_phone("IN"), "example_phone_local": "old-number",
        "example_pass": "existing-password", "example_country_code": "+91",
    }
    number = local_phone()
    running = asyncio.create_task(ask(ctx, "phone", force_refresh=True))
    try:
        await asyncio.wait_for(ctx.sent.wait(), 5)
        await handle_text_message(reply(ctx, number))
        result = await asyncio.wait_for(running, 5)
        assert result.error is None
        assert ctx.controller.sensitive_data["https://*.example.com"] == {
            "example_phone_number": number, "example_pass": "existing-password", "example_country_code": "+91",
        }
    finally:
        await finish(running)


async def test_group_task_collects_number_privately_and_cleans_both_chat_bindings():
    ctx = await context(group=True)
    value = local_phone()
    running = asyncio.create_task(ask(ctx, "phone"))
    try:
        await asyncio.wait_for(ctx.sent.wait(), 5)
        assert ctx.bot.send_message.call_args.kwargs["chat_id"] == ctx.user.telegram_id
        pending = task_registry.get_chat_input(ctx.task.chat_id)
        assert pending is task_registry.get_chat_input(ctx.user.telegram_id)
        await handle_text_message(reply(ctx, value, chat_id=ctx.task.chat_id))
        assert pending.response is None
        await handle_text_message(reply(ctx, value))
        result = await asyncio.wait_for(running, 5)
        assert result.error is None
        assert ctx.task.chat_id == -ctx.user.telegram_id
        assert task_registry.get_chat_input(ctx.task.chat_id) is None
        assert task_registry.get_chat_input(ctx.user.telegram_id) is None
    finally:
        await finish(running)


async def test_private_input_cannot_be_overwritten_by_another_group_task():
    first = await context(group=True)
    running = asyncio.create_task(ask(first, "phone"))
    try:
        await asyncio.wait_for(first.sent.wait(), 5)
        pending = task_registry.get_chat_input(first.user.telegram_id)
        second = await context(user=first.user, group=True)
        second.task.chat_id -= 1
        result = await ask(second, "email")
        assert result.error and "Another input request" in result.error
        assert task_registry.get_chat_input(first.user.telegram_id) is pending
        assert task_registry.get_chat_input(second.task.chat_id) is None
    finally:
        await finish(running)
    assert task_registry.get_chat_input(first.user.telegram_id) is None


async def test_unavailable_private_chat_fails_without_collecting_in_group():
    ctx = await context(group=True)

    async def send(**kwargs):
        if kwargs["chat_id"] == ctx.user.telegram_id:
            raise TelegramForbiddenError(method=SendMessage(chat_id=ctx.user.telegram_id, text="Input"), message="Forbidden")
        return SimpleNamespace(message_id=1)

    ctx.bot.send_message.side_effect = send
    result = await ask(ctx, "phone")
    assert result.error and "private chat" in result.error
    assert ctx.task.state == TaskState.FAILED
    assert task_registry.get_chat_input(ctx.user.telegram_id) is None
    assert task_registry.get_chat_input(ctx.task.chat_id) is None
    assert "retry this task" in ctx.bot.send_message.call_args.kwargs["text"]


@pytest.mark.parametrize("other_owner", [False, True])
async def test_saved_identifier_is_not_reused_for_another_domain_or_owner(other_owner):
    original = await context()
    async with async_session_factory() as db:
        await CredentialRepository.add_or_update_credential(
            db, original.user.id, "example.com", "email", encrypt_secret("private@example.com", settings.vault_key_bytes),
        )
        await db.commit()
    other = await context(user=None if other_owner else original.user, domain="example.com" if other_owner else "other.example")
    running = asyncio.create_task(other.controller.registry.registry.actions["ask_user"].function(
        domain="example.com" if other_owner else "other.example", field="email", browser_session=other.browser,
    ))
    try:
        await asyncio.wait_for(other.sent.wait(), 5)
        assert other.controller.sensitive_data == {}
        assert "private@example.com" not in other.bot.send_message.call_args.kwargs["text"]
    finally:
        await finish(running)


async def test_controller_cannot_use_a_different_vault_owner():
    ctx = await context()
    other = await context()
    ctx.controller.user_id = other.user.id
    result = await ask(ctx, "email")
    assert "authenticated vault owner" in result.error
    ctx.bot.send_message.assert_not_awaited()
    assert ctx.controller.sensitive_data == {}


async def test_saved_combined_phone_requires_a_fresh_number_without_a_code():
    ctx = await context()
    async with async_session_factory() as db:
        await CredentialRepository.add_or_update_credential(
            db, ctx.user.id, "example.com", "phone", encrypt_secret(example_phone("IN"), settings.vault_key_bytes),
        )
        await db.commit()
    running = asyncio.create_task(ask(ctx, "phone"))
    try:
        await asyncio.wait_for(ctx.sent.wait(), 5)
        assert "without a country code" in ctx.bot.send_message.call_args.kwargs["text"]
        assert ctx.controller.sensitive_data == {}
        await handle_text_message(reply(ctx, local_phone()))
        assert (await asyncio.wait_for(running, 5)).error is None
        async with async_session_factory() as db:
            saved = await CredentialRepository.get_credentials_for_domain(db, ctx.user.id, "example.com")
            assert decrypt_secret(saved[0].encrypted_blob, settings.vault_key_bytes) == local_phone()
    finally:
        await finish(running)


async def test_changed_origin_blocks_cached_identifier():
    ctx = await context()
    async with async_session_factory() as db:
        await CredentialRepository.add_or_update_credential(
            db, ctx.user.id, "example.com", "email", encrypt_secret("private@example.com", settings.vault_key_bytes),
        )
        await db.commit()
    ctx.browser.get_current_page_url.side_effect = ["https://example.com/login", "https://attacker.example"]
    result = await ask(ctx, "email")
    assert "Page or task changed" in result.error
    ctx.bot.send_message.assert_not_awaited()
    assert ctx.controller.sensitive_data == {}


async def test_explicit_refresh_replaces_only_requested_identifier():
    ctx = await context()
    async with async_session_factory() as db:
        old = await CredentialRepository.add_or_update_credential(
            db, ctx.user.id, "example.com", "email", encrypt_secret("old@example.com", settings.vault_key_bytes),
        )
        await CredentialRepository.add_or_update_credential(
            db, ctx.user.id, "example.com", "password", encrypt_secret("private-password", settings.vault_key_bytes),
        )
        old_id = old.id
        await db.commit()
    preloaded, _ = await resolve_task_credentials(telegram_id=ctx.user.telegram_id, explicit_domain="example.com")
    ctx.controller.sensitive_data.update(preloaded)
    running = asyncio.create_task(ask(ctx, "email", force_refresh=True))
    try:
        await asyncio.wait_for(ctx.sent.wait(), 5)
        await handle_text_message(reply(ctx, "new@example.com"))
        assert (await asyncio.wait_for(running, 5)).error is None
        scoped = ctx.controller.sensitive_data["https://*.example.com"]
        assert scoped["example_user"] == scoped["x_user"] == scoped["example_email"] == "new@example.com"
        async with async_session_factory() as db:
            values = {item.auth_type: item for item in await CredentialRepository.get_credentials_for_domain(db, ctx.user.id, "example.com")}
            assert values["email"].id == old_id
            assert decrypt_secret(values["email"].encrypted_blob, settings.vault_key_bytes) == "new@example.com"
            assert decrypt_secret(values["password"].encrypted_blob, settings.vault_key_bytes) == "private-password"
    finally:
        await finish(running)


async def test_changed_origin_rejects_identifier_before_vault_write():
    ctx = await context()
    ctx.browser.get_current_page_url.side_effect = ["https://example.com/login", "https://attacker.example"]
    running = asyncio.create_task(ask(ctx, "phone"))
    try:
        await asyncio.wait_for(ctx.sent.wait(), 5)
        await handle_text_message(reply(ctx, local_phone()))
        result = await asyncio.wait_for(running, 5)
        assert "Page changed origin" in result.error
        assert ctx.controller.sensitive_data == {}
        async with async_session_factory() as db:
            assert await CredentialRepository.get_credentials_for_user(db, ctx.user.id) == []
    finally:
        await finish(running)


@pytest.mark.parametrize("legacy_identifier", ["legacy@example.com", "  legacy@example.com  "])
async def test_legacy_login_identifier_is_migrated_to_encrypted_field(legacy_identifier):
    ctx = await context()
    async with async_session_factory() as db:
        await CredentialRepository.add_or_update_credential(
            db, ctx.user.id, "example.com", "password", encrypt_secret("private-password", settings.vault_key_bytes),
            username_or_identifier=legacy_identifier,
        )
        await db.commit()
    result = await ask(ctx, "email")
    assert result.error is None and "legacy@example.com" not in result.model_dump_json()
    ctx.bot.send_message.assert_not_awaited()
    async with async_session_factory() as db:
        values = {item.auth_type: item for item in await CredentialRepository.get_credentials_for_domain(db, ctx.user.id, "example.com")}
        assert values["password"].username_or_identifier is None
        assert decrypt_secret(values["email"].encrypted_blob, settings.vault_key_bytes) == "legacy@example.com"


async def test_late_phone_reply_never_reaches_model_or_memory(monkeypatch):
    ctx = await context()
    monkeypatch.setattr(settings, "CONVERSATION_MEMORY_ENABLED", True)
    route = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    msg = reply(ctx, local_phone())
    msg.reply_to_message.text = split_message(account_input_prompt("example.com", "phone"), 80)[-1]
    await handle_text_message(msg)
    route.assert_not_awaited()
    assert "expired" in msg.answer.call_args.args[0]
    assert not (await conversation_memory.load(ctx.user.telegram_id, ctx.user.telegram_id)).messages


def test_formatted_number_and_case_changed_email_are_redacted_from_memory():
    number = example_phone()
    formatted = phonenumbers.format_number(phonenumbers.parse(number, None), phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    redacted = sanitize_memory_text(f"Contact: {formatted}, private.user@example.com", secrets=(number, "Private.User@Example.com"))
    assert formatted not in redacted and "private.user@example.com" not in redacted
    assert "REDACTED" in redacted


def test_short_local_phone_is_redacted_when_website_formats_it():
    redacted = sanitize_memory_text("Phone: 012-345", secrets=("012345",))
    assert "012-345" not in redacted and "REDACTED" in redacted
