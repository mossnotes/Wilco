import asyncio
import json
import time
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from google.genai import types

from app.bot.handlers import handle_text_message
from app.bot.memory import ConversationContext, ConversationMemory, MemoryMessage, sanitize_memory_text
from app.bot.message_router import MessageDecision, _parse_gemini_response, route_message
from app.bot.serialization import incoming_messages
from app.browser.runner import run_browser_task
from app.config import settings
from app.db.engine import async_session_factory, init_db
from app.db.models import ConversationModel
from app.db.repository import TaskRepository
from app.tasks.registry import ActiveTaskRegistry
from app.tasks.state import TaskRecord, TaskState


@pytest.fixture(autouse=True)
async def memory_setup(monkeypatch):
    await init_db()
    monkeypatch.setattr(settings, "CONVERSATION_MEMORY_ENABLED", True)
    memory = ConversationMemory()
    registry = ActiveTaskRegistry()
    monkeypatch.setattr("app.bot.handlers.conversation_memory", memory)
    monkeypatch.setattr("app.browser.runner.conversation_memory", memory)
    monkeypatch.setattr("app.bot.memory.task_registry", registry)
    monkeypatch.setattr("app.bot.handlers.task_registry", registry)
    monkeypatch.setattr("app.bot.tools.task_registry", registry)
    return SimpleNamespace(memory=memory, registry=registry, user_id=uuid.uuid4().int % 10**12)


def message(scope, text, message_id=1, *, chat_id=None):
    return SimpleNamespace(
        text=text, message_id=message_id,
        chat=SimpleNamespace(id=chat_id or scope.user_id, type="private"),
        from_user=SimpleNamespace(id=scope.user_id), bot=SimpleNamespace(id=987),
        reply_to_message=None, answer=AsyncMock(), delete=AsyncMock(),
    )


async def test_history_survives_service_recreation_and_isolates_user_and_chat(memory_setup):
    scope = memory_setup
    await scope.memory.remember(scope.user_id, 42, "user", "Check my deployments")
    await scope.memory.remember(scope.user_id, 42, "assistant", "Which platform?")
    restored = ConversationMemory()
    context = await restored.load(scope.user_id, 42)
    assert [item.content for item in context.messages] == ["Check my deployments", "Which platform?"]
    assert not (await restored.load(scope.user_id + 1, 42)).has_context
    assert not (await restored.load(scope.user_id, 43)).has_context


async def test_history_is_compacted_and_prompt_size_bounded(memory_setup, monkeypatch):
    scope = memory_setup
    monkeypatch.setattr(settings, "CONVERSATION_RECENT_MESSAGES", 2)
    monkeypatch.setattr(settings, "CONVERSATION_SUMMARY_MAX_CHARS", 300)
    monkeypatch.setattr(settings, "CONVERSATION_CONTEXT_MAX_CHARS", 2000)
    for index in range(12):
        await scope.memory.remember(scope.user_id, 42, "user", f"Request {index}: " + "useful detail " * 30)
    context = await scope.memory.load(scope.user_id, 42)
    assert len(context.messages) <= 2
    assert "Request 11" in context.messages[-1].content
    assert context.summary and len(context.summary) <= 300
    assert len(context.model_dump_json()) <= 2000


async def test_concurrent_appends_do_not_overwrite_each_other(memory_setup):
    scope = memory_setup
    await asyncio.gather(*(
        scope.memory.remember(scope.user_id, 42, "tool", f"outcome {index}") for index in range(10)
    ))
    context = await scope.memory.load(scope.user_id, 42)
    assert [item.content for item in context.messages] == [f"outcome {index}" for index in range(10)]
    assert scope.memory._locks.entries == {}


async def test_secrets_and_private_urls_are_scrubbed_before_storage_and_compaction(memory_setup, monkeypatch):
    scope = memory_setup
    monkeypatch.setattr(settings, "CONVERSATION_RECENT_MESSAGES", 2)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "configured-key-canary")
    secrets = ("vault-password-canary", "004291")
    text = (
        "configured-key-canary vault-password-canary 004291 "
        "https://user:private-pass@example.com/companion/link?token=pairing-canary#fragment-canary "
        "<secret>browser-secret-canary</secret>"
    )
    await scope.memory.remember(scope.user_id, 42, "tool", text, secrets=secrets)
    await scope.memory.remember(scope.user_id, 42, "user", "Next request")
    await scope.memory.remember(scope.user_id, 42, "assistant", "Next answer")
    async with async_session_factory() as session:
        row = await session.get(ConversationModel, (scope.user_id, 42))
        stored = row.summary + json.dumps(row.messages)
    for value in (*secrets, "configured-key-canary", "private-pass", "pairing-canary", "fragment-canary", "browser-secret-canary"):
        assert value not in stored
    assert "REDACTED" in stored


@pytest.mark.parametrize("text,secret", [
    ('{"access_token": "private-cookie-canary"}', "private-cookie-canary"),
    ("verification code: 123 456", "456"),
    ("password: private-password", "private-password"),
    ("https://example.com/token/private-path-canary", "private-path-canary"),
])
def test_memory_sanitizer_covers_embedded_secrets(text, secret):
    assert secret not in sanitize_memory_text(text)


async def test_clarification_followup_becomes_complete_browser_request(memory_setup, monkeypatch):
    scope = memory_setup
    contexts = []

    async def route(text, **kwargs):
        contexts.append(kwargs.get("context"))
        if text == "Check my deployments":
            return MessageDecision(route="reply", reply="Which platform?")
        assert text == "Vercel"
        history = kwargs["context"].model_dump_json()
        assert "Check my deployments" in history and "Which platform?" in history
        return MessageDecision(route="browser", browser_request="Check my deployments on Vercel.")

    monkeypatch.setattr("app.bot.handlers.route_message", route)
    run = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.run_browser_task", run)
    await handle_text_message(message(scope, "Check my deployments"))
    await handle_text_message(message(scope, "Vercel", 2))
    await asyncio.sleep(0)
    assert contexts[0] is None
    task = run.call_args.args[0]
    assert task.prompt == "Check my deployments on Vercel."
    assert task.user_id == scope.user_id
    context = await scope.memory.load(scope.user_id, scope.user_id)
    assert any("start_browser_task accepted" in item.content for item in context.messages)


async def test_incoming_turns_wait_for_previous_reply_and_history(memory_setup, monkeypatch):
    scope = memory_setup
    entered, release = asyncio.Event(), asyncio.Event()
    routed = []

    async def route(text, **kwargs):
        routed.append(text)
        if text == "First":
            entered.set()
            await release.wait()
        else:
            assert "First answer" in kwargs["context"].model_dump_json()
        return MessageDecision(route="reply", reply=f"{text} answer")

    monkeypatch.setattr("app.bot.handlers.route_message", route)
    first = asyncio.create_task(handle_text_message(message(scope, "First")))
    await entered.wait()
    second = asyncio.create_task(handle_text_message(message(scope, "Second", 2)))
    await asyncio.sleep(0)
    assert routed == ["First"]
    release.set()
    await asyncio.gather(first, second)
    assert routed == ["First", "Second"]
    assert incoming_messages.entries == {}


async def test_pasted_secret_is_deleted_even_when_earlier_turn_is_blocked(memory_setup, monkeypatch):
    scope = memory_setup
    entered, release = asyncio.Event(), asyncio.Event()

    async def route(text, **kwargs):
        entered.set()
        await release.wait()
        return MessageDecision(route="reply", reply="Ready")

    monkeypatch.setattr("app.bot.handlers.route_message", route)
    first = asyncio.create_task(handle_text_message(message(scope, "Hello")))
    await entered.wait()
    secret = message(scope, "my password is private-pasted-canary", 2)
    try:
        await asyncio.wait_for(handle_text_message(secret), 1)
        secret.delete.assert_awaited_once()
        context = await scope.memory.load(scope.user_id, scope.user_id)
        assert "private-pasted-canary" not in context.model_dump_json()
    finally:
        release.set()
        await first


async def test_current_public_url_parameters_reach_browser_while_memory_scrubs_queries(memory_setup, monkeypatch):
    scope = memory_setup
    text = "Inspect https://example.com/deployments?project=wilco&state=failed"

    async def route(current, **kwargs):
        assert current == text
        return MessageDecision(route="browser", browser_request=text)

    run = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    monkeypatch.setattr("app.bot.handlers.run_browser_task", run)
    await handle_text_message(message(scope, text))
    await asyncio.sleep(0)
    assert run.call_args.args[0].prompt == text
    context = await scope.memory.load(scope.user_id, scope.user_id)
    assert "project=wilco" not in context.model_dump_json()


async def test_other_chat_can_progress_while_first_chat_waits(memory_setup, monkeypatch):
    scope = memory_setup
    entered, release = asyncio.Event(), asyncio.Event()

    async def route(text, **kwargs):
        if text == "First":
            entered.set()
            await release.wait()
        return MessageDecision(route="reply", reply="Ready")

    monkeypatch.setattr("app.bot.handlers.route_message", route)
    first = asyncio.create_task(handle_text_message(message(scope, "First")))
    await entered.wait()
    other = message(scope, "Other chat", chat_id=scope.user_id + 1)
    try:
        await asyncio.wait_for(handle_text_message(other), 1)
        other.answer.assert_awaited_once()
        assert not first.done()
    finally:
        release.set()
        await first


async def test_verification_reply_is_never_remembered(memory_setup, monkeypatch):
    scope = memory_setup
    task = TaskRecord(user_id=scope.user_id, chat_id=scope.user_id, prompt="Login", state=TaskState.NEEDS_INPUT)
    pending = scope.registry.register_chat_input(task, "otp", time.time() + 100)
    pending.prompt_message_id = 77
    route = AsyncMock()
    monkeypatch.setattr("app.bot.handlers.route_message", route)
    msg = message(scope, "004291")
    msg.reply_to_message = SimpleNamespace(message_id=77)
    await handle_text_message(msg)
    route.assert_not_awaited()
    assert pending.response == "004291"
    assert not (await scope.memory.load(scope.user_id, scope.user_id)).messages


async def test_tasks_are_owner_scoped_and_stale_workers_are_not_reported_running(memory_setup):
    scope = memory_setup
    own = TaskRecord(user_id=scope.user_id, chat_id=42, prompt="Check Vercel")
    other = TaskRecord(user_id=scope.user_id + 1, chat_id=42, prompt="Other user's private task")
    async with async_session_factory() as session:
        await TaskRepository.save_task(session, own)
        await TaskRepository.save_task(session, other)
        await session.commit()
    context = await scope.memory.load(scope.user_id, 42)
    assert len(context.tasks) == 1
    assert context.tasks[0].state == "interrupted"
    running = MagicMock()
    running.done.return_value = False
    own.transition_to(TaskState.NEEDS_INPUT)
    own.metadata["companion_url"] = "https://secret-link?token=private"
    scope.registry.register(42, own, running, None)
    context = await scope.memory.load(scope.user_id, 42)
    assert context.tasks[0].state == "needs_input"
    assert "secret-link" not in context.model_dump_json()
    assert "Other user's" not in context.model_dump_json()


async def test_companion_outcome_contains_no_pairing_token(memory_setup, monkeypatch):
    scope = memory_setup
    monkeypatch.setattr("app.bot.handlers.route_message", AsyncMock(return_value=MessageDecision(route="companion")))
    msg = message(scope, "Open my Companion App")
    await handle_text_message(msg)
    button = msg.answer.call_args.kwargs["reply_markup"].inline_keyboard[0][0]
    url = button.url or button.web_app.url
    token = url.split("token=")[-1]
    context = await scope.memory.load(scope.user_id, scope.user_id)
    assert "delivered privately" in context.model_dump_json()
    assert token not in context.model_dump_json()


async def test_structured_provider_receives_context_and_resolves_request(monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "openai")
    context = ConversationContext(messages=[MemoryMessage(role="user", content="Check my deployments")])
    llm = SimpleNamespace(ainvoke=AsyncMock(return_value=SimpleNamespace(completion=MessageDecision(
        route="browser", browser_request="Check my Vercel deployments.",
    ))))
    with patch("app.bot.message_router.get_llm", return_value=llm):
        decision = await route_message("Vercel", context=context)
    messages = llm.ainvoke.call_args.args[0]
    assert "Check my deployments" in messages[1].content
    assert messages[-1].content == "Vercel"
    assert decision.browser_request == "Check my Vercel deployments."


@pytest.mark.parametrize("success", [True, False, None])
async def test_browser_outcomes_are_persisted_without_vault_secrets(memory_setup, monkeypatch, success):
    scope = memory_setup
    task = TaskRecord(user_id=scope.user_id, chat_id=scope.user_id, prompt="Check Vercel deployments")
    history = SimpleNamespace(
        is_successful=lambda: success,
        final_result=lambda: "deployment-a: failed; deployment-b: ready. vault-canary 004291",
    )
    agent = SimpleNamespace(run=AsyncMock(return_value=history))
    browser = SimpleNamespace(take_screenshot=AsyncMock(return_value=b"fake-png-data"))
    context = AsyncMock()
    context.__aenter__.return_value = browser
    bot = SimpleNamespace(send_message=AsyncMock(), send_photo=AsyncMock())
    monkeypatch.setattr("app.browser.runner.resolve_task_credentials", AsyncMock(return_value=(
        {"https://vercel.com": {"pass": "vault-canary", "otp": "004291"}}, [],
    )))
    with (
        patch("app.browser.runner.browser_session_context", return_value=context),
        patch("app.browser.runner.create_agent", return_value=agent),
    ):
        await run_browser_task(task, SimpleNamespace(update=AsyncMock()), bot)

    restored = ConversationMemory()
    memory = await restored.load(scope.user_id, scope.user_id)
    payload = memory.model_dump_json()
    assert "vault-canary" not in payload and "004291" not in payload
    assert memory.tasks[0].state == ("done" if success else "failed")
    if success:
        assert "deployment-a: failed" in payload
        assert "Result delivered" in payload
        assert "vault-canary" not in bot.send_message.call_args.kwargs["text"]

        async def followup(text, **kwargs):
            assert "deployment-a: failed" in kwargs["context"].model_dump_json()
            return MessageDecision(route="reply", reply="deployment-a failed.")

        monkeypatch.setattr("app.bot.handlers.conversation_memory", restored)
        monkeypatch.setattr("app.bot.handlers.route_message", followup)
        msg = message(scope, "Show only failed deployments")
        await handle_text_message(msg)
        msg.answer.assert_awaited_once_with("deployment-a failed.", parse_mode=None)
    else:
        assert "No successful result was confirmed" in payload
        assert "Result delivered" not in payload
        bot.send_message.assert_not_awaited()


async def test_cancelled_browser_records_failure_instead_of_success(memory_setup, monkeypatch):
    scope = memory_setup
    entered = asyncio.Event()
    task = TaskRecord(user_id=scope.user_id, chat_id=scope.user_id, prompt="Check deployments")

    async def run(**kwargs):
        entered.set()
        await asyncio.Event().wait()

    context = AsyncMock()
    monkeypatch.setattr("app.browser.runner.resolve_task_credentials", AsyncMock(return_value=({}, [])))
    with (
        patch("app.browser.runner.browser_session_context", return_value=context),
        patch("app.browser.runner.create_agent", return_value=SimpleNamespace(run=run)),
    ):
        running = asyncio.create_task(run_browser_task(task, SimpleNamespace(update=AsyncMock()), AsyncMock()))
        await entered.wait()
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running
    memory = await scope.memory.load(scope.user_id, scope.user_id)
    assert memory.tasks[0].state == "failed"
    assert "Result delivered" not in memory.model_dump_json()


async def test_cancelled_incoming_waiter_never_enters_history(memory_setup, monkeypatch):
    scope = memory_setup
    entered, release = asyncio.Event(), asyncio.Event()

    async def route(text, **kwargs):
        if text == "First":
            entered.set()
            await release.wait()
        return MessageDecision(route="reply", reply=f"{text} answer")

    monkeypatch.setattr("app.bot.handlers.route_message", route)
    first = asyncio.create_task(handle_text_message(message(scope, "First")))
    await entered.wait()
    cancelled = asyncio.create_task(handle_text_message(message(scope, "Cancelled message", 2)))
    await asyncio.sleep(0)
    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    last = asyncio.create_task(handle_text_message(message(scope, "Last", 3)))
    release.set()
    await asyncio.gather(first, last)
    context = await scope.memory.load(scope.user_id, scope.user_id)
    assert "Cancelled message" not in context.model_dump_json()
    assert "Last answer" in context.model_dump_json()
    assert incoming_messages.entries == {}


@pytest.mark.parametrize("args", [
    {"request": "Check Vercel", "user_id": 999}, {"request": ""},
    {"request": "x" * 4001}, {"request": 123},
])
def test_browser_resolution_cannot_supply_identity_or_invalid_requests(args):
    response = types.GenerateContentResponse(candidates=[types.Candidate(
        finish_reason="STOP", content=types.Content(role="model", parts=[types.Part(
            function_call=types.FunctionCall(name="start_browser_task", args=args),
        )]),
    )])
    with pytest.raises(ValueError):
        _parse_gemini_response(response)
