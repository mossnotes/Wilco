import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from google.genai import errors, types

from app.bot import message_router
from app.config import settings


def response_with(*parts, finish_reason="STOP"):
    return types.GenerateContentResponse(
        candidates=[types.Candidate(
            content=types.Content(role="model", parts=list(parts)),
            finish_reason=finish_reason,
        )],
        usage_metadata=types.GenerateContentResponseUsageMetadata(
            prompt_token_count=100, candidates_token_count=10, total_token_count=110,
        ),
    )


def browser_call(**kwargs):
    return types.Part(function_call=types.FunctionCall(name="start_browser_task", **kwargs))


@pytest.fixture
def gemini_client(monkeypatch):
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "api-key-canary")
    client = SimpleNamespace(models=SimpleNamespace(generate_content=AsyncMock()))
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    context.__aexit__ = AsyncMock(return_value=False)
    factory = MagicMock(return_value=SimpleNamespace(aio=context))
    monkeypatch.setattr(message_router.genai, "Client", factory)
    return SimpleNamespace(client=client, context=context, factory=factory)


@pytest.mark.asyncio
async def test_native_text_reply_and_request_contract(gemini_client):
    generate = gemini_client.client.models.generate_content
    generate.return_value = response_with(types.Part(text="Hello!"))
    decision = await message_router.route_message("Hello")

    assert decision.route == "reply"
    assert decision.reply == "Hello!"
    kwargs = generate.call_args.kwargs
    assert kwargs["model"] == settings.LLM_MODEL
    assert kwargs["contents"][0].role == "user"
    assert kwargs["contents"][0].parts[0].text == "Hello"
    config = kwargs["config"]
    assert config.tool_config.function_calling_config.mode == "AUTO"
    assert config.automatic_function_calling.disable is True
    assert config.response_schema is None
    assert config.response_mime_type is None
    assert config.tools[0].function_declarations[0].name == "start_browser_task"
    assert "no arguments" in config.tools[0].function_declarations[0].description
    options = gemini_client.factory.call_args.kwargs["http_options"]
    assert options.timeout == int(settings.ROUTING_TIMEOUT_SECONDS * 1000)
    assert options.retry_options.attempts == 2
    gemini_client.context.__aexit__.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("args", [None, {}])
async def test_native_browser_call_is_a_handoff(gemini_client, args):
    gemini_client.client.models.generate_content.return_value = response_with(
        types.Part(text="I will check."), browser_call(args=args),
    )
    decision = await message_router.route_message("Check my Vercel deployments")
    assert decision.route == "browser"
    assert decision.reply == ""  # Browser runner owns progress and result delivery.


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [
    response_with(types.Part(function_call=types.FunctionCall(name="unknown_tool", args={}))),
    response_with(browser_call(args={"user_id": 999})),
    response_with(browser_call(args={"prompt": "different task"})),
    response_with(browser_call(), browser_call()),
    response_with(browser_call(), finish_reason="MAX_TOKENS"),
    response_with(finish_reason="SAFETY"),
    types.GenerateContentResponse(),
    response_with(types.Part(text="   ")),
    response_with(types.Part(text="x" * 4001)),
    types.GenerateContentResponse(candidates=[types.Candidate(), types.Candidate()]),
])
async def test_rejects_invalid_or_incomplete_responses(gemini_client, response):
    gemini_client.client.models.generate_content.return_value = response
    with pytest.raises(ValueError):
        await message_router.route_message("Hello")
    gemini_client.context.__aexit__.assert_awaited_once()


@pytest.mark.asyncio
async def test_thought_text_is_not_delivered(gemini_client):
    gemini_client.client.models.generate_content.return_value = response_with(
        types.Part(text="internal reasoning", thought=True),
        types.Part(text="Hello!"),
    )
    decision = await message_router.route_message("Hello")
    assert decision.reply == "Hello!"


@pytest.mark.asyncio
async def test_timeout_closes_client(gemini_client, monkeypatch):
    async def stalled_request(**kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(settings, "ROUTING_TIMEOUT_SECONDS", 0.01)
    gemini_client.client.models.generate_content.side_effect = stalled_request
    with pytest.raises(TimeoutError):
        await message_router.route_message("Hello")
    gemini_client.context.__aexit__.assert_awaited_once()


@pytest.mark.asyncio
async def test_missing_key_does_not_open_client(gemini_client, monkeypatch):
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")
    monkeypatch.setattr(settings, "GOOGLE_API_KEY", "")
    with pytest.raises(ValueError, match="API key is missing"):
        await message_router.route_message("Hello")
    gemini_client.factory.assert_not_called()


@pytest.mark.asyncio
async def test_debug_logs_show_request_response_and_trace_metadata(gemini_client, caplog):
    caplog.set_level(logging.DEBUG, logger="app.bot.message_router")
    gemini_client.client.models.generate_content.return_value = response_with(
        types.Part(text="private-reply-canary"),
    )
    await message_router.route_message("private-request-canary", request_id="trace-test")
    assert "Routing[trace-test] started" in caplog.text
    assert "mode=AUTO" in caplog.text
    assert "total_tokens=110" in caplog.text
    assert "completed route=reply" in caplog.text
    assert "request_json=" in caplog.text
    assert "response_json=" in caplog.text
    assert "private-request-canary" in caplog.text
    assert "private-reply-canary" in caplog.text
    assert "api-key-canary" not in caplog.text


@pytest.mark.asyncio
async def test_provider_error_closes_client_and_logs_only_metadata(gemini_client, caplog):
    caplog.set_level(logging.DEBUG, logger="app.bot.message_router")
    error = RuntimeError("api-key-canary private-request-canary")
    error.code = 503
    gemini_client.client.models.generate_content.side_effect = error
    with pytest.raises(RuntimeError):
        await message_router.route_message("private-request-canary", request_id="trace-error")
    gemini_client.context.__aexit__.assert_awaited_once()
    assert "error_type=RuntimeError provider_status=503" in caplog.text
    assert "api-key-canary" not in caplog.text
    assert "private-request-canary" in caplog.text  # The explicit request body is logged.


@pytest.mark.asyncio
async def test_payload_logs_redact_credentials_in_text_and_fields(gemini_client, caplog):
    caplog.set_level(logging.DEBUG, logger="app.bot.message_router")
    gemini_client.client.models.generate_content.return_value = response_with(
        browser_call(args={"password": "hidden-password", "api_key": "unknown-api-key"}),
        types.Part(text="api-key-canary password: hidden-text-password"),
    )
    with pytest.raises(ValueError):
        await message_router.route_message("hello api-key-canary")
    for secret in ["api-key-canary", "hidden-password", "unknown-api-key", "hidden-text-password"]:
        assert secret not in caplog.text
    assert "[REDACTED_SECRET]" in caplog.text


@pytest.mark.asyncio
async def test_api_error_response_body_is_logged_with_redaction(gemini_client, caplog):
    caplog.set_level(logging.DEBUG, logger="app.bot.message_router")
    gemini_client.client.models.generate_content.side_effect = errors.ClientError(
        400, {"error": {"message": "Invalid api-key-canary", "status": "INVALID_ARGUMENT"}},
    )
    with pytest.raises(errors.ClientError):
        await message_router.route_message("Hello")
    assert "error_response_json=" in caplog.text
    assert "INVALID_ARGUMENT" in caplog.text
    assert "api-key-canary" not in caplog.text


@pytest.mark.asyncio
async def test_info_logs_omit_payload_bodies(gemini_client, caplog):
    caplog.set_level(logging.INFO, logger="app.bot.message_router")
    gemini_client.client.models.generate_content.return_value = response_with(
        types.Part(text="private-reply-canary"),
    )
    await message_router.route_message("private-request-canary")
    assert "request_json=" not in caplog.text
    assert "response_json=" not in caplog.text
    assert "private-request-canary" not in caplog.text
    assert "private-reply-canary" not in caplog.text
