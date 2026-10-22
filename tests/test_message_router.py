import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError

from app.bot.message_router import MessageDecision, route_message
from app.config import settings


@pytest.fixture(autouse=True)
def use_structured_provider(monkeypatch):
    """These tests cover the non-Gemini compatibility path."""
    monkeypatch.setattr(settings, "LLM_PROVIDER", "openai")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text, decision",
    [
        ("Hello", MessageDecision(route="reply", reply="Hello!")),
        ("Check my deployments", MessageDecision(route="browser", reply="")),
    ],
)
async def test_router_uses_configured_llm_with_structured_output(text, decision):
    llm = SimpleNamespace(ainvoke=AsyncMock(return_value=SimpleNamespace(completion=decision)))
    with patch("app.bot.message_router.get_llm", return_value=llm) as factory:
        result = await route_message(text)

    assert result == decision
    factory.assert_called_once_with()
    llm.ainvoke.assert_awaited_once()
    messages = llm.ainvoke.call_args.args[0]
    assert [message.role for message in messages] == ["system", "user"]
    assert messages[1].content == text
    assert llm.ainvoke.call_args.kwargs["output_format"] is MessageDecision


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "completion",
    [
        {"route": "unknown", "reply": "Hello"},
        {"route": "reply", "reply": "   "},
        {"route": "reply", "reply": "x" * 4001},
    ],
)
async def test_router_rejects_invalid_decisions(completion):
    llm = SimpleNamespace(ainvoke=AsyncMock(return_value=SimpleNamespace(completion=completion)))
    with patch("app.bot.message_router.get_llm", return_value=llm):
        with pytest.raises(ValidationError):
            await route_message("Hello")


@pytest.mark.asyncio
async def test_router_bounds_model_wait_time(monkeypatch):
    async def stalled_model(*args, **kwargs):
        await asyncio.Event().wait()

    llm = SimpleNamespace(ainvoke=AsyncMock(side_effect=stalled_model))
    monkeypatch.setattr(settings, "ROUTING_TIMEOUT_SECONDS", 0.01)
    with patch("app.bot.message_router.get_llm", return_value=llm):
        with pytest.raises(TimeoutError):
            await route_message("Hello")


@pytest.mark.asyncio
async def test_router_honors_configured_deadline(monkeypatch):
    async def delayed_model(*args, **kwargs):
        await asyncio.sleep(0.03)
        return SimpleNamespace(completion=MessageDecision(route="reply", reply="Hello!"))

    llm = SimpleNamespace(ainvoke=AsyncMock(side_effect=delayed_model))
    with patch("app.bot.message_router.get_llm", return_value=llm):
        monkeypatch.setattr(settings, "ROUTING_TIMEOUT_SECONDS", 0.01)
        with pytest.raises(TimeoutError):
            await route_message("Hello")
        monkeypatch.setattr(settings, "ROUTING_TIMEOUT_SECONDS", 1)
        result = await route_message("Hello")

    assert result.reply == "Hello!"
