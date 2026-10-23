import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError
from aiogram.methods import SetMessageReaction

from app.bot.acknowledgement import browser_task_acknowledgement
from app.bot.handlers import handle_text_message
from app.bot.message_router import MessageDecision
from app.db.engine import init_db
from app.tasks.registry import ActiveTaskRegistry
from app.tasks.state import TaskState


def request_message():
    return SimpleNamespace(
        message_id=42, text="Check my Wikimedia account",
        chat=SimpleNamespace(id=123, type="private"),
        from_user=SimpleNamespace(id=123), reply_to_message=None,
        answer=AsyncMock(), delete=AsyncMock(),
        bot=SimpleNamespace(set_message_reaction=AsyncMock(return_value=True)),
    )


def reactions(message):
    return [call.kwargs["reaction"] for call in message.bot.set_message_reaction.await_args_list]


async def test_reaction_stays_until_work_finishes_without_sending_another_message():
    message = request_message()
    async with browser_task_acknowledgement(message):
        assert len(reactions(message)) == 1
        assert reactions(message)[0][0].emoji == "👀"
        message.answer.assert_not_awaited()
    assert reactions(message)[1] == []
    for call in message.bot.set_message_reaction.await_args_list:
        assert call.kwargs["chat_id"] == 123
        assert call.kwargs["message_id"] == 42
        assert call.kwargs["is_big"] is False


@pytest.mark.parametrize("error", [
    TelegramBadRequest(method=SetMessageReaction(chat_id=123, message_id=42), message="REACTION_INVALID"),
    TelegramForbiddenError(method=SetMessageReaction(chat_id=123, message_id=42), message="Forbidden"),
    TimeoutError(),
])
async def test_failed_reaction_falls_back_to_on_it_and_work_still_runs(error):
    message = request_message()
    message.bot.set_message_reaction.side_effect = [error, True]
    work = AsyncMock()
    async with browser_task_acknowledgement(message):
        await work()
    message.answer.assert_awaited_once_with("On it.", parse_mode=None)
    work.assert_awaited_once()
    assert reactions(message)[-1] == []


async def test_failed_reaction_and_fallback_cannot_prevent_work_or_leak_error_details(caplog):
    message = request_message()
    message.bot.set_message_reaction.side_effect = RuntimeError("private-error-canary")
    message.answer.side_effect = RuntimeError("private-error-canary")
    work = AsyncMock()
    async with browser_task_acknowledgement(message):
        await work()
    work.assert_awaited_once()
    assert "private-error-canary" not in caplog.text


async def test_work_failure_clears_reaction_and_preserves_the_error():
    message = request_message()
    with pytest.raises(RuntimeError, match="worker failed"):
        async with browser_task_acknowledgement(message):
            raise RuntimeError("worker failed")
    assert reactions(message)[-1] == []


async def test_cleanup_failure_does_not_mask_work_failure():
    message = request_message()
    message.bot.set_message_reaction.side_effect = [True, RuntimeError("reaction cleanup failed")]
    with pytest.raises(RuntimeError, match="worker failed"):
        async with browser_task_acknowledgement(message):
            raise RuntimeError("worker failed")


@pytest.mark.parametrize("cancel_during", ["reaction", "fallback", "work"])
async def test_cancellation_clears_reaction_and_still_propagates(cancel_during):
    message = request_message()
    entered = asyncio.Event()

    async def wait():
        entered.set()
        await asyncio.Event().wait()

    async def set_reaction(**kwargs):
        if kwargs["reaction"]:
            if cancel_during == "reaction":
                await wait()
            elif cancel_during == "fallback":
                raise RuntimeError("reactions disabled")
        return True

    async def fallback(*args, **kwargs):
        await wait()

    message.bot.set_message_reaction.side_effect = set_reaction
    message.answer.side_effect = fallback

    async def run():
        async with browser_task_acknowledgement(message):
            await wait()

    worker = asyncio.create_task(run())
    try:
        await asyncio.wait_for(entered.wait(), 1)
        worker.cancel()
        with pytest.raises(asyncio.CancelledError):
            await worker
        assert reactions(message)[-1] == []
    finally:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)


async def test_slow_reaction_times_out_and_falls_back_before_starting_work(monkeypatch):
    monkeypatch.setattr("app.bot.acknowledgement.ACKNOWLEDGEMENT_TIMEOUT_SECONDS", 0.01)
    message = request_message()

    async def set_reaction(**kwargs):
        if kwargs["reaction"]:
            await asyncio.Event().wait()
        return True

    message.bot.set_message_reaction.side_effect = set_reaction
    async with browser_task_acknowledgement(message):
        message.answer.assert_awaited_once_with("On it.", parse_mode=None)
    assert reactions(message)[-1] == []


async def test_handler_acknowledges_only_registered_work_and_keeps_reaction_while_paused(monkeypatch):
    await init_db()
    message = request_message()
    registry = ActiveTaskRegistry()
    monkeypatch.setattr("app.bot.handlers.task_registry", registry)
    monkeypatch.setattr("app.bot.handlers.route_message", AsyncMock(return_value=MessageDecision(route="browser")))
    started = asyncio.Event()

    async def set_reaction(**kwargs):
        if kwargs["reaction"]:
            assert registry.get_by_chat(message.chat.id) is not None
        return True

    async def run_browser(task, status_manager, bot):
        task.transition_to(TaskState.NEEDS_INPUT)
        started.set()
        await asyncio.Event().wait()

    message.bot.set_message_reaction.side_effect = set_reaction
    monkeypatch.setattr("app.bot.handlers.run_browser_task", run_browser)
    await handle_text_message(message)
    entry = registry.get_by_chat(message.chat.id)
    assert entry is not None
    try:
        await asyncio.wait_for(started.wait(), 1)
        assert len(reactions(message)) == 1
        assert await registry.cancel_task_by_chat(message.chat.id, user_id=message.from_user.id)
        await asyncio.gather(entry[1], return_exceptions=True)
        assert reactions(message)[-1] == []
        message.answer.assert_not_awaited()
    finally:
        entry[1].cancel()
        await asyncio.gather(entry[1], return_exceptions=True)
