import asyncio
from html.parser import HTMLParser
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiogram import Bot
from aiogram.client.default import DefaultBotProperties
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter
from aiogram.methods import GetMe, SendChatAction, SendMessage, SendPhoto
from aiogram.types import Chat, ForceReply, Message, MessageEntity

from app.bot.delivery import MessageDeliveryMiddleware, split_message
from app.bot.setup import get_bot
from app.bot.status_manager import StatusManager
from app.config import settings
from app.tasks.state import TaskRecord, TaskState


class VisibleHTML(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.text = ""
        self.tags = []
        self.feed(text)
        assert not self.tags

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)

    def handle_endtag(self, tag):
        assert self.tags.pop() == tag

    def handle_data(self, text):
        self.text += text


@pytest.fixture
def bot():
    return Bot(token="123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi", default=DefaultBotProperties(parse_mode="HTML"))


@pytest.fixture
def fast_typing(monkeypatch):
    real_sleep = asyncio.sleep

    async def yield_once(delay):
        await real_sleep(0)

    sleep = AsyncMock(side_effect=yield_once)
    monkeypatch.setattr("app.bot.delivery.asyncio.sleep", sleep)
    return sleep


@pytest.mark.parametrize("text", [
    "A short reply.",
    "First thought.\n\nSecond thought.",
    "A useful sentence. Another useful sentence. " * 40,
    "line one\nline two\n" * 40,
    "界🙂" * 1000,
    "x" * 5000,
])
def test_plain_chunks_are_short_and_preserve_content(text):
    parts = split_message(text, 80)
    assert all(0 < len(part) <= 80 for part in parts)
    assert "".join("".join(parts).split()) == "".join(text.split())


def test_paragraphs_become_separate_bubbles_even_when_short():
    assert split_message("Hello!\n\nHow can I help?") == ["Hello!", "How can I help?"]


def test_nested_html_entities_and_links_survive_splitting():
    text = '<b>Hello <i>Tom &amp; Jo 🙂! ' + "Useful &lt;content&gt;. " * 60 + '</i></b><a href="https://example.com?a=1&amp;b=2">Read more</a>'
    parts = split_message(text, 80, is_html=True)
    visible = [VisibleHTML(part).text for part in parts]
    assert all(0 < len(part) <= 80 for part in visible)
    assert "".join("".join(visible).split()) == "".join(VisibleHTML(text).text.split())
    assert 'href="https://example.com?a=1&amp;b=2"' in parts[-1]


async def test_session_intercepts_message_answer_and_returns_last_prompt(bot, fast_typing):
    methods = []

    async def request(bot, method, **kwargs):
        methods.append(method)
        return SimpleNamespace(message_id=len(methods))

    bot.session.make_request = AsyncMock(side_effect=request)
    bot.session.middleware.register(MessageDeliveryMiddleware(max_chars=80))
    incoming = Message(message_id=1, date=1700000000, chat=Chat(id=42, type="private"), text="Hello").as_(bot)
    result = await incoming.answer("First paragraph.\n\nSecond paragraph.", reply_markup=ForceReply(), parse_mode=None)

    assert [type(method) for method in methods] == [SendChatAction, SendMessage, SendChatAction, SendMessage]
    assert all(method.action == "typing" for method in methods[::2])
    assert methods[1].reply_markup is None
    assert methods[3].reply_markup.force_reply
    assert methods[3].parse_mode is None
    assert result.message_id == 4
    assert all(1 <= call.args[0] <= 4 for call in fast_typing.await_args_list)


async def test_concurrent_batches_are_fifo_and_do_not_interleave(bot, fast_typing):
    middleware = MessageDeliveryMiddleware()
    entered, release = asyncio.Event(), asyncio.Event()
    sent = []

    async def request(bot, method):
        if isinstance(method, SendMessage):
            sent.append(method.text)
            if method.text == "First":
                entered.set()
                await release.wait()
        return SimpleNamespace(message_id=len(sent))

    first = asyncio.create_task(middleware(request, bot, SendMessage(chat_id=42, text="First\n\nSecond")))
    await entered.wait()
    second = asyncio.create_task(middleware(request, bot, SendMessage(chat_id=42, text="Third\n\nFourth")))
    third = asyncio.create_task(middleware(request, bot, SendMessage(chat_id=42, text="Fifth")))
    release.set()
    await asyncio.gather(first, second, third)
    assert sent == ["First", "Second", "Third", "Fourth", "Fifth"]
    assert middleware._queues == {}


async def test_other_chats_continue_while_one_is_waiting(bot, fast_typing):
    middleware = MessageDeliveryMiddleware()
    entered, release = asyncio.Event(), asyncio.Event()

    async def request(bot, method):
        if isinstance(method, SendMessage) and method.chat_id == 1:
            entered.set()
            await release.wait()
        return SimpleNamespace(message_id=1)

    first = asyncio.create_task(middleware(request, bot, SendMessage(chat_id=1, text="First")))
    await entered.wait()
    try:
        await asyncio.wait_for(middleware(request, bot, SendMessage(chat_id=2, text="Other chat")), 1)
        assert not first.done()
    finally:
        release.set()
        await first


async def test_cancelled_waiter_does_not_block_queue(bot, fast_typing):
    middleware = MessageDeliveryMiddleware()
    entered, release = asyncio.Event(), asyncio.Event()
    sent = []

    async def request(bot, method):
        if isinstance(method, SendMessage):
            sent.append(method.text)
            if method.text == "First":
                entered.set()
                await release.wait()
        return SimpleNamespace(message_id=1)

    first = asyncio.create_task(middleware(request, bot, SendMessage(chat_id=42, text="First")))
    await entered.wait()
    cancelled = asyncio.create_task(middleware(request, bot, SendMessage(chat_id=42, text="Cancelled")))
    await asyncio.sleep(0)
    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    last = asyncio.create_task(middleware(request, bot, SendMessage(chat_id=42, text="Last")))
    release.set()
    await asyncio.gather(first, last)
    assert sent == ["First", "Last"]
    assert middleware._queues == {}


async def test_rate_limit_retries_only_current_chunk_in_order(bot, fast_typing):
    middleware = MessageDeliveryMiddleware()
    sent, failed = [], False

    async def request(bot, method):
        nonlocal failed
        if isinstance(method, SendMessage):
            if method.text == "Second" and not failed:
                failed = True
                raise TelegramRetryAfter(method=method, message="Too many requests", retry_after=2)
            sent.append(method.text)
        return SimpleNamespace(message_id=len(sent))

    await middleware(request, bot, SendMessage(chat_id=42, text="First\n\nSecond\n\nThird"))
    assert sent == ["First", "Second", "Third"]
    assert any(call.args[0] == 2 for call in fast_typing.await_args_list)


async def test_typing_failure_does_not_drop_message(bot, fast_typing):
    middleware = MessageDeliveryMiddleware()
    sent = []

    async def request(bot, method):
        if isinstance(method, SendChatAction):
            raise TelegramBadRequest(method=method, message="Typing unavailable")
        sent.append(method.text)
        return SimpleNamespace(message_id=1)

    await middleware(request, bot, SendMessage(chat_id=42, text="Hello"))
    assert sent == ["Hello"]


async def test_photo_caption_is_short_and_full_result_is_preserved(bot, fast_typing):
    middleware = MessageDeliveryMiddleware(max_chars=80)
    requests = []

    async def request(bot, method):
        requests.append(method)
        return SimpleNamespace(message_id=len(requests))

    text = "Full result & <details>. " * 100
    result = await middleware(request, bot, SendPhoto(chat_id=42, photo="photo-id", caption=text, parse_mode=None))
    messages = [method for method in requests if isinstance(method, (SendPhoto, SendMessage))]
    parts = [method.caption if isinstance(method, SendPhoto) else method.text for method in messages]
    assert len(parts) > 1 and all(len(part) <= 80 for part in parts)
    assert "".join("".join(parts).split()) == "".join(text.split())
    assert result.message_id == 2


async def test_explicit_entities_survive_utf16_offsets(bot, fast_typing):
    middleware = MessageDeliveryMiddleware(max_chars=80)
    request = AsyncMock(return_value=SimpleNamespace(message_id=1))
    await middleware(request, bot, SendMessage(
        chat_id=42, text="🙂 " + "bold " * 40,
        entities=[MessageEntity(type="bold", offset=3, length=200)], parse_mode=None,
    ))
    parts = [call.args[1] for call in request.await_args_list if isinstance(call.args[1], SendMessage)]
    assert all(part.parse_mode == "HTML" and part.entities is None for part in parts)
    assert all(len(VisibleHTML(part.text).text) <= 80 for part in parts)
    assert "<b>" in parts[-1].text


async def test_non_delivery_api_calls_bypass_typing(bot, fast_typing):
    middleware = MessageDeliveryMiddleware()
    request = AsyncMock(return_value=True)
    method = GetMe()
    await middleware(request, bot, method)
    request.assert_awaited_once_with(bot, method)
    fast_typing.assert_not_awaited()


def test_bot_factory_registers_shared_delivery_middleware(monkeypatch):
    monkeypatch.setattr("app.bot.setup._bot", None)
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
    configured = get_bot()
    assert get_bot() is configured
    assert len(configured.session.middleware) == 1
    assert isinstance(configured.session.middleware[0], MessageDeliveryMiddleware)


async def test_normal_mode_hides_all_background_progress(monkeypatch):
    monkeypatch.setattr(settings, "TELEGRAM_DEBUG_STATUS", False)
    bot = AsyncMock()
    manager = StatusManager(bot)
    task = TaskRecord(user_id=1, chat_id=42, prompt="Sensitive task context")
    assert await manager.send_initial(task) is None
    for state in (TaskState.RUNNING, TaskState.VERIFYING, TaskState.DONE):
        task.state = state
        task.update_status("Internal reasoning and browser details")
        await manager.update(task, force=True)
    await manager.flush(task)
    assert task.message_id is None
    bot.send_message.assert_not_awaited()
    bot.edit_message_text.assert_not_awaited()


async def test_normal_mode_removes_used_credential_button_after_resume(monkeypatch):
    monkeypatch.setattr(settings, "TELEGRAM_DEBUG_STATUS", False)
    bot = AsyncMock()
    bot.send_message.return_value.message_id = 99
    manager = StatusManager(bot)
    task = TaskRecord(user_id=1, chat_id=42, prompt="Login")
    task.transition_to(TaskState.NEEDS_INPUT, status_message="INTERNAL DETAIL")
    task.metadata.update(target_domain="example.com", credential_type="password", companion_url="https://example.com/vault")
    await asyncio.gather(manager.update(task), manager.update(task))
    bot.send_message.assert_awaited_once()
    call = bot.send_message.call_args.kwargs
    assert "password" in call["text"] and "example.com" in call["text"]
    assert "INTERNAL DETAIL" not in call["text"]
    assert call["reply_markup"].inline_keyboard[0][0].web_app
    task.transition_to(TaskState.RUNNING)
    await manager.update(task)
    bot.edit_message_reply_markup.assert_awaited_once_with(chat_id=42, message_id=99, reply_markup=None)
    assert task.message_id is None


async def test_chat_input_does_not_create_redundant_status_prompt(monkeypatch):
    monkeypatch.setattr(settings, "TELEGRAM_DEBUG_STATUS", False)
    bot = AsyncMock()
    task = TaskRecord(user_id=1, chat_id=42, prompt="Login", state=TaskState.NEEDS_INPUT, metadata={"chat_input_field": "otp"})
    await StatusManager(bot).update(task, force=True)
    bot.send_message.assert_not_awaited()


async def test_debug_mode_removes_credential_button_when_request_ends(monkeypatch):
    monkeypatch.setattr(settings, "TELEGRAM_DEBUG_STATUS", True)
    bot = AsyncMock()
    manager = StatusManager(bot)
    task = TaskRecord(user_id=1, chat_id=1, prompt="Login", message_id=42, state=TaskState.NEEDS_INPUT)
    task.metadata.update(target_domain="example.com", credential_type="password", companion_url="https://wilco.example/vault/link?token=one-time")
    await manager.update(task)
    button = bot.edit_message_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0]
    assert button.web_app.url == task.metadata["companion_url"]
    task.transition_to(TaskState.RUNNING)
    await manager.update(task, force=True)
    assert bot.edit_message_text.call_args.kwargs["reply_markup"] is None
    bot.send_message.assert_not_awaited()
    bot.edit_message_reply_markup.assert_not_awaited()


@pytest.mark.parametrize("error,expected", [
    ("Connection failure with private browser details", "couldn't complete"),
    ("No reply: timed out", "timed out"),
    ("Cancelled by user via /cancel", None),
])
async def test_normal_mode_reports_failure_once_without_internal_details(monkeypatch, error, expected):
    monkeypatch.setattr(settings, "TELEGRAM_DEBUG_STATUS", False)
    bot = AsyncMock()
    manager = StatusManager(bot)
    task = TaskRecord(user_id=1, chat_id=42, prompt="Task")
    task.transition_to(TaskState.FAILED, error=error)
    await manager.update(task)
    await manager.flush(task)
    if expected is None:
        bot.send_message.assert_not_awaited()
    else:
        bot.send_message.assert_awaited_once()
        assert expected in bot.send_message.call_args.kwargs["text"]
        assert "private browser details" not in bot.send_message.call_args.kwargs["text"]
