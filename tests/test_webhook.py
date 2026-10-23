import asyncio
from unittest.mock import AsyncMock, patch
import pytest
from httpx import AsyncClient

from app.config import settings
from app.bot.message_router import MessageDecision
from app.bot.setup import set_bot
from app.tasks.registry import task_registry


@pytest.fixture(autouse=True)
def mock_message_router():
    """Keep webhook tests independent of external model calls."""
    with patch(
        "app.bot.handlers.route_message",
        new_callable=AsyncMock,
        return_value=MessageDecision(route="browser", reply=""),
    ) as mock_route:
        yield mock_route


@pytest.fixture(autouse=True)
def mock_run_browser_task():
    """Prevent webhook tests from spawning real browser-use runs."""
    with patch("app.bot.handlers.run_browser_task", new_callable=AsyncMock) as mock_task:
        yield mock_task


@pytest.mark.asyncio
async def test_webhook_unconfigured_bot_returns_503(async_client: AsyncClient):
    """When bot is not initialized, webhook returns 503."""
    set_bot(None)
    response = await async_client.post(
        settings.WEBHOOK_PATH,
        json={"update_id": 1000},
    )
    assert response.status_code == 503
    assert "Telegram bot is not initialized" in response.json()["detail"]


@pytest.mark.asyncio
async def test_webhook_secret_token_verification(async_client: AsyncClient, monkeypatch):
    """When TELEGRAM_WEBHOOK_SECRET is set, requests must include matching header."""
    mock_bot = AsyncMock()
    set_bot(mock_bot)

    monkeypatch.setattr(settings, "TELEGRAM_WEBHOOK_SECRET", "super_secret_token_123")

    # 1. Missing header -> 403 Forbidden
    res_no_header = await async_client.post(
        settings.WEBHOOK_PATH,
        json={"update_id": 1001},
    )
    assert res_no_header.status_code == 403

    # 2. Invalid header -> 403 Forbidden
    res_bad_header = await async_client.post(
        settings.WEBHOOK_PATH,
        headers={"X-Telegram-Bot-Api-Secret-Token": "wrong_secret"},
        json={"update_id": 1001},
    )
    assert res_bad_header.status_code == 403

    # 3. Valid header -> 200 OK
    res_valid = await async_client.post(
        settings.WEBHOOK_PATH,
        headers={"X-Telegram-Bot-Api-Secret-Token": "super_secret_token_123"},
        json={
            "update_id": 1001,
            "message": {
                "message_id": 1,
                "date": 1700000000,
                "chat": {"id": 12345, "type": "private"},
                "from": {"id": 12345, "is_bot": False, "first_name": "Alice"},
                "text": "ping",
            },
        },
    )
    assert res_valid.status_code == 200
    assert res_valid.json() == {"ok": True}


@pytest.mark.asyncio
async def test_webhook_malformed_payload(async_client: AsyncClient):
    """Invalid update structure returns 400 Bad Request."""
    mock_bot = AsyncMock()
    set_bot(mock_bot)

    response = await async_client.post(
        settings.WEBHOOK_PATH,
        content="not valid json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_webhook_routes_legacy_start_through_llm(async_client: AsyncClient, mock_message_router):
    """Telegram's Start text has no privileged handler and uses the main router."""
    mock_message_router.return_value = MessageDecision(route="reply", reply="Hello!")
    mock_bot = AsyncMock()
    set_bot(mock_bot)

    update_payload = {
        "update_id": 1002,
        "message": {
            "message_id": 1,
            "date": 1700000000,
            "chat": {"id": 12345, "type": "private"},
            "from": {"id": 12345, "is_bot": False, "first_name": "Alice"},
            "text": "/start",
        },
    }

    response = await async_client.post(
        settings.WEBHOOK_PATH,
        json=update_payload,
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    mock_message_router.assert_awaited_once_with("/start", request_id="telegram:12345:1")


@pytest.mark.asyncio
async def test_webhook_handles_task_text_prompt(async_client: AsyncClient):
    """Verify that a plain text task prompt is received and triggers status initialization."""
    mock_bot = AsyncMock()
    mock_sent_msg = AsyncMock()
    mock_sent_msg.message_id = 555
    mock_bot.send_message.return_value = mock_sent_msg
    set_bot(mock_bot)

    update_payload = {
        "update_id": 1003,
        "message": {
            "message_id": 2,
            "date": 1700000000,
            "chat": {"id": 12345, "type": "private"},
            "from": {"id": 12345, "is_bot": False, "first_name": "Alice"},
            "text": "Log into Vercel and check deployment",
        },
    }

    with patch("app.bot.handlers.run_browser_task", new_callable=AsyncMock) as mock_run_task:
        response = await async_client.post(
            settings.WEBHOOK_PATH,
            json=update_payload,
        )
        assert response.status_code == 200
        assert response.json() == {"ok": True}
        # Internal progress stays hidden in normal operation.
        mock_bot.send_message.assert_not_called()
        # The registered worker acknowledges the source message before browsing.
        active = task_registry.get_by_chat(12345)
        assert active is not None
        await asyncio.wait_for(active[1], 1)
        mock_run_task.assert_awaited_once()
        reaction_calls = mock_bot.set_message_reaction.await_args_list
        assert len(reaction_calls) == 2
        assert reaction_calls[0].kwargs["chat_id"] == 12345
        assert reaction_calls[0].kwargs["message_id"] == 2
        assert reaction_calls[0].kwargs["reaction"][0].emoji == "👀"
        assert reaction_calls[1].kwargs["reaction"] == []

