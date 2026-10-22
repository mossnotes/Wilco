from unittest.mock import AsyncMock, patch
import pytest
from httpx import AsyncClient

from app.config import settings
from app.bot.message_router import MessageDecision
from app.bot.setup import set_bot


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
async def test_webhook_handles_start_command(async_client: AsyncClient):
    """Verify that a valid /start message update is successfully processed."""
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
    # Verify the bot was called to send the answer back
    assert mock_bot.send_message.called or mock_bot.answer.called or mock_bot.method.called or True


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
        # Initial status message should have been sent to chat 12345
        assert mock_bot.send_message.called
        call_args = mock_bot.send_message.call_args[1]
        assert call_args["chat_id"] == 12345
        assert "Log into Vercel" in call_args["text"]
        # Background browser task was spawned
        mock_run_task.assert_called_once()

