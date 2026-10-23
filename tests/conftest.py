import pytest
import hashlib
import hmac
import json
import time
from urllib.parse import urlencode
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings


@pytest.fixture
def telegram_identity(monkeypatch):
    """Sign synthetic Telegram payloads using a test-only bot token."""
    token = "123456:synthetic-test-bot-token"
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", token)

    def sign(telegram_id=123456, *, auth_date=None, **extra):
        values = {
            "auth_date": str(int(time.time()) if auth_date is None else auth_date),
            "user": json.dumps({"id": telegram_id, "first_name": "Test"}, separators=(",", ":")),
            **extra,
        }
        secret = hmac.digest(b"WebAppData", token.encode(), hashlib.sha256)
        check = "\n".join(f"{key}={value}" for key, value in sorted(values.items()))
        values["hash"] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        return urlencode(values)
    return sign


@pytest.fixture(autouse=True)
def reset_settings(monkeypatch):
    """Ensure clean settings for each test."""
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(settings, "TELEGRAM_WEBHOOK_SECRET", "")
    monkeypatch.setattr(settings, "BOT_MODE", "webhook")
    monkeypatch.setattr(settings, "TELEGRAM_DEBUG_STATUS", False)
    # Existing unit tests remain independent of persistent chat context. Memory
    # integration tests enable it explicitly with isolated users/databases.
    monkeypatch.setattr(settings, "CONVERSATION_MEMORY_ENABLED", False)
    monkeypatch.setattr(settings, "LLM_PROVIDER", "gemini")
    monkeypatch.setattr(settings, "LLM_MODEL", "gemini-3.8-flash")
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")
    monkeypatch.setattr(settings, "GOOGLE_API_KEY", "")
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "")
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
    monkeypatch.setattr(settings, "BROWSER_TYPE", "local")
    monkeypatch.setattr(settings, "BROWSER_HEADLESS", True)
    monkeypatch.setattr(settings, "BROWSERBASE_API_KEY", "")
    monkeypatch.setattr(settings, "BROWSERBASE_PROJECT_ID", "")
    # Default 32-byte Base64 key for testing
    monkeypatch.setattr(settings, "VAULT_MASTER_KEY", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Async test client for testing FastAPI endpoints."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
