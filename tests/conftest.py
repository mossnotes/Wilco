import pytest
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings


@pytest.fixture(autouse=True)
def reset_settings(monkeypatch):
    """Ensure clean settings for each test."""
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(settings, "TELEGRAM_WEBHOOK_SECRET", "")
    monkeypatch.setattr(settings, "BOT_MODE", "webhook")
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
