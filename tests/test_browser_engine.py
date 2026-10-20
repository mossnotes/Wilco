import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.config import settings
from app.browser.context import (
    create_browser,
    get_browser_cdp_url,
    browser_session_context,
)


def test_browser_config_defaults():
    assert settings.BROWSER_TYPE in ("local", "browserbase")
    assert isinstance(settings.BROWSER_HEADLESS, bool)


def test_get_browser_cdp_url_when_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "BROWSER_TYPE", "local")
    monkeypatch.setattr(settings, "BROWSERBASE_API_KEY", "")
    assert get_browser_cdp_url() is None


def test_get_browser_cdp_url_when_browserbase_configured(monkeypatch):
    monkeypatch.setattr(settings, "BROWSER_TYPE", "browserbase")
    monkeypatch.setattr(settings, "BROWSERBASE_API_KEY", "test-key-123")
    monkeypatch.setattr(settings, "BROWSERBASE_PROJECT_ID", "test-proj-456")
    url = get_browser_cdp_url()
    assert url == "wss://connect.browserbase.com?apiKey=test-key-123&projectId=test-proj-456"


def test_create_browser_local(monkeypatch):
    monkeypatch.setattr(settings, "BROWSER_TYPE", "local")
    monkeypatch.setattr(settings, "BROWSER_HEADLESS", True)
    
    with patch("app.browser.context.Browser") as mock_browser_cls:
        create_browser()
        mock_browser_cls.assert_called_once_with(
            headless=True,
            is_local=True,
        )


def test_create_browser_browserbase(monkeypatch):
    monkeypatch.setattr(settings, "BROWSER_TYPE", "browserbase")
    monkeypatch.setattr(settings, "BROWSERBASE_API_KEY", "bb-key")
    monkeypatch.setattr(settings, "BROWSERBASE_PROJECT_ID", "")
    
    with patch("app.browser.context.Browser") as mock_browser_cls:
        create_browser()
        mock_browser_cls.assert_called_once_with(
            cdp_url="wss://connect.browserbase.com?apiKey=bb-key"
        )


@pytest.mark.asyncio
async def test_browser_session_context():
    mock_browser = MagicMock()
    mock_browser.start = AsyncMock()
    mock_browser.stop = AsyncMock()

    async with browser_session_context(browser=mock_browser) as session:
        assert session == mock_browser
        mock_browser.start.assert_awaited_once()
        mock_browser.stop.assert_not_awaited()

    mock_browser.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_browser_session_context_cleanup_on_error():
    mock_browser = MagicMock()
    mock_browser.start = AsyncMock()
    mock_browser.stop = AsyncMock()

    with pytest.raises(RuntimeError, match="Boom"):
        async with browser_session_context(browser=mock_browser):
            raise RuntimeError("Boom")

    mock_browser.start.assert_awaited_once()
    mock_browser.stop.assert_awaited_once()

