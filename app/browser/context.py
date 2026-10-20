import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
from browser_use import Browser
from app.config import settings

logger = logging.getLogger(__name__)


def get_browser_cdp_url() -> Optional[str]:
    """
    Constructs a CDP WebSocket URL if Browserbase cloud provider is configured.
    """
    if settings.BROWSER_TYPE == "browserbase" and settings.BROWSERBASE_API_KEY:
        url = f"wss://connect.browserbase.com?apiKey={settings.BROWSERBASE_API_KEY}"
        if settings.BROWSERBASE_PROJECT_ID:
            url += f"&projectId={settings.BROWSERBASE_PROJECT_ID}"
        return url
    return None


def create_browser(
    headless: Optional[bool] = None,
    cdp_url: Optional[str] = None,
    keep_alive: bool = True,
) -> Browser:
    """
    Instantiates a configured BrowserSession.
    Supports local Chromium or remote CDP (Browserbase).
    
    Sets keep_alive=True so that agent.run() does not prematurely kill
    the browser session and CDP client before verification and screenshots.
    """
    is_headless = headless if headless is not None else settings.BROWSER_HEADLESS
    remote_cdp = cdp_url or get_browser_cdp_url()

    if remote_cdp:
        logger.info("Initializing Browser via remote CDP endpoint (keep_alive=%s)", keep_alive)
        return Browser(cdp_url=remote_cdp, keep_alive=keep_alive)

    logger.info("Initializing local Browser (headless=%s, keep_alive=%s)", is_headless, keep_alive)
    return Browser(
        headless=is_headless,
        is_local=True,
        keep_alive=keep_alive,
    )


@asynccontextmanager
async def browser_session_context(
    browser: Optional[Browser] = None,
    headless: Optional[bool] = None,
) -> AsyncGenerator[Browser, None]:
    """
    Async context manager managing the lifecycle (start and stop) of a Browser session.
    """
    session = browser or create_browser(headless=headless)
    logger.info("Starting browser session...")
    await session.start()
    try:
        yield session
    finally:
        logger.info("Stopping browser session...")
        try:
            await session.stop()
        except Exception as e:
            logger.warning("Error occurred while stopping browser session: %s", e)

