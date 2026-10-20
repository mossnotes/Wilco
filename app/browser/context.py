import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, Optional, Union
import uuid

from browser_use import Browser

from app.config import settings
from app.db.engine import async_session_factory
from app.db.repository import BrowserProfileRepository

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
    storage_state: Optional[Union[Dict[str, Any], str]] = None,
) -> Browser:
    """
    Instantiates a configured BrowserSession.
    Supports local Chromium or remote CDP (Browserbase), and optional persistent session state.
    
    Sets keep_alive=True so that agent.run() does not prematurely kill
    the browser session and CDP client before verification and screenshots.
    """
    is_headless = headless if headless is not None else settings.BROWSER_HEADLESS
    remote_cdp = cdp_url or get_browser_cdp_url()

    browser_kwargs: dict[str, Any] = {
        "keep_alive": keep_alive,
    }

    if storage_state is not None:
        browser_kwargs["storage_state"] = storage_state

    if remote_cdp:
        logger.info("Initializing Browser via remote CDP endpoint (keep_alive=%s)", keep_alive)
        return Browser(cdp_url=remote_cdp, **browser_kwargs)

    logger.info("Initializing local Browser (headless=%s, keep_alive=%s)", is_headless, keep_alive)
    return Browser(
        headless=is_headless,
        is_local=True,
        **browser_kwargs,
    )


@asynccontextmanager
async def browser_session_context(
    browser: Optional[Browser] = None,
    headless: Optional[bool] = None,
    storage_state: Optional[Union[Dict[str, Any], str]] = None,
    user_id: Optional[uuid.UUID] = None,
    site_domain: Optional[str] = None,
) -> AsyncGenerator[Browser, None]:
    """
    Async context manager managing the lifecycle (start and stop) of a Browser session.
    Automatically loads stored profile cookies/localStorage on start, and exports
    updated session state to the database on completion.
    """
    active_storage_state = storage_state

    # Auto-load saved profile if user_id and site_domain are provided
    if active_storage_state is None and user_id and site_domain:
        try:
            async with async_session_factory() as db:
                profile = await BrowserProfileRepository.get_profile(db, user_id, site_domain)
                if profile and profile.storage_state_json:
                    active_storage_state = json.loads(profile.storage_state_json)
                    logger.info("Restoring persistent session profile for %s (user %s)", site_domain, user_id)
        except Exception as exc:
            logger.warning("Failed to restore browser profile for %s: %exc", site_domain, exc)

    session = browser or create_browser(headless=headless, storage_state=active_storage_state)
    logger.info("Starting browser session...")
    await session.start()
    try:
        yield session
    finally:
        # Auto-export updated profile cookies on shutdown
        if user_id and site_domain:
            try:
                exported = await session.export_storage_state()
                if exported and (exported.get("cookies") or exported.get("origins")):
                    async with async_session_factory() as db:
                        await BrowserProfileRepository.save_profile(
                            db,
                            user_id=user_id,
                            site_domain=site_domain,
                            storage_state_json=json.dumps(exported),
                        )
                        await db.commit()
                        logger.info("Saved updated browser session profile for %s", site_domain)
            except Exception as exc:
                logger.debug("Failed to auto-export browser profile for %s: %s", site_domain, exc)

        logger.info("Stopping browser session...")
        try:
            await session.stop()
        except Exception as e:
            logger.warning("Error occurred while stopping browser session: %s", e)
