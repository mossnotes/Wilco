import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, List, Optional, Union
from urllib.parse import urlsplit
import uuid

from browser_use import Browser

from app.config import settings
from app.db.engine import async_session_factory
from app.db.repository import UserRepository
from app.browser.profiles import load_session_profiles, save_session_profiles
from app.security.browser_access import profile_lock, profile_revision, register_browser, unregister_browser

logger = logging.getLogger(__name__)

SESSION_STORAGE_TIMEOUT_SECONDS = 10


def _redact_storage_state_warning(record: logging.LogRecord) -> bool:
    # Browser-use's profile validator interpolates the complete storage dict in
    # this warning, including cookies and origin tokens. Windows temp paths can
    # trigger it even for a newly isolated browser profile.
    if "was passed both storage_state AND user_data_dir" in record.getMessage():
        record.msg = "BrowserSession received both storage_state and user_data_dir; storage values redacted."
        record.args = ()
    return True


logging.getLogger("browser_use.utils").addFilter(_redact_storage_state_warning)


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
    allowed_domains: Optional[List[str]] = None,
) -> Browser:
    """
    Instantiates a configured BrowserSession.
    Supports local Chromium or remote CDP (Browserbase), optional persistent session state,
    and network-level allowed_domains restriction.
    
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

    if allowed_domains:
        browser_kwargs["allowed_domains"] = list(allowed_domains)

    if remote_cdp:
        logger.info("Initializing Browser via remote CDP endpoint (keep_alive=%s, allowed_domains=%s)", keep_alive, allowed_domains)
        return Browser(cdp_url=remote_cdp, **browser_kwargs)

    logger.info("Initializing local Browser (headless=%s, keep_alive=%s, allowed_domains=%s)", is_headless, keep_alive, allowed_domains)
    return Browser(
        headless=is_headless,
        is_local=True,
        **browser_kwargs,
    )


async def _export_session_state(session: Browser, restored_state: Any) -> dict[str, Any]:
    state = await session.export_storage_state()
    # The public exporter currently returns cookies only. Use the origin reader
    # used by browser-use's native storage watchdog for local/session storage.
    observed = await session._cdp_get_origins()
    origins = {
        item["origin"]: item for item in (
            restored_state.get("origins", []) if isinstance(restored_state, dict) else []
        )
    }
    # The native reader reports storage in the focused page and its frames.
    # Preserve restored origins that this task never opened, while allowing an
    # empty active origin (e.g. after logout) to clear its previous storage.
    try:
        page = urlsplit(await session.get_current_page_url())
        origins.pop(f"{page.scheme}://{page.netloc}", None)
    except Exception:
        pass
    origins.update((item["origin"], item) for item in observed)
    state["origins"] = list(origins.values())
    return state


@asynccontextmanager
async def browser_session_context(
    browser: Optional[Browser] = None,
    headless: Optional[bool] = None,
    storage_state: Optional[Union[Dict[str, Any], str]] = None,
    user_id: Optional[uuid.UUID] = None,
    site_domain: Optional[str] = None,
    allowed_domains: Optional[List[str]] = None,
    telegram_id: Optional[int] = None,
    task_prompt: str = "",
) -> AsyncGenerator[Browser, None]:
    """
    Async context manager managing the lifecycle (start and stop) of a Browser session.
    Automatically restores the owner's requested sites and saves updated cookies
    and origin storage before stopping, including after failure or cancellation.
    
    Session cookies in storage_state_json are encrypted using AES-256-GCM.
    """
    active_storage_state = storage_state
    profile_owner = user_id
    loaded_domains: set[str] = set()
    revision = 0

    if telegram_id:
        try:
            async with async_session_factory() as db:
                user, _ = await UserRepository.get_or_create_by_telegram_id(db, telegram_id)
                if profile_owner is not None and profile_owner != user.id:
                    raise ValueError("Browser profile owner does not match the task owner")
                profile_owner = user.id
                await db.commit()
        except Exception:
            profile_owner = None
            logger.warning("Could not resolve browser profile owner for Telegram user %s", telegram_id)

    if profile_owner:
        async with profile_lock(profile_owner):
            revision = profile_revision(profile_owner)
            if active_storage_state is None:
                try:
                    active_storage_state, loaded_domains = await load_session_profiles(profile_owner, task_prompt, site_domain)
                except Exception:
                    logger.warning("Could not load browser profiles for user %s", profile_owner)

    session = browser or create_browser(
        headless=headless,
        storage_state=active_storage_state,
        allowed_domains=allowed_domains,
    )
    logger.info("Starting browser session...")
    if profile_owner:
        register_browser(profile_owner)
    started = False
    try:
        await session.start()
        started = True
        yield session
    finally:
        try:
            if profile_owner and started and revision == profile_revision(profile_owner):
                try:
                    async with asyncio.timeout(SESSION_STORAGE_TIMEOUT_SECONDS):
                        exported = await _export_session_state(session, active_storage_state)
                        await save_session_profiles(profile_owner, exported, loaded_domains, expected_revision=revision)
                except Exception:
                    logger.warning("Could not save browser profiles for user %s", profile_owner)
        finally:
            logger.info("Stopping browser session...")
            try:
                if profile_owner and revision != profile_revision(profile_owner):
                    await session.kill()
                else:
                    await session.stop()
            except Exception:
                logger.warning("Error occurred while stopping browser session")
            finally:
                if profile_owner:
                    unregister_browser(profile_owner)
