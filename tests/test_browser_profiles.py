import asyncio
import copy
import json
import logging
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.browser.context import browser_session_context, create_browser
from app.browser.profiles import load_session_profiles
from app.browser.runner import run_browser_task
from app.config import settings
from app.db.engine import async_session_factory, init_db
from app.db.repository import BrowserProfileRepository, UserRepository
from app.security.vault import decrypt_secret, encrypt_secret
from app.tasks.state import TaskRecord, TaskState


@pytest.fixture(autouse=True)
async def database():
    await init_db()


def storage(domain="vercel.com", value="SESSION_TOKEN_CANARY"):
    return {
        "cookies": [{
            "name": "session", "value": value, "domain": f".{domain}", "path": "/",
            "secure": True, "httpOnly": True, "expires": -1, "sameSite": "Lax",
        }],
        "origins": [{"origin": f"https://{domain}", "localStorage": [{"name": "auth", "value": value}]}],
    }


def browser_with(state, *, url="https://vercel.com/dashboard"):
    return SimpleNamespace(
        start=AsyncMock(), stop=AsyncMock(), take_screenshot=AsyncMock(return_value=None),
        get_current_page_url=AsyncMock(return_value=url),
        export_storage_state=AsyncMock(return_value={"cookies": copy.deepcopy(state["cookies"]), "origins": []}),
        _cdp_get_origins=AsyncMock(return_value=copy.deepcopy(state["origins"])),
    )


async def owner():
    async with async_session_factory() as db:
        user, _ = await UserRepository.get_or_create_by_telegram_id(db, uuid.uuid4().int % 10**12)
        await db.commit()
        return user


async def save_profile(user, domain, state):
    async with async_session_factory() as db:
        await BrowserProfileRepository.save_profile(
            db, user.id, domain, encrypt_secret(json.dumps(state), settings.vault_key_bytes),
        )
        await db.commit()


async def saved_state(user, domain):
    async with async_session_factory() as db:
        profile = await BrowserProfileRepository.get_profile(db, user.id, domain)
        return json.loads(decrypt_secret(profile.storage_state_json, settings.vault_key_bytes))


def test_real_browser_profile_validation_does_not_log_restored_session_tokens(caplog):
    caplog.set_level(logging.DEBUG)
    browser = create_browser(storage_state=storage(value="PROFILE_LOG_TOKEN_CANARY"))
    assert browser.browser_profile.storage_state == storage(value="PROFILE_LOG_TOKEN_CANARY")
    assert "PROFILE_LOG_TOKEN_CANARY" not in caplog.text


async def test_runner_saves_first_login_and_restores_it_by_site_name_on_next_task(monkeypatch):
    telegram_id = uuid.uuid4().int % 10**12
    state = storage()
    first, second = browser_with(state), browser_with(state)
    factory = MagicMock(side_effect=[first, second])
    monkeypatch.setattr("app.browser.context.create_browser", factory)
    history = SimpleNamespace(
        is_successful=lambda: True, final_result=lambda: "Ready.",
        screenshot_paths=lambda **kwargs: [], screenshots=lambda: [],
    )
    monkeypatch.setattr("app.browser.runner.create_agent", lambda **kwargs: SimpleNamespace(run=AsyncMock(return_value=history)))
    bot = AsyncMock()
    status = SimpleNamespace(update=AsyncMock())

    for _ in range(2):
        task = TaskRecord(user_id=telegram_id, chat_id=telegram_id, prompt="Check my Vercel deployments")
        await run_browser_task(task, status, bot)
        assert task.state == TaskState.DONE

    assert factory.call_args_list[0].kwargs["storage_state"] == {"cookies": [], "origins": []}
    assert factory.call_args_list[1].kwargs["storage_state"] == state
    async with async_session_factory() as db:
        user = await UserRepository.get_by_telegram_id(db, telegram_id)
        profile = await BrowserProfileRepository.get_profile(db, user.id, "vercel.com")
        assert "SESSION_TOKEN_CANARY" not in profile.storage_state_json
        assert await UserRepository.get_by_id(db, user.id) is not None
    assert await saved_state(user, "vercel.com") == state
    first.stop.assert_awaited_once()
    second.stop.assert_awaited_once()


async def test_restore_is_scoped_to_owner_and_requested_site(monkeypatch):
    alice, bob = await owner(), await owner()
    await save_profile(alice, "vercel.com", storage(value="ALICE_SESSION"))
    await save_profile(bob, "vercel.com", storage(value="BOB_SESSION"))
    await save_profile(alice, "github.com", storage("github.com", "OTHER_SITE_SESSION"))
    factory = MagicMock(return_value=browser_with(storage(value="ALICE_SESSION")))
    monkeypatch.setattr("app.browser.context.create_browser", factory)

    async with browser_session_context(telegram_id=alice.telegram_id, task_prompt="Check https://vercel.com/dashboard"):
        restored = factory.call_args.kwargs["storage_state"]
        assert restored == storage(value="ALICE_SESSION")
        assert "BOB_SESSION" not in json.dumps(restored)
        assert "OTHER_SITE_SESSION" not in json.dumps(restored)


async def test_restore_multiple_sites_and_parent_cookies_for_subdomains():
    user = await owner()
    await save_profile(user, "vercel.com", storage())
    await save_profile(user, "github.com", storage("github.com", "GITHUB_SESSION"))
    combined, _ = await load_session_profiles(user.id, "Check Vercel and GitHub")
    assert {cookie["value"] for cookie in combined["cookies"]} == {"SESSION_TOKEN_CANARY", "GITHUB_SESSION"}
    selected, _ = await load_session_profiles(user.id, "Inspect https://dashboard.vercel.com")
    assert selected == storage()
    unrelated, _ = await load_session_profiles(user.id, "Inspect https://attacker.com/vercel")
    assert unrelated == {"cookies": [], "origins": []}


async def test_cookie_and_origin_domains_are_saved_separately_after_redirects():
    user = await owner()
    state = storage("wikipedia.org", "WIKI_SESSION")
    state["cookies"] += storage("wikimedia.org", "SSO_SESSION")["cookies"]
    state["origins"] += storage("auth.wikimedia.org", "SSO_STORAGE")["origins"]
    browser = browser_with(state, url="https://wikipedia.org")
    async with browser_session_context(browser=browser, telegram_id=user.telegram_id, task_prompt="Open Wikipedia"):
        pass
    wiki = await saved_state(user, "wikipedia.org")
    sso = await saved_state(user, "wikimedia.org")
    auth = await saved_state(user, "auth.wikimedia.org")
    assert [cookie["value"] for cookie in wiki["cookies"]] == ["WIKI_SESSION"]
    assert [cookie["value"] for cookie in sso["cookies"]] == ["SSO_SESSION"]
    assert auth["origins"][0]["origin"] == "https://auth.wikimedia.org"


@pytest.mark.parametrize("raw", ["CORRUPT_SESSION_TOKEN_CANARY", json.dumps(storage(value="PLAINTEXT_SESSION_CANARY"))])
async def test_invalid_or_unencrypted_profiles_start_fresh_without_logging_tokens(raw, caplog):
    user = await owner()
    async with async_session_factory() as db:
        await BrowserProfileRepository.save_profile(db, user.id, "vercel.com", raw)
        await db.commit()
    state, loaded = await load_session_profiles(user.id, "Open Vercel")
    assert state == {"cookies": [], "origins": []}
    assert loaded == set()
    assert "CORRUPT_SESSION_TOKEN_CANARY" not in caplog.text
    assert "PLAINTEXT_SESSION_CANARY" not in caplog.text


async def test_older_bundle_cannot_restore_unrelated_site_storage():
    user = await owner()
    state = storage()
    state["cookies"] += storage("attacker.com", "UNRELATED_COOKIE")["cookies"]
    state["origins"] += storage("attacker.com", "UNRELATED_STORAGE")["origins"]
    await save_profile(user, "vercel.com", state)
    restored, _ = await load_session_profiles(user.id, "Open Vercel")
    assert restored == storage()


async def test_logout_clears_saved_cookies_and_local_storage(monkeypatch):
    user = await owner()
    await save_profile(user, "vercel.com", storage())
    empty = {"cookies": [], "origins": []}
    monkeypatch.setattr("app.browser.context.create_browser", lambda **kwargs: browser_with(empty))
    async with browser_session_context(telegram_id=user.telegram_id, task_prompt="Log out of Vercel"):
        pass
    assert await saved_state(user, "vercel.com") == empty
    restored, _ = await load_session_profiles(user.id, "Open Vercel")
    assert restored == empty


async def test_local_storage_for_an_unopened_restored_origin_is_preserved(monkeypatch):
    user = await owner()
    await save_profile(user, "vercel.com", storage())
    dashboard = storage("dashboard.vercel.com", "DASHBOARD_STORAGE")
    dashboard["cookies"] = []
    await save_profile(user, "dashboard.vercel.com", dashboard)
    empty = {"cookies": [], "origins": []}
    monkeypatch.setattr("app.browser.context.create_browser", lambda **kwargs: browser_with(empty))
    async with browser_session_context(telegram_id=user.telegram_id, task_prompt="Open Vercel"):
        pass
    assert await saved_state(user, "dashboard.vercel.com") == dashboard


@pytest.mark.parametrize("failure", [RuntimeError("task failed"), asyncio.CancelledError()])
async def test_failure_and_cancellation_still_save_session_and_stop_browser(failure):
    user = await owner()
    browser = browser_with(storage())
    with pytest.raises(type(failure)):
        async with browser_session_context(browser=browser, telegram_id=user.telegram_id, task_prompt="Open Vercel"):
            raise failure
    assert await saved_state(user, "vercel.com") == storage()
    browser.stop.assert_awaited_once()


@pytest.mark.parametrize("failure_stage", ["start", "export_storage_state", "_cdp_get_origins"])
async def test_failed_browser_or_export_does_not_erase_saved_login(failure_stage, monkeypatch, caplog):
    user = await owner()
    await save_profile(user, "vercel.com", storage())
    browser = browser_with({"cookies": [], "origins": []})
    getattr(browser, failure_stage).side_effect = RuntimeError("SESSION_ERROR_CANARY")
    monkeypatch.setattr("app.browser.context.create_browser", lambda **kwargs: browser)
    if failure_stage == "start":
        with pytest.raises(RuntimeError):
            async with browser_session_context(telegram_id=user.telegram_id, task_prompt="Open Vercel"):
                pass
    else:
        async with browser_session_context(telegram_id=user.telegram_id, task_prompt="Open Vercel"):
            pass
    assert await saved_state(user, "vercel.com") == storage()
    assert "SESSION_ERROR_CANARY" not in caplog.text
    browser.stop.assert_awaited_once()


async def test_mismatched_telegram_owner_cannot_restore_or_update_another_users_profile(monkeypatch):
    alice, bob = await owner(), await owner()
    await save_profile(bob, "vercel.com", storage(value="BOB_SESSION"))
    browser = browser_with(storage(value="ALICE_SESSION"))
    factory = MagicMock(return_value=browser)
    monkeypatch.setattr("app.browser.context.create_browser", factory)
    async with browser_session_context(user_id=bob.id, telegram_id=alice.telegram_id, task_prompt="Open Vercel"):
        assert factory.call_args.kwargs["storage_state"] is None
    assert await saved_state(bob, "vercel.com") == storage(value="BOB_SESSION")
    browser.export_storage_state.assert_not_awaited()


async def test_cancellation_during_profile_export_still_stops_browser():
    user = await owner()
    browser = browser_with(storage())
    exporting = asyncio.Event()

    async def blocked_export():
        exporting.set()
        await asyncio.Event().wait()

    browser.export_storage_state.side_effect = blocked_export

    async def run():
        async with browser_session_context(browser=browser, telegram_id=user.telegram_id, task_prompt="Open Vercel"):
            pass

    worker = asyncio.create_task(run())
    try:
        await asyncio.wait_for(exporting.wait(), 1)
        worker.cancel()
        with pytest.raises(asyncio.CancelledError):
            await worker
        browser.stop.assert_awaited_once()
    finally:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)


async def test_slow_export_times_out_without_erasing_saved_login(monkeypatch):
    monkeypatch.setattr("app.browser.context.SESSION_STORAGE_TIMEOUT_SECONDS", 0.01)
    user = await owner()
    await save_profile(user, "vercel.com", storage())
    browser = browser_with(storage())

    async def blocked_export():
        await asyncio.Event().wait()

    browser.export_storage_state.side_effect = blocked_export
    async with browser_session_context(browser=browser, telegram_id=user.telegram_id, task_prompt="Open Vercel"):
        pass
    browser.stop.assert_awaited_once()
    assert await saved_state(user, "vercel.com") == storage()
