"""One-time credential capture, grouped accounts, and browser access revocation."""

import asyncio
from contextlib import asynccontextmanager
from html import unescape
import re
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit
import uuid

import pytest

from app.browser.context import browser_session_context
from app.browser.controller import SecureController
from app.browser.profiles import save_session_profiles
from app.security.browser_access import profile_revision
from app.companion.auth import SESSION_COOKIE_NAME, validate_telegram_identity
from app.config import settings
from app.db.engine import async_session_factory, init_db
from app.db.repository import BrowserProfileRepository, CredentialRepository, IdentityTokenRepository, TaskRepository, UserRepository
from app.security.vault import decrypt_secret, encrypt_secret
from app.tasks.registry import task_registry
from app.tasks.state import TaskRecord, TaskState


@pytest.fixture(autouse=True)
async def database():
    await init_db()


async def sign_in(client, identity):
    telegram_id = uuid.uuid4().int % 10**12
    response = await client.post("/companion/auth/telegram", json={"init_data": identity(telegram_id)})
    assert response.status_code == 200
    async with async_session_factory() as db:
        return await UserRepository.get_by_telegram_id(db, telegram_id)


def local_url(url):
    parts = urlsplit(url)
    return parts.path + "?" + parts.query


@asynccontextmanager
async def credential_request(user, *, auth_type="password", sensitive_data=None, force_refresh=False):
    task = TaskRecord(user_id=user.telegram_id, chat_id=user.telegram_id, prompt="Login to example.com")
    ready = asyncio.Event()
    status = SimpleNamespace(update=AsyncMock(side_effect=lambda *args, **kwargs: ready.set()))
    controller = SecureController(user_id=user.id, task=task, status_manager=status, sensitive_data=sensitive_data)
    action = controller.registry.registry.actions["need_password" if auth_type == "password" else "need_api_key"].function
    browser = SimpleNamespace(get_current_page_url=AsyncMock(return_value="https://example.com/login"))
    kwargs = {"force_refresh": True} if force_refresh else {}
    running = asyncio.create_task(action(domain="example.com", browser_session=browser, **kwargs))
    try:
        await asyncio.wait_for(ready.wait(), 5)
        yield task, controller, running
    finally:
        if not running.done():
            running.cancel()
        await asyncio.gather(running, return_exceptions=True)


def input_headers(page):
    token = unescape(re.search(r'data-input-session="([^"]+)"', page.text).group(1))
    return {"X-Credential-Input": token}


async def test_telegram_signature_compatible_with_aiogram(telegram_identity):
    from aiogram.utils.web_app import safe_parse_webapp_init_data
    raw = telegram_identity(123, query_id="synthetic-query", signature="extra-telegram-field")
    assert validate_telegram_identity(raw) == 123
    assert safe_parse_webapp_init_data(settings.TELEGRAM_BOT_TOKEN, raw).user.id == 123


@pytest.mark.parametrize("case", ["tampered", "wrong_bot", "old", "future", "duplicate", "missing_user", "invalid_id", "unsigned"])
async def test_invalid_telegram_identity_cannot_create_vault_session(async_client, telegram_identity, monkeypatch, case):
    raw = telegram_identity(123)
    if case == "tampered":
        raw = raw.replace("Test", "Other")
    elif case == "wrong_bot":
        monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "other-bot-token")
    elif case == "old":
        raw = telegram_identity(123, auth_date=int(time.time()) - 301)
    elif case == "future":
        raw = telegram_identity(123, auth_date=int(time.time()) + 60)
    elif case == "duplicate":
        raw += "&user=%7B%22id%22%3A456%7D"
    elif case == "missing_user":
        raw = telegram_identity(123, user="null")
    elif case == "invalid_id":
        raw = telegram_identity(True)
    else:
        raw = "user=%7B%22id%22%3A123%7D"
    response = await async_client.post("/companion/auth/telegram", json={"init_data": raw})
    assert response.status_code == 401 and SESSION_COOKIE_NAME not in response.cookies
    assert (await async_client.get("/api/vault/accounts")).status_code == 401


@pytest.mark.parametrize("auth_type", ["password", "api_key"])
async def test_link_opens_once_and_can_only_submit_its_credential(async_client, telegram_identity, auth_type):
    user = await sign_in(async_client, telegram_identity)
    async_client.cookies.clear()
    async with credential_request(user, auth_type=auth_type) as (task, controller, running):
        url = local_url(task.metadata["companion_url"])
        raw_token = parse_qs(urlsplit(url).query)["token"][0]
        promoted = await async_client.get("/companion/link", params={"token": raw_token})
        assert promoted.status_code == 401 and SESSION_COOKIE_NAME not in promoted.cookies
        page = await async_client.get(url)
        assert page.status_code == 200 and "🔐 Save to Vault</button>" in page.text
        assert "input-countdown" not in page.text and "data-deadline" not in page.text
        assert "https://example.com/favicon.ico" in page.text
        assert SESSION_COOKIE_NAME not in page.cookies
        assert (await async_client.get(url)).status_code == 410
        headers = input_headers(page)
        assert (await async_client.get("/api/vault/accounts", headers=headers)).status_code == 401
        assert (await async_client.get("/api/vault/accounts", headers={"Authorization": "Bearer " + headers["X-Credential-Input"]})).status_code == 401
        assert (await async_client.post("/api/tasks/other-task/resolve-input", headers=headers, json={"credential_type": auth_type, "secret": "wrong-target"})).status_code == 401
        payload = {"credential_type": auth_type, "secret": "  exact-canary-secret  "}
        response = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", headers=headers, json=payload)
        assert response.status_code == 200
        assert (await asyncio.wait_for(running, 5)).error is None
        assert "exact-canary-secret" not in response.text
        assert (await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", headers=headers, json=payload)).status_code == 401
        async with async_session_factory() as db:
            credentials = await CredentialRepository.get_credentials_for_domain(db, user.id, "example.com")
            assert decrypt_secret(credentials[0].encrypted_blob, settings.vault_key_bytes) == payload["secret"]


async def test_expiry_prevents_both_link_opening_and_existing_form_submission(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    async with credential_request(user) as (task, _, running):
        url = local_url(task.metadata["companion_url"])
        page = await async_client.get(url)
        pending = task_registry.get_credential_input(task.task_id)
        pending.deadline = time.time() - 1
        assert (await async_client.get(url)).status_code == 410
        response = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", headers=input_headers(page), json={"credential_type": "password", "secret": "too-late"})
        assert response.status_code == 401
        async with async_session_factory() as db:
            assert await CredentialRepository.get_credentials_for_domain(db, user.id, "example.com") == []


async def test_unused_link_is_invalidated_on_task_cancellation(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    async with credential_request(user) as (task, _, running):
        url = local_url(task.metadata["companion_url"])
        running.cancel()
        await asyncio.gather(running, return_exceptions=True)
        assert (await async_client.get(url)).status_code == 410
        async with async_session_factory() as db:
            from urllib.parse import parse_qs
            token = parse_qs(urlsplit(url).query)["token"][0]
            assert (await IdentityTokenRepository.get_token(db, token)).is_used


async def test_rejected_password_uses_new_form_and_preserves_identifier(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    async with async_session_factory() as db:
        await CredentialRepository.add_or_update_credential(db, user.id, "example.com", "password", encrypt_secret("old-password", settings.vault_key_bytes), "test-account")
        await db.commit()
    shared = {"https://*.example.com": {"example_pass": "old-password", "x_pass": "old-password"}}
    async with credential_request(user, sensitive_data=shared, force_refresh=True) as (task, _, running):
        assert "example_pass" not in shared["https://*.example.com"]
        assert task.metadata["credential_rejected"] is True
        page = await async_client.get(local_url(task.metadata["companion_url"]))
        result = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", headers=input_headers(page), json={"credential_type": "password", "secret": "new-password"})
        assert result.status_code == 200 and (await running).error is None
        assert shared["https://*.example.com"]["example_pass"] == "new-password"
        async with async_session_factory() as db:
            credentials = await CredentialRepository.get_credentials_for_domain(db, user.id, "example.com")
            assert credentials[0].username_or_identifier == "test-account"


async def test_account_edits_do_not_submit_a_waiting_request(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    async with credential_request(user) as (task, _, running):
        response = await async_client.put("/api/vault/accounts/example.com", json={"password": "saved-through-accounts"})
        assert response.status_code == 200
        assert task_registry.get_credential_input(task.task_id).is_pending
        assert not running.done()


async def test_grouped_account_details_and_atomic_editing(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    values = {"username": "test-user", "email": "user@example.com", "phone": "00123456789", "country_code": "+44", "password": "password-canary", "api_key": "api-key-canary", "totp_seed": "JBSWY3DPEHPK3PXP"}
    response = await async_client.put("/api/vault/accounts/EXAMPLE.com", json=values)
    assert response.status_code == 200
    assert (await async_client.get("/api/vault/accounts")).json() == [{"site_domain": "example.com"}]
    page = await async_client.get("/companion/accounts")
    assert page.text.count('class="account-row"') == 2  # one row plus the client template
    details_page = await async_client.get("/companion/accounts/example.com")
    for value in values.values():
        assert value not in details_page.text
    details_response = await async_client.get("/api/vault/accounts/example.com")
    assert details_response.headers["cache-control"] == "no-store"
    details = details_response.json()
    assert details["details"] == {field: values[field] for field in ("username", "email", "phone", "country_code")}
    assert set(details["stored_secrets"]) == {"password", "api_key", "totp_seed"}
    for secret in (values["password"], values["api_key"], values["totp_seed"]):
        assert secret not in details_response.text
    bad = await async_client.put("/api/vault/accounts/example.com", json={"username": "must-not-write", "totp_seed": "INVALID-890!"})
    assert bad.status_code == 400
    assert (await async_client.get("/api/vault/accounts/example.com")).json()["details"]["username"] == "test-user"
    assert (await async_client.put("/api/vault/accounts/example.com", json={"email": None, "password": ""})).status_code == 200
    updated = (await async_client.get("/api/vault/accounts/example.com")).json()
    assert updated["details"]["email"] == "" and "password" in updated["stored_secrets"]
    async with async_session_factory() as db:
        rows = await CredentialRepository.get_credentials_for_domain(db, user.id, "example.com")
        assert all(c.encrypted_blob != values[c.auth_type] for c in rows)
        password = next(c for c in rows if c.auth_type == "password")
        assert decrypt_secret(password.encrypted_blob, settings.vault_key_bytes) == values["password"]


async def test_legacy_identifier_is_shown_and_can_be_changed_without_losing_password(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    async with async_session_factory() as db:
        await CredentialRepository.add_or_update_credential(db, user.id, "example.com", "password", encrypt_secret("old-password", settings.vault_key_bytes), "old@example.com")
        await db.commit()
    assert (await async_client.get("/api/vault/accounts/example.com")).json()["details"]["email"] == "old@example.com"
    assert (await async_client.put("/api/vault/accounts/example.com", json={"password": "new-password"})).status_code == 200
    assert (await async_client.get("/api/vault/accounts/example.com")).json()["details"]["email"] == "old@example.com"
    assert (await async_client.put("/api/vault/accounts/example.com", json={"email": "new@example.com"})).status_code == 200
    assert (await async_client.get("/api/vault/accounts/example.com")).json()["details"]["email"] == "new@example.com"


async def test_signed_session_works_without_cookies_and_isolates_owners(async_client, telegram_identity):
    first = await sign_in(async_client, telegram_identity)
    await async_client.put("/api/vault/accounts/example.com", json={"username": "first-owner"})
    old_cookie = async_client.cookies.get(SESSION_COOKIE_NAME)
    response = await async_client.post("/companion/auth/telegram", json={"init_data": telegram_identity(first.telegram_id + 1)})
    headers = {"Authorization": "Bearer " + response.json()["session_token"]}
    async_client.cookies.clear()
    assert (await async_client.get("/api/vault/accounts", headers=headers)).json() == []
    async_client.cookies.set(SESSION_COOKIE_NAME, old_cookie)
    assert (await async_client.get("/api/vault/accounts/example.com", headers=headers)).status_code == 404
    assert (await async_client.delete("/api/vault/accounts/example.com", headers=headers)).status_code == 404
    assert (await async_client.get("/api/vault/accounts/example.com")).json()["details"]["username"] == "first-owner"


async def test_delete_account_removes_every_field_and_related_sessions_only(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    await async_client.put("/api/vault/accounts/example.com", json={"username": "test-user", "password": "password", "totp_seed": "JBSWY3DPEHPK3PXP"})
    await async_client.put("/api/vault/accounts/other.com", json={"username": "other-user"})
    async with async_session_factory() as db:
        for domain in ("example.com", "auth.example.com", "other.com", "notexample.com"):
            await BrowserProfileRepository.save_profile(db, user.id, domain, encrypt_secret('{"cookies":[],"origins":[]}', settings.vault_key_bytes))
        other, _ = await UserRepository.get_or_create_by_telegram_id(db, uuid.uuid4().int % 10**12)
        await BrowserProfileRepository.save_profile(db, other.id, "example.com", "other-owner-profile")
        await db.commit()
    assert (await async_client.delete("/api/vault/accounts/example.com")).status_code == 200
    assert (await async_client.get("/api/vault/accounts")).json() == [{"site_domain": "other.com"}]
    async with async_session_factory() as db:
        assert await CredentialRepository.get_credentials_for_domain(db, user.id, "example.com") == []
        assert {p.site_domain for p in await BrowserProfileRepository.get_profiles_for_user(db, user.id)} == {"other.com", "notexample.com"}
        assert await BrowserProfileRepository.get_profile(db, other.id, "example.com") is not None


async def test_delete_closes_live_browser_and_prevents_stale_profile_save(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    await async_client.put("/api/vault/accounts/example.com", json={"password": "password"})
    state = {"cookies": [{"domain": "example.com", "name": "session", "value": "session-canary"}], "origins": []}
    await save_session_profiles(user.id, state, set())
    revision = profile_revision(user.id)
    browser = SimpleNamespace(start=AsyncMock(), stop=AsyncMock(), kill=AsyncMock(), export_storage_state=AsyncMock(return_value=state))
    ready = asyncio.Event()

    async def run():
        async with browser_session_context(browser=browser, user_id=user.id, task_prompt="example.com"):
            ready.set()
            await asyncio.Event().wait()

    running = asyncio.create_task(run())
    try:
        await asyncio.wait_for(ready.wait(), 5)
        assert (await async_client.delete("/api/vault/accounts/example.com")).status_code == 200
        assert running.cancelled()
        browser.kill.assert_awaited_once()
        browser.export_storage_state.assert_not_awaited()
        await save_session_profiles(user.id, state, {"example.com"}, expected_revision=revision)
        async with async_session_factory() as db:
            assert await BrowserProfileRepository.get_profiles_for_user(db, user.id) == []
    finally:
        if not running.done():
            running.cancel()
        await asyncio.gather(running, return_exceptions=True)


async def test_delete_invalidates_open_credential_form(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    await async_client.put("/api/vault/accounts/example.com", json={"username": "test-user"})
    async with credential_request(user) as (task, _, running):
        page = await async_client.get(local_url(task.metadata["companion_url"]))
        assert (await async_client.delete("/api/vault/accounts/example.com")).status_code == 200
        response = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", headers=input_headers(page), json={"credential_type": "password", "secret": "must-not-restore"})
        assert response.status_code == 401
        assert (await asyncio.wait_for(running, 5)).error
        assert (await async_client.get("/api/vault/accounts")).json() == []


async def test_account_correction_already_saved_is_reloaded_without_another_form(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    await async_client.put("/api/vault/accounts/example.com", json={"password": "already-corrected"})
    shared = {"https://*.example.com": {"example_pass": "rejected-old-value"}}
    task = TaskRecord(user_id=user.telegram_id, chat_id=user.telegram_id, prompt="Login")
    controller = SecureController(user_id=user.id, task=task, sensitive_data=shared)
    controller._wait_for_credentials = AsyncMock()
    browser = SimpleNamespace(get_current_page_url=AsyncMock(return_value="https://example.com/login"))
    action = controller.registry.registry.actions["need_password"].function
    result = await action(domain="example.com", force_refresh=True, browser_session=browser)
    assert result.error is None
    controller._wait_for_credentials.assert_not_awaited()
    assert shared["https://*.example.com"]["example_pass"] == "already-corrected"


async def test_delete_cancels_owners_registered_work_before_browser_launch(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    await async_client.put("/api/vault/accounts/example.com", json={"password": "password"})
    task = TaskRecord(user_id=user.telegram_id, chat_id=user.telegram_id, prompt="Login")
    other = TaskRecord(user_id=user.telegram_id + 1, chat_id=user.telegram_id + 1, prompt="Other task")
    running = asyncio.create_task(asyncio.Event().wait())
    unrelated = asyncio.create_task(asyncio.Event().wait())
    task_registry.register(task.chat_id, task, running, None)
    task_registry.register(other.chat_id, other, unrelated, None)
    try:
        response = await async_client.delete("/api/vault/accounts/example.com")
        assert response.status_code == 200
        assert running.cancelled() and task.state == TaskState.FAILED
        assert not unrelated.done() and other.state == TaskState.RUNNING
    finally:
        unrelated.cancel()
        running.cancel()
        await asyncio.gather(running, unrelated, return_exceptions=True)
