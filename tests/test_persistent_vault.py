"""Persistent editor, Telegram authentication, and task-independent vault saves."""

import asyncio
import time
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.companion.auth import SESSION_COOKIE_NAME, validate_telegram_identity
from app.browser.controller import SecureController
from app.config import settings
from app.db.engine import async_session_factory, init_db
from app.db.repository import CredentialRepository, TaskRepository, UserRepository
from app.security.vault import decrypt_secret, encrypt_secret
from app.tasks.registry import task_registry
from app.tasks.state import TaskRecord, TaskState


@pytest.fixture(autouse=True)
async def database():
    await init_db()


async def sign_in(client, identity, telegram_id=None):
    telegram_id = telegram_id or uuid.uuid4().int % 10**12
    response = await client.post("/companion/auth/telegram", json={"init_data": identity(telegram_id)})
    assert response.status_code == 200
    async with async_session_factory() as db:
        return await UserRepository.get_by_telegram_id(db, telegram_id)


async def save(client, domain="example.com", secret="test-password", auth_type="password"):
    return await client.post("/api/vault/credentials", json={
        "site_domain": domain, "auth_type": auth_type, "secret": secret,
    })


async def test_telegram_signature_compatible_with_aiogram(telegram_identity):
    from aiogram.utils.web_app import safe_parse_webapp_init_data
    raw = telegram_identity(123, query_id="synthetic-query", signature="new-telegram-field")
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
    assert response.status_code == 401
    assert SESSION_COOKIE_NAME not in response.cookies
    assert (await save(async_client)).status_code == 401


async def test_public_editor_contains_no_secrets_or_countdown(async_client):
    response = await async_client.get("/companion/credentials?domain=https://www.example.com/login")
    assert response.status_code == 200
    assert 'data-target-domain="example.com"' in response.text
    assert "Save to vault</button>" in response.text
    assert "input-countdown" not in response.text and "data-deadline" not in response.text
    assert "https://example.com/favicon.ico" in response.text
    assert 'referrerpolicy="no-referrer"' in response.text
    assert "credential-form" in response.text and "telegram-web-app.js" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert (await save(async_client)).status_code == 401


async def test_repeated_open_and_save_replaces_encrypted_secret_without_task(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    first = await save(async_client, secret="old-canary")
    assert first.status_code == 201 and first.json()["resumed"] is False
    second = await save(async_client, secret="new-canary")
    assert second.status_code == 201 and second.json()["id"] == first.json()["id"]
    async with async_session_factory() as db:
        credentials = await CredentialRepository.get_credentials_for_domain(db, user.id, "example.com")
        assert len(credentials) == 1
        assert "canary" not in credentials[0].encrypted_blob
        assert decrypt_secret(credentials[0].encrypted_blob, settings.vault_key_bytes) == "new-canary"
    for _ in range(2):
        page = await async_client.get("/companion/credentials?domain=example.com")
        assert page.status_code == 200 and "new-canary" not in page.text


async def test_signed_user_replaces_previous_cookie_owner(async_client, telegram_identity):
    first = await sign_in(async_client, telegram_identity)
    await save(async_client, secret="first-owner")
    second = await sign_in(async_client, telegram_identity)
    await save(async_client, secret="second-owner")
    async with async_session_factory() as db:
        for user, expected in ((first, "first-owner"), (second, "second-owner")):
            credentials = await CredentialRepository.get_credentials_for_domain(db, user.id, "example.com")
            assert decrypt_secret(credentials[0].encrypted_blob, settings.vault_key_bytes) == expected


async def test_signed_session_works_without_cookies_and_overrides_stale_cookie(async_client, telegram_identity):
    first = await sign_in(async_client, telegram_identity)
    old_cookie = async_client.cookies.get(SESSION_COOKIE_NAME)
    response = await async_client.post("/companion/auth/telegram", json={"init_data": telegram_identity(first.telegram_id + 1)})
    bearer = response.json()["session_token"]
    async_client.cookies.clear()
    headers = {"Authorization": f"Bearer {bearer}"}
    assert (await async_client.get("/api/vault/credentials", headers=headers)).status_code == 200
    async_client.cookies.set(SESSION_COOKIE_NAME, old_cookie)
    result = await async_client.post("/api/vault/credentials", headers=headers, json={
        "site_domain": "example.com", "auth_type": "password", "secret": "new-owner-secret",
    })
    assert result.status_code == 201
    async with async_session_factory() as db:
        assert await CredentialRepository.get_credentials_for_user(db, first.id) == []


@pytest.mark.parametrize("state", [TaskState.FAILED, TaskState.DONE, TaskState.NEEDS_INPUT])
async def test_save_survives_expired_or_finished_task(async_client, telegram_identity, state):
    user = await sign_in(async_client, telegram_identity)
    task = TaskRecord(user_id=user.telegram_id, chat_id=user.telegram_id, prompt="Login", state=state)
    async with async_session_factory() as db:
        await TaskRepository.save_task(db, task)
        await db.commit()
    pending = task_registry.register_credential_input(task, "example.com", time.time() - 1)
    try:
        result = await save(async_client)
        assert result.status_code == 201 and result.json()["resumed"] is False
        assert task.state == state and not pending.event.is_set()
    finally:
        task_registry.clear_credential_input(task.task_id)


@pytest.mark.parametrize("difference", ["owner", "domain", "type"])
async def test_save_cannot_wake_unrelated_task(async_client, telegram_identity, difference):
    user = await sign_in(async_client, telegram_identity)
    task = TaskRecord(user_id=user.telegram_id + (1 if difference == "owner" else 0), chat_id=1, prompt="Login", state=TaskState.NEEDS_INPUT)
    task.metadata["credential_type"] = "api_key" if difference == "type" else "password"
    pending = task_registry.register_credential_input(task, "other.com" if difference == "domain" else "example.com", time.time() + 100)
    try:
        result = await save(async_client)
        assert result.status_code == 201 and result.json()["resumed"] is False
        assert pending.is_pending
    finally:
        task_registry.clear_credential_input(task.task_id)


async def test_rejected_password_waits_and_reloads_corrected_value(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    async with async_session_factory() as db:
        await CredentialRepository.add_or_update_credential(db, user.id, "example.com", "password", encrypt_secret("old-password", settings.vault_key_bytes), "test-account")
        await db.commit()
    shared = {"https://*.example.com": {"example_pass": "old-password", "x_pass": "old-password"}}
    task = TaskRecord(user_id=user.telegram_id, chat_id=user.telegram_id, prompt="Login")
    ready = asyncio.Event()
    status = SimpleNamespace(update=AsyncMock(side_effect=lambda *args, **kwargs: ready.set()))
    controller = SecureController(user_id=user.id, task=task, status_manager=status, sensitive_data=shared)
    action = controller.registry.registry.actions["need_password"].function
    browser = SimpleNamespace(get_current_page_url=AsyncMock(return_value="https://example.com/login"))
    running = asyncio.create_task(action(domain="example.com", force_refresh=True, browser_session=browser))
    try:
        await asyncio.wait_for(ready.wait(), 5)
        assert "example_pass" not in shared["https://*.example.com"]
        assert task.metadata["credential_rejected"] is True
        result = await save(async_client, secret="new-password")
        assert result.status_code == 201 and result.json()["resumed"] is True
        action_result = await asyncio.wait_for(running, 5)
        assert action_result.error is None
        assert shared["https://*.example.com"]["example_pass"] == "new-password"
        assert "new-password" not in action_result.model_dump_json()
        async with async_session_factory() as db:
            credentials = await CredentialRepository.get_credentials_for_domain(db, user.id, "example.com")
            assert credentials[0].username_or_identifier == "test-account"
    finally:
        if not running.done():
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)


async def test_slow_task_wakeup_never_loses_saved_credential_or_revives_timed_out_task(async_client, telegram_identity, monkeypatch):
    user = await sign_in(async_client, telegram_identity)
    task = TaskRecord(user_id=user.telegram_id, chat_id=user.telegram_id, prompt="Login")
    monkeypatch.setattr("app.browser.controller.CREDENTIAL_INPUT_TIMEOUT", 0.2)
    ready, saving, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    status = SimpleNamespace(update=AsyncMock(side_effect=lambda *args, **kwargs: ready.set()))
    controller = SecureController(user_id=user.id, task=task, status_manager=status)
    original = TaskRepository.save_task

    async def slow_save(db, record):
        if record.task_id == task.task_id and record.state == TaskState.RUNNING:
            saving.set()
            await release.wait()
        return await original(db, record)

    monkeypatch.setattr(TaskRepository, "save_task", slow_save)
    action = controller.registry.registry.actions["need_password"].function
    browser = SimpleNamespace(get_current_page_url=AsyncMock(return_value="https://example.com/login"))
    running = asyncio.create_task(action(domain="example.com", browser_session=browser))
    submission = None
    try:
        await asyncio.wait_for(ready.wait(), 5)
        submission = asyncio.create_task(save(async_client, secret="late-but-saved"))
        await asyncio.wait_for(saving.wait(), 5)
        await asyncio.sleep(0.25)
        release.set()
        response, result = await asyncio.wait_for(asyncio.gather(submission, running), 5)
        assert response.status_code == 201 and response.json()["resumed"] is False
        assert "timed out" in result.error and task.state == TaskState.FAILED
        async with async_session_factory() as db:
            stored = await CredentialRepository.get_credentials_for_domain(db, user.id, "example.com")
            assert decrypt_secret(stored[0].encrypted_blob, settings.vault_key_bytes) == "late-but-saved"
            assert (await TaskRepository.get_task(db, task.task_id)).state == TaskState.FAILED
    finally:
        release.set()
        for future in (submission, running):
            if future is not None and not future.done():
                future.cancel()
                await asyncio.gather(future, return_exceptions=True)


async def test_rejection_reloads_a_password_already_corrected_through_older_link(async_client, telegram_identity):
    user = await sign_in(async_client, telegram_identity)
    assert (await save(async_client, secret="already-corrected")).status_code == 201
    shared = {"https://*.example.com": {"example_pass": "rejected-old-value"}}
    task = TaskRecord(user_id=user.telegram_id, chat_id=user.telegram_id, prompt="Login")
    controller = SecureController(user_id=user.id, task=task, sensitive_data=shared)
    controller._wait_for_credentials = AsyncMock()
    browser = SimpleNamespace(get_current_page_url=AsyncMock(return_value="https://example.com/login"))
    action = controller.registry.registry.actions["need_password"].function
    result = await action(domain="example.com", force_refresh=True, browser_session=browser)
    controller._wait_for_credentials.assert_not_awaited()
    assert result.error is None
    assert shared["https://*.example.com"]["example_pass"] == "already-corrected"
