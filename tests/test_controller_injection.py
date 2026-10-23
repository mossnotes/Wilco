"""Smart Vault action coverage (the former injection tools are deliberately retired)."""

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, urlsplit
import uuid

import pytest
import pytest_asyncio

from app.browser.controller import SecureController, clean_domain, validate_origin
from app.config import settings
from app.db.engine import async_session_factory, init_db
from app.db.repository import CredentialRepository, TaskRepository, UserRepository
from app.security.vault import decrypt_secret, encrypt_secret
from app.tasks.registry import task_registry
from app.tasks.state import TaskRecord, TaskState


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


def browser_at(url="https://vercel.com/login"):
    browser = MagicMock()
    browser.get_current_page_url = AsyncMock(return_value=url)
    browser.browser_profile = SimpleNamespace(allowed_domains=["github.com", "*.github.com"])
    return browser


async def vault_user(credentials=(), domain="vercel.com"):
    async with async_session_factory() as db:
        user, _ = await UserRepository.get_or_create_by_telegram_id(db, uuid.uuid4().int % 10**12)
        for auth_type, secret in credentials:
            await CredentialRepository.add_or_update_credential(
                db, user.id, domain, auth_type, encrypt_secret(secret, settings.vault_key_bytes),
                username_or_identifier="admin@example.com" if auth_type == "password" else None,
            )
        await db.commit()
    return user


def request_action(controller):
    return controller.registry.registry.actions["request_domain_credentials"].function


@pytest.mark.parametrize("raw, expected", [
    ("https://vercel.com/login", "vercel.com"), ("http://www.github.com/settings", "github.com"),
    ("app.supabase.com:8080/dashboard", "app.supabase.com"), ("subdomain.example.co.uk/", "subdomain.example.co.uk"),
    ("", ""), ("*.example.com", ""), ("https://example.com@evil.com", ""), ("foo:invalid", ""),
])
def test_clean_domain_utility(raw, expected):
    assert clean_domain(raw) == expected


@pytest.mark.parametrize("url, domain, valid", [
    ("https://vercel.com/login", "vercel.com", True),
    ("https://www.vercel.com/login", "vercel.com", True),
    ("https://auth.api.vercel.com/login", "vercel.com", True),
    ("https://evil-vercel.com", "vercel.com", False),
    ("https://vercel.com.attacker.com", "vercel.com", False),
    ("http://vercel.com", "vercel.com", False),
    ("http://localhost:3000/login", "localhost", True),
    ("http://127.0.0.1:8000", "127.0.0.1", True),
    ("http://[::1]:8000", "[::1]", True),
    ("http://0.0.0.0:8000", "0.0.0.0", False),
    ("file:///etc/passwd", "localhost", False),
    ("javascript:alert(1)", "vercel.com", False),
    ("", "vercel.com", False), ("https://vercel.com", "", False),
])
def test_validate_origin_rules(url, domain, valid):
    assert validate_origin(url, domain)[0] is valid


def test_controller_action_registration():
    actions = SecureController().registry.registry.actions
    assert "request_domain_credentials" in actions
    assert "input" in actions
    assert "inject_credential" not in actions
    assert "inject_totp" not in actions


async def test_cached_domain_loads_all_placeholders_without_typing():
    user = await vault_user([("password", "VerySecretPassword"), ("totp_seed", "JBSWY3DPEHPK3PXP"), ("api_key", "secret-key")])
    shared = {}
    controller = SecureController(telegram_id=user.telegram_id, sensitive_data=shared)
    browser = browser_at()
    result = await request_action(controller)(domain="https://www.vercel.com/login", browser_session=browser)
    assert result.error is None
    assert controller.sensitive_data is shared
    assert shared["https://*.vercel.com"] == {
        "vercel_user": "admin@example.com", "vercel_pass": "VerySecretPassword",
        "vercel_bu_2fa_code": "JBSWY3DPEHPK3PXP", "vercel_api_key": "secret-key",
    }
    assert "<secret>vercel_pass</secret>" in result.extracted_content
    assert "VerySecretPassword" not in result.model_dump_json()
    assert "JBSWY3DPEHPK3PXP" not in result.model_dump_json()
    assert set(browser.browser_profile.allowed_domains) == {"github.com", "*.github.com"}
    browser.event_bus.dispatch.assert_not_called()


async def test_credential_request_leaves_navigation_open():
    user = await vault_user([("password", "private")])
    browser = browser_at()
    browser.browser_profile.allowed_domains = None
    controller = SecureController(user_id=user.id)
    result = await request_action(controller)(domain="vercel.com", browser_session=browser)
    assert result.error is None
    assert browser.browser_profile.allowed_domains is None


async def test_origin_failure_never_reads_vault(monkeypatch):
    lookup = AsyncMock()
    monkeypatch.setattr(CredentialRepository, "get_credentials_for_domain", lookup)
    controller = SecureController(user_id=uuid.uuid4())
    result = await request_action(controller)(domain="vercel.com", browser_session=browser_at("https://evil-vercel.com"))
    assert "Security violation" in result.error
    lookup.assert_not_awaited()
    assert controller.sensitive_data == {}


async def test_revalidates_origin_before_publishing():
    user = await vault_user([("password", "private")])
    controller = SecureController(user_id=user.id)
    browser = browser_at()
    browser.get_current_page_url.side_effect = ["https://vercel.com", "https://attacker.com"]
    result = await request_action(controller)(domain="vercel.com", browser_session=browser)
    assert "Page changed origin" in result.error
    assert controller.sensitive_data == {}


async def test_unauthorized_user():
    result = await request_action(SecureController())(domain="vercel.com", browser_session=browser_at())
    assert "Unauthorized" in result.error


async def test_no_browser_session():
    result = await request_action(SecureController())(domain="vercel.com")
    assert "No active browser" in result.error


async def test_missing_credentials_without_task_context():
    user = await vault_user()
    result = await request_action(SecureController(user_id=user.id))(domain="vercel.com", browser_session=browser_at())
    assert "WebApp" in result.error


async def test_decryption_failure_does_not_publish_or_log_secret(caplog):
    user = await vault_user()
    async with async_session_factory() as db:
        await CredentialRepository.add_or_update_credential(db, user.id, "vercel.com", "password", "CORRUPT_SECRET_BLOB")
        await db.commit()
    controller = SecureController(user_id=user.id)
    result = await request_action(controller)(domain="vercel.com", browser_session=browser_at())
    assert "Failed to decrypt" in result.error
    assert controller.sensitive_data == {}
    assert "CORRUPT_SECRET_BLOB" not in caplog.text


async def test_missing_credentials_webapp_roundtrip(async_client, monkeypatch, telegram_identity):
    monkeypatch.setattr(settings, "COMPANION_BASE_URL", "https://wilco.example/companion")
    user = await vault_user()
    task = TaskRecord(user_id=user.telegram_id, chat_id=user.telegram_id, prompt="Login to vercel.com")
    status = SimpleNamespace(update=AsyncMock())
    shared = {}
    controller = SecureController(user_id=user.id, task=task, status_manager=status, sensitive_data=shared)
    browser = browser_at()
    pending_seen = asyncio.Event()
    urls = []

    async def update(record, **kwargs):
        if record.state == TaskState.NEEDS_INPUT:
            urls.append(record.metadata["companion_url"])
            pending_seen.set()
    status.update.side_effect = update
    action_task = asyncio.create_task(request_action(controller)(domain="vercel.com", browser_session=browser))
    try:
        await asyncio.wait_for(pending_seen.wait(), 5)
        pending = task_registry.get_credential_input(task.task_id)
        assert pending.is_pending
        link = urlsplit(urls[0])
        response = await async_client.get(f"{link.path}?{link.query}", follow_redirects=True)
        assert response.status_code == 200
        assert 'id="secret" name="secret" type="password"' in response.text
        assert 'id="username"' not in response.text
        assert 'id="totp_seed"' not in response.text
        assert "vercel.com" in response.text
        auth = await async_client.post("/companion/auth/telegram", json={"init_data": telegram_identity(user.telegram_id)})
        assert auth.status_code == 200
        response = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", json={
            "credential_type": "password", "secret": "  exact password  ",
        })
        assert response.status_code == 200
        result = await asyncio.wait_for(action_task, 5)
        assert result.error is None
        assert shared["https://*.vercel.com"]["vercel_pass"] == "  exact password  "
        assert "vercel_user" not in shared["https://*.vercel.com"]
        assert "vercel_bu_2fa_code" not in shared["https://*.vercel.com"]
        assert task.state == TaskState.RUNNING
        assert task_registry.get_credential_input(task.task_id) is None
        assert "companion_url" not in task.metadata
        async with async_session_factory() as db:
            credentials = await CredentialRepository.get_credentials_for_domain(db, user.id, "vercel.com")
            password = next(c for c in credentials if c.auth_type == "password")
            assert password.encrypted_blob != "  exact password  "
            assert decrypt_secret(password.encrypted_blob, settings.vault_key_bytes) == "  exact password  "
            saved = await TaskRepository.get_task(db, task.task_id)
            assert saved.state == TaskState.RUNNING
            assert "exact password" not in saved.model_dump_json()
        assert "token" in parse_qs(link.query)
        reopened = await async_client.get(f"{link.path}?{link.query}")
        assert reopened.status_code == 410
    finally:
        if not action_task.done():
            action_task.cancel()
            await asyncio.gather(action_task, return_exceptions=True)


async def test_credential_timeout_is_terminal_and_cleans_up(monkeypatch):
    monkeypatch.setattr("app.browser.controller.CREDENTIAL_INPUT_TIMEOUT", 0.05)
    user = await vault_user()
    task = TaskRecord(user_id=user.telegram_id, chat_id=user.telegram_id, prompt="Login")
    status = SimpleNamespace(update=AsyncMock())
    controller = SecureController(user_id=user.id, task=task, status_manager=status)
    result = await request_action(controller)(domain="vercel.com", browser_session=browser_at())
    assert "timed out" in result.error
    assert task.state == TaskState.FAILED
    assert task_registry.get_credential_input(task.task_id) is None
    assert "companion_url" not in task.metadata
    assert controller.sensitive_data == {}
    async with async_session_factory() as db:
        assert (await TaskRepository.get_task(db, task.task_id)).state == TaskState.FAILED


async def test_cancelling_wait_cleans_up():
    user = await vault_user()
    task = TaskRecord(user_id=user.telegram_id, chat_id=user.telegram_id, prompt="Login")
    ready = asyncio.Event()
    status = SimpleNamespace(update=AsyncMock(side_effect=lambda *args, **kwargs: ready.set()))
    controller = SecureController(user_id=user.id, task=task, status_manager=status)
    running = asyncio.create_task(request_action(controller)(domain="vercel.com", browser_session=browser_at()))
    await asyncio.wait_for(ready.wait(), 5)
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    assert task.state == TaskState.FAILED
    assert task_registry.get_credential_input(task.task_id) is None
    assert "companion_url" not in task.metadata


async def test_first_task_can_provision_webapp_identity():
    task = TaskRecord(user_id=uuid.uuid4().int % 10**12, chat_id=1, prompt="Login")
    controller = SecureController(task=task)
    user_id = await controller._resolve_user_id()
    assert user_id is not None
    async with async_session_factory() as db:
        assert (await UserRepository.get_by_telegram_id(db, task.user_id)).id == user_id


async def test_submission_crossing_deadline_cannot_overwrite_failed_state(async_client, monkeypatch):
    from app.companion.auth import SESSION_COOKIE_NAME, create_session_token

    monkeypatch.setattr("app.browser.controller.CREDENTIAL_INPUT_TIMEOUT", 0.2)
    user = await vault_user()
    task = TaskRecord(user_id=user.telegram_id, chat_id=user.telegram_id, prompt="Login")
    ready = asyncio.Event()
    saving = asyncio.Event()
    release_save = asyncio.Event()
    status = SimpleNamespace(update=AsyncMock(side_effect=lambda *args, **kwargs: ready.set()))
    original_save = TaskRepository.save_task

    async def delayed_save(db, record):
        if record.task_id == task.task_id and record.state == TaskState.RUNNING:
            saving.set()
            await release_save.wait()
        return await original_save(db, record)

    monkeypatch.setattr(TaskRepository, "save_task", delayed_save)
    controller = SecureController(user_id=user.id, task=task, status_manager=status)
    running = asyncio.create_task(request_action(controller)(domain="vercel.com", browser_session=browser_at()))
    submission = None
    try:
        await asyncio.wait_for(ready.wait(), 5)
        async_client.cookies.set(SESSION_COOKIE_NAME, create_session_token(user.id, user.telegram_id))
        submission = asyncio.create_task(async_client.post(
            f"/api/tasks/{task.task_id}/resolve-input", json={"credential_type": "password", "secret": "late-password"},
        ))
        await asyncio.wait_for(saving.wait(), 5)
        # The controller times out while the submission holds the persistence lock.
        await asyncio.sleep(0.25)
        release_save.set()
        response, result = await asyncio.wait_for(asyncio.gather(submission, running), 5)
        assert response.status_code == 409
        assert "timed out" in result.error
        assert task.state == TaskState.FAILED
        async with async_session_factory() as db:
            assert (await TaskRepository.get_task(db, task.task_id)).state == TaskState.FAILED
    finally:
        release_save.set()
        for future in (running, submission):
            if future is not None and not future.done():
                future.cancel()
                await asyncio.gather(future, return_exceptions=True)
