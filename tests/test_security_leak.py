import logging
from unittest.mock import AsyncMock, MagicMock
import pytest
import pytest_asyncio

from browser_use.browser.events import TypeTextEvent

from app.browser.controller import SecureController
from app.config import settings
from app.db.engine import async_session_factory, init_db
from app.db.repository import CredentialRepository, UserRepository
from app.security.sanitizer import contains_sensitive_data, sanitize_log
from app.security.vault import encrypt_secret

CANARY_PASSWORD = "CANARY_SECRET_PWD_999888_ABCXYZ"
CANARY_API_KEY = "sk-ant-api03-canarysecretkey999888777666555444333"
CANARY_TOTP_SEED = "JBSWY3DPEHPK3PXP"


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


@pytest.mark.asyncio
async def test_canary_password_never_leaks(caplog):
    """End-to-End canary verification: password never appears in results or logs (Step 4 Component 6)."""
    caplog.set_level(logging.DEBUG)
    telegram_id = 99112233

    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        blob = encrypt_secret(CANARY_PASSWORD, settings.vault_key_bytes)
        await CredentialRepository.add_or_update_credential(
            session,
            user_id=user.id,
            site_domain="vercel.com",
            auth_type="password",
            encrypted_blob=blob,
            username_or_identifier="canary_user@example.com",
        )
        await session.commit()

    controller = SecureController(user_id=user.id)

    mock_page = MagicMock()
    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)
    mock_browser_session.get_current_page_url = AsyncMock(return_value="https://vercel.com/login")
    mock_browser_session.event_bus = MagicMock()
    mock_browser_session.event_bus.dispatch = MagicMock(return_value=None)

    inject_fn = controller.registry.registry.actions["inject_credential"].function
    result = await inject_fn(slot="password", domain="vercel.com", browser_session=mock_browser_session)

    # 1. Action result verification
    assert result.error is None
    assert CANARY_PASSWORD not in (result.extracted_content or "")
    if result.error:
        assert CANARY_PASSWORD not in result.error

    # 2. Event bus dispatch verification
    mock_browser_session.event_bus.dispatch.assert_called_once()
    dispatched = mock_browser_session.event_bus.dispatch.call_args[0][0]
    assert isinstance(dispatched, TypeTextEvent)
    assert dispatched.is_sensitive is True
    assert dispatched.sensitive_key_name == "password"

    # 3. Log inspection: secret must NEVER appear anywhere in caplog
    assert CANARY_PASSWORD not in caplog.text


@pytest.mark.asyncio
async def test_canary_api_key_never_leaks(caplog):
    """End-to-End canary verification: API key never appears in results or logs (Step 4 Component 6)."""
    caplog.set_level(logging.DEBUG)
    telegram_id = 99112244

    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        blob = encrypt_secret(CANARY_API_KEY, settings.vault_key_bytes)
        await CredentialRepository.add_or_update_credential(
            session,
            user_id=user.id,
            site_domain="github.com",
            auth_type="api_key",
            encrypted_blob=blob,
        )
        await session.commit()

    controller = SecureController(user_id=user.id)

    mock_page = MagicMock()
    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)
    mock_browser_session.get_current_page_url = AsyncMock(return_value="https://github.com/settings")
    mock_browser_session.event_bus = MagicMock()
    mock_browser_session.event_bus.dispatch = MagicMock(return_value=None)

    inject_fn = controller.registry.registry.actions["inject_credential"].function
    result = await inject_fn(slot="api_key", domain="github.com", browser_session=mock_browser_session)

    assert result.error is None
    assert CANARY_API_KEY not in (result.extracted_content or "")
    assert CANARY_API_KEY not in caplog.text

    dispatched = mock_browser_session.event_bus.dispatch.call_args[0][0]
    assert dispatched.is_sensitive is True
    assert dispatched.sensitive_key_name == "api_key"


@pytest.mark.asyncio
async def test_canary_totp_seed_never_leaks(caplog):
    """End-to-End canary verification: TOTP seed never appears in results or logs (Step 4 Component 6)."""
    caplog.set_level(logging.DEBUG)
    telegram_id = 99112255

    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        blob = encrypt_secret(CANARY_TOTP_SEED, settings.vault_key_bytes)
        await CredentialRepository.add_or_update_credential(
            session,
            user_id=user.id,
            site_domain="vercel.com",
            auth_type="totp_seed",
            encrypted_blob=blob,
        )
        await session.commit()

    controller = SecureController(user_id=user.id)

    mock_page = MagicMock()
    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)
    mock_browser_session.get_current_page_url = AsyncMock(return_value="https://vercel.com/login")
    mock_browser_session.event_bus = MagicMock()
    mock_browser_session.event_bus.dispatch = MagicMock(return_value=None)

    inject_totp_fn = controller.registry.registry.actions["inject_totp"].function
    result = await inject_totp_fn(domain="vercel.com", browser_session=mock_browser_session)

    assert result.error is None
    assert CANARY_TOTP_SEED not in (result.extracted_content or "")
    assert CANARY_TOTP_SEED not in caplog.text


def test_canary_sanitizer_redaction():
    """Verify that the sanitizer detects and redacts canary secrets from raw log lines."""
    raw_message = f"Connecting with password: {CANARY_PASSWORD} and key {CANARY_API_KEY} and seed {CANARY_TOTP_SEED}"
    sanitized = sanitize_log(raw_message)

    assert CANARY_PASSWORD not in sanitized
    assert CANARY_API_KEY not in sanitized
    assert CANARY_TOTP_SEED not in sanitized
    assert "[REDACTED_SECRET]" in sanitized

