from unittest.mock import AsyncMock, MagicMock
import pytest
import pytest_asyncio

from app.browser.controller import SecureController, clean_domain
from app.db.engine import async_session_factory, init_db
from app.db.repository import CredentialRepository, UserRepository
from app.security.vault import encrypt_secret
from app.config import settings


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Ensure schema is initialized."""
    await init_db()


def test_clean_domain_utility():
    assert clean_domain("https://vercel.com/login") == "vercel.com"
    assert clean_domain("http://www.github.com/settings") == "github.com"
    assert clean_domain("app.supabase.com:8080/dashboard") == "app.supabase.com"
    assert clean_domain("subdomain.example.co.uk/") == "subdomain.example.co.uk"
    assert clean_domain("") == ""


@pytest.mark.asyncio
async def test_controller_action_registration():
    controller = SecureController(telegram_id=12345)
    actions = controller.registry.registry.actions
    assert "inject_credential" in actions
    assert "inject_totp" in actions


@pytest.mark.asyncio
async def test_inject_credential_password_success():
    telegram_id = 11223344
    secret_password = "SuperSecurePassword123!"

    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        blob = encrypt_secret(secret_password, settings.vault_key_bytes)
        await CredentialRepository.add_or_update_credential(
            session,
            user_id=user.id,
            site_domain="vercel.com",
            auth_type="password",
            encrypted_blob=blob,
            username_or_identifier="admin@vercel.com",
        )
        await session.commit()

    controller = SecureController(user_id=user.id)

    # Mock Playwright Page and BrowserSession
    mock_page = MagicMock()
    mock_page.keyboard = MagicMock()
    mock_page.keyboard.type = AsyncMock()

    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)
    mock_browser_session.get_current_page_url = AsyncMock(return_value="https://vercel.com/login")

    # Retrieve and execute action
    inject_fn = controller.registry.registry.actions["inject_credential"].function
    result = await inject_fn(slot="password", domain="vercel.com", browser_session=mock_browser_session)

    # Verify Playwright keyboard was called with the plaintext password
    mock_page.keyboard.type.assert_called_once_with(secret_password, delay=50)

    # Verify result content never leaks the password
    assert result.error is None
    assert "[SUCCESS] Password" in result.extracted_content
    assert secret_password not in result.extracted_content


@pytest.mark.asyncio
async def test_inject_credential_username():
    telegram_id = 99881122
    username = "my_user@company.com"

    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        blob = encrypt_secret("some_pass", settings.vault_key_bytes)
        await CredentialRepository.add_or_update_credential(
            session,
            user_id=user.id,
            site_domain="github.com",
            auth_type="password",
            encrypted_blob=blob,
            username_or_identifier=username,
        )
        await session.commit()

    controller = SecureController(user_id=user.id)

    mock_page = MagicMock()
    mock_page.keyboard = MagicMock()
    mock_page.keyboard.type = AsyncMock()

    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)

    inject_fn = controller.registry.registry.actions["inject_credential"].function
    result = await inject_fn(slot="username", domain="github.com", browser_session=mock_browser_session)

    mock_page.keyboard.type.assert_called_once_with(username, delay=50)
    assert "[SUCCESS] Username" in result.extracted_content


@pytest.mark.asyncio
async def test_inject_credential_missing_domain_returns_error():
    controller = SecureController(user_id="00000000-0000-0000-0000-000000000001")

    mock_page = MagicMock()
    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)

    inject_fn = controller.registry.registry.actions["inject_credential"].function
    result = await inject_fn(slot="password", domain="nonexistent.org", browser_session=mock_browser_session)

    assert result.error is not None
    assert "No stored credentials found" in result.error


@pytest.mark.asyncio
async def test_inject_totp_success():
    telegram_id = 55443322
    totp_seed = "JBSWY3DPEHPK3PXP"

    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        blob = encrypt_secret(totp_seed, settings.vault_key_bytes)
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
    mock_page.keyboard = MagicMock()
    mock_page.keyboard.type = AsyncMock()

    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)

    inject_totp_fn = controller.registry.registry.actions["inject_totp"].function
    result = await inject_totp_fn(domain="vercel.com", browser_session=mock_browser_session)

    assert result.error is None
    assert "[SUCCESS] 6-digit TOTP code" in result.extracted_content
    assert totp_seed not in result.extracted_content

    # Check that typed code was 6 digits
    typed_code = mock_page.keyboard.type.call_args[0][0]
    assert len(typed_code) == 6
    assert typed_code.isdigit()
