from unittest.mock import AsyncMock, MagicMock, create_autospec
import pytest
import pytest_asyncio

from browser_use.browser.events import TypeTextEvent
from browser_use.browser.session import BrowserSession
from browser_use.dom.views import EnhancedDOMTreeNode, NodeType

from app.browser.controller import (
    SecureController,
    clean_domain,
    validate_origin,
    verify_active_focus_editable,
    create_root_dom_node,
)
from app.db.engine import async_session_factory, init_db
from app.db.repository import CredentialRepository, UserRepository
from app.security.vault import encrypt_secret
from app.config import settings


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Ensure schema is initialized."""
    await init_db()


def make_test_dom_node(index: int = 1, tag: str = "input", backend_id: int = 101) -> EnhancedDOMTreeNode:
    """Helper creating a valid EnhancedDOMTreeNode for tests."""
    return EnhancedDOMTreeNode(
        node_id=index,
        backend_node_id=backend_id,
        node_type=NodeType.ELEMENT_NODE,
        node_name=tag.upper(),
        node_value="",
        attributes={"type": "password"},
        is_scrollable=False,
        is_visible=True,
        absolute_position=None,
        target_id="target-1",
        frame_id="frame-1",
        session_id="session-1",
        content_document=None,
        shadow_root_type=None,
        shadow_roots=None,
        parent_node=None,
        children_nodes=None,
        ax_node=None,
        snapshot_node=None,
    )


def test_clean_domain_utility():
    assert clean_domain("https://vercel.com/login") == "vercel.com"
    assert clean_domain("http://www.github.com/settings") == "github.com"
    assert clean_domain("app.supabase.com:8080/dashboard") == "app.supabase.com"
    assert clean_domain("subdomain.example.co.uk/") == "subdomain.example.co.uk"
    assert clean_domain("") == ""


def test_validate_origin_rules():
    """Tests anti-phishing strict origin validation rules (Step 4 Component 2)."""
    # Valid HTTPS matches
    assert validate_origin("https://vercel.com/login", "vercel.com")[0] is True
    assert validate_origin("https://www.vercel.com/login", "vercel.com")[0] is True
    assert validate_origin("https://app.vercel.com/dashboard", "vercel.com")[0] is True
    assert validate_origin("https://auth.api.vercel.com/v1/auth", "vercel.com")[0] is True

    # Phishing / domain spoofing attacks rejected
    assert validate_origin("https://evil-vercel.com/login", "vercel.com")[0] is False
    assert validate_origin("https://vercel.com.attacker.com/login", "vercel.com")[0] is False
    assert validate_origin("https://fake-login-vercel.com", "vercel.com")[0] is False
    assert validate_origin("https://notvercel.com", "vercel.com")[0] is False

    # Insecure remote HTTP rejected
    assert validate_origin("http://github.com/login", "github.com")[0] is False
    assert validate_origin("http://my-bank.com/login", "my-bank.com")[0] is False

    # Local development HTTP allowed
    assert validate_origin("http://localhost:3000/login", "localhost")[0] is True
    assert validate_origin("http://127.0.0.1:8000/login", "127.0.0.1")[0] is True

    # Dangerous / non-HTTP schemes rejected
    assert validate_origin("javascript:alert(1)", "vercel.com")[0] is False
    assert validate_origin("data:text/html,evil", "vercel.com")[0] is False
    assert validate_origin("file:///etc/passwd", "localhost")[0] is False

    # Empty inputs rejected
    assert validate_origin("", "vercel.com")[0] is False
    assert validate_origin("https://vercel.com/login", "")[0] is False


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

    # Mock BrowserSession and event_bus
    mock_page = MagicMock()
    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)
    mock_browser_session.get_current_page_url = AsyncMock(return_value="https://vercel.com/login")
    mock_browser_session.event_bus = MagicMock()
    mock_browser_session.event_bus.dispatch = MagicMock(return_value=None)

    # Retrieve and execute action
    inject_fn = controller.registry.registry.actions["inject_credential"].function
    result = await inject_fn(slot="password", domain="vercel.com", browser_session=mock_browser_session)

    # Verify native CDP TypeTextEvent was dispatched on event_bus with is_sensitive=True
    mock_browser_session.event_bus.dispatch.assert_called_once()
    dispatched_event = mock_browser_session.event_bus.dispatch.call_args[0][0]
    assert isinstance(dispatched_event, TypeTextEvent)
    assert dispatched_event.text == secret_password
    assert dispatched_event.is_sensitive is True
    assert dispatched_event.sensitive_key_name == "password"

    # Verify result content never leaks the password
    assert result.error is None
    assert "[SUCCESS] Password" in result.extracted_content
    assert secret_password not in result.extracted_content


@pytest.mark.asyncio
async def test_inject_credential_with_element_index():
    """Verify targeted keystroke injection using element index (Step 4 Component 1)."""
    telegram_id = 11223355
    secret_password = "TargetedElementPassword456!"

    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        blob = encrypt_secret(secret_password, settings.vault_key_bytes)
        await CredentialRepository.add_or_update_credential(
            session,
            user_id=user.id,
            site_domain="vercel.com",
            auth_type="password",
            encrypted_blob=blob,
        )
        await session.commit()

    controller = SecureController(user_id=user.id)

    mock_page = MagicMock()
    target_node = make_test_dom_node(index=7, tag="input", backend_id=505)

    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)
    mock_browser_session.get_current_page_url = AsyncMock(return_value="https://vercel.com/login")
    mock_browser_session.get_element_by_index = AsyncMock(return_value=target_node)
    mock_browser_session.event_bus = MagicMock()
    mock_browser_session.event_bus.dispatch = MagicMock(return_value=None)

    inject_fn = controller.registry.registry.actions["inject_credential"].function
    result = await inject_fn(
        slot="password",
        domain="vercel.com",
        index=7,
        browser_session=mock_browser_session,
    )

    mock_browser_session.get_element_by_index.assert_called_once_with(7)
    mock_browser_session.event_bus.dispatch.assert_called_once()
    dispatched = mock_browser_session.event_bus.dispatch.call_args[0][0]
    assert dispatched.node == target_node
    assert dispatched.text == secret_password
    assert result.error is None


@pytest.mark.asyncio
async def test_inject_credential_missing_element_index_fails_closed():
    """Verify that targeting an invalid or expired element index fails closed immediately."""
    telegram_id = 11223366
    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        blob = encrypt_secret("some_pass", settings.vault_key_bytes)
        await CredentialRepository.add_or_update_credential(
            session,
            user_id=user.id,
            site_domain="vercel.com",
            auth_type="password",
            encrypted_blob=blob,
        )
        await session.commit()

    controller = SecureController(user_id=user.id)

    mock_page = MagicMock()
    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)
    mock_browser_session.get_current_page_url = AsyncMock(return_value="https://vercel.com/login")
    # Element index 99 does not exist on page
    mock_browser_session.get_element_by_index = AsyncMock(return_value=None)
    mock_browser_session.event_bus = MagicMock()

    inject_fn = controller.registry.registry.actions["inject_credential"].function
    result = await inject_fn(
        slot="password",
        domain="vercel.com",
        index=99,
        browser_session=mock_browser_session,
    )

    assert result.error is not None
    assert "Element index 99 not found on page" in result.error
    mock_browser_session.event_bus.dispatch.assert_not_called()


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
    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)
    mock_browser_session.get_current_page_url = AsyncMock(return_value="https://github.com/login")
    mock_browser_session.event_bus = MagicMock()
    mock_browser_session.event_bus.dispatch = MagicMock(return_value=None)

    inject_fn = controller.registry.registry.actions["inject_credential"].function
    result = await inject_fn(slot="username", domain="github.com", browser_session=mock_browser_session)

    mock_browser_session.event_bus.dispatch.assert_called_once()
    dispatched = mock_browser_session.event_bus.dispatch.call_args[0][0]
    assert dispatched.text == username
    assert dispatched.is_sensitive is True
    assert dispatched.sensitive_key_name == "username"
    assert "[SUCCESS] Username" in result.extracted_content


@pytest.mark.asyncio
async def test_inject_credential_missing_domain_returns_error():
    controller = SecureController(user_id="00000000-0000-0000-0000-000000000001")

    mock_page = MagicMock()
    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)
    mock_browser_session.get_current_page_url = AsyncMock(return_value="https://nonexistent.org/login")

    inject_fn = controller.registry.registry.actions["inject_credential"].function
    result = await inject_fn(slot="password", domain="nonexistent.org", browser_session=mock_browser_session)

    assert result.error is not None
    assert "No stored credentials found" in result.error


@pytest.mark.asyncio
async def test_inject_credential_phishing_origin_mismatch_rejected():
    """Verify that credentials are NEVER injected into a phishing site with mismatched origin."""
    telegram_id = 77889900
    secret_password = "SecretPasswordToProtect!"

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

    mock_page = MagicMock()
    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)
    # Active page is on a phishing site pretending to be vercel
    mock_browser_session.get_current_page_url = AsyncMock(return_value="https://evil-phishing-vercel.com/login")
    mock_browser_session.event_bus = MagicMock()

    inject_fn = controller.registry.registry.actions["inject_credential"].function
    # LLM requests vercel.com credentials while on phishing domain
    result = await inject_fn(slot="password", domain="vercel.com", browser_session=mock_browser_session)

    # Must be blocked by origin verification
    assert result.error is not None
    assert "Security violation: Origin verification failed" in result.error
    assert "does not match target domain" in result.error

    # Ensure keystrokes were NEVER dispatched
    mock_browser_session.event_bus.dispatch.assert_not_called()


@pytest.mark.asyncio
async def test_inject_credential_insecure_http_rejected():
    """Verify that credentials are rejected if the page is on insecure HTTP (remote domain)."""
    telegram_id = 33445566
    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        blob = encrypt_secret("some_pass", settings.vault_key_bytes)
        await CredentialRepository.add_or_update_credential(
            session,
            user_id=user.id,
            site_domain="github.com",
            auth_type="password",
            encrypted_blob=blob,
        )
        await session.commit()

    controller = SecureController(user_id=user.id)

    mock_page = MagicMock()
    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)
    mock_browser_session.get_current_page_url = AsyncMock(return_value="http://github.com/login")
    mock_browser_session.event_bus = MagicMock()

    inject_fn = controller.registry.registry.actions["inject_credential"].function
    result = await inject_fn(slot="password", domain="github.com", browser_session=mock_browser_session)

    assert result.error is not None
    assert "Insecure HTTP scheme rejected" in result.error
    mock_browser_session.event_bus.dispatch.assert_not_called()


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
    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)
    mock_browser_session.get_current_page_url = AsyncMock(return_value="https://vercel.com/login")
    mock_browser_session.event_bus = MagicMock()
    mock_browser_session.event_bus.dispatch = MagicMock(return_value=None)

    inject_totp_fn = controller.registry.registry.actions["inject_totp"].function
    result = await inject_totp_fn(domain="vercel.com", browser_session=mock_browser_session)

    assert result.error is None
    assert "[SUCCESS] 6-digit TOTP code" in result.extracted_content
    assert totp_seed not in result.extracted_content

    # Check that typed code was dispatched via event_bus
    mock_browser_session.event_bus.dispatch.assert_called_once()
    dispatched = mock_browser_session.event_bus.dispatch.call_args[0][0]
    assert isinstance(dispatched, TypeTextEvent)
    assert len(dispatched.text) == 6
    assert dispatched.text.isdigit()
    assert dispatched.is_sensitive is True


@pytest.mark.asyncio
async def test_inject_totp_post_drift_navigation_abort():
    """Verify that if page navigates away during TOTP computation, injection is aborted."""
    telegram_id = 44556677
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
    mock_browser_session = MagicMock()
    mock_browser_session.must_get_current_page = AsyncMock(return_value=mock_page)

    # First call before TOTP: valid vercel.com
    # Second call after TOTP sleep: hijacked / navigated to attacker site
    mock_browser_session.get_current_page_url = AsyncMock(
        side_effect=["https://vercel.com/login", "https://attacker-hijack.com/login"]
    )
    mock_browser_session.event_bus = MagicMock()

    inject_totp_fn = controller.registry.registry.actions["inject_totp"].function
    result = await inject_totp_fn(domain="vercel.com", browser_session=mock_browser_session)

    assert result.error is not None
    assert "Security violation: Page navigated or changed origin during TOTP generation" in result.error
    mock_browser_session.event_bus.dispatch.assert_not_called()
