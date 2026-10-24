import json
from pathlib import Path
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import pytest_asyncio

from app.browser.agent import create_agent
from app.browser.controller import SecureController
from app.browser.context import browser_session_context, create_browser
from app.browser.runner import run_browser_task
from app.config import settings
from app.db.engine import async_session_factory, init_db
from app.db.repository import BrowserProfileRepository, UserRepository
from app.security.vault import decrypt_secret
from app.tasks.state import TaskRecord
from app.tasks.state import TaskState


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


def test_agent_receives_sensitive_data_and_placeholders():
    """Verify that create_agent properly configures sensitive_data and system prompt."""
    sens_data = {
        "vercel_user": "test_user",
        "vercel_pass": "test_pass",
        "vercel_bu_2fa_code": "JBSWY3DPEHPK3PXP",
    }
    agent = create_agent(
        task="Login to vercel.com",
        llm=MagicMock(),
        sensitive_data=sens_data,
        use_vision=False,
    )
    # Check that sensitive_data is attached to agent
    assert agent.sensitive_data == sens_data
    # Check that placeholders are announced in system prompt
    assert "vercel_user" in str(agent.message_manager.system_prompt)
    assert "vercel_pass" in str(agent.message_manager.system_prompt)
    assert agent.settings.use_vision is False


def test_browser_allowed_domains_applied():
    """Verify that create_browser configures allowed_domains in BrowserProfile."""
    allowed = ["*.vercel.com", "vercel.com"]
    browser = create_browser(allowed_domains=allowed)
    assert browser.browser_profile.allowed_domains == allowed


@pytest.mark.parametrize("provided", [False, True])
def test_empty_sensitive_data_is_shared_with_controller_agent_and_messages(provided):
    shared = {}
    kwargs = {"sensitive_data": shared} if provided else {}
    with patch("app.browser.agent.Agent") as agent_class:
        create_agent(task="Login", llm=MagicMock(), telegram_id=123, **kwargs)
        passed = agent_class.call_args.kwargs
        controller = passed["controller"]
        assert isinstance(controller, SecureController)
        assert controller.sensitive_data is passed["sensitive_data"]
        if provided:
            assert controller.sensitive_data is shared
        assert passed["step_timeout"] >= 240

    # Also check the real upstream Agent / MessageManager don't copy an empty map.
    agent = create_agent(task="Login", llm=MagicMock(), sensitive_data=shared, use_vision=False)
    assert agent.sensitive_data is shared
    assert agent._message_manager.sensitive_data is shared
    shared["https://*.example.com"] = {"example_pass": "private"}
    description = agent._message_manager._get_sensitive_data_description("https://example.com/login")
    assert "example_pass" in description
    assert "private" not in description


async def test_agent_stop_callback_tracks_task_failure():
    task = TaskRecord(user_id=1, chat_id=1, prompt="Login")
    with patch("app.browser.agent.Agent") as agent_class:
        create_agent(task="Login", llm=MagicMock(), task_record=task)
        callback = agent_class.call_args.kwargs["register_should_stop_callback"]
        assert await callback() is False
        task.transition_to(TaskState.FAILED, error="Credential request expired")
        assert await callback() is True


@pytest.mark.asyncio
async def test_encrypted_storage_state_roundtrip():
    """Verify that browser profile storage states are AES-256-GCM encrypted in database."""
    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id=77665544)
        await session.commit()
        user_id = user.id

    site_domain = "vercel.com"
    dummy_cookie_data = {
        "cookies": [{"name": "auth_token", "value": "SUPER_SECRET_SESSION_TOKEN_12345", "domain": ".vercel.com", "path": "/"}],
        "origins": [],
    }

    mock_browser = MagicMock()
    mock_browser.start = AsyncMock()
    mock_browser.stop = AsyncMock()
    mock_browser.export_storage_state = AsyncMock(return_value=dummy_cookie_data)
    mock_browser._cdp_get_origins = AsyncMock(return_value=[])

    # Run browser session context to trigger save_profile in finally block
    async with browser_session_context(
        browser=mock_browser,
        user_id=user_id,
        site_domain=site_domain,
    ):
        pass

    # Inspect the saved database record
    async with async_session_factory() as db:
        profile = await BrowserProfileRepository.get_profile(db, user_id, site_domain)
        assert profile is not None
        # Must NOT contain plaintext session token
        assert "SUPER_SECRET_SESSION_TOKEN_12345" not in profile.storage_state_json
        # Must decrypt cleanly with master key
        decrypted_json = decrypt_secret(profile.storage_state_json, settings.vault_key_bytes)
        parsed = json.loads(decrypted_json)
        assert parsed["cookies"][0]["value"] == "SUPER_SECRET_SESSION_TOKEN_12345"


@pytest.mark.asyncio
async def test_all_intermediate_screenshots_purged():
    """Verify that all intermediate screenshots generated across steps are deleted on completion."""
    with tempfile.TemporaryDirectory() as temp_dir:
        dir_path = Path(temp_dir)
        ss1 = dir_path / "step_1.png"
        ss2 = dir_path / "step_2.png"
        ss3 = dir_path / "step_3.png"
        
        valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
        ss1.write_bytes(valid_png)
        ss2.write_bytes(valid_png)
        ss3.write_bytes(valid_png)

        mock_history = MagicMock()
        mock_history.screenshot_paths.return_value = [str(ss1), str(ss2), str(ss3)]
        mock_history.final_result.return_value = "Done"

        mock_agent = MagicMock()
        mock_agent.run = AsyncMock(return_value=mock_history)

        mock_browser = MagicMock()
        mock_browser.take_screenshot = AsyncMock(return_value=valid_png)

        mock_bot = MagicMock()
        mock_bot.send_photo = AsyncMock()
        mock_status_mgr = MagicMock()
        mock_status_mgr.update = AsyncMock()

        task = TaskRecord(user_id=1, chat_id=1, prompt="Test screenshot purge")

        with patch("app.browser.runner.browser_session_context") as mock_ctx_factory, \
             patch("app.browser.runner.create_agent", return_value=mock_agent):
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value = mock_browser
            mock_ctx.__aexit__.return_value = None
            mock_ctx_factory.return_value = mock_ctx

            await run_browser_task(task, mock_status_mgr, mock_bot, max_steps=5)

        # Assert all three screenshot files were deleted by finally cleanup
        assert not ss1.exists()
        assert not ss2.exists()
        assert not ss3.exists()
