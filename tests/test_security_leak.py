import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
import uuid

import pyotp
import pytest
import pytest_asyncio
from browser_use.browser.events import TypeTextEvent
from browser_use.dom.views import EnhancedDOMTreeNode, NodeType
from browser_use.tools.views import InputTextAction

from app.browser.controller import SecureController
from app.browser.credentials_resolver import credential_scope
from app.config import settings
from app.db.engine import async_session_factory, init_db
from app.db.repository import CredentialRepository, UserRepository
from app.security.sanitizer import sanitize_log
from app.security.vault import encrypt_secret

CANARY_PASSWORD = "CANARY_SECRET_PWD_999888_ABCXYZ"
CANARY_API_KEY = "sk-ant-api03-canarysecretkey999888777666555444333"
CANARY_TOTP_SEED = "JBSWY3DPEHPK3PXP"


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


class TypedEvent:
    def __await__(self):
        return self.wait().__await__()

    async def wait(self):
        return self

    async def event_result(self, **kwargs):
        return {}


def input_browser_at(url="https://vercel.com/login"):
    browser = MagicMock()
    browser.get_current_page_url = AsyncMock(return_value=url)
    browser.browser_profile = SimpleNamespace(allowed_domains=None)
    browser.agent_focus_target_id = "target"
    browser.session_manager.get_target.return_value = SimpleNamespace(url=url)
    browser.get_element_by_index = AsyncMock(return_value=EnhancedDOMTreeNode(
        node_id=1, backend_node_id=101, node_type=NodeType.ELEMENT_NODE, node_name="INPUT",
        node_value="", attributes={"type": "password"}, is_scrollable=False, is_visible=True,
        absolute_position=None, target_id="target", frame_id="frame", session_id="session",
        content_document=None, shadow_root_type=None, shadow_roots=None, parent_node=None,
        children_nodes=None, ax_node=None, snapshot_node=None,
    ))
    browser.highlight_interaction_element = AsyncMock()
    browser.event_bus.dispatch.return_value = TypedEvent()
    return browser


@pytest.mark.parametrize("text, url, value", [
    ("<secret>need_password(domain='auth.wikimedia.org')</secret>", "https://auth.wikimedia.org/login", None),
    ("<secret>need_password(domain='auth.wikimedia.org')</secret>", "https://auth.wikimedia.org/login", CANARY_PASSWORD),
    ("<secret>wikimedia_pass</secret>", "https://auth.wikimedia.org/login", None),
    ("<secret>wikimedia_pass</secret>", "https://auth.wikimedia.org/login", ""),
    ("<secret>wikimedia_pass</secret>", "https://attacker.com/login", CANARY_PASSWORD),
    ("<secret>wikimedia_pass</secret>", "http://auth.wikimedia.org/login", CANARY_PASSWORD),
    ("<secret>wikimedia_pass</secret>", "about:blank", CANARY_PASSWORD),
    ("<secret>missing</secret>", "https://auth.wikimedia.org/login", CANARY_PASSWORD),
    ("<secret>wikimedia_pass</secret><secret>missing</secret>", "https://auth.wikimedia.org/login", CANARY_PASSWORD),
    ("<secret>wikimedia_pass", "https://auth.wikimedia.org/login", CANARY_PASSWORD),
    ("wikimedia_pass</secret>", "https://auth.wikimedia.org/login", CANARY_PASSWORD),
    ("<secret></secret>", "https://auth.wikimedia.org/login", CANARY_PASSWORD),
])
async def test_native_input_blocks_unresolved_secret_tags_before_typing(text, url, value):
    data = {} if value is None else {"https://*.wikimedia.org": {"wikimedia_pass": value}}
    controller = SecureController(sensitive_data=data)
    browser = input_browser_at(url)
    action = controller.registry.create_action_model()(input={"index": 6, "text": text})

    result = await controller.act(action, browser_session=browser, sensitive_data=data)

    assert result.error and "placeholder" in result.error
    assert "need_password" in result.error
    browser.get_element_by_index.assert_not_awaited()
    browser.event_bus.dispatch.assert_not_called()
    assert CANARY_PASSWORD not in result.model_dump_json()


@pytest.mark.parametrize("text", ["Wikimedia", ""])
async def test_native_input_still_types_plain_text_and_clears_fields(text):
    controller = SecureController()
    browser = input_browser_at()
    action = controller.registry.create_action_model()(input={"index": 1, "text": text})

    result = await controller.act(action, browser_session=browser)

    assert result.error is None
    event = browser.event_bus.dispatch.call_args.args[0]
    assert isinstance(event, TypeTextEvent)
    assert event.text == text
    assert event.clear is True


@pytest.mark.parametrize("auth_type, slot, secret", [
    ("password", "vercel_pass", CANARY_PASSWORD),
    ("api_key", "vercel_api_key", CANARY_API_KEY),
    ("totp_seed", "vercel_bu_2fa_code", CANARY_TOTP_SEED),
])
async def test_native_input_keeps_vault_secrets_out_of_results_and_logs(auth_type, slot, secret, caplog):
    caplog.set_level(logging.DEBUG)
    async with async_session_factory() as db:
        user, _ = await UserRepository.get_or_create_by_telegram_id(db, uuid.uuid4().int % 10**12)
        await CredentialRepository.add_or_update_credential(
            db, user.id, "vercel.com", auth_type, encrypt_secret(secret, settings.vault_key_bytes),
        )
        await db.commit()
    controller = SecureController(user_id=user.id)
    browser = input_browser_at()
    requested = await controller.registry.registry.actions["request_domain_credentials"].function(
        domain="vercel.com", browser_session=browser,
    )
    assert requested.error is None
    browser.event_bus.dispatch.assert_not_called()

    # Exercise browser-use's own registered input, substitution, TOTP, and event dispatch.
    action_model = controller.registry.create_action_model()
    action = action_model(input={"index": 1, "text": f"<secret>{slot}</secret>"})
    result = await controller.act(action, browser_session=browser, sensitive_data=controller.sensitive_data)
    assert result.error is None
    event = browser.event_bus.dispatch.call_args.args[0]
    assert isinstance(event, TypeTextEvent)
    assert event.is_sensitive is True
    if auth_type == "totp_seed":
        assert pyotp.TOTP(secret).verify(event.text, valid_window=1)
        assert event.text != secret
    else:
        assert event.text == secret
        assert result.extracted_content in ("Typed sensitive data", f"Typed {slot}")
    assert secret not in requested.model_dump_json()
    assert secret not in result.model_dump_json()
    assert secret not in caplog.text
    assert event.text not in result.model_dump_json()


@pytest.mark.parametrize("url", ["https://attacker.com", "http://vercel.com", "https://vercel.com.evil.com", "https://github.com"])
def test_native_substitution_never_releases_other_origin_credentials(url):
    controller = SecureController(sensitive_data={"https://*.vercel.com": {"vercel_pass": CANARY_PASSWORD}})
    params = InputTextAction(index=1, text="<secret>vercel_pass</secret>")
    result = controller.registry._replace_sensitive_data(params, controller.sensitive_data, url)
    assert result.text == "<secret>vercel_pass</secret>"


@pytest.mark.parametrize("domain, url", [
    ("localhost", "http://localhost:3000/login"), ("127.0.0.1", "http://127.0.0.1:8000/login"),
    ("::1", "http://[::1]:8000/login"),
])
def test_native_substitution_supports_local_http_development(domain, url):
    data = {credential_scope(domain): {"local_pass": CANARY_PASSWORD}}
    controller = SecureController(sensitive_data=data)
    result = controller.registry._replace_sensitive_data(InputTextAction(index=1, text="<secret>local_pass</secret>"), data, url)
    assert result.text == CANARY_PASSWORD


async def test_non_input_actions_cannot_expand_secrets():
    controller = SecureController(sensitive_data={"https://*.vercel.com": {"vercel_pass": CANARY_PASSWORD}})

    @controller.action("Echo the literal argument for testing")
    async def echo_literal(value: str):
        return value

    browser = MagicMock()
    browser.get_current_page_url = AsyncMock(return_value="https://vercel.com")
    browser.agent_focus_target_id = "target"
    browser.session_manager.get_target.return_value = SimpleNamespace(url="https://vercel.com")
    action_model = controller.registry.create_action_model()
    action = action_model(echo_literal={"value": "<secret>vercel_pass</secret>"})
    result = await controller.act(action, browser_session=browser, sensitive_data=controller.sensitive_data)
    assert result.extracted_content == "<secret>vercel_pass</secret>"
    assert CANARY_PASSWORD not in result.model_dump_json()


def test_canary_sanitizer_redaction():
    raw = f"Connecting with password: {CANARY_PASSWORD} and key {CANARY_API_KEY} and seed {CANARY_TOTP_SEED}"
    sanitized = sanitize_log(raw)
    for secret in (CANARY_PASSWORD, CANARY_API_KEY, CANARY_TOTP_SEED):
        assert secret not in sanitized
    assert "[REDACTED_SECRET]" in sanitized
