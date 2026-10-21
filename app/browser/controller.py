import asyncio
import logging
import re
from typing import Optional, Union
import urllib.parse
import uuid

from browser_use import ActionResult, Controller
from browser_use.browser.session import BrowserSession

from app.config import settings
from app.db.engine import async_session_factory
from app.db.repository import CredentialRepository, UserRepository
from app.security.totp import get_safe_totp_code
from app.security.vault import decrypt_secret

logger = logging.getLogger(__name__)


def clean_domain(raw_domain: str) -> str:
    """
    Normalizes input URL or host into a canonical hostname.
    e.g. 'https://vercel.com/login' -> 'vercel.com', 'http://www.github.com' -> 'github.com'.
    """
    if not raw_domain:
        return ""
    raw = raw_domain.strip().lower()
    if "://" not in raw and not raw.startswith("//"):
        raw = f"//{raw}"
    try:
        parts = urllib.parse.urlsplit(raw)
        host = parts.hostname or ""
    except Exception:
        host = ""
    if not host:
        raw_s = raw_domain.strip().lower()
        raw_s = re.sub(r"^https?://", "", raw_s)
        raw_s = re.sub(r"^www\.", "", raw_s)
        return raw_s.split("/")[0].split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host


def validate_origin(page_url: str, expected_domain: str) -> tuple[bool, str]:
    """
    Validates that page_url matches expected_domain under strict anti-phishing rules:
    1. Scheme must be HTTPS, or HTTP only for local development (localhost, 127.0.0.1, ::1).
    2. Active page hostname must match expected_domain or be a direct subdomain (.expected_domain).
    """
    if not page_url or not page_url.strip():
        return False, "Active page URL is empty or unverified."
    if not expected_domain or not expected_domain.strip():
        return False, "Target credential domain is empty."

    try:
        parts = urllib.parse.urlsplit(page_url.strip())
    except Exception as exc:
        return False, f"Malformed active page URL: {exc}"

    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if not host:
        return False, "Active page URL has no valid hostname."

    is_local = host in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
    if scheme == "http":
        if not is_local:
            return False, f"Insecure HTTP scheme rejected for remote domain '{host}'. HTTPS is required."
    elif scheme != "https":
        return False, f"Invalid URL scheme '{scheme}'. Only HTTPS (or local HTTP) is permitted."

    active_host = host[4:] if host.startswith("www.") else host
    target_host = clean_domain(expected_domain)
    if not target_host:
        return False, "Target credential domain cannot be empty."

    if active_host == target_host or active_host.endswith(f".{target_host}"):
        return True, ""

    return False, f"Active page host '{active_host}' does not match target domain '{target_host}'."


class SecureController(Controller):
    """
    Custom Controller providing zero-knowledge keystroke injection for authenticated browser tasks.
    
    Exposes:
    - inject_credential: Types vaulted passwords or usernames directly into the active field.
    - inject_totp: Computes RFC 6238 TOTP codes server-side with drift protection and types them into 2FA fields.
    
    Guarantees:
    - Anti-phishing origin verification prevents credential leak into mismatched or unencrypted sites.
    - Post-drift URL re-verification prevents injection if page navigates during TOTP calculation.
    - Secrets are never returned to the LLM context or recorded in action histories.
    - Keystrokes are emitted via Playwright's CDP keyboard layer.
    """

    def __init__(
        self,
        user_id: Optional[Union[uuid.UUID, str]] = None,
        telegram_id: Optional[int] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if isinstance(user_id, str):
            try:
                self.user_id = uuid.UUID(user_id)
            except ValueError:
                self.user_id = None
        else:
            self.user_id = user_id
        self.telegram_id = telegram_id
        self._register_secure_actions()

    async def _resolve_user_id(self) -> Optional[uuid.UUID]:
        """Resolves User UUID from either self.user_id or self.telegram_id."""
        if self.user_id:
            return self.user_id
        if self.telegram_id:
            async with async_session_factory() as db:
                user = await UserRepository.get_by_telegram_id(db, self.telegram_id)
                if user:
                    self.user_id = user.id
                    return user.id
        return None

    def _register_secure_actions(self) -> None:
        @self.action(
            "Inject a vaulted credential (password, username, or API key) directly into the active focused input field on the page. "
            "Never exposes the secret to the LLM prompt or history."
        )
        async def inject_credential(
            slot: str = "password",
            domain: str = "",
            browser_session: Optional[BrowserSession] = None,
        ) -> ActionResult:
            if not browser_session:
                return ActionResult(error="No active browser session available for keystroke injection.")

            page = await browser_session.must_get_current_page()
            if not page:
                return ActionResult(error="No active page found in browser session.")

            # Retrieve active page URL for anti-phishing verification
            try:
                current_url = await browser_session.get_current_page_url()
            except Exception as exc:
                return ActionResult(error=f"Could not verify active page URL: {exc}")

            target_domain = clean_domain(domain)
            if not target_domain and current_url:
                target_domain = clean_domain(current_url)

            if not target_domain:
                return ActionResult(error="Could not determine target domain for credential lookup.")

            # Anti-Phishing Strict Origin Verification (Step 4 Component 2)
            is_valid, err_msg = validate_origin(current_url, target_domain)
            if not is_valid:
                logger.warning(
                    f"Origin verification failed: active URL '{current_url}' vs expected domain '{target_domain}': {err_msg}"
                )
                return ActionResult(
                    error=f"Security violation: Origin verification failed ({err_msg}). Aborting credential injection."
                )

            resolved_user_id = await self._resolve_user_id()
            if not resolved_user_id:
                return ActionResult(error="Unauthorized: User identity not established.")

            async with async_session_factory() as db:
                creds = await CredentialRepository.get_credentials_for_domain(
                    db, resolved_user_id, target_domain
                )

            if not creds:
                return ActionResult(
                    error=f"No stored credentials found in vault for domain '{target_domain}'. "
                    "Please ask the user to add credentials via the Wilco Companion App."
                )

            slot_normalized = slot.strip().lower()
            value_to_type: Optional[str] = None

            if slot_normalized in ("username", "user", "email", "identifier", "login"):
                for c in creds:
                    if c.username_or_identifier:
                        value_to_type = c.username_or_identifier
                        break
                if not value_to_type:
                    return ActionResult(
                        error=f"No stored username or login identifier found for domain '{target_domain}'."
                    )

            elif slot_normalized in ("password", "pwd", "pass"):
                pwd_cred = next((c for c in creds if c.auth_type == "password"), None)
                if not pwd_cred:
                    return ActionResult(
                        error=f"No password credential found in vault for domain '{target_domain}'."
                    )
                try:
                    value_to_type = decrypt_secret(pwd_cred.encrypted_blob, settings.vault_key_bytes)
                except Exception as exc:
                    logger.error(f"Failed to decrypt password for domain {target_domain}: {exc}")
                    return ActionResult(error="Failed to decrypt password credential from secure vault.")

            elif slot_normalized in ("api_key", "token", "key"):
                key_cred = next((c for c in creds if c.auth_type == "api_key"), None)
                if not key_cred:
                    return ActionResult(error=f"No API key found in vault for domain '{target_domain}'.")
                try:
                    value_to_type = decrypt_secret(key_cred.encrypted_blob, settings.vault_key_bytes)
                except Exception as exc:
                    logger.error(f"Failed to decrypt API key for domain {target_domain}: {exc}")
                    return ActionResult(error="Failed to decrypt API key credential from secure vault.")
            else:
                return ActionResult(
                    error=f"Unsupported credential slot '{slot}'. Use 'password', 'username', or 'api_key'."
                )

            # Perform keystroke injection directly via CDP keyboard layer
            try:
                await page.keyboard.type(value_to_type, delay=50)
                return ActionResult(
                    extracted_content=f"[SUCCESS] {slot.capitalize()} credential safely injected into active page input."
                )
            except Exception as exc:
                logger.error(f"Error during keystroke injection: {exc}")
                return ActionResult(error=f"Failed to inject keystrokes into page: {exc}")

        @self.action(
            "Generate and type a 6-digit TOTP verification code for two-factor authentication directly into the active input field. "
            "Calculates the code server-side with drift protection."
        )
        async def inject_totp(
            domain: str = "",
            browser_session: Optional[BrowserSession] = None,
        ) -> ActionResult:
            if not browser_session:
                return ActionResult(error="No active browser session available for TOTP injection.")

            page = await browser_session.must_get_current_page()
            if not page:
                return ActionResult(error="No active page found in browser session.")

            # Retrieve active page URL for anti-phishing verification
            try:
                current_url = await browser_session.get_current_page_url()
            except Exception as exc:
                return ActionResult(error=f"Could not verify active page URL: {exc}")

            target_domain = clean_domain(domain)
            if not target_domain and current_url:
                target_domain = clean_domain(current_url)

            if not target_domain:
                return ActionResult(error="Could not determine target domain for TOTP lookup.")

            # Anti-Phishing Strict Origin Verification (Step 4 Component 2)
            is_valid, err_msg = validate_origin(current_url, target_domain)
            if not is_valid:
                logger.warning(
                    f"Origin verification failed before TOTP: active URL '{current_url}' vs expected domain '{target_domain}': {err_msg}"
                )
                return ActionResult(
                    error=f"Security violation: Origin verification failed ({err_msg}). Aborting TOTP injection."
                )

            resolved_user_id = await self._resolve_user_id()
            if not resolved_user_id:
                return ActionResult(error="Unauthorized: User identity not established.")

            async with async_session_factory() as db:
                creds = await CredentialRepository.get_credentials_for_domain(
                    db, resolved_user_id, target_domain
                )

            totp_cred = next((c for c in creds if c.auth_type == "totp_seed"), None)
            if not totp_cred:
                return ActionResult(
                    error=f"No TOTP seed found in vault for domain '{target_domain}'. "
                    "Please ask the user to add a 2FA seed via the Wilco Companion App."
                )

            try:
                decrypted_seed = decrypt_secret(totp_cred.encrypted_blob, settings.vault_key_bytes)
            except Exception as exc:
                logger.error(f"Failed to decrypt TOTP seed for domain {target_domain}: {exc}")
                return ActionResult(error="Failed to decrypt TOTP seed from secure vault.")

            try:
                totp_code = await get_safe_totp_code(decrypted_seed, min_drift_buffer=5)
            except Exception as exc:
                logger.error(f"Failed to generate safe TOTP code: {exc}")
                return ActionResult(error=f"Failed to compute TOTP code: {exc}")

            # Re-verify page URL after potential drift wait (Step 4 Component 2)
            try:
                post_sleep_url = await browser_session.get_current_page_url()
            except Exception as exc:
                return ActionResult(error=f"Could not re-verify page URL after TOTP drift sleep: {exc}")

            is_valid_post, err_msg_post = validate_origin(post_sleep_url, target_domain)
            if not is_valid_post:
                logger.warning(
                    f"Origin re-verification failed after TOTP wait: URL shifted to '{post_sleep_url}' (expected '{target_domain}'): {err_msg_post}"
                )
                return ActionResult(
                    error="Security violation: Page navigated or changed origin during TOTP generation. Aborting injection."
                )

            try:
                await page.keyboard.type(totp_code, delay=50)
                return ActionResult(
                    extracted_content="[SUCCESS] 6-digit TOTP code safely injected into active page input."
                )
            except Exception as exc:
                logger.error(f"Error during TOTP keystroke typing: {exc}")
                return ActionResult(error=f"Failed to inject TOTP code into page: {exc}")
