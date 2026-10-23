import asyncio
import logging
import re
import time
from functools import wraps
from typing import Any, Literal, Optional, Union
import uuid

from browser_use import ActionResult, Controller
from browser_use.browser.session import BrowserSession
from aiogram.types import ForceReply
from aiogram.exceptions import TelegramForbiddenError

from app.browser.credentials_resolver import SensitiveData, credential_scope, get_domain_slug, unpack_credentials
from app.config import settings
from app.db.engine import async_session_factory
from app.db.repository import CredentialRepository, TaskRepository, UserRepository
from app.security.origins import clean_domain, validate_origin
from app.security.account_details import account_placeholders, normalize_account_detail
from app.security.vault import decrypt_secret, encrypt_secret
from app.tasks.chat_input import ChatInputField, OTPChannel, account_input_prompt, otp_prompt
from app.companion.links import credential_editor_url
from app.tasks.registry import task_registry
from app.tasks.state import TaskRecord, TaskState

logger = logging.getLogger(__name__)

CREDENTIAL_INPUT_TIMEOUT = 150


class SecureController(Controller):
    """Load scoped vault placeholders and guard native browser input."""

    def __init__(
        self,
        user_id: Optional[Union[uuid.UUID, str]] = None,
        telegram_id: Optional[int] = None,
        sensitive_data: Optional[SensitiveData] = None,
        task: Optional[TaskRecord] = None,
        status_manager: Any = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        try:
            self.user_id = uuid.UUID(user_id) if isinstance(user_id, str) else user_id
        except ValueError:
            self.user_id = None
        self.telegram_id = telegram_id if telegram_id is not None else (task.user_id if task else None)
        self.sensitive_data = sensitive_data if sensitive_data is not None else {}
        self.task = task
        self.status_manager = status_manager
        self._guard_native_input()
        self._register_secure_actions()

    def _guard_native_input(self) -> None:
        registered_input = self.registry.registry.actions.get("input")
        if registered_input is None:
            return
        native_input = registered_input.function

        @wraps(native_input)
        async def guarded_input(*, params: Any, **context: Any) -> ActionResult:
            # Registry.execute_action has already applied origin-scoped substitution.
            # Upstream leaves unknown tags unchanged; never send those to the page.
            if re.search(r"</?secret\b", params.text, re.IGNORECASE):
                return ActionResult(error=(
                    "Input blocked: unresolved or malformed secret placeholder. "
                    "Call the appropriate credential tool (e.g. need_password) as a separate action, "
                    "wait for its result, then input the exact returned <secret>name</secret>. "
                    "Never put tool calls inside secret tags."
                ))
            return await native_input(params=params, **context)

        registered_input.function = guarded_input

    async def act(self, action: Any, browser_session: BrowserSession, **kwargs: Any) -> ActionResult:
        # Upstream substitutes tags for every action. Only native input should receive
        # secrets; URL navigation, JS evaluation, and extraction must keep literal tags.
        actions = action.model_dump(exclude_unset=True)
        if input_action := actions.get("input"):
            text = input_action.get("text", "")
            separate_value = re.search(r"<secret>[^<>]+_(?:phone_number|country_code)</secret>", text)
            if separate_value and text != separate_value.group():
                return ActionResult(error=(
                    "Phone-number and country-code inputs must each use their own placeholder alone. "
                    "Do not prepend, append, or concatenate a country code and phone number."
                ))
        if not actions.get("input"):
            kwargs.pop("sensitive_data", None)
        if any(actions.get(name) is not None for name in ("request_domain_credentials", "need_password", "need_api_key", "ask_user", "ask_phone_number", "ask_country_code", "need_otp")) and kwargs.get("action_timeout") is None:
            kwargs["action_timeout"] = CREDENTIAL_INPUT_TIMEOUT + 30
        return await super().act(action=action, browser_session=browser_session, **kwargs)

    async def _resolve_user_id(self) -> Optional[uuid.UUID]:
        if self.user_id:
            if self.task:
                async with async_session_factory() as db:
                    user = await UserRepository.get_by_id(db, self.user_id)
                if not user or user.telegram_id != self.task.user_id:
                    return None
            return self.user_id
        if self.telegram_id:
            async with async_session_factory() as db:
                user = await UserRepository.get_by_telegram_id(db, self.telegram_id)
                if user is None and self.task and self.telegram_id == self.task.user_id:
                    user, _ = await UserRepository.get_or_create_by_telegram_id(db, self.telegram_id)
                    await db.commit()
                if user:
                    self.user_id = user.id
        return self.user_id

    async def _save_task(self) -> None:
        if self.task:
            async with async_session_factory() as db:
                await TaskRepository.save_task(db, self.task)
                await db.commit()

    async def _update_status(self) -> None:
        if self.task and self.status_manager:
            try:
                # Required prompts may wait behind other messages in the delivery
                # queue. The surrounding input/task deadline bounds this wait.
                await self.status_manager.update(self.task, force=True)
            except Exception:
                logger.warning("Could not update credential status for task %s", self.task.task_id)

    async def _wait_for_credentials(self, domain: str, credential_type: Optional[str] = None, *, rejected: bool = False) -> Optional[str]:
        task = self.task
        if task is None or self.status_manager is None or self.telegram_id != task.user_id:
            return "Credentials are missing. Open the Wilco WebApp to add them, then retry."
        if task.state != TaskState.RUNNING:
            return "Task is no longer running; credential request aborted."

        deadline = time.time() + CREDENTIAL_INPUT_TIMEOUT
        companion_url = credential_editor_url(domain, credential_type or "password")
        task.metadata.update({
            "target_domain": domain,
            "credential_input_deadline": deadline,
            "companion_url": companion_url,
            "credential_rejected": rejected,
        })
        if credential_type:
            task.metadata["credential_type"] = credential_type
        logger.info("Task %s requesting secure input type=%s domain=%s", task.task_id, credential_type or "credentials", domain)
        task.transition_to(TaskState.NEEDS_INPUT, status_message=f"Waiting for {domain} credentials in the WebApp.")
        pending = task_registry.register_credential_input(task, domain, deadline)
        try:
            await self._save_task()
            # The browser wait is bounded; the editor itself never expires with it.
            async with asyncio.timeout(max(0, deadline - time.time())):
                await self._update_status()
                await pending.event.wait()
            if task.state != TaskState.RUNNING:
                return "Credential entry was cancelled; task stopped."
            return None
        except TimeoutError:
            if not task.is_terminal:
                task.transition_to(
                    TaskState.FAILED,
                    status_message="Credential entry timed out. Start a new task to try again.",
                    error=f"No credentials provided within {CREDENTIAL_INPUT_TIMEOUT} seconds.",
                )
            return "Credential entry timed out; task stopped."
        except asyncio.CancelledError:
            if not task.is_terminal:
                task.transition_to(TaskState.FAILED, status_message="Credential request cancelled.", error="Task cancelled.")
            raise
        except Exception:
            if not task.is_terminal:
                task.transition_to(TaskState.FAILED, status_message="Unable to request credentials through the WebApp.")
            logger.error("Credential WebApp request failed for task %s", task.task_id)
            return "Unable to request credentials securely; task stopped."
        finally:
            # Serialize cleanup with submissions so a late commit cannot overwrite FAILED.
            async with pending.lock:
                task_registry.clear_credential_input(task.task_id)
                for key in ("target_domain", "credential_type", "credential_rejected", "credential_input_deadline", "companion_url"):
                    task.metadata.pop(key, None)
                try:
                    async with async_session_factory() as db:
                        await TaskRepository.save_task(db, task)
                        await db.commit()
                except Exception:
                    logger.error("Could not persist credential request cleanup for task %s", task.task_id)
            await self._update_status()

    async def _saved_account_detail(
        self, user_id: uuid.UUID, domain: str, field: str,
    ) -> tuple[Optional[str], bool]:
        async with async_session_factory() as db:
            credentials = await CredentialRepository.get_credentials_for_domain(db, user_id, domain)
        stored = next((item for item in credentials if item.auth_type == field), None)
        value = decrypt_secret(stored.encrypted_blob, settings.vault_key_bytes) if stored else None
        legacy = False
        if value is None and field in ("username", "email"):
            # Migrate the old password-associated identifier when it matches the
            # requested field. Never invent an email from a saved username.
            value = next((item.username_or_identifier for item in credentials if item.username_or_identifier and (
                ("@" in item.username_or_identifier) == (field == "email")
            )), None)
            legacy = value is not None
        if value is not None:
            try:
                normalized = normalize_account_detail(value, field)
                return normalized, legacy or normalized != value
            except ValueError:
                pass  # Old combined international numbers require a fresh phone-only reply.
        return None, False

    async def _save_account_detail(self, user_id: uuid.UUID, domain: str, field: str, value: str) -> None:
        encrypted = encrypt_secret(value, settings.vault_key_bytes)
        async with async_session_factory() as db:
            await CredentialRepository.add_or_update_credential(db, user_id, domain, field, encrypted)
            if field in ("username", "email"):
                credentials = await CredentialRepository.get_credentials_for_domain(db, user_id, domain)
                for item in credentials:
                    if item.username_or_identifier and item.username_or_identifier.strip() == value:
                        item.username_or_identifier = None
            await db.commit()

    def _publish_account_detail(self, domain: str, field: str, value: str) -> ActionResult:
        slug = get_domain_slug(domain)
        slots = account_placeholders(slug, field, value)
        scoped = self.sensitive_data.setdefault(credential_scope(domain), {})
        previous_login = scoped.get(f"{slug}_user")
        if field == "phone":
            # A refreshed local number must not retain the previous number's
            # international formats in the shared placeholder dictionary.
            for name in tuple(scoped):
                if name.startswith(f"{slug}_phone_"):
                    scoped.pop(name)
        scoped.update(slots)
        if field in ("username", "email") and previous_login is not None:
            # Keep preloaded compatibility aliases in sync after a refresh.
            login = scoped.get(f"{slug}_username") or scoped[f"{slug}_email"]
            scoped[f"{slug}_user"] = login
            if scoped.get("x_user") == previous_login:
                scoped["x_user"] = login
        placeholders = ", ".join(f"<secret>{name}</secret>" for name in slots)
        details = ""
        if field == "phone":
            details = " Use phone_number alone in the phone field. Keep the country calling code separate."
        elif field == "country_code":
            # Calling codes are public selector metadata, not the user's phone
            # number. The number remains available only as a secret placeholder.
            details = (
                f" Calling code: {value}; digits without '+': {value[1:]}. "
                "Use only in the country-code field or selector."
            )
        return ActionResult(extracted_content=(
            f"{field.capitalize()} ready for {domain}.{details} Use the standard input action with: {placeholders}."
        ))

    async def _ask_user(
        self, domain: str, field: ChatInputField, browser_session: Optional[BrowserSession],
        channel: OTPChannel = "unknown",
        force_refresh: bool = False,
    ) -> ActionResult:
        task = self.task
        if field not in ("username", "email", "phone", "country_code", "otp"):
            return ActionResult(error="Only account identifiers, country calling codes, or one-time codes can be requested in chat.")
        if not task or not self.status_manager or self.telegram_id != task.user_id or task.state != TaskState.RUNNING:
            return ActionResult(error="No running task with an authenticated chat is available.")
        target = clean_domain(domain)
        if not browser_session or not target:
            return ActionResult(error="An active browser and valid domain are required.")
        try:
            current_url = await browser_session.get_current_page_url()
        except Exception:
            return ActionResult(error="Could not verify active page URL.")
        if not validate_origin(current_url, target)[0]:
            return ActionResult(error="Security violation: Active page does not match the requested domain.")

        user_id = None
        if field != "otp":
            try:
                user_id = await self._resolve_user_id()
                if user_id is None:
                    return ActionResult(error="An authenticated vault owner is required.")
                value, needs_save = (None, False) if force_refresh else await self._saved_account_detail(
                    user_id, target, field,
                )
                if value is not None:
                    current_url = await browser_session.get_current_page_url()
                    if not validate_origin(current_url, target)[0] or task.state != TaskState.RUNNING:
                        return ActionResult(error="Security violation: Page or task changed during account lookup.")
                    if needs_save:
                        await self._save_account_detail(user_id, target, field, value)
                        current_url = await browser_session.get_current_page_url()
                        if not validate_origin(current_url, target)[0] or task.state != TaskState.RUNNING:
                            return ActionResult(error="Security violation: Page or task changed while saving account details.")
                    return self._publish_account_detail(target, field, value)
            except Exception:
                logger.error("Could not load saved account detail for task %s field=%s", task.task_id, field)
                return ActionResult(error="Could not read saved account details securely.")

        deadline = time.time() + CREDENTIAL_INPUT_TIMEOUT
        try:
            pending = task_registry.register_chat_input(
                task, field, deadline, reply_chat_id=task.user_id,
            )
        except RuntimeError:
            return ActionResult(error="Another input request is waiting for this user's private reply. Complete it first.")
        task.metadata["chat_input_field"] = field
        task.transition_to(TaskState.NEEDS_INPUT, status_message=f"Waiting for your {field} in Telegram.")
        logger.info("Task %s requesting chat input field=%s domain=%s", task.task_id, field, target)
        try:
            async with asyncio.timeout(max(0, deadline - time.time())):
                await self._save_task()
                await self._update_status()
                prompt = await self.status_manager.bot.send_message(
                    chat_id=pending.reply_chat_id,
                    text=otp_prompt(target, channel) if field == "otp" else account_input_prompt(target, field),
                    parse_mode=None,
                    reply_markup=ForceReply(selective=True),
                )
                pending.prompt_message_id = prompt.message_id
                await pending.event.wait()
            if task.state != TaskState.RUNNING or pending.response is None:
                return ActionResult(error="User input was cancelled; task stopped.")
            current_url = await browser_session.get_current_page_url()
            if not validate_origin(current_url, target)[0]:
                return ActionResult(error="Security violation: Page changed origin during the input request.")
            if task.state != TaskState.RUNNING:
                return ActionResult(error="Task stopped during the input request.")
            if field == "otp":
                # Keep the code out of model messages, tool results, and persisted task data.
                slot = f"{get_domain_slug(target)}_otp"
                self.sensitive_data.setdefault(credential_scope(target), {})[slot] = pending.response
                return ActionResult(extracted_content=(
                    f"One-time code ready for {target}. Use the standard input action with <secret>{slot}</secret>."
                ))
            value = normalize_account_detail(pending.response, field)
            await self._save_account_detail(user_id, target, field, value)
            # Saving is owner/domain bound; publishing also needs a fresh origin
            # check in case the page changed during database IO.
            current_url = await browser_session.get_current_page_url()
            if not validate_origin(current_url, target)[0] or task.state != TaskState.RUNNING:
                return ActionResult(error="Security violation: Page or task changed while saving account details.")
            return self._publish_account_detail(target, field, value)
        except TimeoutError:
            if not task.is_terminal:
                task.transition_to(TaskState.FAILED, status_message="Chat input timed out.", error="No reply received before the deadline.")
            return ActionResult(error="Chat input timed out; task stopped.")
        except asyncio.CancelledError:
            if not task.is_terminal:
                task.transition_to(TaskState.FAILED, status_message="Chat input cancelled.")
            raise
        except TelegramForbiddenError:
            if not task.is_terminal:
                task.transition_to(TaskState.FAILED, status_message="Private input chat unavailable.")
            if task.chat_id != task.user_id:
                await self.status_manager.bot.send_message(
                    chat_id=task.chat_id,
                    text="Please open a private chat with me, then retry this task so I can ask for your account details privately.",
                    parse_mode=None,
                )
            return ActionResult(error="The task owner must open a private chat before supplying account details.")
        except Exception:
            if not task.is_terminal:
                task.transition_to(TaskState.FAILED, status_message="Unable to request chat input.")
            logger.error("Chat input request failed for task %s", task.task_id)
            return ActionResult(error="Unable to request chat input; task stopped.")
        finally:
            async with pending.lock:
                task_registry.clear_chat_input(task.chat_id)
                pending.response = None
                task.metadata.pop("chat_input_field", None)
                await self._save_task()
            await self._update_status()

    def _register_secure_actions(self) -> None:
        async def load_credentials(
            domain: str,
            browser_session: Optional[BrowserSession] = None,
            credential_type: Optional[str] = None,
            force_refresh: bool = False,
        ) -> ActionResult:
            if browser_session is None:
                return ActionResult(error="No active browser session available.")
            if self.task and self.task.state != TaskState.RUNNING:
                return ActionResult(error="Task is no longer running.")
            target = clean_domain(domain)
            if not target:
                return ActionResult(error="Invalid target credential domain.")
            try:
                current_url = await browser_session.get_current_page_url()
            except Exception:
                return ActionResult(error="Could not verify active page URL.")
            valid, reason = validate_origin(current_url, target)
            if not valid:
                return ActionResult(error=f"Security violation: Origin verification failed ({reason}).")
            user_id = await self._resolve_user_id()
            if user_id is None:
                return ActionResult(error="Unauthorized: User identity not established. Link your account in the WebApp.")

            async with async_session_factory() as db:
                credentials = await CredentialRepository.get_credentials_for_domain(db, user_id, target)
            if credential_type:
                credentials = [c for c in credentials if c.auth_type == credential_type]
            if force_refresh and credentials:
                # The owner may already have corrected the vault through an older
                # persistent button while this agent still held the rejected value.
                scope = self.sensitive_data.get(credential_scope(target), {})
                previous = scope.get(f"{get_domain_slug(target)}_pass") if isinstance(scope, dict) else None
                if previous is not None:
                    try:
                        latest = unpack_credentials(target, credentials).get(f"{get_domain_slug(target)}_pass")
                    except Exception:
                        return ActionResult(error="Failed to decrypt credentials from the secure vault.")
                    if latest is not None and latest != previous:
                        force_refresh = False
            if not credentials or force_refresh:
                if force_refresh:
                    # Do not keep an explicitly rejected password available for further inputs.
                    scope = self.sensitive_data.get(credential_scope(target), {})
                    if isinstance(scope, dict):
                        for key in (f"{get_domain_slug(target)}_pass", "x_pass"):
                            scope.pop(key, None)
                error = await self._wait_for_credentials(target, credential_type or "password", rejected=force_refresh)
                if error:
                    return ActionResult(error=error)
                async with async_session_factory() as db:
                    credentials = await CredentialRepository.get_credentials_for_domain(db, user_id, target)
                if credential_type:
                    credentials = [c for c in credentials if c.auth_type == credential_type]
                if not credentials:
                    return ActionResult(error="No credentials were saved for the requested domain.")
            try:
                secrets = unpack_credentials(target, credentials)
            except Exception:
                logger.error("Failed to decrypt vaulted credentials for %s", target)
                return ActionResult(error="Failed to decrypt credentials from the secure vault.")
            # Recheck after human input or database IO, before publishing any secrets.
            try:
                current_url = await browser_session.get_current_page_url()
            except Exception:
                return ActionResult(error="Could not reverify active page URL.")
            valid, reason = validate_origin(current_url, target)
            if not valid:
                return ActionResult(error=f"Security violation: Page changed origin during credential request ({reason}).")
            if not secrets:
                return ActionResult(error="No supported credentials available for this domain.")
            if self.task and self.task.state != TaskState.RUNNING:
                return ActionResult(error="Task stopped during the credential request.")
            # Mutate, never replace, the shared dictionary used by Agent and MessageManager.
            # Navigation stays open for multi-hop logins; upstream scopes substitution by origin.
            self.sensitive_data.setdefault(credential_scope(target), {}).update(secrets)
            placeholders = ", ".join(f"<secret>{name}</secret>" for name in sorted(secrets))
            return ActionResult(extracted_content=f"Credentials ready for {target}. Use the standard input action with: {placeholders}")

        @self.action(
            "Load existing credentials for the active website from the vault; returns only scoped "
            "<secret> placeholders for the standard input action. Prefer need_password or need_api_key "
            "when a particular secret is needed. Use ask_user for username/email, ask_phone_number for "
            "the phone number, and ask_country_code only if the website needs a separate calling code."
        )
        async def request_domain_credentials(domain: str, browser_session: Optional[BrowserSession] = None) -> ActionResult:
            return await load_credentials(domain, browser_session)

        @self.action(
            "Get the password for the active website domain. Use an existing vaulted password if present; "
            "otherwise pause the task and send the user a secure link with one password field. "
            "Returns only a <secret> placeholder for the standard input action, never plaintext. "
            "Execute this action first, wait for its result, then input the exact returned placeholder. "
            "Never put a tool call inside secret tags or input text. "
            "Call ask_user for a missing username/email or ask_phone_number for a missing phone number. "
            "Never request passwords in chat."
            " If the website explicitly rejects the password, call again with force_refresh=true to "
            "ask the owner to replace it in the same editor. Wait for their save, then use the newly returned placeholder."
        )
        async def need_password(domain: str, force_refresh: bool = False, browser_session: Optional[BrowserSession] = None) -> ActionResult:
            return await load_credentials(domain, browser_session, "password", force_refresh=force_refresh)

        @self.action(
            "Get an API key for the active website domain. Use an existing vaulted API key if present; "
            "otherwise pause the task and send the user a secure link with one API key field. "
            "Returns only a scoped <secret> placeholder for the standard input action, never plaintext. "
            "Execute this action first, wait for its result, then input the exact returned placeholder. "
            "Never put a tool call inside secret tags or input text. "
            "Never ask for an API key in chat or use this for a password."
        )
        async def need_api_key(domain: str, browser_session: Optional[BrowserSession] = None) -> ActionResult:
            return await load_credentials(domain, browser_session, "api_key")

        @self.action(
            "Get a username or email for the active website. Reuse its saved, domain-bound "
            "vault value, or ask the authenticated task owner privately and save their reply encrypted "
            "for this domain. Returns only scoped <secret> placeholders, never the actual value. "
            "Use only when needed for the user's requested task. Use ask_phone_number for a phone number "
            "and ask_country_code separately for a required calling code. "
            "force_refresh is only for an explicitly requested change or a rejected "
            "saved value. Never use this for passwords, API keys, OTPs, tokens or recovery codes."
        )
        async def ask_user(
            domain: str, field: Literal["username", "email"], force_refresh: bool = False,
            browser_session: Optional[BrowserSession] = None,
        ) -> ActionResult:
            return await self._ask_user(
                domain, field, browser_session, force_refresh=force_refresh,
            )

        @self.action(
            "Get only the task owner's phone number for the active website's phone-number field. "
            "Reuse its domain-bound vault value or ask the owner privately and save their reply encrypted. "
            "Returns one phone_number placeholder containing only the supplied digits, preserving leading "
            "zeros. It never infers a country, adds a prefix, creates international formats, or asks for a "
            "country code. Use this placeholder alone in a normal phone field, including fields next to a "
            "country selector or fixed prefix. Never prepend country-code metadata to that field. "
            "Use ask_country_code separately only if the website actually needs a calling code. "
            "force_refresh is only for an explicitly requested change or a rejected saved number."
        )
        async def ask_phone_number(
            domain: str, force_refresh: bool = False, browser_session: Optional[BrowserSession] = None,
        ) -> ActionResult:
            return await self._ask_user(domain, "phone", browser_session, force_refresh=force_refresh)

        @self.action(
            "Get only the task owner's country calling code, such as +1 or +44, for the active website. "
            "Use only when the website explicitly requires a country-code field or selector that still "
            "needs this information. If the website already has the correct code selected or fixed, "
            "leave it in place. Never call merely to save, normalize, or enter a phone number. "
            "Reuse the domain-bound saved code or ask the owner privately and save it encrypted, "
            "independently of their phone number. Returns a country_code placeholder and public calling-code "
            "metadata for choosing a country option. If the control already supplies '+', use the returned "
            "digits metadata there. Use only in the country-code control; never insert "
            "a full phone number here or automatically attach this code to a phone-number placeholder. "
            "force_refresh is only for an explicitly requested change or a rejected saved code."
        )
        async def ask_country_code(
            domain: str, force_refresh: bool = False, browser_session: Optional[BrowserSession] = None,
        ) -> ActionResult:
            return await self._ask_user(domain, "country_code", browser_session, force_refresh=force_refresh)

        @self.action(
            "Ask the task owner in Telegram for a one-time login or verification code, then wait for their reply. "
            "domain must match the active website. Set channel to sms, whatsapp, email, or authenticator "
            "only when the current page identifies that delivery method; otherwise use unknown. "
            "The prompt tells the user where to find the code. Returns a scoped <secret> placeholder "
            "for the standard input action; the actual code is not returned to the model or saved in the vault. "
            "Use for one-time codes only, never passwords, API keys, recovery codes, or authenticator setup seeds."
        )
        async def need_otp(
            domain: str, channel: OTPChannel = "unknown", browser_session: Optional[BrowserSession] = None,
        ) -> ActionResult:
            return await self._ask_user(domain, "otp", browser_session, channel)
