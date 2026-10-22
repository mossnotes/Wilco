import asyncio
import logging
import math
import time
from typing import Any, Optional, Union
from urllib.parse import urlencode
import uuid

from browser_use import ActionResult, Controller
from browser_use.browser.session import BrowserSession

from app.browser.credentials_resolver import SensitiveData, credential_scope, unpack_credentials
from app.config import settings
from app.db.engine import async_session_factory
from app.db.repository import CredentialRepository, IdentityTokenRepository, TaskRepository, UserRepository
from app.security.origins import clean_domain, validate_origin
from app.tasks.registry import task_registry
from app.tasks.state import TaskRecord, TaskState

logger = logging.getLogger(__name__)

CREDENTIAL_INPUT_TIMEOUT = 150
COUNTDOWN_INTERVAL = 10


class SecureController(Controller):
    """Load scoped vault placeholders; browser-use performs all browser input."""

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
        self._register_secure_actions()

    async def act(self, action: Any, browser_session: BrowserSession, **kwargs: Any) -> ActionResult:
        # Upstream substitutes tags for every action. Only native input should receive
        # secrets; URL navigation, JS evaluation, and extraction must keep literal tags.
        actions = action.model_dump(exclude_unset=True)
        if not actions.get("input"):
            kwargs.pop("sensitive_data", None)
        if actions.get("request_domain_credentials") and kwargs.get("action_timeout") is None:
            kwargs["action_timeout"] = CREDENTIAL_INPUT_TIMEOUT + 30
        return await super().act(action=action, browser_session=browser_session, **kwargs)

    async def _resolve_user_id(self) -> Optional[uuid.UUID]:
        if self.user_id:
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
                async with asyncio.timeout(5):
                    await self.status_manager.update(self.task, force=True)
            except Exception:
                logger.warning("Could not update credential status for task %s", self.task.task_id)

    async def _wait_for_credentials(self, domain: str) -> Optional[str]:
        task = self.task
        if task is None or self.status_manager is None or self.telegram_id != task.user_id:
            return "Credentials are missing. Open the Wilco WebApp to add them, then retry."
        if task.state != TaskState.RUNNING:
            return "Task is no longer running; credential request aborted."

        deadline = time.time() + CREDENTIAL_INPUT_TIMEOUT
        async with async_session_factory() as db:
            token = await IdentityTokenRepository.create_token(
                db, task.user_id, ttl_minutes=max(1, math.ceil(CREDENTIAL_INPUT_TIMEOUT / 60))
            )
            await db.commit()
        query = urlencode({"token": token.token, "task_id": task.task_id, "domain": domain})
        companion_url = f"{settings.COMPANION_BASE_URL.rstrip('/')}/link?{query}"
        task.metadata.update({
            "target_domain": domain,
            "credential_input_deadline": deadline,
            "companion_url": companion_url,
        })
        task.transition_to(TaskState.NEEDS_INPUT, status_message=f"Waiting for {domain} credentials in the WebApp.")
        pending = task_registry.register_credential_input(task, domain, deadline)
        try:
            await self._save_task()
            # The wait cap includes sending Telegram updates and all countdown edits.
            async with asyncio.timeout(max(0, deadline - time.time())):
                await self._update_status()
                while not pending.event.is_set():
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        raise TimeoutError
                    try:
                        await asyncio.wait_for(pending.event.wait(), timeout=min(COUNTDOWN_INTERVAL, remaining))
                    except TimeoutError:
                        if task.state != TaskState.NEEDS_INPUT:
                            break
                        await self._update_status()
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
                for key in ("target_domain", "credential_input_deadline", "companion_url"):
                    task.metadata.pop(key, None)
                # Invalidate the link even when it was never opened.
                try:
                    async with async_session_factory() as db:
                        stored_token = await IdentityTokenRepository.get_token(db, token.token)
                        if stored_token:
                            stored_token.is_used = True
                        await TaskRepository.save_task(db, task)
                        await db.commit()
                except Exception:
                    logger.error("Could not persist credential request cleanup for task %s", task.task_id)
            await self._update_status()

    def _register_secure_actions(self) -> None:
        @self.action(
            "Request all available credentials for the active website domain from the secure vault. "
            "Returns only placeholder names, such as <secret>example_user</secret> and "
            "<secret>example_pass</secret>, for the standard input action. "
            "If missing, pauses and asks the user through the secure WebApp."
        )
        async def request_domain_credentials(
            domain: str,
            browser_session: Optional[BrowserSession] = None,
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
            if not credentials:
                error = await self._wait_for_credentials(target)
                if error:
                    return ActionResult(error=error)
                async with async_session_factory() as db:
                    credentials = await CredentialRepository.get_credentials_for_domain(db, user_id, target)
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
            self.sensitive_data[credential_scope(target)] = secrets
            placeholders = ", ".join(f"<secret>{name}</secret>" for name in sorted(secrets))
            return ActionResult(extracted_content=f"Credentials ready for {target}. Use the standard input action with: {placeholders}")
