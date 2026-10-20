import logging
from typing import Any, Callable, Optional, Union
import uuid

from browser_use import Agent, Browser, Controller

from app.browser.controller import SecureController
from app.browser.llm import get_llm

logger = logging.getLogger(__name__)

SECURITY_INSTRUCTIONS = """
CREDENTIAL INJECTION & ZERO-KNOWLEDGE SECURITY INSTRUCTIONS:
1. When encountering an authentication, login, or verification page, NEVER ask the user to post their passwords, API keys, or TOTP seeds in chat.
2. When a password input field is visible, focus or click it, then invoke the 'inject_credential' tool with slot='password' and domain='<domain>'.
3. If a username or login email is required, invoke 'inject_credential' with slot='username' and domain='<domain>'.
4. If a two-factor authentication (2FA) or TOTP verification code is required, focus the code input field and invoke 'inject_totp' with domain='<domain>'.
5. Credentials and TOTP codes are typed directly into the active browser page via the secure keystroke layer. Never attempt to guess, extract, or echo plaintext secrets in your thoughts, plans, or final results.
"""


def create_agent(
    task: str,
    browser: Optional[Browser] = None,
    llm: Optional[Any] = None,
    step_callback: Optional[Callable] = None,
    controller: Optional[Controller] = None,
    user_id: Optional[Union[uuid.UUID, str]] = None,
    telegram_id: Optional[int] = None,
    max_failures: int = 3,
    use_vision: bool = True,
    extend_system_message: Optional[str] = None,
    **kwargs: Any,
) -> Agent:
    """
    Factory creating a configured browser-use Agent instance.
    
    Args:
        task: Natural language description of what the agent needs to achieve.
        browser: Active BrowserSession instance (or None to let browser-use launch one).
        llm: Initialized LLM model instance (or None to load from application settings).
        step_callback: Optional callback invoked on each agent step with (state, output, step_number).
        controller: Optional custom Controller instance (defaults to SecureController if user context is provided).
        user_id: Optional user UUID for secure credential vaulting.
        telegram_id: Optional Telegram ID for user identification.
        max_failures: Maximum consecutive failures before agent halts.
        use_vision: Whether the agent should inspect page screenshots/visual elements.
        extend_system_message: Additional system prompt instructions to append.
        **kwargs: Additional parameters forwarded to Agent.__init__.
    """
    agent_llm = llm or get_llm()
    logger.info("Creating browser-use Agent for task: %s", task)

    # Automatically provision SecureController if user context is provided
    agent_controller = controller
    if agent_controller is None and (user_id is not None or telegram_id is not None):
        agent_controller = SecureController(user_id=user_id, telegram_id=telegram_id)

    # Append security instructions
    combined_system_message = SECURITY_INSTRUCTIONS
    if extend_system_message:
        combined_system_message = f"{SECURITY_INSTRUCTIONS}\n\n{extend_system_message}"

    agent_kwargs: dict[str, Any] = {
        "task": task,
        "llm": agent_llm,
        "browser": browser,
        "max_failures": max_failures,
        "use_vision": use_vision,
        "controller": agent_controller,
        "extend_system_message": combined_system_message,
        **kwargs,
    }

    if step_callback is not None:
        agent_kwargs["register_new_step_callback"] = step_callback

    return Agent(**agent_kwargs)
