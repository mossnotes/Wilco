import logging
from typing import Any, Callable, Dict, Optional, Union
import uuid

from browser_use import Agent, Browser, Controller

from app.browser.controller import SecureController
from app.browser.credentials_resolver import SensitiveData
from app.browser.llm import get_llm
from app.personality import PERSONALITY_INSTRUCTIONS
from app.tasks.state import TaskRecord

logger = logging.getLogger(__name__)

SECURITY_INSTRUCTIONS = """
CREDENTIAL VAULT SECURITY INSTRUCTIONS:
1. When encountering an authentication, login, or verification page, NEVER ask the user to post their passwords, API keys, or TOTP seeds in chat.
2. Use the standard input action with only the exact tagged placeholders returned by a credential tool or listed as available for the active domain. browser-use substitutes the secret securely at execution time.
3. If a password placeholder is unavailable, execute need_password as a separate browser action with domain set to the active website's host. For an API key, execute need_api_key. Wait for the tool result before the next input action, then copy its exact returned <secret>placeholder_name</secret>. Secret tags contain only available placeholder names, never tool names, function calls, or expressions. Each tool loads that secret from the vault or pauses and sends a secure single-field WebApp link. Never pass a secret as a tool argument or ask for it in chat.
4. For two-factor authentication, use the provided placeholder ending in 'bu_2fa_code' with the standard input action. browser-use generates a fresh code when typing. Never type or expose the underlying TOTP seed.
5. Only use placeholders for their associated domain. Never guess, extract, or echo plaintext secrets in thoughts, plans, results, or other tools. If credential entry times out or is cancelled, stop the task.
6. For a username or email, first use a matching available scoped placeholder. Otherwise call ask_user(domain='<active website domain>', field='username' or 'email'). It reuses the domain-bound vault value, or asks the task owner privately and saves their reply encrypted for this domain. It returns only scoped placeholders, never plaintext. Use force_refresh only when the user asks to change the saved value or the website rejects it. Do not open the secure page for ordinary identifiers. Never use ask_user for a phone number, country code, OTP, verification code, password, API key, token, recovery code, or other secret.
   Phone numbers and country calling codes have separate tools and separate vault entries. Call ask_phone_number(domain='<active website domain>') for the phone number alone. Use its phone_number placeholder alone in the phone field, including a field beside a country selector or fixed prefix. Never add a dialing prefix, infer a country, generate international variants, or remove leading zeros. Call ask_country_code(domain='<active website domain>') only if the website explicitly needs a calling code that is not already selected or fixed correctly. Use its country_code placeholder or public calling-code metadata only in the country-code control. Obtaining a country code must never change the phone-number placeholder. A normal phone field must never receive concatenated code and number values. Inspect and follow the website's actual fields instead of normalizing them into one international number. If the site needs an SMS verification code afterwards, call need_otp(channel='sms') separately; codes are never saved as phone numbers.
7. When a website requires a one-time code that is not available through a saved authenticator seed, call need_otp(domain='<active website domain>', channel='sms', 'whatsapp', 'email', or 'authenticator'). Use channel='unknown' if the page does not identify where the code is delivered; never invent the delivery method. This asks the user in Telegram and tells them where to look. The tool returns a scoped <secret> placeholder for the standard input action. Do not ask them to use the Companion App for a one-time code, and never echo the code in text or other tools.
"""


def create_agent(
    task: str,
    browser: Optional[Browser] = None,
    llm: Optional[Any] = None,
    step_callback: Optional[Callable] = None,
    controller: Optional[Controller] = None,
    user_id: Optional[Union[uuid.UUID, str]] = None,
    telegram_id: Optional[int] = None,
    sensitive_data: Optional[SensitiveData] = None,
    task_record: Optional[TaskRecord] = None,
    status_manager: Any = None,
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
        sensitive_data: Optional dictionary mapping placeholder names to secrets for native browser-use substitution.
        task_record: Running task record used to pause and resume credential requests.
        status_manager: Telegram status manager used to deliver the secure WebApp link.
        max_failures: Maximum consecutive failures before agent halts.
        use_vision: Whether the agent should inspect page screenshots/visual elements.
        extend_system_message: Additional system prompt instructions to append.
        **kwargs: Additional parameters forwarded to Agent.__init__.
    """
    agent_llm = llm or get_llm()
    logger.info("Creating browser-use Agent for task: %s", task)

    # Preserve identity even for an empty dictionary so mid-run additions are visible.
    if sensitive_data is None:
        sensitive_data = controller.sensitive_data if isinstance(controller, SecureController) else {}

    # Automatically provision SecureController if user context is provided
    agent_controller = controller
    if agent_controller is None and (user_id is not None or telegram_id is not None or task_record is not None):
        agent_controller = SecureController(
            user_id=user_id, telegram_id=telegram_id, sensitive_data=sensitive_data,
            task=task_record, status_manager=status_manager,
        )
    elif isinstance(agent_controller, SecureController):
        agent_controller.sensitive_data = sensitive_data
        agent_controller.task = task_record or agent_controller.task
        if status_manager is not None:
            agent_controller.status_manager = status_manager

    # Share Wilco's voice while retaining the browser's credential instructions.
    combined_system_message = f"{SECURITY_INSTRUCTIONS}\n\n{PERSONALITY_INSTRUCTIONS}"
    combined_system_message += (
        "\n\nUSER-FACING RESULTS: Report the useful result without "
        "narrating browser steps, internal reasoning, or implementation details."
    )
    if sensitive_data:
        placeholder_names = ", ".join(
            f"{scope}: {', '.join(values)}" if isinstance(values, dict) else scope
            for scope, values in sensitive_data.items()
        )
        placeholder_guidance = (
            f"\nAVAILABLE SENSITIVE PLACEHOLDERS: {placeholder_names}\n"
            "Use these placeholder keys when typing into authentication forms; real values are injected at runtime."
        )
        combined_system_message = f"{combined_system_message}\n{placeholder_guidance}"

    if extend_system_message:
        combined_system_message = f"{combined_system_message}\n\n{extend_system_message}"

    agent_kwargs: Dict[str, Any] = {
        "task": task,
        "browser": browser,
        "llm": agent_llm,
        "controller": agent_controller,
        "register_new_step_callback": step_callback,
        "max_failures": max_failures,
        "use_vision": use_vision,
        "extend_system_message": combined_system_message,
        "sensitive_data": sensitive_data,
        # The step includes model reasoning as well as the 150-second human wait.
        "step_timeout": 300,
    }
    if task_record is not None:
        async def should_stop() -> bool:
            return task_record.is_terminal
        agent_kwargs["register_should_stop_callback"] = should_stop

    agent_kwargs.update(kwargs)

    return Agent(**agent_kwargs)

