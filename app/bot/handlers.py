import asyncio
import logging
import re
from aiogram import F, Router
from aiogram.types import Message

from app.bot.acknowledgement import browser_task_acknowledgement
from app.bot.message_router import route_message
from app.bot.memory import conversation_memory, sanitize_memory_text
from app.bot.serialization import incoming_messages
from app.bot.status_manager import StatusManager
from app.bot.tools import execute_assistant_tool
from app.browser.runner import run_browser_task
from app.config import settings
from app.db.engine import async_session_factory
from app.db.repository import TaskRepository
from app.security.sanitizer import contains_sensitive_data
from app.security.account_details import normalize_account_detail
from app.tasks.chat_input import ACCOUNT_PROMPT_PREFIXES, OTP_PROMPT_PREFIX, normalize_otp
from app.tasks.registry import task_registry
from app.tasks.state import TaskRecord, TaskState

logger = logging.getLogger(__name__)
router = Router(name="main_router")

# While awaiting input, only a small vocabulary of assistant-control language
# may reach the LLM. Arbitrary input values, including codes embedded in prose,
# stay local. This gate permits routing; the model still chooses the action.
_PAUSED_CONTROL_WORDS = frozenset((
    "a about account active add app assistant browser can cancel companion could "
    "current do don't for get guide help how i is it link manage me my need no not "
    "now of on open please request running set setup show start started stop task "
    "tell the this to up use vault waiting want what wilco with work would you your"
).split())


def _is_paused_control_request(text: str) -> bool:
    if not re.fullmatch(r"[A-Za-z\s'’?!.,]+", text):
        return False
    words = re.findall(r"[a-z]+(?:'[a-z]+)?", text.lower().replace("’", "'"))
    return len(words) > 1 and all(word in _PAUSED_CONTROL_WORDS for word in words)


async def _run_acknowledged_browser_task(
    task: TaskRecord, status_manager: StatusManager, message: Message,
) -> None:
    async with browser_task_acknowledgement(message):
        await run_browser_task(task, status_manager, message.bot)


@router.message(F.text)
async def handle_text_message(message: Message) -> None:
    # Delete pasted credentials promptly, even while an earlier turn is waiting
    # on the model or Telegram delivery. All other turns are ordered per chat.
    if contains_sensitive_data(message.text or ""):
        await _handle_text_message(message)
        return
    async with incoming_messages.hold(message.chat.id):
        await _handle_text_message(message)


async def _handle_text_message(message: Message) -> None:
    """
    Handle incoming text prompts from the user.
    
    Workflow:
    1. Pasted Secret Interceptor: Scans for API keys, passwords, and seeds. Deletes immediately if found.
    2. LLM Routing: Replies directly or selects the existing browser task path.
       Browser concurrency is checked only when a browser task is requested.
    3. TaskRecord Creation: Initializes state machine and persists to database.
    4. Optional Debug Card: Internal progress is hidden unless explicitly enabled.
    5. Registry & Execution: Registers background task in task_registry and begins runner.
    """
    text = (message.text or "").strip()
    if not text:
        return
    chat_id = message.chat.id
    user_id = message.from_user.id if message.from_user else 0

    # Delete pasted credentials before processing the message.
    if contains_sensitive_data(text):
        logger.warning("Pasted secret detected from user %s in chat %s! Intercepting and deleting.", user_id, chat_id)
        try:
            await message.delete()
        except Exception as exc:
            logger.warning("Could not delete message with sensitive data: %s", exc)

        warning_text = (
            "⚠️ <b>Security Alert: Secret Intercepted!</b>\n\n"
            "For your security, passwords, API keys, and OTP seeds must <b>never</b> be sent in Telegram chat!\n"
            "Wilco deleted your message to prevent credential exposure.\n\n"
            "🔐 Ask me to open <b>Vault</b> to securely save your credentials."
        )
        await message.answer(warning_text)
        return

    # Resume task-bound input before routing; one-time codes must bypass LLM logs.
    pending = task_registry.get_chat_input(chat_id)
    control_request = False
    if pending:
        if user_id != pending.task.user_id:
            return
        reply = getattr(message, "reply_to_message", None)
        if chat_id != pending.reply_chat_id or not reply or reply.message_id != pending.prompt_message_id:
            # Only a new, ordinary language request can reach the LLM while
            # paused. Replies and code/identifier-shaped values never do.
            if (
                reply or normalize_otp(text) is not None or not any(char.isspace() for char in text)
                or len(text) > 320 or "\n" in text or not _is_paused_control_request(text)
            ):
                await message.answer(
                    "Please reply to my input question in our private chat. To stop instead, send 'stop the current task' as a new message.",
                    parse_mode=None,
                )
                return
            control_request = True
    if pending and not control_request:
        async with pending.lock:
            if not pending.is_pending:
                await message.answer("That input request has expired.")
                return
            if pending.field == "otp":
                code = normalize_otp(text)
                if code is None:
                    await message.answer("Please reply with only the 4–12 character code, using letters or numbers.")
                    return
                text = code
            else:
                try:
                    text = normalize_account_detail(text, pending.field)
                except ValueError as exc:
                    await message.answer(str(exc), parse_mode=None)
                    return
            record = pending.task.model_copy(deep=True)
            record.metadata.pop("chat_input_field", None)
            record.transition_to(TaskState.RUNNING, status_message=(
                "One-time code received. Resuming task." if pending.field == "otp"
                else "Account information received. Resuming task."
            ))
            async with async_session_factory() as session:
                await TaskRepository.save_task(session, record)
                await session.commit()
            if not pending.is_pending:
                return
            pending.task.metadata = record.metadata
            pending.task.transition_to(TaskState.RUNNING, status_message=record.status_message)
            pending.response = text
            pending.event.set()
            logger.info("Task %s received chat input field=%s", record.task_id, pending.field)
        await message.answer("Got it. Thanks!")
        return

    # Replies to expired/consumed input prompts must not become fresh model requests.
    reply = getattr(message, "reply_to_message", None)
    if (
        reply and isinstance(reply.text, str)
        and any(reply.text.startswith(prefix) or f"\n\n{prefix}" in reply.text for prefix in (OTP_PROMPT_PREFIX, *ACCOUNT_PROMPT_PREFIXES))
        and reply.from_user and reply.from_user.id == message.bot.id
    ):
        await message.answer("That input request has expired or has already been answered.")
        return

    # Load history before appending this message, so the current turn appears once.
    # Preserve public URL parameters needed to execute the current request;
    # persistence applies the stricter memory-only URL scrubbing separately.
    text = sanitize_memory_text(text, strip_url_query=False)
    context = await conversation_memory.load(user_id, chat_id)
    await conversation_memory.remember(user_id, chat_id, "user", text)

    # 2. Resolve the current request using sanitized conversation/task context.
    request_id = f"telegram:{chat_id}:{message.message_id}"
    routing_started = asyncio.get_running_loop().time()
    try:
        routing_context = {"context": context} if context and context.has_context else {}
        decision = await route_message(text, request_id=request_id, **routing_context)
    except TimeoutError:
        elapsed = asyncio.get_running_loop().time() - routing_started
        logger.warning(
            "Message routing timed out in chat %s after %.1fs "
            "(provider=%s, model=%s, deadline=%ss)",
            chat_id, elapsed, settings.LLM_PROVIDER, settings.LLM_MODEL,
            settings.ROUTING_TIMEOUT_SECONDS,
        )
        await message.answer("The AI model took too long to respond. Please try again.")
        return
    except Exception as exc:
        # Provider exceptions can contain request data; log only the error type.
        logger.warning("Message routing failed in chat %s (%s)", chat_id, type(exc).__name__)
        await message.answer("I couldn't process your message right now. Please try again.")
        return

    if decision.route == "reply":
        await message.answer(decision.reply, parse_mode=None)
        await conversation_memory.remember(user_id, chat_id, "assistant", decision.reply)
        logger.info("Routing[%s] direct reply delivered", request_id)
        return

    if decision.route != "browser":
        outcome = await execute_assistant_tool(decision.route, message)
        await conversation_memory.remember(user_id, chat_id, "tool", f"{decision.route}: {outcome}")
        logger.info("Routing[%s] assistant tool handled route=%s", request_id, decision.route)
        return

    if not user_id:
        await message.answer("Send me a message from your own Telegram account to start a task.", parse_mode=None)
        return

    if context and context.has_context and not decision.browser_request:
        await message.answer("Could you clarify what you'd like me to do next?", parse_mode=None)
        return

    # Allow direct replies while keeping the existing browser concurrency check.
    if control_request or task_registry.get_by_chat(chat_id):
        logger.info("Routing[%s] browser handoff rejected: active task exists", request_id)
        await message.answer(
            "⚠️ A task is already running in this chat.\n"
            "Please wait for it to complete, or ask me to stop the current task before starting another."
        )
        return

    logger.info("Routing[%s] starting browser task for user %s", request_id, user_id)

    # 3. Create persistent TaskRecord domain entity
    task = TaskRecord(
        user_id=user_id,
        chat_id=chat_id,
        prompt=sanitize_memory_text(decision.browser_request or text, strip_url_query=False),
        status_message="Task received. Initializing worker...",
    )

    # Persist the initial task before starting execution.
    try:
        async with async_session_factory() as session:
            await TaskRepository.save_task(session, task)
            await session.commit()
    except Exception as exc:
        logger.warning("Failed to persist initial task record: %s", exc)

    # 4. Initialize throttled status manager
    status_manager = StatusManager(bot=message.bot)
    await status_manager.send_initial(task)

    # Record acceptance before spawning, so a fast runner cannot record its
    # outcome before the handoff. This is not a claim that the task succeeded.
    await conversation_memory.remember(
        user_id, chat_id, "tool", f"start_browser_task accepted task={task.task_id}. Request: {task.prompt}",
    )

    # 5. Launch background execution with registry tracking
    # The worker acknowledges only after registration, then clears its reaction
    # on every exit path, including cancellation while awaiting user input.
    bg_task = asyncio.create_task(_run_acknowledged_browser_task(task, status_manager, message))
    task_registry.register(chat_id, task, bg_task, status_manager)
    logger.info("Routing[%s] browser task registered task_id=%s", request_id, task.task_id)
