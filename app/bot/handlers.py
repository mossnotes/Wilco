import asyncio
import logging
from aiogram import F, Router
from aiogram.filters import Command, CommandStart
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, Message, WebAppInfo

from app.bot.message_router import route_message
from app.bot.status_manager import StatusManager
from app.browser.runner import run_browser_task
from app.config import settings
from app.db.engine import async_session_factory
from app.db.repository import IdentityTokenRepository, TaskRepository, UserRepository
from app.security.sanitizer import contains_sensitive_data
from app.tasks.chat_input import OTP_PROMPT_PREFIX, normalize_otp
from app.tasks.registry import task_registry
from app.tasks.state import TaskRecord, TaskState

logger = logging.getLogger(__name__)
router = Router(name="main_router")


@router.message(CommandStart())
@router.message(Command("login"))
async def handle_start(message: Message) -> None:
    """
    Handle /start and /login commands.
    Greets the user, provisions/fetches their User record, creates a one-time
    pairing token, and presents an inline button opening the Wilco Companion App.
    """
    user_name = message.from_user.first_name if message.from_user else "there"
    telegram_id = message.from_user.id if message.from_user else None

    pairing_url = None
    if telegram_id:
        try:
            async with async_session_factory() as session:
                await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
                token_obj = await IdentityTokenRepository.create_token(
                    session, telegram_id, ttl_minutes=settings.COMPANION_TOKEN_TTL_MINUTES
                )
                await session.commit()
                base = settings.COMPANION_BASE_URL.rstrip("/")
                pairing_url = f"{base}/link?token={token_obj.token}"
        except Exception as exc:
            logger.error(f"Error creating pairing token for user {telegram_id}: {exc}")

    reply_markup = None
    if pairing_url:
        button = (
            InlineKeyboardButton(text="🔗 Open Wilco Companion App", web_app=WebAppInfo(url=pairing_url))
            if pairing_url.startswith("https://")
            else InlineKeyboardButton(text="🔗 Open Wilco Companion App", url=pairing_url)
        )
        reply_markup = InlineKeyboardMarkup(inline_keyboard=[[button]])

    welcome_text = (
        f"👋 Hello <b>{user_name}</b>! I am <b>Wilco</b>, your Autonomous Browser & Tasks Assistant.\n\n"
        "I can automate tasks on the web using a managed browser.\n\n"
        "🔒 <b>Zero-Knowledge Security:</b>\n"
        "• Passwords, API keys, and authenticator setup seeds belong in the Companion App.\n"
        "• When a website needs a one-time code, I will ask you to reply here and tell you where to find it.\n"
        "• Click the button below to link your account and manage vaulted credentials in our secure web companion enclave.\n\n"
        "Send me a prompt (e.g. <i>\"Check my deployments on Vercel\"</i>) to start a task!"
    )
    await message.answer(welcome_text, reply_markup=reply_markup)


@router.message(Command("help"))
async def handle_help(message: Message) -> None:
    """
    Handle the /help command.
    Provides instructions on interacting with Wilco, identity linking, and task cancellation.
    """
    help_text = (
        "🤖 <b>Wilco Commands & Usage</b>\n\n"
        "• <b>/start</b> - Show welcome message & companion link\n"
        "• <b>/login</b> - Generate a fresh companion pairing link\n"
        "• <b>/cancel</b> - Cancel an active running task\n"
        "• <b>/help</b> - Show this help guide\n\n"
        "💡 <b>Running a Task:</b>\n"
        "Simply send a natural language prompt with the action you want completed "
        "(e.g., <i>\"Log in to Vercel and check deployment statuses\"</i>).\n"
        "I will create a task and update a single status card in-place with screenshot verification."
    )
    await message.answer(help_text)


@router.message(Command("cancel"))
async def handle_cancel(message: Message) -> None:
    """
    Handle the /cancel command.
    Cancels the currently running background task in this chat.
    """
    chat_id = message.chat.id
    cancelled = await task_registry.cancel_task_by_chat(chat_id)
    if cancelled:
        await message.answer("❌ Active task cancelled by user.")
    else:
        await message.answer("ℹ️ No active task is currently running in this chat.")


@router.message(F.text)
async def handle_text_message(message: Message) -> None:
    """
    Handle incoming text prompts from the user.
    
    Workflow:
    1. Pasted Secret Interceptor: Scans for API keys, passwords, and seeds. Deletes immediately if found.
    2. LLM Routing: Replies directly or selects the existing browser task path.
       Browser concurrency is checked only when a browser task is requested.
    3. TaskRecord Creation: Initializes state machine and persists to database.
    4. Throttled Status Card: Sends initial Telegram status card.
    5. Registry & Execution: Registers background task in task_registry and begins runner.
    """
    # Ignore slash commands (they are caught by command filters)
    if message.text and message.text.startswith("/"):
        return

    text = message.text.strip()
    if not text:
        return
    chat_id = message.chat.id
    user_id = message.from_user.id if message.from_user else 0

    # 1. Pasted Secret Interceptor (Design Rule 1)
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
            "👉 Please use the <b>Wilco Companion App</b> (/login) to securely add credentials to your encrypted vault."
        )
        await message.answer(warning_text)
        return

    # Resume task-bound input before routing; one-time codes must bypass LLM logs.
    pending = task_registry.get_chat_input(chat_id)
    if pending:
        if user_id != pending.task.user_id:
            return
        async with pending.lock:
            if not pending.is_pending:
                await message.answer("That input request has expired.")
                return
            reply = getattr(message, "reply_to_message", None)
            if not reply or reply.message_id != pending.prompt_message_id:
                await message.answer("Please reply to my input question so I can resume your task.")
                return
            if pending.field == "otp":
                code = normalize_otp(text)
                if code is None:
                    await message.answer("Please reply with only the 4–12 character code, using letters or numbers.")
                    return
                text = code
            elif len(text) > 320 or "\n" in text:
                await message.answer("Please send only the requested username or email, on one line.")
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
        await message.answer("Received. Continuing your browser task.")
        return

    # Replies to an expired/consumed OTP prompt must not become fresh model requests.
    reply = getattr(message, "reply_to_message", None)
    if (
        reply and isinstance(reply.text, str) and reply.text.startswith(OTP_PROMPT_PREFIX)
        and reply.from_user and reply.from_user.id == message.bot.id
    ):
        await message.answer("That code request has expired or has already been answered.")
        return

    # 2. Decide whether this message needs a browser before creating any task.
    request_id = f"telegram:{chat_id}:{message.message_id}"
    routing_started = asyncio.get_running_loop().time()
    try:
        decision = await route_message(text, request_id=request_id)
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
        logger.info("Routing[%s] direct reply delivered", request_id)
        return

    # Allow direct replies while keeping the existing browser concurrency check.
    if task_registry.get_by_chat(chat_id):
        logger.info("Routing[%s] browser handoff rejected: active task exists", request_id)
        await message.answer(
            "⚠️ A task is already running in this chat.\n"
            "Please wait for it to complete or send /cancel to stop it before starting another."
        )
        return

    logger.info("Routing[%s] starting browser task for user %s", request_id, user_id)

    # 3. Create persistent TaskRecord domain entity
    task = TaskRecord(
        user_id=user_id,
        chat_id=chat_id,
        prompt=text,
        status_message="Task received. Initializing worker...",
    )

    # Persist initial task in database (Design Rule 4)
    try:
        async with async_session_factory() as session:
            await TaskRepository.save_task(session, task)
            await session.commit()
    except Exception as exc:
        logger.warning("Failed to persist initial task record: %s", exc)

    # 4. Initialize throttled status manager
    status_manager = StatusManager(bot=message.bot)
    await status_manager.send_initial(task)

    # 5. Launch background execution with registry tracking
    bg_task = asyncio.create_task(run_browser_task(task, status_manager, message.bot))
    task_registry.register(chat_id, task, bg_task, status_manager)
    logger.info("Routing[%s] browser task registered task_id=%s", request_id, task.task_id)
