import asyncio
import logging
from aiogram import F, Router
from aiogram.filters import Command, CommandStart
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, Message, WebAppInfo

from app.bot.status_manager import StatusManager
from app.browser.runner import run_browser_task
from app.config import settings
from app.db.engine import async_session_factory
from app.db.repository import IdentityTokenRepository, TaskRepository, UserRepository
from app.security.sanitizer import contains_sensitive_data
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
        "• Passwords, API keys, and OTPs must <b>never</b> be pasted in this chat.\n"
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
    2. Concurrency Check: Prevents overlapping task executions in the same chat.
    3. TaskRecord Creation: Initializes state machine and persists to database.
    4. Throttled Status Card: Sends initial Telegram status card.
    5. Registry & Execution: Registers background task in task_registry and begins runner.
    """
    # Ignore slash commands (they are caught by command filters)
    if message.text and message.text.startswith("/"):
        return

    text = message.text.strip()
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

    # 2. Concurrency check: check if task is already running in this chat
    if task_registry.get_by_chat(chat_id):
        await message.answer(
            "⚠️ A task is already running in this chat.\n"
            "Please wait for it to complete or send /cancel to stop it before starting another."
        )
        return

    logger.info("Initiating task for user %s in chat %s: '%s'", user_id, chat_id, text)

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
