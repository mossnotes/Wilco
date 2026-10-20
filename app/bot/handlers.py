import logging
from aiogram import Router, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message

logger = logging.getLogger(__name__)
router = Router(name="main_router")


@router.message(CommandStart())
async def handle_start(message: Message) -> None:
    """Handle /start command with greeting and security notice."""
    user_name = message.from_user.first_name if message.from_user else "there"
    welcome_text = (
        f"👋 Hello {user_name}! I am <b>Wilco</b>, your Telegram Browser & Tasks Assistant.\n\n"
        "I can automate tasks on the web using a managed browser.\n\n"
        "🔒 <b>Security First:</b>\n"
        "• Never paste passwords, API keys, or OTPs in this chat.\n"
        "• All credentials and sensitive inputs are entered through our companion web app.\n\n"
        "Type /help to see what I can do or send me a prompt to get started!"
    )
    await message.answer(welcome_text)


@router.message(Command("help"))
async def handle_help(message: Message) -> None:
    """Handle /help command."""
    help_text = (
        "🤖 <b>Wilco Commands & Usage</b>\n\n"
        "• <b>/start</b> - Show welcome and status\n"
        "• <b>/help</b> - Show this help guide\n\n"
        "💡 <b>Running a Task:</b>\n"
        "Simply send a message with the action you want completed, and I will report back progress in a live status message."
    )
    await message.answer(help_text)


@router.message(F.text)
async def handle_text_message(message: Message) -> None:
    """Handle incoming text prompts (task initiation stub)."""
    task_prompt = message.text.strip()
    logger.info(f"Received task request from user {message.from_user.id if message.from_user else 'unknown'}: {task_prompt}")
    await message.answer(
        f"⏳ Received task request: <i>\"{task_prompt}\"</i>\n\n"
        "Browser task execution pipeline will be linked in the next step."
    )

