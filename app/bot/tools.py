"""Main-assistant tool catalog and authenticated, application-owned actions."""

import logging
from dataclasses import dataclass
from typing import Literal

from aiogram.enums import ChatType
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, Message, WebAppInfo

from app.config import settings
from app.db.engine import async_session_factory
from app.db.repository import IdentityTokenRepository, UserRepository
from app.tasks.registry import task_registry
from app.tasks.state import TaskState

logger = logging.getLogger(__name__)
ToolRoute = Literal["browser", "companion", "help", "cancel"]


@dataclass(frozen=True)
class AssistantTool:
    name: str
    route: ToolRoute
    description: str


ASSISTANT_TOOLS = (
    AssistantTool("start_browser_task", "browser", (
        "Start one managed browser task for the user's complete current request. "
        "Use for web research, current or account-specific information, inspecting "
        "a URL, and requested website actions, including logging into a website. "
        "Do not use for greetings, general explanations, help using Wilco, opening "
        "Wilco's Companion App, stopping a Wilco task, or ambiguous requests. "
        "The application supplies the original message, authenticated user, and "
        "current chat; this function takes no arguments. The runner handles secure "
        "login and delivers the result. Calling it starts work, not proof of success."
    )),
    AssistantTool("open_companion", "companion", (
        "Open Wilco's secure Companion App for the requesting user. Use when they "
        "ask to get set up, link their Telegram account, open the Companion, or "
        "add/manage saved credentials. Sends a real, short-lived pairing button "
        "directly in their private chat, or reopens their pending credential request. "
        "Never use just for a greeting, to log into an external website, or to ask "
        "for a one-time code. Never collect passwords, API keys, or authenticator "
        "seeds in chat. Takes no arguments: identity, destination and URL are bound "
        "by the application, never supplied by the model. Does not read, change, "
        "or reveal stored credentials; the user manages them in the Companion."
    )),
    AssistantTool("show_help", "help", (
        "Send a short guide to using Wilco, its capabilities, secure credential "
        "entry, and how to request or stop tasks in natural language. Use when the "
        "user asks for help using this assistant or what it can do. Not for generic "
        "requests like 'help me write a letter' or help with an external website. "
        "Read-only: no login links, browser work, cancellation, or account changes. "
        "Takes no arguments and sends the guide in the current chat."
    )),
    AssistantTool("cancel_current_task", "cancel", (
        "Stop the requesting user's currently running or paused Wilco task in this "
        "chat. Use only for a clear request to stop/cancel the assistant's current "
        "work, such as 'stop the current task'. Never use for a question about "
        "cancellation, negated or quoted instructions, or cancellation of an "
        "external order, subscription, booking, or account. Ambiguous requests need "
        "clarification. Takes no arguments: the application verifies ownership and "
        "selects the active task in this chat. Cannot target another user/chat, "
        "cancel completed work, undo website actions, or guarantee rollback. "
        "The application reports whether a task was actually stopped."
    )),
)
TOOL_ROUTES = {tool.name: tool.route for tool in ASSISTANT_TOOLS}


async def open_companion(message: Message) -> None:
    """Deliver a pairing link only to its authenticated owner's private chat."""
    user_id = message.from_user.id if message.from_user else None
    if not user_id or message.chat.type != ChatType.PRIVATE or message.chat.id != user_id:
        await message.answer("Message me privately to open your secure Companion App.", parse_mode=None)
        return

    active = task_registry.get_by_chat(message.chat.id)
    task = active[0] if active else None
    url = (
        task.metadata.get("companion_url")
        if task and task.user_id == user_id and task.state == TaskState.NEEDS_INPUT else None
    )
    if not url:
        try:
            async with async_session_factory() as session:
                await UserRepository.get_or_create_by_telegram_id(session, user_id)
                token = await IdentityTokenRepository.create_token(
                    session, user_id, ttl_minutes=settings.COMPANION_TOKEN_TTL_MINUTES,
                )
                await session.commit()
            url = f"{settings.COMPANION_BASE_URL.rstrip('/')}/link?token={token.token}"
        except Exception as exc:
            logger.warning("Companion pairing failed for user %s (%s)", user_id, type(exc).__name__)
            await message.answer("I couldn't create your Companion link. Please try again.", parse_mode=None)
            return

    button = (
        InlineKeyboardButton(text="Open Wilco Companion App", web_app=WebAppInfo(url=url))
        if url.startswith("https://") else InlineKeyboardButton(text="Open Wilco Companion App", url=url)
    )
    await message.answer(
        "Here's your secure Companion link. Use it to link your account or manage your saved credentials.",
        parse_mode=None, reply_markup=InlineKeyboardMarkup(inline_keyboard=[[button]]),
    )


async def show_help(message: Message) -> None:
    await message.answer(
        "I can answer questions, research the web, and carry out tasks on websites. Just tell me what you need.\n\n"
        "Try 'check my Vercel deployments', 'open my Companion App', or 'stop the current task'.\n\n"
        "Keep passwords and API keys in the Companion App. If a site needs a one-time code, "
        "I'll ask you to reply to a specific message and tell you where to find it.",
        parse_mode=None,
    )


async def cancel_current_task(message: Message) -> None:
    user_id = message.from_user.id if message.from_user else None
    cancelled = bool(user_id) and await task_registry.cancel_task_by_chat(message.chat.id, user_id=user_id)
    await message.answer(
        "Stopped your current task. Actions already completed on a website may still apply."
        if cancelled else "There isn't an active task of yours to stop in this chat.",
        parse_mode=None,
    )


async def execute_assistant_tool(route: ToolRoute, message: Message) -> None:
    """Execute only allowlisted local actions; no LLM-supplied parameters."""
    handlers = {"companion": open_companion, "help": show_help, "cancel": cancel_current_task}
    if route not in handlers:
        raise ValueError("Unsupported assistant action")
    await handlers[route](message)
