"""Main-assistant tool catalog and authenticated, application-owned actions."""

from dataclasses import dataclass
from typing import Literal

from aiogram.enums import ChatType
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, Message, WebAppInfo

from app.config import settings
from app.tasks.registry import task_registry

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
        "Vault, stopping a Wilco task, or ambiguous requests. "
        "Supply request as a complete instruction resolved from the latest message "
        "and relevant conversation context. Never expand its scope or repeat older "
        "actions without a current request. The application binds the authenticated "
        "user and current chat; no identity or destination arguments are accepted. The runner handles secure "
        "login and delivers the result. Calling it starts work, not proof of success."
    )),
    AssistantTool("open_companion", "companion", (
        "Open Vault, Wilco's secure credential store, for the requesting user. Use when they "
        "ask to get set up, link their Telegram account, open Vault, or "
        "add/manage saved credentials. Sends a persistent Vault button with Telegram sign-in "
        "directly in their private chat. Credential requests use separate one-time links. "
        "Never use just for a greeting, to log into an external website, or to ask "
        "for a one-time code. Never collect passwords, API keys, or authenticator "
        "seeds in chat. Takes no arguments: identity, destination and URL are bound "
        "by the application, never supplied by the model. Does not read, change, "
        "or reveal stored credentials; the user manages them in Vault."
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
        "chat, or the task awaiting their input in this private chat. Use only for "
        "a clear request to stop/cancel the assistant's current "
        "work, such as 'stop the current task'. Never use for a question about "
        "cancellation, negated or quoted instructions, or cancellation of an "
        "external order, subscription, booking, or account. Ambiguous requests need "
        "clarification. Takes no arguments: the application verifies ownership and "
        "selects the active task or the task bound to this private input request. "
        "Cannot target another user's task or an unrelated chat, "
        "cancel completed work, undo website actions, or guarantee rollback. "
        "The application reports whether a task was actually stopped."
    )),
)
TOOL_ROUTES = {tool.name: tool.route for tool in ASSISTANT_TOOLS}


async def open_companion(message: Message) -> str:
    """Deliver a stable Mini App address in the requester's private chat."""
    user_id = message.from_user.id if message.from_user else None
    if not user_id or message.chat.type != ChatType.PRIVATE or message.chat.id != user_id:
        await message.answer("Message me privately to open your Vault.", parse_mode=None)
        return "Vault access requires the requesting user's private chat; no link was issued."

    url = f"{settings.VAULT_BASE_URL.rstrip('/')}/vault/accounts"

    button = (
        InlineKeyboardButton(text="🔐 Open Vault", web_app=WebAppInfo(url=url))
        if url.startswith("https://") else InlineKeyboardButton(text="🔐 Open Vault", url=url)
    )
    await message.answer(
        "Here's your Vault. Manage your saved credentials here anytime.",
        parse_mode=None, reply_markup=InlineKeyboardMarkup(inline_keyboard=[[button]]),
    )
    return "A Vault access button was delivered privately to the requesting user."


async def show_help(message: Message) -> str:
    text = (
        "I can answer questions, research the web, and carry out tasks on websites. Just tell me what you need.\n\n"
        "Try 'check my Vercel deployments', 'open my Vault', or 'stop the current task'.\n\n"
        "Keep passwords and API keys in Vault. If a site needs a one-time code, "
        "I'll ask you to reply to a specific message and tell you where to find it."
    )
    await message.answer(text, parse_mode=None)
    return text


async def cancel_current_task(message: Message) -> str:
    user_id = message.from_user.id if message.from_user else None
    cancelled = bool(user_id) and await task_registry.cancel_task_by_chat(message.chat.id, user_id=user_id)
    text = (
        "Stopped your current task. Actions already completed on a website may still apply."
        if cancelled else "There isn't an active task of yours to stop in this chat."
    )
    await message.answer(text, parse_mode=None)
    return text


async def execute_assistant_tool(route: ToolRoute, message: Message) -> str:
    """Execute only allowlisted local actions; no LLM-supplied parameters."""
    handlers = {"companion": open_companion, "help": show_help, "cancel": cancel_current_task}
    if route not in handlers:
        raise ValueError("Unsupported assistant action")
    return await handlers[route](message)
