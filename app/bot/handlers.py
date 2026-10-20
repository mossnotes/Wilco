import asyncio
import logging
from aiogram import Router, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message

from app.tasks.state import TaskRecord, TaskState
from app.bot.status_manager import StatusManager
from app.browser.runner import run_browser_task

logger = logging.getLogger(__name__)
router = Router(name="main_router")


@router.message(CommandStart())
async def handle_start(message: Message) -> None:
    """
    Handle the /start command.
    
    Greets the user and explicitly states our security guarantees:
    Passwords and sensitive secrets must NEVER be entered in Telegram chat.
    All credentials are provided exclusively via the companion web app (Design Rule 1).
    """
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
    """
    Handle the /help command.
    
    Provides instructions on how to interact with Wilco and initiate tasks.
    """
    help_text = (
        "🤖 <b>Wilco Commands & Usage</b>\n\n"
        "• <b>/start</b> - Show welcome and status\n"
        "• <b>/help</b> - Show this help guide\n\n"
        "💡 <b>Running a Task:</b>\n"
        "Simply send a message with the action you want completed (e.g., <i>\"Check Vercel deployments\"</i>).\n"
        "I will create a task and update a single status message in-place as progress occurs."
    )
    await message.answer(help_text)


async def _run_simulated_task_lifecycle(task: TaskRecord, status_manager: StatusManager) -> None:
    """
    Background worker simulating task execution for Step 1 verification.

    Why this simulation exists in Step 1:
    In Step 1, we are establishing the backend foundation, the Task State Machine,
    and the throttled status message updater before plugging in the real Browser-Use agent.
    This background coroutine demonstrates that:
      1. The initial status message is created.
      2. Status text updates progressively in place.
      3. State transitions follow legal paths (RUNNING -> VERIFYING -> DONE).
      4. Throttling prevents Telegram 429 rate limits.

    In Step 2, this simulation coroutine will be swapped with the real Browser-Use agent runner!
    """
    try:
        # Step 1: Simulate initial browser navigation
        await asyncio.sleep(1.0)
        task.update_status("Launching remote browser and navigating to site...")
        await status_manager.update(task)

        # Step 2: Simulate page action / data extraction
        await asyncio.sleep(1.5)
        task.update_status("Locating target elements and extracting requested data...")
        await status_manager.update(task)

        # Step 3: Transition to VERIFYING (Enforcing Design Rule 3: Verifier checks state before Done)
        await asyncio.sleep(1.5)
        task.transition_to(
            TaskState.VERIFYING,
            status_message="Inspecting page state and confirming goal criteria...",
        )
        await status_manager.update(task)

        # Step 4: Transition to DONE (Terminal state: forced immediate flush)
        await asyncio.sleep(1.5)
        task.transition_to(
            TaskState.DONE,
            status_message="Goal verified successfully! Data extraction complete.",
        )
        await status_manager.update(task, force=True)

    except Exception as exc:
        logger.error(f"Error during simulated task {task.task_id}: {exc}")
        task.transition_to(
            TaskState.FAILED,
            status_message="Task execution failed.",
            error=str(exc),
        )
        await status_manager.update(task, force=True)


@router.message(F.text)
async def handle_text_message(message: Message) -> None:
    """
    Handle incoming text prompts from the user.
    
    Workflow:
    1. Extracts the user's prompt text.
    2. Instantiates a TaskRecord with unique ID and initial RUNNING state.
    3. Posts the initial status message to Telegram using StatusManager.
    4. Spawns the background task loop which progressively edits the message in place.
    """
    # Ignore commands that start with slash (they are caught by command filters)
    if message.text and message.text.startswith("/"):
        return

    task_prompt = message.text.strip()
    user_id = message.from_user.id if message.from_user else 0
    chat_id = message.chat.id

    logger.info(f"Initiating task for user {user_id} in chat {chat_id}: '{task_prompt}'")

    # 1. Create the persistent TaskRecord domain entity
    task = TaskRecord(
        user_id=user_id,
        chat_id=chat_id,
        prompt=task_prompt,
        status_message="Task received. Initializing worker...",
    )

    # 2. Initialize the throttled status manager for this bot session
    status_manager = StatusManager(bot=message.bot)

    # 3. Post the initial status message in Telegram (records task.message_id)
    await status_manager.send_initial(task)

    # 4. Launch the task execution in a non-blocking background task
    # This runs the live browser-use agent and streams step-by-step progress
    # while freeing the webhook handler to return 200 OK to Telegram immediately!
    asyncio.create_task(run_browser_task(task, status_manager, message.bot))
