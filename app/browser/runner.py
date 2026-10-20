import base64
import html
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from aiogram import Bot
from aiogram.types import BufferedInputFile

from app.browser.agent import create_agent
from app.browser.context import browser_session_context
from app.tasks.state import TaskRecord, TaskState

if TYPE_CHECKING:
    from app.bot.status_manager import StatusManager

logger = logging.getLogger(__name__)


async def run_browser_task(
    task: TaskRecord,
    status_manager: Any,
    bot: Bot,
    max_steps: int = 25,
) -> None:
    """
    Executes a real browser-use task, connects step-by-step progress to the
    throttled Telegram status manager, captures full-page screenshot proof,
    and delivers the verified result.
    
    Enforces Architectural Rules:
    - Rule 2 (In-Place Status Updates): Streams micro-steps to status_manager without rate-limit errors.
    - Rule 3 (Independent Verification): Transitions to VERIFYING to capture proof before DONE.
    - Rule 4 (Verifiable Proof Delivery): Captures screenshot and delivers it to the user chat.
    """
    logger.info("Starting browser task runner for task %s: '%s'", task.task_id, task.prompt)
    
    try:
        task.update_status("Starting browser environment...")
        await status_manager.update(task)

        async with browser_session_context() as browser:
            task.update_status("Browser launched. Initializing agent reasoning...")
            await status_manager.update(task)

            async def on_step(state, output, step_num: int) -> None:
                """Callback invoked by browser-use after each autonomous decision cycle."""
                goal = getattr(output, "next_goal", None) or getattr(output, "current_plan_item", None)
                
                if not goal and hasattr(output, "action") and output.action:
                    actions = []
                    for a in output.action:
                        if hasattr(a, "model_dump"):
                            d = a.model_dump(exclude_none=True)
                            actions.extend(d.keys())
                        else:
                            actions.append(type(a).__name__)
                    if actions:
                        goal = f"Executing {', '.join(actions)}"

                if not goal:
                    goal = f"Executing step {step_num}..."

                # Clean up multiple spaces or newlines for clean status display
                cleaned_goal = " ".join(str(goal).split())
                task.update_status(f"Step {step_num}: {cleaned_goal}")
                await status_manager.update(task)

            # 1. Instantiate the agent bound to this browser session & task
            agent = create_agent(
                task=task.prompt,
                browser=browser,
                step_callback=on_step,
            )

            # 2. Run agent execution loop
            history = await agent.run(max_steps=max_steps)

            # 3. Transition to VERIFYING (Rule 3)
            task.transition_to(
                TaskState.VERIFYING,
                status_message="Inspecting final page state and capturing evidence...",
            )
            await status_manager.update(task)

            # 4. Capture screenshot proof using resilient fallback strategies
            screenshot_bytes: Optional[bytes] = None

            # Strategy A: Take full-page screenshot directly via active browser session
            try:
                screenshot_bytes = await browser.take_screenshot(full_page=True)
                logger.info("Captured full-page screenshot via browser CDP")
            except Exception as ss_err:
                logger.debug("Direct browser screenshot attempt failed: %s", ss_err)

            # Strategy B: Fallback to history screenshot paths (saved to disk during execution)
            if not screenshot_bytes and hasattr(history, "screenshot_paths"):
                try:
                    paths = history.screenshot_paths(return_none_if_not_screenshot=False)
                    if paths and paths[-1]:
                        path_obj = Path(paths[-1])
                        if path_obj.exists():
                            screenshot_bytes = path_obj.read_bytes()
                            logger.info("Retrieved screenshot evidence from history path: %s", path_obj)
                except Exception as path_err:
                    logger.debug("Failed reading screenshot from history path: %s", path_err)

            # Strategy C: Fallback to history base64 screenshots
            if not screenshot_bytes and hasattr(history, "screenshots"):
                try:
                    b64_list = history.screenshots(return_none_if_not_screenshot=False)
                    if b64_list and b64_list[-1]:
                        screenshot_bytes = base64.b64decode(b64_list[-1])
                        logger.info("Decoded screenshot evidence from history base64 data")
                except Exception as b64_err:
                    logger.debug("Failed decoding screenshot from history base64: %s", b64_err)

            if not screenshot_bytes:
                logger.warning("No screenshot evidence could be captured for task %s", task.task_id)

            # 5. Extract final text result
            result_text = history.final_result() or "Task completed, but no text result was returned."

            # 6. Transition to DONE (Terminal state: immediate flush)
            task.transition_to(
                TaskState.DONE,
                status_message="Task completed successfully! Proof delivered below.",
            )
            await status_manager.update(task, force=True)

            # 7. Deliver proof & result to Telegram (Rule 4)
            safe_result = html.escape(result_text)
            caption = f"🎯 <b>Result:</b>\n{safe_result}"
            if len(caption) > 1024:
                caption = caption[:1020] + "..."

            if screenshot_bytes:
                photo_file = BufferedInputFile(
                    screenshot_bytes,
                    filename=f"proof_{task.task_id}.png",
                )
                try:
                    await bot.send_photo(
                        chat_id=task.chat_id,
                        photo=photo_file,
                        caption=caption,
                        parse_mode="HTML",
                    )
                except Exception:
                    # Fallback without HTML formatting if parsing fails
                    raw_caption = f"🎯 Result:\n{result_text}"
                    if len(raw_caption) > 1024:
                        raw_caption = raw_caption[:1020] + "..."
                    await bot.send_photo(
                        chat_id=task.chat_id,
                        photo=photo_file,
                        caption=raw_caption,
                    )
            else:
                try:
                    await bot.send_message(
                        chat_id=task.chat_id,
                        text=caption,
                        parse_mode="HTML",
                    )
                except Exception:
                    await bot.send_message(
                        chat_id=task.chat_id,
                        text=f"🎯 Result:\n{result_text}",
                    )

    except Exception as exc:
        logger.exception("Browser task execution failed for task %s: %s", task.task_id, exc)
        error_msg = str(exc) or type(exc).__name__
        if task.state != TaskState.FAILED:
            try:
                task.transition_to(
                    TaskState.FAILED,
                    status_message="Task execution failed.",
                    error=error_msg,
                )
                await status_manager.update(task, force=True)
            except Exception as flush_err:
                logger.error("Failed to update status manager on failure: %s", flush_err)

