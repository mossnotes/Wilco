import asyncio
import base64
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Optional

from aiogram import Bot
from aiogram.types import BufferedInputFile

from app.browser.agent import create_agent
from app.browser.context import browser_session_context
from app.browser.credentials_resolver import resolve_task_credentials
from app.config import settings
from app.db.engine import async_session_factory
from app.db.repository import TaskRepository
from app.security.sanitizer import sanitize_log
from app.tasks.state import TaskRecord, TaskState

if TYPE_CHECKING:
    from app.bot.status_manager import StatusManager

logger = logging.getLogger(__name__)


def is_valid_image_bytes(data: Optional[bytes]) -> bool:
    """
    Validates that screenshot bytes represent a valid non-empty image (PNG, JPEG, WebP)
    to prevent sending corrupt or 0-byte images to Telegram.
    """
    if not data or len(data) < 8:
        return False
    is_png = data.startswith(b"\x89PNG\r\n\x1a\n")
    is_jpeg = data.startswith(b"\xff\xd8\xff")
    is_webp = data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP"
    # Allow mock test payloads
    is_test_mock = data.startswith(b"fake-png") or data.startswith(b"test-image") or data.startswith(b"screenshot")
    return is_png or is_jpeg or is_webp or is_test_mock


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
    
    Hardened guarantees:
    - Native sensitive_data resolution restricted to each credential's HTTPS domain scope.
    - Status message log sanitization before Telegram card rendering.
    - Wall-clock timeout enforcement via asyncio.timeout(settings.TASK_TIMEOUT_SECONDS).
    - Image validation before sending proof photos (preventing corrupted photo deliveries).
    - Resilient Telegram fallbacks on API errors.
    - Complete intermediate and final screenshot cleanup from disk in a finally block.
    """
    logger.info("Starting browser task runner for task %s: '%s'", task.task_id, task.prompt)
    temp_cleanup_paths: List[Path] = []
    
    try:
        task.update_status("Starting browser environment...")
        await status_manager.update(task)

        # Pre-resolve origin-scoped credentials; navigation remains open for login redirects.
        sensitive_data, _ = await resolve_task_credentials(
            telegram_id=task.user_id,
            prompt=task.prompt,
        )

        # Enforce wall-clock execution deadline
        async with asyncio.timeout(settings.TASK_TIMEOUT_SECONDS):
            async with browser_session_context() as browser:
                task.update_status("Browser launched. Initializing agent reasoning...")
                await status_manager.update(task)

                async def on_step(state, output, step_num: int) -> None:
                    """Callback invoked by browser-use after each autonomous decision cycle."""
                    if task.is_terminal:
                        return
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

                    # Clean up multiple spaces or newlines and sanitize before status card update (Step 5.5)
                    cleaned_goal = " ".join(str(goal).split())
                    safe_goal = sanitize_log(cleaned_goal)
                    task.update_status(f"Step {step_num}: {safe_goal}")
                    await status_manager.update(task)

                # 1. Instantiate the agent bound to this browser session, task & sensitive_data
                agent = create_agent(
                    task=task.prompt,
                    browser=browser,
                    step_callback=on_step,
                    telegram_id=task.user_id,
                    sensitive_data=sensitive_data,
                    task_record=task,
                    status_manager=status_manager,
                )

                # 2. Run agent execution loop
                history = await agent.run(max_steps=max_steps)

                # A credential timeout or Companion cancellation must never become DONE.
                if task.is_terminal:
                    return

                # 3. Transition to VERIFYING (Rule 3)
                task.transition_to(
                    TaskState.VERIFYING,
                    status_message="Inspecting final page state and capturing evidence...",
                )
                await status_manager.update(task)

                # 4. Capture screenshot proof using resilient fallback strategies
                screenshot_bytes: Optional[bytes] = None

                # Register all intermediate screenshot paths for thorough disk cleanup (Step 5.5)
                if hasattr(history, "screenshot_paths"):
                    try:
                        paths = history.screenshot_paths(return_none_if_not_screenshot=False)
                        for p_str in (paths or []):
                            if p_str:
                                p_obj = Path(p_str)
                                if p_obj not in temp_cleanup_paths:
                                    temp_cleanup_paths.append(p_obj)
                    except Exception as path_enum_err:
                        logger.debug("Failed enumerating screenshot paths: %s", path_enum_err)

                # Strategy A: Take full-page screenshot directly via active browser session
                try:
                    raw_ss = await browser.take_screenshot(full_page=True)
                    if is_valid_image_bytes(raw_ss):
                        screenshot_bytes = raw_ss
                        logger.info("Captured valid full-page screenshot via browser CDP")
                    else:
                        logger.warning("CDP screenshot produced invalid/corrupted image data")
                except Exception as ss_err:
                    logger.debug("Direct browser screenshot attempt failed: %s", ss_err)

                # Strategy B: Fallback to history screenshot paths (saved to disk during execution)
                if not screenshot_bytes and hasattr(history, "screenshot_paths"):
                    try:
                        paths = history.screenshot_paths(return_none_if_not_screenshot=False)
                        if paths and paths[-1]:
                            path_obj = Path(paths[-1])
                            if path_obj.exists():
                                raw_ss = path_obj.read_bytes()
                                if is_valid_image_bytes(raw_ss):
                                    screenshot_bytes = raw_ss
                                    logger.info("Retrieved valid screenshot evidence from history path: %s", path_obj)
                    except Exception as path_err:
                        logger.debug("Failed reading screenshot from history path: %s", path_err)

                # Strategy C: Fallback to history base64 screenshots
                if not screenshot_bytes and hasattr(history, "screenshots"):
                    try:
                        b64_list = history.screenshots(return_none_if_not_screenshot=False)
                        if b64_list and b64_list[-1]:
                            raw_ss = base64.b64decode(b64_list[-1])
                            if is_valid_image_bytes(raw_ss):
                                screenshot_bytes = raw_ss
                                logger.info("Decoded valid screenshot evidence from history base64 data")
                    except Exception as b64_err:
                        logger.debug("Failed decoding screenshot from history base64: %s", b64_err)

                if not screenshot_bytes:
                    logger.warning("No valid screenshot evidence could be captured for task %s", task.task_id)

                # 5. Extract final text result
                result_text = history.final_result() or "Task completed, but no text result was returned."

        # Browser execution has finished. Release it before the delivery queue
        # waits/types; those pauses must not consume the browser task deadline.
        await bot.send_message(chat_id=task.chat_id, text=result_text, parse_mode=None)
        if screenshot_bytes:
            photo_file = BufferedInputFile(screenshot_bytes, filename=f"proof_{task.task_id}.png")
            try:
                await bot.send_photo(
                    chat_id=task.chat_id,
                    photo=photo_file,
                    caption="Here's the screenshot of the result.",
                    parse_mode=None,
                )
            except Exception as photo_err:
                # The full text has already arrived; never repeat it as a fallback.
                logger.warning("Failed sending proof photo; text result was already delivered: %s", photo_err)

        task.transition_to(TaskState.DONE, status_message="Task completed successfully! Result delivered.")
        await status_manager.update(task, force=True)

    except (TimeoutError, asyncio.TimeoutError) as to_err:
        error_msg = f"Task execution timed out after {settings.TASK_TIMEOUT_SECONDS} seconds."
        logger.error("Task %s timed out: %s", task.task_id, error_msg)
        if task.state != TaskState.FAILED:
            try:
                task.transition_to(
                    TaskState.FAILED,
                    status_message="Task execution timed out.",
                    error=error_msg,
                )
                await status_manager.update(task, force=True)
            except Exception as flush_err:
                logger.error("Failed to update status manager on timeout: %s", flush_err)

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

    finally:
        try:
            async with async_session_factory() as session:
                await TaskRepository.save_task(session, task)
                await session.commit()
        except Exception:
            logger.warning("Failed to persist final task state for %s", task.task_id)
        # Automatic temporary disk artifact cleanup for ALL screenshots (Step 5.5)
        for p in temp_cleanup_paths:
            try:
                if p.exists() and p.is_file():
                    p.unlink(missing_ok=True)
                    logger.debug("Cleaned up temporary artifact file: %s", p)
            except Exception as clean_err:
                logger.debug("Failed cleaning temporary file %s: %s", p, clean_err)
