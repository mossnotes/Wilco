import logging
from typing import Any, Callable, Optional
from browser_use import Agent, Browser
from app.browser.llm import get_llm

logger = logging.getLogger(__name__)


def create_agent(
    task: str,
    browser: Optional[Browser] = None,
    llm: Optional[Any] = None,
    step_callback: Optional[Callable] = None,
    max_failures: int = 3,
    use_vision: bool = True,
    **kwargs: Any,
) -> Agent:
    """
    Factory creating a configured browser-use Agent instance.
    
    Args:
        task: Natural language description of what the agent needs to achieve.
        browser: Active BrowserSession instance (or None to let browser-use launch one).
        llm: Initialized LLM model instance (or None to load from application settings).
        step_callback: Optional callback invoked on each agent step with (state, output, step_number).
        max_failures: Maximum consecutive failures before agent halts.
        use_vision: Whether the agent should inspect page screenshots/visual elements.
        **kwargs: Additional parameters forwarded to Agent.__init__.
    """
    agent_llm = llm or get_llm()
    logger.info("Creating browser-use Agent for task: %s", task)

    agent_kwargs: dict[str, Any] = {
        "task": task,
        "llm": agent_llm,
        "browser": browser,
        "max_failures": max_failures,
        "use_vision": use_vision,
        **kwargs,
    }

    if step_callback is not None:
        agent_kwargs["register_new_step_callback"] = step_callback

    return Agent(**agent_kwargs)

