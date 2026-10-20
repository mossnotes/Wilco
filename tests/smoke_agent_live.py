import asyncio
import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.abspath("."))

from app.browser import browser_session_context, create_agent, create_browser
from app.config import settings

async def main():
    print(f"Provider: {settings.LLM_PROVIDER}")
    print(f"Model: {settings.LLM_MODEL}")
    has_key = bool(settings.effective_gemini_api_key)
    print(f"Gemini API key loaded: {has_key}")

    if not has_key:
        print("ERROR: No Gemini API key detected in settings!")
        return

    async with browser_session_context(headless=True) as browser:
        def step_callback(state, output, step_num):
            goal = getattr(output, "next_goal", "") or getattr(output, "current_plan_item", "")
            print(f"📍 [Step {step_num}] Agent intent: {goal}")

        task = "Go to https://example.com, check the heading, and return the heading text."
        agent = create_agent(
            task=task,
            browser=browser,
            step_callback=step_callback,
        )

        print("\n🚀 Starting Agent execution...")
        history = await agent.run(max_steps=5)
        print("\n🏁 Agent execution finished!")
        print(f"Success: {history.is_successful()}")
        print(f"Steps: {history.number_of_steps()}")
        print(f"Final Result: {history.final_result()}")

if __name__ == "__main__":
    asyncio.run(main())
