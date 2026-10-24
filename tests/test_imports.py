"""Runtime entry points must import independently of pytest's module order."""

import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("module", [
    "app.browser.context",
    "app.browser.runner",
    "app.bot.memory",
    "app.bot.setup",
    "app.bot.message_router",
    "app.companion.routes",
    "app.main",
])
def test_runtime_module_imports_in_fresh_process(module, tmp_path):
    project_root = Path(__file__).resolve().parents[1]
    env = {
        **os.environ,
        "PYTHONPATH": str(project_root),
        "TELEGRAM_BOT_TOKEN": "",
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "BOT_MODE": "webhook",
        "VAULT_MASTER_KEY": "",
        "GEMINI_API_KEY": "",
        "GOOGLE_API_KEY": "",
        "OPENAI_API_KEY": "",
        "ANTHROPIC_API_KEY": "",
        "BROWSERBASE_API_KEY": "",
        "ANONYMIZED_TELEMETRY": "false",
    }
    result = subprocess.run(
        [sys.executable, "-c", f"import importlib; importlib.import_module({module!r})"],
        # A clean working directory prevents loading the developer's .env.
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stderr
