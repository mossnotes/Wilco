"""One LLM call to answer a message or hand it to the browser runner."""

import asyncio
import json
import logging
import time
from typing import Literal, Self
from uuid import uuid4

from browser_use.llm.messages import SystemMessage, UserMessage
from google import genai
from google.genai import errors, types
from pydantic import BaseModel, Field, model_validator

from app.browser.llm import get_llm
from app.config import settings
from app.security.sanitizer import REDACTED_LABEL, sanitize_log

logger = logging.getLogger(__name__)


def _log_gemini_payload(request_id: str, label: str, payload: object) -> None:
    """Log JSON bodies at DEBUG, redacting credential fields and known secrets."""
    if not logger.isEnabledFor(logging.DEBUG):
        return
    configured_secrets = tuple(value for value in (
        settings.GEMINI_API_KEY, settings.GOOGLE_API_KEY, settings.OPENAI_API_KEY,
        settings.ANTHROPIC_API_KEY, settings.TELEGRAM_BOT_TOKEN,
        settings.TELEGRAM_WEBHOOK_SECRET, settings.VAULT_MASTER_KEY,
        settings.BROWSERBASE_API_KEY,
    ) if value)
    sensitive_fields = {
        "apikey", "authorization", "password", "passwd", "pwd", "secret",
        "token", "accesstoken", "refreshtoken", "cookie", "setcookie",
        "otp", "totp", "totpseed", "seed", "thoughtsignature", "headers",
    }

    def scrub(value):
        if isinstance(value, dict):
            return {
                scrub(str(key)): REDACTED_LABEL
                if str(key).lower().replace("_", "").replace("-", "") in sensitive_fields
                else scrub(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [scrub(item) for item in value]
        if isinstance(value, str):
            for secret in configured_secrets:
                value = value.replace(secret, REDACTED_LABEL)
            return sanitize_log(value)
        return value

    logger.debug(
        "Routing[%s] Gemini %s_json=\n%s", request_id, label,
        json.dumps(scrub(payload), ensure_ascii=False, indent=2),
    )


SYSTEM_INSTRUCTIONS = """
You are Wilco, a personal assistant that can answer questions and execute web tasks.
Answer directly when the request can be fulfilled using the supplied message and
general knowledge: greetings, explanations, writing, and questions about your
capabilities. Use concise plain text, without HTML or Markdown, at most 4000
characters. For example, 'hello' and 'explain what Vercel is' need direct answers.

Use the browser tool when the user requests web research, current information,
account-specific information, inspection of a URL, or an action on a website.
For example, 'check my latest Vercel deployment' and 'find today's news' need it.
A website name alone does not require browsing. Never invent live facts, account
data, or a completed action. A browser call starts work; it is not proof of success.

You only have the latest message, with no conversation history or task status.
If essential details are missing, ask the user to include them in a complete new
request. Do not call a tool until the request is sufficiently clear. At most one
browser handoff is allowed per message. When handing off, let the application's
status card communicate progress rather than writing a separate acknowledgement.

Never request passwords, API keys, OTPs, or TOTP seeds in chat. 
"""

# This is a declaration, not an executable Python function exposed to the SDK.
# No arguments: the handler binds the original message and authenticated identity.
BROWSER_TOOL = types.FunctionDeclaration(
    name="start_browser_task",
    description=(
        "Start one managed browser task for the user's complete current request. "
        "Use for browsing or searching websites, reading current or account-specific "
        "information, inspecting a URL, and carrying out requested website actions. "
        "Do not use for greetings, general explanations, drafting text, or ambiguous "
        "requests that need clarification. The application supplies the original "
        "message, user identity, and chat; this function takes no arguments. It "
        "handles progress, secure login through the Companion App, and final result "
        "delivery. Calling it delegates work; it does not mean the task succeeded."
    ),
)


class MessageDecision(BaseModel):
    route: Literal["reply", "browser"]
    reply: str = Field(max_length=4000, description="Plain-text answer, or empty for browser routing.")

    @model_validator(mode="after")
    def require_reply_text(self) -> Self:
        self.reply = self.reply.strip()
        if self.route == "reply" and not self.reply:
            raise ValueError("A direct reply must contain text.")
        return self


async def route_message(text: str, *, request_id: str | None = None) -> MessageDecision:
    """Use the existing provider/model configuration; never launch a browser here."""
    request_id = request_id or uuid4().hex[:12]
    started = time.monotonic()
    logger.info(
        "Routing[%s] started provider=%s model=%s input_chars=%d deadline_seconds=%s",
        request_id, settings.LLM_PROVIDER, settings.LLM_MODEL, len(text), settings.ROUTING_TIMEOUT_SECONDS,
    )
    try:
        async with asyncio.timeout(settings.ROUTING_TIMEOUT_SECONDS):
            if settings.LLM_PROVIDER == "gemini":
                decision = await _route_with_gemini(text, request_id)
            else:
                # Preserve the structured routing for other configured providers.
                response = await get_llm().ainvoke(
                    [
                        SystemMessage(content=SYSTEM_INSTRUCTIONS + (
                            "\nReturn route='reply' with your answer, or route='browser' "
                            "with an empty reply to request the browser handoff."
                        )),
                        UserMessage(content=text),
                    ],
                    output_format=MessageDecision,
                )
                decision = MessageDecision.model_validate(response.completion)
    except asyncio.CancelledError:
        logger.info("Routing[%s] cancelled elapsed_seconds=%.3f", request_id, time.monotonic() - started)
        raise
    except Exception as exc:
        if isinstance(exc, errors.APIError):
            _log_gemini_payload(request_id, "error_response", exc.details)
        status = getattr(exc, "code", getattr(exc, "status_code", None))
        logger.warning(
            "Routing[%s] failed elapsed_seconds=%.3f error_type=%s provider_status=%s",
            request_id, time.monotonic() - started, type(exc).__name__,
            status if isinstance(status, int) else None,
        )
        # Exception messages can include prompts or credentials; do not log them.
        raise
    logger.info(
        "Routing[%s] completed route=%s reply_chars=%d elapsed_seconds=%.3f",
        request_id, decision.route, len(decision.reply), time.monotonic() - started,
    )
    return decision


async def _route_with_gemini(text: str, request_id: str) -> MessageDecision:
    """Native, single-turn function calling using Google's official async SDK."""
    api_key = settings.effective_gemini_api_key
    if not api_key:
        raise ValueError("Gemini API key is missing. Set GEMINI_API_KEY or GOOGLE_API_KEY.")

    http_options = types.HttpOptions(
        timeout=max(1, int(settings.ROUTING_TIMEOUT_SECONDS * 1000)),  # SDK uses milliseconds.
        retry_options=types.HttpRetryOptions(attempts=2),  # Initial attempt + one retry.
    )
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_INSTRUCTIONS,
        tools=[types.Tool(function_declarations=[BROWSER_TOOL])],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(mode="AUTO"),
        ),
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        candidate_count=1,
    )
    logger.debug(
        "Routing[%s] Gemini request api=generate_content tool=%s mode=AUTO "
        "automatic_execution=false http_timeout_ms=%d max_http_attempts=2",
        request_id, BROWSER_TOOL.name, http_options.timeout,
    )
    contents = [types.Content(role="user", parts=[types.Part.from_text(text=text)])]
    if logger.isEnabledFor(logging.DEBUG):
        _log_gemini_payload(request_id, "request", {
            "model": settings.LLM_MODEL,
            "contents": [content.model_dump(mode="json", exclude_none=True) for content in contents],
            "config": config.model_dump(mode="json", exclude_none=True),
        })
    api_started = time.monotonic()
    # Close async network resources on success, provider errors, and cancellation.
    async with genai.Client(api_key=api_key, http_options=http_options).aio as client:
        response = await client.models.generate_content(
            model=settings.LLM_MODEL,
            contents=contents,
            config=config,
        )
    if logger.isEnabledFor(logging.DEBUG):
        _log_gemini_payload(request_id, "response", response.model_dump(
            mode="json", exclude_none=True, exclude={"sdk_http_response"},
        ))
    usage = response.usage_metadata
    candidates = response.candidates or []
    logger.info(
        "Routing[%s] Gemini response elapsed_seconds=%.3f candidates=%d "
        "prompt_tokens=%s output_tokens=%s thinking_tokens=%s total_tokens=%s",
        request_id, time.monotonic() - api_started, len(candidates),
        usage.prompt_token_count if usage else None,
        usage.candidates_token_count if usage else None,
        usage.thoughts_token_count if usage else None,
        usage.total_token_count if usage else None,
    )
    for candidate in candidates:
        parts = (candidate.content.parts or []) if candidate.content else []
        calls = [part.function_call for part in parts if part.function_call is not None]
        logger.debug(
            "Routing[%s] candidate finish_reason=%s parts=%d tool_calls=%d "
            "allowed_tool_names=%s arguments_valid=%s",
            request_id, candidate.finish_reason, len(parts), len(calls),
            all(call.name == BROWSER_TOOL.name for call in calls),
            all(call.args in (None, {}) for call in calls),
        )
    return _parse_gemini_response(response)


def _parse_gemini_response(response: types.GenerateContentResponse) -> MessageDecision:
    """Accept a complete answer or exactly one allowed, argument-free handoff."""
    if not response.candidates or len(response.candidates) != 1:
        raise ValueError("Gemini did not return exactly one candidate.")
    candidate = response.candidates[0]
    if candidate.finish_reason != types.FinishReason.STOP:
        raise ValueError("Gemini response was blocked, truncated, or incomplete.")
    parts = candidate.content.parts if candidate.content else None
    if not parts:
        raise ValueError("Gemini returned no content.")

    calls = [part.function_call for part in parts if part.function_call is not None]
    if calls:
        if len(calls) != 1 or calls[0].name != BROWSER_TOOL.name:
            raise ValueError("Gemini returned an unsupported tool call.")
        if calls[0].args not in (None, {}):
            raise ValueError("The browser handoff does not accept arguments.")
        # A terminal handoff: the handler executes the original request and the
        # browser runner delivers its result. No invented tool result is returned.
        return MessageDecision(route="browser", reply="")

    reply = "".join(part.text for part in parts if part.text and not part.thought)
    return MessageDecision(route="reply", reply=reply)
