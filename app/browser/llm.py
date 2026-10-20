import logging
from typing import Any, Optional
from browser_use import ChatGoogle, ChatOpenAI, ChatAnthropic
from app.config import settings

logger = logging.getLogger(__name__)


def get_llm(
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> Any:
    """
    Returns an initialized LLM chat client based on application configuration.
    Supports Google Gemini, OpenAI, and Anthropic.
    
    Raises:
        ValueError: If an unsupported provider is requested or the required API key is missing.
    """
    target_provider = (provider or settings.LLM_PROVIDER).lower().strip()
    target_model = model or settings.LLM_MODEL

    logger.info("Initializing LLM client for provider: %s, model: %s", target_provider, target_model)

    if target_provider == "gemini":
        api_key = settings.effective_gemini_api_key
        if not api_key:
            raise ValueError(
                "Gemini API key is missing. Please set GEMINI_API_KEY or GOOGLE_API_KEY in your .env file."
            )
        return ChatGoogle(model=target_model, api_key=api_key)

    elif target_provider == "openai":
        api_key = settings.OPENAI_API_KEY.strip()
        if not api_key:
            raise ValueError(
                "OpenAI API key is missing. Please set OPENAI_API_KEY in your .env file."
            )
        return ChatOpenAI(model=target_model, api_key=api_key)

    elif target_provider == "anthropic":
        api_key = settings.ANTHROPIC_API_KEY.strip()
        if not api_key:
            raise ValueError(
                "Anthropic API key is missing. Please set ANTHROPIC_API_KEY in your .env file."
            )
        return ChatAnthropic(model=target_model, api_key=api_key)

    else:
        raise ValueError(
            f"Unsupported LLM provider '{target_provider}'. "
            "Supported providers: 'gemini', 'openai', 'anthropic'."
        )

