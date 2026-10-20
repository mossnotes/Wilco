from typing import Any, Literal
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "wilco"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    LOG_LEVEL: str = "INFO"

    @field_validator("DEBUG", mode="before")
    @classmethod
    def parse_debug_value(cls, v: Any) -> bool:
        if isinstance(v, str):
            return v.lower() in ("true", "1", "yes", "t", "dev", "debug")
        return bool(v)

    # Telegram Bot Settings
    TELEGRAM_BOT_TOKEN: str = ""
    BOT_MODE: Literal["webhook", "polling"] = "webhook"
    TELEGRAM_WEBHOOK_URL: str = ""
    TELEGRAM_WEBHOOK_SECRET: str = ""
    WEBHOOK_PATH: str = "/webhook/telegram"

    # Browser Engine Settings
    BROWSER_TYPE: Literal["local", "browserbase"] = "local"
    BROWSER_HEADLESS: bool = True
    BROWSERBASE_API_KEY: str = ""
    BROWSERBASE_PROJECT_ID: str = ""

    # LLM Provider Configuration
    LLM_PROVIDER: Literal["gemini", "openai", "anthropic"] = "gemini"
    LLM_MODEL: str = "gemini-3.8-flash"
    GEMINI_API_KEY: str = ""
    GOOGLE_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""

    @property
    def effective_gemini_api_key(self) -> str:
        """Returns the configured Gemini/Google API key (checks both GEMINI_API_KEY and GOOGLE_API_KEY)."""
        return (self.GEMINI_API_KEY or self.GOOGLE_API_KEY).strip()

    @field_validator("BROWSER_HEADLESS", mode="before")
    @classmethod
    def parse_headless_value(cls, v: Any) -> bool:
        if isinstance(v, str):
            return v.lower() in ("true", "1", "yes", "t")
        return bool(v)

    @property
    def is_bot_configured(self) -> bool:
        return bool(self.TELEGRAM_BOT_TOKEN and self.TELEGRAM_BOT_TOKEN.strip() and self.TELEGRAM_BOT_TOKEN != "your_bot_token_here")

    @property
    def full_webhook_url(self) -> str:
        if not self.TELEGRAM_WEBHOOK_URL:
            return ""
        base = self.TELEGRAM_WEBHOOK_URL.rstrip("/")
        path = self.WEBHOOK_PATH if self.WEBHOOK_PATH.startswith("/") else f"/{self.WEBHOOK_PATH}"
        return f"{base}{path}"


settings = Settings()
