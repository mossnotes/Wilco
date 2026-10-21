import base64
import os
from typing import Any, Literal
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Step 4 Security Hardening: Ensure telemetry is disabled before any browser_use modules load
os.environ.setdefault("ANONYMIZED_TELEMETRY", "false")


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

    # Database Settings
    DATABASE_URL: str = "sqlite+aiosqlite:///./wilco.db"

    # Cryptographic Vault Settings
    VAULT_MASTER_KEY: str = ""

    # Companion Web App Settings
    COMPANION_BASE_URL: str = "http://localhost:8000/companion"
    COMPANION_TOKEN_TTL_MINUTES: int = 10

    # Concurrency & Execution Limits
    MAX_CONCURRENT_BROWSERS: int = 2
    TASK_TIMEOUT_SECONDS: int = 300

    @field_validator("VAULT_MASTER_KEY")
    @classmethod
    def validate_vault_master_key(cls, v: str) -> str:
        key = v.strip()
        if not key:
            return ""
        try:
            decoded = base64.b64decode(key, validate=True)
            if len(decoded) != 32:
                raise ValueError(
                    f"VAULT_MASTER_KEY must decode to exactly 32 bytes (256 bits), got {len(decoded)} bytes"
                )
        except Exception as e:
            if isinstance(e, ValueError) and "32 bytes" in str(e):
                raise
            raise ValueError(f"VAULT_MASTER_KEY is not valid base64: {e}") from e
        return key

    @property
    def vault_key_bytes(self) -> bytes:
        """Returns the decoded 32-byte master key for AES-256-GCM operations."""
        if not self.VAULT_MASTER_KEY or not self.VAULT_MASTER_KEY.strip():
            raise ValueError("VAULT_MASTER_KEY is not configured in settings")
        return base64.b64decode(self.VAULT_MASTER_KEY.strip())

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

    # Privacy & Telemetry Settings (Step 4 Security Hardening)
    ANONYMIZED_TELEMETRY: bool = False

    @field_validator("ANONYMIZED_TELEMETRY", mode="before")
    @classmethod
    def parse_telemetry_value(cls, v: Any) -> bool:
        if isinstance(v, str):
            val = v.lower() in ("true", "1", "yes", "t")
        else:
            val = bool(v)
        os.environ["ANONYMIZED_TELEMETRY"] = "true" if val else "false"
        return val

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
