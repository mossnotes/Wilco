import hashlib
import hmac
import json
import logging
import time
from typing import Optional
import uuid
from urllib.parse import parse_qsl

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.engine import get_db
from app.db.models import User
from app.db.repository import UserRepository
from app.security.vault import decrypt_secret, encrypt_secret

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = "wilco_session"
TELEGRAM_AUTH_MAX_AGE_SECONDS = 300


def validate_telegram_identity(init_data: str) -> int:
    """Verify Telegram Mini App initData before trusting its user ID.

    https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
    """
    try:
        if not settings.is_bot_configured:
            raise ValueError
        pairs = parse_qsl(init_data, keep_blank_values=True, strict_parsing=True, max_num_fields=32)
        data = dict(pairs)
        if len(data) != len(pairs):
            raise ValueError
        received_hash = data.pop("hash")
        check_string = "\n".join(f"{key}={value}" for key, value in sorted(data.items()))
        secret_key = hmac.digest(b"WebAppData", settings.TELEGRAM_BOT_TOKEN.encode(), "sha256")
        expected_hash = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_hash, received_hash):
            raise ValueError
        age = time.time() - int(data["auth_date"])
        if age < -30 or age > TELEGRAM_AUTH_MAX_AGE_SECONDS:
            raise ValueError
        user = json.loads(data["user"])
        telegram_id = user["id"]
        if type(telegram_id) is not int or not 0 < telegram_id < 2**52 or user.get("is_bot"):
            raise ValueError
        return telegram_id
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
        # Never include signed payloads, bot tokens, or parse errors in responses/logs.
        raise HTTPException(status_code=401, detail="Reopen the Companion App from Telegram.") from None


def create_session_token(
    user_id: uuid.UUID, telegram_id: int, ttl_days: int = 7
) -> str:
    """
    Creates an encrypted, authenticated session cookie payload using the vault master key.
    Zero-knowledge to client; tamper-resistant.
    """
    expires_at = time.time() + (ttl_days * 86400)
    payload = {
        "uid": str(user_id),
        "tg": telegram_id,
        "exp": expires_at,
    }
    serialized = json.dumps(payload)
    return encrypt_secret(serialized, settings.vault_key_bytes)


def decode_session_token(token_str: str) -> Optional[dict]:
    """
    Decrypts and validates the encrypted session token.
    Returns dict if valid and unexpired; None otherwise.
    """
    if not token_str or not token_str.strip():
        return None

    try:
        decrypted = decrypt_secret(token_str.strip(), settings.vault_key_bytes)
        data = json.loads(decrypted)

        # Check expiration
        if data.get("exp", 0) < time.time():
            logger.debug("Session token has expired")
            return None

        return {
            "uid": uuid.UUID(data["uid"]),
            "tg": int(data["tg"]),
        }
    except Exception as exc:
        logger.debug(f"Failed to decode session token: {exc}")
        return None


async def get_current_user_optional(
    request: Request, session: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """
    Extracts authenticated user from session cookie or Authorization header.
    Returns None if unauthenticated.
    """
    # A freshly verified Mini App identity takes priority over an older shared
    # WebView cookie (e.g. after switching Telegram accounts).
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else request.cookies.get(SESSION_COOKIE_NAME)

    if not token:
        return None

    decoded = decode_session_token(token)
    if not decoded:
        return None

    user = await UserRepository.get_by_id(session, decoded["uid"])
    return user


async def get_current_user(
    request: Request, session: AsyncSession = Depends(get_db)
) -> User:
    """
    Strict dependency enforcing authenticated user session.
    Raises HTTP 401 if unauthenticated.
    """
    user = await get_current_user_optional(request, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please link your Telegram account.",
        )
    return user

