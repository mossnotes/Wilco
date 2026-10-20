from datetime import datetime, timedelta, timezone
import json
import logging
import time
from typing import Optional
import uuid

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.engine import get_db
from app.db.models import User
from app.db.repository import UserRepository
from app.security.vault import decrypt_secret, encrypt_secret

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = "wilco_session"


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
    token = request.cookies.get(SESSION_COOKIE_NAME)

    if not token:
        # Check Bearer authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

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

