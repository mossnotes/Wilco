import asyncio
import base64
import binascii
import re
import time
from typing import Optional, Tuple

import pyotp


class TOTPError(Exception):
    """Base exception for TOTP operations."""
    pass


class InvalidTOTPSeedError(TOTPError):
    """Raised when the provided TOTP seed is not valid Base32."""
    pass


_BASE32_REGEX = re.compile(r"^[A-Z2-7=]+$")


def normalize_totp_seed(seed: str) -> str:
    """
    Cleans and validates a Base32 TOTP secret seed.
    Strips whitespace, converts to uppercase, and verifies Base32 characters.
    """
    if not seed or not seed.strip():
        raise InvalidTOTPSeedError("TOTP seed cannot be empty")

    cleaned = seed.strip().replace(" ", "").replace("-", "").upper()

    if not _BASE32_REGEX.match(cleaned):
        raise InvalidTOTPSeedError(f"TOTP seed contains invalid non-Base32 characters: {cleaned[:4]}...")

    # Validate RFC 3548/4648 Base32 decode capability
    try:
        # Add padding if missing for standard b32decode
        padding_needed = (8 - len(cleaned) % 8) % 8
        padded = cleaned + ("=" * padding_needed)
        base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError) as e:
        raise InvalidTOTPSeedError(f"Malformed Base32 seed: {e}") from e

    return cleaned


def generate_totp_code(
    secret_seed: str,
    interval: int = 30,
    digits: int = 6,
    for_time: Optional[float] = None,
) -> Tuple[str, int]:
    """
    Generates an RFC 6238 TOTP code and returns the remaining seconds in the current interval.

    Returns:
        tuple[str, int]: (6-digit TOTP code, seconds_remaining)
    """
    cleaned_seed = normalize_totp_seed(secret_seed)
    totp = pyotp.TOTP(cleaned_seed, interval=interval, digits=digits)

    current_timestamp = for_time if for_time is not None else time.time()
    code = totp.at(current_timestamp)

    seconds_remaining = interval - (int(current_timestamp) % interval)
    return code, seconds_remaining


async def get_safe_totp_code(
    secret_seed: str,
    min_drift_buffer: int = 5,
    interval: int = 30,
    digits: int = 6,
) -> str:
    """
    Generates a TOTP code with time-drift protection.
    If remaining seconds in the current 30s window is less than min_drift_buffer,
    asynchronously waits for the beginning of the next window to avoid expired submissions.
    """
    code, remaining = generate_totp_code(secret_seed, interval=interval, digits=digits)

    if remaining < min_drift_buffer:
        # Wait until current window expires + slight 0.5s margin into next window
        sleep_duration = remaining + 0.5
        await asyncio.sleep(sleep_duration)
        code, _ = generate_totp_code(secret_seed, interval=interval, digits=digits)

    return code

