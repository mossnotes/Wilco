"""Shared contracts for task-bound Telegram input requests."""

import re
from typing import Literal

ChatInputField = Literal["username", "email", "otp"]
OTPChannel = Literal["sms", "whatsapp", "email", "authenticator", "unknown"]
OTP_PROMPT_PREFIX = "Enter the one-time code for "


def otp_prompt(domain: str, channel: OTPChannel) -> str:
    sources = {
        "sms": "Check your SMS messages for the code.",
        "whatsapp": "Check your WhatsApp messages for the code.",
        "email": "Check your email inbox and spam folder for the code.",
        "authenticator": "Open your authenticator app and find the code for this account.",
        "unknown": (
            "Follow the delivery instructions on the website. The code may be in your "
            "SMS, WhatsApp, email, or authenticator app."
        ),
    }
    # The final paragraph fits the smallest delivery limit (80 characters).
    # Its stable prefix identifies expired replies after chunking or a restart.
    return (
        f"{domain}: {sources[channel]}\n\n"
        f"{OTP_PROMPT_PREFIX}this account. Reply with only the code."
    )


def normalize_otp(text: str) -> str | None:
    """Accept short numeric/alphanumeric codes, preserving leading zeros."""
    compact = re.sub(r"[ -]", "", text.strip())
    return compact if re.fullmatch(r"[A-Za-z0-9]{4,12}", compact) else None
