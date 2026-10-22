"""Shared contracts for task-bound Telegram input requests."""

import re
from typing import Literal

ChatInputField = Literal["username", "email", "phone", "country_code", "otp"]
OTPChannel = Literal["sms", "whatsapp", "email", "authenticator", "unknown"]
OTP_PROMPT_PREFIX = "Enter the one-time code for "
ACCOUNT_PROMPT_PREFIXES = (
    "Enter your username for this website.",
    "Enter your email for this website.",
    "Enter your phone number for this website.",
    "Enter the country calling code for this website.",
)


def account_input_prompt(
    domain: str, field: Literal["username", "email", "phone", "country_code"],
) -> str:
    if field == "country_code":
        return (
            f"{domain} needs a country calling code. I'll save it securely for this website.\n\n"
            "Enter the country calling code for this website. Reply with only the code."
        )
    label = "phone number" if field == "phone" else field
    guidance = f"I need your {label} for {domain}. I'll save it securely for this website."
    if field == "phone":
        guidance += " Send just the number for the phone field, without a country code."
    # Keep the final ForceReply bubble within the smallest message limit (80).
    return f"{guidance}\n\nEnter your {label} for this website. Reply with only the {'number' if field == 'phone' else field}."


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
