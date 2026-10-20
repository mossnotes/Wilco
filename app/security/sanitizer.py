import re
from typing import List, Pattern

# Heuristic patterns for sensitive credentials
SENSITIVE_PATTERNS: List[Pattern[str]] = [
    # API Keys (OpenAI, Anthropic, Generic sk- keys)
    re.compile(r"\bsk-[a-zA-Z0-9\-_]{20,}\b"),
    # GitHub Personal Access Tokens
    re.compile(r"\bgh[pousr]_[a-zA-Z0-9]{36,}\b"),
    # Bearer Tokens
    re.compile(r"\bBearer\s+[a-zA-Z0-9\-_\.]{20,}\b", re.IGNORECASE),
    # Telegram Bot Tokens (e.g. 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789)
    re.compile(r"\b\d{8,12}:[a-zA-Z0-9_-]{35}\b"),
    # Password declarations (e.g. password: xyz, pwd = xyz)
    re.compile(r"\b(?:password|passwd|pwd|secret)\s*[:=]\s*(\S+)", re.IGNORECASE),
    # Chat password declarations (e.g. my password is xyz)
    re.compile(r"\bmy\s+(?:password|passwd|pwd|secret)\s+(?:is|=)\s+(\S+)", re.IGNORECASE),
    # Base32 TOTP Seeds (16 to 32 uppercase characters adhering to RFC 3548/4648 Base32)
    re.compile(r"\b(?=[A-Z2-7]{16,32}\b)(?:[A-Z]*[2-7][A-Z0-9]*)\b"),
    re.compile(r"\b[A-Z2-7]{24,32}\b"),
]

# Simple string representation for redactions
REDACTED_LABEL = "[REDACTED_SECRET]"


def contains_sensitive_data(text: str) -> bool:
    """
    Scans the given text against heuristic credential patterns.
    Returns True if any pattern matches.
    """
    if not text or not isinstance(text, str):
        return False

    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(text):
            return True

    return False


def sanitize_log(text: str) -> str:
    """
    Replaces sensitive credentials in log messages or text strings with [REDACTED_SECRET].
    """
    if not text or not isinstance(text, str):
        return text

    sanitized = text

    # Handle assignment patterns first to preserve the label (e.g., 'password: [REDACTED_SECRET]')
    password_assign_pattern = re.compile(
        r"(\b(?:password|passwd|pwd|secret)\s*[:=]\s*)(\S+)",
        re.IGNORECASE,
    )
    sanitized = password_assign_pattern.sub(rf"\1{REDACTED_LABEL}", sanitized)

    chat_password_pattern = re.compile(
        r"(\bmy\s+(?:password|passwd|pwd|secret)\s+(?:is|=)\s+)(\S+)",
        re.IGNORECASE,
    )
    sanitized = chat_password_pattern.sub(rf"\1{REDACTED_LABEL}", sanitized)

    # Sanitize tokens and API keys
    for pattern in SENSITIVE_PATTERNS:
        # If pattern has no capture groups, replace full match
        if pattern.groups == 0:
            sanitized = pattern.sub(REDACTED_LABEL, sanitized)

    return sanitized
