"""Stable Companion addresses; authentication is separate from navigation."""

from urllib.parse import urlencode

from app.config import settings


def credential_editor_url(domain: str, credential_type: str = "password") -> str:
    query = urlencode({"domain": domain, "credential_type": credential_type})
    return f"{settings.COMPANION_BASE_URL.rstrip('/')}/credentials?{query}"
