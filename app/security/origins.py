"""Canonical credential domains and active-page origin checks."""

import ipaddress
import re
from urllib.parse import urlsplit


def clean_domain(raw_domain: str) -> str:
    if not raw_domain or not raw_domain.strip():
        return ""
    raw = raw_domain.strip().lower()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass
    try:
        parts = urlsplit(raw if "://" in raw or raw.startswith("//") else f"//{raw}")
        if parts.username is not None or parts.password is not None:
            return ""
        host = (parts.hostname or "").rstrip(".").encode("idna").decode("ascii")
        # Reading port also rejects malformed authority strings.
        parts.port
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.split(".")
            ):
                return ""
        return host[4:] if host.startswith("www.") else host
    except (ValueError, UnicodeError):
        return ""


def validate_origin(page_url: str, expected_domain: str) -> tuple[bool, str]:
    target = clean_domain(expected_domain)
    host = clean_domain(page_url)
    if not target or not host:
        return False, "Active page URL or target credential domain is invalid."
    try:
        scheme = urlsplit(page_url).scheme.lower()
    except ValueError:
        return False, "Malformed active page URL."
    if scheme == "http":
        if host not in ("localhost", "127.0.0.1", "::1"):
            return False, "Insecure HTTP scheme rejected. HTTPS is required for remote websites."
    elif scheme != "https":
        return False, "Only HTTPS (or local HTTP) is permitted."
    if host == target or host.endswith(f".{target}"):
        return True, ""
    return False, "Active page host does not match the target credential domain."
