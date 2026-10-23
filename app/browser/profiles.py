"""Encrypted, owner-bound browser storage selected by the current task's sites."""

import json
import logging
import re
import uuid
from typing import Any
from urllib.parse import urlsplit

from app.browser.credentials_resolver import extract_candidate_domains, get_domain_slug
from app.security.browser_access import profile_lock, profile_revision
from app.config import settings
from app.db.engine import async_session_factory
from app.db.repository import BrowserProfileRepository
from app.security.origins import clean_domain
from app.security.vault import decrypt_secret, encrypt_secret

logger = logging.getLogger(__name__)


def _related_domains(left: str, right: str) -> bool:
    return left == right or left.endswith(f".{right}") or right.endswith(f".{left}")


def _split_storage_state(state: dict[str, Any]) -> dict[str, dict[str, list]]:
    """Preserve browser cookie scopes and exact origins within separate site records."""
    grouped: dict[str, dict[str, list]] = {}
    for cookie in state.get("cookies", []):
        if not isinstance(cookie, dict) or not isinstance(cookie.get("domain"), str):
            continue
        domain = clean_domain(cookie["domain"].lstrip("."))
        if domain and isinstance(cookie.get("name"), str) and isinstance(cookie.get("value"), str):
            grouped.setdefault(domain, {"cookies": [], "origins": []})["cookies"].append(cookie)
    for origin in state.get("origins", []):
        if not isinstance(origin, dict) or not isinstance(origin.get("origin"), str):
            continue
        domain = clean_domain(origin["origin"])
        if domain and urlsplit(origin["origin"]).scheme in ("https", "http"):
            grouped.setdefault(domain, {"cookies": [], "origins": []})["origins"].append(origin)
    return grouped


async def load_session_profiles(
    user_id: uuid.UUID, prompt: str = "", site_domain: str | None = None,
) -> tuple[dict[str, list], set[str]]:
    """Load only this owner's profiles for requested hosts or familiar site names."""
    targets = {domain for raw in extract_candidate_domains(prompt) if (domain := clean_domain(raw))}
    if site_domain and (domain := clean_domain(site_domain)):
        targets.add(domain)
    cookies: dict[tuple, dict] = {}
    origins: dict[str, dict] = {}
    loaded_domains: set[str] = set()
    async with async_session_factory() as db:
        profiles = await BrowserProfileRepository.get_profiles_for_user(db, user_id)
    for profile in profiles:
        domain = clean_domain(profile.site_domain)
        if not domain:
            continue
        matched = any(_related_domains(domain, target) for target in targets)
        if not targets:
            matched = bool(re.search(rf"\b{re.escape(get_domain_slug(domain))}\b", prompt, re.IGNORECASE))
        if not matched:
            continue
        try:
            state = json.loads(decrypt_secret(profile.storage_state_json, settings.vault_key_bytes))
            # Filter older bundles as well: a site profile must never restore an
            # unrelated site's storage, even if that data was present in the row.
            for stored_domain, storage in _split_storage_state(state).items():
                if not _related_domains(domain, stored_domain):
                    continue
                for cookie in storage["cookies"]:
                    identity = (cookie["name"], cookie["domain"], cookie.get("path", "/"))
                    cookies[identity] = cookie
                for origin in storage["origins"]:
                    origins[origin["origin"]] = origin
            loaded_domains.add(profile.site_domain)
        except Exception:
            # Authentication state and decryption errors must never reach logs.
            logger.warning("Could not restore a saved browser profile for user %s", user_id)
    return {"cookies": list(cookies.values()), "origins": list(origins.values())}, loaded_domains


async def save_session_profiles(
    user_id: uuid.UUID, state: dict[str, Any], loaded_domains: set[str],
    *, expected_revision: int | None = None,
) -> None:
    grouped = _split_storage_state(state)
    async with profile_lock(user_id), async_session_factory() as db:
        if expected_revision is not None and expected_revision != profile_revision(user_id):
            return
        # Empty exported state replaces loaded state too, so logging out cannot
        # resurrect an old authentication cookie on the next task.
        for domain in sorted(loaded_domains | grouped.keys()):
            storage = grouped.get(domain, {"cookies": [], "origins": []})
            encrypted = encrypt_secret(json.dumps(storage), settings.vault_key_bytes)
            await BrowserProfileRepository.save_profile(db, user_id, domain, encrypted)
        await db.commit()
