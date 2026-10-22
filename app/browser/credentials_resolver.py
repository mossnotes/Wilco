import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import urllib.parse
import uuid

from app.config import settings
from app.db.engine import async_session_factory
from app.db.models import EncryptedCredential
from app.db.repository import CredentialRepository, UserRepository
from app.security.vault import decrypt_secret

logger = logging.getLogger(__name__)


def extract_candidate_domains(text: str) -> Set[str]:
    """
    Extracts candidate domain names or URLs mentioned in a natural language prompt.
    E.g., "Login to https://vercel.com/dashboard and github.com" -> {"vercel.com", "github.com"}
    """
    if not text or not isinstance(text, str):
        return set()

    found_domains: Set[str] = set()

    # 1. Match full URLs (http/https/ws/wss)
    url_pattern = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)
    for match in url_pattern.finditer(text):
        raw_url = match.group(0)
        try:
            parsed = urllib.parse.urlsplit(raw_url)
            host = (parsed.hostname or "").lower()
            if host.startswith("www."):
                host = host[4:]
            if host:
                found_domains.add(host)
        except Exception:
            pass

    # 2. Match hostnames like foo.bar.com or foo.com
    host_pattern = re.compile(r"\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\b")
    for match in host_pattern.finditer(text):
        host = match.group(1).lower()
        if host.startswith("www."):
            host = host[4:]
        # Filter out common file extensions that might look like domains (e.g. script.py, data.json)
        if not host.endswith((".py", ".json", ".md", ".txt", ".png", ".jpg", ".html", ".js", ".ts")):
            found_domains.add(host)

    return found_domains


def get_domain_slug(domain: str) -> str:
    """
    Creates a clean identifier slug from a domain.
    E.g. 'vercel.com' -> 'vercel', 'dash.cloudflare.com' -> 'cloudflare'.
    """
    if not domain:
        return "site"
    parts = domain.lower().split(".")
    # If 2 parts like vercel.com -> vercel
    if len(parts) >= 2:
        # Check for ccTLD like example.co.uk
        if len(parts) > 2 and parts[-2] in ("co", "com", "org", "gov", "edu"):
            return parts[-3]
        return parts[-2] if len(parts) > 2 else parts[0]
    return parts[0]


async def resolve_task_credentials(
    user_id: Optional[Union[uuid.UUID, str]] = None,
    telegram_id: Optional[int] = None,
    prompt: str = "",
    explicit_domain: Optional[str] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """
    Resolves vaulted credentials for a task and returns:
    1. sensitive_data dictionary formatted for browser-use (placeholders -> real secrets).
    2. allowed_domains list for browser network security.
    
    If no domains match or no credentials exist, returns ({}, []).
    """
    resolved_uuid: Optional[uuid.UUID] = None
    if isinstance(user_id, str):
        try:
            resolved_uuid = uuid.UUID(user_id)
        except ValueError:
            resolved_uuid = None
    elif isinstance(user_id, uuid.UUID):
        resolved_uuid = user_id

    async with async_session_factory() as session:
        if not resolved_uuid and telegram_id:
            user = await UserRepository.get_by_telegram_id(session, telegram_id)
            if user:
                resolved_uuid = user.id

        if not resolved_uuid:
            return {}, []

        all_creds = await CredentialRepository.get_credentials_for_user(session, resolved_uuid)
        if not all_creds:
            return {}, []

    # Group credentials by normalized domain
    creds_by_domain: Dict[str, List[EncryptedCredential]] = {}
    for c in all_creds:
        dom = c.site_domain.strip().lower()
        creds_by_domain.setdefault(dom, []).append(c)

    # Determine matched domains
    matched_domains: Set[str] = set()
    if explicit_domain:
        norm_exp = explicit_domain.strip().lower()
        if norm_exp.startswith("www."):
            norm_exp = norm_exp[4:]
        for dom in creds_by_domain:
            if dom == norm_exp or norm_exp.endswith(f".{dom}") or dom.endswith(f".{norm_exp}"):
                matched_domains.add(dom)

    candidate_domains = extract_candidate_domains(prompt)
    prompt_lower = prompt.lower()

    for dom in creds_by_domain:
        slug = get_domain_slug(dom)
        # Match exact domain in candidate domains, or slug word match in prompt (e.g. 'vercel' in prompt)
        if dom in candidate_domains or re.search(rf"\b{re.escape(slug)}\b", prompt_lower):
            matched_domains.add(dom)

    if not matched_domains:
        return {}, []

    sensitive_data: Dict[str, str] = {}
    allowed_domains: List[str] = []

    for dom in matched_domains:
        slug = get_domain_slug(dom)
        # Add to allowed domains (domain and subdomains)
        allowed_domains.append(f"*.{dom}")
        allowed_domains.append(dom)

        for cred in creds_by_domain[dom]:
            # Username
            if cred.username_or_identifier and f"{slug}_user" not in sensitive_data:
                sensitive_data[f"{slug}_user"] = cred.username_or_identifier

            # Password
            if cred.auth_type == "password":
                try:
                    decrypted_pass = decrypt_secret(cred.encrypted_blob, settings.vault_key_bytes)
                    sensitive_data[f"{slug}_pass"] = decrypted_pass
                except Exception as exc:
                    logger.error("Failed to decrypt password for domain %s: %s", dom, exc)

            # API Key
            elif cred.auth_type == "api_key":
                try:
                    decrypted_key = decrypt_secret(cred.encrypted_blob, settings.vault_key_bytes)
                    sensitive_data[f"{slug}_api_key"] = decrypted_key
                except Exception as exc:
                    logger.error("Failed to decrypt API key for domain %s: %s", dom, exc)

            # TOTP 2FA Seed (browser-use looks for keys ending in 'bu_2fa_code')
            elif cred.auth_type == "totp_seed":
                try:
                    decrypted_seed = decrypt_secret(cred.encrypted_blob, settings.vault_key_bytes)
                    sensitive_data[f"{slug}_bu_2fa_code"] = decrypted_seed
                except Exception as exc:
                    logger.error("Failed to decrypt TOTP seed for domain %s: %s", dom, exc)

    # If exactly one domain matched, also provide generic 'x_user' and 'x_pass' aliases
    # for seamless browser-use example compatibility
    if len(matched_domains) == 1:
        single_slug = get_domain_slug(list(matched_domains)[0])
        if f"{single_slug}_user" in sensitive_data and "x_user" not in sensitive_data:
            sensitive_data["x_user"] = sensitive_data[f"{single_slug}_user"]
        if f"{single_slug}_pass" in sensitive_data and "x_pass" not in sensitive_data:
            sensitive_data["x_pass"] = sensitive_data[f"{single_slug}_pass"]

    return sensitive_data, sorted(list(set(allowed_domains)))

