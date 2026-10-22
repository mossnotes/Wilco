import logging
import re
from typing import Dict, List, Optional, Set, Tuple, Union
import urllib.parse
import uuid

from app.config import settings
from app.db.engine import async_session_factory
from app.db.models import EncryptedCredential
from app.db.repository import CredentialRepository, UserRepository
from app.security.vault import decrypt_secret
from app.security.origins import clean_domain

logger = logging.getLogger(__name__)

SensitiveData = Dict[str, Union[str, Dict[str, str]]]


def credential_scope(domain: str) -> str:
    """Use upstream's origin-scoped substitution, including HTTPS enforcement."""
    if domain in ("localhost", "127.0.0.1", "::1"):
        return f"http*://{domain}"
    return f"https://*.{domain}"


def unpack_credentials(domain: str, credentials: List[EncryptedCredential]) -> Dict[str, str]:
    """Decrypt into native placeholder slots; TOTP seeds are resolved upstream at input time."""
    slug = get_domain_slug(domain)
    secrets: Dict[str, str] = {}
    suffixes = {"password": "pass", "api_key": "api_key", "totp_seed": "bu_2fa_code"}
    for credential in credentials:
        if credential.username_or_identifier:
            secrets.setdefault(f"{slug}_user", credential.username_or_identifier)
        if suffix := suffixes.get(credential.auth_type):
            secrets[f"{slug}_{suffix}"] = decrypt_secret(credential.encrypted_blob, settings.vault_key_bytes)
    return secrets


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
) -> Tuple[SensitiveData, List[str]]:
    """
    Resolves vaulted credentials for a task and returns:
    1. sensitive_data dictionary formatted for browser-use (HTTPS domain scopes -> placeholders -> secrets).
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
        dom = clean_domain(c.site_domain)
        if not dom:
            continue
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

    sensitive_data: SensitiveData = {}
    allowed_domains: List[str] = []

    for dom in sorted(matched_domains):
        slug = get_domain_slug(dom)
        # Add to allowed domains (domain and subdomains)
        allowed_domains.append(f"*.{dom}")
        allowed_domains.append(dom)

        try:
            secrets = unpack_credentials(dom, creds_by_domain[dom])
        except Exception:
            logger.error("Failed to decrypt credentials for domain %s", dom)
            continue

        # Aliases remain scoped to their site, never exposed on another login origin.
        if len(matched_domains) == 1:
            for suffix in ("user", "pass"):
                if f"{slug}_{suffix}" in secrets:
                    secrets[f"x_{suffix}"] = secrets[f"{slug}_{suffix}"]
        sensitive_data[credential_scope(dom)] = secrets

    return sensitive_data, sorted(list(set(allowed_domains)))

