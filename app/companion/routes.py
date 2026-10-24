import asyncio
import hashlib
import hmac
import logging
from pathlib import Path
from typing import Dict, Literal, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.companion.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    create_input_session,
    get_input_user,
    get_current_user,
    get_current_user_optional,
    validate_telegram_identity,
)
from app.companion.accounts import ACCOUNT_FIELDS, SECRET_FIELDS, UpdateAccountRequest, account_details, group_accounts
from app.security.browser_access import profile_lock, revoke_browsers
from app.config import settings
from app.db.engine import get_db
from app.db.models import User
from app.db.repository import (
    BrowserProfileRepository,
    CredentialRepository,
    IdentityTokenRepository,
    TaskRepository,
    UserRepository,
)
from app.security.totp import InvalidTOTPSeedError, normalize_totp_seed
from app.security.account_details import normalize_account_detail
from app.security.origins import clean_domain
from app.security.vault import decrypt_secret, encrypt_secret, mask_secret
from app.tasks.registry import task_registry
from app.tasks.state import TaskState

logger = logging.getLogger(__name__)

# Template engine setup
TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["ui"] = {
    "app_name": "Wilco",
    "app_title": "Vault · Wilco",
    "accounts": "Accounts",
    "add_account": "Add account",
    "website": "Website",
    "type": "Type",
    "password": "Password",
    "authenticator_key": "Authenticator key",
    "api_key": "API key",
    "username_or_email": "Username or email",
    "username": "Username",
    "email": "Email",
    "phone": "Phone number",
    "country_code": "Country calling code",
    "account_details": "Account details",
    "account_not_found": "This account is no longer available.",
    "back": "Back",
    "hidden_value": "Hidden",
    "delete": "Delete",
    "delete_account": "Delete account?",
    "phone_hint": "Phone number only; keep the country calling code separate.",
    "delete_account_notice": "This deletes all saved details and browser sessions for this domain and stops your active browser tasks.",
    "save": "Save",
    "save_to_vault": "🔐 Save to Vault",
    "saved": "Saved. Wilco will use this next time.",
    "saved_continuing": "Saved. Wilco is continuing.",
    "auth_failed": "Reopen Vault from Telegram to sign in.",
    "connecting": "Connecting…",
    "cancel": "Cancel",
    "close": "Close",
    "remove_account": "Remove account?",
    "remove": "Remove",
    "input_needed": "Input needed",
    "response": "Response",
    "authenticator_key_optional": "Authenticator key (optional)",
    "resume": "Resume",
    "cancel_task": "Cancel task",
    "cancel_task_question": "Cancel task?",
    "expired": "Expired",
    "connected": "Connected",
    "continue": "Continue",
    "sign_in": "Sign in",
    "sign_in_instruction": "Open Vault from your private chat with Wilco.",
    "save_failed": "Save failed",
    "remove_failed": "Remove failed",
    "submit_failed": "Submit failed",
    "cancel_failed": "Cancel failed",
}

# Routers
companion_router = APIRouter(prefix="/companion", tags=["vault"])
vault_api_router = APIRouter(prefix="/api/vault", tags=["vault"])
tasks_api_router = APIRouter(prefix="/api/tasks", tags=["tasks"])


# ---------------------------------------------------------
# Request Models
# ---------------------------------------------------------

class CreateCredentialRequest(BaseModel):
    site_domain: str = Field(..., min_length=1)
    auth_type: Literal["password", "totp_seed", "api_key"] = "password"
    username_or_identifier: Optional[str] = None
    secret: str = Field(..., min_length=1, max_length=16384, repr=False)


class TelegramIdentityRequest(BaseModel):
    init_data: str = Field(..., min_length=1, max_length=16384, repr=False)


class ResolveInputRequest(BaseModel):
    approved: bool = True
    user_input: Optional[str] = None
    credentials: Optional[Dict[str, str]] = None
    username: Optional[str] = Field(default=None, max_length=320)
    totp_seed: Optional[str] = Field(default=None, max_length=1024)
    credential_type: Optional[Literal["password", "api_key"]] = None
    secret: Optional[str] = Field(default=None, min_length=1, max_length=16384, repr=False)


# ---------------------------------------------------------
# Vault HTML Routes
# ---------------------------------------------------------

@companion_router.post("/auth/telegram")
async def authenticate_telegram(
    req: TelegramIdentityRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_db),
):
    telegram_id = validate_telegram_identity(req.init_data)
    user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
    await session.commit()
    session_token = create_session_token(user.id, user.telegram_id)
    response.set_cookie(
        key=SESSION_COOKIE_NAME, value=session_token,
        httponly=True, samesite="strict", max_age=7 * 86400, secure=request.url.scheme == "https",
    )
    response.headers["Cache-Control"] = "no-store"
    # The JS closure can use a bearer session in Telegram Web, where third-party
    # cookies may be blocked. Never put this token in a URL or browser storage.
    return {"user_id": str(user.id), "session_token": session_token}


@companion_router.get("/credentials", response_class=HTMLResponse)
async def legacy_credential_editor(
    request: Request,
    domain: str = Query(...),
):
    target = clean_domain(domain)
    if not target:
        raise HTTPException(status_code=400, detail="Invalid site domain")
    # Previously sent persistent links now lead to the owner's grouped account.
    return RedirectResponse(f"/companion/accounts/{target}", status_code=303)

@companion_router.get("/link", response_class=HTMLResponse)
async def link_identity(
    request: Request,
    response: Response,
    token: str = Query(default=""),
    task_id: Optional[str] = Query(default=None),
    session: AsyncSession = Depends(get_db),
):
    """
    Validates a one-time pairing token generated in Telegram chat.
    Sets the secure session cookie and links the web session to the user.
    """
    if task_id:
        pending = task_registry.get_credential_input(task_id)
        if not pending:
            return templates.TemplateResponse(request=request, name="expired.html", context={}, status_code=410)
        async with pending.lock:
            expected = pending.task.metadata.get("credential_token_digest", "")
            requested_domain = request.query_params.get("domain")
            if (
                not pending.is_pending or not expected
                or not hmac.compare_digest(expected, hashlib.sha256(token.encode()).hexdigest())
                or (requested_domain and clean_domain(requested_domain) != pending.domain)
            ):
                return templates.TemplateResponse(request=request, name="expired.html", context={}, status_code=410)
            telegram_id = await IdentityTokenRepository.validate_and_consume_token(session, token)
            if telegram_id != pending.task.user_id:
                return templates.TemplateResponse(request=request, name="expired.html", context={}, status_code=410)
            user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
            input_session = create_input_session(user, pending)
            await session.commit()
            resp = templates.TemplateResponse(
                request=request,
                name={"password": "need_password.html", "api_key": "need_api_key.html"}.get(
                    pending.task.metadata.get("credential_type"), "needs_input.html",
                ),
                context={"task": pending.task, "target_domain": pending.domain, "input_session": input_session},
            )
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["Referrer-Policy"] = "no-referrer"
            return resp

    if token.startswith("credential."):
        return templates.TemplateResponse(request=request, name="unauthorized.html", context={}, status_code=401)
    telegram_id = await IdentityTokenRepository.validate_and_consume_token(session, token)
    if not telegram_id:
        return templates.TemplateResponse(
            request=request,
            name="unauthorized.html",
            context={},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Get or create user
    user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)

    # Create encrypted session cookie
    session_token = create_session_token(user.id, user.telegram_id)

    resp = templates.TemplateResponse(request=request, name="link.html", context={"user": user})
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        samesite="lax",
        max_age=7 * 86400,
        secure=request.url.scheme == "https",
    )
    await session.commit()
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@companion_router.get("/accounts", response_class=HTMLResponse)
async def list_connected_accounts_page(
    request: Request,
    session: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_current_user_optional),
):
    """Renders the Connected Accounts dashboard for the authenticated user."""
    creds = await CredentialRepository.get_credentials_for_user(session, user.id) if user else []

    response = templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"accounts": group_accounts(creds), "user": user},
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@companion_router.get("/accounts/{domain}", response_class=HTMLResponse)
async def account_details_page(request: Request, domain: str, user: Optional[User] = Depends(get_current_user_optional)):
    target = "" if domain == "new" else clean_domain(domain)
    if domain != "new" and not target:
        raise HTTPException(status_code=400, detail="Invalid site domain")
    # Details are fetched only after the Mini App verifies the current owner.
    response = templates.TemplateResponse(
        request=request, name="account_details.html" if target else "add_account.html",
        context={"target_domain": target, "user": user, "account_fields": ACCOUNT_FIELDS, "secret_fields": SECRET_FIELDS},
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@companion_router.get("/input", response_class=HTMLResponse)
async def task_needs_input_page(
    request: Request,
    task_id: str = Query(default=""),
    session: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_current_user_optional),
):
    """Renders the interactive prompt modal for human-in-the-loop task input resolution."""
    if not user:
        return templates.TemplateResponse(
            request=request,
            name="unauthorized.html",
            context={},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    task = await TaskRepository.get_task(session, task_id)
    if not task:
        return templates.TemplateResponse(
            request=request, name="expired.html", context={}, status_code=404,
        )

    if task.user_id != user.telegram_id:
        return templates.TemplateResponse(
            request=request, name="unauthorized.html", context={}, status_code=403,
        )

    requested_domain = request.query_params.get("domain")
    target_domain = task.metadata.get("target_domain") or (clean_domain(requested_domain) if requested_domain else None)
    if requested_domain and clean_domain(requested_domain) != target_domain:
        return templates.TemplateResponse(
            request=request, name="expired.html", context={}, status_code=400,
        )
    if task.state != TaskState.NEEDS_INPUT:
        return templates.TemplateResponse(
            request=request, name="expired.html", context={}, status_code=409,
        )
    if task.metadata.get("target_domain"):
        pending = task_registry.get_credential_input(task_id)
        if not pending or not pending.is_pending:
            return templates.TemplateResponse(
                request=request, name="expired.html", context={}, status_code=409,
            )

    response = templates.TemplateResponse(
        request=request,
        name={"password": "need_password.html", "api_key": "need_api_key.html"}.get(
            task.metadata.get("credential_type"), "needs_input.html"
        ),
        context={"task": task, "target_domain": target_domain, "user": user},
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# ---------------------------------------------------------
# REST Enclave Vault Endpoints
# ---------------------------------------------------------

@vault_api_router.post("/credentials", status_code=status.HTTP_201_CREATED)
async def store_credential(
    req: CreateCredentialRequest,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Stores an encrypted credential in the vault."""
    domain = clean_domain(req.site_domain)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid site domain")

    # If TOTP seed, validate Base32 format
    secret_to_store = req.secret
    if req.auth_type == "totp_seed":
        try:
            secret_to_store = normalize_totp_seed(req.secret)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid Base32 TOTP seed: {e}") from e

    # Encrypt secret using AES-256-GCM
    try:
        encrypted_blob = encrypt_secret(secret_to_store, settings.vault_key_bytes)
    except Exception as e:
        logger.error(f"Failed to encrypt credential: {e}")
        raise HTTPException(status_code=500, detail="Failed to securely encrypt credential") from e

    identifier = req.username_or_identifier
    if "username_or_identifier" not in req.model_fields_set:
        existing = await CredentialRepository.get_credentials_for_domain(session, user.id, domain)
        identifier = next((c.username_or_identifier for c in existing if c.auth_type == req.auth_type), None)
    cred = await CredentialRepository.add_or_update_credential(
        session,
        user_id=user.id,
        site_domain=domain,
        auth_type=req.auth_type,
        encrypted_blob=encrypted_blob,
        username_or_identifier=identifier,
    )

    masked = mask_secret(secret_to_store, is_api_key=(req.auth_type == "api_key"))
    result = {
        "status": "success",
        "id": str(cred.id),
        "site_domain": cred.site_domain,
        "auth_type": cred.auth_type,
        "username_or_identifier": cred.username_or_identifier,
        "masked_secret": masked,
    }
    await session.commit()
    return result


@vault_api_router.get("/accounts")
async def list_accounts(response: Response, session: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store"
    return group_accounts(await CredentialRepository.get_credentials_for_user(session, user.id))


@vault_api_router.get("/accounts/{domain}")
async def get_account(domain: str, response: Response, session: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    target = clean_domain(domain)
    credentials = await CredentialRepository.get_credentials_for_domain(session, user.id, target) if target else []
    if not credentials:
        raise HTTPException(status_code=404, detail="Account not found")
    response.headers["Cache-Control"] = "no-store"
    try:
        return account_details(target, credentials)
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to read saved account details") from None


@vault_api_router.put("/accounts/{domain}")
async def update_account(domain: str, req: UpdateAccountRequest, session: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    target = clean_domain(domain)
    if not target:
        raise HTTPException(status_code=400, detail="Invalid site domain")
    updates = {}
    # Validate everything before making any changes. Empty secret fields keep the
    # existing value; an empty identifier explicitly removes that identifier.
    for field in req.model_fields_set:
        value = getattr(req, field)
        if field in SECRET_FIELDS and not value:
            continue
        try:
            updates[field] = (
                normalize_account_detail(value, field) if field in ACCOUNT_FIELDS and value and value.strip()
                else normalize_totp_seed(value) if field == "totp_seed"
                else value if field in SECRET_FIELDS else None
            )
        except (ValueError, InvalidTOTPSeedError):
            raise HTTPException(status_code=400, detail=f"Invalid {field}") from None
    credentials = await CredentialRepository.get_credentials_for_domain(session, user.id, target)
    for credential in credentials:
        if value := credential.username_or_identifier:
            if ("email" if "@" in value else "username") in updates:
                credential.username_or_identifier = None
    for field, value in updates.items():
        if value is None:
            for credential in credentials:
                if credential.auth_type == field:
                    await CredentialRepository.delete_credential(session, credential.id, user.id)
        else:
            identifier = next((c.username_or_identifier for c in credentials if c.auth_type == field), None)
            await CredentialRepository.add_or_update_credential(
                session, user.id, target, field, encrypt_secret(value, settings.vault_key_bytes), identifier,
            )
    remaining = await CredentialRepository.get_credentials_for_domain(session, user.id, target)
    if not remaining:
        raise HTTPException(status_code=400, detail="Add at least one account detail")
    await session.commit()
    return {"status": "success", "site_domain": target}


async def delete_account_access(session, user, domain):
    async with profile_lock(user.id):
        running = revoke_browsers(user.id) | task_registry.cancel_tasks_for_user(user.telegram_id)
        await CredentialRepository.delete_credentials_for_domain(session, user.id, domain)
        profiles = await BrowserProfileRepository.get_profiles_for_user(session, user.id)
        for profile in profiles:
            host = clean_domain(profile.site_domain)
            if host and (host == domain or host.endswith(f".{domain}") or domain.endswith(f".{host}")):
                await BrowserProfileRepository.delete_profile(session, user.id, profile.site_domain)
        await session.commit()
        # Also stop work registered while the database deletion was in flight.
        running |= task_registry.cancel_tasks_for_user(user.telegram_id)
    if running:
        await asyncio.wait(running, timeout=10)


@vault_api_router.delete("/accounts/{domain}")
async def delete_account(domain: str, session: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    target = clean_domain(domain)
    if not target or not await CredentialRepository.get_credentials_for_domain(session, user.id, target):
        raise HTTPException(status_code=404, detail="Account not found")
    await delete_account_access(session, user, target)
    return {"status": "deleted", "site_domain": target}


@vault_api_router.get("/credentials")
async def list_credentials(
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Lists registered accounts with masked identifiers (zero plaintext secrets)."""
    creds = await CredentialRepository.get_credentials_for_user(session, user.id)

    results = []
    for c in creds:
        try:
            decrypted = decrypt_secret(c.encrypted_blob, settings.vault_key_bytes)
            masked = mask_secret(decrypted, is_api_key=(c.auth_type == "api_key"))
        except Exception:
            masked = "••••••••"

        results.append({
            "id": str(c.id),
            "site_domain": c.site_domain,
            "auth_type": c.auth_type,
            "username_or_identifier": c.username_or_identifier,
            "masked_secret": masked,
            "created_at": c.created_at.isoformat(),
            "updated_at": c.updated_at.isoformat(),
        })

    return results


@vault_api_router.delete("/credentials/{credential_id}")
async def revoke_credential(
    credential_id: str,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Permanently revokes a stored credential and wipes associated browser profiles if no credentials remain.
    """
    try:
        cred_uuid = uuid.UUID(credential_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid credential UUID")

    # Find credential to inspect domain before deletion
    creds = await CredentialRepository.get_credentials_for_user(session, user.id)
    target = next((c for c in creds if c.id == cred_uuid), None)
    if not target:
        raise HTTPException(status_code=404, detail="Credential not found")

    domain = target.site_domain
    if sum(c.site_domain == domain for c in creds) == 1:
        await delete_account_access(session, user, domain)
    else:
        await CredentialRepository.delete_credential(session, cred_uuid, user.id)

    return {"status": "deleted", "site_domain": domain}


# ---------------------------------------------------------
# REST Tasks Resolution Endpoints
# ---------------------------------------------------------

@tasks_api_router.post("/{task_id}/resolve-input")
async def resolve_task_input(
    task_id: str,
    req: ResolveInputRequest,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_input_user),
):
    """
    Submits user input or manual confirmation for a paused task in NEEDS_INPUT state.
    """
    pending = task_registry.get_credential_input(task_id)
    async with pending.lock if pending else asyncio.Lock():
        task = await TaskRepository.get_task(session, task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        if task.user_id != user.telegram_id:
            raise HTTPException(status_code=403, detail="Access denied to this task")
        if pending:
            task = pending.task.model_copy(deep=True)
        if task.state != TaskState.NEEDS_INPUT:
            raise HTTPException(status_code=400, detail=f"Task is in state '{task.state.value}', not 'needs_input'")

        target_domain = task.metadata.get("target_domain")
        if target_domain and (not pending or not pending.is_pending):
            raise HTTPException(status_code=409, detail="This credential request has expired")
        if req.approved:
            credential_type = task.metadata.get("credential_type")
            if credential_type:
                if (
                    credential_type not in ("password", "api_key")
                    or req.credential_type != credential_type
                    or not req.secret
                    or req.credentials is not None
                    or req.user_input is not None
                    or req.username is not None
                    or req.totp_seed is not None
                ):
                    raise HTTPException(status_code=400, detail="Provide only the requested secret in the secure form")
            elif req.secret is not None or req.credential_type is not None:
                raise HTTPException(status_code=400, detail="No matching secret request is pending")
            # Validate the entire payload before performing any vault writes.
            credentials = {target_domain: req.secret} if credential_type else {}
            for domain, secret in (req.credentials or {}).items():
                domain = clean_domain(domain)
                if not domain or not secret:
                    raise HTTPException(status_code=400, detail="A valid domain and nonempty password are required")
                if target_domain and domain != target_domain:
                    raise HTTPException(status_code=400, detail="Credential domain does not match the pending request")
                credentials[domain] = secret
            if target_domain and set(credentials) != {target_domain}:
                raise HTTPException(status_code=400, detail="Provide credentials for the requested domain in the WebApp")
            normalized_seed = None
            if req.totp_seed:
                if len(credentials) != 1:
                    raise HTTPException(status_code=400, detail="TOTP seed requires exactly one credential domain")
                try:
                    normalized_seed = normalize_totp_seed(req.totp_seed)
                except Exception:
                    raise HTTPException(status_code=400, detail="Invalid Base32 TOTP seed") from None
            for domain, secret in credentials.items():
                previous = await CredentialRepository.get_credentials_for_domain(session, user.id, domain)
                identifier = req.username or next((c.username_or_identifier for c in previous if c.auth_type == (credential_type or "password")), None)
                await CredentialRepository.add_or_update_credential(
                    session, user_id=user.id, site_domain=domain, auth_type=credential_type or "password",
                    encrypted_blob=encrypt_secret(secret, settings.vault_key_bytes),
                    username_or_identifier=identifier,
                )
                if normalized_seed:
                    await CredentialRepository.add_or_update_credential(
                        session, user_id=user.id, site_domain=domain, auth_type="totp_seed",
                        encrypted_blob=encrypt_secret(normalized_seed, settings.vault_key_bytes),
                    )
            task.transition_to(TaskState.RUNNING, status_message="Secure credentials received. Resuming task." if credentials else "Resumed with user input.")
            if not credentials:
                task.metadata["resolved_input"] = req.user_input
        else:
            task.transition_to(
                TaskState.FAILED, status_message="Task cancelled by user via Vault.", error="Cancelled by user",
            )
        if pending and not pending.is_pending:
            raise HTTPException(status_code=409, detail="This credential request has expired")
        for key in ("target_domain", "credential_type", "credential_rejected", "credential_token_digest", "credential_input_deadline", "companion_url"):
            task.metadata.pop(key, None)
        await TaskRepository.save_task(session, task)
        if pending and not pending.is_pending:
            await session.rollback()
            raise HTTPException(status_code=409, detail="This credential request has expired")
        # Commit before waking the browser: its next vault read uses another session.
        await session.commit()
        if pending:
            if not pending.is_pending:
                await TaskRepository.save_task(session, pending.task)
                await session.commit()
                raise HTTPException(status_code=409, detail="This credential request has expired")
            live = pending.task
            live.metadata = task.metadata
            live.transition_to(task.state, status_message=task.status_message, error=task.error)
            pending.event.set()

    return {
        "status": "resolved",
        "task_id": task.task_id,
        "state": task.state.value,
        "approved": req.approved,
    }
