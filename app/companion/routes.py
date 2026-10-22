import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, Literal, Optional
import uuid
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.companion.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    get_current_user,
    get_current_user_optional,
)
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
from app.security.totp import normalize_totp_seed
from app.security.origins import clean_domain
from app.security.vault import decrypt_secret, encrypt_secret, mask_secret
from app.tasks.registry import task_registry
from app.tasks.state import TaskState

logger = logging.getLogger(__name__)

# Template engine setup
TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["ui"] = json.loads(
    (Path(__file__).parent / "ui_copy.json").read_text(encoding="utf-8")
)

# Routers
companion_router = APIRouter(prefix="/companion", tags=["companion"])
vault_api_router = APIRouter(prefix="/api/vault", tags=["vault"])
tasks_api_router = APIRouter(prefix="/api/tasks", tags=["tasks"])


# ---------------------------------------------------------
# Request Models
# ---------------------------------------------------------

class CreateCredentialRequest(BaseModel):
    site_domain: str = Field(..., min_length=1)
    auth_type: Literal["password", "totp_seed", "api_key"] = "password"
    username_or_identifier: Optional[str] = None
    secret: str = Field(..., min_length=1)


class ResolveInputRequest(BaseModel):
    approved: bool = True
    user_input: Optional[str] = None
    credentials: Optional[Dict[str, str]] = None
    username: Optional[str] = Field(default=None, max_length=320)
    totp_seed: Optional[str] = Field(default=None, max_length=1024)
    credential_type: Optional[Literal["password", "api_key"]] = None
    secret: Optional[str] = Field(default=None, min_length=1, max_length=16384, repr=False)


# ---------------------------------------------------------
# Web Companion HTML Routes
# ---------------------------------------------------------

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

    if task_id:
        task = await TaskRepository.get_task(session, task_id)
        if not task or task.user_id != telegram_id:
            return templates.TemplateResponse(
                request=request, name="unauthorized.html", context={}, status_code=403,
            )
        query = {"task_id": task_id}
        if target_domain := task.metadata.get("target_domain"):
            query["domain"] = target_domain
        resp = RedirectResponse(url=f"/companion/input?{urlencode(query)}", status_code=303)
    else:
        resp = templates.TemplateResponse(
            request=request,
            name="link.html",
            context={},
        )
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
    if not user:
        return templates.TemplateResponse(
            request=request,
            name="unauthorized.html",
            context={},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    creds = await CredentialRepository.get_credentials_for_user(session, user.id)

    # The dashboard needs domains and internal row IDs, never decrypted secrets.
    view_credentials = [{"id": str(c.id), "site_domain": c.site_domain} for c in creds]

    response = templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"credentials": view_credentials},
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
        context={"task": task, "target_domain": target_domain},
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

    cred = await CredentialRepository.add_or_update_credential(
        session,
        user_id=user.id,
        site_domain=domain,
        auth_type=req.auth_type,
        encrypted_blob=encrypted_blob,
        username_or_identifier=req.username_or_identifier,
    )

    masked = mask_secret(secret_to_store, is_api_key=(req.auth_type == "api_key"))

    return {
        "status": "success",
        "id": str(cred.id),
        "site_domain": cred.site_domain,
        "auth_type": cred.auth_type,
        "username_or_identifier": cred.username_or_identifier,
        "masked_secret": masked,
    }


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
    deleted = await CredentialRepository.delete_credential(session, cred_uuid, user.id)

    # Check if any other credentials exist for this domain
    remaining = await CredentialRepository.get_credentials_for_domain(session, user.id, domain)
    if not remaining:
        # Wipe associated browser profile to prevent orphaned sessions
        await BrowserProfileRepository.delete_profile(session, user.id, domain)

    return {"status": "deleted", "site_domain": domain}


# ---------------------------------------------------------
# REST Tasks Resolution Endpoints
# ---------------------------------------------------------

@tasks_api_router.post("/{task_id}/resolve-input")
async def resolve_task_input(
    task_id: str,
    req: ResolveInputRequest,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
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
                await CredentialRepository.add_or_update_credential(
                    session, user_id=user.id, site_domain=domain, auth_type=credential_type or "password",
                    encrypted_blob=encrypt_secret(secret, settings.vault_key_bytes),
                    username_or_identifier=req.username,
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
                TaskState.FAILED, status_message="Task cancelled by user via companion app.", error="Cancelled by user",
            )
        if pending and not pending.is_pending:
            raise HTTPException(status_code=409, detail="This credential request has expired")
        for key in ("target_domain", "credential_type", "credential_input_deadline", "companion_url"):
            task.metadata.pop(key, None)
        await TaskRepository.save_task(session, task)
        # Commit before waking the browser: its next vault read uses another session.
        await session.commit()
        if pending:
            if not pending.is_pending:
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
