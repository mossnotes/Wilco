import pytest
import pytest_asyncio
import time
import uuid
from httpx import AsyncClient

from app.companion.auth import SESSION_COOKIE_NAME, create_session_token
from app.db.engine import async_session_factory, init_db
from app.db.repository import (
    IdentityTokenRepository,
    TaskRepository,
    UserRepository,
)
from app.tasks.state import TaskRecord, TaskState
from app.tasks.registry import task_registry
from app.db.repository import CredentialRepository


@pytest_asyncio.fixture(autouse=True)
async def setup_test_database():
    """Ensure database schema is created prior to API tests."""
    await init_db()


@pytest.mark.asyncio
async def test_unauthorized_access(async_client: AsyncClient):
    # Dashboard without session cookie returns 401 HTML
    resp = await async_client.get("/companion/accounts")
    assert resp.status_code == 401
    assert "Session Link Required" in resp.text

    # REST vault API without auth returns 401 JSON
    resp_api = await async_client.get("/api/vault/credentials")
    assert resp_api.status_code == 401


@pytest.mark.asyncio
async def test_identity_linking_flow(async_client: AsyncClient):
    telegram_id = 123987456

    # 1. Create one-time token in repository
    async with async_session_factory() as session:
        token_obj = await IdentityTokenRepository.create_token(
            session, telegram_id=telegram_id, ttl_minutes=10
        )
        await session.commit()
        token_str = token_obj.token

    # 2. Access /companion/link?token=XYZ
    resp = await async_client.get(f"/companion/link?token={token_str}")
    assert resp.status_code == 200
    assert "Identity Linked!" in resp.text
    assert f"#{telegram_id}" in resp.text
    assert SESSION_COOKIE_NAME in resp.cookies

    # 3. Attempting to consume same token again must fail (one-time token)
    resp_second = await async_client.get(f"/companion/link?token={token_str}")
    assert resp_second.status_code == 401
    assert "Session Link Required" in resp_second.text


@pytest.mark.asyncio
async def test_companion_dashboard_authenticated(async_client: AsyncClient):
    telegram_id = 99887766

    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        await session.commit()
        session_cookie = create_session_token(user.id, user.telegram_id)

    async_client.cookies.set(SESSION_COOKIE_NAME, session_cookie)

    resp = await async_client.get("/companion/accounts")
    assert resp.status_code == 200
    assert "Connected Accounts" in resp.text


@pytest.mark.asyncio
async def test_vault_credentials_crud(async_client: AsyncClient):
    telegram_id = 33445566

    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        await session.commit()
        session_cookie = create_session_token(user.id, user.telegram_id)

    async_client.cookies.set(SESSION_COOKIE_NAME, session_cookie)

    # 1. Add password credential with full URL (tests domain normalization)
    add_resp = await async_client.post(
        "/api/vault/credentials",
        json={
            "site_domain": "https://vercel.com/login",
            "auth_type": "password",
            "username_or_identifier": "test@vercel.com",
            "secret": "MySecretPassword123!",
        },
    )
    assert add_resp.status_code == 201
    data = add_resp.json()
    assert data["status"] == "success"
    assert data["site_domain"] == "vercel.com"
    assert data["masked_secret"] == "••••••••"
    cred_id = data["id"]

    # 2. Add TOTP seed credential with valid Base32
    totp_resp = await async_client.post(
        "/api/vault/credentials",
        json={
            "site_domain": "vercel.com",
            "auth_type": "totp_seed",
            "secret": "JBSW Y3DP EHPK 3PXP",  # Test normalization with spaces
        },
    )
    assert totp_resp.status_code == 201
    totp_data = totp_resp.json()
    totp_id = totp_data["id"]

    # 3. Add invalid TOTP seed (must return 400 Bad Request)
    bad_totp = await async_client.post(
        "/api/vault/credentials",
        json={
            "site_domain": "vercel.com",
            "auth_type": "totp_seed",
            "secret": "NOT-VALID-BASE-32-890!!!",
        },
    )
    assert bad_totp.status_code == 400

    # 4. List credentials (must never return plaintext secrets)
    list_resp = await async_client.get("/api/vault/credentials")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert len(items) >= 2
    raw_secrets = [i.get("secret") for i in items if "secret" in i]
    assert len(raw_secrets) == 0  # No plaintext 'secret' key exists in output

    # 5. Revoke credential
    del_resp = await async_client.delete(f"/api/vault/credentials/{cred_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "deleted"

    # Verify count decreased
    after_list = await async_client.get("/api/vault/credentials")
    remaining_ids = [i["id"] for i in after_list.json()]
    assert cred_id not in remaining_ids
    assert totp_id in remaining_ids


@pytest.mark.asyncio
async def test_task_needs_input_resolution(async_client: AsyncClient):
    telegram_id = 77889900

    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        # Create a paused task in NEEDS_INPUT state
        task = TaskRecord(
            user_id=telegram_id,
            chat_id=telegram_id,
            prompt="Deploy my repo to Vercel",
            state=TaskState.NEEDS_INPUT,
            status_message="Waiting for 2FA confirmation code...",
        )
        await TaskRepository.save_task(session, task)
        await session.commit()
        session_cookie = create_session_token(user.id, user.telegram_id)

    async_client.cookies.set(SESSION_COOKIE_NAME, session_cookie)

    # 1. View input page
    page_resp = await async_client.get(f"/companion/input?task_id={task.task_id}")
    assert page_resp.status_code == 200
    assert "Waiting for 2FA confirmation code" in page_resp.text

    # 2. Submit resolution input
    resolve_resp = await async_client.post(
        f"/api/tasks/{task.task_id}/resolve-input",
        json={
            "approved": True,
            "user_input": "2FA code: 847291",
        },
    )
    assert resolve_resp.status_code == 200
    res_data = resolve_resp.json()
    assert res_data["status"] == "resolved"
    assert res_data["state"] == TaskState.RUNNING.value

    # 3. Verify task resumed in database
    async with async_session_factory() as session:
        updated_task = await TaskRepository.get_task(session, task.task_id)
        assert updated_task.state == TaskState.RUNNING
        assert updated_task.metadata.get("resolved_input") == "2FA code: 847291"


@pytest_asyncio.fixture
async def credential_request(async_client):
    telegram_id = uuid.uuid4().int % 10**12
    async with async_session_factory() as db:
        user, _ = await UserRepository.get_or_create_by_telegram_id(db, telegram_id)
        task = TaskRecord(
            user_id=telegram_id, chat_id=telegram_id, prompt="Login", state=TaskState.NEEDS_INPUT,
            metadata={"target_domain": "example.com", "credential_input_deadline": time.time() + 150},
        )
        await TaskRepository.save_task(db, task)
        await db.commit()
    pending = task_registry.register_credential_input(task, "example.com", time.time() + 150)
    async_client.cookies.set(SESSION_COOKIE_NAME, create_session_token(user.id, telegram_id))
    try:
        yield user, task, pending
    finally:
        task_registry.clear_credential_input(task.task_id)


@pytest.mark.parametrize("payload", [
    {"credentials": {"other.com": "secret"}},
    {"credentials": {"example.com": ""}},
    {"credentials": {"example.com": "secret"}, "totp_seed": "NOT-BASE32!!"},
    {"approved": True, "user_input": "my password is ..."},
])
async def test_invalid_credential_input_never_writes_or_wakes(async_client, credential_request, payload):
    user, task, pending = credential_request
    response = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", json=payload)
    assert response.status_code == 400
    assert not pending.event.is_set()
    assert task.state == TaskState.NEEDS_INPUT
    async with async_session_factory() as db:
        assert await CredentialRepository.get_credentials_for_user(db, user.id) == []


async def test_other_user_cannot_view_or_resolve_request(async_client, credential_request):
    _, task, pending = credential_request
    async with async_session_factory() as db:
        other, _ = await UserRepository.get_or_create_by_telegram_id(db, uuid.uuid4().int % 10**12)
        await db.commit()
    async_client.cookies.set(SESSION_COOKIE_NAME, create_session_token(other.id, other.telegram_id))
    page = await async_client.get(f"/companion/input?task_id={task.task_id}&domain=example.com")
    assert page.status_code == 403
    response = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", json={"credentials": {"example.com": "secret"}})
    assert response.status_code == 403
    assert not pending.event.is_set()


async def test_credential_cancel_wakes_agent_without_storing_payload(async_client, credential_request):
    user, task, pending = credential_request
    response = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", json={
        "approved": False, "credentials": {"example.com": "must-not-save"},
    })
    assert response.status_code == 200
    assert pending.event.is_set()
    assert task.state == TaskState.FAILED
    async with async_session_factory() as db:
        assert await CredentialRepository.get_credentials_for_user(db, user.id) == []


async def test_expired_credential_request_cannot_resume(async_client, credential_request):
    _, task, pending = credential_request
    pending.deadline = time.time() - 1
    response = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", json={"credentials": {"example.com": "secret"}})
    assert response.status_code == 409
    assert not pending.event.is_set()


async def test_credential_request_requires_live_waiter(async_client, credential_request):
    _, task, pending = credential_request
    task_registry.clear_credential_input(task.task_id)
    response = await async_client.post(f"/api/tasks/{task.task_id}/resolve-input", json={"credentials": {"example.com": "secret"}})
    assert response.status_code == 409
    assert not pending.event.is_set()


async def test_domain_query_cannot_change_requested_site(async_client, credential_request):
    _, task, _ = credential_request
    response = await async_client.get(f"/companion/input?task_id={task.task_id}&domain=attacker.com")
    assert response.status_code == 400

