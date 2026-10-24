from datetime import datetime, timedelta, timezone
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import (
    Base,
    IdentityToken,
)
from app.db.repository import (
    BrowserProfileRepository,
    CredentialRepository,
    IdentityTokenRepository,
    TaskRepository,
    UserRepository,
)
from app.tasks.state import TaskRecord, TaskState


@pytest_asyncio.fixture
async def db_session():
    """Provides an isolated in-memory SQLite database session for testing."""
    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=test_engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )

    async with session_factory() as session:
        yield session

    await test_engine.dispose()


@pytest.mark.asyncio
async def test_user_repository(db_session: AsyncSession):
    # Create new user
    user, created = await UserRepository.get_or_create_by_telegram_id(
        db_session, telegram_id=123456789, email="test@example.com"
    )
    assert created is True
    assert user.telegram_id == 123456789
    assert user.email == "test@example.com"
    assert user.id is not None

    # Retrieve existing user
    user2, created2 = await UserRepository.get_or_create_by_telegram_id(
        db_session, telegram_id=123456789
    )
    assert created2 is False
    assert user2.id == user.id

    # Lookup by id
    by_id = await UserRepository.get_by_id(db_session, user.id)
    assert by_id is not None
    assert by_id.telegram_id == 123456789


@pytest.mark.asyncio
async def test_identity_token_repository(db_session: AsyncSession):
    telegram_id = 987654321

    # Create token
    token = await IdentityTokenRepository.create_token(
        db_session, telegram_id=telegram_id, ttl_minutes=10
    )
    assert len(token.token) >= 32
    assert token.is_used is False
    assert token.is_valid is True

    # Validate and consume token
    consumed_tg_id = await IdentityTokenRepository.validate_and_consume_token(
        db_session, token.token
    )
    assert consumed_tg_id == telegram_id

    # Second consumption must fail (one-time token)
    consumed_again = await IdentityTokenRepository.validate_and_consume_token(
        db_session, token.token
    )
    assert consumed_again is None

    # Test expired token
    expired_token = IdentityToken(
        token="expired-token-xyz",
        telegram_id=telegram_id,
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        is_used=False,
    )
    db_session.add(expired_token)
    await db_session.flush()

    assert expired_token.is_valid is False
    res = await IdentityTokenRepository.validate_and_consume_token(
        db_session, "expired-token-xyz"
    )
    assert res is None


@pytest.mark.asyncio
async def test_credential_repository(db_session: AsyncSession):
    user, _ = await UserRepository.get_or_create_by_telegram_id(db_session, telegram_id=111222333)

    # Add password credential
    cred1 = await CredentialRepository.add_or_update_credential(
        db_session,
        user_id=user.id,
        site_domain="Vercel.com",  # Test case insensitivity
        auth_type="password",
        encrypted_blob="dummy_encrypted_blob_123",
        username_or_identifier="user@example.com",
    )
    assert cred1.site_domain == "vercel.com"

    # Add TOTP credential
    cred2 = await CredentialRepository.add_or_update_credential(
        db_session,
        user_id=user.id,
        site_domain="vercel.com",
        auth_type="totp_seed",
        encrypted_blob="dummy_totp_blob_456",
    )

    # Fetch domain credentials
    domain_creds = await CredentialRepository.get_credentials_for_domain(
        db_session, user.id, "vercel.com"
    )
    assert len(domain_creds) == 2

    # Update password credential
    updated = await CredentialRepository.add_or_update_credential(
        db_session,
        user_id=user.id,
        site_domain="vercel.com",
        auth_type="password",
        encrypted_blob="new_encrypted_blob_789",
        username_or_identifier="user@example.com",
    )
    assert updated.id == cred1.id
    assert updated.encrypted_blob == "new_encrypted_blob_789"

    # Delete single credential
    deleted = await CredentialRepository.delete_credential(db_session, cred2.id, user.id)
    assert deleted is True

    # Delete all credentials for domain
    deleted_count = await CredentialRepository.delete_credentials_for_domain(
        db_session, user.id, "vercel.com"
    )
    assert deleted_count == 1

    remaining = await CredentialRepository.get_credentials_for_domain(
        db_session, user.id, "vercel.com"
    )
    assert len(remaining) == 0


@pytest.mark.asyncio
async def test_browser_profile_repository(db_session: AsyncSession):
    user, _ = await UserRepository.get_or_create_by_telegram_id(db_session, telegram_id=444555666)

    # Save profile
    profile = await BrowserProfileRepository.save_profile(
        db_session,
        user_id=user.id,
        site_domain="github.com",
        storage_state_json='{"cookies": [{"name": "session", "value": "xyz"}]}',
    )
    assert profile.site_domain == "github.com"

    # Get profile
    fetched = await BrowserProfileRepository.get_profile(db_session, user.id, "github.com")
    assert fetched is not None
    assert "session" in fetched.storage_state_json

    # Delete profile
    deleted = await BrowserProfileRepository.delete_profile(db_session, user.id, "github.com")
    assert deleted is True

    none_profile = await BrowserProfileRepository.get_profile(db_session, user.id, "github.com")
    assert none_profile is None


@pytest.mark.asyncio
async def test_task_repository(db_session: AsyncSession):
    record = TaskRecord(
        user_id=777888999,
        chat_id=12345,
        prompt="Deploy to Vercel",
        state=TaskState.RUNNING,
        status_message="Navigating...",
        metadata={"step": 1},
    )

    # Persist task
    saved_model = await TaskRepository.save_task(db_session, record)
    assert saved_model.id == record.task_id

    # Retrieve task
    retrieved = await TaskRepository.get_task(db_session, record.task_id)
    assert retrieved is not None
    assert retrieved.task_id == record.task_id
    assert retrieved.prompt == "Deploy to Vercel"
    assert retrieved.state == TaskState.RUNNING
    assert retrieved.metadata == {"step": 1}

    # Update state following valid state transitions (RUNNING -> VERIFYING -> DONE)
    record.transition_to(TaskState.VERIFYING, status_message="Verifying page results...")
    record.transition_to(TaskState.DONE, status_message="Finished successfully!")
    await TaskRepository.save_task(db_session, record)

    updated_record = await TaskRepository.get_task(db_session, record.task_id)
    assert updated_record.state == TaskState.DONE
    assert updated_record.status_message == "Finished successfully!"


@pytest.mark.asyncio
async def test_cascade_delete(db_session: AsyncSession):
    user, _ = await UserRepository.get_or_create_by_telegram_id(db_session, telegram_id=999000111)

    # Add credential and profile
    await CredentialRepository.add_or_update_credential(
        db_session,
        user_id=user.id,
        site_domain="demo.com",
        auth_type="password",
        encrypted_blob="blob",
    )
    await BrowserProfileRepository.save_profile(
        db_session,
        user_id=user.id,
        site_domain="demo.com",
        storage_state_json="{}",
    )

    # Delete user
    await db_session.delete(user)
    await db_session.flush()

    # Verify cascades
    creds = await CredentialRepository.get_credentials_for_user(db_session, user.id)
    assert len(creds) == 0

    profile = await BrowserProfileRepository.get_profile(db_session, user.id, "demo.com")
    assert profile is None
