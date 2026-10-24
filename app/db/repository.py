from datetime import datetime, timedelta, timezone
import secrets
from typing import List, Optional, Tuple
import uuid

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    BrowserProfile,
    EncryptedCredential,
    IdentityToken,
    TaskModel,
    User,
)
from app.tasks.state import TaskRecord, TaskState


class UserRepository:
    """Encapsulates database operations for authorized users."""

    @staticmethod
    async def get_by_telegram_id(session: AsyncSession, telegram_id: int) -> Optional[User]:
        stmt = select(User).where(User.telegram_id == telegram_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_id(session: AsyncSession, user_id: uuid.UUID) -> Optional[User]:
        stmt = select(User).where(User.id == user_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_or_create_by_telegram_id(
        session: AsyncSession, telegram_id: int, email: Optional[str] = None
    ) -> Tuple[User, bool]:
        """
        Returns (user, created). If user does not exist, inserts and commits.
        """
        existing = await UserRepository.get_by_telegram_id(session, telegram_id)
        if existing:
            if email and not existing.email:
                existing.email = email
                await session.flush()
            return existing, False

        user = User(telegram_id=telegram_id, email=email)
        session.add(user)
        await session.flush()
        return user, True


class IdentityTokenRepository:
    """Manages one-time pairing tokens for Telegram-to-Web identity linking."""

    @staticmethod
    async def create_token(
        session: AsyncSession, telegram_id: int, ttl_minutes: int = 10
    ) -> IdentityToken:
        token_str = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)

        token_obj = IdentityToken(
            token=token_str,
            telegram_id=telegram_id,
            expires_at=expires_at,
            is_used=False,
        )
        session.add(token_obj)
        await session.flush()
        return token_obj

    @staticmethod
    async def get_token(session: AsyncSession, token_str: str) -> Optional[IdentityToken]:
        stmt = select(IdentityToken).where(IdentityToken.token == token_str)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def validate_and_consume_token(
        session: AsyncSession, token_str: str
    ) -> Optional[int]:
        """
        Validates the pairing token. If valid and not expired:
        marks it as used and returns the associated telegram_id.
        Otherwise returns None.
        """
        # Consume atomically so two simultaneous WebApp opens cannot reuse a token.
        stmt = update(IdentityToken).where(
            IdentityToken.token == token_str,
            IdentityToken.is_used == False,  # noqa: E712
            IdentityToken.expires_at > datetime.now(timezone.utc),
        ).values(is_used=True).returning(IdentityToken.telegram_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()


class CredentialRepository:
    """Manages encrypted secrets in the cryptographic vault."""

    @staticmethod
    async def add_or_update_credential(
        session: AsyncSession,
        user_id: uuid.UUID,
        site_domain: str,
        auth_type: str,
        encrypted_blob: str,
        username_or_identifier: Optional[str] = None,
    ) -> EncryptedCredential:
        domain = site_domain.strip().lower()
        stmt = select(EncryptedCredential).where(
            EncryptedCredential.user_id == user_id,
            EncryptedCredential.site_domain == domain,
            EncryptedCredential.auth_type == auth_type,
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.encrypted_blob = encrypted_blob
            existing.username_or_identifier = username_or_identifier
            existing.updated_at = datetime.now(timezone.utc)
            await session.flush()
            return existing

        cred = EncryptedCredential(
            user_id=user_id,
            site_domain=domain,
            auth_type=auth_type,
            username_or_identifier=username_or_identifier,
            encrypted_blob=encrypted_blob,
        )
        session.add(cred)
        await session.flush()
        return cred

    @staticmethod
    async def get_credentials_for_user(
        session: AsyncSession, user_id: uuid.UUID
    ) -> List[EncryptedCredential]:
        stmt = (
            select(EncryptedCredential)
            .where(EncryptedCredential.user_id == user_id)
            .order_by(EncryptedCredential.site_domain, EncryptedCredential.created_at)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def get_credentials_for_domain(
        session: AsyncSession, user_id: uuid.UUID, site_domain: str
    ) -> List[EncryptedCredential]:
        domain = site_domain.strip().lower()
        stmt = select(EncryptedCredential).where(
            EncryptedCredential.user_id == user_id,
            EncryptedCredential.site_domain == domain,
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def delete_credential(
        session: AsyncSession, credential_id: uuid.UUID, user_id: uuid.UUID
    ) -> bool:
        stmt = delete(EncryptedCredential).where(
            EncryptedCredential.id == credential_id,
            EncryptedCredential.user_id == user_id,
        )
        result = await session.execute(stmt)
        await session.flush()
        return result.rowcount > 0

    @staticmethod
    async def delete_credentials_for_domain(
        session: AsyncSession, user_id: uuid.UUID, site_domain: str
    ) -> int:
        domain = site_domain.strip().lower()
        stmt = delete(EncryptedCredential).where(
            EncryptedCredential.user_id == user_id,
            EncryptedCredential.site_domain == domain,
        )
        result = await session.execute(stmt)
        await session.flush()
        return result.rowcount


class BrowserProfileRepository:
    """Manages persistent browser storage states (cookies/local storage)."""

    @staticmethod
    async def get_profiles_for_user(session: AsyncSession, user_id: uuid.UUID) -> List[BrowserProfile]:
        result = await session.execute(
            select(BrowserProfile).where(BrowserProfile.user_id == user_id).order_by(
                BrowserProfile.updated_at, BrowserProfile.site_domain,
            )
        )
        return list(result.scalars().all())

    @staticmethod
    async def save_profile(
        session: AsyncSession,
        user_id: uuid.UUID,
        site_domain: str,
        storage_state_json: str,
        browserbase_profile_id: Optional[str] = None,
    ) -> BrowserProfile:
        domain = site_domain.strip().lower()
        stmt = select(BrowserProfile).where(
            BrowserProfile.user_id == user_id,
            BrowserProfile.site_domain == domain,
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.storage_state_json = storage_state_json
            if browserbase_profile_id:
                existing.browserbase_profile_id = browserbase_profile_id
            existing.updated_at = datetime.now(timezone.utc)
            await session.flush()
            return existing

        profile = BrowserProfile(
            user_id=user_id,
            site_domain=domain,
            storage_state_json=storage_state_json,
            browserbase_profile_id=browserbase_profile_id,
        )
        session.add(profile)
        await session.flush()
        return profile

    @staticmethod
    async def get_profile(
        session: AsyncSession, user_id: uuid.UUID, site_domain: str
    ) -> Optional[BrowserProfile]:
        domain = site_domain.strip().lower()
        stmt = select(BrowserProfile).where(
            BrowserProfile.user_id == user_id,
            BrowserProfile.site_domain == domain,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def delete_profile(
        session: AsyncSession, user_id: uuid.UUID, site_domain: str
    ) -> bool:
        domain = site_domain.strip().lower()
        stmt = delete(BrowserProfile).where(
            BrowserProfile.user_id == user_id,
            BrowserProfile.site_domain == domain,
        )
        result = await session.execute(stmt)
        await session.flush()
        return result.rowcount > 0


class TaskRepository:
    """Persist task status and metadata; running tasks are coordinated in memory."""

    @staticmethod
    async def save_task(session: AsyncSession, task_record: TaskRecord) -> TaskModel:
        stmt = select(TaskModel).where(TaskModel.id == task_record.task_id)
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.state = task_record.state.value
            existing.status_message = task_record.status_message
            existing.message_id = task_record.message_id
            existing.error = task_record.error
            existing.metadata_json = task_record.metadata
            existing.updated_at = task_record.updated_at
            await session.flush()
            return existing

        task_model = TaskModel.from_record(task_record)
        session.add(task_model)
        await session.flush()
        return task_model

    @staticmethod
    async def get_task(session: AsyncSession, task_id: str) -> Optional[TaskRecord]:
        stmt = select(TaskModel).where(TaskModel.id == task_id)
        result = await session.execute(stmt)
        model = result.scalar_one_or_none()
        return model.to_record() if model else None

    @staticmethod
    async def get_active_tasks_for_chat(
        session: AsyncSession, chat_id: int
    ) -> List[TaskRecord]:
        active_states = [TaskState.RUNNING.value, TaskState.NEEDS_INPUT.value, TaskState.VERIFYING.value]
        stmt = (
            select(TaskModel)
            .where(
                TaskModel.chat_id == chat_id,
                TaskModel.state.in_(active_states),
            )
            .order_by(TaskModel.created_at.desc())
        )
        result = await session.execute(stmt)
        models = result.scalars().all()
        return [m.to_record() for m in models]

