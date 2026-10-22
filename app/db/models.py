from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.tasks.state import TaskRecord, TaskState


class Base(DeclarativeBase):
    """Base declarative class for all Wilco database models."""
    pass


class User(Base):
    """
    Represents an authorized human user linked to their Telegram identity.
    """
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    telegram_id: Mapped[int] = mapped_column(
        BigInteger, unique=True, index=True, nullable=False
    )
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    credentials: Mapped[List["EncryptedCredential"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )
    profiles: Mapped[List["BrowserProfile"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} telegram_id={self.telegram_id}>"


class IdentityToken(Base):
    """
    Cryptographic one-time pairing token for linking Telegram identity to Companion Web sessions.
    """
    __tablename__ = "identity_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    token: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    telegram_id: Mapped[int] = mapped_column(
        BigInteger, index=True, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    is_used: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    @property
    def is_valid(self) -> bool:
        """Checks if token is unused and within its TTL window."""
        now = datetime.now(timezone.utc)
        # Handle timezone-naive comparison if needed
        expires = self.expires_at if self.expires_at.tzinfo else self.expires_at.replace(tzinfo=timezone.utc)
        return not self.is_used and expires > now

    def __repr__(self) -> str:
        return f"<IdentityToken token={self.token[:8]}... telegram_id={self.telegram_id} is_used={self.is_used}>"


class EncryptedCredential(Base):
    """
    Domain-bound secret or account identifier in the AES-256-GCM vault.
    Never stores plaintext secrets.
    """
    __tablename__ = "encrypted_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    site_domain: Mapped[str] = mapped_column(
        String(255), index=True, nullable=False
    )
    auth_type: Mapped[str] = mapped_column(
        String(50), nullable=False  # password | api_key | totp_seed | username | email | phone | country_code
    )
    username_or_identifier: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    encrypted_blob: Mapped[str] = mapped_column(
        Text, nullable=False  # Base64-encoded nonce (12B) + tag (16B) + ciphertext
    )
    key_version: Mapped[int] = mapped_column(
        Integer, default=1, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    user: Mapped["User"] = relationship(back_populates="credentials")

    def __repr__(self) -> str:
        return f"<EncryptedCredential domain={self.site_domain} type={self.auth_type}>"


class BrowserProfile(Base):
    """
    Persisted browser session state (Playwright cookies/localStorage state).
    Enables persistent login sessions across runs.
    """
    __tablename__ = "browser_profiles"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    site_domain: Mapped[str] = mapped_column(
        String(255), index=True, nullable=False
    )
    storage_state_json: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    browserbase_profile_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    user: Mapped["User"] = relationship(back_populates="profiles")

    def __repr__(self) -> str:
        return f"<BrowserProfile domain={self.site_domain} user_id={self.user_id}>"


class ConversationModel(Base):
    """Bounded, sanitized conversational context isolated by user and chat."""

    __tablename__ = "conversations"

    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    chat_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    messages: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
    )


class TaskModel(Base):
    """
    Persisted state machine record for Wilco tasks (satisfies Design Rule 4).
    Bridges seamlessly to TaskRecord in memory.
    """
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        BigInteger, index=True, nullable=False
    )
    chat_id: Mapped[int] = mapped_column(
        BigInteger, index=True, nullable=False
    )
    prompt: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    state: Mapped[str] = mapped_column(
        String(32), index=True, default=TaskState.RUNNING.value, nullable=False
    )
    status_message: Mapped[str] = mapped_column(
        Text, default="Task initialized.", nullable=False
    )
    message_id: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True
    )
    error: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def to_record(self) -> TaskRecord:
        """Converts the database model to an in-memory TaskRecord."""
        return TaskRecord(
            task_id=self.id,
            user_id=self.user_id,
            chat_id=self.chat_id,
            prompt=self.prompt,
            state=TaskState(self.state),
            status_message=self.status_message,
            message_id=self.message_id,
            error=self.error,
            metadata=self.metadata_json or {},
            created_at=self.created_at,
            updated_at=self.updated_at,
        )

    @classmethod
    def from_record(cls, record: TaskRecord) -> "TaskModel":
        """Constructs a TaskModel instance from a TaskRecord."""
        return cls(
            id=record.task_id,
            user_id=record.user_id,
            chat_id=record.chat_id,
            prompt=record.prompt,
            state=record.state.value,
            status_message=record.status_message,
            message_id=record.message_id,
            error=record.error,
            metadata_json=record.metadata,
            created_at=record.created_at,
            updated_at=record.updated_at,
        )

    def __repr__(self) -> str:
        return f"<TaskModel id={self.id} state={self.state}>"

