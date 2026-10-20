from collections.abc import AsyncGenerator
from typing import Optional

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import settings
from app.db.models import Base


def get_engine_args(database_url: str) -> dict:
    """Returns database-specific connection arguments."""
    args = {}
    if "sqlite" in database_url:
        args["connect_args"] = {"check_same_thread": False}
    return args


# Global async database engine
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
    **get_engine_args(settings.DATABASE_URL),
)

# Enforce foreign key constraints in SQLite
if "sqlite" in settings.DATABASE_URL:
    @event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

# Session factory for generating async sessions
async_session_factory = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an active database session.
    Automatically handles commit and rollback on exception.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db(target_engine: Optional[AsyncEngine] = None) -> None:
    """
    Creates all database tables defined in Base.metadata.
    Called during application startup or in test fixtures.
    """
    eng = target_engine or engine
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db(target_engine: Optional[AsyncEngine] = None) -> None:
    """Disposes database connection pools cleanly on application shutdown."""
    eng = target_engine or engine
    await eng.dispose()

