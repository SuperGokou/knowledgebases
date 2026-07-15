from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings, get_settings


def engine_options(settings: Settings) -> dict[str, Any]:
    asyncpg_timeouts = {
        "server_settings": {
            "statement_timeout": str(settings.database_statement_timeout_ms),
            "lock_timeout": str(settings.database_lock_timeout_ms),
            "idle_in_transaction_session_timeout": str(
                settings.database_idle_transaction_timeout_ms
            ),
        }
    }
    psycopg_timeouts = {
        "options": (
            f"-c statement_timeout={settings.database_statement_timeout_ms} "
            f"-c lock_timeout={settings.database_lock_timeout_ms} "
            "-c idle_in_transaction_session_timeout="
            f"{settings.database_idle_transaction_timeout_ms}"
        )
    }
    if settings.serverless:
        connect_args: dict[str, Any] = {}
        if "+asyncpg" in settings.database_url:
            connect_args = {
                "prepared_statement_cache_size": 0,
                "statement_cache_size": 0,
                **asyncpg_timeouts,
            }
        elif "+psycopg" in settings.database_url:
            connect_args = {"prepare_threshold": None, **psycopg_timeouts}
        return {
            "poolclass": NullPool,
            "connect_args": connect_args,
        }
    connect_args = (
        asyncpg_timeouts
        if "+asyncpg" in settings.database_url
        else psycopg_timeouts
        if "+psycopg" in settings.database_url
        else {}
    )
    return {
        "pool_pre_ping": True,
        "pool_size": settings.database_pool_size,
        "max_overflow": settings.database_max_overflow,
        "pool_timeout": settings.database_pool_timeout_seconds,
        "connect_args": connect_args,
    }


settings = get_settings()
engine = create_async_engine(
    settings.database_url,
    **engine_options(settings),
)
SessionFactory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionFactory() as session:
        yield session
