from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings, get_settings


def engine_options(settings: Settings) -> dict[str, Any]:
    if settings.serverless:
        connect_args: dict[str, Any] = {}
        if "+asyncpg" in settings.database_url:
            connect_args = {
                "prepared_statement_cache_size": 0,
                "statement_cache_size": 0,
            }
        elif "+psycopg" in settings.database_url:
            connect_args = {"prepare_threshold": None}
        return {
            "poolclass": NullPool,
            "connect_args": connect_args,
        }
    return {
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
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
