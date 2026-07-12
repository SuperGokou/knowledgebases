from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

EXPECTED_ALEMBIC_HEADS = frozenset({"20260712_0008"})


class DatabaseSchemaDriftError(RuntimeError):
    pass


async def assert_database_schema_current(session: AsyncSession) -> None:
    result = await session.execute(text("SELECT version_num FROM alembic_version"))
    actual = frozenset(result.scalars().all())
    if actual != EXPECTED_ALEMBIC_HEADS:
        raise DatabaseSchemaDriftError("database migration revision does not match application")
