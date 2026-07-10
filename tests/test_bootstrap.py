import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.bootstrap import LIMIT_CATALOG, PERMISSION_CATALOG, seed_database
from app.core.config import Settings
from app.db.base import Base
from app.db.models import LimitDefinition, Permission, Role, RolePermission, User, UserRole


@pytest.mark.asyncio
async def test_bootstrap_is_idempotent_and_creates_a_working_superuser() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    settings = Settings(
        bootstrap_admin_email="owner@example.com",
        bootstrap_admin_password="Owner-password-for-tests-123!",
    )
    async with factory() as session:
        await seed_database(session, settings)
        await seed_database(session, settings)

        user = await session.scalar(select(User).where(User.email == "owner@example.com"))
        role = await session.scalar(select(Role).where(Role.code == "system_admin"))
        assert user is not None and user.is_superuser
        assert role is not None and role.is_system
        assert await session.scalar(select(func.count()).select_from(Permission)) == len(
            PERMISSION_CATALOG
        )
        assert await session.scalar(select(func.count()).select_from(LimitDefinition)) == len(
            LIMIT_CATALOG
        )
        assert await session.scalar(select(func.count()).select_from(RolePermission)) == len(
            PERMISSION_CATALOG
        )
        assert await session.scalar(select(func.count()).select_from(UserRole)) == 1

    await engine.dispose()
