from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.bootstrap import LIMIT_CATALOG, PERMISSION_CATALOG, seed_database
from app.core.config import Settings
from app.db.base import Base
from app.db.models import (
    AuditLog,
    LimitDefinition,
    Permission,
    Role,
    RoleLimit,
    RolePermission,
    User,
    UserRole,
    UserStatus,
)


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


@pytest.mark.asyncio
async def test_bootstrap_refuses_retired_admin_without_any_recovery_side_effect() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    settings = Settings(
        bootstrap_admin_email="retired-bootstrap@example.com",
        bootstrap_admin_password="Retired-bootstrap-password-123!",
    )
    async with factory() as session:
        administrator = await seed_database(session, settings)
        operator = User(
            email="retirement-operator@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        session.add(operator)
        await session.flush()
        await session.execute(delete(UserRole).where(UserRole.user_id == administrator.id))
        administrator.status = UserStatus.DISABLED
        administrator.retired_at = datetime.now(UTC)
        administrator.retired_by_id = operator.id
        administrator.retirement_reason = "Bootstrap account deliberately retired"
        administrator.token_version = 9
        administrator.role_assignment_version = 5
        await session.commit()
        administrator_id = administrator.id
        audit_count = int(await session.scalar(select(func.count()).select_from(AuditLog)) or 0)

    async with factory() as session:
        with pytest.raises(RuntimeError, match="inactive or retired bootstrap administrator"):
            await seed_database(session, settings)
        await session.rollback()

    async with factory() as session:
        administrator = await session.get(User, administrator_id)
        assert administrator is not None
        assert administrator.status is UserStatus.DISABLED
        assert administrator.retired_at is not None
        assert administrator.token_version == 9
        assert administrator.role_assignment_version == 5
        assert (
            await session.scalar(
                select(func.count())
                .select_from(UserRole)
                .where(UserRole.user_id == administrator_id)
            )
            == 0
        )
        assert (
            int(await session.scalar(select(func.count()).select_from(AuditLog)) or 0)
            == audit_count
        )

    await engine.dispose()


@pytest.mark.asyncio
async def test_bootstrap_increments_system_role_policy_version_once_per_actual_repair() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    settings = Settings(
        bootstrap_admin_email="policy-repair@example.com",
        bootstrap_admin_password="Policy-repair-password-for-tests-123!",
    )
    async with factory() as session:
        await seed_database(session, settings)
        role = await session.scalar(select(Role).where(Role.code == "system_admin"))
        assert role is not None
        assert role.policy_version == 1

        permission_link = await session.scalar(
            select(RolePermission).where(RolePermission.role_id == role.id)
        )
        limit_link = await session.scalar(select(RoleLimit).where(RoleLimit.role_id == role.id))
        assert permission_link is not None and limit_link is not None
        await session.delete(permission_link)
        limit_link.value = 1
        role.name = "stale system role name"
        await session.commit()

        await seed_database(session, settings)
        await session.refresh(role)
        assert role.policy_version == 2
        audits = list(
            (
                await session.scalars(
                    select(AuditLog).where(
                        AuditLog.action == "bootstrap.system_admin_policy_restored",
                        AuditLog.resource_id == str(role.id),
                    )
                )
            ).all()
        )
        assert [item.details for item in audits] == [
            {
                "role_code": "system_admin",
                "from_version": 1,
                "to_version": 2,
            }
        ]

        await seed_database(session, settings)
        await session.refresh(role)
        assert role.policy_version == 2
        assert (
            await session.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.action == "bootstrap.system_admin_policy_restored",
                    AuditLog.resource_id == str(role.id),
                )
            )
        ) == 1

    await engine.dispose()


@pytest.mark.asyncio
async def test_bootstrap_role_policy_repair_and_audit_roll_back_together() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    settings = Settings(
        bootstrap_admin_email="policy-repair-atomicity@example.com",
        bootstrap_admin_password="Policy-repair-atomicity-password-for-tests-123!",
    )
    async with factory() as setup:
        await seed_database(setup, settings)
        role = await setup.scalar(select(Role).where(Role.code == "system_admin"))
        assert role is not None
        role.name = "corrupted system role"
        role.policy_version = 7
        await setup.commit()
        role_id = role.id

    async with factory() as trigger_setup:
        await trigger_setup.execute(
            text(
                "CREATE TRIGGER reject_bootstrap_policy_audit "
                "BEFORE INSERT ON audit_logs "
                "WHEN NEW.action = 'bootstrap.system_admin_policy_restored' "
                "BEGIN SELECT RAISE(ABORT, 'simulated audit persistence failure'); END"
            )
        )
        await trigger_setup.commit()

    async with factory() as failing_repair:
        with pytest.raises(IntegrityError, match="simulated audit persistence failure"):
            await seed_database(failing_repair, settings)
        await failing_repair.rollback()

    async with factory() as after_failure:
        unchanged_role = await after_failure.get(Role, role_id)
        assert unchanged_role is not None
        assert unchanged_role.name == "corrupted system role"
        assert unchanged_role.policy_version == 7
        assert (
            await after_failure.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.action == "bootstrap.system_admin_policy_restored",
                    AuditLog.resource_id == str(role_id),
                )
            )
        ) == 0

    async with factory() as trigger_cleanup:
        await trigger_cleanup.execute(text("DROP TRIGGER reject_bootstrap_policy_audit"))
        await trigger_cleanup.commit()

    async with factory() as retry:
        await seed_database(retry, settings)
        repaired_role = await retry.get(Role, role_id)
        assert repaired_role is not None
        assert repaired_role.policy_version == 8
        assert (
            await retry.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.action == "bootstrap.system_admin_policy_restored",
                    AuditLog.resource_id == str(role_id),
                )
            )
        ) == 1

    await engine.dispose()


@pytest.mark.asyncio
async def test_bootstrap_restores_an_existing_admin_without_resetting_password() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    settings = Settings(
        bootstrap_admin_email="recovery@example.com",
        bootstrap_admin_password="A-password-bootstrap-must-not-apply-123!",
    )
    async with factory() as session:
        user = await seed_database(session, settings)
        role = await session.scalar(select(Role).where(Role.code == "system_admin"))
        assert role is not None
        await session.execute(
            delete(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
        )
        user.password_hash = "preserve-this-existing-password-hash"
        user.role_assignment_version = 7
        user.token_version = 11
        await session.commit()

        await seed_database(session, settings)
        await session.refresh(user)
        restored_assignment = await session.scalar(
            select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
        )
        audits = list(
            (
                await session.scalars(
                    select(AuditLog).where(
                        AuditLog.action == "bootstrap.system_admin_role_restored",
                        AuditLog.resource_id == str(user.id),
                    )
                )
            ).all()
        )

        assert restored_assignment is not None
        assert user.password_hash == "preserve-this-existing-password-hash"
        assert user.role_assignment_version == 8
        assert user.token_version == 12
        assert len(audits) == 1
        assert audits[0].actor_id is None
        assert audits[0].details == {
            "role_code": "system_admin",
            "role_id": str(role.id),
            "from_role_assignment_version": 7,
            "to_role_assignment_version": 8,
            "from_token_version": 11,
            "to_token_version": 12,
            "password_reset": False,
        }

    await engine.dispose()
