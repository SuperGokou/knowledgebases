from __future__ import annotations

import asyncio
import os
from collections.abc import Iterable
from uuid import UUID, uuid4

import pytest
from fastapi import Request
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.api.v1.routes.roles as role_routes
import app.api.v1.routes.users as user_routes
import app.bootstrap as bootstrap_module
from app.api.errors import ApiError
from app.bootstrap import seed_database
from app.core.config import Settings
from app.db.models import AuditLog, Role, User, UserRole
from app.schemas.roles import RoleUpdate
from app.schemas.users import RoleAssignmentUpdate
from app.services.access import AccessService
from app.services.rbac_mutation import (
    RBAC_MUTATION_ADVISORY_LOCK,
    acquire_rbac_mutation_lock,
)
from app.services.rbac_mutation import (
    lock_role_union as service_lock_role_union,
)
from scripts.postgres_acceptance import assert_acceptance_database

_POSTGRES_URL = os.getenv("KB_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not _POSTGRES_URL,
    reason="KB_TEST_POSTGRES_URL is required for bootstrap RBAC/CAS verification",
)


def _role_request(user_id: UUID) -> Request:
    return Request(
        {
            "type": "http",
            "method": "PUT",
            "path": f"/api/v1/users/{user_id}/roles",
            "headers": [],
            "query_string": b"",
            "server": ("acceptance.local", 443),
            "client": ("127.0.0.1", 1),
            "scheme": "https",
        }
    )


@pytest.mark.asyncio
async def test_postgres_bootstrap_recovery_waits_for_rbac_writer_and_is_single_shot() -> None:
    assert _POSTGRES_URL is not None
    unique = uuid4().hex
    application_name = f"kb_bootstrap_recovery_{unique}"
    engine = create_async_engine(
        _POSTGRES_URL,
        pool_size=4,
        max_overflow=0,
        connect_args={"server_settings": {"application_name": application_name}},
    )
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    settings = Settings(
        bootstrap_admin_email=f"bootstrap-recovery-{unique}@example.com",
        bootstrap_admin_password="A-password-bootstrap-must-not-apply-123!",
    )

    async with factory() as setup:
        user = await seed_database(setup, settings)
        role = await setup.scalar(select(Role).where(Role.code == "system_admin"))
        assert role is not None
        user_id = user.id
        role_id = role.id
        await setup.execute(
            delete(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
        )
        user.password_hash = "preserve-this-postgres-password-hash"
        user.role_assignment_version = 3
        user.token_version = 5
        await setup.commit()

    async def recover() -> None:
        async with factory() as recovery:
            await seed_database(recovery, settings)

    async with factory() as blocker:
        await acquire_rbac_mutation_lock(blocker)
        blocker_pid = int(await blocker.scalar(text("SELECT pg_backend_pid()")) or 0)
        blocked_user = await blocker.scalar(
            select(User).where(User.id == user_id).with_for_update()
        )
        assert blocked_user is not None
        blocked_user.role_assignment_version = 13
        blocked_user.token_version = 17

        first = asyncio.create_task(recover())
        second = asyncio.create_task(recover())
        deadline = asyncio.get_running_loop().time() + 5
        while asyncio.get_running_loop().time() < deadline:
            async with factory() as observer:
                rbac_lock_waiters = int(
                    await observer.scalar(
                        text(
                            "SELECT count(*) FROM pg_catalog.pg_locks AS locks "
                            "JOIN pg_catalog.pg_stat_activity AS activity "
                            "ON activity.pid = locks.pid "
                            "WHERE activity.application_name = :application_name "
                            "AND activity.pid <> :blocker_pid "
                            "AND locks.locktype = 'advisory' "
                            "AND locks.granted IS FALSE "
                            "AND locks.classid = 0 "
                            "AND locks.objid = :lock_key"
                        ),
                        {
                            "application_name": application_name,
                            "blocker_pid": blocker_pid,
                            "lock_key": RBAC_MUTATION_ADVISORY_LOCK,
                        },
                    )
                    or 0
                )
            if rbac_lock_waiters >= 1:
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("bootstrap did not wait for the RBAC mutation advisory lock")
        assert not first.done()
        assert not second.done()
        await blocker.commit()

    await asyncio.wait_for(asyncio.gather(first, second), timeout=10)

    async with factory() as verification:
        verification_user = await verification.scalar(select(User).where(User.id == user_id))
        assert verification_user is not None
        assignments = int(
            await verification.scalar(
                select(func.count())
                .select_from(UserRole)
                .where(UserRole.user_id == user_id, UserRole.role_id == role_id)
            )
            or 0
        )
        audits = list(
            (
                await verification.scalars(
                    select(AuditLog).where(
                        AuditLog.action == "bootstrap.system_admin_role_restored",
                        AuditLog.resource_id == str(user_id),
                    )
                )
            ).all()
        )

        assert assignments == 1
        assert verification_user.password_hash == "preserve-this-postgres-password-hash"
        assert verification_user.role_assignment_version == 14
        assert verification_user.token_version == 18
        assert len(audits) == 1
        assert audits[0].details["from_role_assignment_version"] == 13
        assert audits[0].details["to_role_assignment_version"] == 14
        assert audits[0].details["from_token_version"] == 17
        assert audits[0].details["to_token_version"] == 18
        assert audits[0].details["password_reset"] is False

    await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_route_cas_observes_committed_bootstrap_recovery_version() -> None:
    assert _POSTGRES_URL is not None
    unique = uuid4().hex
    engine = create_async_engine(_POSTGRES_URL, pool_size=3, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    settings = Settings(
        bootstrap_admin_email=f"bootstrap-linearization-{unique}@example.com",
        bootstrap_admin_password="A-password-bootstrap-must-not-apply-123!",
    )

    async with factory() as setup:
        target = await seed_database(setup, settings)
        system_role = await setup.scalar(select(Role).where(Role.code == "system_admin"))
        assert system_role is not None
        target_id = target.id
        system_role_id = system_role.id
        await setup.execute(
            delete(UserRole).where(
                UserRole.user_id == target_id,
                UserRole.role_id == system_role_id,
            )
        )
        target.role_assignment_version = 9
        target.token_version = 20
        await setup.commit()

        # Linearization order under test: bootstrap restores and commits first.
        await seed_database(setup, settings)
        await setup.refresh(target)
        assert target.role_assignment_version == 10
        assert target.token_version == 21

        actor = User(
            email=f"bootstrap-cas-writer-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        replacement_role = Role(
            code=f"bootstrap_replacement_{unique}",
            name="Bootstrap CAS replacement",
            priority=-1,
        )
        setup.add_all([actor, replacement_role])
        await setup.flush()
        setup.add(UserRole(user_id=actor.id, role_id=system_role_id, assigned_by=actor.id))
        await setup.commit()
        actor_id = actor.id
        replacement_role_id = replacement_role.id

    async with factory() as stale_writer:
        stale_actor = await stale_writer.scalar(select(User).where(User.id == actor_id))
        assert stale_actor is not None
        access = await AccessService().resolve(stale_writer, stale_actor)
        with pytest.raises(ApiError) as stale_error:
            await user_routes.replace_user_roles(
                user_id=target_id,
                payload=RoleAssignmentUpdate(
                    expected_version=9,
                    role_ids=[replacement_role_id],
                ),
                request=_role_request(target_id),
                session=stale_writer,
                access=access,
            )
        assert stale_error.value.status_code == 409
        assert stale_error.value.code == "stale_role_assignment"
        assert stale_error.value.details == {"current_version": 10}
        await stale_writer.rollback()

    async with factory() as after_stale:
        unchanged = await after_stale.scalar(select(User).where(User.id == target_id))
        assert unchanged is not None
        unchanged_role_ids = set(
            (
                await after_stale.scalars(
                    select(UserRole.role_id).where(UserRole.user_id == target_id)
                )
            ).all()
        )
        assert unchanged.role_assignment_version == 10
        assert unchanged.token_version == 21
        assert unchanged_role_ids == {system_role_id}

    async with factory() as current_writer:
        current_actor = await current_writer.scalar(select(User).where(User.id == actor_id))
        assert current_actor is not None
        access = await AccessService().resolve(current_writer, current_actor)
        updated = await user_routes.replace_user_roles(
            user_id=target_id,
            payload=RoleAssignmentUpdate(
                expected_version=10,
                role_ids=[replacement_role_id],
            ),
            request=_role_request(target_id),
            session=current_writer,
            access=access,
        )
        assert updated.role_assignment_version == 11
        assert updated.role_ids == [replacement_role_id]

    async with factory() as verification:
        persisted = await verification.scalar(select(User).where(User.id == target_id))
        assert persisted is not None
        audits = list(
            (
                await verification.scalars(
                    select(AuditLog)
                    .where(
                        AuditLog.resource_id == str(target_id),
                        AuditLog.action.in_(
                            {
                                "bootstrap.system_admin_role_restored",
                                "user.roles.replaced",
                            }
                        ),
                    )
                    .order_by(AuditLog.id)
                )
            ).all()
        )
        assert persisted.role_assignment_version == 11
        assert persisted.token_version == 22
        assert [event.action for event in audits] == [
            "bootstrap.system_admin_role_restored",
            "user.roles.replaced",
        ]
        assert audits[0].details["from_role_assignment_version"] == 9
        assert audits[0].details["to_role_assignment_version"] == 10
        assert audits[1].details == {"from_version": 10, "to_version": 11}

    await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_system_role_repair_and_route_mutation_are_linearly_ordered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _POSTGRES_URL is not None
    unique = uuid4().hex
    engine = create_async_engine(_POSTGRES_URL, pool_size=4, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    settings = Settings(
        bootstrap_admin_email=f"bootstrap-role-repair-{unique}@example.com",
        bootstrap_admin_password="A-password-bootstrap-must-not-apply-123!",
    )

    async with factory() as setup:
        actor = await seed_database(setup, settings)
        system_role = await setup.scalar(select(Role).where(Role.code == "system_admin"))
        assert system_role is not None
        system_role.name = "corrupted system role name"
        system_role.description = "corrupted system role description"
        system_role.policy_version = 5
        await setup.commit()
        actor_access = await AccessService().resolve(setup, actor)
        system_role_id = system_role.id

    bootstrap_holds_policy_domain = asyncio.Event()
    release_bootstrap = asyncio.Event()

    async def hold_bootstrap_after_role_lock(
        session: AsyncSession,
        *,
        user_ids: Iterable[UUID],
        additional_role_ids: Iterable[UUID] = (),
    ) -> dict[UUID, Role]:
        locked = await service_lock_role_union(
            session,
            user_ids=user_ids,
            additional_role_ids=additional_role_ids,
        )
        bootstrap_holds_policy_domain.set()
        await release_bootstrap.wait()
        return locked

    monkeypatch.setattr(bootstrap_module, "lock_role_union", hold_bootstrap_after_role_lock)

    async def repair() -> None:
        async with factory() as session:
            await seed_database(session, settings)

    async def mutate() -> str:
        async with factory() as session:
            try:
                await role_routes.update_role(
                    role_id=system_role_id,
                    payload=RoleUpdate(
                        expected_version=5,
                        name="route must never overwrite system role",
                    ),
                    request=_role_request(system_role_id),
                    session=session,
                    access=actor_access,
                )
                return "updated"
            except ApiError as exc:
                await session.rollback()
                return exc.code

    repair_task = asyncio.create_task(repair())
    mutation_task: asyncio.Task[str] | None = None
    try:
        await asyncio.wait_for(bootstrap_holds_policy_domain.wait(), timeout=5)
        mutation_task = asyncio.create_task(mutate())
        await asyncio.sleep(0.2)
        assert not mutation_task.done()
        release_bootstrap.set()
        await asyncio.wait_for(repair_task, timeout=10)
        assert await asyncio.wait_for(mutation_task, timeout=10) == "system_role"

        async with factory() as verification:
            repaired = await verification.get(Role, system_role_id)
            assert repaired is not None
            audits = list(
                (
                    await verification.scalars(
                        select(AuditLog).where(
                            AuditLog.action == "bootstrap.system_admin_policy_restored",
                            AuditLog.resource_id == str(system_role_id),
                        )
                    )
                ).all()
            )
        assert repaired.name == "系统管理员"
        assert repaired.policy_version == 6
        assert len(audits) == 1
        assert audits[0].details["from_version"] == 5
        assert audits[0].details["to_version"] == 6
    finally:
        release_bootstrap.set()
        if not repair_task.done():
            repair_task.cancel()
        if mutation_task is not None and not mutation_task.done():
            mutation_task.cancel()
        await asyncio.gather(
            repair_task,
            *(tuple([mutation_task]) if mutation_task is not None else ()),
            return_exceptions=True,
        )
        await engine.dispose()
