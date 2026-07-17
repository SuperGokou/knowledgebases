from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.api.v1.routes.knowledge_bases as knowledge_base_routes
import app.api.v1.routes.roles as role_routes
import app.api.v1.routes.users as user_routes
from app.api.errors import ApiError
from app.db.models import (
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.schemas.knowledge_bases import KnowledgeBaseRoleGrantInput, KnowledgeBaseRoleGrantSet
from app.schemas.users import RoleAssignmentUpdate
from app.services.access import AccessContext, AccessService
from app.services.knowledge_bases import KnowledgeBaseAccess, require_knowledge_base_access
from scripts.postgres_acceptance import assert_acceptance_database

_POSTGRES_URL = os.getenv("KB_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not _POSTGRES_URL,
    reason="KB_TEST_POSTGRES_URL is required for RBAC/ACL row-lock verification",
)


@dataclass(frozen=True)
class _Scenario:
    factory: async_sessionmaker[AsyncSession]
    actor_access: AccessContext
    revoker_access: AccessContext
    target_user_id: UUID
    delegated_role_id: UUID
    actor_role_id: UUID
    knowledge_base_id: UUID


@dataclass(frozen=True)
class _RoleDeleteScenario:
    factory: async_sessionmaker[AsyncSession]
    actor_access: AccessContext
    target_user_id: UUID
    role_id: UUID
    role_name: str
    policy_etag: str
    knowledge_base_id: UUID


def _request(path: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "PUT",
            "path": path,
            "headers": [],
            "query_string": b"",
            "server": ("acceptance.local", 443),
            "client": ("127.0.0.1", 1),
            "scheme": "https",
        }
    )


async def _prepare_scenario() -> _Scenario:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=6, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    unique = uuid4().hex[:12]
    async with factory() as session:
        role_assign = await session.scalar(
            select(Permission).where(Permission.code == "role:assign")
        )
        if role_assign is None:
            role_assign = Permission(
                code="role:assign",
                name="Assign roles",
                description="PostgreSQL acceptance fixture",
            )
            session.add(role_assign)
        revoker = User(
            email=f"acl-revoker-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        actor = User(email=f"acl-actor-{unique}@example.com", password_hash="unused")
        target = User(email=f"acl-target-{unique}@example.com", password_hash="unused")
        actor_role = Role(code=f"acl_actor_{unique}", name="ACL actor", priority=100)
        delegated_role = Role(
            code=f"acl_delegated_{unique}", name="ACL delegated", priority=10
        )
        session.add_all([revoker, actor, target, actor_role, delegated_role])
        await session.flush()
        knowledge_base = KnowledgeBase(owner_id=revoker.id, name=f"ACL race {unique}")
        session.add(knowledge_base)
        await session.flush()
        session.add_all(
            [
                RolePermission(role_id=actor_role.id, permission_id=role_assign.id),
                UserRole(user_id=actor.id, role_id=actor_role.id, assigned_by=revoker.id),
                KnowledgeBaseRoleGrant(
                    knowledge_base_id=knowledge_base.id,
                    role_id=actor_role.id,
                    access_level=KnowledgeBaseAccessLevel.MANAGER,
                    granted_by=revoker.id,
                ),
                KnowledgeBaseRoleGrant(
                    knowledge_base_id=knowledge_base.id,
                    role_id=delegated_role.id,
                    access_level=KnowledgeBaseAccessLevel.READER,
                    granted_by=revoker.id,
                ),
            ]
        )
        await session.commit()
        actor_access = await AccessService().resolve(session, actor)
        revoker_access = AccessContext(
            user=revoker,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset(),
            max_role_priority=10_000,
        )
        return _Scenario(
            factory=factory,
            actor_access=actor_access,
            revoker_access=revoker_access,
            target_user_id=target.id,
            delegated_role_id=delegated_role.id,
            actor_role_id=actor_role.id,
            knowledge_base_id=knowledge_base.id,
        )


async def _prepare_role_delete_scenario() -> _RoleDeleteScenario:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=6, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    unique = uuid4().hex[:12]
    async with factory() as session:
        actor = User(
            email=f"role-delete-actor-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        target_user = User(
            email=f"role-delete-target-{unique}@example.com",
            password_hash="unused",
        )
        role = Role(code=f"role_delete_{unique}", name=f"并发删除角色 {unique}", priority=10)
        session.add_all([actor, target_user, role])
        await session.flush()
        knowledge_base = KnowledgeBase(owner_id=actor.id, name=f"Role delete race {unique}")
        session.add(knowledge_base)
        await session.commit()
        role_read = await role_routes._role_read(session, role)
        actor_access = AccessContext(
            user=actor,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset(),
            max_role_priority=10_000,
        )
        return _RoleDeleteScenario(
            factory=factory,
            actor_access=actor_access,
            target_user_id=target_user.id,
            role_id=role.id,
            role_name=role.name,
            policy_etag=role_read.policy_etag,
            knowledge_base_id=knowledge_base.id,
        )


async def _assign_role(scenario: _Scenario) -> str:
    async with scenario.factory() as session:
        try:
            await user_routes.replace_user_roles(
                user_id=scenario.target_user_id,
                payload=RoleAssignmentUpdate(role_ids=[scenario.delegated_role_id]),
                request=_request(f"/api/v1/users/{scenario.target_user_id}/roles"),
                session=session,
                access=scenario.actor_access,
            )
            return "assigned"
        except ApiError as exc:
            await session.rollback()
            assert exc.code in {"knowledge_base_not_found", "knowledge_base_access_denied"}
            return "denied"


async def _revoke_actor_acl(scenario: _Scenario) -> None:
    async with scenario.factory() as session:
        await knowledge_base_routes.replace_role_grants(
            knowledge_base_id=scenario.knowledge_base_id,
            payload=KnowledgeBaseRoleGrantSet(
                grants=[
                    KnowledgeBaseRoleGrantInput(
                        role_id=scenario.delegated_role_id,
                        access_level=KnowledgeBaseAccessLevel.READER,
                    )
                ]
            ),
            request=_request(
                f"/api/v1/knowledge-bases/{scenario.knowledge_base_id}/role-grants"
            ),
            session=session,
            access=scenario.revoker_access,
        )


async def _persisted_assignment(scenario: _Scenario) -> bool:
    async with scenario.factory() as session:
        return (
            await session.scalar(
                select(UserRole.id).where(
                    UserRole.user_id == scenario.target_user_id,
                    UserRole.role_id == scenario.delegated_role_id,
                )
            )
            is not None
        )


async def _actor_acl_exists(scenario: _Scenario) -> bool:
    async with scenario.factory() as session:
        return (
            await session.scalar(
                select(KnowledgeBaseRoleGrant.id).where(
                    KnowledgeBaseRoleGrant.knowledge_base_id == scenario.knowledge_base_id,
                    KnowledgeBaseRoleGrant.role_id == scenario.actor_role_id,
                )
            )
            is not None
        )


@pytest.mark.asyncio
async def test_postgres_acl_revocation_wins_before_role_delegation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = await _prepare_scenario()
    revocation_holds_acl_lock = asyncio.Event()
    release_revocation = asyncio.Event()
    assignment_attempted_acl_lock = asyncio.Event()

    async def hold_revocation(*_args: object, **_kwargs: object) -> None:
        revocation_holds_acl_lock.set()
        await release_revocation.wait()

    original_require = require_knowledge_base_access

    async def observe_assignment(
        session: AsyncSession,
        access: AccessContext,
        knowledge_base_id: UUID,
        *,
        minimum: KnowledgeBaseAccessLevel = KnowledgeBaseAccessLevel.READER,
        lock: bool = False,
    ) -> KnowledgeBaseAccess:
        assignment_attempted_acl_lock.set()
        return await original_require(
            session,
            access,
            knowledge_base_id,
            minimum=minimum,
            lock=lock,
        )

    monkeypatch.setattr(
        knowledge_base_routes, "deny_if_active_external_llm_egress", hold_revocation
    )
    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", _no_egress)
    monkeypatch.setattr(user_routes, "require_knowledge_base_access", observe_assignment)

    revoke_task = asyncio.create_task(_revoke_actor_acl(scenario))
    await asyncio.wait_for(revocation_holds_acl_lock.wait(), timeout=5)
    assign_task = asyncio.create_task(_assign_role(scenario))
    await asyncio.wait_for(assignment_attempted_acl_lock.wait(), timeout=5)
    release_revocation.set()

    await asyncio.wait_for(revoke_task, timeout=5)
    assert await asyncio.wait_for(assign_task, timeout=5) == "denied"
    assert await _actor_acl_exists(scenario) is False
    assert await _persisted_assignment(scenario) is False


@pytest.mark.asyncio
async def test_postgres_role_delegation_wins_before_acl_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = await _prepare_scenario()
    assignment_holds_acl_lock = asyncio.Event()
    release_assignment = asyncio.Event()
    revocation_attempted_acl_lock = asyncio.Event()

    async def hold_assignment(*_args: object, **_kwargs: object) -> None:
        assignment_holds_acl_lock.set()
        await release_assignment.wait()

    original_require = require_knowledge_base_access

    async def observe_revocation(
        session: AsyncSession,
        access: AccessContext,
        knowledge_base_id: UUID,
        *,
        minimum: KnowledgeBaseAccessLevel = KnowledgeBaseAccessLevel.READER,
        lock: bool = False,
    ) -> KnowledgeBaseAccess:
        revocation_attempted_acl_lock.set()
        return await original_require(
            session,
            access,
            knowledge_base_id,
            minimum=minimum,
            lock=lock,
        )

    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", hold_assignment)
    monkeypatch.setattr(
        knowledge_base_routes, "deny_if_active_external_llm_egress", _no_egress
    )
    monkeypatch.setattr(knowledge_base_routes, "require_knowledge_base_access", observe_revocation)

    assign_task = asyncio.create_task(_assign_role(scenario))
    await asyncio.wait_for(assignment_holds_acl_lock.wait(), timeout=5)
    revoke_task = asyncio.create_task(_revoke_actor_acl(scenario))
    await asyncio.wait_for(revocation_attempted_acl_lock.wait(), timeout=5)
    release_assignment.set()

    assert await asyncio.wait_for(assign_task, timeout=5) == "assigned"
    await asyncio.wait_for(revoke_task, timeout=5)
    assert await _actor_acl_exists(scenario) is False
    assert await _persisted_assignment(scenario) is True


async def _no_egress(*_args: object, **_kwargs: object) -> None:
    return None


async def _delete_role(scenario: _RoleDeleteScenario) -> str:
    async with scenario.factory() as session:
        try:
            await role_routes.delete_role(
                role_id=scenario.role_id,
                request=_request(f"/api/v1/roles/{scenario.role_id}"),
                session=session,
                access=scenario.actor_access,
                expected_name=scenario.role_name,
                expected_policy_etag=scenario.policy_etag,
            )
            return "deleted"
        except ApiError as exc:
            await session.rollback()
            return exc.code


async def _grant_deleted_role(scenario: _RoleDeleteScenario) -> str:
    async with scenario.factory() as session:
        try:
            await knowledge_base_routes.replace_role_grants(
                knowledge_base_id=scenario.knowledge_base_id,
                payload=KnowledgeBaseRoleGrantSet(
                    grants=[
                        KnowledgeBaseRoleGrantInput(
                            role_id=scenario.role_id,
                            access_level=KnowledgeBaseAccessLevel.READER,
                        )
                    ]
                ),
                request=_request(
                    f"/api/v1/knowledge-bases/{scenario.knowledge_base_id}/role-grants"
                ),
                session=session,
                access=scenario.actor_access,
            )
            return "granted"
        except ApiError as exc:
            await session.rollback()
            return exc.code


async def _assign_deleted_role(scenario: _RoleDeleteScenario) -> str:
    async with scenario.factory() as session:
        try:
            await user_routes.replace_user_roles(
                user_id=scenario.target_user_id,
                payload=RoleAssignmentUpdate(role_ids=[scenario.role_id]),
                request=_request(f"/api/v1/users/{scenario.target_user_id}/roles"),
                session=session,
                access=scenario.actor_access,
            )
            return "assigned"
        except ApiError as exc:
            await session.rollback()
            return exc.code


@pytest.mark.asyncio
@pytest.mark.parametrize("writer", ["grant", "assignment"])
async def test_postgres_role_delete_wins_without_fk_500_or_silent_cascade(
    monkeypatch: pytest.MonkeyPatch,
    writer: str,
) -> None:
    scenario = await _prepare_role_delete_scenario()
    delete_holds_role_lock = asyncio.Event()
    release_delete = asyncio.Event()
    original_role_read = role_routes._role_read

    async def hold_delete(session: AsyncSession, role: Role):
        result = await original_role_read(session, role)
        if role.id == scenario.role_id:
            delete_holds_role_lock.set()
            await release_delete.wait()
        return result

    monkeypatch.setattr(role_routes, "_role_read", hold_delete)
    monkeypatch.setattr(role_routes, "deny_if_active_external_llm_egress", _no_egress)
    monkeypatch.setattr(knowledge_base_routes, "deny_if_active_external_llm_egress", _no_egress)
    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", _no_egress)

    delete_task = asyncio.create_task(_delete_role(scenario))
    await asyncio.wait_for(delete_holds_role_lock.wait(), timeout=5)
    writer_task = asyncio.create_task(
        _grant_deleted_role(scenario) if writer == "grant" else _assign_deleted_role(scenario)
    )
    await asyncio.sleep(0)
    release_delete.set()

    assert await asyncio.wait_for(delete_task, timeout=5) == "deleted"
    assert await asyncio.wait_for(writer_task, timeout=5) == "unknown_role"
    async with scenario.factory() as session:
        assert await session.get(Role, scenario.role_id) is None
        assert (
            await session.scalar(
                select(UserRole.id).where(
                    UserRole.user_id == scenario.target_user_id,
                    UserRole.role_id == scenario.role_id,
                )
            )
            is None
        )
        assert (
            await session.scalar(
                select(KnowledgeBaseRoleGrant.id).where(
                    KnowledgeBaseRoleGrant.knowledge_base_id == scenario.knowledge_base_id,
                    KnowledgeBaseRoleGrant.role_id == scenario.role_id,
                )
            )
            is None
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("writer", ["grant", "assignment"])
async def test_postgres_role_reference_wins_and_delete_reports_role_in_use(
    monkeypatch: pytest.MonkeyPatch,
    writer: str,
) -> None:
    scenario = await _prepare_role_delete_scenario()
    writer_holds_role_lock = asyncio.Event()
    release_writer = asyncio.Event()

    async def hold_writer(*_args: object, **_kwargs: object) -> None:
        writer_holds_role_lock.set()
        await release_writer.wait()

    monkeypatch.setattr(role_routes, "deny_if_active_external_llm_egress", _no_egress)
    if writer == "grant":
        monkeypatch.setattr(
            knowledge_base_routes,
            "deny_if_active_external_llm_egress",
            hold_writer,
        )
        writer_task = asyncio.create_task(_grant_deleted_role(scenario))
    else:
        monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", hold_writer)
        writer_task = asyncio.create_task(_assign_deleted_role(scenario))

    await asyncio.wait_for(writer_holds_role_lock.wait(), timeout=5)
    delete_task = asyncio.create_task(_delete_role(scenario))
    await asyncio.sleep(0)
    release_writer.set()

    assert await asyncio.wait_for(writer_task, timeout=5) == (
        "granted" if writer == "grant" else "assigned"
    )
    assert await asyncio.wait_for(delete_task, timeout=5) == "role_in_use"
    async with scenario.factory() as session:
        assert await session.get(Role, scenario.role_id) is not None


@pytest.mark.asyncio
async def test_postgres_rbac_advisory_lock_prevents_cross_role_deadlock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=6, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    unique = uuid4().hex[:12]

    async with factory() as session:
        actor_a = User(
            email=f"rbac-deadlock-a-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        actor_b = User(
            email=f"rbac-deadlock-b-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        target = User(
            email=f"rbac-deadlock-target-{unique}@example.com",
            password_hash="unused",
        )
        role_a = Role(code=f"rbac_deadlock_a_{unique}", name="交叉锁角色 A", priority=20)
        role_b = Role(code=f"rbac_deadlock_b_{unique}", name="交叉锁角色 B", priority=10)
        session.add_all([actor_a, actor_b, target, role_a, role_b])
        await session.flush()
        session.add_all(
            [
                UserRole(user_id=actor_a.id, role_id=role_a.id),
                UserRole(user_id=actor_b.id, role_id=role_b.id),
            ]
        )
        await session.commit()
        role_b_read = await role_routes._role_read(session, role_b)
        access_a = AccessContext(
            user=actor_a,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset({role_a.id}),
            max_role_priority=role_a.priority,
        )
        access_b = AccessContext(
            user=actor_b,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset({role_b.id}),
            max_role_priority=role_b.priority,
        )

    delete_scenario = _RoleDeleteScenario(
        factory=factory,
        actor_access=access_a,
        target_user_id=target.id,
        role_id=role_b.id,
        role_name=role_b.name,
        policy_etag=role_b_read.policy_etag,
        knowledge_base_id=uuid4(),
    )
    assignment_scenario = _RoleDeleteScenario(
        factory=factory,
        actor_access=access_b,
        target_user_id=target.id,
        role_id=role_a.id,
        role_name=role_a.name,
        policy_etag="0" * 64,
        knowledge_base_id=uuid4(),
    )

    actor_a_holds_global_lock = asyncio.Event()
    release_actor_a = asyncio.Event()
    original_refresh = role_routes.lock_and_refresh_actor_access

    async def hold_after_actor_role_lock(
        session: AsyncSession,
        access: AccessContext,
        required_permissions: set[str],
    ) -> AccessContext:
        current = await original_refresh(session, access, required_permissions)
        if access.user.id == actor_a.id:
            actor_a_holds_global_lock.set()
            await release_actor_a.wait()
        return current

    monkeypatch.setattr(
        role_routes,
        "lock_and_refresh_actor_access",
        hold_after_actor_role_lock,
    )
    monkeypatch.setattr(role_routes, "deny_if_active_external_llm_egress", _no_egress)
    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", _no_egress)

    delete_task = asyncio.create_task(_delete_role(delete_scenario))
    await asyncio.wait_for(actor_a_holds_global_lock.wait(), timeout=5)
    assignment_task = asyncio.create_task(_assign_deleted_role(assignment_scenario))
    await asyncio.sleep(0.1)
    assert assignment_task.done() is False
    release_actor_a.set()

    assert await asyncio.wait_for(delete_task, timeout=5) == "role_in_use"
    assert await asyncio.wait_for(assignment_task, timeout=5) == "assigned"
