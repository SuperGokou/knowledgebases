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
