from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import app.api.v1.routes.knowledge_bases as knowledge_base_routes
import app.api.v1.routes.roles as role_routes
import app.api.v1.routes.users as user_routes
from app.api.errors import ApiError
from app.core.security import PasswordService
from app.db.models import (
    AuditLog,
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    LimitDefinition,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
    UserStatus,
)
from app.schemas.knowledge_bases import KnowledgeBaseRoleGrantInput, KnowledgeBaseRoleGrantSet
from app.schemas.roles import (
    LimitSet,
    PermissionSet,
    RoleCreate,
    RolePolicySet,
    RoleUpdate,
)
from app.schemas.users import RoleAssignmentUpdate, UserCreate, UserUpdate
from app.services.access import AccessContext, AccessService
from app.services.knowledge_bases import KnowledgeBaseAccess, require_knowledge_base_access
from app.services.rbac_mutation import acquire_rbac_mutation_lock
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
class _GrantMutationScenario:
    engine: AsyncEngine
    factory: async_sessionmaker[AsyncSession]
    actor_access: AccessContext
    grant_manager_access: AccessContext
    target_user_id: UUID
    delegated_role_id: UUID
    knowledge_base_id: UUID
    created_user_email: str
    next_access_level: KnowledgeBaseAccessLevel


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
        knowledge_grant = await session.scalar(
            select(Permission).where(Permission.code == "knowledge:grant")
        )
        if knowledge_grant is None:
            knowledge_grant = Permission(
                code="knowledge:grant",
                name="Manage knowledge grants",
                description="PostgreSQL acceptance fixture",
            )
            session.add(knowledge_grant)
        revoker = User(
            email=f"acl-revoker-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        actor = User(email=f"acl-actor-{unique}@example.com", password_hash="unused")
        target = User(email=f"acl-target-{unique}@example.com", password_hash="unused")
        actor_role = Role(code=f"acl_actor_{unique}", name="ACL actor", priority=100)
        delegated_role = Role(code=f"acl_delegated_{unique}", name="ACL delegated", priority=10)
        session.add_all([revoker, actor, target, actor_role, delegated_role])
        await session.flush()
        knowledge_base = KnowledgeBase(owner_id=revoker.id, name=f"ACL race {unique}")
        session.add(knowledge_base)
        await session.flush()
        session.add_all(
            [
                RolePermission(role_id=actor_role.id, permission_id=role_assign.id),
                RolePermission(role_id=actor_role.id, permission_id=knowledge_grant.id),
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


async def _prepare_grant_mutation_scenario(
    grant_change: str,
) -> _GrantMutationScenario:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=6, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    unique = uuid4().hex[:12]
    async with factory() as session:
        permissions = list(
            (
                await session.scalars(
                    select(Permission).where(Permission.code.in_({"role:assign", "user:manage"}))
                )
            ).all()
        )
        permissions_by_code = {item.code: item for item in permissions}
        for code, name in {
            "role:assign": "Assign roles",
            "user:manage": "Manage users",
        }.items():
            if code not in permissions_by_code:
                permission = Permission(
                    code=code,
                    name=name,
                    description="PostgreSQL role-grant race fixture",
                )
                session.add(permission)
                permissions_by_code[code] = permission
        permissions = list(permissions_by_code.values())
        grant_manager = User(
            email=f"grant-manager-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        actor = User(email=f"grant-actor-{unique}@example.com", password_hash="unused")
        target = User(email=f"grant-target-{unique}@example.com", password_hash="unused")
        actor_role = Role(code=f"grant_actor_{unique}", name="Grant actor", priority=100)
        delegated_role = Role(code=f"grant_delegated_{unique}", name="Grant delegated", priority=10)
        session.add_all([grant_manager, actor, target, actor_role, delegated_role])
        await session.flush()
        knowledge_base = KnowledgeBase(
            owner_id=grant_manager.id,
            name=f"Selected role grant race {unique}",
        )
        session.add(knowledge_base)
        await session.flush()
        session.add_all(
            [
                *[
                    RolePermission(role_id=actor_role.id, permission_id=item.id)
                    for item in permissions
                ],
                UserRole(user_id=actor.id, role_id=actor_role.id, assigned_by=grant_manager.id),
            ]
        )
        if grant_change == "upgrade":
            session.add_all(
                [
                    KnowledgeBaseRoleGrant(
                        knowledge_base_id=knowledge_base.id,
                        role_id=actor_role.id,
                        access_level=KnowledgeBaseAccessLevel.READER,
                        granted_by=grant_manager.id,
                    ),
                    KnowledgeBaseRoleGrant(
                        knowledge_base_id=knowledge_base.id,
                        role_id=delegated_role.id,
                        access_level=KnowledgeBaseAccessLevel.READER,
                        granted_by=grant_manager.id,
                    ),
                ]
            )
            next_access_level = KnowledgeBaseAccessLevel.MANAGER
        else:
            assert grant_change == "add"
            next_access_level = KnowledgeBaseAccessLevel.READER
        await session.commit()
        actor_access = await AccessService().resolve(session, actor)
        grant_manager_access = AccessContext(
            user=grant_manager,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset(),
            max_role_priority=10_000,
        )
        return _GrantMutationScenario(
            engine=engine,
            factory=factory,
            actor_access=actor_access,
            grant_manager_access=grant_manager_access,
            target_user_id=target.id,
            delegated_role_id=delegated_role.id,
            knowledge_base_id=knowledge_base.id,
            created_user_email=f"grant-created-{unique}@example.com",
            next_access_level=next_access_level,
        )


async def _assign_role(scenario: _Scenario) -> str:
    async with scenario.factory() as session:
        try:
            await user_routes.replace_user_roles(
                user_id=scenario.target_user_id,
                payload=RoleAssignmentUpdate(
                    expected_version=1,
                    role_ids=[scenario.delegated_role_id],
                ),
                request=_request(f"/api/v1/users/{scenario.target_user_id}/roles"),
                session=session,
                access=scenario.actor_access,
            )
            return "assigned"
        except ApiError as exc:
            await session.rollback()
            assert exc.code in {"knowledge_base_not_found", "knowledge_base_access_denied"}
            return "denied"


async def _assign_selected_role(
    scenario: _GrantMutationScenario,
    operation: str,
) -> str:
    async with scenario.factory() as session:
        try:
            if operation == "create":
                await user_routes.create_user(
                    payload=UserCreate(
                        email=scenario.created_user_email,
                        password="Controlled-password-123!",
                        role_ids=[scenario.delegated_role_id],
                    ),
                    request=_request("/api/v1/users"),
                    session=session,
                    access=scenario.actor_access,
                    passwords=PasswordService(),
                )
            else:
                assert operation == "replace"
                await user_routes.replace_user_roles(
                    user_id=scenario.target_user_id,
                    payload=RoleAssignmentUpdate(
                        expected_version=1,
                        role_ids=[scenario.delegated_role_id],
                    ),
                    request=_request(f"/api/v1/users/{scenario.target_user_id}/roles"),
                    session=session,
                    access=scenario.actor_access,
                )
            return "assigned"
        except ApiError as exc:
            await session.rollback()
            assert exc.code in {"knowledge_base_not_found", "knowledge_base_access_denied"}
            return "denied"


async def _grant_selected_role(scenario: _GrantMutationScenario) -> None:
    async with scenario.factory() as session:
        await knowledge_base_routes.replace_role_grants(
            knowledge_base_id=scenario.knowledge_base_id,
            payload=KnowledgeBaseRoleGrantSet(
                expected_version=1,
                grants=[
                    KnowledgeBaseRoleGrantInput(
                        role_id=scenario.delegated_role_id,
                        access_level=scenario.next_access_level,
                    )
                ],
            ),
            request=_request(f"/api/v1/knowledge-bases/{scenario.knowledge_base_id}/role-grants"),
            session=session,
            access=scenario.grant_manager_access,
        )


async def _selected_assignment_persisted(
    scenario: _GrantMutationScenario,
    operation: str,
) -> bool:
    async with scenario.factory() as session:
        if operation == "create":
            user_id = await session.scalar(
                select(User.id).where(User.email == scenario.created_user_email)
            )
            if user_id is None:
                return False
        else:
            user_id = scenario.target_user_id
        return (
            await session.scalar(
                select(UserRole.id).where(
                    UserRole.user_id == user_id,
                    UserRole.role_id == scenario.delegated_role_id,
                )
            )
            is not None
        )


async def _revoke_actor_acl(scenario: _Scenario) -> None:
    async with scenario.factory() as session:
        await knowledge_base_routes.replace_role_grants(
            knowledge_base_id=scenario.knowledge_base_id,
            payload=KnowledgeBaseRoleGrantSet(
                expected_version=1,
                grants=[
                    KnowledgeBaseRoleGrantInput(
                        role_id=scenario.delegated_role_id,
                        access_level=KnowledgeBaseAccessLevel.READER,
                    )
                ],
            ),
            request=_request(f"/api/v1/knowledge-bases/{scenario.knowledge_base_id}/role-grants"),
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


async def _revoke_actor_roles(scenario: _Scenario) -> None:
    async with scenario.factory() as session:
        await user_routes.replace_user_roles(
            user_id=scenario.actor_access.user.id,
            payload=RoleAssignmentUpdate(expected_version=1, role_ids=[]),
            request=_request(f"/api/v1/users/{scenario.actor_access.user.id}/roles"),
            session=session,
            access=scenario.revoker_access,
        )


async def _upgrade_delegated_grant_as_actor(scenario: _Scenario) -> str:
    async with scenario.factory() as session:
        try:
            await knowledge_base_routes.replace_role_grants(
                knowledge_base_id=scenario.knowledge_base_id,
                payload=KnowledgeBaseRoleGrantSet(
                    expected_version=1,
                    grants=[
                        KnowledgeBaseRoleGrantInput(
                            role_id=scenario.actor_role_id,
                            access_level=KnowledgeBaseAccessLevel.MANAGER,
                        ),
                        KnowledgeBaseRoleGrantInput(
                            role_id=scenario.delegated_role_id,
                            access_level=KnowledgeBaseAccessLevel.MANAGER,
                        ),
                    ],
                ),
                request=_request(
                    f"/api/v1/knowledge-bases/{scenario.knowledge_base_id}/role-grants"
                ),
                session=session,
                access=scenario.actor_access,
            )
            return "updated"
        except ApiError as exc:
            await session.rollback()
            assert exc.code in {"permission_denied", "knowledge_base_not_found"}
            return "denied"


async def _delegated_grant_level(scenario: _Scenario) -> KnowledgeBaseAccessLevel:
    async with scenario.factory() as session:
        level = await session.scalar(
            select(KnowledgeBaseRoleGrant.access_level).where(
                KnowledgeBaseRoleGrant.knowledge_base_id == scenario.knowledge_base_id,
                KnowledgeBaseRoleGrant.role_id == scenario.delegated_role_id,
            )
        )
        assert level is not None
        return level


@pytest.mark.asyncio
async def test_postgres_actor_role_revocation_wins_before_grant_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = await _prepare_scenario()
    revocation_holds_domain = asyncio.Event()
    release_revocation = asyncio.Event()
    mutation_attempted_domain = asyncio.Event()

    async def hold_revocation(*_args: object, **_kwargs: object) -> None:
        revocation_holds_domain.set()
        await release_revocation.wait()

    async def observe_mutation_domain(session: AsyncSession) -> None:
        mutation_attempted_domain.set()
        await acquire_rbac_mutation_lock(session)

    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", hold_revocation)
    monkeypatch.setattr(
        knowledge_base_routes,
        "deny_if_active_external_llm_egress",
        _no_egress,
    )
    monkeypatch.setattr(
        knowledge_base_routes,
        "acquire_rbac_mutation_lock",
        observe_mutation_domain,
    )

    revoke_task = asyncio.create_task(_revoke_actor_roles(scenario))
    await asyncio.wait_for(revocation_holds_domain.wait(), timeout=5)
    mutation_task = asyncio.create_task(_upgrade_delegated_grant_as_actor(scenario))
    await asyncio.wait_for(mutation_attempted_domain.wait(), timeout=5)
    release_revocation.set()

    await asyncio.wait_for(revoke_task, timeout=5)
    assert await asyncio.wait_for(mutation_task, timeout=5) == "denied"
    assert await _delegated_grant_level(scenario) is KnowledgeBaseAccessLevel.READER


@pytest.mark.asyncio
async def test_postgres_grant_mutation_wins_before_actor_role_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = await _prepare_scenario()
    mutation_holds_domain = asyncio.Event()
    release_mutation = asyncio.Event()
    revocation_attempted_domain = asyncio.Event()

    async def hold_mutation(*_args: object, **_kwargs: object) -> None:
        mutation_holds_domain.set()
        await release_mutation.wait()

    async def observe_revocation_domain(session: AsyncSession) -> None:
        revocation_attempted_domain.set()
        await acquire_rbac_mutation_lock(session)

    monkeypatch.setattr(
        knowledge_base_routes,
        "deny_if_active_external_llm_egress",
        hold_mutation,
    )
    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", _no_egress)
    monkeypatch.setattr(
        user_routes,
        "acquire_rbac_mutation_lock",
        observe_revocation_domain,
    )

    mutation_task = asyncio.create_task(_upgrade_delegated_grant_as_actor(scenario))
    await asyncio.wait_for(mutation_holds_domain.wait(), timeout=5)
    revoke_task = asyncio.create_task(_revoke_actor_roles(scenario))
    await asyncio.wait_for(revocation_attempted_domain.wait(), timeout=5)
    release_mutation.set()

    assert await asyncio.wait_for(mutation_task, timeout=5) == "updated"
    await asyncio.wait_for(revoke_task, timeout=5)
    assert await _delegated_grant_level(scenario) is KnowledgeBaseAccessLevel.MANAGER


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
    try:
        await asyncio.wait_for(assignment_attempted_acl_lock.wait(), timeout=0.5)
        assignment_bypassed_role_lock = True
    except TimeoutError:
        assignment_bypassed_role_lock = False
    release_revocation.set()

    await asyncio.wait_for(revoke_task, timeout=5)
    assert await asyncio.wait_for(assign_task, timeout=5) == "denied"
    assert assignment_bypassed_role_lock is False
    await asyncio.wait_for(assignment_attempted_acl_lock.wait(), timeout=5)
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
        if lock:
            revocation_attempted_acl_lock.set()
        return await original_require(
            session,
            access,
            knowledge_base_id,
            minimum=minimum,
            lock=lock,
        )

    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", hold_assignment)
    monkeypatch.setattr(knowledge_base_routes, "deny_if_active_external_llm_egress", _no_egress)
    monkeypatch.setattr(knowledge_base_routes, "require_knowledge_base_access", observe_revocation)

    assign_task = asyncio.create_task(_assign_role(scenario))
    await asyncio.wait_for(assignment_holds_acl_lock.wait(), timeout=5)
    revoke_task = asyncio.create_task(_revoke_actor_acl(scenario))
    try:
        await asyncio.wait_for(revocation_attempted_acl_lock.wait(), timeout=0.5)
        revocation_bypassed_role_lock = True
    except TimeoutError:
        revocation_bypassed_role_lock = False
    release_assignment.set()

    assert await asyncio.wait_for(assign_task, timeout=5) == "assigned"
    await asyncio.wait_for(revoke_task, timeout=5)
    assert revocation_bypassed_role_lock is False
    await asyncio.wait_for(revocation_attempted_acl_lock.wait(), timeout=5)
    assert await _actor_acl_exists(scenario) is False
    assert await _persisted_assignment(scenario) is True


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["create", "replace"])
@pytest.mark.parametrize("grant_change", ["add", "upgrade"])
async def test_postgres_role_assignment_serializes_before_selected_role_grant_mutation(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    grant_change: str,
) -> None:
    scenario = await _prepare_grant_mutation_scenario(grant_change)
    assignment_checked_grants = asyncio.Event()
    release_assignment = asyncio.Event()
    mutation_reached_write_boundary = asyncio.Event()
    original_ensure = user_routes._ensure_kb_grants_delegable

    async def hold_assignment_after_grant_snapshot(
        session: AsyncSession,
        access: AccessContext,
        grant_rows: list[tuple[UUID, KnowledgeBaseAccessLevel]],
    ) -> None:
        assignment_checked_grants.set()
        await release_assignment.wait()
        await original_ensure(session, access, grant_rows)

    async def observe_mutation_boundary(*_args: object, **_kwargs: object) -> None:
        mutation_reached_write_boundary.set()

    monkeypatch.setattr(
        user_routes,
        "_ensure_kb_grants_delegable",
        hold_assignment_after_grant_snapshot,
    )
    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", _no_egress)
    monkeypatch.setattr(
        knowledge_base_routes,
        "deny_if_active_external_llm_egress",
        observe_mutation_boundary,
    )

    assign_task = asyncio.create_task(_assign_selected_role(scenario, operation))
    mutate_task: asyncio.Task[None] | None = None
    try:
        await asyncio.wait_for(assignment_checked_grants.wait(), timeout=5)
        mutate_task = asyncio.create_task(_grant_selected_role(scenario))
        try:
            await asyncio.wait_for(mutation_reached_write_boundary.wait(), timeout=0.5)
            mutation_bypassed_role_lock = True
        except TimeoutError:
            mutation_bypassed_role_lock = False
        release_assignment.set()
        assert await asyncio.wait_for(assign_task, timeout=5) == "assigned"
        await asyncio.wait_for(mutation_reached_write_boundary.wait(), timeout=5)
        await asyncio.wait_for(mutate_task, timeout=5)
        assignment_persisted = await _selected_assignment_persisted(scenario, operation)
    finally:
        release_assignment.set()
        if not assign_task.done():
            assign_task.cancel()
            await asyncio.gather(assign_task, return_exceptions=True)
        if mutate_task is not None and not mutate_task.done():
            mutate_task.cancel()
            await asyncio.gather(mutate_task, return_exceptions=True)
        await scenario.engine.dispose()

    assert mutation_bypassed_role_lock is False
    assert assignment_persisted is True


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["create", "replace"])
@pytest.mark.parametrize("grant_change", ["add", "upgrade"])
async def test_postgres_selected_role_grant_mutation_serializes_before_role_assignment(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    grant_change: str,
) -> None:
    scenario = await _prepare_grant_mutation_scenario(grant_change)
    mutation_holds_role_domain = asyncio.Event()
    release_mutation = asyncio.Event()
    assignment_checked_grants = asyncio.Event()
    original_ensure = user_routes._ensure_kb_grants_delegable

    async def hold_mutation_before_write(*_args: object, **_kwargs: object) -> None:
        mutation_holds_role_domain.set()
        await release_mutation.wait()

    async def observe_assignment_grant_snapshot(
        session: AsyncSession,
        access: AccessContext,
        grant_rows: list[tuple[UUID, KnowledgeBaseAccessLevel]],
    ) -> None:
        assignment_checked_grants.set()
        await original_ensure(session, access, grant_rows)

    monkeypatch.setattr(
        knowledge_base_routes,
        "deny_if_active_external_llm_egress",
        hold_mutation_before_write,
    )
    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", _no_egress)
    monkeypatch.setattr(
        user_routes,
        "_ensure_kb_grants_delegable",
        observe_assignment_grant_snapshot,
    )

    mutate_task = asyncio.create_task(_grant_selected_role(scenario))
    assign_task: asyncio.Task[str] | None = None
    try:
        await asyncio.wait_for(mutation_holds_role_domain.wait(), timeout=5)
        assign_task = asyncio.create_task(_assign_selected_role(scenario, operation))
        try:
            await asyncio.wait_for(assignment_checked_grants.wait(), timeout=0.5)
            assignment_bypassed_role_lock = True
        except TimeoutError:
            assignment_bypassed_role_lock = False
        release_mutation.set()
        await asyncio.wait_for(mutate_task, timeout=5)
        assert await asyncio.wait_for(assign_task, timeout=5) == "denied"
        assignment_persisted = await _selected_assignment_persisted(scenario, operation)
    finally:
        release_mutation.set()
        if not mutate_task.done():
            mutate_task.cancel()
            await asyncio.gather(mutate_task, return_exceptions=True)
        if assign_task is not None and not assign_task.done():
            assign_task.cancel()
            await asyncio.gather(assign_task, return_exceptions=True)
        await scenario.engine.dispose()

    assert assignment_bypassed_role_lock is False
    assert assignment_persisted is False


@pytest.mark.asyncio
async def test_postgres_same_user_role_version_allows_exactly_one_winner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=6, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    unique = uuid4().hex[:12]

    async with factory() as session:
        actor = User(
            email=f"role-cas-actor-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        target = User(
            email=f"role-cas-target-{unique}@example.com",
            password_hash="unused",
        )
        first_role = Role(code=f"role_cas_first_{unique}", name="CAS first", priority=-1)
        second_role = Role(code=f"role_cas_second_{unique}", name="CAS second", priority=-1)
        session.add_all([actor, target, first_role, second_role])
        await session.commit()
        actor_access = AccessContext(
            user=actor,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset(),
            max_role_priority=10_000,
        )
        target_id = target.id
        candidate_role_ids = (first_role.id, second_role.id)

    start = asyncio.Event()

    async def replace_with(role_id: UUID) -> tuple[str, dict[str, object] | None]:
        async with factory() as session:
            await start.wait()
            try:
                await user_routes.replace_user_roles(
                    user_id=target_id,
                    payload=RoleAssignmentUpdate(
                        expected_version=1,
                        role_ids=[role_id],
                    ),
                    request=_request(f"/api/v1/users/{target_id}/roles"),
                    session=session,
                    access=actor_access,
                )
                return "updated", None
            except ApiError as exc:
                await session.rollback()
                return exc.code, exc.details

    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", _no_egress)
    tasks = [asyncio.create_task(replace_with(role_id)) for role_id in candidate_role_ids]
    try:
        start.set()
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
        assert [result[0] for result in results].count("updated") == 1
        assert [result[0] for result in results].count("stale_role_assignment") == 1
        stale_result = next(result for result in results if result[0] != "updated")
        assert stale_result[1] == {"current_version": 2}

        async with factory() as session:
            persisted_user = await session.get(User, target_id)
            assert persisted_user is not None
            persisted_roles = set(
                (
                    await session.scalars(
                        select(UserRole.role_id).where(UserRole.user_id == target_id)
                    )
                ).all()
            )
            audits = list(
                (
                    await session.scalars(
                        select(AuditLog).where(
                            AuditLog.action == "user.roles.replaced",
                            AuditLog.resource_id == str(target_id),
                        )
                    )
                ).all()
            )
        assert persisted_user.role_assignment_version == 2
        assert persisted_user.token_version == 1
        assert len(persisted_roles) == 1
        assert persisted_roles <= set(candidate_role_ids)
        assert [item.details for item in audits] == [{"from_version": 1, "to_version": 2}]
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_same_knowledge_grant_version_allows_exactly_one_winner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=6, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    unique = uuid4().hex[:12]

    async with factory() as session:
        actor = User(
            email=f"grant-cas-actor-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        first_role = Role(code=f"grant_cas_first_{unique}", name="CAS first")
        second_role = Role(code=f"grant_cas_second_{unique}", name="CAS second")
        session.add_all([actor, first_role, second_role])
        await session.flush()
        knowledge_base = KnowledgeBase(
            owner_id=actor.id,
            name=f"Grant CAS {unique}",
        )
        session.add(knowledge_base)
        await session.commit()
        actor_access = AccessContext(
            user=actor,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset(),
            max_role_priority=10_000,
        )
        knowledge_base_id = knowledge_base.id
        candidate_role_ids = (first_role.id, second_role.id)

    arrived = 0
    arrival_lock = asyncio.Lock()
    preliminary_reads_complete = asyncio.Event()
    original_require = require_knowledge_base_access

    async def synchronize_preliminary_snapshot(
        session: AsyncSession,
        access: AccessContext,
        requested_knowledge_base_id: UUID,
        *,
        minimum: KnowledgeBaseAccessLevel = KnowledgeBaseAccessLevel.READER,
        lock: bool = False,
    ) -> KnowledgeBaseAccess:
        nonlocal arrived
        result = await original_require(
            session,
            access,
            requested_knowledge_base_id,
            minimum=minimum,
            lock=lock,
        )
        if not lock:
            async with arrival_lock:
                arrived += 1
                if arrived == 2:
                    preliminary_reads_complete.set()
            await preliminary_reads_complete.wait()
        return result

    async def replace_with(role_id: UUID) -> tuple[str, int | None, dict[str, object] | None]:
        async with factory() as session:
            try:
                await knowledge_base_routes.replace_role_grants(
                    knowledge_base_id=knowledge_base_id,
                    payload=KnowledgeBaseRoleGrantSet(
                        expected_version=1,
                        grants=[
                            KnowledgeBaseRoleGrantInput(
                                role_id=role_id,
                                access_level=KnowledgeBaseAccessLevel.READER,
                            )
                        ],
                    ),
                    request=_request(f"/api/v1/knowledge-bases/{knowledge_base_id}/role-grants"),
                    session=session,
                    access=actor_access,
                )
                return "updated", None, None
            except ApiError as exc:
                await session.rollback()
                return exc.code, exc.status_code, exc.details

    monkeypatch.setattr(
        knowledge_base_routes,
        "require_knowledge_base_access",
        synchronize_preliminary_snapshot,
    )
    monkeypatch.setattr(
        knowledge_base_routes,
        "deny_if_active_external_llm_egress",
        _no_egress,
    )
    tasks = [asyncio.create_task(replace_with(role_id)) for role_id in candidate_role_ids]
    try:
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
        assert [result[0] for result in results].count("updated") == 1
        assert [result[0] for result in results].count("stale_knowledge_grants") == 1
        stale_result = next(result for result in results if result[0] != "updated")
        assert stale_result[1:] == (409, {"current_version": 2})

        async with factory() as session:
            persisted_knowledge_base = await session.get(
                KnowledgeBase,
                knowledge_base_id,
            )
            assert persisted_knowledge_base is not None
            persisted_roles = set(
                (
                    await session.scalars(
                        select(KnowledgeBaseRoleGrant.role_id).where(
                            KnowledgeBaseRoleGrant.knowledge_base_id == knowledge_base_id
                        )
                    )
                ).all()
            )
            audits = list(
                (
                    await session.scalars(
                        select(AuditLog).where(
                            AuditLog.action == "knowledge_base.role_grants_replaced",
                            AuditLog.resource_id == str(knowledge_base_id),
                        )
                    )
                ).all()
            )
        assert persisted_knowledge_base.role_grant_version == 2
        assert len(persisted_roles) == 1
        assert persisted_roles <= set(candidate_role_ids)
        assert len(audits) == 1
        assert audits[0].details["from_version"] == 1
        assert audits[0].details["to_version"] == 2
        assert set(audits[0].details["role_ids"]) == {str(role_id) for role_id in persisted_roles}
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_cross_actor_role_replacements_do_not_deadlock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=8, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    unique = uuid4().hex[:12]

    async with factory() as session:
        actor_a = User(
            email=f"cross-role-a-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        actor_b = User(
            email=f"cross-role-b-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        target_a = User(email=f"cross-target-a-{unique}@example.com", password_hash="unused")
        target_b = User(email=f"cross-target-b-{unique}@example.com", password_hash="unused")
        role_x = Role(code=f"cross_role_x_{unique}", name="Cross role X", priority=1)
        role_y = Role(code=f"cross_role_y_{unique}", name="Cross role Y", priority=1)
        session.add_all([actor_a, actor_b, target_a, target_b, role_x, role_y])
        await session.flush()
        session.add_all(
            [
                UserRole(user_id=actor_a.id, role_id=role_x.id, assigned_by=actor_a.id),
                UserRole(user_id=actor_b.id, role_id=role_y.id, assigned_by=actor_b.id),
            ]
        )
        await session.commit()
        actor_a_access = AccessContext(
            user=actor_a,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset({role_x.id}),
            max_role_priority=10_000,
        )
        actor_b_access = AccessContext(
            user=actor_b,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset({role_y.id}),
            max_role_priority=10_000,
        )
        target_pairs = (
            (target_a.id, role_y.id, actor_a_access),
            (target_b.id, role_x.id, actor_b_access),
        )

    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", _no_egress)

    async def replace(
        start: asyncio.Event,
        target_id: UUID,
        role_id: UUID,
        actor_access: AccessContext,
        expected_version: int,
    ) -> None:
        async with factory() as session:
            await start.wait()
            await user_routes.replace_user_roles(
                user_id=target_id,
                payload=RoleAssignmentUpdate(
                    expected_version=expected_version,
                    role_ids=[role_id],
                ),
                request=_request(f"/api/v1/users/{target_id}/roles"),
                session=session,
                access=actor_access,
            )

    try:
        # Repetition makes lock-order regressions fail deterministically under
        # PostgreSQL instead of relying on a single lucky scheduler interleave.
        for _ in range(25):
            async with factory() as session:
                versions = {
                    target_id: version
                    for target_id, version in (
                        await session.execute(
                            select(User.id, User.role_assignment_version).where(
                                User.id.in_({target_pairs[0][0], target_pairs[1][0]})
                            )
                        )
                    ).all()
                }
            start = asyncio.Event()
            tasks = [
                asyncio.create_task(
                    replace(start, target_id, role_id, actor_access, versions[target_id])
                )
                for target_id, role_id, actor_access in target_pairs
            ]
            start.set()
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_cross_actor_user_creation_does_not_deadlock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=8, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    unique = uuid4().hex[:12]

    async with factory() as session:
        actor_a = User(
            email=f"cross-create-a-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        actor_b = User(
            email=f"cross-create-b-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        role_x = Role(code=f"cross_create_x_{unique}", name="Cross create X", priority=1)
        role_y = Role(code=f"cross_create_y_{unique}", name="Cross create Y", priority=1)
        session.add_all([actor_a, actor_b, role_x, role_y])
        await session.flush()
        session.add_all(
            [
                UserRole(user_id=actor_a.id, role_id=role_x.id, assigned_by=actor_a.id),
                UserRole(user_id=actor_b.id, role_id=role_y.id, assigned_by=actor_b.id),
            ]
        )
        await session.commit()
        actor_pairs = (
            (
                AccessContext(
                    user=actor_a,
                    permissions=frozenset({"*"}),
                    limits={},
                    role_ids=frozenset({role_x.id}),
                    max_role_priority=10_000,
                ),
                role_y.id,
            ),
            (
                AccessContext(
                    user=actor_b,
                    permissions=frozenset({"*"}),
                    limits={},
                    role_ids=frozenset({role_y.id}),
                    max_role_priority=10_000,
                ),
                role_x.id,
            ),
        )

    async def fast_hash(*_: object, **__: object) -> str:
        return "acceptance-password-hash"

    monkeypatch.setattr(user_routes, "hash_password", fast_hash)

    async def create(
        start: asyncio.Event,
        actor_access: AccessContext,
        role_id: UUID,
        iteration: int,
    ) -> None:
        async with factory() as session:
            await start.wait()
            await user_routes.create_user(
                payload=UserCreate(
                    email=(
                        f"cross-created-{actor_access.user.id.hex[:8]}-"
                        f"{iteration}-{unique}@example.com"
                    ),
                    password="Controlled-password-123!",
                    role_ids=[role_id],
                ),
                request=_request("/api/v1/users"),
                session=session,
                access=actor_access,
                passwords=PasswordService(),
            )

    try:
        for iteration in range(20):
            start = asyncio.Event()
            tasks = [
                asyncio.create_task(create(start, actor_access, role_id, iteration))
                for actor_access, role_id in actor_pairs
            ]
            start.set()
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_cached_actor_is_refreshed_after_status_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The row-lock recheck must not reuse get_current_user's stale identity object."""

    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=4, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    unique = uuid4().hex[:12]

    async with factory() as setup_session:
        permission = await setup_session.scalar(
            select(Permission).where(Permission.code == "role:manage")
        )
        if permission is None:
            permission = Permission(
                code="role:manage",
                name="Manage roles",
                description="PostgreSQL cached-identity revocation fixture",
            )
            setup_session.add(permission)
        revoker = User(
            email=f"cached-revoker-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        actor = User(email=f"cached-actor-{unique}@example.com", password_hash="unused")
        actor_role = Role(code=f"cached_actor_{unique}", name="Cached actor", priority=100)
        setup_session.add_all([revoker, actor, actor_role])
        await setup_session.flush()
        setup_session.add_all(
            [
                RolePermission(role_id=actor_role.id, permission_id=permission.id),
                UserRole(user_id=actor.id, role_id=actor_role.id, assigned_by=revoker.id),
            ]
        )
        await setup_session.commit()
        actor_id = actor.id
        revoker_access = AccessContext(
            user=revoker,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset(),
            max_role_priority=10_000,
        )

    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", _no_egress)

    try:
        async with factory() as request_session:
            # Mirrors get_current_user/get_access_context: the actor is already in
            # this request Session's identity map before the mutation lock is taken.
            cached_actor = await request_session.get(User, actor_id)
            assert cached_actor is not None
            actor_access = await AccessService().resolve(request_session, cached_actor)
            assert actor_access.allows("role:manage")

            async with factory() as revocation_session:
                await user_routes.update_user(
                    user_id=actor_id,
                    payload=UserUpdate(status=UserStatus.DISABLED),
                    request=_request(f"/api/v1/users/{actor_id}"),
                    session=revocation_session,
                    access=revoker_access,
                )

            with pytest.raises(ApiError) as caught:
                await role_routes.create_role(
                    payload=RoleCreate(
                        code=f"cached_revocation_probe_{unique}",
                        name="Cached revocation probe",
                        priority=1,
                    ),
                    request=_request("/api/v1/roles"),
                    session=request_session,
                    access=actor_access,
                )
            assert caught.value.code == "inactive_user"
            await request_session.rollback()
    finally:
        await engine.dispose()


async def _no_egress(*_args: object, **_kwargs: object) -> None:
    return None


@pytest.mark.asyncio
async def test_postgres_same_role_policy_version_allows_exactly_one_winner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=6, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    unique = uuid4().hex[:12]

    async with factory() as session:
        actor = User(
            email=f"policy-cas-actor-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        role = Role(code=f"policy_cas_{unique}", name="Policy CAS", priority=1)
        first_permission = Permission(
            code=f"policy:first:{unique}",
            name="Policy first",
        )
        second_permission = Permission(
            code=f"policy:second:{unique}",
            name="Policy second",
        )
        session.add_all([actor, role, first_permission, second_permission])
        await session.commit()
        actor_access = AccessContext(
            user=actor,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset(),
            max_role_priority=10_000,
        )
        role_id = role.id
        permission_codes = (first_permission.code, second_permission.code)

    start = asyncio.Event()

    async def replace_with(permission_code: str) -> tuple[str, dict[str, object] | None]:
        async with factory() as session:
            await start.wait()
            try:
                await role_routes.replace_policy(
                    role_id=role_id,
                    payload=RolePolicySet(
                        expected_version=1,
                        permission_codes=[permission_code],
                        limits={},
                    ),
                    request=_request(f"/api/v1/roles/{role_id}/policy"),
                    session=session,
                    access=actor_access,
                )
                return "updated", None
            except ApiError as exc:
                await session.rollback()
                return exc.code, exc.details

    monkeypatch.setattr(role_routes, "deny_if_active_external_llm_egress", _no_egress)
    tasks = [asyncio.create_task(replace_with(code)) for code in permission_codes]
    try:
        start.set()
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
        assert [result[0] for result in results].count("updated") == 1
        assert [result[0] for result in results].count("stale_role_policy") == 1
        stale_result = next(result for result in results if result[0] != "updated")
        assert stale_result[1] == {"current_version": 2}

        async with factory() as session:
            persisted_role = await session.get(Role, role_id)
            assert persisted_role is not None
            persisted_permissions = set(
                (
                    await session.scalars(
                        select(Permission.code)
                        .join(RolePermission, RolePermission.permission_id == Permission.id)
                        .where(RolePermission.role_id == role_id)
                    )
                ).all()
            )
            audits = list(
                (
                    await session.scalars(
                        select(AuditLog).where(
                            AuditLog.action == "role.policy.replaced",
                            AuditLog.resource_id == str(role_id),
                        )
                    )
                ).all()
            )
        assert persisted_role.policy_version == 2
        assert len(persisted_permissions) == 1
        assert persisted_permissions <= set(permission_codes)
        assert len(audits) == 1
        assert audits[0].details["from_version"] == 1
        assert audits[0].details["to_version"] == 2
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("policy_mutation", ["permissions", "limits", "policy"])
async def test_postgres_role_metadata_and_policy_mutations_share_one_cas_winner(
    monkeypatch: pytest.MonkeyPatch,
    policy_mutation: str,
) -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=6, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    unique = uuid4().hex[:12]

    async with factory() as session:
        actor = User(
            email=f"metadata-policy-actor-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        role = Role(code=f"metadata_policy_{unique}", name="Metadata policy", priority=1)
        permission = Permission(
            code=f"metadata:policy:{unique}",
            name="Metadata policy permission",
        )
        limit = LimitDefinition(
            key=f"metadata_policy_{unique}",
            name="Metadata policy limit",
            unit="requests",
            window="day",
        )
        session.add_all([actor, role, permission, limit])
        await session.commit()
        actor_access = AccessContext(
            user=actor,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset(),
            max_role_priority=10_000,
        )
        role_id = role.id
        permission_code = permission.code
        limit_key = limit.key

    start = asyncio.Event()

    async def update_metadata() -> tuple[str, dict[str, object] | None]:
        async with factory() as session:
            await start.wait()
            try:
                await role_routes.update_role(
                    role_id=role_id,
                    payload=RoleUpdate(
                        expected_version=1,
                        name="Metadata winner",
                    ),
                    request=_request(f"/api/v1/roles/{role_id}"),
                    session=session,
                    access=actor_access,
                )
                return "updated", None
            except ApiError as exc:
                await session.rollback()
                return exc.code, exc.details

    async def update_policy() -> tuple[str, dict[str, object] | None]:
        async with factory() as session:
            await start.wait()
            try:
                if policy_mutation == "permissions":
                    await role_routes.replace_permissions(
                        role_id=role_id,
                        payload=PermissionSet(
                            expected_version=1,
                            permission_codes=[permission_code],
                        ),
                        request=_request(f"/api/v1/roles/{role_id}/permissions"),
                        session=session,
                        access=actor_access,
                    )
                elif policy_mutation == "limits":
                    await role_routes.replace_limits(
                        role_id=role_id,
                        payload=LimitSet(
                            expected_version=1,
                            limits={limit_key: 10},
                        ),
                        request=_request(f"/api/v1/roles/{role_id}/limits"),
                        session=session,
                        access=actor_access,
                    )
                else:
                    await role_routes.replace_policy(
                        role_id=role_id,
                        payload=RolePolicySet(
                            expected_version=1,
                            permission_codes=[permission_code],
                            limits={limit_key: 10},
                        ),
                        request=_request(f"/api/v1/roles/{role_id}/policy"),
                        session=session,
                        access=actor_access,
                    )
                return "updated", None
            except ApiError as exc:
                await session.rollback()
                return exc.code, exc.details

    monkeypatch.setattr(role_routes, "deny_if_active_external_llm_egress", _no_egress)
    tasks = [asyncio.create_task(update_metadata()), asyncio.create_task(update_policy())]
    try:
        start.set()
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
        assert [result[0] for result in results].count("updated") == 1
        assert [result[0] for result in results].count("stale_role_policy") == 1
        stale = next(result for result in results if result[0] == "stale_role_policy")
        assert stale[1] == {"current_version": 2}

        async with factory() as session:
            persisted_role = await session.get(Role, role_id)
            assert persisted_role is not None
            audits = list(
                (
                    await session.scalars(
                        select(AuditLog).where(
                            AuditLog.resource_id == str(role_id),
                            AuditLog.action.in_(
                                {
                                    "role.updated",
                                    "role.permissions.replaced",
                                    "role.limits.replaced",
                                    "role.policy.replaced",
                                }
                            ),
                        )
                    )
                ).all()
            )
        assert persisted_role.policy_version == 2
        assert len(audits) == 1
        assert audits[0].details["from_version"] == 1
        assert audits[0].details["to_version"] == 2
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_role_delete_and_assignment_never_cascade_or_dangle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=6, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    unique = uuid4().hex[:12]

    async with factory() as session:
        actor = User(
            email=f"delete-race-actor-{unique}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        target = User(
            email=f"delete-race-target-{unique}@example.com",
            password_hash="unused",
        )
        role = Role(code=f"delete_race_{unique}", name="Delete race", priority=-1)
        session.add_all([actor, target, role])
        await session.commit()
        actor_access = AccessContext(
            user=actor,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset(),
            max_role_priority=10_000,
        )
        target_id = target.id
        role_id = role.id

    start = asyncio.Event()

    async def assign() -> str:
        async with factory() as session:
            await start.wait()
            try:
                await user_routes.replace_user_roles(
                    user_id=target_id,
                    payload=RoleAssignmentUpdate(expected_version=1, role_ids=[role_id]),
                    request=_request(f"/api/v1/users/{target_id}/roles"),
                    session=session,
                    access=actor_access,
                )
                return "assigned"
            except ApiError as exc:
                await session.rollback()
                return exc.code

    async def remove() -> str:
        async with factory() as session:
            await start.wait()
            try:
                await role_routes.delete_role(
                    role_id=role_id,
                    request=_request(f"/api/v1/roles/{role_id}"),
                    session=session,
                    access=actor_access,
                    expected_version=1,
                )
                return "deleted"
            except ApiError as exc:
                await session.rollback()
                return exc.code

    monkeypatch.setattr(user_routes, "deny_if_active_external_llm_egress", _no_egress)
    tasks = [asyncio.create_task(assign()), asyncio.create_task(remove())]
    try:
        start.set()
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
        assert set(results) in (
            {"assigned", "role_in_use"},
            {"deleted", "unknown_role"},
        )

        async with factory() as session:
            persisted_role = await session.get(Role, role_id)
            assignment_count = int(
                await session.scalar(
                    select(func.count())
                    .select_from(UserRole)
                    .where(UserRole.user_id == target_id, UserRole.role_id == role_id)
                )
                or 0
            )
        if "assigned" in results:
            assert persisted_role is not None
            assert assignment_count == 1
        else:
            assert persisted_role is None
            assert assignment_count == 0
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await engine.dispose()
