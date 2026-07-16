from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi import Request
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.egress_leases import deny_if_active_external_llm_egress
from app.api.errors import ApiError
from app.core.config import Settings
from app.db.models import (
    ApiKey,
    File,
    FileStatus,
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    LlmBudgetPolicy,
    LlmModelPrice,
    OkfConversionJob,
    OkfConversionStatus,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
    UserStatus,
)
from app.services.access import AccessContext
from app.services.llm_egress_policy import (
    acquire_llm_egress_locks,
    external_llm_egress_allowed,
)
from app.services.llm_usage import (
    LlmBudgetExceeded,
    LlmUsageDimensions,
    LlmUsageDuplicate,
    LlmUsageGovernance,
)
from app.services.okf_conversion import PROMPT_VERSION, _claim_job
from scripts.postgres_acceptance import assert_acceptance_database

_POSTGRES_URL = os.getenv("KB_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not _POSTGRES_URL,
    reason="KB_TEST_POSTGRES_URL is required for row-lock concurrency verification",
)


@dataclass(frozen=True, slots=True)
class _AuthorizationScenario:
    factory: async_sessionmaker[AsyncSession]
    dimensions: LlmUsageDimensions
    role_id: UUID
    permission_id: UUID
    api_key_id: UUID
    knowledge_base_id: UUID


async def _prepare_authorization_scenario() -> _AuthorizationScenario:
    factory, dimensions = await _prepare(tenant_key="egress-authorization", daily_limit=10_000)
    async with factory() as session:
        owner = User(
            id=uuid4(),
            email=f"owner-{uuid4()}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        role = Role(code=f"chat-{uuid4()}", name="Chat reader")
        session.add_all([owner, role])
        await session.flush()
        knowledge_base = KnowledgeBase(
            owner_id=owner.id,
            name=f"authorization-{uuid4()}",
            external_llm_processing_enabled=True,
        )
        session.add(knowledge_base)
        await session.flush()
        permission = await session.scalar(select(Permission).where(Permission.code == "chat:query"))
        if permission is None:
            permission = Permission(code="chat:query", name="Chat query")
            session.add(permission)
            await session.flush()
        api_key = ApiKey(
            user_id=dimensions.user_id,
            created_by=owner.id,
            name="acceptance key",
            key_hash=uuid4().hex + uuid4().hex,
            key_prefix="kb_live_acceptance",
            permission_codes=["chat:query"],
            knowledge_base_ids=[str(knowledge_base.id)],
            requests_per_minute=60,
        )
        session.add_all(
            [
                api_key,
                UserRole(user_id=dimensions.user_id, role_id=role.id, assigned_by=owner.id),
                RolePermission(role_id=role.id, permission_id=permission.id),
                KnowledgeBaseRoleGrant(
                    knowledge_base_id=knowledge_base.id,
                    role_id=role.id,
                    access_level=KnowledgeBaseAccessLevel.READER,
                    granted_by=owner.id,
                ),
            ]
        )
        await session.flush()
        scoped_dimensions = LlmUsageDimensions(
            tenant_key=dimensions.tenant_key,
            user_id=dimensions.user_id,
            api_key_id=api_key.id,
            api_key_credential_family_id=api_key.credential_family_id,
            knowledge_base_id=knowledge_base.id,
            provider=dimensions.provider,
            model=dimensions.model,
            operation="chat.answer",
        )
        await session.commit()
        return _AuthorizationScenario(
            factory=factory,
            dimensions=scoped_dimensions,
            role_id=role.id,
            permission_id=permission.id,
            api_key_id=api_key.id,
            knowledge_base_id=knowledge_base.id,
        )


async def _prepare(
    *,
    tenant_key: str,
    daily_limit: int,
) -> tuple[async_sessionmaker[AsyncSession], LlmUsageDimensions]:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=4, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    unique = uuid4().hex
    provider = f"acceptance-{unique[:12]}"
    model = f"model-{unique[12:24]}"
    async with factory() as session:
        user = User(email=f"{uuid4()}@example.com", password_hash="unused")
        session.add_all(
            [
                user,
                LlmModelPrice(
                    provider=provider,
                    model=model,
                    input_micro_usd_per_million_tokens=1_000_000,
                    output_micro_usd_per_million_tokens=1_000_000,
                    active=True,
                ),
                LlmBudgetPolicy(
                    name=f"concurrency budget {unique}",
                    tenant_key=f"{tenant_key}-{unique}",
                    daily_token_limit=daily_limit,
                    enabled=True,
                ),
            ]
        )
        await session.flush()
        dimensions = LlmUsageDimensions(
            tenant_key=f"{tenant_key}-{unique}",
            user_id=user.id,
            api_key_id=None,
            knowledge_base_id=None,
            provider=provider,
            model=model,
            operation="concurrency.test",
        )
        await session.commit()
    return factory, dimensions


@pytest.mark.asyncio
async def test_postgres_same_idempotency_key_has_one_winner_and_one_domain_duplicate() -> None:
    factory, dimensions = await _prepare(tenant_key="idempotency", daily_limit=10_000)
    start = asyncio.Event()

    async def reserve() -> str:
        async with factory() as session:
            await start.wait()
            try:
                await LlmUsageGovernance().reserve(
                    session,
                    dimensions=dimensions,
                    idempotency_key="same-concurrent-key",
                    estimated_input_tokens=100,
                    maximum_output_tokens=100,
                )
                await session.commit()
                return "winner"
            except LlmUsageDuplicate:
                await session.rollback()
                return "duplicate"

    tasks = [asyncio.create_task(reserve()) for _ in range(2)]
    start.set()
    assert sorted(await asyncio.gather(*tasks)) == ["duplicate", "winner"]


@pytest.mark.asyncio
async def test_postgres_same_client_key_for_different_users_has_two_winners() -> None:
    factory, first_dimensions = await _prepare(
        tenant_key="subject-scoped-idempotency", daily_limit=10_000
    )
    async with factory() as session:
        second_user = User(email=f"{uuid4()}@example.com", password_hash="unused")
        session.add(second_user)
        await session.flush()
        second_dimensions = LlmUsageDimensions(
            tenant_key=first_dimensions.tenant_key,
            user_id=second_user.id,
            api_key_id=None,
            knowledge_base_id=first_dimensions.knowledge_base_id,
            provider=first_dimensions.provider,
            model=first_dimensions.model,
            operation=first_dimensions.operation,
        )
        await session.commit()
    start = asyncio.Event()

    async def reserve(dimensions: LlmUsageDimensions) -> str:
        async with factory() as session:
            await start.wait()
            await LlmUsageGovernance().reserve(
                session,
                dimensions=dimensions,
                idempotency_key="same-client-key",
                estimated_input_tokens=100,
                maximum_output_tokens=100,
            )
            await session.commit()
            return "winner"

    tasks = [
        asyncio.create_task(reserve(first_dimensions)),
        asyncio.create_task(reserve(second_dimensions)),
    ]
    start.set()
    assert await asyncio.gather(*tasks) == ["winner", "winner"]


@pytest.mark.asyncio
async def test_postgres_row_lock_prevents_concurrent_budget_overspend() -> None:
    factory, dimensions = await _prepare(tenant_key="budget", daily_limit=200)
    start = asyncio.Event()

    async def reserve(idempotency_key: str) -> str:
        async with factory() as session:
            await start.wait()
            try:
                await LlmUsageGovernance().reserve(
                    session,
                    dimensions=dimensions,
                    idempotency_key=idempotency_key,
                    estimated_input_tokens=100,
                    maximum_output_tokens=100,
                )
                await session.commit()
                return "winner"
            except LlmBudgetExceeded:
                await session.rollback()
                return "budget_exceeded"

    tasks = [
        asyncio.create_task(reserve("budget-key-1")),
        asyncio.create_task(reserve("budget-key-2")),
    ]
    start.set()
    assert sorted(await asyncio.gather(*tasks)) == ["budget_exceeded", "winner"]


@pytest.mark.asyncio
async def test_postgres_okf_held_usage_serializes_stale_lease_reclaim() -> None:
    factory, dimensions = await _prepare(tenant_key="okf-egress", daily_limit=10_000)
    async with factory() as setup:
        knowledge_base = KnowledgeBase(
            owner_id=dimensions.user_id,
            name=f"okf-egress-{uuid4()}",
            external_llm_processing_enabled=True,
        )
        setup.add(knowledge_base)
        await setup.flush()
        file = File(
            owner_id=dimensions.user_id,
            knowledge_base_id=knowledge_base.id,
            bucket="kb",
            object_key=f"objects/{uuid4()}.txt",
            original_name="source.txt",
            extension=".txt",
            content_type="text/plain",
            size_bytes=5,
            status=FileStatus.PROCESSING,
        )
        setup.add(file)
        await setup.flush()
        original_lease = uuid4()
        job = OkfConversionJob(
            file_id=file.id,
            knowledge_base_id=knowledge_base.id,
            file_version=file.version,
            prompt_version=PROMPT_VERSION,
            status=OkfConversionStatus.PROCESSING,
            attempts=1,
            locked_at=datetime.now(UTC) - timedelta(hours=1),
            lease_id=original_lease,
        )
        setup.add(job)
        await setup.flush()
        job_id = job.id
        await LlmUsageGovernance().reserve(
            setup,
            dimensions=LlmUsageDimensions(
                tenant_key=dimensions.tenant_key,
                user_id=dimensions.user_id,
                api_key_id=None,
                knowledge_base_id=knowledge_base.id,
                provider=dimensions.provider,
                model=dimensions.model,
                operation="okf.compile",
            ),
            idempotency_key="postgres-okf-active-egress",
            estimated_input_tokens=100,
            maximum_output_tokens=100,
        )
        await setup.commit()

    async with factory() as egress, factory() as reclaimer:
        await acquire_llm_egress_locks(egress, [("okf_conversion_job", job_id)])
        reclaim = asyncio.create_task(
            _claim_job(
                reclaimer,
                Settings(environment="test", okf_conversion_lease_seconds=60),
            )
        )
        done, _ = await asyncio.wait({reclaim}, timeout=0.1)
        assert not done

        await egress.commit()
        assert await asyncio.wait_for(reclaim, timeout=5) is None

    async with factory() as verify:
        persisted = await verify.get(OkfConversionJob, job_id)
        assert persisted is not None
        assert persisted.status is OkfConversionStatus.PROCESSING
        assert persisted.lease_id == original_lease
        assert persisted.attempts == 1


def _scenario_scope(scenario: _AuthorizationScenario, scope: str) -> tuple[str, UUID]:
    if scope == "user":
        return scope, scenario.dimensions.user_id
    if scope == "role":
        return scope, scenario.role_id
    if scope == "api_key":
        return scope, scenario.api_key_id
    return "knowledge_base", scenario.knowledge_base_id


async def _apply_revocation(
    session: AsyncSession,
    scenario: _AuthorizationScenario,
    scope: str,
) -> None:
    if scope == "user":
        user = await session.get(User, scenario.dimensions.user_id)
        assert user is not None
        user.status = UserStatus.DISABLED
    elif scope == "role":
        await session.execute(
            delete(RolePermission).where(
                RolePermission.role_id == scenario.role_id,
                RolePermission.permission_id == scenario.permission_id,
            )
        )
    elif scope == "api_key":
        api_key = await session.get(ApiKey, scenario.api_key_id)
        assert api_key is not None
        api_key.revoked_at = datetime.now(UTC)
    else:
        knowledge_base = await session.get(KnowledgeBase, scenario.knowledge_base_id)
        assert knowledge_base is not None
        knowledge_base.external_llm_processing_enabled = False


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["user", "role", "api_key", "knowledge_base"])
async def test_postgres_revocation_first_makes_fresh_egress_authorization_fail_closed(
    scope: str,
) -> None:
    scenario = await _prepare_authorization_scenario()
    async with scenario.factory() as revoker, scenario.factory() as caller:
        await acquire_llm_egress_locks(revoker, [_scenario_scope(scenario, scope)])
        await _apply_revocation(revoker, scenario, scope)

        preflight = asyncio.create_task(
            external_llm_egress_allowed(
                caller,
                user_id=scenario.dimensions.user_id,
                knowledge_base_id=scenario.knowledge_base_id,
                api_key_id=scenario.api_key_id,
                required_permission="chat:query",
                minimum_access=KnowledgeBaseAccessLevel.READER,
            )
        )
        done, _ = await asyncio.wait({preflight}, timeout=0.1)
        assert not done

        await revoker.commit()
        assert await asyncio.wait_for(preflight, timeout=5) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["user", "api_key", "knowledge_base"])
async def test_postgres_revocation_first_refreshes_cached_egress_authorization(
    scope: str,
) -> None:
    """A committed request Session must not reuse its pre-revocation ORM identity."""

    scenario = await _prepare_authorization_scenario()
    async with scenario.factory() as revoker, scenario.factory() as caller:
        if scope == "user":
            cached = await caller.get(User, scenario.dimensions.user_id)
        elif scope == "api_key":
            cached = await caller.get(ApiKey, scenario.api_key_id)
        else:
            cached = await caller.get(KnowledgeBase, scenario.knowledge_base_id)
        assert cached is not None
        # GovernedLlmExecutor commits the durable usage hold before this preflight.
        # expire_on_commit=False deliberately preserves the identity-map entries.
        await caller.commit()

        await acquire_llm_egress_locks(revoker, [_scenario_scope(scenario, scope)])
        await _apply_revocation(revoker, scenario, scope)
        preflight = asyncio.create_task(
            external_llm_egress_allowed(
                caller,
                user_id=scenario.dimensions.user_id,
                knowledge_base_id=scenario.knowledge_base_id,
                api_key_id=scenario.api_key_id,
                required_permission="chat:query",
                minimum_access=KnowledgeBaseAccessLevel.READER,
            )
        )
        done, _ = await asyncio.wait({preflight}, timeout=0.1)
        assert not done

        await revoker.commit()
        assert await asyncio.wait_for(preflight, timeout=5) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["user", "role", "api_key", "knowledge_base"])
async def test_postgres_egress_first_makes_revocation_observe_the_held_lease(
    scope: str,
) -> None:
    scenario = await _prepare_authorization_scenario()
    async with scenario.factory() as setup:
        usage = await LlmUsageGovernance().reserve(
            setup,
            dimensions=scenario.dimensions,
            idempotency_key=f"egress-first-{scope}-{uuid4()}",
            estimated_input_tokens=100,
            maximum_output_tokens=100,
        )
        await setup.commit()

    async with scenario.factory() as caller, scenario.factory() as revoker:
        await acquire_llm_egress_locks(caller, [_scenario_scope(scenario, scope)])
        actor = await revoker.get(User, scenario.dimensions.user_id)
        assert actor is not None
        access = AccessContext(
            user=actor,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset({scenario.role_id}),
            max_role_priority=10_000,
        )
        request = Request({"type": "http", "headers": []})
        request.state.request_id = f"egress-first-{scope}"

        async def attempt_revocation() -> ApiError | None:
            try:
                kwargs = {
                    "knowledge_base_id": (
                        scenario.knowledge_base_id if scope == "knowledge_base" else None
                    ),
                    "user_id": scenario.dimensions.user_id if scope == "user" else None,
                    "api_key_id": scenario.api_key_id if scope == "api_key" else None,
                    "role_id": scenario.role_id if scope == "role" else None,
                }
                await deny_if_active_external_llm_egress(
                    revoker,
                    request,
                    access,
                    revocation_scope=f"acceptance_{scope}",
                    resource_type=scope,
                    resource_id=str(_scenario_scope(scenario, scope)[1]),
                    **kwargs,
                )
            except ApiError as error:
                return error
            return None

        revocation = asyncio.create_task(attempt_revocation())
        done, _ = await asyncio.wait({revocation}, timeout=0.1)
        assert not done

        await caller.commit()
        denied = await asyncio.wait_for(revocation, timeout=5)
        assert denied is not None
        assert denied.status_code == 409
        assert denied.code == "external_llm_processing_in_progress"

    async with scenario.factory() as verify:
        persisted = await verify.get(type(usage), usage.id)
        assert persisted is not None
        assert persisted.status.value == "held"
