from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import (
    LlmBudgetCounter,
    LlmBudgetPolicy,
    LlmModelPrice,
    LlmUsageRecord,
    LlmUsageStatus,
    Role,
    User,
    UserRole,
)
from app.services.llm_provider import (
    LlmChatResult,
    LlmProviderError,
    MeteringOutcome,
)
from app.services.llm_usage import (
    GovernedLlmExecutor,
    LlmBudgetExceeded,
    LlmEgressDenied,
    LlmUsageDimensions,
    LlmUsageDuplicate,
    LlmUsageGovernance,
    LlmUsageMeteringMismatch,
    LlmUsagePricingUnavailable,
    LlmUsageUnmetered,
    find_active_llm_egress,
)


@pytest_asyncio.fixture
async def governance_session() -> AsyncSession:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
    )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        yield session
    await engine.dispose()


async def _configured_dimensions(
    session: AsyncSession,
    *,
    daily_tokens: int = 10_000,
    monthly_tokens: int = 100_000,
    daily_cost_micro_usd: int = 10_000,
    monthly_cost_micro_usd: int = 100_000,
) -> LlmUsageDimensions:
    user = User(
        email=f"governance-{uuid4()}@example.com",
        password_hash="unused",
    )
    session.add_all(
        [
            user,
            LlmModelPrice(
                provider="qwen",
                model="qwen-plus",
                input_micro_usd_per_million_tokens=1_000_000,
                output_micro_usd_per_million_tokens=2_000_000,
                active=True,
            ),
            LlmBudgetPolicy(
                name="tenant hard budget",
                tenant_key="heyi",
                daily_token_limit=daily_tokens,
                monthly_token_limit=monthly_tokens,
                daily_cost_limit_micro_usd=daily_cost_micro_usd,
                monthly_cost_limit_micro_usd=monthly_cost_micro_usd,
                enabled=True,
            ),
        ]
    )
    await session.flush()
    return LlmUsageDimensions(
        tenant_key="heyi",
        user_id=user.id,
        api_key_id=None,
        knowledge_base_id=uuid4(),
        provider="qwen",
        model="qwen-plus",
        operation="chat.answer",
    )


@pytest.mark.asyncio
async def test_unknown_model_price_fails_closed(governance_session: AsyncSession) -> None:
    user = User(email="unknown-price@example.com", password_hash="unused")
    governance_session.add_all(
        [
            user,
            LlmBudgetPolicy(
                name="tenant budget",
                tenant_key="heyi",
                daily_token_limit=1_000,
                enabled=True,
            ),
        ]
    )
    await governance_session.flush()

    with pytest.raises(LlmUsagePricingUnavailable):
        await LlmUsageGovernance().reserve(
            governance_session,
            dimensions=LlmUsageDimensions(
                tenant_key="heyi",
                user_id=user.id,
                api_key_id=None,
                knowledge_base_id=uuid4(),
                provider="unknown",
                model="unpriced",
                operation="chat.answer",
            ),
            idempotency_key="request-unknown-price",
            estimated_input_tokens=100,
            maximum_output_tokens=100,
        )


@pytest.mark.asyncio
async def test_reserve_and_settle_refunds_unused_budget_without_storing_content(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)
    service = LlmUsageGovernance()

    reservation = await service.reserve(
        governance_session,
        dimensions=dimensions,
        idempotency_key="request-settlement",
        estimated_input_tokens=1_000,
        maximum_output_tokens=1_000,
    )
    assert reservation.status is LlmUsageStatus.HELD
    assert reservation.reserved_token_count == 2_000
    assert reservation.reserved_cost_micro_usd == 3_000

    settled = await service.settle(
        governance_session,
        usage_id=reservation.id,
        input_tokens=400,
        output_tokens=100,
    )
    assert settled.status is LlmUsageStatus.SETTLED
    assert settled.actual_token_count == 500
    assert settled.actual_cost_micro_usd == 600

    counters = list((await governance_session.scalars(select(LlmBudgetCounter))).all())
    assert {item.window_kind for item in counters} == {"day", "month"}
    assert all(item.reserved_token_count == 0 for item in counters)
    assert all(item.used_token_count == 500 for item in counters)
    assert all(item.reserved_cost_micro_usd == 0 for item in counters)
    assert all(item.used_cost_micro_usd == 600 for item in counters)

    columns = set(Base.metadata.tables["llm_usage_records"].c.keys())
    assert not columns & {"prompt", "answer", "messages", "content"}


@pytest.mark.asyncio
async def test_same_idempotency_key_never_reserves_or_bills_twice(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)
    service = LlmUsageGovernance()
    first = await service.reserve(
        governance_session,
        dimensions=dimensions,
        idempotency_key="stable-client-request",
        estimated_input_tokens=100,
        maximum_output_tokens=100,
    )

    with pytest.raises(LlmUsageDuplicate) as duplicate:
        await service.reserve(
            governance_session,
            dimensions=dimensions,
            idempotency_key="stable-client-request",
            estimated_input_tokens=100,
            maximum_output_tokens=100,
        )

    assert duplicate.value.usage_id == first.id
    assert len(list((await governance_session.scalars(select(LlmUsageRecord))).all())) == 1
    counters = list((await governance_session.scalars(select(LlmBudgetCounter))).all())
    assert all(item.reserved_token_count == 200 for item in counters)


@pytest.mark.asyncio
async def test_same_client_key_is_scoped_to_the_calling_subject(
    governance_session: AsyncSession,
) -> None:
    first_dimensions = await _configured_dimensions(governance_session)
    second_user = User(
        email=f"governance-{uuid4()}@example.com",
        password_hash="unused",
    )
    governance_session.add(second_user)
    await governance_session.flush()
    second_dimensions = LlmUsageDimensions(
        tenant_key=first_dimensions.tenant_key,
        user_id=second_user.id,
        api_key_id=None,
        knowledge_base_id=first_dimensions.knowledge_base_id,
        provider=first_dimensions.provider,
        model=first_dimensions.model,
        operation=first_dimensions.operation,
    )
    service = LlmUsageGovernance()

    first = await service.reserve(
        governance_session,
        dimensions=first_dimensions,
        idempotency_key="shared-client-key",
        estimated_input_tokens=10,
        maximum_output_tokens=10,
    )
    second = await service.reserve(
        governance_session,
        dimensions=second_dimensions,
        idempotency_key="shared-client-key",
        estimated_input_tokens=10,
        maximum_output_tokens=10,
    )

    assert first.id != second.id
    assert first.idempotency_hash != second.idempotency_hash


@pytest.mark.asyncio
async def test_daily_and_monthly_hard_budgets_reject_before_provider_call(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(
        governance_session,
        daily_tokens=199,
        monthly_tokens=199,
    )

    with pytest.raises(LlmBudgetExceeded) as exceeded:
        await LlmUsageGovernance().reserve(
            governance_session,
            dimensions=dimensions,
            idempotency_key="over-budget",
            estimated_input_tokens=100,
            maximum_output_tokens=100,
        )

    assert exceeded.value.metric == "tokens"
    assert exceeded.value.window_kind in {"day", "month"}
    assert not list((await governance_session.scalars(select(LlmUsageRecord))).all())


@pytest.mark.asyncio
async def test_indeterminate_failure_keeps_one_conservative_hold_and_blocks_retry(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)
    service = LlmUsageGovernance()
    reservation = await service.reserve(
        governance_session,
        dimensions=dimensions,
        idempotency_key="timeout-request",
        estimated_input_tokens=100,
        maximum_output_tokens=100,
    )

    await service.mark_indeterminate(
        governance_session,
        usage_id=reservation.id,
        error_code="llm_transport_error",
    )
    with pytest.raises(LlmUsageDuplicate):
        await service.reserve(
            governance_session,
            dimensions=dimensions,
            idempotency_key="timeout-request",
            estimated_input_tokens=100,
            maximum_output_tokens=100,
        )

    record = await governance_session.get(LlmUsageRecord, reservation.id)
    assert record is not None
    assert record.status is LlmUsageStatus.INDETERMINATE
    assert record.error_code == "llm_transport_error"
    counters = list((await governance_session.scalars(select(LlmBudgetCounter))).all())
    assert all(item.reserved_token_count == 200 for item in counters)


@pytest.mark.asyncio
async def test_known_non_billable_failure_releases_the_hold(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)
    service = LlmUsageGovernance()
    reservation = await service.reserve(
        governance_session,
        dimensions=dimensions,
        idempotency_key="rejected-request",
        estimated_input_tokens=100,
        maximum_output_tokens=100,
    )

    released = await service.release(
        governance_session,
        usage_id=reservation.id,
        error_code="llm_request_rejected",
    )

    assert released.status is LlmUsageStatus.RELEASED
    assert released.settled_at is not None
    counters = list((await governance_session.scalars(select(LlmBudgetCounter))).all())
    assert all(item.reserved_token_count == 0 for item in counters)
    assert all(item.used_token_count == 0 for item in counters)


def test_governance_schema_has_concurrency_and_idempotency_constraints() -> None:
    records = Base.metadata.tables["llm_usage_records"]
    record_unique_sets = {
        frozenset(constraint.columns.keys())
        for constraint in records.constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }
    assert frozenset({"tenant_key", "idempotency_hash"}) in record_unique_sets
    assert "ix_llm_usage_knowledge_base_status" in {
        index.name for index in LlmUsageRecord.__table__.indexes
    }

    counters = Base.metadata.tables["llm_budget_counters"]
    counter_unique_sets = {
        frozenset(constraint.columns.keys())
        for constraint in counters.constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }
    assert frozenset({"policy_id", "window_kind", "window_start"}) in counter_unique_sets


@pytest.mark.asyncio
async def test_active_egress_lease_is_discoverable_by_every_revocation_dimension(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)
    role = Role(code=f"lease-{uuid4()}", name="Lease role")
    governance_session.add(role)
    await governance_session.flush()
    governance_session.add(UserRole(user_id=dimensions.user_id, role_id=role.id))
    reservation = await LlmUsageGovernance().reserve(
        governance_session,
        dimensions=dimensions,
        idempotency_key="revocation-dimension-matrix",
        estimated_input_tokens=100,
        maximum_output_tokens=100,
    )
    reservation.api_key_id = uuid4()
    await governance_session.flush()

    assert (
        await find_active_llm_egress(
            governance_session, knowledge_base_id=dimensions.knowledge_base_id
        )
        == reservation.id
    )
    assert (
        await find_active_llm_egress(governance_session, user_id=dimensions.user_id)
        == reservation.id
    )
    assert (
        await find_active_llm_egress(governance_session, api_key_id=reservation.api_key_id)
        == reservation.id
    )
    assert await find_active_llm_egress(governance_session, role_id=role.id) == reservation.id
    assert (
        await find_active_llm_egress(
            governance_session,
            knowledge_base_id=dimensions.knowledge_base_id,
            user_id=dimensions.user_id,
            operation=dimensions.operation,
        )
        == reservation.id
    )
    assert (
        await find_active_llm_egress(
            governance_session,
            knowledge_base_id=dimensions.knowledge_base_id,
            user_id=dimensions.user_id,
            operation="different.operation",
        )
        is None
    )


def test_window_boundaries_are_utc_and_month_aligned() -> None:
    service = LlmUsageGovernance()
    instant = datetime(2026, 7, 12, 23, 59, tzinfo=UTC)

    assert service.window_start("day", instant) == datetime(2026, 7, 12, tzinfo=UTC)
    assert service.window_start("month", instant) == datetime(2026, 7, 1, tzinfo=UTC)


class _FakeChatClient:
    provider = "qwen"
    model = "qwen-plus"

    def __init__(self, *, metered: bool = True) -> None:
        self.calls = 0
        self.metered = metered
        self.result_model = self.model

    async def complete_chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> LlmChatResult:
        del messages, temperature, max_tokens
        self.calls += 1
        return LlmChatResult(
            content="governed result",
            provider=self.provider,
            model=self.result_model,
            prompt_tokens=50 if self.metered else None,
            completion_tokens=25 if self.metered else None,
        )


class _FailingChatClient:
    provider = "qwen"
    model = "qwen-plus"

    def __init__(self, error: LlmProviderError) -> None:
        self.error = error
        self.calls = 0

    async def complete_chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> LlmChatResult:
        del messages, temperature, max_tokens
        self.calls += 1
        raise self.error


@pytest.mark.asyncio
async def test_governed_executor_reserves_before_call_and_settles_reported_usage(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)
    client = _FakeChatClient()
    messages = [{"role": "user", "content": "sensitive content is never persisted"}]

    result = await GovernedLlmExecutor().complete_chat(
        governance_session,
        client=client,
        dimensions=dimensions,
        idempotency_key="executor-success",
        messages=messages,
        maximum_output_tokens=100,
    )

    assert result.content == "governed result"
    assert client.calls == 1
    record = await governance_session.scalar(
        select(LlmUsageRecord).where(LlmUsageRecord.operation == "chat.answer")
    )
    assert record is not None
    assert record.status is LlmUsageStatus.SETTLED
    assert record.actual_token_count == 75
    serialized_values = {str(value) for value in record.__dict__.values()}
    assert messages[0]["content"] not in serialized_values


@pytest.mark.asyncio
async def test_governed_executor_releases_hold_when_call_boundary_denies_egress(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)
    client = _FakeChatClient()

    async def deny_egress() -> bool:
        # Model the read transaction opened by a call-time consent refresh.
        assert await governance_session.scalar(select(LlmBudgetPolicy.id)) is not None
        return False

    with pytest.raises(LlmEgressDenied):
        await GovernedLlmExecutor().complete_chat(
            governance_session,
            client=client,
            dimensions=dimensions,
            idempotency_key="executor-consent-revoked",
            messages=[{"role": "user", "content": "private excerpt"}],
            maximum_output_tokens=100,
            before_egress=deny_egress,
        )

    record = await governance_session.scalar(select(LlmUsageRecord))
    assert record is not None
    assert record.status is LlmUsageStatus.RELEASED
    assert record.error_code == "llm_egress_denied"
    assert client.calls == 0


@pytest.mark.asyncio
async def test_governed_executor_closes_preflight_transaction_before_provider_wait(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)

    class TransactionCheckingClient(_FakeChatClient):
        async def complete_chat(
            self,
            messages: list[dict[str, str]],
            *,
            temperature: float = 0.2,
            max_tokens: int | None = None,
        ) -> LlmChatResult:
            assert not governance_session.in_transaction()
            return await super().complete_chat(
                messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )

    async def allow_egress() -> bool:
        assert await governance_session.scalar(select(LlmBudgetPolicy.id)) is not None
        assert governance_session.in_transaction()
        return True

    client = TransactionCheckingClient()
    await GovernedLlmExecutor().complete_chat(
        governance_session,
        client=client,
        dimensions=dimensions,
        idempotency_key="executor-no-open-db-transaction",
        messages=[{"role": "user", "content": "hello"}],
        maximum_output_tokens=100,
        before_egress=allow_egress,
    )

    assert client.calls == 1


@pytest.mark.asyncio
async def test_governed_executor_keeps_hold_when_provider_omits_usage(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)
    client = _FakeChatClient(metered=False)

    with pytest.raises(LlmUsageUnmetered):
        await GovernedLlmExecutor().complete_chat(
            governance_session,
            client=client,
            dimensions=dimensions,
            idempotency_key="executor-unmetered",
            messages=[{"role": "user", "content": "hello"}],
            maximum_output_tokens=100,
        )

    record = await governance_session.scalar(select(LlmUsageRecord))
    assert record is not None
    assert record.status is LlmUsageStatus.INDETERMINATE
    assert client.calls == 1


@pytest.mark.asyncio
async def test_governed_executor_settles_known_usage_on_bad_200_response(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)
    client = _FailingChatClient(
        LlmProviderError(
            "llm_invalid_output",
            provider="qwen",
            retryable=True,
            metering_outcome=MeteringOutcome.KNOWN,
            prompt_tokens=19,
            completion_tokens=5,
        )
    )

    with pytest.raises(LlmProviderError):
        await GovernedLlmExecutor().complete_chat(
            governance_session,
            client=client,
            dimensions=dimensions,
            idempotency_key="known-bad-response",
            messages=[{"role": "user", "content": "hello"}],
            maximum_output_tokens=100,
        )

    record = await governance_session.scalar(select(LlmUsageRecord))
    assert record is not None
    assert record.status is LlmUsageStatus.SETTLED
    assert record.actual_input_tokens == 19
    assert record.actual_output_tokens == 5


@pytest.mark.asyncio
async def test_governed_executor_retains_hold_on_unknown_transport_outcome(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)
    client = _FailingChatClient(
        LlmProviderError(
            "llm_transport_error",
            provider="qwen",
            retryable=True,
            metering_outcome=MeteringOutcome.UNKNOWN,
        )
    )

    with pytest.raises(LlmProviderError):
        await GovernedLlmExecutor().complete_chat(
            governance_session,
            client=client,
            dimensions=dimensions,
            idempotency_key="unknown-transport",
            messages=[{"role": "user", "content": "hello"}],
            maximum_output_tokens=100,
        )

    record = await governance_session.scalar(select(LlmUsageRecord))
    assert record is not None
    assert record.status is LlmUsageStatus.INDETERMINATE


@pytest.mark.asyncio
async def test_governed_executor_duplicate_does_not_call_provider_again(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)
    first_client = _FakeChatClient()
    executor = GovernedLlmExecutor()
    arguments = {
        "session": governance_session,
        "dimensions": dimensions,
        "idempotency_key": "executor-duplicate",
        "messages": [{"role": "user", "content": "hello"}],
        "maximum_output_tokens": 100,
    }
    await executor.complete_chat(client=first_client, **arguments)
    duplicate_client = _FakeChatClient()

    with pytest.raises(LlmUsageDuplicate):
        await executor.complete_chat(client=duplicate_client, **arguments)

    assert first_client.calls == 1
    assert duplicate_client.calls == 0


@pytest.mark.asyncio
async def test_provider_model_mismatch_is_not_charged_to_the_configured_price(
    governance_session: AsyncSession,
) -> None:
    dimensions = await _configured_dimensions(governance_session)
    client = _FakeChatClient()
    client.result_model = "different-unpriced-model"

    with pytest.raises(LlmUsageMeteringMismatch):
        await GovernedLlmExecutor().complete_chat(
            governance_session,
            client=client,
            dimensions=dimensions,
            idempotency_key="model-mismatch",
            messages=[{"role": "user", "content": "hello"}],
            maximum_output_tokens=100,
        )

    record = await governance_session.scalar(select(LlmUsageRecord))
    assert record is not None
    assert record.status is LlmUsageStatus.INDETERMINATE
    assert record.actual_token_count is None
