from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import UUID

from sqlalchemy import or_, select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    LlmBudgetCounter,
    LlmBudgetPolicy,
    LlmModelPrice,
    LlmUsageBudgetHold,
    LlmUsageRecord,
    LlmUsageStatus,
    UserRole,
)
from app.services.llm_provider import (
    LlmChatResult,
    LlmProviderError,
    LlmResult,
    MeteringOutcome,
)

WindowKind = Literal["day", "month"]

_LOGGER = logging.getLogger(__name__)
_PRICE_DENOMINATOR = 1_000_000
_MAX_MATCHED_BUDGET_POLICIES = 100


class LlmUsageGovernanceError(RuntimeError):
    pass


class LlmUsagePricingUnavailable(LlmUsageGovernanceError):
    pass


class LlmBudgetConfigurationUnavailable(LlmUsageGovernanceError):
    pass


class LlmUsageDuplicate(LlmUsageGovernanceError):
    def __init__(self, usage_id: UUID, status: LlmUsageStatus) -> None:
        super().__init__("llm usage idempotency key was already claimed")
        self.usage_id = usage_id
        self.status = status


class LlmBudgetExceeded(LlmUsageGovernanceError):
    def __init__(
        self,
        *,
        policy_id: UUID,
        window_kind: WindowKind,
        metric: Literal["tokens", "cost_micro_usd"],
        limit: int,
    ) -> None:
        super().__init__(f"LLM {metric} budget exceeded for {window_kind} window")
        self.policy_id = policy_id
        self.window_kind = window_kind
        self.metric = metric
        self.limit = limit


class LlmUsageInvalidState(LlmUsageGovernanceError):
    pass


class LlmUsageUnmetered(LlmUsageGovernanceError):
    pass


class LlmUsageMeteringMismatch(LlmUsageGovernanceError):
    pass


class LlmEgressDenied(LlmUsageGovernanceError):
    """A read-only call-boundary policy check denied provider egress."""

    pass


class _ChatClient(Protocol):
    @property
    def provider(self) -> str: ...

    @property
    def model(self) -> str: ...

    async def complete_chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> LlmChatResult: ...


class _OkfClient(Protocol):
    @property
    def provider(self) -> str: ...

    @property
    def model(self) -> str: ...

    async def compile_okf(self, source_text: str, *, user_id: str) -> LlmResult: ...


@dataclass(frozen=True, slots=True)
class LlmUsageDimensions:
    tenant_key: str
    user_id: UUID
    api_key_id: UUID | None
    knowledge_base_id: UUID | None
    provider: str
    model: str
    operation: str
    api_key_credential_family_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class _WindowReservation:
    policy: LlmBudgetPolicy
    counter: LlmBudgetCounter
    window_kind: WindowKind
    window_start: datetime
    token_limit: int | None
    cost_limit_micro_usd: int | None


class LlmUsageGovernance:
    """Reserve provider spend before a call and settle only content-free usage metadata."""

    @staticmethod
    def window_start(window_kind: WindowKind, now: datetime | None = None) -> datetime:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if window_kind == "day":
            return current.replace(hour=0, minute=0, second=0, microsecond=0)
        return current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    @staticmethod
    def estimate_input_tokens(messages: list[dict[str, str]]) -> int:
        """Return a tokenizer-independent upper bound based on UTF-8 bytes plus framing."""
        return sum(len(item.get("content", "").encode("utf-8")) + 32 for item in messages)

    async def reserve(
        self,
        session: AsyncSession,
        *,
        dimensions: LlmUsageDimensions,
        idempotency_key: str,
        estimated_input_tokens: int,
        maximum_output_tokens: int,
        now: datetime | None = None,
    ) -> LlmUsageRecord:
        if estimated_input_tokens < 0 or maximum_output_tokens < 0:
            raise ValueError("token reservations cannot be negative")
        if not 1 <= len(idempotency_key) <= 200:
            raise ValueError("idempotency_key must contain 1 to 200 characters")
        if not dimensions.tenant_key or len(dimensions.tenant_key) > 100:
            raise ValueError("tenant_key must contain 1 to 100 characters")
        if dimensions.api_key_id is not None and dimensions.api_key_credential_family_id is None:
            raise ValueError("api-key usage requires a credential family")

        idempotency_context = json.dumps(
            {
                "tenant": dimensions.tenant_key,
                "user": str(dimensions.user_id),
                # Keep the historical JSON field name stable.  Only its value
                # changes from the physical key UUID to the credential-family
                # UUID, whose migration backfill initially equals that key ID.
                # Renaming this key would invalidate pre-0018 usage hashes and
                # could permit duplicate provider egress after an upgrade.
                "api_key": (
                    str(dimensions.api_key_credential_family_id)
                    if dimensions.api_key_credential_family_id
                    else str(dimensions.api_key_id)
                    if dimensions.api_key_id
                    else None
                ),
                "knowledge_base": (
                    str(dimensions.knowledge_base_id) if dimensions.knowledge_base_id else None
                ),
                "provider": dimensions.provider,
                "model": dimensions.model,
                "operation": dimensions.operation,
                "client_key": idempotency_key,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        idempotency_hash = hashlib.sha256(idempotency_context.encode("utf-8")).hexdigest()
        duplicate = await session.scalar(
            select(LlmUsageRecord)
            .where(
                LlmUsageRecord.tenant_key == dimensions.tenant_key,
                LlmUsageRecord.idempotency_hash == idempotency_hash,
            )
            .with_for_update()
        )
        if duplicate is not None:
            raise LlmUsageDuplicate(duplicate.id, duplicate.status)

        price = await session.scalar(
            select(LlmModelPrice).where(
                LlmModelPrice.provider == dimensions.provider,
                LlmModelPrice.model == dimensions.model,
                LlmModelPrice.active.is_(True),
            )
        )
        if price is None:
            raise LlmUsagePricingUnavailable("active provider/model price is required")

        policies = list(
            (
                await session.scalars(
                    select(LlmBudgetPolicy)
                    .where(
                        LlmBudgetPolicy.tenant_key == dimensions.tenant_key,
                        LlmBudgetPolicy.enabled.is_(True),
                        or_(
                            LlmBudgetPolicy.user_id.is_(None),
                            LlmBudgetPolicy.user_id == dimensions.user_id,
                        ),
                        or_(
                            LlmBudgetPolicy.api_key_id.is_(None),
                            LlmBudgetPolicy.api_key_id == dimensions.api_key_id,
                        ),
                        or_(
                            LlmBudgetPolicy.provider.is_(None),
                            LlmBudgetPolicy.provider == dimensions.provider,
                        ),
                        or_(
                            LlmBudgetPolicy.model.is_(None),
                            LlmBudgetPolicy.model == dimensions.model,
                        ),
                    )
                    .order_by(LlmBudgetPolicy.id)
                    .limit(_MAX_MATCHED_BUDGET_POLICIES + 1)
                    .with_for_update()
                )
            ).all()
        )
        if not policies:
            raise LlmBudgetConfigurationUnavailable("at least one hard budget is required")
        if len(policies) > _MAX_MATCHED_BUDGET_POLICIES:
            raise LlmBudgetConfigurationUnavailable(
                "matching hard-budget policy count exceeds the safe runtime limit"
            )

        reserved_tokens = estimated_input_tokens + maximum_output_tokens
        reserved_cost = self._cost(
            estimated_input_tokens,
            maximum_output_tokens,
            price.input_micro_usd_per_million_tokens,
            price.output_micro_usd_per_million_tokens,
        )
        reservation_specs: list[
            tuple[LlmBudgetPolicy, WindowKind, datetime, int | None, int | None]
        ] = []
        current = now or datetime.now(UTC)
        for policy in policies:
            for window_kind in ("day", "month"):
                token_limit, cost_limit = self._limits(policy, window_kind)
                if token_limit is None and cost_limit is None:
                    continue
                window_start = self.window_start(window_kind, current)
                reservation_specs.append(
                    (policy, window_kind, window_start, token_limit, cost_limit)
                )
        counters = await self._locked_counters(
            session,
            [
                (policy.id, window_kind, window_start)
                for policy, window_kind, window_start, _, _ in reservation_specs
            ],
        )
        reservations = [
            _WindowReservation(
                policy=policy,
                counter=counters[(policy.id, window_kind)],
                window_kind=window_kind,
                window_start=window_start,
                token_limit=token_limit,
                cost_limit_micro_usd=cost_limit,
            )
            for policy, window_kind, window_start, token_limit, cost_limit in reservation_specs
        ]

        for item in reservations:
            if (
                item.token_limit is not None
                and item.counter.used_token_count
                + item.counter.reserved_token_count
                + reserved_tokens
                > item.token_limit
            ):
                raise LlmBudgetExceeded(
                    policy_id=item.policy.id,
                    window_kind=item.window_kind,
                    metric="tokens",
                    limit=item.token_limit,
                )
            if (
                item.cost_limit_micro_usd is not None
                and item.counter.used_cost_micro_usd
                + item.counter.reserved_cost_micro_usd
                + reserved_cost
                > item.cost_limit_micro_usd
            ):
                raise LlmBudgetExceeded(
                    policy_id=item.policy.id,
                    window_kind=item.window_kind,
                    metric="cost_micro_usd",
                    limit=item.cost_limit_micro_usd,
                )

        record = LlmUsageRecord(
            tenant_key=dimensions.tenant_key,
            idempotency_hash=idempotency_hash,
            user_id=dimensions.user_id,
            api_key_id=dimensions.api_key_id,
            api_key_credential_family_id=dimensions.api_key_credential_family_id,
            knowledge_base_id=dimensions.knowledge_base_id,
            provider=dimensions.provider,
            model=dimensions.model,
            operation=dimensions.operation,
            status=LlmUsageStatus.HELD,
            reserved_input_tokens=estimated_input_tokens,
            reserved_output_tokens=maximum_output_tokens,
            reserved_token_count=reserved_tokens,
            reserved_cost_micro_usd=reserved_cost,
            input_price_micro_usd_per_million_tokens=(price.input_micro_usd_per_million_tokens),
            output_price_micro_usd_per_million_tokens=(price.output_micro_usd_per_million_tokens),
        )
        try:
            async with session.begin_nested():
                session.add(record)
                await session.flush()
        except IntegrityError:
            # A concurrent request may have checked the key before the winner committed.
            # Translate the unique-index arbitration into the same stable domain outcome;
            # provider egress has not happened at this point.
            duplicate = await session.scalar(
                select(LlmUsageRecord).where(
                    LlmUsageRecord.tenant_key == dimensions.tenant_key,
                    LlmUsageRecord.idempotency_hash == idempotency_hash,
                )
            )
            if duplicate is not None:
                raise LlmUsageDuplicate(duplicate.id, duplicate.status) from None
            raise
        for item in reservations:
            item.counter.reserved_token_count += reserved_tokens
            item.counter.reserved_cost_micro_usd += reserved_cost
            session.add(
                LlmUsageBudgetHold(
                    usage_id=record.id,
                    policy_id=item.policy.id,
                    window_kind=item.window_kind,
                    window_start=item.window_start,
                    reserved_token_count=reserved_tokens,
                    reserved_cost_micro_usd=reserved_cost,
                )
            )
        _LOGGER.info(
            "Reserved governed LLM usage",
            extra={
                "usage_id": str(record.id),
                "tenant_key": dimensions.tenant_key,
                "provider": dimensions.provider,
                "model": dimensions.model,
                "operation": dimensions.operation,
                "reserved_tokens": reserved_tokens,
                "reserved_cost_micro_usd": reserved_cost,
            },
        )
        return record

    async def settle(
        self,
        session: AsyncSession,
        *,
        usage_id: UUID,
        input_tokens: int,
        output_tokens: int,
        now: datetime | None = None,
    ) -> LlmUsageRecord:
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("actual token counts cannot be negative")
        record = await self._locked_record(session, usage_id)
        if record.status is LlmUsageStatus.SETTLED:
            return record
        if record.status is not LlmUsageStatus.HELD:
            raise LlmUsageInvalidState(f"cannot settle usage in {record.status} state")

        actual_tokens = input_tokens + output_tokens
        actual_cost = self._cost(
            input_tokens,
            output_tokens,
            record.input_price_micro_usd_per_million_tokens,
            record.output_price_micro_usd_per_million_tokens,
        )
        await self._settle_holds(
            session,
            record,
            used_tokens=actual_tokens,
            used_cost_micro_usd=actual_cost,
        )
        record.actual_input_tokens = input_tokens
        record.actual_output_tokens = output_tokens
        record.actual_token_count = actual_tokens
        record.actual_cost_micro_usd = actual_cost
        record.status = LlmUsageStatus.SETTLED
        record.settled_at = now or datetime.now(UTC)
        _LOGGER.info(
            "Settled governed LLM usage",
            extra={
                "usage_id": str(record.id),
                "provider": record.provider,
                "model": record.model,
                "actual_tokens": actual_tokens,
                "actual_cost_micro_usd": actual_cost,
            },
        )
        return record

    async def release(
        self,
        session: AsyncSession,
        *,
        usage_id: UUID,
        error_code: str,
        now: datetime | None = None,
    ) -> LlmUsageRecord:
        record = await self._locked_record(session, usage_id)
        if record.status is LlmUsageStatus.RELEASED:
            return record
        if record.status is not LlmUsageStatus.HELD:
            raise LlmUsageInvalidState(f"cannot release usage in {record.status} state")
        await self._settle_holds(session, record, used_tokens=0, used_cost_micro_usd=0)
        record.status = LlmUsageStatus.RELEASED
        record.error_code = error_code[:100]
        record.settled_at = now or datetime.now(UTC)
        return record

    async def mark_indeterminate(
        self,
        session: AsyncSession,
        *,
        usage_id: UUID,
        error_code: str,
        now: datetime | None = None,
    ) -> LlmUsageRecord:
        record = await self._locked_record(session, usage_id)
        if record.status is LlmUsageStatus.INDETERMINATE:
            return record
        if record.status is not LlmUsageStatus.HELD:
            raise LlmUsageInvalidState(f"cannot mark usage indeterminate in {record.status} state")
        record.status = LlmUsageStatus.INDETERMINATE
        record.error_code = error_code[:100]
        record.settled_at = now or datetime.now(UTC)
        _LOGGER.warning(
            "LLM usage outcome is indeterminate; conservative budget hold retained",
            extra={
                "usage_id": str(record.id),
                "provider": record.provider,
                "model": record.model,
                "error_code": record.error_code,
            },
        )
        return record

    async def _locked_counters(
        self,
        session: AsyncSession,
        keys: list[tuple[UUID, WindowKind, datetime]],
    ) -> dict[tuple[UUID, str], LlmBudgetCounter]:
        if not keys:
            return {}
        counters = list(
            (
                await session.scalars(
                    select(LlmBudgetCounter)
                    .where(
                        tuple_(
                            LlmBudgetCounter.policy_id,
                            LlmBudgetCounter.window_kind,
                            LlmBudgetCounter.window_start,
                        ).in_(keys)
                    )
                    .order_by(
                        LlmBudgetCounter.policy_id,
                        LlmBudgetCounter.window_kind,
                        LlmBudgetCounter.window_start,
                    )
                    .with_for_update()
                )
            ).all()
        )
        by_window = {(counter.policy_id, counter.window_kind): counter for counter in counters}
        created = False
        for policy_id, window_kind, window_start in keys:
            key = (policy_id, window_kind)
            if key in by_window:
                continue
            counter = LlmBudgetCounter(
                policy_id=policy_id,
                window_kind=window_kind,
                window_start=window_start,
                used_token_count=0,
                reserved_token_count=0,
                used_cost_micro_usd=0,
                reserved_cost_micro_usd=0,
            )
            session.add(counter)
            by_window[key] = counter
            created = True
        if created:
            # The parent policy rows are already locked in deterministic ID order,
            # serializing first-window creation without one query per policy/window.
            await session.flush()
        return by_window

    async def _locked_record(self, session: AsyncSession, usage_id: UUID) -> LlmUsageRecord:
        record = await session.scalar(
            select(LlmUsageRecord).where(LlmUsageRecord.id == usage_id).with_for_update()
        )
        if record is None:
            raise LlmUsageInvalidState("LLM usage record was not found")
        return record

    async def _settle_holds(
        self,
        session: AsyncSession,
        record: LlmUsageRecord,
        *,
        used_tokens: int,
        used_cost_micro_usd: int,
    ) -> None:
        holds = list(
            (
                await session.scalars(
                    select(LlmUsageBudgetHold)
                    .where(LlmUsageBudgetHold.usage_id == record.id)
                    .order_by(
                        LlmUsageBudgetHold.policy_id,
                        LlmUsageBudgetHold.window_kind,
                    )
                    .with_for_update()
                )
            ).all()
        )
        counter_keys = [(hold.policy_id, hold.window_kind, hold.window_start) for hold in holds]
        counters = (
            list(
                (
                    await session.scalars(
                        select(LlmBudgetCounter)
                        .where(
                            tuple_(
                                LlmBudgetCounter.policy_id,
                                LlmBudgetCounter.window_kind,
                                LlmBudgetCounter.window_start,
                            ).in_(counter_keys)
                        )
                        .order_by(
                            LlmBudgetCounter.policy_id,
                            LlmBudgetCounter.window_kind,
                            LlmBudgetCounter.window_start,
                        )
                        .with_for_update()
                    )
                ).all()
            )
            if counter_keys
            else []
        )
        counters_by_window = {
            (counter.policy_id, counter.window_kind, counter.window_start): counter
            for counter in counters
        }
        for hold in holds:
            counter = counters_by_window.get((hold.policy_id, hold.window_kind, hold.window_start))
            if counter is None:
                raise LlmUsageInvalidState("budget counter for usage hold was not found")
            counter.reserved_token_count = max(
                counter.reserved_token_count - hold.reserved_token_count, 0
            )
            counter.reserved_cost_micro_usd = max(
                counter.reserved_cost_micro_usd - hold.reserved_cost_micro_usd, 0
            )
            counter.used_token_count += used_tokens
            counter.used_cost_micro_usd += used_cost_micro_usd

    @staticmethod
    def _limits(policy: LlmBudgetPolicy, window_kind: WindowKind) -> tuple[int | None, int | None]:
        if window_kind == "day":
            return policy.daily_token_limit, policy.daily_cost_limit_micro_usd
        return policy.monthly_token_limit, policy.monthly_cost_limit_micro_usd

    @staticmethod
    def _cost(
        input_tokens: int,
        output_tokens: int,
        input_price: int,
        output_price: int,
    ) -> int:
        numerator = input_tokens * input_price + output_tokens * output_price
        return (numerator + _PRICE_DENOMINATOR - 1) // _PRICE_DENOMINATOR


async def find_active_llm_egress(
    session: AsyncSession,
    *,
    knowledge_base_id: UUID | None = None,
    user_id: UUID | None = None,
    api_key_id: UUID | None = None,
    role_id: UUID | None = None,
    operation: str | None = None,
) -> UUID | None:
    """Return one durable provider-egress lease matching a revocation scope."""

    filters = [LlmUsageRecord.status == LlmUsageStatus.HELD]
    if knowledge_base_id is not None:
        filters.append(LlmUsageRecord.knowledge_base_id == knowledge_base_id)
    if user_id is not None:
        filters.append(LlmUsageRecord.user_id == user_id)
    if api_key_id is not None:
        filters.append(LlmUsageRecord.api_key_id == api_key_id)
    if role_id is not None:
        filters.append(
            LlmUsageRecord.user_id.in_(select(UserRole.user_id).where(UserRole.role_id == role_id))
        )
    if operation is not None:
        filters.append(LlmUsageRecord.operation == operation)
    usage_id: UUID | None = await session.scalar(select(LlmUsageRecord.id).where(*filters).limit(1))
    return usage_id


class GovernedLlmExecutor:
    """Transaction boundary ensuring a durable hold exists before provider egress."""

    def __init__(self, governance: LlmUsageGovernance | None = None) -> None:
        self._governance = governance or LlmUsageGovernance()

    async def _reconcile_provider_error(
        self,
        session: AsyncSession,
        *,
        usage_id: UUID,
        error: LlmProviderError,
    ) -> None:
        if error.metering_outcome is MeteringOutcome.NOT_STARTED:
            await self._governance.release(
                session,
                usage_id=usage_id,
                error_code=error.code,
            )
        elif error.metering_outcome is MeteringOutcome.KNOWN:
            if error.prompt_tokens is None or error.completion_tokens is None:
                raise LlmUsageUnmetered("known metering omitted required token usage")
            await self._governance.settle(
                session,
                usage_id=usage_id,
                input_tokens=error.prompt_tokens,
                output_tokens=error.completion_tokens,
            )
        else:
            await self._governance.mark_indeterminate(
                session,
                usage_id=usage_id,
                error_code=error.code,
            )

    async def _enforce_egress_policy(
        self,
        session: AsyncSession,
        *,
        usage_id: UUID,
        before_egress: Callable[[], Awaitable[bool]] | None,
    ) -> None:
        if before_egress is None:
            return
        try:
            allowed = await before_egress()
        except asyncio.CancelledError:
            # Cancellation happened before provider egress, so no provider-side
            # outcome can exist. Release the durable hold instead of leaking it.
            await session.rollback()
            await self._governance.release(
                session,
                usage_id=usage_id,
                error_code="llm_egress_preflight_cancelled",
            )
            await session.commit()
            raise
        except Exception:
            # A preflight is read-only and runs before network egress. Always clear any
            # transaction it opened, release the durable hold, and fail closed.
            await session.rollback()
            await self._governance.release(
                session,
                usage_id=usage_id,
                error_code="llm_egress_preflight_failed",
            )
            await session.commit()
            raise
        if session.in_transaction():
            # Do not retain a database transaction or pooled connection while waiting
            # on an external model. Preflight callbacks must be read-only.
            await session.rollback()
        if allowed:
            return
        await self._governance.release(
            session,
            usage_id=usage_id,
            error_code="llm_egress_denied",
        )
        await session.commit()
        raise LlmEgressDenied("provider egress was denied by call-boundary policy")

    async def complete_chat(
        self,
        session: AsyncSession,
        *,
        client: _ChatClient,
        dimensions: LlmUsageDimensions,
        idempotency_key: str,
        messages: list[dict[str, str]],
        maximum_output_tokens: int,
        temperature: float = 0.2,
        before_egress: Callable[[], Awaitable[bool]] | None = None,
    ) -> LlmChatResult:
        if client.provider != dimensions.provider or client.model != dimensions.model:
            raise ValueError("provider client does not match governed usage dimensions")
        reservation = await self._governance.reserve(
            session,
            dimensions=dimensions,
            idempotency_key=idempotency_key,
            estimated_input_tokens=self._governance.estimate_input_tokens(messages),
            maximum_output_tokens=maximum_output_tokens,
        )
        reservation_id = reservation.id
        # The hold must survive a worker crash or upstream timeout after network egress.
        await session.commit()
        await self._enforce_egress_policy(
            session,
            usage_id=reservation_id,
            before_egress=before_egress,
        )
        try:
            result = await client.complete_chat(
                messages,
                temperature=temperature,
                max_tokens=maximum_output_tokens,
            )
        except asyncio.CancelledError:
            await self._governance.mark_indeterminate(
                session,
                usage_id=reservation_id,
                error_code="llm_request_cancelled",
            )
            await session.commit()
            raise
        except LlmProviderError as error:
            await self._reconcile_provider_error(session, usage_id=reservation_id, error=error)
            await session.commit()
            raise
        except Exception:
            await self._governance.mark_indeterminate(
                session,
                usage_id=reservation_id,
                error_code="llm_unexpected_provider_error",
            )
            await session.commit()
            raise

        if result.provider != dimensions.provider or result.model != dimensions.model:
            await self._governance.mark_indeterminate(
                session,
                usage_id=reservation_id,
                error_code="llm_metering_dimension_mismatch",
            )
            await session.commit()
            raise LlmUsageMeteringMismatch(
                "provider response dimensions do not match the reserved price"
            )
        if result.prompt_tokens is None or result.completion_tokens is None:
            await self._governance.mark_indeterminate(
                session,
                usage_id=reservation_id,
                error_code="llm_usage_missing",
            )
            await session.commit()
            raise LlmUsageUnmetered("provider response omitted required token usage")
        await self._governance.settle(
            session,
            usage_id=reservation_id,
            input_tokens=result.prompt_tokens,
            output_tokens=result.completion_tokens,
        )
        await session.commit()
        return result

    async def compile_okf(
        self,
        session: AsyncSession,
        *,
        client: _OkfClient,
        dimensions: LlmUsageDimensions,
        idempotency_key: str,
        source_text: str,
        provider_user_id: str,
        maximum_output_tokens: int,
        before_egress: Callable[[], Awaitable[bool]] | None = None,
    ) -> LlmResult:
        if client.provider != dimensions.provider or client.model != dimensions.model:
            raise ValueError("provider client does not match governed usage dimensions")
        reservation = await self._governance.reserve(
            session,
            dimensions=dimensions,
            idempotency_key=idempotency_key,
            # Include conservative framing for the private compiler system prompt.
            estimated_input_tokens=len(source_text.encode("utf-8")) + 2_048,
            maximum_output_tokens=maximum_output_tokens,
        )
        reservation_id = reservation.id
        await session.commit()
        await self._enforce_egress_policy(
            session,
            usage_id=reservation_id,
            before_egress=before_egress,
        )
        try:
            result = await client.compile_okf(source_text, user_id=provider_user_id)
        except asyncio.CancelledError:
            await self._governance.mark_indeterminate(
                session,
                usage_id=reservation_id,
                error_code="llm_request_cancelled",
            )
            await session.commit()
            raise
        except LlmProviderError as error:
            await self._reconcile_provider_error(session, usage_id=reservation_id, error=error)
            await session.commit()
            raise
        except Exception:
            await self._governance.mark_indeterminate(
                session,
                usage_id=reservation_id,
                error_code="llm_unexpected_provider_error",
            )
            await session.commit()
            raise
        if result.provider != dimensions.provider or result.model != dimensions.model:
            await self._governance.mark_indeterminate(
                session,
                usage_id=reservation_id,
                error_code="llm_metering_dimension_mismatch",
            )
            await session.commit()
            raise LlmUsageMeteringMismatch(
                "provider response dimensions do not match the reserved price"
            )
        if result.prompt_tokens is None or result.completion_tokens is None:
            await self._governance.mark_indeterminate(
                session,
                usage_id=reservation_id,
                error_code="llm_usage_missing",
            )
            await session.commit()
            raise LlmUsageUnmetered("provider response omitted required token usage")
        await self._governance.settle(
            session,
            usage_id=reservation_id,
            input_tokens=result.prompt_tokens,
            output_tokens=result.completion_tokens,
        )
        await session.commit()
        return result
