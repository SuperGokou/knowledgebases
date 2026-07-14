from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.config import Settings
from app.db.base import Base
from app.db.models import (
    File,
    FileStatus,
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeEntry,
    KnowledgeIngestionStatus,
    LlmBudgetPolicy,
    LlmModelPrice,
    LlmUsageRecord,
    LlmUsageStatus,
    OkfConversionJob,
    OkfConversionStatus,
    User,
)
from app.services.deepseek import DeepSeekClient, DeepSeekResult, OkfConceptDraft
from app.services.document_parser import ParsedDocument, ParseLimits
from app.services.knowledge_bases import search_knowledge_entries
from app.services.llm_egress_policy import external_llm_egress_allowed
from app.services.llm_provider import LlmProviderError, MeteringOutcome
from app.services.llm_usage import LlmUsageDimensions, LlmUsageGovernance
from app.services.okf_conversion import (
    PROMPT_VERSION,
    _persist_result,
    enqueue_okf_conversion,
    process_okf_conversion_batch,
)


@dataclass
class TextStorage:
    content: bytes

    async def read_bytes(self, *, key: str, max_bytes: int) -> bytes:
        assert key == "objects/source.txt"
        assert len(self.content) <= max_bytes
        return self.content


@dataclass
class TransactionObservingStorage:
    content: bytes
    session: AsyncSession

    async def read_bytes(self, *, key: str, max_bytes: int) -> bytes:
        assert key == "objects/source.txt"
        assert len(self.content) <= max_bytes
        assert not self.session.in_transaction()
        return self.content


class SuccessfulClient:
    configured = True
    provider = "qwen"
    model = "qwen-plus"

    async def compile_okf(self, source_text: str, *, user_id: str) -> DeepSeekResult:
        assert source_text == "Revenue policy: refunds require approval."
        assert user_id.startswith("kb_")
        return DeepSeekResult(
            draft=OkfConceptDraft(
                type="Policy",
                title="Revenue refund policy",
                description="Refunds require approval.",
                tags=["revenue", "refunds"],
                body_markdown="# Policy\n\nRefunds require approval.",
            ),
            model="qwen-plus",
            prompt_tokens=20,
            completion_tokens=30,
            provider="qwen",
        )


class SequencedClient(SuccessfulClient):
    def __init__(self, errors: list[LlmProviderError]) -> None:
        self.errors = errors
        self.calls = 0

    async def compile_okf(self, source_text: str, *, user_id: str) -> DeepSeekResult:
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return await super().compile_okf(source_text, user_id=user_id)


async def _create_external_conversion(session: AsyncSession) -> OkfConversionJob:
    user = User(email=f"owner-{uuid4()}@example.com", password_hash="hash")
    session.add(user)
    await session.flush()
    kb = KnowledgeBase(
        owner_id=user.id,
        name="Retry policies",
        external_llm_processing_enabled=True,
    )
    session.add(kb)
    await session.flush()
    session.add_all(
        [
            LlmModelPrice(
                provider="qwen",
                model="qwen-plus",
                input_micro_usd_per_million_tokens=1_000_000,
                output_micro_usd_per_million_tokens=2_000_000,
                active=True,
            ),
            LlmBudgetPolicy(
                name="OKF retry budget",
                tenant_key="default",
                daily_token_limit=100_000,
                monthly_token_limit=1_000_000,
                daily_cost_limit_micro_usd=100_000,
                monthly_cost_limit_micro_usd=1_000_000,
                enabled=True,
            ),
        ]
    )
    file = File(
        owner_id=user.id,
        knowledge_base_id=kb.id,
        bucket="kb",
        object_key="objects/source.txt",
        original_name="source.txt",
        extension=".txt",
        content_type="text/plain",
        size_bytes=42,
        status=FileStatus.PROCESSING,
    )
    session.add(file)
    await session.flush()
    job = await enqueue_okf_conversion(session, file)
    assert job is not None
    await session.commit()
    return job


@pytest.mark.asyncio
async def test_explicit_non_billable_retry_uses_a_new_attempt_key_and_can_succeed() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        job = await _create_external_conversion(session)
        client = SequencedClient(
            [
                LlmProviderError(
                    "llm_upstream_error",
                    provider="qwen",
                    retryable=True,
                    upstream_status=429,
                    metering_outcome=MeteringOutcome.NOT_STARTED,
                )
            ]
        )
        settings = Settings(environment="test")

        assert (
            await process_okf_conversion_batch(
                session,
                TextStorage(b"Revenue policy: refunds require approval."),  # type: ignore[arg-type]
                client,  # type: ignore[arg-type]
                settings,
                batch_size=1,
            )
            == 1
        )
        await session.refresh(job)
        assert job.status is OkfConversionStatus.RETRY_WAIT
        job.next_attempt_at = None
        await session.commit()

        assert (
            await process_okf_conversion_batch(
                session,
                TextStorage(b"Revenue policy: refunds require approval."),  # type: ignore[arg-type]
                client,  # type: ignore[arg-type]
                settings,
                batch_size=1,
            )
            == 1
        )
        await session.refresh(job)
        assert job.status.value == OkfConversionStatus.SUCCEEDED.value
        usages = list(
            (
                await session.scalars(select(LlmUsageRecord).order_by(LlmUsageRecord.created_at))
            ).all()
        )
        assert [usage.status for usage in usages] == [
            LlmUsageStatus.RELEASED,
            LlmUsageStatus.SETTLED,
        ]
        assert len({usage.idempotency_hash for usage in usages}) == 2
        assert client.calls == 2
    await engine.dispose()


@pytest.mark.asyncio
async def test_unknown_transport_outcome_is_terminal_and_never_auto_retried() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        job = await _create_external_conversion(session)
        client = SequencedClient(
            [
                LlmProviderError(
                    "llm_transport_error",
                    provider="qwen",
                    retryable=True,
                    metering_outcome=MeteringOutcome.UNKNOWN,
                )
            ]
        )
        settings = Settings(environment="test")

        assert (
            await process_okf_conversion_batch(
                session,
                TextStorage(b"Revenue policy: refunds require approval."),  # type: ignore[arg-type]
                client,  # type: ignore[arg-type]
                settings,
                batch_size=1,
            )
            == 1
        )
        await session.refresh(job)
        assert job.status is OkfConversionStatus.FAILED
        assert job.error_code == "llm_transport_error"
        assert (
            await process_okf_conversion_batch(
                session,
                TextStorage(b"Revenue policy: refunds require approval."),  # type: ignore[arg-type]
                client,  # type: ignore[arg-type]
                settings,
                batch_size=1,
            )
            == 0
        )
        assert client.calls == 1
        usage = await session.scalar(select(LlmUsageRecord))
        assert usage is not None
        assert usage.status is LlmUsageStatus.INDETERMINATE
    await engine.dispose()


@pytest.mark.asyncio
async def test_conversion_creates_valid_okf_entry_and_is_idempotent() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        user = User(email="owner@example.com", password_hash="hash")
        session.add(user)
        await session.flush()
        kb = KnowledgeBase(
            owner_id=user.id,
            name="Policies",
            external_llm_processing_enabled=True,
        )
        session.add(kb)
        await session.flush()
        session.add_all(
            [
                LlmModelPrice(
                    provider="qwen",
                    model="qwen-plus",
                    input_micro_usd_per_million_tokens=1_000_000,
                    output_micro_usd_per_million_tokens=2_000_000,
                    active=True,
                ),
                LlmBudgetPolicy(
                    name="OKF tenant budget",
                    tenant_key="default",
                    daily_token_limit=100_000,
                    monthly_token_limit=1_000_000,
                    daily_cost_limit_micro_usd=100_000,
                    monthly_cost_limit_micro_usd=1_000_000,
                    enabled=True,
                ),
            ]
        )
        file = File(
            owner_id=user.id,
            knowledge_base_id=kb.id,
            bucket="kb",
            object_key="objects/source.txt",
            original_name="source.txt",
            extension=".txt",
            content_type="text/plain",
            size_bytes=42,
            status=FileStatus.PROCESSING,
        )
        session.add(file)
        await session.flush()
        first = await enqueue_okf_conversion(session, file)
        second = await enqueue_okf_conversion(session, file)
        assert first is not None and second is first
        await session.commit()

        count = await process_okf_conversion_batch(
            session,
            TextStorage(b"Revenue policy: refunds require approval."),  # type: ignore[arg-type]
            SuccessfulClient(),  # type: ignore[arg-type]
            Settings(environment="test"),
            batch_size=1,
        )
        assert count == 1
        usage = await session.scalar(
            select(LlmUsageRecord).where(LlmUsageRecord.operation == "okf.compile")
        )
        assert usage is not None
        assert usage.status is LlmUsageStatus.SETTLED
        assert usage.actual_token_count == 50
        await session.refresh(first)
        assert first.status is OkfConversionStatus.SUCCEEDED
        assert first.output_entry_id is not None
        entry = await session.get(KnowledgeEntry, first.output_entry_id)
        assert entry is not None
        assert entry.format_version == "okf/0.1"
        assert entry.custom_metadata["okf_version"] == "0.1"
        assert entry.custom_metadata["resource"] == f"kb-file://{file.id}"
        assert entry.custom_metadata["generator"]["prompt_version"] == PROMPT_VERSION
        assert entry.custom_metadata["generator"]["provider"] == "qwen"
        assert entry.custom_metadata["generator"]["model"] == "qwen-plus"
        assert entry.publication_status.value == "draft"
        assert await search_knowledge_entries(session, kb.id, query="refund", limit=5) == []
        file.status = FileStatus.AVAILABLE
        entry.publication_status = entry.publication_status.PUBLISHED
        await session.commit()
        hits = await search_knowledge_entries(session, kb.id, query="refund", limit=5)
        assert [hit.entry_id for hit in hits] == [entry.id]

        assert (
            await process_okf_conversion_batch(
                session,
                TextStorage(b"unused"),  # type: ignore[arg-type]
                SuccessfulClient(),  # type: ignore[arg-type]
                Settings(environment="test"),
                batch_size=1,
            )
            == 0
        )
    await engine.dispose()


@pytest.mark.asyncio
async def test_conversion_releases_database_transaction_before_object_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        job = await _create_external_conversion(session)

        def observed_parser(
            raw: bytes,
            extension: str,
            limits: ParseLimits,
        ) -> ParsedDocument:
            assert not session.in_transaction()
            assert extension == ".txt"
            assert len(raw) <= limits.max_source_bytes
            return ParsedDocument(
                text=raw.decode("utf-8"),
                source_locations=("line:1",),
                parser="transaction-observer",
            )

        monkeypatch.setattr("app.services.okf_conversion.parse_document", observed_parser)

        class TransactionObservingClient(SuccessfulClient):
            async def compile_okf(self, source_text: str, *, user_id: str) -> DeepSeekResult:
                assert not session.in_transaction()
                return await super().compile_okf(source_text, user_id=user_id)

        assert await process_okf_conversion_batch(
            session,
            TransactionObservingStorage(
                b"Revenue policy: refunds require approval.",
                session,
            ),  # type: ignore[arg-type]
            TransactionObservingClient(),  # type: ignore[arg-type]
            Settings(environment="test"),
            batch_size=1,
        ) == 1

        await session.refresh(job)
        assert job.status is OkfConversionStatus.SUCCEEDED
    await engine.dispose()


@pytest.mark.asyncio
async def test_replaced_lease_during_object_read_cannot_egress_or_publish() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        job = await _create_external_conversion(session)
        job_id = job.id
        replacement_lease = uuid4()

        class LeaseReplacingStorage(TextStorage):
            async def read_bytes(self, *, key: str, max_bytes: int) -> bytes:
                assert not session.in_transaction()
                async with factory() as concurrent_session:
                    persisted = await concurrent_session.get(OkfConversionJob, job_id)
                    assert persisted is not None
                    persisted.lease_id = replacement_lease
                    await concurrent_session.commit()
                return await super().read_bytes(key=key, max_bytes=max_bytes)

        client = SequencedClient([])
        assert await process_okf_conversion_batch(
            session,
            LeaseReplacingStorage(b"Revenue policy: refunds require approval."),  # type: ignore[arg-type]
            client,  # type: ignore[arg-type]
            Settings(environment="test"),
            batch_size=1,
        ) == 1

        await session.refresh(job)
        assert job.status is OkfConversionStatus.PROCESSING
        assert job.lease_id == replacement_lease
        assert job.output_entry_id is None
        assert client.calls == 0
        assert await session.scalar(select(KnowledgeEntry)) is None
        assert await session.scalar(select(LlmUsageRecord)) is None
    await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutated_field", ["object_key", "status", "version", "deleted_at"])
async def test_replaced_file_identity_during_object_read_cannot_egress_or_publish(
    mutated_field: str,
) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        job = await _create_external_conversion(session)
        file_id = job.file_id

        class FileReplacingStorage(TextStorage):
            async def read_bytes(self, *, key: str, max_bytes: int) -> bytes:
                assert not session.in_transaction()
                async with factory() as concurrent_session:
                    persisted = await concurrent_session.get(File, file_id)
                    assert persisted is not None
                    if mutated_field == "object_key":
                        persisted.object_key = "objects/replaced.txt"
                    elif mutated_field == "status":
                        persisted.status = FileStatus.FAILED
                    elif mutated_field == "version":
                        persisted.version += 1
                    else:
                        persisted.deleted_at = datetime.now(UTC)
                    await concurrent_session.commit()
                return await super().read_bytes(key=key, max_bytes=max_bytes)

        client = SequencedClient([])
        assert await process_okf_conversion_batch(
            session,
            FileReplacingStorage(b"Revenue policy: refunds require approval."),  # type: ignore[arg-type]
            client,  # type: ignore[arg-type]
            Settings(environment="test"),
            batch_size=1,
        ) == 1

        assert client.calls == 0
        assert await session.scalar(select(KnowledgeEntry)) is None
        assert await session.scalar(select(LlmUsageRecord)) is None
    await engine.dispose()


@pytest.mark.asyncio
async def test_lease_replaced_inside_egress_policy_cancels_provider_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        job = await _create_external_conversion(session)
        job_id = job.id
        replacement_lease = uuid4()

        async def replacing_policy(
            policy_session: AsyncSession,
            *,
            user_id: UUID,
            knowledge_base_id: UUID,
            api_key_id: UUID | None,
            required_permission: str | None,
            minimum_access: KnowledgeBaseAccessLevel,
        ) -> bool:
            async with factory() as concurrent_session:
                persisted = await concurrent_session.get(OkfConversionJob, job_id)
                assert persisted is not None
                persisted.lease_id = replacement_lease
                await concurrent_session.commit()
            return await external_llm_egress_allowed(
                policy_session,
                user_id=user_id,
                knowledge_base_id=knowledge_base_id,
                api_key_id=api_key_id,
                required_permission=required_permission,
                minimum_access=minimum_access,
            )

        monkeypatch.setattr(
            "app.services.okf_conversion.external_llm_egress_allowed",
            replacing_policy,
        )
        client = SequencedClient([])

        assert await process_okf_conversion_batch(
            session,
            TextStorage(b"Revenue policy: refunds require approval."),  # type: ignore[arg-type]
            client,  # type: ignore[arg-type]
            Settings(environment="test"),
            batch_size=1,
        ) == 1

        await session.refresh(job)
        assert job.status is OkfConversionStatus.PROCESSING
        assert job.lease_id == replacement_lease
        assert job.output_entry_id is None
        assert client.calls == 0
        assert await session.scalar(select(KnowledgeEntry)) is None
        usage = await session.scalar(select(LlmUsageRecord))
        assert usage is not None
        assert usage.status is LlmUsageStatus.RELEASED
    await engine.dispose()


@pytest.mark.asyncio
async def test_file_identity_changed_after_provider_cannot_publish_result() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        job = await _create_external_conversion(session)
        file_id = job.file_id

        class FileReplacingClient(SequencedClient):
            async def compile_okf(self, source_text: str, *, user_id: str) -> DeepSeekResult:
                result = await super().compile_okf(source_text, user_id=user_id)
                assert not session.in_transaction()
                async with factory() as concurrent_session:
                    persisted = await concurrent_session.get(File, file_id)
                    assert persisted is not None
                    persisted.version += 1
                    await concurrent_session.commit()
                return result

        client = FileReplacingClient([])
        assert await process_okf_conversion_batch(
            session,
            TextStorage(b"Revenue policy: refunds require approval."),  # type: ignore[arg-type]
            client,  # type: ignore[arg-type]
            Settings(environment="test"),
            batch_size=1,
        ) == 1

        await session.refresh(job)
        assert job.status is OkfConversionStatus.PROCESSING
        assert job.output_entry_id is None
        assert client.calls == 1
        assert await session.scalar(select(KnowledgeEntry)) is None
        usage = await session.scalar(select(LlmUsageRecord))
        assert usage is not None
        assert usage.status is LlmUsageStatus.SETTLED
    await engine.dispose()


@pytest.mark.asyncio
async def test_active_okf_egress_lease_blocks_stale_worker_reclaim() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        job = await _create_external_conversion(session)
        file = await session.get(File, job.file_id)
        assert file is not None and file.knowledge_base_id is not None
        original_lease = uuid4()
        job.status = OkfConversionStatus.PROCESSING
        job.lease_id = original_lease
        job.locked_at = datetime.now(UTC) - timedelta(hours=1)
        await LlmUsageGovernance().reserve(
            session,
            dimensions=LlmUsageDimensions(
                tenant_key="default",
                user_id=file.owner_id,
                api_key_id=None,
                knowledge_base_id=file.knowledge_base_id,
                provider="qwen",
                model="qwen-plus",
                operation="okf.compile",
            ),
            idempotency_key="active-okf-egress",
            estimated_input_tokens=100,
            maximum_output_tokens=100,
        )
        await session.commit()

        assert await process_okf_conversion_batch(
            session,
            TextStorage(b"must not be read"),  # type: ignore[arg-type]
            SuccessfulClient(),  # type: ignore[arg-type]
            Settings(environment="test", okf_conversion_lease_seconds=60),
            batch_size=1,
        ) == 0

        await session.refresh(job)
        assert job.status is OkfConversionStatus.PROCESSING
        assert job.lease_id == original_lease
        assert job.attempts == 0
    await engine.dispose()


@pytest.mark.asyncio
async def test_binary_format_is_not_sent_to_model() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        user = User(email="owner@example.com", password_hash="hash")
        session.add(user)
        await session.flush()
        kb = KnowledgeBase(owner_id=user.id, name="Documents")
        session.add(kb)
        await session.flush()
        file = File(
            owner_id=user.id,
            knowledge_base_id=kb.id,
            bucket="kb",
            object_key="objects/source.pdf",
            original_name="source.pdf",
            extension=".pdf",
            content_type="application/pdf",
            size_bytes=100,
            status=FileStatus.PROCESSING,
        )
        session.add(file)
        await session.flush()
        job = OkfConversionJob(
            file_id=file.id,
            knowledge_base_id=kb.id,
            file_version=1,
            prompt_version=PROMPT_VERSION,
        )
        session.add(job)
        await session.commit()
        assert (
            await process_okf_conversion_batch(
                session,
                TextStorage(b"must not be read"),  # type: ignore[arg-type]
                None,
                Settings(environment="test", external_llm_enabled=False),
                batch_size=1,
            )
            == 1
        )
        await session.refresh(job)
        assert job.status is OkfConversionStatus.UNSUPPORTED
        assert job.error_code == "parser_pdf_capability_unavailable"
    await engine.dispose()


@pytest.mark.asyncio
async def test_isolated_text_conversion_uses_local_deterministic_compiler() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        user = User(email="isolated@example.com", password_hash="hash")
        session.add(user)
        await session.flush()
        kb = KnowledgeBase(
            owner_id=user.id,
            name="Isolated documents",
            external_llm_processing_enabled=False,
        )
        session.add(kb)
        await session.flush()
        file = File(
            owner_id=user.id,
            knowledge_base_id=kb.id,
            bucket="kb",
            object_key="objects/source.txt",
            original_name="company-profile.txt",
            extension=".txt",
            content_type="text/plain",
            size_bytes=32,
            status=FileStatus.PROCESSING,
        )
        session.add(file)
        await session.flush()
        job = await enqueue_okf_conversion(session, file)
        assert job is not None
        await session.commit()

        processed = await process_okf_conversion_batch(
            session,
            TextStorage("江苏和熠光显有限公司成立于2023年。".encode()),  # type: ignore[arg-type]
            None,
            Settings(environment="test", external_llm_enabled=False),
            batch_size=1,
        )

        assert processed == 1
        await session.refresh(job)
        assert job.status is OkfConversionStatus.SUCCEEDED
        assert job.output_entry_id is not None
        entry = await session.get(KnowledgeEntry, job.output_entry_id)
        assert entry is not None
        await session.refresh(file)
        assert file.knowledge_status is KnowledgeIngestionStatus.DRAFT_READY
        assert "江苏和熠光显有限公司" in entry.content
        assert entry.custom_metadata["generator"] == {
            "provider": "local",
            "model": "local-deterministic-v1",
            "prompt_version": PROMPT_VERSION,
        }
        assert entry.publication_status.value == "draft"
    await engine.dispose()


def test_deepseek_is_disabled_without_server_side_key() -> None:
    client = DeepSeekClient(Settings(environment="test", deepseek_api_key=None))
    assert client.configured is False


@pytest.mark.asyncio
async def test_stale_lease_cannot_publish_result() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        user = User(email="lease@example.com", password_hash="hash")
        session.add(user)
        await session.flush()
        kb = KnowledgeBase(
            owner_id=user.id,
            name="Lease test",
            external_llm_processing_enabled=True,
        )
        session.add(kb)
        await session.flush()
        file = File(
            owner_id=user.id,
            knowledge_base_id=kb.id,
            bucket="kb",
            object_key="objects/source.txt",
            original_name="source.txt",
            extension=".txt",
            content_type="text/plain",
            size_bytes=1,
            status=FileStatus.PROCESSING,
        )
        session.add(file)
        await session.flush()
        current_lease = uuid4()
        stale_lease = uuid4()
        job = OkfConversionJob(
            file_id=file.id,
            knowledge_base_id=kb.id,
            file_version=1,
            prompt_version=PROMPT_VERSION,
            status=OkfConversionStatus.PROCESSING,
            lease_id=current_lease,
        )
        session.add(job)
        await session.commit()
        result = await SuccessfulClient().compile_okf(
            "Revenue policy: refunds require approval.", user_id=f"kb_{kb.id.hex}"
        )
        await _persist_result(session, job.id, stale_lease, file, result)
        await session.refresh(job)
        assert job.status is OkfConversionStatus.PROCESSING
        assert job.lease_id == current_lease
        assert job.output_entry_id is None
    await engine.dispose()


@pytest.mark.asyncio
async def test_available_file_cannot_make_model_result_auto_publish() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        user = User(email="published-source@example.com", password_hash="hash")
        session.add(user)
        await session.flush()
        kb = KnowledgeBase(owner_id=user.id, name="Published source")
        session.add(kb)
        await session.flush()
        file = File(
            owner_id=user.id,
            knowledge_base_id=kb.id,
            bucket="kb",
            object_key="objects/source.txt",
            original_name="source.txt",
            extension=".txt",
            content_type="text/plain",
            size_bytes=1,
            status=FileStatus.AVAILABLE,
        )
        session.add(file)
        await session.flush()
        lease_id = uuid4()
        job = OkfConversionJob(
            file_id=file.id,
            knowledge_base_id=kb.id,
            file_version=1,
            prompt_version=PROMPT_VERSION,
            status=OkfConversionStatus.PROCESSING,
            lease_id=lease_id,
        )
        session.add(job)
        await session.commit()

        result = await SuccessfulClient().compile_okf(
            "Revenue policy: refunds require approval.", user_id=f"kb_{kb.id.hex}"
        )
        await _persist_result(session, job.id, lease_id, file, result)

        await session.refresh(job)
        assert job.status is OkfConversionStatus.SUCCEEDED
        assert job.output_entry_id is not None
        entry = await session.get(KnowledgeEntry, job.output_entry_id)
        assert entry is not None
        assert entry.publication_status.value == "draft"
    await engine.dispose()


def test_okf_draft_rejects_unknown_model_fields() -> None:
    with pytest.raises(ValueError):
        OkfConceptDraft.model_validate(
            {
                "type": "Reference",
                "title": "T",
                "description": "D",
                "tags": [],
                "body_markdown": "Body",
                "unexpected": "not persisted",
            }
        )
