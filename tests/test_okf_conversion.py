from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.config import Settings
from app.db.base import Base
from app.db.models import (
    File,
    FileStatus,
    KnowledgeBase,
    KnowledgeEntry,
    OkfConversionJob,
    OkfConversionStatus,
    User,
)
from app.services.deepseek import DeepSeekClient, DeepSeekResult, OkfConceptDraft
from app.services.knowledge_bases import search_knowledge_entries
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


class SuccessfulClient:
    configured = True

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
            model="deepseek-v4-flash",
            prompt_tokens=20,
            completion_tokens=30,
        )


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
        await session.refresh(first)
        assert first.status is OkfConversionStatus.SUCCEEDED
        assert first.output_entry_id is not None
        entry = await session.get(KnowledgeEntry, first.output_entry_id)
        assert entry is not None
        assert entry.format_version == "okf/0.1"
        assert entry.custom_metadata["okf_version"] == "0.1"
        assert entry.custom_metadata["resource"] == f"kb-file://{file.id}"
        assert entry.custom_metadata["generator"]["prompt_version"] == PROMPT_VERSION
        assert entry.publication_status.value == "draft"
        assert await search_knowledge_entries(
            session, kb.id, query="refund", limit=5
        ) == []
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
                SuccessfulClient(),  # type: ignore[arg-type]
                Settings(environment="test"),
                batch_size=1,
            )
            == 0
        )
        await session.refresh(job)
        assert job.status is OkfConversionStatus.PENDING

        kb.external_llm_processing_enabled = True
        await session.commit()
        await process_okf_conversion_batch(
            session,
            TextStorage(b"must not be read"),  # type: ignore[arg-type]
            SuccessfulClient(),  # type: ignore[arg-type]
            Settings(environment="test"),
            batch_size=1,
        )
        await session.refresh(job)
        assert job.status is OkfConversionStatus.UNSUPPORTED
        assert job.error_code == "parser_required"
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
