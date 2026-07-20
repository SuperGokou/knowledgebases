from __future__ import annotations

import io
import zipfile
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
    OkfConversionStatus,
    User,
)
from app.services.document_parser import (
    compute_source_locations_sha256,
    compute_source_text_sha256,
)
from app.services.okf_conversion import enqueue_okf_conversion, process_okf_conversion_batch


class MemoryStorage:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    async def read_bytes(self, *, key: str, max_bytes: int) -> bytes:
        assert key == "objects/source.docx"
        if len(self.payload) > max_bytes:
            raise ValueError("object exceeds maximum size")
        return self.payload


def _docx() -> bytes:
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        archive.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/'
            'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>'
            "采购金额不得超过42万元</w:t></w:r></w:p></w:body></w:document>",
        )
    return target.getvalue()


@pytest.mark.asyncio
async def test_docx_runs_through_okf_and_persists_parser_provenance() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        user = User(email=f"owner-{uuid4()}@example.com", password_hash="hash")
        session.add(user)
        await session.flush()
        knowledge_base = KnowledgeBase(
            owner_id=user.id,
            name="Office documents",
            external_llm_processing_enabled=False,
        )
        session.add(knowledge_base)
        await session.flush()
        payload = _docx()
        file = File(
            owner_id=user.id,
            knowledge_base_id=knowledge_base.id,
            bucket="kb",
            object_key="objects/source.docx",
            original_name="purchase-policy.docx",
            extension=".docx",
            content_type=(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
            size_bytes=len(payload),
            status=FileStatus.PROCESSING,
        )
        session.add(file)
        await session.flush()
        job = await enqueue_okf_conversion(session, file)
        assert job is not None
        await session.commit()

        processed = await process_okf_conversion_batch(
            session,
            MemoryStorage(payload),  # type: ignore[arg-type]
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
        assert "[paragraph:1]" in entry.content
        assert "采购金额不得超过42万元" in entry.content
        assert entry.custom_metadata["source_parser"] == "ooxml-docx"
        assert entry.custom_metadata["source_locations"] == ["paragraph:1"]
        assert entry.custom_metadata["source_location_count"] == 1
        assert entry.custom_metadata["source_locations_truncated"] is False
        source_text_length = entry.custom_metadata["source_text_length"]
        assert isinstance(source_text_length, int)
        source_text = entry.content[-source_text_length:]
        assert entry.custom_metadata["source_text_sha256"] == compute_source_text_sha256(
            source_text
        )
        assert entry.custom_metadata["source_locations_sha256"] == compute_source_locations_sha256(
            ("paragraph:1",)
        )
    await engine.dispose()
