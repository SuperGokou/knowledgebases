from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import (
    KnowledgeBase,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
    User,
)
from app.services.knowledge_bases import search_knowledge_entries


@pytest.mark.asyncio
async def test_chinese_sentence_query_matches_relevant_published_entry() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with factory() as session:
        user = User(email="search@example.com", password_hash="hash")
        session.add(user)
        await session.flush()
        knowledge_base = KnowledgeBase(owner_id=user.id, name="产品知识")
        session.add(knowledge_base)
        await session.flush()
        entry = KnowledgeEntry(
            knowledge_base_id=knowledge_base.id,
            entry_type="Capability",
            title="平台能力概览",
            content="平台支持 DeepSeek、Qwen、MiniMax 模型切换和动态权限管理。",
            publication_status=KnowledgeEntryPublicationStatus.PUBLISHED,
        )
        session.add(entry)
        await session.commit()

        hits = await search_knowledge_entries(
            session,
            knowledge_base.id,
            query="平台支持哪些模型切换和权限管理能力？",
            limit=5,
        )

        assert [hit.entry_id for hit in hits] == [entry.id]

    await engine.dispose()
