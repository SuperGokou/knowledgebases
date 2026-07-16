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


@pytest.mark.asyncio
async def test_chinese_contact_query_ranks_specific_contact_content_and_focuses_excerpt() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with factory() as session:
        user = User(email="contact-search@example.com", password_hash="hash")
        session.add(user)
        await session.flush()
        knowledge_base = KnowledgeBase(owner_id=user.id, name="企业资料")
        session.add(knowledge_base)
        await session.flush()
        contact_entry = KnowledgeEntry(
            knowledge_base_id=knowledge_base.id,
            entry_type="CompanyProfile",
            title="公司概况",
            content=(
                "# 公司概况\n\n江苏和熠光显有限公司专注于显示模组研发。\n\n"
                "## 联系方式\n\n| 项目 | 信息 |\n| --- | --- |\n"
                "| 联系人 | 张经理 |\n| 联系电话 | 0514-00000000 |\n"
            ),
            publication_status=KnowledgeEntryPublicationStatus.PUBLISHED,
        )
        platform_entry = KnowledgeEntry(
            knowledge_base_id=knowledge_base.id,
            entry_type="Capability",
            title="平台能力概览",
            content="本公司企业知识中台提供账号管理、文件信息和模型切换能力。",
            publication_status=KnowledgeEntryPublicationStatus.PUBLISHED,
        )
        session.add_all([platform_entry, contact_entry])
        await session.commit()

        hits = await search_knowledge_entries(
            session,
            knowledge_base.id,
            query="公司联系人信息",
            limit=5,
        )

        assert hits[0].entry_id == contact_entry.id
        assert "联系人" in hits[0].excerpt
        assert all(hit.entry_id != platform_entry.id for hit in hits)

    await engine.dispose()


@pytest.mark.asyncio
async def test_weak_two_character_overlap_does_not_fabricate_an_answer() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with factory() as session:
        user = User(email="no-answer-search@example.com", password_hash="hash")
        session.add(user)
        await session.flush()
        knowledge_base = KnowledgeBase(owner_id=user.id, name="合成检索资料")
        session.add(knowledge_base)
        await session.flush()
        session.add(
            KnowledgeEntry(
                knowledge_base_id=knowledge_base.id,
                entry_type="SyntheticEvaluation",
                title="珊瑚车间包装作业",
                content="珊瑚车间只记录显示模组包装流程。",
                publication_status=KnowledgeEntryPublicationStatus.PUBLISHED,
            )
        )
        await session.commit()

        hits = await search_knowledge_entries(
            session,
            knowledge_base.id,
            query="深海珊瑚邮局的潜水邮票面值是多少？",
            limit=5,
        )
        exact_hits = await search_knowledge_entries(
            session,
            knowledge_base.id,
            query="珊瑚",
            limit=5,
        )

        assert hits == []
        assert len(exact_hits) == 1
        assert exact_hits[0].title == "珊瑚车间包装作业"

    await engine.dispose()
