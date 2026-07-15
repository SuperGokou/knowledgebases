from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import KnowledgeBase, KnowledgeEntry, QuotaCounter, User
from app.domain.errors import QuotaExceeded
from app.services.knowledge_entry_quota import consume_manual_entry_storage_quota
from app.services.quota import lifetime_window_start
from scripts.postgres_acceptance import assert_acceptance_database

_POSTGRES_URL = os.getenv("KB_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not _POSTGRES_URL,
    reason="KB_TEST_POSTGRES_URL is required for storage quota row-lock verification",
)


@dataclass(frozen=True, slots=True)
class _QuotaScenario:
    factory: async_sessionmaker[AsyncSession]
    user_id: UUID
    knowledge_base_id: UUID


@pytest_asyncio.fixture
async def quota_scenario() -> AsyncIterator[_QuotaScenario]:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=3, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        user = User(
            email=f"manual-entry-quota-{uuid4()}@example.com",
            password_hash="unused",
        )
        session.add(user)
        await session.flush()
        knowledge_base = KnowledgeBase(
            owner_id=user.id,
            name=f"manual-entry-quota-{uuid4()}",
        )
        session.add(knowledge_base)
        await session.flush()
        scenario = _QuotaScenario(
            factory=factory,
            user_id=user.id,
            knowledge_base_id=knowledge_base.id,
        )
        await session.commit()

    try:
        yield scenario
    finally:
        async with factory() as session:
            await session.execute(
                delete(KnowledgeEntry).where(
                    KnowledgeEntry.knowledge_base_id == scenario.knowledge_base_id
                )
            )
            await session.execute(
                delete(QuotaCounter).where(QuotaCounter.user_id == scenario.user_id)
            )
            await session.execute(
                delete(KnowledgeBase).where(KnowledgeBase.id == scenario.knowledge_base_id)
            )
            await session.execute(delete(User).where(User.id == scenario.user_id))
            await session.commit()
        await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_manual_entry_quota_has_exactly_one_concurrent_winner(
    quota_scenario: _QuotaScenario,
) -> None:
    # Pre-create the shared counter so this test exercises the row lock itself,
    # rather than relying on INSERT ... ON CONFLICT to serialize first use.
    async with quota_scenario.factory() as session:
        session.add(
            QuotaCounter(
                user_id=quota_scenario.user_id,
                limit_key="storage_bytes",
                window_start=lifetime_window_start(),
                used_value=0,
                reserved_value=0,
            )
        )
        await session.commit()

    start = asyncio.Event()

    async def write_entry(title: str) -> str:
        async with quota_scenario.factory() as session:
            await start.wait()
            try:
                await consume_manual_entry_storage_quota(
                    session,
                    user_id=quota_scenario.user_id,
                    storage_limit=3,
                    previous_content=None,
                    next_content="你",
                )
                session.add(
                    KnowledgeEntry(
                        knowledge_base_id=quota_scenario.knowledge_base_id,
                        entry_type="manual",
                        title=title,
                        content="你",
                    )
                )
                await session.commit()
                return "committed"
            except QuotaExceeded:
                await session.rollback()
                return "quota_exceeded"

    tasks = [
        asyncio.create_task(write_entry("first contender")),
        asyncio.create_task(write_entry("second contender")),
    ]
    start.set()
    assert sorted(await asyncio.gather(*tasks)) == ["committed", "quota_exceeded"]

    async with quota_scenario.factory() as session:
        entry_count = await session.scalar(
            select(func.count(KnowledgeEntry.id)).where(
                KnowledgeEntry.knowledge_base_id == quota_scenario.knowledge_base_id
            )
        )
        counter = await session.scalar(
            select(QuotaCounter).where(
                QuotaCounter.user_id == quota_scenario.user_id,
                QuotaCounter.limit_key == "storage_bytes",
            )
        )
        assert entry_count == 1
        assert counter is not None
        assert counter.used_value == 3
        assert counter.reserved_value == 0


@pytest.mark.asyncio
async def test_postgres_manual_entry_quota_rolls_back_with_entry_transaction(
    quota_scenario: _QuotaScenario,
) -> None:
    async with quota_scenario.factory() as session:
        await consume_manual_entry_storage_quota(
            session,
            user_id=quota_scenario.user_id,
            storage_limit=3,
            previous_content=None,
            next_content="你",
        )
        session.add(
            KnowledgeEntry(
                knowledge_base_id=quota_scenario.knowledge_base_id,
                entry_type="manual",
                title="must roll back",
                content="你",
            )
        )
        await session.flush()
        await session.rollback()

    async with quota_scenario.factory() as session:
        counter = await session.scalar(
            select(QuotaCounter).where(
                QuotaCounter.user_id == quota_scenario.user_id,
                QuotaCounter.limit_key == "storage_bytes",
            )
        )
        entry_count = await session.scalar(
            select(func.count(KnowledgeEntry.id)).where(
                KnowledgeEntry.knowledge_base_id == quota_scenario.knowledge_base_id
            )
        )
        assert counter is None
        assert entry_count == 0

    async with quota_scenario.factory() as session:
        await consume_manual_entry_storage_quota(
            session,
            user_id=quota_scenario.user_id,
            storage_limit=3,
            previous_content=None,
            next_content="你",
        )
        session.add(
            KnowledgeEntry(
                knowledge_base_id=quota_scenario.knowledge_base_id,
                entry_type="manual",
                title="committed retry",
                content="你",
            )
        )
        await session.commit()

    async with quota_scenario.factory() as session:
        counter = await session.scalar(
            select(QuotaCounter).where(
                QuotaCounter.user_id == quota_scenario.user_id,
                QuotaCounter.limit_key == "storage_bytes",
            )
        )
        assert counter is not None
        assert counter.used_value == 3
