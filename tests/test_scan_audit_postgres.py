from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings
from app.db.models import File, FileStatus, MalwareScanStatus, OkfConversionJob, User
from app.db.runtime_role import reconcile_runtime_role_privileges
from app.maintenance import process_malware_scan_batch
from app.services.malware_scanner import ScanResult, ScanVerdict
from scripts.postgres_acceptance import assert_acceptance_database

_POSTGRES_URL = os.getenv("KB_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not _POSTGRES_URL,
    reason="KB_TEST_POSTGRES_URL is required for PostgreSQL concurrency verification",
)


class _Storage:
    def iter_chunks(self, *, key: str, chunk_size: int) -> AsyncIterator[bytes]:
        del key, chunk_size

        async def _chunks() -> AsyncIterator[bytes]:
            yield b"clean"

        return _chunks()


async def _fresh_factory() -> async_sessionmaker[AsyncSession]:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=4, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    return async_sessionmaker(engine, expire_on_commit=False)


async def _insert_quarantined_file(
    factory: async_sessionmaker[AsyncSession],
) -> File:
    async with factory() as session:
        owner = User(email=f"{uuid4()}@example.com", password_hash="unused")
        session.add(owner)
        await session.flush()
        file = File(
            owner_id=owner.id,
            bucket="kb",
            object_key=f"objects/{uuid4()}.txt",
            original_name="concurrent.txt",
            extension=".txt",
            content_type="text/plain",
            size_bytes=5,
            status=FileStatus.QUARANTINED,
        )
        session.add(file)
        await session.commit()
        return file


@pytest.mark.asyncio
async def test_postgres_two_workers_cannot_claim_the_same_malware_scan() -> None:
    factory = await _fresh_factory()
    file = await _insert_quarantined_file(factory)
    started = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    class BlockingScanner:
        async def scan(self, chunks: AsyncIterator[bytes]) -> ScanResult:
            nonlocal calls
            assert [chunk async for chunk in chunks]
            calls += 1
            started.set()
            await release.wait()
            return ScanResult(verdict=ScanVerdict.CLEAN)

    settings = Settings(environment="test", maintenance_batch_size=1)

    async def run_worker() -> int:
        async with factory() as session:
            return await process_malware_scan_batch(
                session,
                _Storage(),  # type: ignore[arg-type]
                BlockingScanner(),
                settings,
                batch_size=1,
            )

    first = asyncio.create_task(run_worker())
    await asyncio.wait_for(started.wait(), timeout=5)
    second = asyncio.create_task(run_worker())
    second_result = await asyncio.wait_for(second, timeout=5)
    release.set()
    first_result = await asyncio.wait_for(first, timeout=5)

    assert sorted((first_result, second_result)) == [0, 1]
    assert calls == 1
    async with factory() as session:
        persisted = await session.get(File, file.id)
        assert persisted is not None
        assert persisted.malware_scan_status is MalwareScanStatus.CLEAN
        assert persisted.malware_scan_attempts == 1


@pytest.mark.asyncio
async def test_postgres_stale_malware_result_cannot_overwrite_a_new_lease() -> None:
    factory = await _fresh_factory()
    file = await _insert_quarantined_file(factory)
    started = asyncio.Event()
    release = asyncio.Event()
    replacement_lease = uuid4()

    class BlockingScanner:
        async def scan(self, chunks: AsyncIterator[bytes]) -> ScanResult:
            assert [chunk async for chunk in chunks]
            started.set()
            await release.wait()
            return ScanResult(verdict=ScanVerdict.CLEAN)

    async with factory() as worker_session:
        worker = asyncio.create_task(
            process_malware_scan_batch(
                worker_session,
                _Storage(),  # type: ignore[arg-type]
                BlockingScanner(),
                Settings(environment="test", maintenance_batch_size=1),
                batch_size=1,
            )
        )
        await asyncio.wait_for(started.wait(), timeout=5)
        async with factory() as recovery_session:
            await recovery_session.execute(
                update(File)
                .where(File.id == file.id)
                .values(malware_scan_lease_id=replacement_lease)
            )
            await recovery_session.commit()
        release.set()
        assert await asyncio.wait_for(worker, timeout=5) == 1

    async with factory() as session:
        persisted = await session.get(File, file.id)
        assert persisted is not None
        assert persisted.status is FileStatus.QUARANTINED
        assert persisted.malware_scan_status is MalwareScanStatus.PROCESSING
        assert persisted.malware_scan_lease_id == replacement_lease
        assert (
            await session.scalar(
                select(OkfConversionJob).where(OkfConversionJob.file_id == file.id)
            )
            is None
        )


@pytest.mark.asyncio
async def test_postgres_runtime_role_upgrade_is_idempotent_and_append_only() -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=2, max_overflow=0)
    role_name = f"kb-runtime-{uuid4().hex[:12]}"
    quoted_role = engine.dialect.identifier_preparer.quote(role_name)
    try:
        async with engine.begin() as connection:
            await assert_acceptance_database(connection)
            await connection.execute(text(f"CREATE ROLE {quoted_role}"))
            await connection.execute(text(f"GRANT ALL ON TABLE public.audit_logs TO {quoted_role}"))
            await reconcile_runtime_role_privileges(connection, role_name)
            await reconcile_runtime_role_privileges(connection, role_name)

        async with engine.begin() as connection:
            await connection.execute(text(f"SET ROLE {quoted_role}"))
            await connection.execute(
                text(
                    "INSERT INTO public.audit_logs "
                    "(action, result, resource_type, details) VALUES "
                    "('upgrade.append_test', 'SUCCESS'::audit_result, 'test', '{}'::json)"
                )
            )
            assert (
                await connection.scalar(
                    text(
                        "SELECT count(*) FROM public.audit_logs "
                        "WHERE action = 'upgrade.append_test'"
                    )
                )
                == 1
            )
            await connection.execute(text("RESET ROLE"))

        for statement in (
            "UPDATE public.audit_logs SET action = 'tampered'",
            "DELETE FROM public.audit_logs",
            "TRUNCATE TABLE public.audit_logs",
        ):
            with pytest.raises(DBAPIError):
                async with engine.begin() as connection:
                    await connection.execute(text(f"SET ROLE {quoted_role}"))
                    await connection.execute(text(statement))

        async with engine.begin() as connection:
            await connection.execute(
                text(f"GRANT UPDATE ON TABLE public.audit_logs TO {quoted_role}")
            )
            await connection.execute(
                text("ALTER TABLE public.audit_logs ADD COLUMN reconciliation_probe integer")
            )
            assert (
                await connection.scalar(
                    text("SELECT has_table_privilege(:role_name, 'public.audit_logs', 'UPDATE')"),
                    {"role_name": role_name},
                )
                is False
            )
    finally:
        async with engine.begin() as connection:
            await assert_acceptance_database(connection)
            await connection.execute(text(f"DROP OWNED BY {quoted_role}"))
            await connection.execute(text(f"DROP ROLE IF EXISTS {quoted_role}"))
        await engine.dispose()
