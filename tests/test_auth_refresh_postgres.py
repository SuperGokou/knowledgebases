from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.dependencies import redis_dependency
from app.core.security import PasswordService
from app.db.models import RefreshToken, User
from app.db.session import get_db
from app.main import create_app
from scripts.postgres_acceptance import assert_acceptance_database

_POSTGRES_URL = os.getenv("KB_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not _POSTGRES_URL,
    reason="KB_TEST_POSTGRES_URL is required for refresh-token transaction verification",
)


class _FakeRedis:
    def __init__(self) -> None:
        self.counters: dict[str, int] = {}

    async def eval(self, _script: str, _keys: int, key: str, ttl_ms: int) -> list[int]:
        self.counters[key] = self.counters.get(key, 0) + 1
        return [self.counters[key], ttl_ms]


@dataclass(frozen=True, slots=True)
class _PostgresAuthHarness:
    client: httpx.AsyncClient
    session_factory: async_sessionmaker[AsyncSession]
    user_id: UUID
    email: str
    password: str
    application_name: str

    async def login(self) -> dict[str, Any]:
        response = await self.client.post(
            "/api/v1/auth/token",
            data={"username": self.email, "password": self.password},
        )
        assert response.status_code == 200, response.text
        return cast("dict[str, Any]", response.json())


@pytest_asyncio.fixture
async def postgres_auth_harness() -> AsyncIterator[_PostgresAuthHarness]:
    assert _POSTGRES_URL is not None
    unique = uuid4().hex
    application_name = f"kb_auth_refresh_{unique}"
    engine = create_async_engine(
        _POSTGRES_URL,
        pool_size=6,
        max_overflow=0,
        connect_args={"server_settings": {"application_name": application_name}},
    )
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    email = f"refresh-{unique}@example.com"
    password = "Postgres-refresh-acceptance-123!"
    async with session_factory() as session:
        user = User(
            email=email,
            password_hash=PasswordService().hash(password),
        )
        session.add(user)
        await session.commit()
        user_id = user.id

    application = create_app()
    fake_redis = _FakeRedis()

    async def override_db() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    async def override_redis() -> AsyncIterator[_FakeRedis]:
        yield fake_redis

    application.dependency_overrides[get_db] = override_db
    application.dependency_overrides[redis_dependency] = override_redis
    transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            yield _PostgresAuthHarness(
                client=client,
                session_factory=session_factory,
                user_id=user_id,
                email=email,
                password=password,
                application_name=application_name,
            )
    finally:
        application.dependency_overrides.clear()
        async with engine.begin() as connection:
            await assert_acceptance_database(connection)
            await connection.execute(delete(User).where(User.id == user_id))
        await engine.dispose()


async def _wait_for_lock_waiters(
    harness: _PostgresAuthHarness,
    *,
    guard_pid: int,
    expected: int,
) -> None:
    deadline = asyncio.get_running_loop().time() + 5
    while asyncio.get_running_loop().time() < deadline:
        async with harness.session_factory() as observer:
            waiters = int(
                await observer.scalar(
                    text(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE application_name = :application_name "
                        "AND pid <> :guard_pid AND wait_event_type = 'Lock'"
                    ),
                    {
                        "application_name": harness.application_name,
                        "guard_pid": guard_pid,
                    },
                )
                or 0
            )
        if waiters >= expected:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"expected {expected} PostgreSQL lock waiters")


@pytest.mark.asyncio
async def test_postgres_refresh_rotation_persists_a_valid_token_chain(
    postgres_auth_harness: _PostgresAuthHarness,
) -> None:
    tokens = await postgres_auth_harness.login()

    refreshed = await postgres_auth_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert refreshed.status_code == 200, refreshed.text
    async with postgres_auth_harness.session_factory() as session:
        records = list(
            (
                await session.scalars(
                    select(RefreshToken).where(
                        RefreshToken.user_id == postgres_auth_harness.user_id
                    )
                )
            ).all()
        )
    assert len(records) == 2
    original = next(record for record in records if record.parent_id is None)
    replacement = next(record for record in records if record.parent_id == original.id)
    assert original.revoked_at is not None
    assert original.replaced_by_id == replacement.id
    assert replacement.family_id == original.family_id
    assert replacement.revoked_at is None
    assert replacement.reuse_detected_at is None


@pytest.mark.asyncio
async def test_postgres_concurrent_refresh_has_one_winner_and_revokes_the_family(
    postgres_auth_harness: _PostgresAuthHarness,
) -> None:
    tokens = await postgres_auth_harness.login()

    first, second = await asyncio.gather(
        postgres_auth_harness.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        ),
        postgres_auth_harness.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        ),
    )

    assert sorted((first.status_code, second.status_code)) == [200, 401]
    winner = first if first.status_code == 200 else second
    denied = second if first.status_code == 200 else first
    assert denied.json()["error"]["code"] == "refresh_token_reuse_detected"

    revoked_access = await postgres_auth_harness.client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {winner.json()['access_token']}"},
    )
    assert revoked_access.status_code == 401
    assert revoked_access.json()["error"]["code"] == "token_revoked"

    async with postgres_auth_harness.session_factory() as session:
        records = list(
            (
                await session.scalars(
                    select(RefreshToken).where(
                        RefreshToken.user_id == postgres_auth_harness.user_id
                    )
                )
            ).all()
        )
        user = await session.get(User, postgres_auth_harness.user_id)
    assert len(records) == 2
    assert user is not None
    assert user.token_version == 1
    assert all(record.revoked_at is not None for record in records)
    assert all(record.reuse_detected_at is not None for record in records)


@pytest.mark.asyncio
async def test_postgres_concurrent_reuse_across_families_has_no_lost_revocation(
    postgres_auth_harness: _PostgresAuthHarness,
) -> None:
    first_login = await postgres_auth_harness.login()
    second_login = await postgres_auth_harness.login()
    first_rotation = await postgres_auth_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": first_login["refresh_token"]},
    )
    second_rotation = await postgres_auth_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": second_login["refresh_token"]},
    )
    assert first_rotation.status_code == 200, first_rotation.text
    assert second_rotation.status_code == 200, second_rotation.text

    async with postgres_auth_harness.session_factory() as guard:
        await guard.scalar(
            select(User).where(User.id == postgres_auth_harness.user_id).with_for_update()
        )
        guard_pid = int(await guard.scalar(text("SELECT pg_backend_pid()")) or 0)
        replay_tasks = (
            asyncio.create_task(
                postgres_auth_harness.client.post(
                    "/api/v1/auth/refresh",
                    json={"refresh_token": first_login["refresh_token"]},
                )
            ),
            asyncio.create_task(
                postgres_auth_harness.client.post(
                    "/api/v1/auth/refresh",
                    json={"refresh_token": second_login["refresh_token"]},
                )
            ),
        )
        try:
            await _wait_for_lock_waiters(
                postgres_auth_harness,
                guard_pid=guard_pid,
                expected=2,
            )
            await guard.commit()
            replay_responses = await asyncio.wait_for(
                asyncio.gather(*replay_tasks),
                timeout=5,
            )
        finally:
            if guard.in_transaction():
                await guard.rollback()
            for task in replay_tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*replay_tasks, return_exceptions=True)

    assert [response.status_code for response in replay_responses] == [401, 401]
    assert all(
        response.json()["error"]["code"] == "refresh_token_reuse_detected"
        for response in replay_responses
    )

    access_tokens = (
        first_login["access_token"],
        second_login["access_token"],
        first_rotation.json()["access_token"],
        second_rotation.json()["access_token"],
    )
    for access_token in access_tokens:
        revoked = await postgres_auth_harness.client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert revoked.status_code == 401
        assert revoked.json()["error"]["code"] == "token_revoked"

    async with postgres_auth_harness.session_factory() as session:
        records = list(
            (
                await session.scalars(
                    select(RefreshToken).where(
                        RefreshToken.user_id == postgres_auth_harness.user_id
                    )
                )
            ).all()
        )
        user = await session.get(User, postgres_auth_harness.user_id)
    assert len(records) == 4
    assert len({record.family_id for record in records}) == 2
    assert user is not None
    assert user.token_version == 2
    assert all(record.revoked_at is not None for record in records)
    assert all(record.reuse_detected_at is not None for record in records)
