from __future__ import annotations

import asyncio
import base64
import os
from collections.abc import Awaitable, Callable
from uuid import UUID, uuid4

import pytest
from fastapi import Request, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.api.v1.routes.api_keys as api_key_routes
from app.api.errors import ApiError
from app.core.config import Settings
from app.db.models import (
    ApiKey,
    ChatIdempotencyRecord,
    ChatIdempotencyStatus,
    KnowledgeBase,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
    User,
)
from app.schemas.chat import ChatQueryRequest, ChatQueryResponse, ChatSourceStatus
from app.services.access import AccessService
from app.services.chat_idempotency import (
    ChatIdempotencyPrincipal,
    execute_chat_query_idempotently,
)
from app.services.chat_replay_authorization import (
    ChatAuthorizationSnapshot,
    authorize_api_key_chat_snapshot,
)
from scripts.postgres_acceptance import assert_acceptance_database

_POSTGRES_URL = os.getenv("KB_TEST_POSTGRES_URL")
_CHAT_REPLAY_KEYS = {
    version: base64.urlsafe_b64encode(bytes([version]) * 32).decode("ascii") for version in (1, 2)
}
pytestmark = pytest.mark.skipif(
    not _POSTGRES_URL,
    reason="KB_TEST_POSTGRES_URL is required for chat idempotency concurrency verification",
)


def _settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "database_url": _POSTGRES_URL or "postgresql+asyncpg://unused:unused@localhost/unused",
        "chat_replay_encryption_keys": {1: _CHAT_REPLAY_KEYS[1]},
        "chat_replay_active_key_version": 1,
        "chat_idempotency_ttl_seconds": 3_600,
        "chat_idempotency_processing_timeout_seconds": 60,
        "deepseek_timeout_seconds": 5,
        **updates,
    }
    return Settings.model_validate(values)


def _response(request: ChatQueryRequest) -> ChatQueryResponse:
    return ChatQueryResponse(
        knowledge_base_id=request.knowledge_base_id,
        answer="durable PostgreSQL response",
        citations=[],
        source_status=ChatSourceStatus(
            status="no_results",
            strategy="retrieval",
            reason="no_matching_content",
            citation_count=0,
        ),
    )


async def _create_knowledge_base(
    factory: async_sessionmaker[AsyncSession],
) -> KnowledgeBase:
    async with factory() as session:
        owner = User(
            email=f"chat-idempotency-{uuid4()}@example.com",
            password_hash="unused",
        )
        session.add(owner)
        await session.flush()
        knowledge_base = KnowledgeBase(owner_id=owner.id, name="Chat idempotency acceptance")
        session.add(knowledge_base)
        await session.commit()
        await session.refresh(knowledge_base)
        return knowledge_base


def _authorization(
    knowledge_base_id: UUID,
) -> Callable[[AsyncSession], Awaitable[ChatAuthorizationSnapshot]]:
    async def authorize(session: AsyncSession) -> ChatAuthorizationSnapshot:
        knowledge_base = await session.scalar(
            select(KnowledgeBase)
            .where(KnowledgeBase.id == knowledge_base_id)
            .with_for_update(read=True)
        )
        assert knowledge_base is not None
        return ChatAuthorizationSnapshot(
            knowledge_base_id=knowledge_base.id,
            content_version=knowledge_base.content_version,
        )

    return authorize


def _request(path: str, *, method: str = "POST") -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],
            "query_string": b"",
            "scheme": "https",
            "server": ("acceptance.test", 443),
            "client": ("127.0.0.1", 50000),
        }
    )


@pytest.mark.asyncio
async def test_postgres_chat_idempotency_has_one_executor_and_durable_replay() -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=4, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    knowledge_base = await _create_knowledge_base(factory)
    request = ChatQueryRequest(knowledge_base_id=knowledge_base.id, message="execute exactly once")
    principal = ChatIdempotencyPrincipal.for_api_key(uuid4())
    key = f"postgres-chat-{uuid4()}"
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        return _response(request)

    async def execute_first() -> ChatQueryResponse:
        async with factory() as session:
            return await execute_chat_query_idempotently(
                session,
                _settings(),
                principal=principal,
                idempotency_key=key,
                request=request,
                authorize=_authorization(request.knowledge_base_id),
                operation=operation,
            )

    first_task = asyncio.create_task(execute_first())
    await asyncio.wait_for(entered.wait(), timeout=5)
    try:
        async with factory() as duplicate_session:
            with pytest.raises(ApiError) as in_progress:
                await execute_chat_query_idempotently(
                    duplicate_session,
                    _settings(),
                    principal=principal,
                    idempotency_key=key,
                    request=request,
                    authorize=_authorization(request.knowledge_base_id),
                    operation=operation,
                )
        assert in_progress.value.code == "idempotency_in_progress"
    finally:
        release.set()
    first = await asyncio.wait_for(first_task, timeout=5)

    async with factory() as replay_session:
        replay = await execute_chat_query_idempotently(
            replay_session,
            _settings(),
            principal=principal,
            idempotency_key=key,
            request=request,
            authorize=_authorization(request.knowledge_base_id),
            operation=operation,
        )
    assert replay == first
    assert calls == 1

    async with factory() as conflict_session:
        with pytest.raises(ApiError) as conflict:
            await execute_chat_query_idempotently(
                conflict_session,
                _settings(),
                principal=principal,
                idempotency_key=key,
                request=request.model_copy(update={"message": "not the same request"}),
                authorize=_authorization(request.knowledge_base_id),
                operation=operation,
            )
    assert conflict.value.code == "idempotency_conflict"

    async with factory() as cleanup:
        await cleanup.execute(
            delete(ChatIdempotencyRecord).where(
                ChatIdempotencyRecord.principal_hash == principal.fingerprint()
            )
        )
        await cleanup.commit()
    await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_aead_tamper_and_key_rotation_fail_closed() -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=2, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    knowledge_base = await _create_knowledge_base(factory)
    request = ChatQueryRequest(
        knowledge_base_id=knowledge_base.id,
        message="PostgreSQL AEAD rotation and tamper",
    )
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    calls = 0

    async def operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        return _response(request)

    rotated_settings = _settings(
        chat_replay_encryption_keys=dict(_CHAT_REPLAY_KEYS),
        chat_replay_active_key_version=2,
    )
    try:
        async with factory() as session:
            first = await execute_chat_query_idempotently(
                session,
                _settings(),
                principal=principal,
                idempotency_key="postgres-aead-v1",
                request=request,
                authorize=_authorization(request.knowledge_base_id),
                operation=operation,
            )
        async with factory() as session:
            replay = await execute_chat_query_idempotently(
                session,
                rotated_settings,
                principal=principal,
                idempotency_key="postgres-aead-v1",
                request=request,
                authorize=_authorization(request.knowledge_base_id),
                operation=operation,
            )
        async with factory() as session:
            await execute_chat_query_idempotently(
                session,
                rotated_settings,
                principal=principal,
                idempotency_key="postgres-aead-v2",
                request=request,
                authorize=_authorization(request.knowledge_base_id),
                operation=operation,
            )
        assert replay == first
        assert calls == 2

        async with factory() as tamper:
            records = list(
                (
                    await tamper.scalars(
                        select(ChatIdempotencyRecord)
                        .where(ChatIdempotencyRecord.principal_hash == principal.fingerprint())
                        .order_by(ChatIdempotencyRecord.response_key_version)
                    )
                ).all()
            )
            assert [record.response_key_version for record in records] == [1, 2]
            assert all(record.response_encoding == "aesgcm-zlib-json-v1" for record in records)
            assert all(record.response_nonce is not None for record in records)
            assert records[0].response_nonce is not None
            nonce = bytearray(records[0].response_nonce)
            nonce[0] ^= 1
            records[0].response_nonce = bytes(nonce)
            await tamper.commit()

        async with factory() as replay_session:
            with pytest.raises(ApiError) as captured:
                await execute_chat_query_idempotently(
                    replay_session,
                    rotated_settings,
                    principal=principal,
                    idempotency_key="postgres-aead-v1",
                    request=request,
                    authorize=_authorization(request.knowledge_base_id),
                    operation=operation,
                )
        assert captured.value.code == "idempotency_outcome_unknown"
        assert calls == 2

        async with factory() as verification:
            invalidated = await verification.scalar(
                select(ChatIdempotencyRecord).where(ChatIdempotencyRecord.id == records[0].id)
            )
            assert invalidated is not None
            assert invalidated.status is ChatIdempotencyStatus.OUTCOME_UNKNOWN
            assert invalidated.response_body is None
            assert invalidated.response_nonce is None
            assert invalidated.response_key_version is None
    finally:
        async with factory() as cleanup:
            await cleanup.execute(
                delete(ChatIdempotencyRecord).where(
                    ChatIdempotencyRecord.principal_hash == principal.fingerprint()
                )
            )
            await cleanup.commit()
        await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_published_content_change_invalidates_replay_without_reexecution() -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=2, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    knowledge_base = await _create_knowledge_base(factory)
    request = ChatQueryRequest(
        knowledge_base_id=knowledge_base.id,
        message="revision-bound PostgreSQL answer",
    )
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    key = f"postgres-content-revision-{uuid4()}"
    calls = 0

    async def operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        return _response(request)

    try:
        async with factory() as session:
            first = await execute_chat_query_idempotently(
                session,
                _settings(),
                principal=principal,
                idempotency_key=key,
                request=request,
                authorize=_authorization(request.knowledge_base_id),
                operation=operation,
            )
        assert first.answer == "durable PostgreSQL response"
        assert calls == 1

        async with factory() as session:
            session.add(
                KnowledgeEntry(
                    knowledge_base_id=knowledge_base.id,
                    entry_type="policy",
                    title="Newly published revision",
                    content="This visible content changes the answer corpus.",
                    publication_status=KnowledgeEntryPublicationStatus.PUBLISHED,
                )
            )
            await session.commit()
            current_version = await session.scalar(
                select(KnowledgeBase.content_version).where(KnowledgeBase.id == knowledge_base.id)
            )
        assert current_version == 2

        async with factory() as session:
            with pytest.raises(ApiError) as invalidated:
                await execute_chat_query_idempotently(
                    session,
                    _settings(),
                    principal=principal,
                    idempotency_key=key,
                    request=request,
                    authorize=_authorization(request.knowledge_base_id),
                    operation=operation,
                )
        assert invalidated.value.code == "idempotency_resource_changed"
        assert calls == 1

        async with factory() as session:
            record = await session.scalar(
                select(ChatIdempotencyRecord).where(
                    ChatIdempotencyRecord.principal_hash == principal.fingerprint()
                )
            )
            assert record is not None
            assert record.status is ChatIdempotencyStatus.INVALIDATED
            assert record.response_body is None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_api_key_family_rotation_replays_and_revocation_linearizes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=6, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    family_id = uuid4()
    async with factory() as setup:
        user = User(
            email=f"chat-family-{uuid4()}@example.com",
            password_hash="unused",
            is_superuser=True,
        )
        setup.add(user)
        await setup.flush()
        knowledge_base = KnowledgeBase(
            owner_id=user.id,
            name="Credential family PostgreSQL acceptance",
        )
        setup.add(knowledge_base)
        await setup.flush()
        first_key = ApiKey(
            user_id=user.id,
            created_by=user.id,
            credential_family_id=family_id,
            name="Rotatable PostgreSQL key",
            key_hash=uuid4().hex + uuid4().hex,
            key_prefix=f"kb_pg_{uuid4().hex[:12]}",
            permission_codes=["chat:query"],
            knowledge_base_ids=[str(knowledge_base.id)],
            requests_per_minute=60,
        )
        setup.add(first_key)
        await setup.flush()
        access = await AccessService().resolve(setup, user)
        await setup.commit()
        user_id = user.id
        knowledge_base_id = knowledge_base.id
        first_key_id = first_key.id

    request = ChatQueryRequest(
        knowledge_base_id=knowledge_base_id,
        message="stable request across secret rotation",
    )
    principal = ChatIdempotencyPrincipal.for_api_key(family_id)
    client_key = f"postgres-family-{uuid4()}"
    calls = 0

    async def operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        return _response(request)

    def authorize_key(
        api_key_id: UUID,
    ) -> Callable[[AsyncSession], Awaitable[ChatAuthorizationSnapshot]]:
        async def authorize(session: AsyncSession) -> ChatAuthorizationSnapshot:
            return await authorize_api_key_chat_snapshot(
                session,
                api_key_id=api_key_id,
                credential_family_id=family_id,
                user_id=user_id,
                knowledge_base_id=knowledge_base_id,
            )

        return authorize

    try:
        async with factory() as session:
            first = await execute_chat_query_idempotently(
                session,
                _settings(),
                principal=principal,
                idempotency_key=client_key,
                request=request,
                authorize=authorize_key(first_key_id),
                operation=operation,
            )
        assert calls == 1

        async with factory() as session:
            rotated = await api_key_routes.rotate_api_key(
                api_key_id=first_key_id,
                request=_request(f"/api/v1/api-keys/{first_key_id}/rotate"),
                response=Response(),
                session=session,
                access=access,
            )
        replacement_id = rotated.id
        assert rotated.credential_family_id == family_id
        assert replacement_id != first_key_id

        async with factory() as session:
            with pytest.raises(ApiError) as old_secret:
                await execute_chat_query_idempotently(
                    session,
                    _settings(),
                    principal=principal,
                    idempotency_key=client_key,
                    request=request,
                    authorize=authorize_key(first_key_id),
                    operation=operation,
                )
        assert old_secret.value.code == "invalid_api_key"
        assert calls == 1

        async with factory() as session:
            replay = await execute_chat_query_idempotently(
                session,
                _settings(),
                principal=principal,
                idempotency_key=client_key,
                request=request,
                authorize=authorize_key(replacement_id),
                operation=operation,
            )
        assert replay == first
        assert calls == 1

        independent_family_id = uuid4()
        async with factory() as session:
            independent_key = ApiKey(
                user_id=user_id,
                created_by=user_id,
                credential_family_id=independent_family_id,
                name="Independent PostgreSQL key",
                key_hash=uuid4().hex + uuid4().hex,
                key_prefix=f"kb_pg_{uuid4().hex[:12]}",
                permission_codes=["chat:query"],
                knowledge_base_ids=[str(knowledge_base_id)],
                requests_per_minute=60,
            )
            session.add(independent_key)
            await session.commit()
            independent_key_id = independent_key.id

        async def authorize_independent(
            session: AsyncSession,
        ) -> ChatAuthorizationSnapshot:
            return await authorize_api_key_chat_snapshot(
                session,
                api_key_id=independent_key_id,
                credential_family_id=independent_family_id,
                user_id=user_id,
                knowledge_base_id=knowledge_base_id,
            )

        async with factory() as session:
            independent = await execute_chat_query_idempotently(
                session,
                _settings(),
                principal=ChatIdempotencyPrincipal.for_api_key(independent_family_id),
                idempotency_key=client_key,
                request=request,
                authorize=authorize_independent,
                operation=operation,
            )
        assert independent == first
        assert calls == 2

        revoke_holds_rbac_domain = asyncio.Event()
        release_revoke = asyncio.Event()
        original_mutation_lock = api_key_routes.acquire_rbac_mutation_lock

        async def hold_revoke_after_domain_lock(session: AsyncSession) -> None:
            await original_mutation_lock(session)
            revoke_holds_rbac_domain.set()
            await release_revoke.wait()

        monkeypatch.setattr(
            api_key_routes,
            "acquire_rbac_mutation_lock",
            hold_revoke_after_domain_lock,
        )

        async def revoke() -> int:
            async with factory() as session:
                response = await api_key_routes.revoke_api_key(
                    api_key_id=replacement_id,
                    request=_request(
                        f"/api/v1/api-keys/{replacement_id}",
                        method="DELETE",
                    ),
                    session=session,
                    access=access,
                )
                return response.status_code

        async def replay_during_revoke() -> str:
            async with factory() as session:
                try:
                    await execute_chat_query_idempotently(
                        session,
                        _settings(),
                        principal=principal,
                        idempotency_key=client_key,
                        request=request,
                        authorize=authorize_key(replacement_id),
                        operation=operation,
                    )
                except ApiError as error:
                    return error.code
                return "replayed"

        revoke_task = asyncio.create_task(revoke())
        replay_task: asyncio.Task[str] | None = None
        try:
            await asyncio.wait_for(revoke_holds_rbac_domain.wait(), timeout=5)
            replay_task = asyncio.create_task(replay_during_revoke())
            await asyncio.sleep(0.2)
            assert not replay_task.done()
            release_revoke.set()
            assert await asyncio.wait_for(revoke_task, timeout=10) == 204
            assert await asyncio.wait_for(replay_task, timeout=10) == "invalid_api_key"
        finally:
            release_revoke.set()
            if not revoke_task.done():
                revoke_task.cancel()
            if replay_task is not None and not replay_task.done():
                replay_task.cancel()
        assert calls == 2

        async with factory() as session:
            ledgers = list(
                (
                    await session.scalars(
                        select(ChatIdempotencyRecord).where(
                            ChatIdempotencyRecord.idempotency_key_hash.is_not(None)
                        )
                    )
                ).all()
            )
        matching = [
            row
            for row in ledgers
            if row.principal_hash
            in {
                principal.fingerprint(),
                ChatIdempotencyPrincipal.for_api_key(independent_family_id).fingerprint(),
            }
        ]
        assert len(matching) == 2
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_postgres_unknown_chat_outcome_is_not_executed_again() -> None:
    assert _POSTGRES_URL is not None
    engine = create_async_engine(_POSTGRES_URL, pool_size=2, max_overflow=0)
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    knowledge_base = await _create_knowledge_base(factory)
    request = ChatQueryRequest(
        knowledge_base_id=knowledge_base.id,
        message="uncertain provider outcome",
    )
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    key = f"postgres-unknown-{uuid4()}"
    calls = 0

    async def fail_after_egress() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        raise RuntimeError("simulated transport loss")

    try:
        for _ in range(2):
            async with factory() as session:
                with pytest.raises(ApiError) as captured:
                    await execute_chat_query_idempotently(
                        session,
                        _settings(),
                        principal=principal,
                        idempotency_key=key,
                        request=request,
                        authorize=_authorization(request.knowledge_base_id),
                        operation=fail_after_egress,
                    )
            assert captured.value.code == "idempotency_outcome_unknown"
        assert calls == 1
    finally:
        async with factory() as cleanup:
            await cleanup.execute(
                delete(ChatIdempotencyRecord).where(
                    ChatIdempotencyRecord.principal_hash == principal.fingerprint()
                )
            )
            await cleanup.commit()
        await engine.dispose()
