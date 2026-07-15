from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.errors import ApiError
from app.core.config import Settings, get_settings
from app.db.base import Base
from app.db.models import (
    ChatIdempotencyRecord,
    ChatIdempotencyStatus,
    LlmBudgetPolicy,
    LlmModelPrice,
    LlmUsageRecord,
    LlmUsageStatus,
)
from app.main import app
from app.schemas.chat import ChatQueryRequest, ChatQueryResponse, ChatSourceStatus
from app.services.chat_idempotency import (
    ChatIdempotencyPrincipal,
    cleanup_chat_idempotency_records,
    execute_chat_query_idempotently,
)
from app.services.chat_replay_authorization import ChatAuthorizationSnapshot
from app.services.llm_provider import LlmChatResult

pytest_plugins = ("test_integration_api",)

_CHAT_REPLAY_KEYS = {
    version: base64.urlsafe_b64encode(bytes([version]) * 32).decode("ascii") for version in (1, 2)
}


def _response(request: ChatQueryRequest, *, answer: str = "bounded answer") -> ChatQueryResponse:
    return ChatQueryResponse(
        knowledge_base_id=request.knowledge_base_id,
        answer=answer,
        citations=[],
        source_status=ChatSourceStatus(
            status="no_results",
            strategy="retrieval",
            reason="no_matching_content",
            citation_count=0,
        ),
    )


def _authorization(
    request: ChatQueryRequest,
    *,
    content_version: int = 1,
) -> Any:
    async def authorize(_session: AsyncSession) -> ChatAuthorizationSnapshot:
        return ChatAuthorizationSnapshot(
            knowledge_base_id=request.knowledge_base_id,
            content_version=content_version,
        )

    return authorize


@pytest_asyncio.fixture
async def idempotency_factory(
    tmp_path: Any,
) -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'idempotency.sqlite3'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    try:
        yield factory
    finally:
        await engine.dispose()


def _settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "chat_replay_encryption_keys": {1: _CHAT_REPLAY_KEYS[1]},
        "chat_replay_active_key_version": 1,
        "chat_idempotency_ttl_seconds": 3_600,
        "chat_idempotency_processing_timeout_seconds": 60,
        "deepseek_timeout_seconds": 5,
        **updates,
    }
    return Settings.model_validate(values)


def test_processing_timeout_must_cover_generation_and_review() -> None:
    with pytest.raises(ValidationError, match="generation and review timeouts"):
        Settings(
            environment="test",
            deepseek_timeout_seconds=45,
            chat_idempotency_processing_timeout_seconds=60,
        )


@pytest.mark.asyncio
async def test_completed_chat_response_is_replayed_without_running_operation_twice(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    request = ChatQueryRequest(
        knowledge_base_id=uuid4(),
        message="confidential question that must not be persisted",
        limit=5,
    )
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    calls = 0

    async def operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        return _response(request)

    async with idempotency_factory() as first_session:
        first = await execute_chat_query_idempotently(
            first_session,
            _settings(),
            principal=principal,
            idempotency_key="stable-chat-key",
            request=request,
            authorize=_authorization(request),
            operation=operation,
        )
    async with idempotency_factory() as replay_session:
        replay = await execute_chat_query_idempotently(
            replay_session,
            _settings(),
            principal=principal,
            idempotency_key="stable-chat-key",
            request=request,
            authorize=_authorization(request),
            operation=operation,
        )

    assert replay == first
    assert calls == 1
    async with idempotency_factory() as verification:
        record = await verification.scalar(select(ChatIdempotencyRecord))
        assert record is not None
        assert record.status is ChatIdempotencyStatus.COMPLETED
        assert record.request_hash != request.message
        assert len(record.request_hash) == 64
        assert not hasattr(record, "request_body")
        assert record.response_body is not None
        assert b"bounded answer" not in bytes(record.response_body)
        assert record.response_encoding == "aesgcm-zlib-json-v1"
        assert record.response_size_bytes is not None
        assert record.response_key_version == 1
        assert record.response_nonce is not None
        assert len(record.response_nonce) == 12


@pytest.mark.asyncio
async def test_missing_replay_keyring_fails_before_claim_or_model_execution(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    request = ChatQueryRequest(knowledge_base_id=uuid4(), message="must not leave process")
    calls = 0

    async def operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        return _response(request)

    async with idempotency_factory() as session:
        with pytest.raises(RuntimeError, match="replay encryption keyring"):
            await execute_chat_query_idempotently(
                session,
                Settings(
                    environment="test",
                    deepseek_timeout_seconds=5,
                    chat_idempotency_processing_timeout_seconds=60,
                ),
                principal=ChatIdempotencyPrincipal.for_user(uuid4()),
                idempotency_key="missing-keyring",
                request=request,
                authorize=_authorization(request),
                operation=operation,
            )

    assert calls == 0
    async with idempotency_factory() as verification:
        assert await verification.scalar(select(func.count(ChatIdempotencyRecord.id))) == 0


@pytest.mark.asyncio
async def test_tampered_encrypted_replay_fails_closed_without_reexecution(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    request = ChatQueryRequest(knowledge_base_id=uuid4(), message="integrity-bound answer")
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    calls = 0

    async def operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        return _response(request, answer="sensitive integrity protected answer")

    async with idempotency_factory() as session:
        await execute_chat_query_idempotently(
            session,
            _settings(),
            principal=principal,
            idempotency_key="tampered-replay",
            request=request,
            authorize=_authorization(request),
            operation=operation,
        )

    async with idempotency_factory() as tamper:
        record = await tamper.scalar(select(ChatIdempotencyRecord))
        assert record is not None and record.response_body is not None
        ciphertext = bytearray(record.response_body)
        ciphertext[-1] ^= 1
        record.response_body = bytes(ciphertext)
        await tamper.commit()

    async with idempotency_factory() as replay_session:
        with pytest.raises(ApiError) as captured:
            await execute_chat_query_idempotently(
                replay_session,
                _settings(),
                principal=principal,
                idempotency_key="tampered-replay",
                request=request,
                authorize=_authorization(request),
                operation=operation,
            )

    assert captured.value.code == "idempotency_outcome_unknown"
    assert calls == 1
    async with idempotency_factory() as verification:
        record = await verification.scalar(select(ChatIdempotencyRecord))
        assert record is not None
        assert record.status is ChatIdempotencyStatus.OUTCOME_UNKNOWN
        assert record.response_body is None
        assert record.response_encoding is None
        assert record.response_size_bytes is None
        assert record.response_key_version is None
        assert record.response_nonce is None


@pytest.mark.asyncio
async def test_ciphertext_cannot_be_relocated_to_a_different_aad_record_id(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    request = ChatQueryRequest(knowledge_base_id=uuid4(), message="AAD relocation defense")
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    calls = 0

    async def operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        return _response(request, answer="record-bound confidential answer")

    async with idempotency_factory() as session:
        await execute_chat_query_idempotently(
            session,
            _settings(),
            principal=principal,
            idempotency_key="aad-record-binding",
            request=request,
            authorize=_authorization(request),
            operation=operation,
        )

    async with idempotency_factory() as relocate:
        record = await relocate.scalar(select(ChatIdempotencyRecord))
        assert record is not None
        record.id = uuid4()
        await relocate.commit()

    async with idempotency_factory() as replay_session:
        with pytest.raises(ApiError) as captured:
            await execute_chat_query_idempotently(
                replay_session,
                _settings(),
                principal=principal,
                idempotency_key="aad-record-binding",
                request=request,
                authorize=_authorization(request),
                operation=operation,
            )

    assert captured.value.code == "idempotency_outcome_unknown"
    assert calls == 1


@pytest.mark.asyncio
async def test_key_rotation_reads_old_ciphertext_and_writes_only_the_active_version(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    request = ChatQueryRequest(knowledge_base_id=uuid4(), message="rotation-safe replay")
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    calls = 0

    async def operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        return _response(request, answer=f"encrypted response {calls}")

    async with idempotency_factory() as first_session:
        first = await execute_chat_query_idempotently(
            first_session,
            _settings(),
            principal=principal,
            idempotency_key="key-version-one",
            request=request,
            authorize=_authorization(request),
            operation=operation,
        )

    rotated_settings = _settings(
        chat_replay_encryption_keys=dict(_CHAT_REPLAY_KEYS),
        chat_replay_active_key_version=2,
    )
    async with idempotency_factory() as replay_session:
        replay = await execute_chat_query_idempotently(
            replay_session,
            rotated_settings,
            principal=principal,
            idempotency_key="key-version-one",
            request=request,
            authorize=_authorization(request),
            operation=operation,
        )
    async with idempotency_factory() as second_session:
        second = await execute_chat_query_idempotently(
            second_session,
            rotated_settings,
            principal=principal,
            idempotency_key="key-version-two",
            request=request,
            authorize=_authorization(request),
            operation=operation,
        )

    assert replay == first
    assert second.answer == "encrypted response 2"
    assert calls == 2
    async with idempotency_factory() as verification:
        records = list(
            (
                await verification.scalars(
                    select(ChatIdempotencyRecord).order_by(
                        ChatIdempotencyRecord.response_key_version
                    )
                )
            ).all()
        )
        assert [record.response_key_version for record in records] == [1, 2]


@pytest.mark.asyncio
async def test_completed_response_is_invalidated_after_knowledge_content_changes(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    request = ChatQueryRequest(knowledge_base_id=uuid4(), message="revision-bound answer")
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    content_version = 1
    calls = 0

    async def authorize(_session: AsyncSession) -> ChatAuthorizationSnapshot:
        return ChatAuthorizationSnapshot(
            knowledge_base_id=request.knowledge_base_id,
            content_version=content_version,
        )

    async def operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        return _response(request)

    async with idempotency_factory() as session:
        await execute_chat_query_idempotently(
            session,
            _settings(),
            principal=principal,
            idempotency_key="content-version-key",
            request=request,
            authorize=authorize,
            operation=operation,
        )
    content_version = 2
    for _ in range(2):
        async with idempotency_factory() as session:
            with pytest.raises(ApiError) as captured:
                await execute_chat_query_idempotently(
                    session,
                    _settings(),
                    principal=principal,
                    idempotency_key="content-version-key",
                    request=request,
                    authorize=authorize,
                    operation=operation,
                )
        assert captured.value.code == "idempotency_resource_changed"

    assert calls == 1
    async with idempotency_factory() as session:
        record = await session.scalar(select(ChatIdempotencyRecord))
        assert record is not None
        assert record.status is ChatIdempotencyStatus.INVALIDATED
        assert record.response_body is None


@pytest.mark.asyncio
async def test_same_principal_and_key_with_different_request_is_a_conflict(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    knowledge_base_id = uuid4()
    first_request = ChatQueryRequest(
        knowledge_base_id=knowledge_base_id,
        message="first",
    )
    conflicting_request = first_request.model_copy(update={"message": "second"})
    principal = ChatIdempotencyPrincipal.for_user(uuid4())

    async with idempotency_factory() as first_session:
        await execute_chat_query_idempotently(
            first_session,
            _settings(),
            principal=principal,
            idempotency_key="conflict-key",
            request=first_request,
            authorize=_authorization(first_request),
            operation=lambda: asyncio.sleep(0, result=_response(first_request)),
        )
    async with idempotency_factory() as conflict_session:
        with pytest.raises(ApiError) as captured:
            await execute_chat_query_idempotently(
                conflict_session,
                _settings(),
                principal=principal,
                idempotency_key="conflict-key",
                request=conflicting_request,
                authorize=_authorization(conflicting_request),
                operation=lambda: asyncio.sleep(0, result=_response(conflicting_request)),
            )

    assert captured.value.status_code == 409
    assert captured.value.code == "idempotency_conflict"


@pytest.mark.asyncio
async def test_concurrent_duplicate_returns_in_progress_without_second_operation(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    request = ChatQueryRequest(knowledge_base_id=uuid4(), message="one logical request")
    principal = ChatIdempotencyPrincipal.for_api_key(uuid4())
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def delayed_operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        return _response(request)

    async def first_request() -> ChatQueryResponse:
        async with idempotency_factory() as session:
            return await execute_chat_query_idempotently(
                session,
                _settings(),
                principal=principal,
                idempotency_key="processing-key",
                request=request,
                authorize=_authorization(request),
                operation=delayed_operation,
            )

    first_task = asyncio.create_task(first_request())
    await asyncio.wait_for(entered.wait(), timeout=2)
    async with idempotency_factory() as duplicate_session:
        with pytest.raises(ApiError) as captured:
            await execute_chat_query_idempotently(
                duplicate_session,
                _settings(),
                principal=principal,
                idempotency_key="processing-key",
                request=request,
                authorize=_authorization(request),
                operation=delayed_operation,
            )
    release.set()
    await asyncio.wait_for(first_task, timeout=2)

    assert captured.value.status_code == 409
    assert captured.value.code == "idempotency_in_progress"
    assert calls == 1


@pytest.mark.asyncio
async def test_unknown_operation_failure_is_terminal_and_never_reexecuted(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    request = ChatQueryRequest(knowledge_base_id=uuid4(), message="may have reached provider")
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    calls = 0

    async def uncertain_operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        raise RuntimeError("transport outcome is unknown")

    for _ in range(2):
        async with idempotency_factory() as session:
            with pytest.raises(ApiError) as captured:
                await execute_chat_query_idempotently(
                    session,
                    _settings(),
                    principal=principal,
                    idempotency_key="unknown-key",
                    request=request,
                    authorize=_authorization(request),
                    operation=uncertain_operation,
                )
        assert captured.value.status_code == 409
        assert captured.value.code == "idempotency_outcome_unknown"

    assert calls == 1


@pytest.mark.asyncio
async def test_different_principals_can_reuse_the_same_key(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    request = ChatQueryRequest(knowledge_base_id=uuid4(), message="shared client key")
    calls = 0

    async def operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        return _response(request)

    for principal in (
        ChatIdempotencyPrincipal.for_user(uuid4()),
        ChatIdempotencyPrincipal.for_api_key(uuid4()),
    ):
        async with idempotency_factory() as session:
            await execute_chat_query_idempotently(
                session,
                _settings(),
                principal=principal,
                idempotency_key="same-key",
                request=request,
                authorize=_authorization(request),
                operation=operation,
            )

    assert calls == 2


@pytest.mark.asyncio
async def test_oversized_response_becomes_unknown_instead_of_unreplayable_success(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    request = ChatQueryRequest(knowledge_base_id=uuid4(), message="bounded response")
    principal = ChatIdempotencyPrincipal.for_user(uuid4())

    async with idempotency_factory() as session:
        with pytest.raises(ApiError) as captured:
            await execute_chat_query_idempotently(
                session,
                _settings(),
                principal=principal,
                idempotency_key="oversized-response",
                request=request,
                authorize=_authorization(request),
                operation=lambda: asyncio.sleep(0, result=_response(request, answer="x" * 600_000)),
            )

    assert captured.value.code == "idempotency_outcome_unknown"


@pytest.mark.asyncio
async def test_maintenance_expires_terminal_rows_and_marks_abandoned_processing_unknown(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    now = datetime.now(UTC)
    async with idempotency_factory() as session:
        session.add_all(
            [
                ChatIdempotencyRecord(
                    principal_hash="a" * 64,
                    idempotency_key_hash="b" * 64,
                    request_hash="c" * 64,
                    status=ChatIdempotencyStatus.OUTCOME_UNKNOWN,
                    completed_at=now - timedelta(hours=2),
                    expires_at=now - timedelta(seconds=1),
                ),
                ChatIdempotencyRecord(
                    principal_hash="d" * 64,
                    idempotency_key_hash="e" * 64,
                    request_hash="f" * 64,
                    knowledge_base_id=uuid4(),
                    knowledge_base_content_version=1,
                    status=ChatIdempotencyStatus.PROCESSING,
                    created_at=now - timedelta(minutes=5),
                    updated_at=now - timedelta(minutes=5),
                ),
            ]
        )
        await session.commit()

    async with idempotency_factory() as session:
        processed = await cleanup_chat_idempotency_records(
            session,
            _settings(chat_idempotency_processing_timeout_seconds=40),
            batch_size=100,
            now=now,
        )
    assert processed == 2

    async with idempotency_factory() as session:
        rows = list((await session.scalars(select(ChatIdempotencyRecord))).all())
        assert len(rows) == 1
        assert rows[0].status is ChatIdempotencyStatus.OUTCOME_UNKNOWN
        assert rows[0].expires_at is not None
        assert await session.scalar(select(func.count(ChatIdempotencyRecord.id))) == 1


@pytest.mark.asyncio
async def test_maintenance_does_not_starve_expired_responses_behind_processing_rows(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    now = datetime.now(UTC)
    async with idempotency_factory() as session:
        session.add_all(
            [
                ChatIdempotencyRecord(
                    principal_hash=principal * 64,
                    idempotency_key_hash=key * 64,
                    request_hash=request * 64,
                    knowledge_base_id=uuid4(),
                    knowledge_base_content_version=1,
                    status=ChatIdempotencyStatus.PROCESSING,
                    created_at=now - timedelta(minutes=5),
                    updated_at=now - timedelta(minutes=5),
                )
                for principal, key, request in [("a", "b", "c"), ("d", "e", "f")]
            ]
            + [
                ChatIdempotencyRecord(
                    principal_hash="1" * 64,
                    idempotency_key_hash="2" * 64,
                    request_hash="3" * 64,
                    status=ChatIdempotencyStatus.OUTCOME_UNKNOWN,
                    completed_at=now - timedelta(hours=2),
                    expires_at=now - timedelta(seconds=1),
                )
            ]
        )
        await session.commit()

    async with idempotency_factory() as session:
        processed = await cleanup_chat_idempotency_records(
            session,
            _settings(chat_idempotency_processing_timeout_seconds=40),
            batch_size=1,
            now=now,
        )

    assert processed == 2
    async with idempotency_factory() as session:
        rows = list((await session.scalars(select(ChatIdempotencyRecord))).all())
        assert len(rows) == 2
        assert {row.status for row in rows} == {
            ChatIdempotencyStatus.PROCESSING,
            ChatIdempotencyStatus.OUTCOME_UNKNOWN,
        }


@pytest.mark.asyncio
async def test_maintenance_drains_multiple_independent_batches(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    now = datetime.now(UTC)
    async with idempotency_factory() as session:
        session.add_all(
            [
                ChatIdempotencyRecord(
                    principal_hash=character * 64,
                    idempotency_key_hash=str(index) * 64,
                    request_hash=chr(ord("k") + index) * 64,
                    knowledge_base_id=uuid4(),
                    knowledge_base_content_version=1,
                    status=ChatIdempotencyStatus.PROCESSING,
                    created_at=now - timedelta(minutes=5),
                    updated_at=now - timedelta(minutes=5),
                )
                for index, character in enumerate(("a", "b", "c"), start=1)
            ]
            + [
                ChatIdempotencyRecord(
                    principal_hash=character * 64,
                    idempotency_key_hash=str(index) * 64,
                    request_hash=chr(ord("q") + index) * 64,
                    status=ChatIdempotencyStatus.OUTCOME_UNKNOWN,
                    completed_at=now - timedelta(hours=2),
                    expires_at=now - timedelta(seconds=1),
                )
                for index, character in enumerate(("d", "e", "f"), start=4)
            ]
        )
        await session.commit()

    async with idempotency_factory() as session:
        processed = await cleanup_chat_idempotency_records(
            session,
            _settings(chat_idempotency_processing_timeout_seconds=40),
            batch_size=2,
            max_batches=2,
            now=now,
        )

    assert processed == 6
    async with idempotency_factory() as session:
        rows = list((await session.scalars(select(ChatIdempotencyRecord))).all())
        assert len(rows) == 3
        assert all(row.status is ChatIdempotencyStatus.OUTCOME_UNKNOWN for row in rows)
        assert all(row.expires_at is not None for row in rows)
        assert all(
            row.expires_at.replace(tzinfo=UTC) == now + timedelta(hours=1)
            for row in rows
            if row.expires_at is not None
        )


@pytest.mark.asyncio
async def test_authenticated_chat_http_replays_final_response(
    api_harness: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app.dependency_overrides[get_settings] = lambda: _settings()
    tokens = await api_harness.login()
    headers = {
        "Authorization": f"Bearer {tokens['access_token']}",
        "Idempotency-Key": "http-replay-key",
    }
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases",
        headers=headers,
        json={"name": "HTTP idempotency"},
    )
    assert knowledge_base.status_code == 201, knowledge_base.text
    request = {
        "knowledge_base_id": knowledge_base.json()["id"],
        "message": "answer once",
        "limit": 5,
    }
    calls = 0

    async def fake_answer(
        _session: AsyncSession,
        _settings: Settings,
        _access: object,
        *,
        knowledge_base_id: UUID,
        message: str,
        limit: int,
        idempotency_key: str,
        api_key_id: UUID | None,
    ) -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        assert message == request["message"]
        assert limit == request["limit"]
        assert idempotency_key == headers["Idempotency-Key"]
        assert api_key_id is None
        return _response(ChatQueryRequest.model_validate(request))

    monkeypatch.setattr("app.api.v1.routes.chat.answer_knowledge_query", fake_answer)
    first = await api_harness.client.post("/api/v1/chat/query", headers=headers, json=request)
    replay = await api_harness.client.post("/api/v1/chat/query", headers=headers, json=request)
    conflict = await api_harness.client.post(
        "/api/v1/chat/query",
        headers=headers,
        json={**request, "message": "different request"},
    )

    assert first.status_code == 200, first.text
    assert replay.status_code == 200, replay.text
    assert replay.json() == first.json()
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["error"]["code"] == "idempotency_conflict"
    assert calls == 1


@pytest.mark.asyncio
async def test_public_chat_replays_across_rotation_and_isolates_other_families(
    api_harness: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app.dependency_overrides[get_settings] = lambda: _settings()
    tokens = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases",
        headers=admin_headers,
        json={"name": "Credential family replay"},
    )
    assert knowledge_base.status_code == 201, knowledge_base.text
    knowledge_base_id = knowledge_base.json()["id"]
    entry = await api_harness.client.post(
        f"/api/v1/knowledge-bases/{knowledge_base_id}/entries",
        headers=admin_headers,
        json={
            "entry_type": "policy",
            "title": "Refund Policy",
            "content": "Refunds require manager approval.",
        },
    )
    assert entry.status_code == 201, entry.text
    consent = await api_harness.client.patch(
        f"/api/v1/knowledge-bases/{knowledge_base_id}",
        headers=admin_headers,
        json={"external_llm_processing_enabled": True},
    )
    assert consent.status_code == 200, consent.text

    async with api_harness.session_factory() as session:
        session.add_all(
            [
                LlmModelPrice(
                    provider="qwen",
                    model="qwen-plus",
                    input_micro_usd_per_million_tokens=1_000_000,
                    output_micro_usd_per_million_tokens=1_000_000,
                    active=True,
                ),
                LlmModelPrice(
                    provider="minimax",
                    model="MiniMax-M2.7",
                    input_micro_usd_per_million_tokens=1_000_000,
                    output_micro_usd_per_million_tokens=1_000_000,
                    active=True,
                ),
                LlmBudgetPolicy(
                    name="credential family acceptance budget",
                    tenant_key="default",
                    daily_token_limit=1_000_000,
                    monthly_token_limit=10_000_000,
                    daily_cost_limit_micro_usd=1_000_000,
                    monthly_cost_limit_micro_usd=10_000_000,
                    enabled=True,
                ),
            ]
        )
        await session.commit()

    provider_calls: list[tuple[str, str]] = []

    class FakeClient:
        def __init__(
            self,
            provider: str,
            model: str,
            *,
            configured: bool = True,
        ) -> None:
            self.provider = provider
            self.model = model
            self.configured = configured
            self.close_calls = 0

        async def complete_chat(
            self,
            messages: list[dict[str, str]],
            *,
            temperature: float = 0.2,
            max_tokens: int | None = None,
        ) -> LlmChatResult:
            del temperature, max_tokens
            provider_calls.append((self.provider, messages[0]["content"]))
            if "strict grounding auditor" in messages[0]["content"]:
                content = '{"verdict":"pass","unsupported_claims":[]}'
            else:
                content = '{"answer":"Refunds require manager approval [1].","table":null}'
            return LlmChatResult(
                content=content,
                provider=self.provider,
                model=self.model,
                prompt_tokens=10,
                completion_tokens=5,
            )

        async def aclose(self) -> None:
            self.close_calls += 1
            assert self.close_calls == 1

    async def fake_resolve(
        *_args: object,
        provider: str | None = None,
        **_kwargs: object,
    ) -> FakeClient:
        if provider is None:
            return FakeClient("qwen", "qwen-plus")
        if provider == "deepseek":
            return FakeClient(
                "deepseek",
                "deepseek-chat",
                configured=False,
            )
        return FakeClient("minimax", "MiniMax-M2.7")

    monkeypatch.setattr("app.services.chat.resolve_provider_client", fake_resolve)

    async def create_key(name: str) -> dict[str, Any]:
        response = await api_harness.client.post(
            "/api/v1/api-keys",
            headers=admin_headers,
            json={
                "name": name,
                "permission_codes": ["chat:query"],
                "knowledge_base_ids": [knowledge_base_id],
                "requests_per_minute": 60,
            },
        )
        assert response.status_code == 201, response.text
        return response.json()

    first_key = await create_key("Primary integration")
    first_key_id = UUID(first_key["id"])
    first_family_id = UUID(first_key["credential_family_id"])
    payload = {"knowledge_base_id": knowledge_base_id, "message": "refund approval"}
    request_headers = {
        "X-API-Key": first_key["key"],
        "Idempotency-Key": "family-stable-chat",
    }
    first = await api_harness.client.post(
        "/api/v1/public/chat/query",
        headers=request_headers,
        json=payload,
    )
    assert first.status_code == 200, first.text
    assert first.json()["mode"] == "rag"
    assert len(provider_calls) == 2

    rotated = await api_harness.client.post(
        f"/api/v1/api-keys/{first_key_id}/rotate",
        headers=admin_headers,
    )
    assert rotated.status_code == 201, rotated.text
    replacement = rotated.json()
    replacement_id = UUID(replacement["id"])
    assert UUID(replacement["credential_family_id"]) == first_family_id
    old_key = await api_harness.client.post(
        "/api/v1/public/chat/query",
        headers=request_headers,
        json=payload,
    )
    assert old_key.status_code == 401

    family_replay = await api_harness.client.post(
        "/api/v1/public/chat/query",
        headers={
            "X-API-Key": replacement["key"],
            "Idempotency-Key": "family-stable-chat",
        },
        json=payload,
    )
    assert family_replay.status_code == 200, family_replay.text
    assert family_replay.json() == first.json()
    assert len(provider_calls) == 2

    independent_key = await create_key("Independent integration")
    independent_id = UUID(independent_key["id"])
    independent_family_id = UUID(independent_key["credential_family_id"])
    assert independent_family_id != first_family_id
    independent = await api_harness.client.post(
        "/api/v1/public/chat/query",
        headers={
            "X-API-Key": independent_key["key"],
            "Idempotency-Key": "family-stable-chat",
        },
        json=payload,
    )
    assert independent.status_code == 200, independent.text
    assert independent.json() == first.json()
    assert len(provider_calls) == 4

    async with api_harness.session_factory() as session:
        usage_rows = list(
            (
                await session.scalars(select(LlmUsageRecord).order_by(LlmUsageRecord.created_at))
            ).all()
        )
        ledgers = list((await session.scalars(select(ChatIdempotencyRecord))).all())
    assert len(usage_rows) == 4
    assert len(ledgers) == 2
    assert all(row.status is LlmUsageStatus.SETTLED for row in usage_rows)
    first_usage = [row for row in usage_rows if row.api_key_id == first_key_id]
    independent_usage = [row for row in usage_rows if row.api_key_id == independent_id]
    assert len(first_usage) == 2
    assert len(independent_usage) == 2
    assert all(row.api_key_credential_family_id == first_family_id for row in first_usage)
    assert all(
        row.api_key_credential_family_id == independent_family_id for row in independent_usage
    )
    assert all(row.api_key_id != replacement_id for row in usage_rows)
