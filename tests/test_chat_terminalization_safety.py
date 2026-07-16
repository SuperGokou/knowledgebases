from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.services.chat_idempotency as chat_idempotency
from app.api.errors import ApiError
from app.core.config import Settings
from app.db.base import Base
from app.db.models import ChatIdempotencyRecord, ChatIdempotencyStatus
from app.schemas.chat import ChatQueryRequest, ChatQueryResponse, ChatSourceStatus
from app.services.chat_idempotency import (
    ChatIdempotencyPrincipal,
    ChatTerminalizationAck,
    chat_finalization_backlog_size,
    execute_chat_query_idempotently,
)
from app.services.chat_replay_authorization import ChatAuthorizationSnapshot
from app.services.chat_safety import chat_safety_poisoned
from app.services.chat_timeout import run_chat_with_budget


@pytest_asyncio.fixture
async def terminalization_factory(
    tmp_path: Path,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    database_path = tmp_path / "terminalization.sqlite3"
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    try:
        yield factory
    finally:
        await engine.dispose()


def _settings() -> Settings:
    return Settings(
        environment="test",
        deepseek_timeout_seconds=5,
        chat_idempotency_processing_timeout_seconds=60,
        chat_replay_encryption_keys={1: base64.urlsafe_b64encode(b"t" * 32).decode("ascii")},
        chat_replay_active_key_version=1,
    )


def _response(knowledge_base_id: UUID) -> ChatQueryResponse:
    return ChatQueryResponse(
        knowledge_base_id=knowledge_base_id,
        answer="verified answer",
        citations=[],
        source_status=ChatSourceStatus(
            status="no_results",
            strategy="retrieval",
            reason="no_matching_content",
            citation_count=0,
        ),
    )


def _install_terminal_fault_session(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail_unknown_before_commit: int = 0,
    fail_completed_after_commit: int = 0,
    fail_terminal_rollback: int = 0,
) -> type[Any]:
    class FaultSession(AsyncSession):
        unknown_before_remaining = fail_unknown_before_commit
        completed_after_remaining = fail_completed_after_commit
        terminal_rollback_remaining = fail_terminal_rollback

        unknown_commit_attempts = 0
        completed_commit_attempts = 0
        terminal_rollback_attempts = 0

        def _has_status(self, status: ChatIdempotencyStatus) -> bool:
            return any(
                isinstance(item, ChatIdempotencyRecord) and item.status is status
                for item in self.identity_map.values()
            )

        async def commit(self) -> None:
            unknown = self._has_status(ChatIdempotencyStatus.OUTCOME_UNKNOWN)
            completed = self._has_status(ChatIdempotencyStatus.COMPLETED)
            if unknown:
                type(self).unknown_commit_attempts += 1
            if completed:
                type(self).completed_commit_attempts += 1
            if unknown and type(self).unknown_before_remaining:
                type(self).unknown_before_remaining -= 1
                raise OSError("terminal commit failed before commit")

            await super().commit()

            if completed and type(self).completed_after_remaining:
                type(self).completed_after_remaining -= 1
                raise OSError("terminal commit acknowledgement lost")

        async def rollback(self) -> None:
            terminal = any(
                self._has_status(status)
                for status in (
                    ChatIdempotencyStatus.COMPLETED,
                    ChatIdempotencyStatus.OUTCOME_UNKNOWN,
                    ChatIdempotencyStatus.INVALIDATED,
                )
            )
            if terminal:
                type(self).terminal_rollback_attempts += 1
            if terminal and type(self).terminal_rollback_remaining:
                type(self).terminal_rollback_remaining -= 1
                raise OSError("terminal rollback failed")
            await super().rollback()

    monkeypatch.setattr(chat_idempotency, "AsyncSession", FaultSession)
    return FaultSession


@pytest.mark.asyncio
async def test_unknown_terminal_commit_retries_in_fresh_session(
    terminalization_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fault_session = _install_terminal_fault_session(
        monkeypatch,
        fail_unknown_before_commit=1,
    )
    knowledge_base_id = uuid4()
    request = ChatQueryRequest(
        knowledge_base_id=knowledge_base_id,
        message="operation outcome is unknown",
    )
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    operation_calls = 0

    async def authorize(_session: AsyncSession) -> ChatAuthorizationSnapshot:
        return ChatAuthorizationSnapshot(
            knowledge_base_id=knowledge_base_id,
            content_version=1,
        )

    async def operation() -> ChatQueryResponse:
        nonlocal operation_calls
        operation_calls += 1
        raise OSError("provider acknowledgement lost")

    async with terminalization_factory() as session:
        with pytest.raises(ApiError) as first:
            await execute_chat_query_idempotently(
                session,
                _settings(),
                principal=principal,
                idempotency_key="unknown-commit-retry",
                request=request,
                authorize=authorize,
                operation=operation,
            )
    assert first.value.code == "idempotency_outcome_unknown"

    async with terminalization_factory() as retry_session:
        with pytest.raises(ApiError) as retry:
            await execute_chat_query_idempotently(
                retry_session,
                _settings(),
                principal=principal,
                idempotency_key="unknown-commit-retry",
                request=request,
                authorize=authorize,
                operation=operation,
            )
    assert retry.value.code == "idempotency_outcome_unknown"

    async with terminalization_factory() as verification:
        record = await verification.scalar(select(ChatIdempotencyRecord))
        assert record is not None
        assert record.status is ChatIdempotencyStatus.OUTCOME_UNKNOWN

    assert fault_session.unknown_commit_attempts == 2
    assert operation_calls == 1
    assert chat_finalization_backlog_size() == 0
    assert chat_safety_poisoned() is False


@pytest.mark.asyncio
async def test_completed_commit_ack_loss_returns_and_replays_response(
    terminalization_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fault_session = _install_terminal_fault_session(
        monkeypatch,
        fail_completed_after_commit=1,
    )
    knowledge_base_id = uuid4()
    request = ChatQueryRequest(
        knowledge_base_id=knowledge_base_id,
        message="completed commit acknowledgement is lost",
    )
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    operation_calls = 0

    async def authorize(_session: AsyncSession) -> ChatAuthorizationSnapshot:
        return ChatAuthorizationSnapshot(
            knowledge_base_id=knowledge_base_id,
            content_version=1,
        )

    async def operation() -> ChatQueryResponse:
        nonlocal operation_calls
        operation_calls += 1
        return _response(knowledge_base_id)

    async with terminalization_factory() as session:
        first = await execute_chat_query_idempotently(
            session,
            _settings(),
            principal=principal,
            idempotency_key="completed-commit-ack-loss",
            request=request,
            authorize=authorize,
            operation=operation,
        )
    async with terminalization_factory() as replay_session:
        replay = await execute_chat_query_idempotently(
            replay_session,
            _settings(),
            principal=principal,
            idempotency_key="completed-commit-ack-loss",
            request=request,
            authorize=authorize,
            operation=operation,
        )
    async with terminalization_factory() as verification:
        record = await verification.scalar(select(ChatIdempotencyRecord))
        assert record is not None
        assert record.status is ChatIdempotencyStatus.COMPLETED

    assert first == replay
    assert first.answer == "verified answer"
    assert fault_session.completed_commit_attempts == 1
    assert operation_calls == 1
    assert chat_finalization_backlog_size() == 0
    assert chat_safety_poisoned() is False


@pytest.mark.asyncio
async def test_completed_commit_survives_terminal_rollback_failure(
    terminalization_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fault_session = _install_terminal_fault_session(
        monkeypatch,
        fail_completed_after_commit=1,
        fail_terminal_rollback=1,
    )
    knowledge_base_id = uuid4()
    request = ChatQueryRequest(
        knowledge_base_id=knowledge_base_id,
        message="terminal rollback fails after completed commit",
    )
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    operation_calls = 0

    async def authorize(_session: AsyncSession) -> ChatAuthorizationSnapshot:
        return ChatAuthorizationSnapshot(
            knowledge_base_id=knowledge_base_id,
            content_version=1,
        )

    async def operation() -> ChatQueryResponse:
        nonlocal operation_calls
        operation_calls += 1
        return _response(knowledge_base_id)

    async with terminalization_factory() as session:
        first = await execute_chat_query_idempotently(
            session,
            _settings(),
            principal=principal,
            idempotency_key="completed-rollback-failure",
            request=request,
            authorize=authorize,
            operation=operation,
        )
    async with terminalization_factory() as replay_session:
        replay = await execute_chat_query_idempotently(
            replay_session,
            _settings(),
            principal=principal,
            idempotency_key="completed-rollback-failure",
            request=request,
            authorize=authorize,
            operation=operation,
        )
    async with terminalization_factory() as verification:
        record = await verification.scalar(select(ChatIdempotencyRecord))
        assert record is not None
        assert record.status is ChatIdempotencyStatus.COMPLETED

    assert first == replay
    assert fault_session.completed_commit_attempts == 1
    assert fault_session.terminal_rollback_attempts >= 1
    assert fault_session.terminal_rollback_remaining == 0
    assert operation_calls == 1
    assert chat_finalization_backlog_size() == 0
    assert chat_safety_poisoned() is False


@pytest.mark.asyncio
async def test_final_store_cancellation_terminalizes_unknown_before_restoring_cancel(
    terminalization_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    knowledge_base_id = uuid4()
    request = ChatQueryRequest(
        knowledge_base_id=knowledge_base_id,
        message="cancel during final store",
    )
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    store_started = asyncio.Event()
    operation_calls = 0

    async def authorize(_session: AsyncSession) -> ChatAuthorizationSnapshot:
        return ChatAuthorizationSnapshot(
            knowledge_base_id=knowledge_base_id,
            content_version=1,
        )

    async def operation() -> ChatQueryResponse:
        nonlocal operation_calls
        operation_calls += 1
        return _response(knowledge_base_id)

    async def blocked_store(*_args: object, **_kwargs: object) -> None:
        store_started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(chat_idempotency, "_store_completed_response", blocked_store)
    async with terminalization_factory() as session:
        request_task = asyncio.create_task(
            execute_chat_query_idempotently(
                session,
                _settings(),
                principal=principal,
                idempotency_key="final-store-cancel",
                request=request,
                authorize=authorize,
                operation=operation,
            )
        )
        await asyncio.wait_for(store_started.wait(), timeout=1)
        request_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request_task

    async with terminalization_factory() as verification:
        record = await verification.scalar(select(ChatIdempotencyRecord))
        assert record is not None
        assert record.status is ChatIdempotencyStatus.OUTCOME_UNKNOWN

    async with terminalization_factory() as retry_session:
        with pytest.raises(ApiError) as retry:
            await execute_chat_query_idempotently(
                retry_session,
                _settings(),
                principal=principal,
                idempotency_key="final-store-cancel",
                request=request,
                authorize=authorize,
                operation=operation,
            )
    assert retry.value.code == "idempotency_outcome_unknown"
    assert operation_calls == 1
    assert chat_safety_poisoned() is False


@pytest.mark.asyncio
async def test_completed_commit_is_recognized_after_transport_error(
    terminalization_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    knowledge_base_id = uuid4()
    request = ChatQueryRequest(
        knowledge_base_id=knowledge_base_id,
        message="commit then lose acknowledgement",
    )
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    operation_calls = 0

    async def authorize(_session: AsyncSession) -> ChatAuthorizationSnapshot:
        return ChatAuthorizationSnapshot(
            knowledge_base_id=knowledge_base_id,
            content_version=1,
        )

    async def operation() -> ChatQueryResponse:
        nonlocal operation_calls
        operation_calls += 1
        return _response(knowledge_base_id)

    original_store = chat_idempotency._store_completed_response

    async def store_then_raise(*args: object, **kwargs: object) -> None:
        await cast(Any, original_store)(*args, **kwargs)
        raise OSError("commit acknowledgement lost")

    monkeypatch.setattr(chat_idempotency, "_store_completed_response", store_then_raise)
    async with terminalization_factory() as session:
        first = await execute_chat_query_idempotently(
            session,
            _settings(),
            principal=principal,
            idempotency_key="commit-ack-lost",
            request=request,
            authorize=authorize,
            operation=operation,
        )
    assert first.answer == "verified answer"
    assert chat_safety_poisoned() is False

    monkeypatch.setattr(chat_idempotency, "_store_completed_response", original_store)
    async with terminalization_factory() as replay_session:
        replay = await execute_chat_query_idempotently(
            replay_session,
            _settings(),
            principal=principal,
            idempotency_key="commit-ack-lost",
            request=request,
            authorize=authorize,
            operation=operation,
        )
    assert replay.answer == "verified answer"
    assert operation_calls == 1


@pytest.mark.asyncio
async def test_terminalization_failure_preserves_cancel_and_blocks_new_chat(
    terminalization_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    knowledge_base_id = uuid4()
    request = ChatQueryRequest(
        knowledge_base_id=knowledge_base_id,
        message="terminal writer unavailable",
    )
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    operation_started = asyncio.Event()

    async def authorize(_session: AsyncSession) -> ChatAuthorizationSnapshot:
        return ChatAuthorizationSnapshot(
            knowledge_base_id=knowledge_base_id,
            content_version=1,
        )

    async def blocked_operation() -> ChatQueryResponse:
        operation_started.set()
        await asyncio.Event().wait()
        return _response(knowledge_base_id)

    async def failed_terminalizer(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(
        chat_idempotency,
        "_reconcile_outcome_unknown",
        failed_terminalizer,
    )
    async with terminalization_factory() as session:
        request_task = asyncio.create_task(
            execute_chat_query_idempotently(
                session,
                _settings(),
                principal=principal,
                idempotency_key="terminalizer-failure",
                request=request,
                authorize=authorize,
                operation=blocked_operation,
            )
        )
        await asyncio.wait_for(operation_started.wait(), timeout=1)
        request_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request_task

    assert chat_safety_poisoned() is True
    new_operation_started = False

    async def must_not_start() -> str:
        nonlocal new_operation_started
        new_operation_started = True
        return "unsafe"

    with pytest.raises(ApiError) as blocked:
        await run_chat_with_budget(
            must_not_start,
            is_disconnected=lambda: asyncio.sleep(0, result=False),
            timeout_seconds=1,
            operation_cleanup_seconds=0.25,
        )
    assert blocked.value.code == "chat_safety_poisoned"
    assert new_operation_started is False

    async with terminalization_factory() as verification:
        record = await verification.scalar(select(ChatIdempotencyRecord))
        assert record is not None
        assert record.status is ChatIdempotencyStatus.PROCESSING


@pytest.mark.asyncio
async def test_terminalization_deadline_supervises_once_and_poison_is_sticky(
    terminalization_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    knowledge_base_id = uuid4()
    request = ChatQueryRequest(
        knowledge_base_id=knowledge_base_id,
        message="terminal writer deadline",
    )
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    operation_started = asyncio.Event()
    terminalizer_started = asyncio.Event()
    release_terminalizer = asyncio.Event()
    terminalizer_cancellations = 0

    async def authorize(_session: AsyncSession) -> ChatAuthorizationSnapshot:
        return ChatAuthorizationSnapshot(
            knowledge_base_id=knowledge_base_id,
            content_version=1,
        )

    async def blocked_operation() -> ChatQueryResponse:
        operation_started.set()
        await asyncio.Event().wait()
        return _response(knowledge_base_id)

    async def stuck_terminalizer(
        _factory: object,
        _settings_value: object,
        descriptor: Any,
    ) -> ChatTerminalizationAck:
        nonlocal terminalizer_cancellations
        terminalizer_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            terminalizer_cancellations += 1
            await release_terminalizer.wait()
        return ChatTerminalizationAck(
            record_id=descriptor.record_id,
            status=ChatIdempotencyStatus.OUTCOME_UNKNOWN,
        )

    monkeypatch.setattr(
        chat_idempotency,
        "_reconcile_outcome_unknown",
        stuck_terminalizer,
    )
    monkeypatch.setattr(
        chat_idempotency,
        "_CHAT_TERMINALIZATION_TIMEOUT_SECONDS",
        0.5,
    )
    async with terminalization_factory() as session:
        request_task = asyncio.create_task(
            execute_chat_query_idempotently(
                session,
                _settings(),
                principal=principal,
                idempotency_key="terminalizer-deadline",
                request=request,
                authorize=authorize,
                operation=blocked_operation,
            )
        )
        await asyncio.wait_for(operation_started.wait(), timeout=1)
        request_task.cancel()
        await asyncio.wait_for(terminalizer_started.wait(), timeout=1)
        with pytest.raises(asyncio.CancelledError):
            await request_task

    assert terminalizer_cancellations == 1
    assert chat_finalization_backlog_size() == 1
    assert chat_safety_poisoned() is True

    release_terminalizer.set()
    for _ in range(100):
        if chat_finalization_backlog_size() == 0:
            break
        await asyncio.sleep(0.01)
    assert chat_finalization_backlog_size() == 0
    assert chat_safety_poisoned() is True
