from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.errors import ApiError
from app.core.config import Settings
from app.db.base import Base
from app.db.models import ChatIdempotencyRecord, ChatIdempotencyStatus
from app.schemas.chat import ChatQueryRequest, ChatQueryResponse, ChatSourceStatus
from app.services.chat_idempotency import (
    ChatIdempotencyPrincipal,
    execute_chat_query_idempotently,
)
from app.services.chat_replay_authorization import ChatAuthorizationSnapshot
from app.services.chat_timeout import (
    CHAT_DISCONNECT_POLL_SECONDS,
    CHAT_SERVER_TIMEOUT_SECONDS,
    run_chat_with_budget,
)

pytest_plugins = ("test_integration_api",)


@pytest.mark.asyncio
async def test_chat_total_budget_cancels_the_active_upstream_before_a_second_phase() -> None:
    active_cancelled = asyncio.Event()
    second_phase_started = False

    async def operation() -> str:
        nonlocal second_phase_started
        try:
            await asyncio.Event().wait()
            second_phase_started = True
            return "unreachable"
        finally:
            active_cancelled.set()

    with pytest.raises(ApiError) as captured:
        await run_chat_with_budget(
            operation,
            is_disconnected=_always_connected,
            timeout_seconds=0.01,
            disconnect_poll_seconds=0.001,
        )

    assert captured.value.status_code == 504
    assert captured.value.code == "chat_request_timeout"
    assert active_cancelled.is_set()
    assert second_phase_started is False


@pytest.mark.asyncio
async def test_client_disconnect_cancels_the_active_upstream() -> None:
    active_cancelled = asyncio.Event()
    checks = 0

    async def is_disconnected() -> bool:
        nonlocal checks
        checks += 1
        return checks >= 2

    async def operation() -> str:
        try:
            await asyncio.Event().wait()
            return "unreachable"
        finally:
            active_cancelled.set()

    with pytest.raises(ApiError) as captured:
        await run_chat_with_budget(
            operation,
            is_disconnected=is_disconnected,
            timeout_seconds=1,
            disconnect_poll_seconds=0.001,
        )

    assert captured.value.status_code == 499
    assert captured.value.code == "client_disconnected"
    assert active_cancelled.is_set()


@pytest.mark.asyncio
async def test_success_cancels_the_disconnect_monitor_without_leaking_a_task() -> None:
    monitor_cancelled = asyncio.Event()

    async def monitored_connection() -> bool:
        try:
            await asyncio.Event().wait()
            return False
        finally:
            monitor_cancelled.set()

    result = await run_chat_with_budget(
        lambda: asyncio.sleep(0, result="complete"),
        is_disconnected=monitored_connection,
        timeout_seconds=1,
        disconnect_poll_seconds=0.001,
    )

    assert result == "complete"
    assert monitor_cancelled.is_set()


@pytest.mark.asyncio
async def test_outer_request_cancellation_propagates_to_the_active_operation() -> None:
    active_started = asyncio.Event()
    active_cancelled = asyncio.Event()

    async def operation() -> str:
        active_started.set()
        try:
            await asyncio.Event().wait()
            return "unreachable"
        finally:
            active_cancelled.set()

    request_task = asyncio.create_task(
        run_chat_with_budget(
            operation,
            is_disconnected=_always_connected,
            timeout_seconds=1,
            disconnect_poll_seconds=0.001,
        )
    )
    await asyncio.wait_for(active_started.wait(), timeout=1)
    request_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await request_task

    assert active_cancelled.is_set()


async def _always_connected() -> bool:
    return False


def test_production_chat_budget_is_explicit_and_bounded() -> None:
    assert CHAT_SERVER_TIMEOUT_SECONDS == 95
    assert 0 < CHAT_DISCONNECT_POLL_SECONDS <= 0.25


@pytest.mark.asyncio
async def test_authenticated_chat_timeout_returns_a_stable_504_contract(
    api_harness: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def timeout_before_operation(
        _operation: Any,
        *,
        is_disconnected: Any,
    ) -> ChatQueryResponse:
        assert callable(is_disconnected)
        raise ApiError(
            status_code=504,
            code="chat_request_timeout",
            message="The chat request exceeded its bounded processing time",
        )

    monkeypatch.setattr(
        "app.api.v1.routes.chat.run_chat_with_budget",
        timeout_before_operation,
    )
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases",
        headers=headers,
        json={"name": "Timeout contract"},
    )
    assert knowledge_base.status_code == 201, knowledge_base.text

    response = await api_harness.client.post(
        "/api/v1/chat/query",
        headers={**headers, "Idempotency-Key": "timeout-contract-key"},
        json={
            "knowledge_base_id": knowledge_base.json()["id"],
            "message": "bounded request",
            "limit": 5,
        },
    )

    assert response.status_code == 504
    assert response.json()["error"] == {
        "code": "chat_request_timeout",
        "message": "The chat request exceeded its bounded processing time",
    }


@pytest.mark.asyncio
async def test_api_key_chat_timeout_uses_the_same_stable_504_contract(
    api_harness: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def timeout_before_operation(
        _operation: Any,
        *,
        is_disconnected: Any,
    ) -> ChatQueryResponse:
        assert callable(is_disconnected)
        raise ApiError(
            status_code=504,
            code="chat_request_timeout",
            message="The chat request exceeded its bounded processing time",
        )

    monkeypatch.setattr(
        "app.api.v1.routes.public_api.run_chat_with_budget",
        timeout_before_operation,
    )
    tokens = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases",
        headers=admin_headers,
        json={"name": "Public timeout contract"},
    )
    assert knowledge_base.status_code == 201, knowledge_base.text
    api_key = await api_harness.client.post(
        "/api/v1/api-keys",
        headers=admin_headers,
        json={
            "name": "Timeout integration",
            "permission_codes": ["chat:query"],
            "knowledge_base_ids": [knowledge_base.json()["id"]],
            "requests_per_minute": 60,
        },
    )
    assert api_key.status_code == 201, api_key.text

    response = await api_harness.client.post(
        "/api/v1/public/chat/query",
        headers={
            "X-API-Key": api_key.json()["key"],
            "Idempotency-Key": "public-timeout-contract-key",
        },
        json={
            "knowledge_base_id": knowledge_base.json()["id"],
            "message": "bounded public request",
            "limit": 5,
        },
    )

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "chat_request_timeout"


@pytest_asyncio.fixture
async def idempotency_factory(
    tmp_path: Any,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'timeout.sqlite3'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    try:
        yield factory
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_timeout_terminalizes_idempotency_claim_and_retry_never_reexecutes(
    idempotency_factory: async_sessionmaker[AsyncSession],
) -> None:
    knowledge_base_id = uuid4()
    request = ChatQueryRequest(
        knowledge_base_id=knowledge_base_id,
        message="one provider outcome only",
    )
    principal = ChatIdempotencyPrincipal.for_user(uuid4())
    calls = 0
    started = asyncio.Event()
    settings = Settings(
        environment="test",
        deepseek_timeout_seconds=5,
        chat_idempotency_processing_timeout_seconds=60,
        chat_replay_encryption_keys={1: base64.urlsafe_b64encode(b"t" * 32).decode("ascii")},
        chat_replay_active_key_version=1,
    )

    async def authorize(_session: AsyncSession) -> ChatAuthorizationSnapshot:
        return ChatAuthorizationSnapshot(
            knowledge_base_id=knowledge_base_id,
            content_version=1,
        )

    async def blocked_operation() -> ChatQueryResponse:
        nonlocal calls
        calls += 1
        started.set()
        await asyncio.Event().wait()
        return ChatQueryResponse(
            knowledge_base_id=knowledge_base_id,
            answer="unreachable",
            citations=[],
            source_status=ChatSourceStatus(
                status="no_results",
                strategy="retrieval",
                reason="no_matching_content",
                citation_count=0,
            ),
        )

    async with idempotency_factory() as session:
        with pytest.raises(ApiError) as timed_out:
            await run_chat_with_budget(
                lambda: execute_chat_query_idempotently(
                    session,
                    settings,
                    principal=principal,
                    idempotency_key="timeout-terminal-key",
                    request=request,
                    authorize=authorize,
                    operation=blocked_operation,
                ),
                is_disconnected=_always_connected,
                timeout_seconds=1,
                disconnect_poll_seconds=0.001,
            )

    assert timed_out.value.code == "chat_request_timeout"
    assert started.is_set()
    async with idempotency_factory() as verification:
        record = await verification.scalar(select(ChatIdempotencyRecord))
        assert record is not None
        assert record.status is ChatIdempotencyStatus.OUTCOME_UNKNOWN

    async with idempotency_factory() as retry_session:
        with pytest.raises(ApiError) as retry:
            await execute_chat_query_idempotently(
                retry_session,
                settings,
                principal=principal,
                idempotency_key="timeout-terminal-key",
                request=request,
                authorize=authorize,
                operation=blocked_operation,
            )

    assert retry.value.code == "idempotency_outcome_unknown"
    assert calls == 1
