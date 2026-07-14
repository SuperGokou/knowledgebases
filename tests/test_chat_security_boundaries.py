from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import uuid4

import pytest
from fastapi import Request
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.api.errors import ApiError
from app.api.v1.routes.knowledge_bases import update_knowledge_base
from app.core.config import Settings
from app.db.base import Base
from app.db.models import (
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    LlmBudgetPolicy,
    LlmModelPrice,
    User,
)
from app.schemas.knowledge_bases import KnowledgeBaseUpdate, KnowledgeSearchHit
from app.services import chat as chat_service
from app.services.access import AccessContext
from app.services.knowledge_bases import KnowledgeBaseAccess
from app.services.llm_provider import LlmChatResult
from app.services.llm_usage import GovernedLlmExecutor, LlmUsageDimensions


class ConsentSession:
    def __init__(self, *, committed_consent: bool) -> None:
        self.committed_consent = committed_consent
        self.scalar_count = 0
        self.rollback_count = 0
        self.commit_count = 0

    async def scalar(self, _statement: object) -> bool:
        self.scalar_count += 1
        return self.committed_consent

    async def rollback(self) -> None:
        self.rollback_count += 1

    async def commit(self) -> None:
        self.commit_count += 1


class RecordingClient:
    configured = True

    def __init__(self, *, provider: str = "qwen", model: str = "qwen-plus") -> None:
        self.provider = provider
        self.model = model
        self.calls: list[list[dict[str, str]]] = []

    async def complete_chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> LlmChatResult:
        del temperature, max_tokens
        self.calls.append(messages)
        is_review = "strict grounding auditor" in messages[0]["content"]
        return LlmChatResult(
            content=(
                '{"verdict":"pass","unsupported_claims":[]}'
                if is_review
                else '{"answer":"Approved [1].","table":null}'
            ),
            provider=self.provider,
            model=self.model,
            prompt_tokens=10,
            completion_tokens=5,
        )


class PassthroughExecutor:
    async def complete_chat(
        self,
        _session: object,
        *,
        client: RecordingClient,
        messages: list[dict[str, str]],
        before_egress: Callable[[], Awaitable[bool]] | None = None,
        **_kwargs: Any,
    ) -> LlmChatResult:
        if before_egress is not None and not await before_egress():
            return LlmChatResult(
                content="",
                provider=client.provider,
                model=client.model,
                prompt_tokens=0,
                completion_tokens=0,
            )
        return await client.complete_chat(messages)


def _chat_context(*, consent: bool) -> tuple[KnowledgeBase, AccessContext, KnowledgeSearchHit]:
    user = User(id=uuid4(), email=f"reader-{uuid4()}@example.com", password_hash="hash")
    knowledge_base = KnowledgeBase(
        id=uuid4(),
        owner_id=user.id,
        name="Policies",
        external_llm_processing_enabled=consent,
    )
    access = AccessContext(
        user=user,
        permissions=frozenset({"chat:query"}),
        limits={},
        role_ids=frozenset(),
        max_role_priority=0,
    )
    hit = KnowledgeSearchHit(
        entry_id=uuid4(),
        source_file_id=None,
        title="Approval policy",
        excerpt="Approval is required.",
        source_path=None,
        format_version="okf/0.1",
    )
    return knowledge_base, access, hit


async def _install_chat_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    knowledge_base: KnowledgeBase,
    hit: KnowledgeSearchHit,
    resolve: Callable[..., Awaitable[RecordingClient]],
) -> None:
    async def require_access(*_args: object, **_kwargs: object) -> KnowledgeBaseAccess:
        return KnowledgeBaseAccess(knowledge_base, KnowledgeBaseAccessLevel.READER)

    async def search(*_args: object, **_kwargs: object) -> list[KnowledgeSearchHit]:
        return [hit]

    async def egress_allowed(session: ConsentSession, **_kwargs: object) -> bool:
        allowed = await session.scalar(object())
        await session.commit()
        return allowed

    monkeypatch.setattr(chat_service, "require_knowledge_base_access", require_access)
    monkeypatch.setattr(chat_service, "search_knowledge_entries", search)
    monkeypatch.setattr(chat_service, "resolve_provider_client", resolve)
    monkeypatch.setattr(chat_service, "external_llm_egress_allowed", egress_allowed)
    monkeypatch.setattr(chat_service, "GovernedLlmExecutor", PassthroughExecutor)


@pytest.mark.asyncio
async def test_consent_is_rechecked_at_the_provider_egress_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    knowledge_base, access, hit = _chat_context(consent=True)
    session = ConsentSession(committed_consent=False)
    client = RecordingClient()

    async def resolve(*_args: object, **_kwargs: object) -> RecordingClient:
        return client

    await _install_chat_fakes(
        monkeypatch,
        knowledge_base=knowledge_base,
        hit=hit,
        resolve=resolve,
    )

    response = await chat_service.answer_knowledge_query(
        session,  # type: ignore[arg-type]
        Settings(environment="test"),
        access,
        knowledge_base_id=knowledge_base.id,
        message="What needs approval?",
        limit=5,
        idempotency_key="consent-race",
        api_key_id=None,
    )

    assert response.mode == "retrieval"
    assert client.calls == []
    assert session.scalar_count == 1
    assert session.rollback_count == 0
    assert session.commit_count == 1


@pytest.mark.asyncio
async def test_same_provider_cannot_self_approve_generated_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    knowledge_base, access, hit = _chat_context(consent=True)
    session = ConsentSession(committed_consent=True)
    only_client = RecordingClient()

    async def resolve(*_args: object, **_kwargs: object) -> RecordingClient:
        return only_client

    await _install_chat_fakes(
        monkeypatch,
        knowledge_base=knowledge_base,
        hit=hit,
        resolve=resolve,
    )

    response = await chat_service.answer_knowledge_query(
        session,  # type: ignore[arg-type]
        Settings(environment="test"),
        access,
        knowledge_base_id=knowledge_base.id,
        message="What needs approval?",
        limit=5,
        idempotency_key="independent-review",
        api_key_id=None,
    )

    assert response.mode == "retrieval"
    assert response.source_status.reason == "independent_reviewer_unavailable"
    assert len(only_client.calls) == 1


@pytest.mark.asyncio
async def test_committed_revocation_cannot_cross_an_active_provider_egress_lease() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with factory() as setup:
        user = User(
            id=uuid4(),
            email=f"manager-{uuid4()}@example.com",
            password_hash="hash",
            is_superuser=True,
        )
        knowledge_base = KnowledgeBase(
            id=uuid4(),
            owner_id=user.id,
            name="Consent serialization",
            external_llm_processing_enabled=True,
        )
        setup.add_all(
            [
                user,
                knowledge_base,
                LlmModelPrice(
                    provider="qwen",
                    model="qwen-plus",
                    input_micro_usd_per_million_tokens=1_000_000,
                    output_micro_usd_per_million_tokens=2_000_000,
                    active=True,
                ),
                LlmBudgetPolicy(
                    name="Consent test budget",
                    tenant_key="default",
                    daily_token_limit=100_000,
                    monthly_token_limit=1_000_000,
                    daily_cost_limit_micro_usd=100_000,
                    monthly_cost_limit_micro_usd=1_000_000,
                    enabled=True,
                ),
            ]
        )
        await setup.commit()
        user_id = user.id
        knowledge_base_id = knowledge_base.id

    started = asyncio.Event()
    finish = asyncio.Event()

    class BlockingClient:
        provider = "qwen"
        model = "qwen-plus"

        async def complete_chat(
            self,
            messages: list[dict[str, str]],
            *,
            temperature: float = 0.2,
            max_tokens: int | None = None,
        ) -> LlmChatResult:
            del messages, temperature, max_tokens
            started.set()
            await finish.wait()
            return LlmChatResult(
                content="done",
                provider=self.provider,
                model=self.model,
                prompt_tokens=10,
                completion_tokens=5,
            )

    async with factory() as call_session, factory() as manager_session:
        call_kb = await call_session.get(KnowledgeBase, knowledge_base_id)
        manager = await manager_session.get(User, user_id)
        assert call_kb is not None and manager is not None
        access = AccessContext(
            user=manager,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset(),
            max_role_priority=10_000,
        )

        operation = asyncio.create_task(
            GovernedLlmExecutor().complete_chat(
                call_session,
                client=BlockingClient(),
                dimensions=LlmUsageDimensions(
                    tenant_key="default",
                    user_id=user_id,
                    api_key_id=None,
                    knowledge_base_id=knowledge_base_id,
                    provider="qwen",
                    model="qwen-plus",
                    operation="chat.answer",
                ),
                idempotency_key="active-egress-lease",
                messages=[{"role": "user", "content": "private evidence"}],
                maximum_output_tokens=100,
                before_egress=lambda: chat_service._external_processing_allowed_at_egress(
                    call_session,
                    call_kb,
                    access,
                    None,
                ),
            )
        )
        await started.wait()

        request = Request({"type": "http", "headers": []})
        request.state.request_id = "consent-revocation-test"
        denied: ApiError | None = None
        try:
            try:
                await update_knowledge_base(
                    knowledge_base_id,
                    KnowledgeBaseUpdate(external_llm_processing_enabled=False),
                    request,
                    manager_session,  # type: ignore[arg-type]
                    access,
                )
            except ApiError as error:
                denied = error
            assert denied is not None
            assert denied.status_code == 409
            assert denied.code == "external_llm_processing_in_progress"
            await manager_session.rollback()
            still_enabled = await manager_session.get(KnowledgeBase, knowledge_base_id)
            assert still_enabled is not None
            await manager_session.refresh(still_enabled)
            assert still_enabled.external_llm_processing_enabled is True
        finally:
            finish.set()
            await operation

        manager = await manager_session.get(User, user_id)
        assert manager is not None
        access = AccessContext(
            user=manager,
            permissions=frozenset({"*"}),
            limits={},
            role_ids=frozenset(),
            max_role_priority=10_000,
        )
        updated = await update_knowledge_base(
            knowledge_base_id,
            KnowledgeBaseUpdate(external_llm_processing_enabled=False),
            request,
            manager_session,  # type: ignore[arg-type]
            access,
        )
        assert updated.external_llm_processing_enabled is False

    await engine.dispose()
