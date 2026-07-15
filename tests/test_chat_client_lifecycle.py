from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import uuid4

import pytest

from app.core.config import Settings
from app.db.models import KnowledgeBase, KnowledgeBaseAccessLevel, User
from app.schemas.chat import ChatQueryResponse
from app.schemas.knowledge_bases import KnowledgeSearchHit
from app.services import chat as chat_service
from app.services.access import AccessContext
from app.services.knowledge_bases import KnowledgeBaseAccess
from app.services.llm_provider import LlmChatResult, LlmProviderError, MeteringOutcome

ClientMode = Literal["generate", "review", "fail"]


@dataclass
class ClientLifecycle:
    opened: list[str] = field(default_factory=list)
    closed: list[str] = field(default_factory=list)

    def client(
        self,
        name: str,
        *,
        provider: str,
        model: str,
        configured: bool = True,
        mode: ClientMode = "generate",
    ) -> LifecycleClient:
        self.opened.append(name)
        return LifecycleClient(
            lifecycle=self,
            name=name,
            provider=provider,
            model=model,
            configured=configured,
            mode=mode,
        )

    def assert_balanced(self) -> None:
        assert sorted(self.closed) == sorted(self.opened)


class LifecycleClient:
    def __init__(
        self,
        *,
        lifecycle: ClientLifecycle,
        name: str,
        provider: str,
        model: str,
        configured: bool,
        mode: ClientMode,
    ) -> None:
        self._lifecycle = lifecycle
        self._name = name
        self.provider = provider
        self.model = model
        self.configured = configured
        self.mode = mode
        self.close_calls = 0

    async def complete_chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> LlmChatResult:
        del messages, temperature, max_tokens
        if self.mode == "fail":
            raise LlmProviderError(
                "llm_transport_error",
                provider=self.provider,
                retryable=True,
                metering_outcome=MeteringOutcome.NOT_STARTED,
            )
        content = (
            '{"verdict":"pass","unsupported_claims":[]}'
            if self.mode == "review"
            else '{"answer":"Approval is required [1].","table":null}'
        )
        return LlmChatResult(
            content=content,
            provider=self.provider,
            model=self.model,
            prompt_tokens=10,
            completion_tokens=5,
        )

    async def aclose(self) -> None:
        self.close_calls += 1
        assert self.close_calls == 1, f"{self._name} was closed more than once"
        self._lifecycle.closed.append(self._name)


class PassthroughExecutor:
    async def complete_chat(
        self,
        _session: object,
        *,
        client: LifecycleClient,
        messages: list[dict[str, str]],
        before_egress: Callable[[], Awaitable[bool]] | None = None,
        **_kwargs: Any,
    ) -> LlmChatResult:
        if before_egress is not None:
            assert await before_egress()
        return await client.complete_chat(messages)


@dataclass(frozen=True)
class ChatHarness:
    session: object
    settings: Settings
    access: AccessContext
    knowledge_base: KnowledgeBase

    async def answer(self, *, request_key: str) -> ChatQueryResponse:
        return await chat_service.answer_knowledge_query(
            self.session,  # type: ignore[arg-type]
            self.settings,
            self.access,
            knowledge_base_id=self.knowledge_base.id,
            message="What needs approval?",
            limit=5,
            idempotency_key=request_key,
            api_key_id=None,
        )


async def _install_harness(
    monkeypatch: pytest.MonkeyPatch,
    *,
    resolve: Callable[..., Awaitable[LifecycleClient]],
) -> ChatHarness:
    user = User(id=uuid4(), email=f"reader-{uuid4()}@example.com", password_hash="hash")
    knowledge_base = KnowledgeBase(
        id=uuid4(),
        owner_id=user.id,
        name="Policies",
        external_llm_processing_enabled=True,
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

    async def require_access(*_args: object, **_kwargs: object) -> KnowledgeBaseAccess:
        return KnowledgeBaseAccess(knowledge_base, KnowledgeBaseAccessLevel.READER)

    async def search(*_args: object, **_kwargs: object) -> list[KnowledgeSearchHit]:
        return [hit]

    async def egress_allowed(*_args: object, **_kwargs: object) -> bool:
        return True

    monkeypatch.setattr(chat_service, "require_knowledge_base_access", require_access)
    monkeypatch.setattr(chat_service, "search_knowledge_entries", search)
    monkeypatch.setattr(chat_service, "resolve_provider_client", resolve)
    monkeypatch.setattr(chat_service, "external_llm_egress_allowed", egress_allowed)
    monkeypatch.setattr(chat_service, "GovernedLlmExecutor", PassthroughExecutor)
    return ChatHarness(
        session=object(),
        settings=Settings(environment="test"),
        access=access,
        knowledge_base=knowledge_base,
    )


@pytest.mark.asyncio
async def test_unconfigured_generation_client_is_closed_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = ClientLifecycle()

    async def resolve(*_args: object, **_kwargs: object) -> LifecycleClient:
        return lifecycle.client(
            "generation",
            provider="deepseek",
            model="deepseek-chat",
            configured=False,
        )

    harness = await _install_harness(monkeypatch, resolve=resolve)
    response = await harness.answer(request_key="unconfigured-client")

    assert response.source_status.reason == "provider_unconfigured"
    lifecycle.assert_balanced()


@pytest.mark.asyncio
async def test_generation_failure_closes_generation_client_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = ClientLifecycle()

    async def resolve(*_args: object, **_kwargs: object) -> LifecycleClient:
        return lifecycle.client(
            "generation",
            provider="deepseek",
            model="deepseek-chat",
            mode="fail",
        )

    harness = await _install_harness(monkeypatch, resolve=resolve)
    response = await harness.answer(request_key="generation-failure")

    assert response.source_status.reason == "provider_unavailable"
    lifecycle.assert_balanced()


@pytest.mark.asyncio
async def test_unavailable_reviewer_closes_both_clients_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = ClientLifecycle()

    async def resolve(
        *_args: object,
        provider: str | None = None,
        **_kwargs: object,
    ) -> LifecycleClient:
        if provider is None:
            return lifecycle.client("generation", provider="deepseek", model="deepseek-chat")
        return lifecycle.client(
            "review", provider=provider, model=f"{provider}-review", mode="fail"
        )

    harness = await _install_harness(monkeypatch, resolve=resolve)
    response = await harness.answer(request_key="review-unavailable")

    assert response.source_status.reason == "answer_review_unavailable"
    lifecycle.assert_balanced()


@pytest.mark.asyncio
async def test_success_closes_generation_and_review_clients_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = ClientLifecycle()

    async def resolve(
        *_args: object,
        provider: str | None = None,
        **_kwargs: object,
    ) -> LifecycleClient:
        if provider is None:
            return lifecycle.client("generation", provider="deepseek", model="deepseek-chat")
        return lifecycle.client(
            "review", provider=provider, model=f"{provider}-review", mode="review"
        )

    harness = await _install_harness(monkeypatch, resolve=resolve)
    response = await harness.answer(request_key="success")

    assert response.mode == "rag"
    lifecycle.assert_balanced()


@pytest.mark.asyncio
async def test_skipped_reviewer_candidate_is_closed_before_successful_reviewer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = ClientLifecycle()

    async def resolve(
        *_args: object,
        provider: str | None = None,
        **_kwargs: object,
    ) -> LifecycleClient:
        if provider is None:
            return lifecycle.client("generation", provider="deepseek", model="deepseek-chat")
        if provider == "qwen":
            return lifecycle.client(
                "skipped-qwen",
                provider="qwen",
                model="qwen-plus",
                configured=False,
            )
        return lifecycle.client(
            "review-minimax",
            provider="minimax",
            model="MiniMax-M2.7",
            mode="review",
        )

    harness = await _install_harness(monkeypatch, resolve=resolve)
    response = await harness.answer(request_key="skipped-candidate")

    assert response.mode == "rag"
    lifecycle.assert_balanced()
