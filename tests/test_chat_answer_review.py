from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.schemas.chat import ChatCitation
from app.services import chat as chat_service
from app.services.chat import (
    _GeneratedChatResponse,
    _review_generated_answer,
    _run_grounding_review,
)
from app.services.llm_provider import LlmChatResult, LlmProviderError, MeteringOutcome
from app.services.llm_usage import LlmBudgetConfigurationUnavailable


def _citation() -> ChatCitation:
    return ChatCitation(
        entry_id=uuid4(),
        source_file_id=None,
        title="公司概况",
        excerpt="江苏和熠光显有限公司成立于 2023 年。",
        source_path="company/profile.md",
        format_version="okf/0.1",
        citation_number=1,
        marker="[1]",
    )


class ReviewClient:
    provider = "deepseek"
    model = "deepseek-chat"
    configured = True

    def __init__(self, content: str | None = None, *, fail: bool = False) -> None:
        self.content = content
        self.fail = fail
        self.close_count = 0

    async def complete_chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> LlmChatResult:
        del messages, temperature, max_tokens
        if self.fail:
            raise LlmProviderError("llm_transport_error", provider=self.provider, retryable=True)
        return LlmChatResult(
            content=self.content or "",
            provider=self.provider,
            model=self.model,
            prompt_tokens=10,
            completion_tokens=5,
        )

    async def aclose(self) -> None:
        self.close_count += 1


@pytest.mark.asyncio
async def test_answer_review_passes_only_explicit_grounding_verdict() -> None:
    generated = _GeneratedChatResponse(answer="公司成立于 2023 年 [1]。")

    result = await _review_generated_answer(
        ReviewClient('{"verdict":"pass","unsupported_claims":[]}'),
        question="公司何时成立？",
        generated=generated,
        citations=[_citation()],
    )

    assert result == "semantic_verified"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("client", "expected"),
    [
        (
            ReviewClient('{"verdict":"fail","unsupported_claims":["注册资本为一亿元"]}'),
            "answer_review_rejected",
        ),
        (ReviewClient("not-json"), "answer_review_invalid"),
        (ReviewClient(fail=True), "answer_review_unavailable"),
    ],
)
async def test_answer_review_fails_closed(client: ReviewClient, expected: str) -> None:
    generated = _GeneratedChatResponse(answer="公司注册资本为一亿元 [1]。")

    result = await _review_generated_answer(
        client,
        question="公司注册资本？",
        generated=generated,
        citations=[_citation()],
    )

    assert result == expected


def test_chat_service_has_no_orphan_recursive_provider_wrapper() -> None:
    assert not hasattr(chat_service, "_answer_with_provider")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "first_error",
    [
        LlmProviderError(
            "llm_upstream_error",
            provider="deepseek",
            retryable=True,
            upstream_status=429,
            metering_outcome=MeteringOutcome.NOT_STARTED,
        ),
        LlmProviderError(
            "llm_incomplete_output",
            provider="deepseek",
            retryable=True,
            metering_outcome=MeteringOutcome.KNOWN,
            prompt_tokens=20,
            completion_tokens=10,
        ),
        LlmBudgetConfigurationUnavailable("reviewer budget policy missing"),
    ],
)
async def test_review_gate_uses_next_reviewer_after_safe_pre_egress_failure(
    monkeypatch: pytest.MonkeyPatch,
    first_error: Exception,
) -> None:
    first = ReviewClient()
    first.provider = "deepseek"
    first.model = "deepseek-v4-flash"
    second = ReviewClient('{"verdict":"pass","unsupported_claims":[]}')
    second.provider = "minimax"
    second.model = "MiniMax-M2.7"

    async def fake_resolve(*_args: object, **_kwargs: object) -> list[ReviewClient]:
        return [first, second]

    calls: list[str] = []

    class Executor:
        async def complete_chat(self, *_args: object, client: ReviewClient, **_kwargs: object):
            calls.append(client.provider)
            if client is first:
                raise first_error
            return await client.complete_chat([])

    monkeypatch.setattr(chat_service, "_resolve_independent_review_clients", fake_resolve)
    result = await _run_grounding_review(
        SimpleNamespace(),
        SimpleNamespace(llm_tenant_key="default"),
        SimpleNamespace(user=SimpleNamespace(id=uuid4())),
        executor=Executor(),
        knowledge_base=SimpleNamespace(id=uuid4()),
        knowledge_base_id=uuid4(),
        api_key_id=None,
        generation_provider="qwen",
        generation_model="qwen-plus",
        idempotency_key="review-failover-regression",
        question="公司何时成立？",
        generated=_GeneratedChatResponse(answer="公司成立于 2023 年 [1]。"),
        citations=[_citation()],
    )

    assert result == "semantic_verified"
    assert calls == ["deepseek", "minimax"]
    assert first.close_count == 1
    assert second.close_count == 1


@pytest.mark.asyncio
async def test_review_gate_does_not_retry_unknown_metering_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = ReviewClient()
    first.provider = "deepseek"
    first.model = "deepseek-v4-flash"
    second = ReviewClient('{"verdict":"pass","unsupported_claims":[]}')
    second.provider = "minimax"
    second.model = "MiniMax-M2.7"

    async def fake_resolve(*_args: object, **_kwargs: object) -> list[ReviewClient]:
        return [first, second]

    calls: list[str] = []

    class Executor:
        async def complete_chat(self, *_args: object, client: ReviewClient, **_kwargs: object):
            calls.append(client.provider)
            raise LlmProviderError(
                "llm_transport_error",
                provider=client.provider,
                retryable=True,
                metering_outcome=MeteringOutcome.UNKNOWN,
            )

    monkeypatch.setattr(chat_service, "_resolve_independent_review_clients", fake_resolve)
    result = await _run_grounding_review(
        SimpleNamespace(),
        SimpleNamespace(llm_tenant_key="default"),
        SimpleNamespace(user=SimpleNamespace(id=uuid4())),
        executor=Executor(),
        knowledge_base=SimpleNamespace(id=uuid4()),
        knowledge_base_id=uuid4(),
        api_key_id=None,
        generation_provider="qwen",
        generation_model="qwen-plus",
        idempotency_key="review-unknown-metering-regression",
        question="公司何时成立？",
        generated=_GeneratedChatResponse(answer="公司成立于 2023 年 [1]。"),
        citations=[_citation()],
    )

    assert result == "answer_review_unavailable"
    assert calls == ["deepseek"]
    assert first.close_count == 1
    assert second.close_count == 1


@pytest.mark.asyncio
async def test_review_gate_closes_partial_candidates_when_resolution_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = ReviewClient()
    first.provider = "deepseek"
    first.model = "deepseek-v4-flash"

    async def fake_provider_resolve(
        *_args: object,
        provider: str | None = None,
        **_kwargs: object,
    ) -> ReviewClient:
        if provider == "deepseek":
            return first
        raise RuntimeError("database temporarily unavailable")

    class Executor:
        async def complete_chat(self, *_args: object, **_kwargs: object) -> LlmChatResult:
            raise AssertionError("review egress must not run after resolver failure")

    monkeypatch.setattr(chat_service, "resolve_provider_client", fake_provider_resolve)
    result = await _run_grounding_review(
        SimpleNamespace(),
        SimpleNamespace(llm_tenant_key="default"),
        SimpleNamespace(user=SimpleNamespace(id=uuid4())),
        executor=Executor(),
        knowledge_base=SimpleNamespace(id=uuid4()),
        knowledge_base_id=uuid4(),
        api_key_id=None,
        generation_provider="qwen",
        generation_model="qwen-plus",
        idempotency_key="review-resolver-cleanup-regression",
        question="公司何时成立？",
        generated=_GeneratedChatResponse(answer="公司成立于 2023 年 [1]。"),
        citations=[_citation()],
    )

    assert result == "answer_review_unavailable"
    assert first.close_count == 1
