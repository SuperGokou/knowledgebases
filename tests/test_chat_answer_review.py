from __future__ import annotations

from uuid import uuid4

import pytest

from app.schemas.chat import ChatCitation
from app.services import chat as chat_service
from app.services.chat import _GeneratedChatResponse, _review_generated_answer
from app.services.llm_provider import LlmChatResult, LlmProviderError


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
