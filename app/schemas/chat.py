from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.schemas.knowledge_bases import KnowledgeSearchHit


class ChatQueryRequest(BaseModel):
    knowledge_base_id: UUID
    message: str = Field(min_length=1, max_length=2000)
    limit: int = Field(default=5, ge=1, le=20)

    @field_validator("message")
    @classmethod
    def message_must_not_be_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("message cannot be blank")
        return normalized


class ChatCitation(KnowledgeSearchHit):
    """A stable, machine-readable mapping for a citation marker in the answer."""

    citation_number: int = Field(ge=1)
    marker: str = Field(pattern=r"^\[[1-9][0-9]*\]$")


class ChatSourceStatus(BaseModel):
    """Explains how an answer was grounded, including every graceful-degradation path."""

    status: Literal["grounded", "no_results"]
    strategy: Literal["rag", "retrieval", "retrieval_fallback"]
    reason: Literal[
        "llm_generated",
        "external_processing_disabled",
        "provider_unconfigured",
        "provider_configuration_error",
        "provider_unavailable",
        "missing_model_citations",
        "invalid_model_citations",
        "no_matching_content",
    ]
    citation_count: int = Field(ge=0)


class ChatQueryResponse(BaseModel):
    knowledge_base_id: UUID
    answer: str
    mode: str = "retrieval"
    provider: str | None = None
    model: str | None = None
    citations: list[ChatCitation]
    source_status: ChatSourceStatus
