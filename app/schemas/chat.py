from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

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
    strategy: Literal["structured", "rag", "retrieval", "retrieval_fallback"]
    reason: Literal[
        "structured_query",
        "llm_generated",
        "external_processing_disabled",
        "provider_unconfigured",
        "provider_configuration_error",
        "provider_unavailable",
        "usage_governance_unavailable",
        "usage_budget_exceeded",
        "usage_metering_unavailable",
        "duplicate_request",
        "missing_model_citations",
        "invalid_model_citations",
        "invalid_model_response",
        "answer_review_rejected",
        "answer_review_unavailable",
        "answer_review_invalid",
        "independent_reviewer_unavailable",
        "no_matching_content",
    ]
    citation_count: int = Field(ge=0)


class ChatDataTable(BaseModel):
    """A bounded, source-linked table safe for direct UI rendering."""

    title: str = Field(min_length=1, max_length=200)
    columns: list[str] = Field(min_length=1, max_length=8)
    rows: list[list[str]] = Field(min_length=1, max_length=50)
    citation_numbers: list[int] = Field(min_length=1, max_length=20)

    @field_validator("title")
    @classmethod
    def normalize_title(cls, value: str) -> str:
        return value.strip()

    @field_validator("columns")
    @classmethod
    def validate_columns(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(not item or len(item) > 80 for item in normalized):
            raise ValueError("table columns must contain 1 to 80 characters")
        if len(set(normalized)) != len(normalized):
            raise ValueError("table columns must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_rows_and_sources(self) -> ChatDataTable:
        width = len(self.columns)
        for row in self.rows:
            if len(row) != width:
                raise ValueError("every table row must match the column count")
            if any(not isinstance(cell, str) or len(cell.strip()) > 1_000 for cell in row):
                raise ValueError("table cells must be strings of at most 1000 characters")
        if any(number < 1 for number in self.citation_numbers):
            raise ValueError("table citation numbers must be positive")
        if len(set(self.citation_numbers)) != len(self.citation_numbers):
            raise ValueError("table citation numbers must be unique")
        self.rows = [[cell.strip() for cell in row] for row in self.rows]
        return self


class ChatAnswerReview(BaseModel):
    """Public proof that generated prose passed the post-generation gate."""

    status: Literal["passed", "fallback"]
    reason: Literal[
        "deterministic_verified",
        "semantic_verified",
        "retrieval_only",
        "answer_review_rejected",
        "answer_review_unavailable",
        "answer_review_invalid",
    ]

    @model_validator(mode="after")
    def validate_status_reason_pair(self) -> ChatAnswerReview:
        verified_reasons = {"deterministic_verified", "semantic_verified"}
        if self.status == "passed" and self.reason not in verified_reasons:
            raise ValueError("passed reviews must be deterministically or semantically verified")
        if self.status == "fallback" and self.reason in verified_reasons:
            raise ValueError("fallback reviews cannot be verified")
        return self


class ChatQueryResponse(BaseModel):
    knowledge_base_id: UUID
    answer: str
    mode: Literal["structured", "rag", "retrieval"] = "retrieval"
    provider: str | None = None
    model: str | None = None
    table: ChatDataTable | None = None
    answer_review: ChatAnswerReview = Field(
        default_factory=lambda: ChatAnswerReview(status="fallback", reason="retrieval_only")
    )
    citations: list[ChatCitation]
    source_status: ChatSourceStatus
