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
    strategy: Literal["rag", "retrieval", "retrieval_fallback"]
    reason: Literal[
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
    row_citation_numbers: list[list[int]] | None = Field(default=None, max_length=50)

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

        # Normalize legacy single-source payloads. A missing map on a historic
        # multi-source replay remains readable as table-level provenance, while the
        # live generation parser rejects it before it can become a new answer.
        if self.row_citation_numbers is None:
            if len(self.citation_numbers) == 1:
                self.row_citation_numbers = [self.citation_numbers.copy() for _ in self.rows]
            return self
        if len(self.row_citation_numbers) != len(self.rows):
            raise ValueError("every table row must have a citation mapping")

        table_sources = set(self.citation_numbers)
        mapped_sources: set[int] = set()
        for row_sources in self.row_citation_numbers:
            if not row_sources or len(row_sources) > 20:
                raise ValueError("every table row must cite 1 to 20 sources")
            if any(number < 1 for number in row_sources):
                raise ValueError("row citation numbers must be positive")
            if len(set(row_sources)) != len(row_sources):
                raise ValueError("row citation numbers must be unique")
            if not set(row_sources).issubset(table_sources):
                raise ValueError("row citations must be declared as table citations")
            mapped_sources.update(row_sources)
        if mapped_sources != table_sources:
            raise ValueError("table citations must exactly match the row citation mappings")

        return self


class ChatAnswerReview(BaseModel):
    """Public proof that generated prose passed the post-generation gate."""

    status: Literal["passed", "fallback"]
    reason: Literal[
        "semantic_verified",
        "retrieval_only",
        "answer_review_rejected",
        "answer_review_unavailable",
        "answer_review_invalid",
    ]

    @model_validator(mode="after")
    def validate_status_reason_pair(self) -> ChatAnswerReview:
        if self.status == "passed" and self.reason != "semantic_verified":
            raise ValueError("passed reviews must be semantically verified")
        if self.status == "fallback" and self.reason == "semantic_verified":
            raise ValueError("fallback reviews cannot be semantically verified")
        return self


class ChatQueryResponse(BaseModel):
    knowledge_base_id: UUID
    answer: str
    mode: str = "retrieval"
    provider: str | None = None
    model: str | None = None
    table: ChatDataTable | None = None
    answer_review: ChatAnswerReview = Field(
        default_factory=lambda: ChatAnswerReview(status="fallback", reason="retrieval_only")
    )
    citations: list[ChatCitation]
    source_status: ChatSourceStatus
