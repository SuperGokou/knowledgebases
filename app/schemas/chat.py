from __future__ import annotations

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


class ChatQueryResponse(BaseModel):
    knowledge_base_id: UUID
    answer: str
    mode: str = "retrieval"
    provider: str | None = None
    model: str | None = None
    citations: list[KnowledgeSearchHit]
