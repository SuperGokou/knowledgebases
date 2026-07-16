from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models import KnowledgeBaseAccessLevel, KnowledgeEntryPublicationStatus


class KnowledgeBaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    external_llm_processing_enabled: bool = False
    custom_metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeBaseUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    external_llm_processing_enabled: bool | None = None
    custom_metadata: dict[str, Any] | None = None

    @field_validator("name", "custom_metadata", "external_llm_processing_enabled")
    @classmethod
    def non_nullable_fields(cls, value: object) -> object:
        if value is None:
            raise ValueError("field cannot be null; omit it to leave it unchanged")
        return value


class KnowledgeBaseRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    owner_id: UUID
    name: str
    description: str | None
    external_llm_processing_enabled: bool
    custom_metadata: dict[str, Any]
    role_grant_version: int = Field(ge=1)
    access_level: KnowledgeBaseAccessLevel
    created_at: datetime
    updated_at: datetime


class KnowledgeBaseRoleGrantInput(BaseModel):
    role_id: UUID
    access_level: KnowledgeBaseAccessLevel


class KnowledgeBaseRoleGrantSet(BaseModel):
    expected_version: int = Field(ge=1)
    grants: list[KnowledgeBaseRoleGrantInput] = Field(max_length=200)

    @field_validator("grants")
    @classmethod
    def unique_roles(
        cls, value: list[KnowledgeBaseRoleGrantInput]
    ) -> list[KnowledgeBaseRoleGrantInput]:
        if len({item.role_id for item in value}) != len(value):
            raise ValueError("role grants must contain unique role ids")
        return value


class KnowledgeBaseRoleGrantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    role_id: UUID
    access_level: KnowledgeBaseAccessLevel
    granted_by: UUID | None
    created_at: datetime
    updated_at: datetime


class KnowledgeEntryCreate(BaseModel):
    source_file_id: UUID | None = None
    entry_type: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    content: str = Field(min_length=1, max_length=2_000_000)
    source_path: str | None = Field(default=None, max_length=1000)
    format_version: str | None = Field(default=None, max_length=50)
    custom_metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeEntryUpdate(BaseModel):
    entry_type: str | None = Field(default=None, min_length=1, max_length=100)
    title: str | None = Field(default=None, min_length=1, max_length=500)
    content: str | None = Field(default=None, min_length=1, max_length=2_000_000)
    source_path: str | None = Field(default=None, max_length=1000)
    format_version: str | None = Field(default=None, max_length=50)
    custom_metadata: dict[str, Any] | None = None

    @field_validator("entry_type", "title", "content", "custom_metadata")
    @classmethod
    def non_nullable_fields(cls, value: object) -> object:
        if value is None:
            raise ValueError("field cannot be null; omit it to leave it unchanged")
        return value


class KnowledgeEntryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    knowledge_base_id: UUID
    source_file_id: UUID | None
    entry_type: str
    title: str
    content: str
    source_path: str | None
    format_version: str | None
    publication_status: KnowledgeEntryPublicationStatus
    custom_metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class KnowledgeEntrySummary(BaseModel):
    """Bounded list representation; large entry bodies are fetched individually."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    knowledge_base_id: UUID
    source_file_id: UUID | None
    entry_type: str
    title: str
    source_path: str | None
    format_version: str | None
    publication_status: KnowledgeEntryPublicationStatus
    created_at: datetime
    updated_at: datetime


class KnowledgeSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=10, ge=1, le=50)

    @field_validator("query")
    @classmethod
    def query_must_not_be_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("query cannot be blank")
        return normalized


class KnowledgeSearchHit(BaseModel):
    entry_id: UUID
    source_file_id: UUID | None
    title: str
    excerpt: str
    source_path: str | None
    format_version: str | None


class KnowledgeSearchResponse(BaseModel):
    query: str
    items: list[KnowledgeSearchHit]
    mode: str = "retrieval"
    provider: str | None = None
    model: str | None = None
