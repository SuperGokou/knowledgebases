from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ApiKeyCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=200)
    user_id: UUID | None = None
    permission_codes: list[str] = Field(
        default_factory=lambda: ["chat:query"], min_length=1, max_length=10
    )
    knowledge_base_ids: list[UUID] = Field(min_length=1, max_length=100)
    expires_at: datetime | None = None
    requests_per_minute: int = Field(default=60, ge=1, le=10_000)

    @field_validator("permission_codes")
    @classmethod
    def normalize_permissions(cls, value: list[str]) -> list[str]:
        normalized = [item.strip().lower() for item in value]
        if any(not item or len(item) > 150 for item in normalized):
            raise ValueError("permission codes must be non-empty and at most 150 characters")
        if len(set(normalized)) != len(normalized):
            raise ValueError("permission codes must be unique")
        return normalized

    @field_validator("knowledge_base_ids")
    @classmethod
    def unique_knowledge_bases(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("knowledge base ids must be unique")
        return value


class ApiKeyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    user_id: UUID
    created_by: UUID | None
    name: str
    key_prefix: str
    permission_codes: list[str]
    knowledge_base_ids: list[UUID]
    requests_per_minute: int
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class ApiKeyCreated(ApiKeyRead):
    # Deliberately serialized once on create. It is never stored or returned again.
    key: str = Field(min_length=32, repr=False)
