from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RoleCreate(BaseModel):
    code: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,99}$")
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    priority: int = Field(default=0, ge=-10_000, le=10_000)
    permission_codes: list[str] = Field(default_factory=list, max_length=200)
    limits: dict[str, int | None] = Field(default_factory=dict)

    @field_validator("limits")
    @classmethod
    def validate_limits(cls, value: dict[str, int | None]) -> dict[str, int | None]:
        if any(item is not None and item < 0 for item in value.values()):
            raise ValueError("limit values cannot be negative")
        return value


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    priority: int | None = Field(default=None, ge=-10_000, le=10_000)

    @field_validator("name", "priority")
    @classmethod
    def reject_explicit_nulls(cls, value: object) -> object:
        if value is None:
            raise ValueError("field cannot be null; omit it to leave it unchanged")
        return value


class RoleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    code: str
    name: str
    description: str | None
    priority: int
    is_system: bool
    created_at: datetime
    updated_at: datetime
    permission_codes: list[str] = Field(default_factory=list)
    limits: dict[str, int | None] = Field(default_factory=dict)


class PermissionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    code: str
    name: str
    description: str | None


class LimitDefinitionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    key: str
    name: str
    description: str | None
    unit: str
    window: str


class PermissionSet(BaseModel):
    permission_codes: list[str] = Field(max_length=200)


class LimitSet(BaseModel):
    limits: dict[str, int | None]

    @field_validator("limits")
    @classmethod
    def validate_limits(cls, value: dict[str, int | None]) -> dict[str, int | None]:
        if any(item is not None and item < 0 for item in value.values()):
            raise ValueError("limit values cannot be negative")
        return value
