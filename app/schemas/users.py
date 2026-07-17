from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.db.models import UserStatus


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    display_name: str | None = Field(default=None, max_length=200)
    role_ids: list[UUID] = Field(default_factory=list, max_length=20)


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=200)
    status: UserStatus | None = None

    @field_validator("status")
    @classmethod
    def status_cannot_be_null(cls, value: UserStatus | None) -> UserStatus:
        if value is None:
            raise ValueError("status cannot be null; omit it to leave it unchanged")
        return value


class UserPasswordReset(BaseModel):
    password: str = Field(min_length=12, max_length=256)


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    display_name: str | None
    status: UserStatus
    is_superuser: bool
    created_at: datetime
    updated_at: datetime
    role_ids: list[UUID] = Field(default_factory=list)


class RoleAssignmentUpdate(BaseModel):
    role_ids: list[UUID] = Field(max_length=20)
