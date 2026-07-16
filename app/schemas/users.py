from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator

from app.core.password_policy import validate_strong_password
from app.db.models import UserStatus


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    display_name: str | None = Field(default=None, max_length=200)
    role_ids: list[UUID] = Field(default_factory=list, max_length=20)

    @field_validator("password")
    @classmethod
    def require_strong_password(cls, value: str) -> str:
        return validate_strong_password(value)


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=200)
    status: UserStatus | None = None

    @field_validator("status")
    @classmethod
    def status_cannot_be_null(cls, value: UserStatus | None) -> UserStatus:
        if value is None:
            raise ValueError("status cannot be null; omit it to leave it unchanged")
        return value


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    display_name: str | None
    status: UserStatus
    is_superuser: bool
    created_at: datetime
    updated_at: datetime
    role_assignment_version: int = Field(ge=1)
    role_ids: list[UUID] = Field(default_factory=list)
    retired_at: datetime | None
    retired_by_id: UUID | None
    retirement_reason: str | None


class RoleAssignmentUpdate(BaseModel):
    expected_version: int = Field(ge=1)
    role_ids: list[UUID] = Field(max_length=20)


class UserPasswordReset(BaseModel):
    """Password replacement with conditional proof for the signed-in account."""

    model_config = ConfigDict(extra="forbid")

    current_password: SecretStr | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        description="Required only when the signed-in user changes their own password.",
        json_schema_extra={"writeOnly": True},
    )
    new_password: SecretStr = Field(
        min_length=12,
        max_length=256,
        json_schema_extra={"writeOnly": True},
    )

    @field_validator("new_password", mode="before")
    @classmethod
    def require_strong_password(cls, value: str | SecretStr) -> str | SecretStr:
        cleartext = value.get_secret_value() if isinstance(value, SecretStr) else value
        validate_strong_password(cleartext)
        return value


class UserRetirement(BaseModel):
    """Explicit operator confirmation for irreversible account retirement."""

    model_config = ConfigDict(extra="forbid")

    confirmation_email: EmailStr
    reason: str | None = Field(default=None, max_length=1_000)
    replacement_owner_id: UUID | None = Field(
        default=None,
        description=(
            "Active successor that atomically receives every knowledge base owned by "
            "the retiring account."
        ),
    )

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str | None) -> str | None:
        normalized = value.strip() if value is not None else ""
        return normalized or None
