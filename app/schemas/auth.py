from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from app.db.models import UserStatus


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20)


class AuthMe(BaseModel):
    id: UUID
    email: str
    display_name: str | None
    status: UserStatus
    is_superuser: bool
    permission_codes: list[str]
    role_ids: list[UUID]
    limits: dict[str, int | None]
