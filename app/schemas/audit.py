from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.db.models import AuditResult

__all__ = ["AuditLogPage", "AuditLogRead", "AuditResult"]


class AuditLogRead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    actor_id: UUID | None
    action: str
    resource_type: str
    resource_id: str | None
    request_id: str | None
    result: AuditResult
    created_at: datetime


class AuditLogPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[AuditLogRead]
    next_cursor: int | None
