from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog, AuditResult

__all__ = ["AuditEventView", "AuditResult", "add_audit_event", "list_audit_events"]


@dataclass(frozen=True, slots=True)
class AuditEventView:
    """The only audit fields allowed to leave the database query boundary."""

    id: int
    actor_id: UUID | None
    action: str
    result: AuditResult
    resource_type: str
    resource_id: str | None
    request_id: str | None
    created_at: datetime


async def list_audit_events(
    session: AsyncSession,
    *,
    actor_id: UUID | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    result: AuditResult | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    cursor: int | None = None,
    limit: int = 50,
) -> tuple[list[AuditEventView], int | None]:
    statement = select(
        AuditLog.id,
        AuditLog.actor_id,
        AuditLog.action,
        AuditLog.result,
        AuditLog.resource_type,
        AuditLog.resource_id,
        AuditLog.request_id,
        AuditLog.created_at,
    )
    if actor_id is not None:
        statement = statement.where(AuditLog.actor_id == actor_id)
    if action is not None:
        statement = statement.where(AuditLog.action == action)
    if resource_type is not None:
        statement = statement.where(AuditLog.resource_type == resource_type)
    if resource_id is not None:
        statement = statement.where(AuditLog.resource_id == resource_id)
    if result is not None:
        statement = statement.where(AuditLog.result == result)
    if created_from is not None:
        statement = statement.where(AuditLog.created_at >= created_from)
    if created_to is not None:
        statement = statement.where(AuditLog.created_at <= created_to)
    if cursor is not None:
        statement = statement.where(AuditLog.id < cursor)

    rows = (await session.execute(statement.order_by(AuditLog.id.desc()).limit(limit + 1))).all()
    events = [
        AuditEventView(
            id=row.id,
            actor_id=row.actor_id,
            action=row.action,
            result=row.result,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            request_id=row.request_id,
            created_at=row.created_at,
        )
        for row in rows
    ]
    has_more = len(events) > limit
    page = events[:limit]
    next_cursor = page[-1].id if has_more and page else None
    return page, next_cursor


def add_audit_event(
    session: AsyncSession,
    *,
    action: str,
    result: AuditResult,
    resource_type: str,
    actor_id: UUID | None = None,
    resource_id: str | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    session.add(
        AuditLog(
            actor_id=actor_id,
            action=action,
            result=result,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id,
            ip_address=ip_address,
            details=details or {},
        )
    )
