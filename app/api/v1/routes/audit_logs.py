from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import AwareDatetime

from app.api.dependencies import DatabaseSession, require_permission
from app.api.errors import ApiError
from app.schemas.audit import AuditLogPage, AuditLogRead, AuditResult
from app.services.access import AccessContext
from app.services.audit import list_audit_events

router = APIRouter()


@router.get("", response_model=AuditLogPage)
async def list_audit_logs(
    session: DatabaseSession,
    _: Annotated[AccessContext, Depends(require_permission("audit:read"))],
    actor_id: Annotated[UUID | None, Query()] = None,
    action: Annotated[str | None, Query(min_length=1, max_length=150)] = None,
    resource_type: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    resource_id: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    result: Annotated[AuditResult | None, Query()] = None,
    created_from: Annotated[AwareDatetime | None, Query()] = None,
    created_to: Annotated[AwareDatetime | None, Query()] = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> AuditLogPage:
    if created_from is not None and created_to is not None and created_from > created_to:
        raise ApiError(
            status_code=422,
            code="invalid_time_range",
            message="created_from must be earlier than or equal to created_to",
        )

    events, next_cursor = await list_audit_events(
        session,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        created_from=created_from,
        created_to=created_to,
        cursor=cursor,
        limit=limit,
    )
    return AuditLogPage(
        items=[
            AuditLogRead(
                id=event.id,
                actor_id=event.actor_id,
                action=event.action,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                request_id=event.request_id,
                result=event.result,
                created_at=event.created_at,
            )
            for event in events
        ],
        next_cursor=next_cursor,
    )
