from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import and_, or_, select

from app.api.dependencies import DatabaseSession, require_permission
from app.api.errors import ApiError
from app.db.models import LlmUsageRecord, LlmUsageStatus
from app.schemas.llm_usage import LlmUsagePage, LlmUsageRead, LlmUsageReconciliation
from app.services.access import AccessContext
from app.services.audit import AuditResult, add_audit_event
from app.services.llm_usage import LlmUsageGovernance

router = APIRouter()


@router.post("/{usage_id}/reconcile", response_model=LlmUsageRead)
async def reconcile_stale_llm_egress_lease(
    usage_id: UUID,
    payload: LlmUsageReconciliation,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("quota:manage"))],
) -> LlmUsageRecord:
    """Release a stale HELD lease only after a privileged, audited attestation."""

    usage = await session.scalar(
        select(LlmUsageRecord).where(LlmUsageRecord.id == usage_id).with_for_update()
    )
    if usage is None:
        raise ApiError(status_code=404, code="llm_usage_not_found", message="Not found")
    if usage.status is not LlmUsageStatus.HELD:
        raise ApiError(
            status_code=409,
            code="llm_usage_not_held",
            message="Only a HELD usage record can be reconciled",
        )
    usage = await LlmUsageGovernance().release(
        session,
        usage_id=usage.id,
        error_code="operator_reconciled_no_egress",
    )
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="llm.usage_reconciled",
        result=AuditResult.SUCCESS,
        resource_type="llm_usage_record",
        resource_id=str(usage.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "provider_egress_terminated": payload.provider_egress_terminated,
            "reason": payload.reason,
        },
    )
    await session.commit()
    await session.refresh(usage)
    return usage


@router.get("", response_model=LlmUsagePage)
async def list_llm_usage(
    session: DatabaseSession,
    _: Annotated[AccessContext, Depends(require_permission("audit:read"))],
    tenant_key: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    user_id: Annotated[UUID | None, Query()] = None,
    api_key_id: Annotated[UUID | None, Query()] = None,
    knowledge_base_id: Annotated[UUID | None, Query()] = None,
    provider: Annotated[str | None, Query(min_length=1, max_length=30)] = None,
    model: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    operation: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    usage_status: Annotated[LlmUsageStatus | None, Query(alias="status")] = None,
    created_from: Annotated[datetime | None, Query()] = None,
    created_to: Annotated[datetime | None, Query()] = None,
    cursor: Annotated[UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> LlmUsagePage:
    filters = []
    for column, value in (
        (LlmUsageRecord.tenant_key, tenant_key),
        (LlmUsageRecord.user_id, user_id),
        (LlmUsageRecord.api_key_id, api_key_id),
        (LlmUsageRecord.knowledge_base_id, knowledge_base_id),
        (LlmUsageRecord.provider, provider),
        (LlmUsageRecord.model, model),
        (LlmUsageRecord.operation, operation),
        (LlmUsageRecord.status, usage_status),
    ):
        if value is not None:
            filters.append(column == value)
    if created_from is not None:
        filters.append(LlmUsageRecord.created_at >= created_from)
    if created_to is not None:
        filters.append(LlmUsageRecord.created_at <= created_to)

    if cursor is not None:
        cursor_row = await session.get(LlmUsageRecord, cursor)
        if cursor_row is not None:
            filters.append(
                or_(
                    LlmUsageRecord.created_at < cursor_row.created_at,
                    and_(
                        LlmUsageRecord.created_at == cursor_row.created_at,
                        LlmUsageRecord.id < cursor_row.id,
                    ),
                )
            )

    rows = list(
        (
            await session.scalars(
                select(LlmUsageRecord)
                .where(*filters)
                .order_by(LlmUsageRecord.created_at.desc(), LlmUsageRecord.id.desc())
                .limit(limit + 1)
            )
        ).all()
    )
    has_more = len(rows) > limit
    items = rows[:limit]
    return LlmUsagePage(
        items=items,
        next_cursor=items[-1].id if has_more and items else None,
    )
