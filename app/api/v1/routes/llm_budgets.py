from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import select

from app.api.dependencies import DatabaseSession, require_permission
from app.api.errors import ApiError
from app.db.models import ApiKey, LlmBudgetPolicy, User
from app.schemas.llm_usage import (
    LlmBudgetPolicyCreate,
    LlmBudgetPolicyRead,
    LlmBudgetPolicyUpdate,
)
from app.services.access import AccessContext
from app.services.audit import AuditResult, add_audit_event

router = APIRouter()


@router.get("", response_model=list[LlmBudgetPolicyRead])
async def list_budget_policies(
    session: DatabaseSession,
    _: Annotated[AccessContext, Depends(require_permission("quota:manage"))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[LlmBudgetPolicy]:
    return list(
        (
            await session.scalars(
                select(LlmBudgetPolicy)
                .order_by(LlmBudgetPolicy.created_at, LlmBudgetPolicy.id)
                .limit(limit)
                .offset(offset)
            )
        ).all()
    )


@router.post(
    "",
    response_model=LlmBudgetPolicyRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_budget_policy(
    payload: LlmBudgetPolicyCreate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("quota:manage"))],
) -> LlmBudgetPolicy:
    await _validate_references(session, payload.user_id, payload.api_key_id)
    policy = LlmBudgetPolicy(
        **payload.model_dump(),
        updated_by=access.user.id,
    )
    session.add(policy)
    await session.flush()
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="llm.budget_policy_created",
        result=AuditResult.SUCCESS,
        resource_type="llm_budget_policy",
        resource_id=str(policy.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "tenant_key": policy.tenant_key,
            "provider": policy.provider,
            "model": policy.model,
            "user_scoped": policy.user_id is not None,
            "api_key_scoped": policy.api_key_id is not None,
        },
    )
    await session.commit()
    await session.refresh(policy)
    return policy


@router.patch("/{policy_id}", response_model=LlmBudgetPolicyRead)
async def update_budget_policy(
    policy_id: UUID,
    payload: LlmBudgetPolicyUpdate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("quota:manage"))],
) -> LlmBudgetPolicy:
    policy = await session.scalar(
        select(LlmBudgetPolicy)
        .where(LlmBudgetPolicy.id == policy_id)
        .with_for_update()
    )
    if policy is None:
        raise ApiError(status_code=404, code="llm_budget_policy_not_found", message="Not found")
    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        setattr(policy, field, value)
    if all(
        value is None
        for value in (
            policy.daily_token_limit,
            policy.monthly_token_limit,
            policy.daily_cost_limit_micro_usd,
            policy.monthly_cost_limit_micro_usd,
        )
    ):
        raise ApiError(
            status_code=422,
            code="llm_budget_policy_requires_limit",
            message="At least one hard token or cost limit is required",
        )
    policy.updated_by = access.user.id
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="llm.budget_policy_updated",
        result=AuditResult.SUCCESS,
        resource_type="llm_budget_policy",
        resource_id=str(policy.id),
        request_id=getattr(request.state, "request_id", None),
        details={"fields": sorted(updates)},
    )
    await session.commit()
    await session.refresh(policy)
    return policy


async def _validate_references(
    session: DatabaseSession,
    user_id: UUID | None,
    api_key_id: UUID | None,
) -> None:
    if user_id is not None and await session.get(User, user_id) is None:
        raise ApiError(status_code=422, code="llm_budget_user_not_found", message="User not found")
    if api_key_id is not None and await session.get(ApiKey, api_key_id) is None:
        raise ApiError(
            status_code=422,
            code="llm_budget_api_key_not_found",
            message="API key not found",
        )
