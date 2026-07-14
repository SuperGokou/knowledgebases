from __future__ import annotations

from uuid import UUID

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import ApiError
from app.services.access import AccessContext
from app.services.audit import AuditResult, add_audit_event
from app.services.llm_egress_policy import acquire_llm_egress_locks
from app.services.llm_usage import find_active_llm_egress


async def deny_if_active_external_llm_egress(
    session: AsyncSession,
    request: Request,
    access: AccessContext,
    *,
    revocation_scope: str,
    resource_type: str,
    resource_id: str,
    knowledge_base_id: UUID | None = None,
    user_id: UUID | None = None,
    api_key_id: UUID | None = None,
    role_id: UUID | None = None,
) -> None:
    """Serialize authorization revocation against durable provider-egress leases."""

    scopes: list[tuple[str, UUID]] = []
    if knowledge_base_id is not None:
        scopes.append(("knowledge_base", knowledge_base_id))
    if user_id is not None:
        scopes.append(("user", user_id))
    if api_key_id is not None:
        scopes.append(("api_key", api_key_id))
    if role_id is not None:
        scopes.append(("role", role_id))
    await acquire_llm_egress_locks(session, scopes)
    usage_id = await find_active_llm_egress(
        session,
        knowledge_base_id=knowledge_base_id,
        user_id=user_id,
        api_key_id=api_key_id,
        role_id=role_id,
    )
    if usage_id is None:
        return
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="external_llm.revocation_denied",
        result=AuditResult.DENIED,
        resource_type=resource_type,
        resource_id=resource_id,
        request_id=getattr(request.state, "request_id", None),
        details={
            "reason_code": "external_llm_processing_in_progress",
            "revocation_scope": revocation_scope,
            "usage_id": str(usage_id),
        },
    )
    # No target mutation has occurred when this guard is called. Commit only the
    # denial audit and release authorization-row locks before returning 409.
    await session.commit()
    raise ApiError(
        status_code=409,
        code="external_llm_processing_in_progress",
        message=(
            "External model processing is in progress; retry revocation after "
            "the active operation has settled"
        ),
    )
