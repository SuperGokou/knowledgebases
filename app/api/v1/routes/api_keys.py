from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import DatabaseSession, require_permission
from app.api.egress_leases import deny_if_active_external_llm_egress
from app.api.errors import ApiError
from app.db.models import ApiKey, LlmBudgetPolicy, User, UserStatus
from app.schemas.api_keys import ApiKeyCreate, ApiKeyCreated, ApiKeyRead
from app.services.access import AccessContext, AccessService
from app.services.api_keys import PUBLIC_API_PERMISSIONS, generate_api_key
from app.services.audit import AuditResult, add_audit_event
from app.services.knowledge_bases import require_knowledge_base_access
from app.services.rbac_mutation import (
    acquire_rbac_mutation_lock,
    lock_role_union,
    locked_users_statement,
    refresh_locked_actor_access,
)
from app.services.user_activity import (
    ActivityLockMode,
    acquire_user_activity_locks,
    rbac_mutation_endpoint,
)

router = APIRouter()


async def _lock_api_key_mutation(
    session: AsyncSession,
    access: AccessContext,
    api_key_id: UUID,
) -> tuple[ApiKey, AccessContext, User]:
    candidate = await session.scalar(select(ApiKey).where(ApiKey.id == api_key_id))
    if candidate is None or (
        not access.user.is_superuser and candidate.user_id != access.user.id
    ):
        raise ApiError(status_code=404, code="api_key_not_found", message="API key not found")

    await acquire_rbac_mutation_lock(session)
    actor = await session.scalar(
        select(User)
        .where(User.id == access.user.id)
        .execution_options(populate_existing=True)
    )
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    await lock_role_union(session, user_ids={actor.id})
    current = await refresh_locked_actor_access(session, actor, {"api-key:manage"})

    # Re-read and object-authorize under RBAC-X before taking another user's
    # activity lock. A scoped key manager must not lock arbitrary principals.
    candidate = await session.scalar(
        select(ApiKey)
        .where(ApiKey.id == api_key_id)
        .execution_options(populate_existing=True)
    )
    if candidate is None or (
        not current.user.is_superuser and candidate.user_id != current.user.id
    ):
        raise ApiError(status_code=404, code="api_key_not_found", message="API key not found")
    await acquire_user_activity_locks(
        session,
        {
            actor.id: ActivityLockMode.SHARED,
            candidate.user_id: ActivityLockMode.SHARED,
        },
    )
    users = list(
        (
            await session.scalars(
                locked_users_statement({actor.id, candidate.user_id})
            )
        ).all()
    )
    users_by_id = {user.id: user for user in users}
    await lock_role_union(session, user_ids=users_by_id)
    actor = users_by_id.get(actor.id)
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    current = await refresh_locked_actor_access(session, actor, {"api-key:manage"})
    api_key = await session.scalar(
        select(ApiKey)
        .where(ApiKey.id == api_key_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if api_key is None or (not current.user.is_superuser and api_key.user_id != current.user.id):
        raise ApiError(status_code=404, code="api_key_not_found", message="API key not found")
    target = users_by_id.get(api_key.user_id)
    if target is None:
        raise ApiError(status_code=404, code="user_not_found", message="User not found")
    return api_key, current, target


async def _lock_api_key_creation(
    session: AsyncSession,
    access: AccessContext,
    target_user_id: UUID,
) -> tuple[AccessContext, User]:
    """Reauthorize key issuance before locking an authorized target account."""

    await acquire_rbac_mutation_lock(session)
    actor = await session.scalar(
        select(User)
        .where(User.id == access.user.id)
        .execution_options(populate_existing=True)
    )
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    await lock_role_union(session, user_ids={actor.id})
    current = await refresh_locked_actor_access(session, actor, {"api-key:manage"})
    candidate = await session.scalar(
        select(User)
        .where(User.id == target_user_id)
        .execution_options(populate_existing=True)
    )
    if candidate is None:
        raise ApiError(status_code=404, code="user_not_found", message="Active user not found")
    if candidate.id != actor.id and not current.user.is_superuser:
        raise ApiError(
            status_code=403,
            code="api_key_escalation_denied",
            message="Only a superuser can issue an API key for another user",
        )
    await acquire_user_activity_locks(
        session,
        {
            actor.id: ActivityLockMode.SHARED,
            candidate.id: ActivityLockMode.SHARED,
        },
    )
    users = list(
        (
            await session.scalars(
                locked_users_statement({actor.id, candidate.id})
            )
        ).all()
    )
    users_by_id = {user.id: user for user in users}
    actor = users_by_id.get(actor.id)
    target = users_by_id.get(target_user_id)
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    if target is None or target.status is not UserStatus.ACTIVE or target.retired_at is not None:
        raise ApiError(status_code=404, code="user_not_found", message="Active user not found")
    await lock_role_union(session, user_ids=users_by_id)
    current = await refresh_locked_actor_access(session, actor, {"api-key:manage"})
    if target.id != actor.id and not current.user.is_superuser:
        raise ApiError(
            status_code=403,
            code="api_key_escalation_denied",
            message="Only a superuser can issue an API key for another user",
        )
    return current, target


@router.get("", response_model=list[ApiKeyRead])
async def list_api_keys(
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("api-key:manage"))],
    user_id: Annotated[UUID | None, Query()] = None,
    include_revoked: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ApiKey]:
    statement = select(ApiKey)
    if not access.user.is_superuser:
        if user_id is not None and user_id != access.user.id:
            return []
        statement = statement.where(ApiKey.user_id == access.user.id)
    elif user_id is not None:
        statement = statement.where(ApiKey.user_id == user_id)
    if not include_revoked:
        statement = statement.where(ApiKey.revoked_at.is_(None))
    statement = statement.order_by(ApiKey.created_at.desc(), ApiKey.id).limit(limit).offset(offset)
    return list((await session.scalars(statement)).all())


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
@rbac_mutation_endpoint
async def create_api_key(
    payload: ApiKeyCreate,
    request: Request,
    response: Response,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("api-key:manage"))],
) -> ApiKeyCreated:
    target_user_id = payload.user_id or access.user.id
    access, target = await _lock_api_key_creation(session, access, target_user_id)

    requested_permissions = set(payload.permission_codes)
    unsupported = requested_permissions - PUBLIC_API_PERMISSIONS
    if unsupported:
        raise ApiError(
            status_code=422,
            code="unsupported_api_key_permission",
            message="One or more permissions are not available to public API keys",
            details={"supported": sorted(PUBLIC_API_PERMISSIONS)},
        )
    target_access = await AccessService().resolve(session, target)
    missing = sorted(
        permission for permission in requested_permissions if not target_access.allows(permission)
    )
    if missing:
        raise ApiError(
            status_code=422,
            code="api_key_permission_escalation",
            message="API key permissions must be held by the target user",
            details={"missing_permissions": missing},
        )
    for knowledge_base_id in payload.knowledge_base_ids:
        await require_knowledge_base_access(session, target_access, knowledge_base_id)

    expires_at = payload.expires_at
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        else:
            expires_at = expires_at.astimezone(UTC)
        if expires_at <= datetime.now(UTC):
            raise ApiError(
                status_code=422,
                code="invalid_api_key_expiry",
                message="API key expiration must be in the future",
            )

    cleartext, fingerprint, prefix = generate_api_key()
    api_key = ApiKey(
        user_id=target.id,
        created_by=access.user.id,
        name=payload.name,
        key_hash=fingerprint,
        key_prefix=prefix,
        permission_codes=sorted(requested_permissions),
        knowledge_base_ids=sorted(str(item) for item in payload.knowledge_base_ids),
        requests_per_minute=payload.requests_per_minute,
        expires_at=expires_at,
    )
    session.add(api_key)
    await session.flush()
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="api_key.created",
        result=AuditResult.SUCCESS,
        resource_type="api_key",
        resource_id=str(api_key.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "target_user_id": str(target.id),
            "key_prefix": api_key.key_prefix,
            "permission_codes": api_key.permission_codes,
            "knowledge_base_ids": api_key.knowledge_base_ids,
            "requests_per_minute": api_key.requests_per_minute,
            "expires_at": expires_at.isoformat() if expires_at is not None else None,
        },
    )
    await session.commit()
    await session.refresh(api_key)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Location"] = f"/api/v1/api-keys/{api_key.id}"
    read = ApiKeyRead.model_validate(api_key)
    return ApiKeyCreated(**read.model_dump(), key=cleartext)


@router.post(
    "/{api_key_id}/rotate",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
)
@rbac_mutation_endpoint
async def rotate_api_key(
    api_key_id: UUID,
    request: Request,
    response: Response,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("api-key:manage"))],
) -> ApiKeyCreated:
    previous, access, target = await _lock_api_key_mutation(session, access, api_key_id)
    now = datetime.now(UTC)
    if previous.revoked_at is not None or (
        previous.expires_at is not None and _as_utc(previous.expires_at) <= now
    ):
        raise ApiError(
            status_code=409,
            code="api_key_not_rotatable",
            message="Only an active API key can be rotated",
        )
    if target.status is not UserStatus.ACTIVE or target.retired_at is not None:
        raise ApiError(status_code=404, code="user_not_found", message="Active user not found")
    await deny_if_active_external_llm_egress(
        session,
        request,
        access,
        revocation_scope="api_key_rotation",
        resource_type="api_key",
        resource_id=str(previous.id),
        api_key_id=previous.id,
    )

    cleartext, fingerprint, prefix = generate_api_key()
    previous.revoked_at = now
    await session.flush()
    replacement = ApiKey(
        user_id=previous.user_id,
        created_by=access.user.id,
        credential_family_id=previous.credential_family_id,
        name=previous.name,
        key_hash=fingerprint,
        key_prefix=prefix,
        permission_codes=list(previous.permission_codes),
        knowledge_base_ids=list(previous.knowledge_base_ids),
        requests_per_minute=previous.requests_per_minute,
        expires_at=previous.expires_at,
    )
    session.add(replacement)
    await session.flush()
    # A key-scoped budget belongs to the stable client lineage, not to one
    # secret. Moving the FK preserves existing counters and hard limits.
    await session.execute(
        update(LlmBudgetPolicy)
        .where(LlmBudgetPolicy.api_key_id == previous.id)
        .values(api_key_id=replacement.id)
    )
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="api_key.rotated",
        result=AuditResult.SUCCESS,
        resource_type="api_key",
        resource_id=str(replacement.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "previous_api_key_id": str(previous.id),
            "replacement_api_key_id": str(replacement.id),
            "credential_family_id": str(replacement.credential_family_id),
            "previous_key_prefix": previous.key_prefix,
            "replacement_key_prefix": replacement.key_prefix,
        },
    )
    await session.commit()
    await session.refresh(replacement)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Location"] = f"/api/v1/api-keys/{replacement.id}"
    read = ApiKeyRead.model_validate(replacement)
    return ApiKeyCreated(**read.model_dump(), key=cleartext)


@router.delete("/{api_key_id}", status_code=status.HTTP_204_NO_CONTENT)
@rbac_mutation_endpoint
async def revoke_api_key(
    api_key_id: UUID,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("api-key:manage"))],
) -> Response:
    api_key, access, _ = await _lock_api_key_mutation(session, access, api_key_id)
    if api_key.revoked_at is None:
        await deny_if_active_external_llm_egress(
            session,
            request,
            access,
            revocation_scope="api_key",
            resource_type="api_key",
            resource_id=str(api_key.id),
            api_key_id=api_key.id,
        )
        api_key.revoked_at = datetime.now(UTC)
        add_audit_event(
            session,
            actor_id=access.user.id,
            action="api_key.revoked",
            result=AuditResult.SUCCESS,
            resource_type="api_key",
            resource_id=str(api_key.id),
            request_id=getattr(request.state, "request_id", None),
            details={"target_user_id": str(api_key.user_id), "key_prefix": api_key.key_prefix},
        )
        await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
