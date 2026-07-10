from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import select

from app.api.dependencies import DatabaseSession, require_permission
from app.api.errors import ApiError
from app.db.models import ApiKey, User, UserStatus
from app.schemas.api_keys import ApiKeyCreate, ApiKeyCreated, ApiKeyRead
from app.services.access import AccessContext, AccessService
from app.services.api_keys import PUBLIC_API_PERMISSIONS, generate_api_key
from app.services.audit import add_audit_event
from app.services.knowledge_bases import require_knowledge_base_access

router = APIRouter()


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
async def create_api_key(
    payload: ApiKeyCreate,
    request: Request,
    response: Response,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("api-key:manage"))],
) -> ApiKeyCreated:
    target_user_id = payload.user_id or access.user.id
    if target_user_id != access.user.id and not access.user.is_superuser:
        raise ApiError(
            status_code=403,
            code="api_key_escalation_denied",
            message="Only a superuser can issue an API key for another user",
        )
    target = await session.get(User, target_user_id)
    if target is None or target.status is not UserStatus.ACTIVE:
        raise ApiError(status_code=404, code="user_not_found", message="Active user not found")

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


@router.delete("/{api_key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    api_key_id: UUID,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("api-key:manage"))],
) -> Response:
    statement = select(ApiKey).where(ApiKey.id == api_key_id)
    if not access.user.is_superuser:
        statement = statement.where(ApiKey.user_id == access.user.id)
    api_key = await session.scalar(statement.with_for_update())
    if api_key is None:
        raise ApiError(status_code=404, code="api_key_not_found", message="API key not found")
    if api_key.revoked_at is None:
        api_key.revoked_at = datetime.now(UTC)
        add_audit_event(
            session,
            actor_id=access.user.id,
            action="api_key.revoked",
            resource_type="api_key",
            resource_id=str(api_key.id),
            request_id=getattr(request.state, "request_id", None),
            details={"target_user_id": str(api_key.user_id), "key_prefix": api_key.key_prefix},
        )
        await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
