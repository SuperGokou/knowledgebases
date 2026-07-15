from __future__ import annotations

import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import delete, func, select

from app.api.dependencies import DatabaseSession, require_any_permission, require_permission
from app.api.egress_leases import deny_if_active_external_llm_egress
from app.api.errors import ApiError
from app.core.config import Settings, get_settings
from app.db.models import (
    File,
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
)
from app.schemas.knowledge_bases import (
    KnowledgeBaseCreate,
    KnowledgeBaseRead,
    KnowledgeBaseRoleGrantRead,
    KnowledgeBaseRoleGrantSet,
    KnowledgeBaseUpdate,
    KnowledgeEntryCreate,
    KnowledgeEntryRead,
    KnowledgeEntrySummary,
    KnowledgeEntryUpdate,
    KnowledgeSearchRequest,
    KnowledgeSearchResponse,
)
from app.services.access import AccessContext
from app.services.audit import AuditResult, add_audit_event
from app.services.knowledge_bases import (
    KnowledgeBaseAccess,
    list_accessible_knowledge_bases,
    require_knowledge_base_access,
    search_knowledge_entries,
)
from app.services.knowledge_entry_quota import consume_manual_entry_storage_quota
from app.services.rbac_mutation import (
    acquire_rbac_mutation_lock,
    lock_role_union,
    locked_users_statement,
    refresh_locked_actor_access,
)

router = APIRouter()


def _ensure_metadata_size(value: dict[str, object]) -> None:
    if len(json.dumps(value, ensure_ascii=False).encode("utf-8")) > 16_384:
        raise ApiError(
            status_code=422,
            code="metadata_too_large",
            message="Custom metadata must not exceed 16 KiB",
        )


async def _knowledge_entry_usage(
    session: DatabaseSession,
    *,
    knowledge_base_id: UUID,
) -> tuple[int, int]:
    bind = session.get_bind()
    content_bytes = (
        func.octet_length(KnowledgeEntry.content)
        if bind.dialect.name == "postgresql"
        else func.length(KnowledgeEntry.content)
    )
    row = (
        await session.execute(
            select(
                func.count(KnowledgeEntry.id),
                func.coalesce(func.sum(content_bytes), 0),
            ).where(
                KnowledgeEntry.knowledge_base_id == knowledge_base_id,
                KnowledgeEntry.deleted_at.is_(None),
            )
        )
    ).one()
    return int(row[0] or 0), int(row[1] or 0)


def _enforce_knowledge_entry_capacity(
    *,
    current_count: int,
    current_bytes: int,
    incoming_count: int,
    incoming_bytes: int,
    settings: Settings,
) -> None:
    if current_count + incoming_count > settings.platform_max_entries_per_knowledge_base:
        raise ApiError(
            status_code=507,
            code="knowledge_entry_count_limit_reached",
            message="The knowledge base entry-count safety limit has been reached",
        )
    if current_bytes + incoming_bytes > settings.platform_max_entry_bytes_per_knowledge_base:
        raise ApiError(
            status_code=507,
            code="knowledge_entry_bytes_limit_reached",
            message="The knowledge base entry-byte safety limit has been reached",
        )


def _knowledge_base_read(item: KnowledgeBaseAccess) -> KnowledgeBaseRead:
    knowledge_base = item.knowledge_base
    return KnowledgeBaseRead(
        id=knowledge_base.id,
        owner_id=knowledge_base.owner_id,
        name=knowledge_base.name,
        description=knowledge_base.description,
        external_llm_processing_enabled=knowledge_base.external_llm_processing_enabled,
        custom_metadata=knowledge_base.custom_metadata,
        role_grant_version=knowledge_base.role_grant_version,
        access_level=item.level,
        created_at=knowledge_base.created_at,
        updated_at=knowledge_base.updated_at,
    )


@router.get("", response_model=list[KnowledgeBaseRead])
async def list_knowledge_bases(
    session: DatabaseSession,
    access: Annotated[
        AccessContext,
        Depends(require_any_permission("knowledge:read", "chat:query", "file:upload")),
    ],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    q: Annotated[str | None, Query(max_length=200)] = None,
    minimum_access_level: Annotated[KnowledgeBaseAccessLevel | None, Query()] = None,
) -> list[KnowledgeBaseRead]:
    rows = await list_accessible_knowledge_bases(
        session,
        access,
        limit=limit,
        offset=offset,
        query=q,
        minimum_access_level=minimum_access_level,
    )
    return [_knowledge_base_read(item) for item in rows]


@router.post("", response_model=KnowledgeBaseRead, status_code=201)
async def create_knowledge_base(
    payload: KnowledgeBaseCreate,
    request: Request,
    response: Response,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("knowledge:create"))],
) -> KnowledgeBaseRead:
    _ensure_metadata_size(payload.custom_metadata)
    knowledge_base = KnowledgeBase(
        owner_id=access.user.id,
        name=payload.name.strip(),
        description=payload.description,
        external_llm_processing_enabled=payload.external_llm_processing_enabled,
        custom_metadata=payload.custom_metadata,
    )
    session.add(knowledge_base)
    await session.flush()
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="knowledge_base.created",
        result=AuditResult.SUCCESS,
        resource_type="knowledge_base",
        resource_id=str(knowledge_base.id),
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(knowledge_base)
    response.headers["Location"] = f"/api/v1/knowledge-bases/{knowledge_base.id}"
    return _knowledge_base_read(
        KnowledgeBaseAccess(knowledge_base, KnowledgeBaseAccessLevel.MANAGER)
    )


@router.get("/{knowledge_base_id}", response_model=KnowledgeBaseRead)
async def get_knowledge_base(
    knowledge_base_id: UUID,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("knowledge:read"))],
) -> KnowledgeBaseRead:
    item = await require_knowledge_base_access(session, access, knowledge_base_id)
    return _knowledge_base_read(item)


@router.patch("/{knowledge_base_id}", response_model=KnowledgeBaseRead)
async def update_knowledge_base(
    knowledge_base_id: UUID,
    payload: KnowledgeBaseUpdate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("knowledge:update"))],
) -> KnowledgeBaseRead:
    item = await require_knowledge_base_access(
        session,
        access,
        knowledge_base_id,
        minimum=KnowledgeBaseAccessLevel.MANAGER,
        lock=True,
    )
    changes = payload.model_dump(exclude_unset=True)
    if "custom_metadata" in changes:
        _ensure_metadata_size(changes["custom_metadata"])
    if "name" in changes:
        changes["name"] = changes["name"].strip()
    if (
        changes.get("external_llm_processing_enabled") is False
        and item.knowledge_base.external_llm_processing_enabled
    ):
        await deny_if_active_external_llm_egress(
            session,
            request,
            access,
            revocation_scope="knowledge_base_external_processing",
            resource_type="knowledge_base",
            resource_id=str(knowledge_base_id),
            knowledge_base_id=knowledge_base_id,
        )
    if (
        "external_llm_processing_enabled" in changes
        and changes["external_llm_processing_enabled"]
        is not item.knowledge_base.external_llm_processing_enabled
    ):
        # Consent changes invalidate completed answers under the same KB lock;
        # a replay cannot bypass a revocation that commits first.
        item.knowledge_base.content_version += 1
    for key, value in changes.items():
        setattr(item.knowledge_base, key, value)
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="knowledge_base.updated",
        result=AuditResult.SUCCESS,
        resource_type="knowledge_base",
        resource_id=str(knowledge_base_id),
        request_id=getattr(request.state, "request_id", None),
        details={"fields": sorted(changes)},
    )
    await session.commit()
    await session.refresh(item.knowledge_base)
    return _knowledge_base_read(item)


@router.get(
    "/{knowledge_base_id}/role-grants",
    response_model=list[KnowledgeBaseRoleGrantRead],
)
async def list_role_grants(
    knowledge_base_id: UUID,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("knowledge:grant"))],
) -> list[KnowledgeBaseRoleGrant]:
    await require_knowledge_base_access(
        session,
        access,
        knowledge_base_id,
        minimum=KnowledgeBaseAccessLevel.MANAGER,
    )
    return list(
        (
            await session.scalars(
                select(KnowledgeBaseRoleGrant)
                .where(KnowledgeBaseRoleGrant.knowledge_base_id == knowledge_base_id)
                .order_by(KnowledgeBaseRoleGrant.role_id)
            )
        ).all()
    )


@router.put(
    "/{knowledge_base_id}/role-grants",
    response_model=list[KnowledgeBaseRoleGrantRead],
)
async def replace_role_grants(
    knowledge_base_id: UUID,
    payload: KnowledgeBaseRoleGrantSet,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("knowledge:grant"))],
) -> list[KnowledgeBaseRoleGrant]:
    # Reject callers outside the KB boundary before they can contend on arbitrary
    # role rows. The authorization decision is repeated under the KB row lock below.
    await require_knowledge_base_access(
        session,
        access,
        knowledge_base_id,
        minimum=KnowledgeBaseAccessLevel.MANAGER,
    )
    role_ids = {item.role_id for item in payload.grants}
    await acquire_rbac_mutation_lock(session)
    actor = await session.scalar(locked_users_statement({access.user.id}))
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    locked_roles = await lock_role_union(
        session,
        user_ids={actor.id},
        additional_role_ids=role_ids,
    )
    access = await refresh_locked_actor_access(session, actor, {"knowledge:grant"})
    if set(locked_roles).intersection(role_ids) != role_ids:
        raise ApiError(
            status_code=422,
            code="unknown_role",
            message="One or more roles do not exist",
        )
    locked_access = await require_knowledge_base_access(
        session,
        access,
        knowledge_base_id,
        minimum=KnowledgeBaseAccessLevel.MANAGER,
        lock=True,
    )
    knowledge_base = locked_access.knowledge_base
    current_version = knowledge_base.role_grant_version
    if payload.expected_version != current_version:
        raise ApiError(
            status_code=409,
            code="stale_knowledge_grants",
            message="Knowledge-base grants changed; reload them before retrying",
            details={"current_version": current_version},
        )
    current_grants = list(
        (
            await session.scalars(
                select(KnowledgeBaseRoleGrant)
                .where(KnowledgeBaseRoleGrant.knowledge_base_id == knowledge_base_id)
                .order_by(KnowledgeBaseRoleGrant.role_id)
            )
        ).all()
    )
    current_policy = {item.role_id: item.access_level for item in current_grants}
    requested_policy = {item.role_id: item.access_level for item in payload.grants}
    if current_policy == requested_policy:
        return current_grants
    await deny_if_active_external_llm_egress(
        session,
        request,
        access,
        revocation_scope="knowledge_base_role_grants",
        resource_type="knowledge_base",
        resource_id=str(knowledge_base_id),
        knowledge_base_id=knowledge_base_id,
    )
    await session.execute(
        delete(KnowledgeBaseRoleGrant).where(
            KnowledgeBaseRoleGrant.knowledge_base_id == knowledge_base_id
        )
    )
    grants = [
        KnowledgeBaseRoleGrant(
            knowledge_base_id=knowledge_base_id,
            role_id=item.role_id,
            access_level=item.access_level,
            granted_by=access.user.id,
        )
        for item in payload.grants
    ]
    session.add_all(grants)
    knowledge_base.role_grant_version += 1
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="knowledge_base.role_grants_replaced",
        result=AuditResult.SUCCESS,
        resource_type="knowledge_base",
        resource_id=str(knowledge_base_id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "from_version": current_version,
            "to_version": knowledge_base.role_grant_version,
            "role_ids": sorted(str(item) for item in role_ids),
        },
    )
    await session.commit()
    for grant in grants:
        await session.refresh(grant)
    return sorted(grants, key=lambda item: str(item.role_id))


@router.get(
    "/{knowledge_base_id}/entries",
    response_model=list[KnowledgeEntrySummary],
)
async def list_entries(
    knowledge_base_id: UUID,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("knowledge:read"))],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[KnowledgeEntrySummary]:
    kb_access = await require_knowledge_base_access(session, access, knowledge_base_id)
    statement = (
        select(
            KnowledgeEntry.id,
            KnowledgeEntry.knowledge_base_id,
            KnowledgeEntry.source_file_id,
            KnowledgeEntry.entry_type,
            KnowledgeEntry.title,
            KnowledgeEntry.source_path,
            KnowledgeEntry.format_version,
            KnowledgeEntry.publication_status,
            KnowledgeEntry.created_at,
            KnowledgeEntry.updated_at,
        )
        .where(
            KnowledgeEntry.knowledge_base_id == knowledge_base_id,
            KnowledgeEntry.deleted_at.is_(None),
        )
        .order_by(KnowledgeEntry.updated_at.desc(), KnowledgeEntry.id)
        .limit(limit)
        .offset(offset)
    )
    if kb_access.level is not KnowledgeBaseAccessLevel.MANAGER:
        statement = statement.where(
            KnowledgeEntry.publication_status == KnowledgeEntryPublicationStatus.PUBLISHED
        )
    rows = (await session.execute(statement)).mappings()
    return [KnowledgeEntrySummary.model_validate(row) for row in rows]


@router.get(
    "/{knowledge_base_id}/entries/{entry_id}",
    response_model=KnowledgeEntryRead,
)
async def get_entry(
    knowledge_base_id: UUID,
    entry_id: UUID,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("knowledge:read"))],
) -> KnowledgeEntry:
    kb_access = await require_knowledge_base_access(session, access, knowledge_base_id)
    visibility = []
    if kb_access.level is not KnowledgeBaseAccessLevel.MANAGER:
        visibility.append(
            KnowledgeEntry.publication_status == KnowledgeEntryPublicationStatus.PUBLISHED
        )
    entry = await session.scalar(
        select(KnowledgeEntry).where(
            KnowledgeEntry.id == entry_id,
            KnowledgeEntry.knowledge_base_id == knowledge_base_id,
            KnowledgeEntry.deleted_at.is_(None),
            *visibility,
        )
    )
    if entry is None:
        raise ApiError(
            status_code=404,
            code="knowledge_entry_not_found",
            message="Knowledge entry not found",
        )
    return entry


@router.post(
    "/{knowledge_base_id}/entries",
    response_model=KnowledgeEntryRead,
    status_code=201,
)
async def create_entry(
    knowledge_base_id: UUID,
    payload: KnowledgeEntryCreate,
    request: Request,
    response: Response,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("knowledge:update"))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> KnowledgeEntry:
    await require_knowledge_base_access(
        session,
        access,
        knowledge_base_id,
        minimum=KnowledgeBaseAccessLevel.EDITOR,
        lock=True,
    )
    _ensure_metadata_size(payload.custom_metadata)
    current_count, current_bytes = await _knowledge_entry_usage(
        session,
        knowledge_base_id=knowledge_base_id,
    )
    _enforce_knowledge_entry_capacity(
        current_count=current_count,
        current_bytes=current_bytes,
        incoming_count=1,
        incoming_bytes=len(payload.content.encode("utf-8")),
        settings=settings,
    )
    if payload.source_file_id is not None:
        source_file = await session.scalar(
            select(File).where(
                File.id == payload.source_file_id,
                File.knowledge_base_id == knowledge_base_id,
                File.deleted_at.is_(None),
            )
        )
        if source_file is None:
            raise ApiError(
                status_code=422,
                code="invalid_source_file",
                message="Source file does not belong to this knowledge base",
            )
    storage_bytes_charged = await consume_manual_entry_storage_quota(
        session,
        user_id=access.user.id,
        storage_limit=access.limits.get("storage_bytes", 0),
        previous_content=None,
        next_content=payload.content,
    )
    entry = KnowledgeEntry(
        knowledge_base_id=knowledge_base_id,
        source_file_id=payload.source_file_id,
        entry_type=payload.entry_type.strip(),
        title=payload.title.strip(),
        content=payload.content,
        source_path=payload.source_path,
        format_version=payload.format_version,
        custom_metadata=payload.custom_metadata,
    )
    session.add(entry)
    await session.flush()
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="knowledge_entry.created",
        result=AuditResult.SUCCESS,
        resource_type="knowledge_entry",
        resource_id=str(entry.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "knowledge_base_id": str(knowledge_base_id),
            "storage_bytes_charged": storage_bytes_charged,
        },
    )
    await session.commit()
    await session.refresh(entry)
    response.headers["Location"] = f"/api/v1/knowledge-bases/{knowledge_base_id}/entries/{entry.id}"
    return entry


@router.patch(
    "/{knowledge_base_id}/entries/{entry_id}",
    response_model=KnowledgeEntryRead,
)
async def update_entry(
    knowledge_base_id: UUID,
    entry_id: UUID,
    payload: KnowledgeEntryUpdate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("knowledge:update"))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> KnowledgeEntry:
    await require_knowledge_base_access(
        session,
        access,
        knowledge_base_id,
        minimum=KnowledgeBaseAccessLevel.EDITOR,
        lock=True,
    )
    entry = await session.scalar(
        select(KnowledgeEntry)
        .where(
            KnowledgeEntry.id == entry_id,
            KnowledgeEntry.knowledge_base_id == knowledge_base_id,
            KnowledgeEntry.deleted_at.is_(None),
        )
        .with_for_update()
    )
    if entry is None:
        raise ApiError(
            status_code=404,
            code="knowledge_entry_not_found",
            message="Knowledge entry not found",
        )
    changes = payload.model_dump(exclude_unset=True)
    storage_bytes_charged = 0
    if "custom_metadata" in changes:
        _ensure_metadata_size(changes["custom_metadata"])
    if "content" in changes:
        current_count, current_bytes = await _knowledge_entry_usage(
            session,
            knowledge_base_id=knowledge_base_id,
        )
        previous_bytes = len(entry.content.encode("utf-8"))
        next_bytes = len(str(changes["content"]).encode("utf-8"))
        _enforce_knowledge_entry_capacity(
            current_count=current_count,
            current_bytes=max(current_bytes - previous_bytes, 0),
            incoming_count=0,
            incoming_bytes=next_bytes,
            settings=settings,
        )
        storage_bytes_charged = await consume_manual_entry_storage_quota(
            session,
            user_id=access.user.id,
            storage_limit=access.limits.get("storage_bytes", 0),
            previous_content=entry.content,
            next_content=str(changes["content"]),
        )
    for key, value in changes.items():
        setattr(entry, key, value)
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="knowledge_entry.updated",
        result=AuditResult.SUCCESS,
        resource_type="knowledge_entry",
        resource_id=str(entry.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "fields": sorted(changes),
            "storage_bytes_charged": storage_bytes_charged,
        },
    )
    await session.commit()
    await session.refresh(entry)
    return entry


@router.post(
    "/{knowledge_base_id}/search",
    response_model=KnowledgeSearchResponse,
)
async def search_entries(
    knowledge_base_id: UUID,
    payload: KnowledgeSearchRequest,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("knowledge:read"))],
) -> KnowledgeSearchResponse:
    await require_knowledge_base_access(session, access, knowledge_base_id)
    items = await search_knowledge_entries(
        session,
        knowledge_base_id,
        query=payload.query,
        limit=payload.limit,
    )
    return KnowledgeSearchResponse(query=payload.query, items=items)
