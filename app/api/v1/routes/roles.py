from __future__ import annotations

import hashlib
import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import Select, delete, func, select

from app.api.dependencies import DatabaseSession, require_permission
from app.api.egress_leases import deny_if_active_external_llm_egress
from app.api.errors import ApiError
from app.db.models import (
    KnowledgeBaseRoleGrant,
    LimitDefinition,
    Permission,
    Role,
    RoleLimit,
    RolePermission,
    UserRole,
)
from app.schemas.roles import (
    LimitDefinitionRead,
    LimitSet,
    PermissionRead,
    PermissionSet,
    RoleCreate,
    RolePolicySet,
    RoleRead,
    RoleUpdate,
)
from app.services.access import AccessContext
from app.services.audit import AuditResult, add_audit_event
from app.services.rbac_mutations import lock_and_refresh_actor_access

router = APIRouter()
permission_router = APIRouter()
limit_router = APIRouter()


def _locked_role_for_delete_statement(role_id: UUID) -> Select[tuple[Role]]:
    return select(Role).where(Role.id == role_id).with_for_update()


def _role_policy_etag(
    role: Role,
    permission_codes: list[str],
    limits: dict[str, int | None],
) -> str:
    """Return a stable digest for every mutable part of a role policy."""

    payload = {
        "code": role.code,
        "description": role.description,
        "id": str(role.id),
        "is_system": role.is_system,
        "limits": dict(sorted(limits.items())),
        "name": role.name,
        "permission_codes": sorted(permission_codes),
        "priority": role.priority,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _ensure_role_mutable(access: AccessContext, role: Role) -> None:
    if role.is_system:
        raise ApiError(
            status_code=403,
            code="system_role",
            message="System roles are immutable",
        )
    if not access.user.is_superuser and role.priority >= access.max_role_priority:
        raise ApiError(
            status_code=403,
            code="role_escalation_denied",
            message="You cannot modify a role at or above your own priority",
        )


def _ensure_policy_grantable(
    access: AccessContext,
    *,
    permission_codes: list[str] | None = None,
    limits: dict[str, int | None] | None = None,
) -> None:
    if access.user.is_superuser:
        return
    if permission_codes and any(not access.allows(code) for code in permission_codes):
        raise ApiError(
            status_code=403,
            code="permission_escalation_denied",
            message="A role cannot grant permissions that you do not hold",
        )
    for key, value in (limits or {}).items():
        own_value = access.limits.get(key, 0)
        if own_value is not None and (value is None or value > own_value):
            raise ApiError(
                status_code=403,
                code="limit_escalation_denied",
                message=f"A role cannot grant a {key} limit above your effective limit",
            )


async def _role_reads(session: DatabaseSession, roles: list[Role]) -> list[RoleRead]:
    if not roles:
        return []
    role_ids = [role.id for role in roles]
    permission_rows = (
        await session.execute(
            select(RolePermission.role_id, Permission.code)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(RolePermission.role_id.in_(role_ids))
        )
    ).all()
    limit_rows = (
        await session.execute(
            select(RoleLimit.role_id, LimitDefinition.key, RoleLimit.value)
            .join(LimitDefinition, LimitDefinition.id == RoleLimit.limit_definition_id)
            .where(RoleLimit.role_id.in_(role_ids))
        )
    ).all()
    permissions_by_role: dict[UUID, list[str]] = {role_id: [] for role_id in role_ids}
    limits_by_role: dict[UUID, dict[str, int | None]] = {role_id: {} for role_id in role_ids}
    for role_id, code in permission_rows:
        permissions_by_role[role_id].append(code)
    for role_id, key, value in limit_rows:
        limits_by_role[role_id][key] = value
    reads: list[RoleRead] = []
    for role in roles:
        permission_codes = sorted(permissions_by_role[role.id])
        limits = dict(sorted(limits_by_role[role.id].items()))
        reads.append(
            RoleRead(
                id=role.id,
                code=role.code,
                name=role.name,
                description=role.description,
                priority=role.priority,
                is_system=role.is_system,
                created_at=role.created_at,
                updated_at=role.updated_at,
                permission_codes=permission_codes,
                limits=limits,
                policy_etag=_role_policy_etag(role, permission_codes, limits),
            )
        )
    return reads


async def _role_read(session: DatabaseSession, role: Role) -> RoleRead:
    return (await _role_reads(session, [role]))[0]


@router.get("", response_model=list[RoleRead])
async def list_roles(
    session: DatabaseSession,
    _: Annotated[AccessContext, Depends(require_permission("role:read"))],
) -> list[RoleRead]:
    roles = list(
        (await session.scalars(select(Role).order_by(Role.priority.desc(), Role.code))).all()
    )
    return await _role_reads(session, roles)


@router.get("/{role_id}", response_model=RoleRead)
async def get_role(
    role_id: UUID,
    session: DatabaseSession,
    _: Annotated[AccessContext, Depends(require_permission("role:read"))],
) -> RoleRead:
    role = await session.get(Role, role_id)
    if role is None:
        raise ApiError(status_code=404, code="role_not_found", message="Role not found")
    return await _role_read(session, role)


async def _resolve_permissions(
    session: DatabaseSession, permission_codes: list[str]
) -> list[Permission]:
    unique_codes = set(permission_codes)
    permissions = list(
        (await session.scalars(select(Permission).where(Permission.code.in_(unique_codes)))).all()
    )
    if {item.code for item in permissions} != unique_codes:
        raise ApiError(
            status_code=422,
            code="unknown_permission",
            message="One or more permission codes are not in the server catalog",
        )
    return permissions


async def _resolve_limits(
    session: DatabaseSession, limits: dict[str, int | None]
) -> list[tuple[LimitDefinition, int | None]]:
    keys = set(limits)
    definitions = list(
        (await session.scalars(select(LimitDefinition).where(LimitDefinition.key.in_(keys)))).all()
    )
    if {item.key for item in definitions} != keys:
        raise ApiError(
            status_code=422,
            code="unknown_limit",
            message="One or more limit keys are not in the server catalog",
        )
    return [(definition, limits[definition.key]) for definition in definitions]


@router.post("", response_model=RoleRead, status_code=status.HTTP_201_CREATED)
async def create_role(
    payload: RoleCreate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:manage"))],
) -> RoleRead:
    if not access.user.is_superuser and payload.priority > access.max_role_priority:
        raise ApiError(
            status_code=403,
            code="role_escalation_denied",
            message="A role cannot be created above your own priority",
        )
    _ensure_policy_grantable(
        access,
        permission_codes=payload.permission_codes,
        limits=payload.limits,
    )
    if await session.scalar(select(Role.id).where(Role.code == payload.code)) is not None:
        raise ApiError(status_code=409, code="role_exists", message="Role code already exists")
    permissions = await _resolve_permissions(session, payload.permission_codes)
    limits = await _resolve_limits(session, payload.limits)
    role = Role(
        code=payload.code,
        name=payload.name,
        description=payload.description,
        priority=payload.priority,
    )
    session.add(role)
    await session.flush()
    session.add_all(
        [RolePermission(role_id=role.id, permission_id=item.id) for item in permissions]
    )
    session.add_all(
        [
            RoleLimit(role_id=role.id, limit_definition_id=item.id, value=value)
            for item, value in limits
        ]
    )
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="role.created",
        result=AuditResult.SUCCESS,
        resource_type="role",
        resource_id=str(role.id),
        request_id=getattr(request.state, "request_id", None),
        details={"permissions": payload.permission_codes, "limits": payload.limits},
    )
    await session.commit()
    await session.refresh(role)
    return await _role_read(session, role)


@router.patch("/{role_id}", response_model=RoleRead)
async def update_role(
    role_id: UUID,
    payload: RoleUpdate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:manage"))],
) -> RoleRead:
    role = await session.scalar(select(Role).where(Role.id == role_id).with_for_update())
    if role is None:
        raise ApiError(status_code=404, code="role_not_found", message="Role not found")
    _ensure_role_mutable(access, role)
    changes = payload.model_dump(exclude_unset=True)
    new_priority = changes.get("priority", role.priority)
    if not access.user.is_superuser and new_priority > access.max_role_priority:
        raise ApiError(
            status_code=403,
            code="role_escalation_denied",
            message="A role cannot be raised above your own priority",
        )
    for key, value in changes.items():
        setattr(role, key, value)
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="role.updated",
        result=AuditResult.SUCCESS,
        resource_type="role",
        resource_id=str(role.id),
        request_id=getattr(request.state, "request_id", None),
        details={"fields": sorted(changes)},
    )
    await session.commit()
    await session.refresh(role)
    return await _role_read(session, role)


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: UUID,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:manage"))],
    expected_name: Annotated[str, Query(min_length=1, max_length=200)],
    expected_policy_etag: Annotated[
        str,
        Query(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
    ],
) -> None:
    """Delete an unused custom role without cascading business authorization."""

    access = await lock_and_refresh_actor_access(session, access, {"role:manage"})
    # FOR UPDATE serializes this decision with role assignment and PostgreSQL
    # foreign-key checks. New references cannot appear between the counts and
    # the delete; they either precede the lock and are counted, or wait and fail
    # after the role is deleted.
    role = await session.scalar(_locked_role_for_delete_statement(role_id))
    if role is None:
        raise ApiError(status_code=404, code="role_not_found", message="Role not found")
    _ensure_role_mutable(access, role)
    if role.name != expected_name:
        raise ApiError(
            status_code=409,
            code="role_changed",
            message="Role changed after delete confirmation; refresh and confirm again",
        )
    current_policy = await _role_read(session, role)
    if current_policy.policy_etag != expected_policy_etag:
        raise ApiError(
            status_code=409,
            code="stale_role_policy",
            message="Role policy changed after delete confirmation; refresh and confirm again",
        )

    user_assignments = int(
        await session.scalar(
            select(func.count()).select_from(UserRole).where(UserRole.role_id == role_id)
        )
        or 0
    )
    knowledge_base_grants = int(
        await session.scalar(
            select(func.count())
            .select_from(KnowledgeBaseRoleGrant)
            .where(KnowledgeBaseRoleGrant.role_id == role_id)
        )
        or 0
    )
    references = {
        "knowledge_base_grants": knowledge_base_grants,
        "user_assignments": user_assignments,
    }
    if any(references.values()):
        raise ApiError(
            status_code=409,
            code="role_in_use",
            message="Role is still assigned or granted and cannot be deleted",
            details={"references": references},
        )

    await deny_if_active_external_llm_egress(
        session,
        request,
        access,
        revocation_scope="role_delete",
        resource_type="role",
        resource_id=str(role.id),
        role_id=role.id,
    )
    audit_details = {
        "code": role.code,
        "name": role.name,
        "policy_etag": current_policy.policy_etag,
        "priority": role.priority,
    }
    # Policy rows are owned by the role and are intentionally removed. Business
    # references above are never cascaded by this endpoint.
    await session.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
    await session.execute(delete(RoleLimit).where(RoleLimit.role_id == role_id))
    await session.delete(role)
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="role.deleted",
        result=AuditResult.SUCCESS,
        resource_type="role",
        resource_id=str(role_id),
        request_id=getattr(request.state, "request_id", None),
        details=audit_details,
    )
    await session.commit()


@router.put("/{role_id}/permissions", response_model=RoleRead)
async def replace_permissions(
    role_id: UUID,
    payload: PermissionSet,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:manage"))],
) -> RoleRead:
    role = await session.scalar(select(Role).where(Role.id == role_id).with_for_update())
    if role is None:
        raise ApiError(status_code=404, code="role_not_found", message="Role not found")
    _ensure_role_mutable(access, role)
    _ensure_policy_grantable(access, permission_codes=payload.permission_codes)
    permissions = await _resolve_permissions(session, payload.permission_codes)
    await deny_if_active_external_llm_egress(
        session,
        request,
        access,
        revocation_scope="role_permissions",
        resource_type="role",
        resource_id=str(role.id),
        role_id=role.id,
    )
    await session.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
    session.add_all(
        [RolePermission(role_id=role_id, permission_id=item.id) for item in permissions]
    )
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="role.permissions.replaced",
        result=AuditResult.SUCCESS,
        resource_type="role",
        resource_id=str(role.id),
        request_id=getattr(request.state, "request_id", None),
        details={"permissions": payload.permission_codes},
    )
    await session.commit()
    await session.refresh(role)
    return await _role_read(session, role)


@router.put("/{role_id}/limits", response_model=RoleRead)
async def replace_limits(
    role_id: UUID,
    payload: LimitSet,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:manage"))],
) -> RoleRead:
    role = await session.scalar(select(Role).where(Role.id == role_id).with_for_update())
    if role is None:
        raise ApiError(status_code=404, code="role_not_found", message="Role not found")
    _ensure_role_mutable(access, role)
    _ensure_policy_grantable(access, limits=payload.limits)
    limits = await _resolve_limits(session, payload.limits)
    await session.execute(delete(RoleLimit).where(RoleLimit.role_id == role_id))
    session.add_all(
        [
            RoleLimit(role_id=role_id, limit_definition_id=item.id, value=value)
            for item, value in limits
        ]
    )
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="role.limits.replaced",
        result=AuditResult.SUCCESS,
        resource_type="role",
        resource_id=str(role.id),
        request_id=getattr(request.state, "request_id", None),
        details={"limits": payload.limits},
    )
    await session.commit()
    await session.refresh(role)
    return await _role_read(session, role)


@router.put("/{role_id}/policy", response_model=RoleRead)
async def replace_policy(
    role_id: UUID,
    payload: RolePolicySet,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:manage"))],
) -> RoleRead:
    role = await session.scalar(select(Role).where(Role.id == role_id).with_for_update())
    if role is None:
        raise ApiError(status_code=404, code="role_not_found", message="Role not found")
    _ensure_role_mutable(access, role)
    _ensure_policy_grantable(
        access,
        permission_codes=payload.permission_codes,
        limits=payload.limits,
    )
    permissions = await _resolve_permissions(session, payload.permission_codes)
    limits = await _resolve_limits(session, payload.limits)

    await deny_if_active_external_llm_egress(
        session,
        request,
        access,
        revocation_scope="role_policy",
        resource_type="role",
        resource_id=str(role.id),
        role_id=role.id,
    )
    await session.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
    await session.execute(delete(RoleLimit).where(RoleLimit.role_id == role_id))
    session.add_all(
        [RolePermission(role_id=role_id, permission_id=item.id) for item in permissions]
    )
    session.add_all(
        [
            RoleLimit(role_id=role_id, limit_definition_id=item.id, value=value)
            for item, value in limits
        ]
    )
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="role.policy.replaced",
        result=AuditResult.SUCCESS,
        resource_type="role",
        resource_id=str(role.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "permissions": payload.permission_codes,
            "limits": payload.limits,
        },
    )
    await session.commit()
    await session.refresh(role)
    return await _role_read(session, role)


@permission_router.get("", response_model=list[PermissionRead])
async def list_permissions(
    session: DatabaseSession,
    _: Annotated[AccessContext, Depends(require_permission("role:read"))],
) -> list[Permission]:
    return list((await session.scalars(select(Permission).order_by(Permission.code))).all())


@limit_router.get("", response_model=list[LimitDefinitionRead])
async def list_limit_definitions(
    session: DatabaseSession,
    _: Annotated[AccessContext, Depends(require_permission("role:read"))],
) -> list[LimitDefinition]:
    return list(
        (await session.scalars(select(LimitDefinition).order_by(LimitDefinition.key))).all()
    )
