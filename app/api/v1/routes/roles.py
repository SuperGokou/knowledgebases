from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import and_, case, delete, exists, func, or_, select
from sqlalchemy.orm import aliased

from app.api.dependencies import DatabaseSession, require_permission
from app.api.egress_leases import deny_if_active_external_llm_egress
from app.api.errors import ApiError
from app.db.models import (
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    LimitDefinition,
    Permission,
    Role,
    RoleLimit,
    RolePermission,
    User,
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
from app.services.list_search import literal_contains_pattern
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
permission_router = APIRouter()
limit_router = APIRouter()


async def _lock_and_refresh_role_admin(
    session: DatabaseSession,
    access: AccessContext,
    *,
    target_role_ids: set[UUID] | None = None,
) -> tuple[AccessContext, dict[UUID, Role]]:
    await acquire_rbac_mutation_lock(session)
    actor = await session.scalar(
        select(User)
        .where(User.id == access.user.id)
        .execution_options(populate_existing=True)
    )
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    locked_roles = await lock_role_union(
        session,
        user_ids={actor.id},
        additional_role_ids=target_role_ids or (),
    )
    refreshed = await refresh_locked_actor_access(session, actor, {"role:manage"})
    await acquire_user_activity_locks(
        session,
        {actor.id: ActivityLockMode.SHARED},
    )
    actor = await session.scalar(locked_users_statement({actor.id}))
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    locked_roles = await lock_role_union(
        session,
        user_ids={actor.id},
        additional_role_ids=target_role_ids or (),
    )
    refreshed = await refresh_locked_actor_access(session, actor, {"role:manage"})
    return refreshed, locked_roles


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
    return [
        RoleRead.model_validate(role).model_copy(
            update={
                "permission_codes": sorted(permissions_by_role[role.id]),
                "limits": dict(sorted(limits_by_role[role.id].items())),
            }
        )
        for role in roles
    ]


async def _role_read(session: DatabaseSession, role: Role) -> RoleRead:
    return (await _role_reads(session, [role]))[0]


def _ensure_role_policy_version(role: Role, expected_version: int) -> None:
    if expected_version != role.policy_version:
        raise ApiError(
            status_code=409,
            code="stale_role_policy",
            message="The role policy changed after this editor was opened",
            details={"current_version": role.policy_version},
        )


async def _current_permission_codes(
    session: DatabaseSession,
    role_id: UUID,
) -> set[str]:
    return set(
        (
            await session.scalars(
                select(Permission.code)
                .join(RolePermission, RolePermission.permission_id == Permission.id)
                .where(RolePermission.role_id == role_id)
            )
        ).all()
    )


async def _current_limits(
    session: DatabaseSession,
    role_id: UUID,
) -> dict[str, int | None]:
    rows = (
        await session.execute(
            select(LimitDefinition.key, RoleLimit.value)
            .join(RoleLimit, RoleLimit.limit_definition_id == LimitDefinition.id)
            .where(RoleLimit.role_id == role_id)
        )
    ).all()
    return {key: value for key, value in rows}


@router.get("", response_model=list[RoleRead])
async def list_roles(
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:read"))],
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    q: Annotated[str | None, Query(max_length=200)] = None,
    assignable: bool = False,
) -> list[RoleRead]:
    statement = select(Role)
    if assignable:
        if not access.allows("role:assign"):
            raise ApiError(
                status_code=403,
                code="permission_denied",
                message="Permission required: role:assign",
            )
        # Candidate discovery is intentionally stricter than role management:
        # system and equal-priority roles never appear, even for superusers.
        statement = statement.where(
            Role.is_system.is_(False),
            Role.priority < access.max_role_priority,
        )
        if not access.user.is_superuser:
            denied_permission = exists(
                select(RolePermission.id)
                .join(Permission, Permission.id == RolePermission.permission_id)
                .where(
                    RolePermission.role_id == Role.id,
                    Permission.code.not_in(tuple(access.permissions)),
                )
            )
            statement = statement.where(~denied_permission)

            denied_limit_conditions = [
                and_(
                    LimitDefinition.key == key,
                    or_(RoleLimit.value.is_(None), RoleLimit.value > own_value),
                )
                for key, own_value in access.limits.items()
                if own_value is not None
            ]
            known_limit_keys = tuple(access.limits)
            if known_limit_keys:
                denied_limit_conditions.append(
                    and_(
                        LimitDefinition.key.not_in(known_limit_keys),
                        or_(RoleLimit.value.is_(None), RoleLimit.value > 0),
                    )
                )
            else:
                denied_limit_conditions.append(or_(RoleLimit.value.is_(None), RoleLimit.value > 0))
            denied_limit = exists(
                select(RoleLimit.id)
                .join(
                    LimitDefinition,
                    LimitDefinition.id == RoleLimit.limit_definition_id,
                )
                .where(
                    RoleLimit.role_id == Role.id,
                    or_(*denied_limit_conditions),
                )
            )
            statement = statement.where(~denied_limit)

            candidate_grant = aliased(KnowledgeBaseRoleGrant)
            actor_grant = aliased(KnowledgeBaseRoleGrant)
            candidate_rank = case(
                (candidate_grant.access_level == KnowledgeBaseAccessLevel.READER, 10),
                (candidate_grant.access_level == KnowledgeBaseAccessLevel.EDITOR, 20),
                (candidate_grant.access_level == KnowledgeBaseAccessLevel.MANAGER, 30),
                else_=0,
            )
            actor_rank = case(
                (actor_grant.access_level == KnowledgeBaseAccessLevel.READER, 10),
                (actor_grant.access_level == KnowledgeBaseAccessLevel.EDITOR, 20),
                (actor_grant.access_level == KnowledgeBaseAccessLevel.MANAGER, 30),
                else_=0,
            )
            actor_max_rank = (
                select(func.max(actor_rank))
                .where(
                    actor_grant.knowledge_base_id == candidate_grant.knowledge_base_id,
                    actor_grant.role_id.in_(tuple(access.role_ids)),
                )
                .correlate(candidate_grant)
                .scalar_subquery()
            )
            denied_knowledge_grant = exists(
                select(candidate_grant.id)
                .join(
                    KnowledgeBase,
                    KnowledgeBase.id == candidate_grant.knowledge_base_id,
                )
                .where(
                    candidate_grant.role_id == Role.id,
                    KnowledgeBase.owner_id != access.user.id,
                    func.coalesce(actor_max_rank, 0) < candidate_rank,
                )
            )
            statement = statement.where(~denied_knowledge_grant)
    normalized_query = q.strip() if q else ""
    if normalized_query:
        pattern = literal_contains_pattern(normalized_query)
        statement = statement.where(
            or_(
                Role.name.ilike(pattern, escape="\\"),
                Role.code.ilike(pattern, escape="\\"),
            )
        )
    roles = list(
        (
            await session.scalars(
                statement.order_by(Role.priority.desc(), Role.code, Role.id)
                .offset(offset)
                .limit(limit)
            )
        ).all()
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
@rbac_mutation_endpoint
async def create_role(
    payload: RoleCreate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:manage"))],
) -> RoleRead:
    access, _ = await _lock_and_refresh_role_admin(session, access)
    if not access.user.is_superuser and payload.priority >= access.max_role_priority:
        raise ApiError(
            status_code=403,
            code="role_escalation_denied",
            message="A role cannot be created at or above your own priority",
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
@rbac_mutation_endpoint
async def update_role(
    role_id: UUID,
    payload: RoleUpdate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:manage"))],
) -> RoleRead:
    access, locked_roles = await _lock_and_refresh_role_admin(
        session,
        access,
        target_role_ids={role_id},
    )
    role = locked_roles.get(role_id)
    if role is None:
        raise ApiError(status_code=404, code="role_not_found", message="Role not found")
    _ensure_role_mutable(access, role)
    _ensure_role_policy_version(role, payload.expected_version)
    changes = payload.model_dump(exclude_unset=True, exclude={"expected_version"})
    changes = {key: value for key, value in changes.items() if getattr(role, key) != value}
    new_priority = changes.get("priority", role.priority)
    if not access.user.is_superuser and new_priority >= access.max_role_priority:
        raise ApiError(
            status_code=403,
            code="role_escalation_denied",
            message="A role cannot be raised to your own priority or above",
        )
    if not changes:
        return await _role_read(session, role)
    previous_version = role.policy_version
    for key, value in changes.items():
        setattr(role, key, value)
    role.policy_version += 1
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="role.updated",
        result=AuditResult.SUCCESS,
        resource_type="role",
        resource_id=str(role.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "fields": sorted(changes),
            "from_version": previous_version,
            "to_version": role.policy_version,
        },
    )
    await session.commit()
    await session.refresh(role)
    return await _role_read(session, role)


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
@rbac_mutation_endpoint
async def delete_role(
    role_id: UUID,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:manage"))],
    expected_version: Annotated[int, Query(ge=1)],
) -> None:
    access, locked_roles = await _lock_and_refresh_role_admin(
        session,
        access,
        target_role_ids={role_id},
    )
    role = locked_roles.get(role_id)
    if role is None:
        raise ApiError(status_code=404, code="role_not_found", message="Role not found")

    # Upgrade the normal NO KEY UPDATE policy lock to FOR UPDATE. This blocks
    # new foreign-key references before the reference counts are evaluated.
    role = await session.scalar(
        select(Role)
        .where(Role.id == role_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if role is None:
        raise ApiError(status_code=404, code="role_not_found", message="Role not found")
    _ensure_role_mutable(access, role)
    _ensure_role_policy_version(role, expected_version)

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

    audit_details = {
        "code": role.code,
        "name": role.name,
        "policy_version": role.policy_version,
    }
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
@rbac_mutation_endpoint
async def replace_permissions(
    role_id: UUID,
    payload: PermissionSet,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:manage"))],
) -> RoleRead:
    access, locked_roles = await _lock_and_refresh_role_admin(
        session,
        access,
        target_role_ids={role_id},
    )
    role = locked_roles.get(role_id)
    if role is None:
        raise ApiError(status_code=404, code="role_not_found", message="Role not found")
    _ensure_role_mutable(access, role)
    _ensure_role_policy_version(role, payload.expected_version)
    desired_codes = set(payload.permission_codes)
    if desired_codes == await _current_permission_codes(session, role.id):
        return await _role_read(session, role)
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
    previous_version = role.policy_version
    role.policy_version += 1
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="role.permissions.replaced",
        result=AuditResult.SUCCESS,
        resource_type="role",
        resource_id=str(role.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "permissions": sorted(desired_codes),
            "from_version": previous_version,
            "to_version": role.policy_version,
        },
    )
    await session.commit()
    await session.refresh(role)
    return await _role_read(session, role)


@router.put("/{role_id}/limits", response_model=RoleRead)
@rbac_mutation_endpoint
async def replace_limits(
    role_id: UUID,
    payload: LimitSet,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:manage"))],
) -> RoleRead:
    access, locked_roles = await _lock_and_refresh_role_admin(
        session,
        access,
        target_role_ids={role_id},
    )
    role = locked_roles.get(role_id)
    if role is None:
        raise ApiError(status_code=404, code="role_not_found", message="Role not found")
    _ensure_role_mutable(access, role)
    _ensure_role_policy_version(role, payload.expected_version)
    if payload.limits == await _current_limits(session, role.id):
        return await _role_read(session, role)
    _ensure_policy_grantable(access, limits=payload.limits)
    limits = await _resolve_limits(session, payload.limits)
    await session.execute(delete(RoleLimit).where(RoleLimit.role_id == role_id))
    session.add_all(
        [
            RoleLimit(role_id=role_id, limit_definition_id=item.id, value=value)
            for item, value in limits
        ]
    )
    previous_version = role.policy_version
    role.policy_version += 1
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="role.limits.replaced",
        result=AuditResult.SUCCESS,
        resource_type="role",
        resource_id=str(role.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "limits": dict(sorted(payload.limits.items())),
            "from_version": previous_version,
            "to_version": role.policy_version,
        },
    )
    await session.commit()
    await session.refresh(role)
    return await _role_read(session, role)


@router.put("/{role_id}/policy", response_model=RoleRead)
@rbac_mutation_endpoint
async def replace_policy(
    role_id: UUID,
    payload: RolePolicySet,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:manage"))],
) -> RoleRead:
    access, locked_roles = await _lock_and_refresh_role_admin(
        session,
        access,
        target_role_ids={role_id},
    )
    role = locked_roles.get(role_id)
    if role is None:
        raise ApiError(status_code=404, code="role_not_found", message="Role not found")
    _ensure_role_mutable(access, role)
    _ensure_role_policy_version(role, payload.expected_version)
    desired_codes = set(payload.permission_codes)
    current_codes = await _current_permission_codes(session, role.id)
    current_limits = await _current_limits(session, role.id)
    if desired_codes == current_codes and payload.limits == current_limits:
        return await _role_read(session, role)
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
    previous_version = role.policy_version
    role.policy_version += 1
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="role.policy.replaced",
        result=AuditResult.SUCCESS,
        resource_type="role",
        resource_id=str(role.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "permissions": sorted(desired_codes),
            "limits": dict(sorted(payload.limits.items())),
            "from_version": previous_version,
            "to_version": role.policy_version,
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
