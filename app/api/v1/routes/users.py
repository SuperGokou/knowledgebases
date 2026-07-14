from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import Select, delete, func, or_, select, text

from app.api.dependencies import DatabaseSession, get_password_service, require_permission
from app.api.egress_leases import deny_if_active_external_llm_egress
from app.api.errors import ApiError
from app.core.password_async import hash_password
from app.core.security import PasswordService
from app.db.models import (
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    LimitDefinition,
    Permission,
    Role,
    RoleLimit,
    RolePermission,
    User,
    UserRole,
    UserStatus,
)
from app.schemas.users import RoleAssignmentUpdate, UserCreate, UserRead, UserUpdate
from app.services.access import AccessContext, AccessService
from app.services.audit import AuditResult, add_audit_event
from app.services.knowledge_bases import require_knowledge_base_access

router = APIRouter()


def _locked_roles_statement(role_ids: set[UUID]) -> Select[tuple[Role]]:
    # PostgreSQL FK checks take KEY SHARE on Role. NO KEY UPDATE still serializes
    # policy mutation/deletion but stays compatible with ACL grant replacement,
    # whose global order is KnowledgeBase -> Role FK check.
    return select(Role).where(Role.id.in_(role_ids)).with_for_update(key_share=True)


def _locked_actor_user_statement(user_id: UUID) -> Select[tuple[User]]:
    return select(User).where(User.id == user_id).with_for_update()


def _locked_actor_roles_statement(user_id: UUID) -> Select[tuple[Role]]:
    now = datetime.now(UTC)
    return (
        select(Role)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(
            UserRole.user_id == user_id,
            or_(UserRole.expires_at.is_(None), UserRole.expires_at > now),
        )
        .with_for_update(of=Role, key_share=True)
    )


async def _refresh_locked_actor_access(
    session: DatabaseSession,
    actor: User,
    required_permissions: set[str],
) -> AccessContext:
    if actor.status is not UserStatus.ACTIVE:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    # Lock every active role before re-resolving mutable permissions and limits.
    # Policy mutation endpoints coordinate on these same Role rows.
    list((await session.scalars(_locked_actor_roles_statement(actor.id))).all())
    current = await AccessService().resolve(session, actor)
    missing = sorted(code for code in required_permissions if not current.allows(code))
    if missing:
        raise ApiError(
            status_code=403,
            code="permission_denied",
            message=f"Permissions required: {', '.join(missing)}",
        )
    return current


async def _lock_and_refresh_actor_access(
    session: DatabaseSession,
    access: AccessContext,
    required_permissions: set[str],
) -> AccessContext:
    actor = await session.scalar(_locked_actor_user_statement(access.user.id))
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    return await _refresh_locked_actor_access(session, actor, required_permissions)


async def _ensure_kb_grants_delegable(
    session: DatabaseSession,
    access: AccessContext,
    grant_rows: list[tuple[UUID, KnowledgeBaseAccessLevel]],
) -> None:
    for knowledge_base_id, access_level in grant_rows:
        await require_knowledge_base_access(
            session,
            access,
            knowledge_base_id,
            minimum=access_level,
            lock=True,
        )


async def _user_reads(session: DatabaseSession, users: list[User]) -> list[UserRead]:
    if not users:
        return []
    user_ids = [user.id for user in users]
    rows = (
        await session.execute(
            select(UserRole.user_id, UserRole.role_id).where(UserRole.user_id.in_(user_ids))
        )
    ).all()
    roles_by_user: dict[UUID, list[UUID]] = {user_id: [] for user_id in user_ids}
    for user_id, role_id in rows:
        roles_by_user[user_id].append(role_id)
    return [
        UserRead.model_validate(user).model_copy(
            update={"role_ids": sorted(roles_by_user[user.id], key=str)}
        )
        for user in users
    ]


async def _user_read(session: DatabaseSession, user: User) -> UserRead:
    return (await _user_reads(session, [user]))[0]


async def _lock_superuser_guard(session: DatabaseSession) -> None:
    if session.get_bind().dialect.name == "postgresql":
        await session.execute(text("SELECT pg_advisory_xact_lock(1262836038)"))


async def _ensure_target_is_below_actor(
    session: DatabaseSession,
    access: AccessContext,
    target_user_id: UUID,
) -> None:
    if access.user.is_superuser:
        return
    now = datetime.now(UTC)
    rows = (
        await session.execute(
            select(Role.priority, Role.is_system)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(
                UserRole.user_id == target_user_id,
                or_(UserRole.expires_at.is_(None), UserRole.expires_at > now),
            )
        )
    ).all()
    target_priority = max((priority for priority, _ in rows), default=-10_001)
    if any(is_system for _, is_system in rows) or target_priority >= access.max_role_priority:
        raise ApiError(
            status_code=403,
            code="target_user_protected",
            message="You can only manage users whose active roles are below your own priority",
        )


async def _ensure_roles_assignable(
    session: DatabaseSession,
    access: AccessContext,
    roles: list[Role],
) -> None:
    if access.user.is_superuser:
        return
    if any(role.is_system or role.priority > access.max_role_priority for role in roles):
        raise ApiError(
            status_code=403,
            code="role_escalation_denied",
            message="You cannot assign a system role or a role above your own priority",
        )
    role_ids = [role.id for role in roles]
    permission_codes = (
        await session.scalars(
            select(Permission.code)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .where(RolePermission.role_id.in_(role_ids))
            .distinct()
        )
    ).all()
    if any(not access.allows(code) for code in permission_codes):
        raise ApiError(
            status_code=403,
            code="permission_escalation_denied",
            message="You cannot assign a role containing permissions that you do not hold",
        )
    limit_rows = (
        await session.execute(
            select(LimitDefinition.key, RoleLimit.value)
            .join(RoleLimit, RoleLimit.limit_definition_id == LimitDefinition.id)
            .where(RoleLimit.role_id.in_(role_ids))
        )
    ).all()
    for key, value in limit_rows:
        own_value = access.limits.get(key, 0)
        if own_value is not None and (value is None or value > own_value):
            raise ApiError(
                status_code=403,
                code="limit_escalation_denied",
                message="You cannot assign a role with limits above your effective limits",
            )
    grant_rows = (
        await session.execute(
            select(
                KnowledgeBaseRoleGrant.knowledge_base_id,
                KnowledgeBaseRoleGrant.access_level,
            ).where(KnowledgeBaseRoleGrant.role_id.in_(role_ids))
        )
    ).all()
    await _ensure_kb_grants_delegable(
        session,
        access,
        [(knowledge_base_id, access_level) for knowledge_base_id, access_level in grant_rows],
    )


@router.get("", response_model=list[UserRead])
async def list_users(
    session: DatabaseSession,
    _: Annotated[AccessContext, Depends(require_permission("user:manage"))],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[UserRead]:
    users = list(
        (
            await session.scalars(
                select(User).order_by(User.created_at.desc(), User.id).limit(limit).offset(offset)
            )
        ).all()
    )
    return await _user_reads(session, users)


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("user:manage"))],
    passwords: Annotated[PasswordService, Depends(get_password_service)],
) -> UserRead:
    role_ids = set(payload.role_ids)
    required_permissions = {"user:manage"}
    if role_ids:
        required_permissions.add("role:assign")
    access = await _lock_and_refresh_actor_access(session, access, required_permissions)
    email = str(payload.email).lower()
    if await session.scalar(select(User.id).where(User.email == email)) is not None:
        raise ApiError(status_code=409, code="email_exists", message="Email already exists")

    if role_ids and not access.allows("role:assign"):
        raise ApiError(
            status_code=403,
            code="permission_denied",
            message="Permission required: role:assign",
        )
    if role_ids:
        roles = list((await session.scalars(_locked_roles_statement(role_ids))).all())
        existing_ids = {role.id for role in roles}
        if existing_ids != role_ids:
            raise ApiError(
                status_code=422, code="unknown_role", message="One or more roles do not exist"
            )
        await _ensure_roles_assignable(session, access, roles)

    user = User(
        email=email,
        password_hash=await hash_password(passwords, payload.password),
        display_name=payload.display_name,
    )
    session.add(user)
    await session.flush()
    for role_id in role_ids:
        session.add(UserRole(user_id=user.id, role_id=role_id, assigned_by=access.user.id))
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="user.created",
        result=AuditResult.SUCCESS,
        resource_type="user",
        resource_id=str(user.id),
        request_id=getattr(request.state, "request_id", None),
        details={"roles": [str(item) for item in role_ids]},
    )
    await session.commit()
    await session.refresh(user)
    return await _user_read(session, user)


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: UUID,
    payload: UserUpdate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("user:manage"))],
) -> UserRead:
    locked_users = list(
        (
            await session.scalars(
                select(User)
                .where(User.id.in_({access.user.id, user_id}))
                .order_by(User.id)
                .with_for_update()
            )
        ).all()
    )
    users_by_id = {item.id: item for item in locked_users}
    actor = users_by_id.get(access.user.id)
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    access = await _refresh_locked_actor_access(session, actor, {"role:assign"})
    user = users_by_id.get(user_id)
    if user is None:
        raise ApiError(status_code=404, code="user_not_found", message="User not found")
    await _ensure_target_is_below_actor(session, access, user.id)
    if user.is_superuser and not access.user.is_superuser:
        raise ApiError(
            status_code=403,
            code="superuser_protected",
            message="Only a superuser can modify another superuser",
        )
    changes = payload.model_dump(exclude_unset=True)
    if (
        user.is_superuser
        and changes.get("status") is not None
        and changes["status"] is not UserStatus.ACTIVE
    ):
        await _lock_superuser_guard(session)
        remaining = await session.scalar(
            select(func.count())
            .select_from(User)
            .where(
                User.is_superuser.is_(True),
                User.status == UserStatus.ACTIVE,
                User.id != user.id,
            )
        )
        if not remaining:
            raise ApiError(
                status_code=409,
                code="last_superuser_protected",
                message="The final active superuser cannot be disabled or locked",
            )
    if (
        user.status is UserStatus.ACTIVE
        and changes.get("status") is not None
        and changes["status"] is not UserStatus.ACTIVE
    ):
        await deny_if_active_external_llm_egress(
            session,
            request,
            access,
            revocation_scope="user_status",
            resource_type="user",
            resource_id=str(user.id),
            user_id=user.id,
        )
    for key, value in changes.items():
        setattr(user, key, value)
    if "status" in changes:
        user.token_version += 1
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="user.updated",
        result=AuditResult.SUCCESS,
        resource_type="user",
        resource_id=str(user.id),
        request_id=getattr(request.state, "request_id", None),
        details={"fields": sorted(changes)},
    )
    await session.commit()
    await session.refresh(user)
    return await _user_read(session, user)


@router.put("/{user_id}/roles", response_model=UserRead)
async def replace_user_roles(
    user_id: UUID,
    payload: RoleAssignmentUpdate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:assign"))],
) -> UserRead:
    locked_users = list(
        (
            await session.scalars(
                select(User)
                .where(User.id.in_({access.user.id, user_id}))
                .order_by(User.id)
                .with_for_update()
            )
        ).all()
    )
    users_by_id = {item.id: item for item in locked_users}
    actor = users_by_id.get(access.user.id)
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    access = await _refresh_locked_actor_access(session, actor, {"role:assign"})
    user = users_by_id.get(user_id)
    if user is None:
        raise ApiError(status_code=404, code="user_not_found", message="User not found")
    await _ensure_target_is_below_actor(session, access, user.id)
    if user.is_superuser:
        if not access.user.is_superuser:
            raise ApiError(
                status_code=403,
                code="superuser_protected",
                message="Only a superuser can replace another superuser's roles",
            )
        await _lock_superuser_guard(session)
        remaining = await session.scalar(
            select(func.count())
            .select_from(User)
            .where(
                User.is_superuser.is_(True),
                User.status == UserStatus.ACTIVE,
                User.id != user.id,
            )
        )
        if not remaining:
            raise ApiError(
                status_code=409,
                code="last_superuser_protected",
                message="The final active superuser's roles cannot be replaced",
            )
    role_ids = set(payload.role_ids)
    roles = list((await session.scalars(_locked_roles_statement(role_ids))).all())
    existing_ids = {role.id for role in roles}
    if existing_ids != role_ids:
        raise ApiError(
            status_code=422, code="unknown_role", message="One or more roles do not exist"
        )
    await _ensure_roles_assignable(session, access, roles)
    current_role_ids = set(
        (await session.scalars(select(UserRole.role_id).where(UserRole.user_id == user_id))).all()
    )
    if current_role_ids != role_ids:
        await deny_if_active_external_llm_egress(
            session,
            request,
            access,
            revocation_scope="user_roles",
            resource_type="user",
            resource_id=str(user.id),
            user_id=user.id,
        )
    await session.execute(delete(UserRole).where(UserRole.user_id == user_id))
    for role_id in role_ids:
        session.add(UserRole(user_id=user_id, role_id=role_id, assigned_by=access.user.id))
    user.token_version += 1
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="user.roles.replaced",
        result=AuditResult.SUCCESS,
        resource_type="user",
        resource_id=str(user.id),
        request_id=getattr(request.state, "request_id", None),
        details={"roles": [str(item) for item in role_ids]},
    )
    await session.commit()
    await session.refresh(user)
    return await _user_read(session, user)
