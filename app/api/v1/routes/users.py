from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import delete, func, or_, select, text

from app.api.dependencies import DatabaseSession, get_password_service, require_permission
from app.api.errors import ApiError
from app.core.password_async import hash_password
from app.core.security import PasswordService
from app.db.models import (
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
from app.services.access import AccessContext
from app.services.audit import add_audit_event

router = APIRouter()


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
    email = str(payload.email).lower()
    if await session.scalar(select(User.id).where(User.email == email)) is not None:
        raise ApiError(status_code=409, code="email_exists", message="Email already exists")

    role_ids = set(payload.role_ids)
    if role_ids:
        roles = list((await session.scalars(select(Role).where(Role.id.in_(role_ids)))).all())
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
    user = await session.scalar(select(User).where(User.id == user_id).with_for_update())
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
    for key, value in changes.items():
        setattr(user, key, value)
    if "status" in changes:
        user.token_version += 1
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="user.updated",
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
    user = await session.scalar(select(User).where(User.id == user_id).with_for_update())
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
    roles = list((await session.scalars(select(Role).where(Role.id.in_(role_ids)))).all())
    existing_ids = {role.id for role in roles}
    if existing_ids != role_ids:
        raise ApiError(
            status_code=422, code="unknown_role", message="One or more roles do not exist"
        )
    await _ensure_roles_assignable(session, access, roles)
    await session.execute(delete(UserRole).where(UserRole.user_id == user_id))
    for role_id in role_ids:
        session.add(UserRole(user_id=user_id, role_id=role_id, assigned_by=access.user.id))
    user.token_version += 1
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="user.roles.replaced",
        resource_type="user",
        resource_id=str(user.id),
        request_id=getattr(request.state, "request_id", None),
        details={"roles": [str(item) for item in role_ids]},
    )
    await session.commit()
    await session.refresh(user)
    return await _user_read(session, user)
