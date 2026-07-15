from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from redis.asyncio import Redis
from sqlalchemy import delete, func, or_, select, text, update

from app.api.dependencies import (
    DatabaseSession,
    get_password_service,
    redis_dependency,
    require_authenticated_access,
    require_permission,
)
from app.api.egress_leases import deny_if_active_external_llm_egress
from app.api.errors import ApiError
from app.core.config import Settings, get_settings
from app.core.password_async import hash_password, verify_password
from app.core.security import PasswordService
from app.db.models import (
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    LimitDefinition,
    Permission,
    RefreshToken,
    Role,
    RoleLimit,
    RolePermission,
    User,
    UserRole,
    UserStatus,
)
from app.schemas.users import (
    RoleAssignmentUpdate,
    UserCreate,
    UserPasswordReset,
    UserRead,
    UserUpdate,
)
from app.services.access import AccessContext
from app.services.audit import AuditResult, add_audit_event
from app.services.knowledge_bases import require_knowledge_base_access
from app.services.list_search import literal_contains_pattern
from app.services.rate_limit import RateLimiter
from app.services.rbac_mutation import (
    acquire_rbac_mutation_lock,
    lock_role_union,
    locked_users_statement,
    refresh_locked_actor_access,
)

router = APIRouter()


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
    if any(role.is_system or role.priority >= access.max_role_priority for role in roles):
        raise ApiError(
            status_code=403,
            code="role_escalation_denied",
            message="You cannot assign a system role or a role at or above your own priority",
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
            )
            .where(KnowledgeBaseRoleGrant.role_id.in_(role_ids))
            .order_by(
                KnowledgeBaseRoleGrant.knowledge_base_id,
                KnowledgeBaseRoleGrant.role_id,
            )
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
    search: Annotated[str | None, Query(max_length=200)] = None,
) -> list[UserRead]:
    statement = select(User)
    term = search.strip() if search else ""
    if term:
        pattern = literal_contains_pattern(term)
        statement = statement.where(
            or_(
                User.email.ilike(pattern, escape="\\"),
                User.display_name.ilike(pattern, escape="\\"),
            )
        )
    users = list(
        (
            await session.scalars(
                statement.order_by(User.created_at.desc(), User.id).limit(limit).offset(offset)
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
    password_hash = await hash_password(passwords, payload.password)
    await acquire_rbac_mutation_lock(session)
    actor = await session.scalar(locked_users_statement({access.user.id}))
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    locked_roles = await lock_role_union(
        session,
        user_ids={actor.id},
        additional_role_ids=role_ids,
    )
    access = await refresh_locked_actor_access(session, actor, required_permissions)
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
        roles = [locked_roles[role_id] for role_id in role_ids if role_id in locked_roles]
        existing_ids = {role.id for role in roles}
        if existing_ids != role_ids:
            raise ApiError(
                status_code=422, code="unknown_role", message="One or more roles do not exist"
            )
        await _ensure_roles_assignable(session, access, roles)

    user = User(
        email=email,
        password_hash=password_hash,
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
    await acquire_rbac_mutation_lock(session)
    locked_users = list(
        (await session.scalars(locked_users_statement({access.user.id, user_id}))).all()
    )
    users_by_id = {item.id: item for item in locked_users}
    await lock_role_union(session, user_ids=users_by_id)
    actor = users_by_id.get(access.user.id)
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    access = await refresh_locked_actor_access(session, actor, {"user:manage"})
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


async def _replace_user_password(
    user_id: UUID,
    payload: UserPasswordReset,
    request: Request,
    response: Response,
    session: DatabaseSession,
    access: AccessContext,
    passwords: PasswordService,
    *,
    required_permissions: set[str],
) -> None:
    """Replace a password and revoke every previously issued session atomically."""

    is_self_change = access.user.id == user_id
    current_password = (
        payload.current_password.get_secret_value()
        if payload.current_password is not None
        else None
    )
    if not is_self_change and not access.user.is_superuser:
        raise ApiError(
            status_code=403,
            code="superuser_required",
            message="Only a superuser can reset another user's password",
        )
    if is_self_change and current_password is None:
        raise ApiError(
            status_code=422,
            code="current_password_required",
            message="The current password is required when changing your own password",
        )
    if not is_self_change and current_password is not None:
        raise ApiError(
            status_code=422,
            code="current_password_not_allowed",
            message="Do not provide the target user's current password for an administrative reset",
        )

    verified_password_hash: str | None = None
    if is_self_change:
        verified_password_hash = access.user.password_hash
        if not await verify_password(passwords, current_password or "", verified_password_hash):
            raise ApiError(
                status_code=401,
                code="invalid_current_password",
                message="The current password is incorrect",
            )

    # Argon2 work is deliberately completed outside the RBAC critical section.
    # The resulting one-way hash is safe to hold briefly and keeps the global
    # policy lock from being occupied by CPU-bound password derivation.
    password_hash = await hash_password(passwords, payload.new_password.get_secret_value())
    await acquire_rbac_mutation_lock(session)
    locked_users = list(
        (await session.scalars(locked_users_statement({access.user.id, user_id}))).all()
    )
    users_by_id = {item.id: item for item in locked_users}
    await lock_role_union(session, user_ids=users_by_id)
    actor = users_by_id.get(access.user.id)
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    access = await refresh_locked_actor_access(session, actor, required_permissions)
    user = users_by_id.get(user_id)
    if user is None:
        raise ApiError(status_code=404, code="user_not_found", message="User not found")

    is_self_change = user.id == actor.id
    if is_self_change:
        # Verification happens outside the global RBAC lock. Bind it to the
        # exact hash now locked so a concurrent password change cannot turn a
        # stale proof into a successful replacement.
        if verified_password_hash is None or actor.password_hash != verified_password_hash:
            raise ApiError(
                status_code=401,
                code="invalid_current_password",
                message="The current password is incorrect",
            )
    elif not actor.is_superuser:
        # Re-check after locking so authorization cannot be won with a stale
        # access context if the actor changes concurrently.
        raise ApiError(
            status_code=403,
            code="superuser_required",
            message="Only a superuser can reset another user's password",
        )

    now = datetime.now(UTC)
    previous_token_version = user.token_version
    user.password_hash = password_hash
    user.token_version += 1
    revoked = await session.execute(
        update(RefreshToken)
        .where(
            RefreshToken.user_id == user.id,
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    revoked_count = max(int(getattr(revoked, "rowcount", 0) or 0), 0)
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="user.password.reset",
        result=AuditResult.SUCCESS,
        resource_type="user",
        resource_id=str(user.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "from_token_version": previous_token_version,
            "to_token_version": user.token_version,
            "revoked_refresh_tokens": revoked_count,
        },
    )
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


async def _enforce_self_password_change_rate_limit(
    response: Response,
    access: AccessContext,
    redis: Redis,
    settings: Settings,
) -> None:
    limit = settings.login_attempts_per_account_per_minute
    try:
        decision = await RateLimiter(redis).check(
            key=f"rate:password-change:user:{access.user.id}",
            limit=limit,
        )
    except Exception as error:
        raise ApiError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="rate_limiter_unavailable",
            message="Password change rate limiting is temporarily unavailable",
        ) from error
    response.headers["X-RateLimit-Limit"] = str(decision.limit)
    response.headers["X-RateLimit-Remaining"] = str(decision.remaining)
    if not decision.allowed:
        raise ApiError(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="rate_limit_exceeded",
            message="Too many password change attempts",
            details={"retry_after_seconds": decision.retry_after_seconds},
            headers={
                "Retry-After": str(decision.retry_after_seconds),
                "X-RateLimit-Limit": str(decision.limit),
                "X-RateLimit-Remaining": "0",
            },
        )


@router.put("/me/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_own_password(
    payload: UserPasswordReset,
    request: Request,
    response: Response,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_authenticated_access)],
    passwords: Annotated[PasswordService, Depends(get_password_service)],
    redis: Annotated[Redis, Depends(redis_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    """Change the signed-in user's password without granting member-management access."""

    await _enforce_self_password_change_rate_limit(response, access, redis, settings)
    await _replace_user_password(
        access.user.id,
        payload,
        request,
        response,
        session,
        access,
        passwords,
        required_permissions=set(),
    )


@router.put("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_user_password(
    user_id: UUID,
    payload: UserPasswordReset,
    request: Request,
    response: Response,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("user:manage"))],
    passwords: Annotated[PasswordService, Depends(get_password_service)],
    redis: Annotated[Redis, Depends(redis_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    """Administratively replace a password; only a live superuser may target another user."""

    if user_id == access.user.id:
        await _enforce_self_password_change_rate_limit(response, access, redis, settings)
    await _replace_user_password(
        user_id,
        payload,
        request,
        response,
        session,
        access,
        passwords,
        required_permissions={"user:manage"},
    )


@router.put("/{user_id}/roles", response_model=UserRead)
async def replace_user_roles(
    user_id: UUID,
    payload: RoleAssignmentUpdate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("role:assign"))],
) -> UserRead:
    role_ids = set(payload.role_ids)
    await acquire_rbac_mutation_lock(session)
    locked_users = list(
        (await session.scalars(locked_users_statement({access.user.id, user_id}))).all()
    )
    users_by_id = {item.id: item for item in locked_users}
    locked_roles = await lock_role_union(
        session,
        user_ids=users_by_id,
        additional_role_ids=role_ids,
    )
    actor = users_by_id.get(access.user.id)
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    access = await refresh_locked_actor_access(session, actor, {"role:assign"})
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
    current_version = user.role_assignment_version
    if payload.expected_version != current_version:
        raise ApiError(
            status_code=409,
            code="stale_role_assignment",
            message="The user's role assignment changed; reload it before retrying",
            details={"current_version": current_version},
        )
    roles = [locked_roles[role_id] for role_id in role_ids if role_id in locked_roles]
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
        user.role_assignment_version += 1
        user.token_version += 1
        add_audit_event(
            session,
            actor_id=access.user.id,
            action="user.roles.replaced",
            result=AuditResult.SUCCESS,
            resource_type="user",
            resource_id=str(user.id),
            request_id=getattr(request.state, "request_id", None),
            details={
                "from_version": current_version,
                "to_version": user.role_assignment_version,
            },
        )
    await session.commit()
    await session.refresh(user)
    return await _user_read(session, user)
