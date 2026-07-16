from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import Select, or_, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import ApiError
from app.db.models import Role, User, UserRole, UserStatus
from app.services.access import AccessContext, AccessService

# Every user/role policy write takes this transaction-scoped domain lock before
# row locks. Administrative writes are low volume, and serializing this domain
# prevents cross-request User/Role lock inversions and authorization TOCTOU.
RBAC_MUTATION_ADVISORY_LOCK = 1_262_836_039
_LOCK_NOT_AVAILABLE_SQLSTATE = "55P03"


def _database_sqlstate(error: BaseException) -> str | None:
    """Read a driver SQLSTATE without broad exception translation."""

    pending: list[BaseException] = [error]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        for attribute in ("sqlstate", "pgcode"):
            value = getattr(current, attribute, None)
            if isinstance(value, str):
                return value
        for attribute in ("orig", "__cause__", "__context__"):
            nested = getattr(current, attribute, None)
            if isinstance(nested, BaseException):
                pending.append(nested)
    return None


def raise_authorization_lock_timeout(error: DBAPIError) -> None:
    """Map only PostgreSQL lock timeout/not-available to a retryable API error."""

    if _database_sqlstate(error) != _LOCK_NOT_AVAILABLE_SQLSTATE:
        raise error
    raise ApiError(
        status_code=503,
        code="authorization_change_busy",
        message="Authorization policy is changing; retry this request shortly",
        headers={"Retry-After": "1"},
    ) from error


async def acquire_authorization_advisory_lock(
    session: AsyncSession,
    lock_key: int,
    *,
    shared: bool = False,
) -> None:
    if session.get_bind().dialect.name != "postgresql":
        return
    function = "pg_advisory_xact_lock_shared" if shared else "pg_advisory_xact_lock"
    try:
        await session.execute(
            text(f"SELECT {function}(:lock_key)"),
            {"lock_key": lock_key},
        )
    except DBAPIError as error:
        raise_authorization_lock_timeout(error)


async def acquire_rbac_mutation_lock(session: AsyncSession) -> None:
    await acquire_authorization_advisory_lock(session, RBAC_MUTATION_ADVISORY_LOCK)


async def acquire_rbac_authorization_lock(session: AsyncSession) -> None:
    """Take the shared side of the RBAC policy linearization lock.

    Concurrent authorization snapshots remain parallel, while every mutating
    route uses the exclusive form above and therefore wins or loses before the
    snapshot is consumed.
    """

    await acquire_authorization_advisory_lock(
        session,
        RBAC_MUTATION_ADVISORY_LOCK,
        shared=True,
    )


def locked_users_statement(user_ids: set[UUID]) -> Select[tuple[User]]:
    return (
        select(User)
        .where(User.id.in_(user_ids))
        .order_by(User.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def locked_roles_statement(role_ids: set[UUID]) -> Select[tuple[Role]]:
    # NO KEY UPDATE conflicts with role-policy/grant writers but remains
    # compatible with the foreign-key checks performed by UserRole inserts.
    return (
        select(Role)
        .where(Role.id.in_(role_ids))
        .order_by(Role.id)
        .with_for_update(key_share=True)
        .execution_options(populate_existing=True)
    )


async def lock_role_union(
    session: AsyncSession,
    *,
    user_ids: Iterable[UUID],
    additional_role_ids: Iterable[UUID] = (),
) -> dict[UUID, Role]:
    user_id_set = set(user_ids)
    role_ids = set(additional_role_ids)
    if user_id_set:
        role_ids.update(
            (
                await session.scalars(
                    select(UserRole.role_id).where(UserRole.user_id.in_(user_id_set))
                )
            ).all()
        )
    if not role_ids:
        return {}
    roles = list((await session.scalars(locked_roles_statement(role_ids))).all())
    return {role.id: role for role in roles}


def locked_active_actor_roles_statement(user_id: UUID) -> Select[tuple[Role]]:
    now = datetime.now(UTC)
    return (
        select(Role)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(
            UserRole.user_id == user_id,
            or_(UserRole.expires_at.is_(None), UserRole.expires_at > now),
        )
        .order_by(Role.id)
        .with_for_update(of=Role, key_share=True)
    )


async def refresh_locked_actor_access(
    session: AsyncSession,
    actor: User,
    required_permissions: set[str],
) -> AccessContext:
    if actor.status is not UserStatus.ACTIVE or actor.retired_at is not None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    # lock_role_union must run first. Re-locking the active subset here is
    # intentional documentation of the authorization snapshot consumed below.
    list((await session.scalars(locked_active_actor_roles_statement(actor.id))).all())
    current = await AccessService().resolve(session, actor)
    missing = sorted(code for code in required_permissions if not current.allows(code))
    if missing:
        raise ApiError(
            status_code=403,
            code="permission_denied",
            message=f"Permissions required: {', '.join(missing)}",
        )
    return current
