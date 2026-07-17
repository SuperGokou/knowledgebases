from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import Select, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import ApiError
from app.db.models import Role, User, UserRole, UserStatus
from app.services.access import AccessContext, AccessService

_RBAC_MUTATION_LOCK_KEY = 5_207_666_715_571_405_123  # ASCII namespace: HEYIRBAC


async def acquire_rbac_mutation_lock(session: AsyncSession) -> None:
    """Serialize infrequent RBAC writes before any user or role row lock."""

    if session.get_bind().dialect.name == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": _RBAC_MUTATION_LOCK_KEY},
        )


def locked_roles_statement(role_ids: set[UUID]) -> Select[tuple[Role]]:
    """Lock referenced roles without blocking compatible foreign-key checks."""

    return select(Role).where(Role.id.in_(role_ids)).with_for_update(key_share=True)


def locked_actor_user_statement(user_id: UUID) -> Select[tuple[User]]:
    return select(User).where(User.id == user_id).with_for_update()


def locked_actor_roles_statement(user_id: UUID) -> Select[tuple[Role]]:
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


async def refresh_locked_actor_access(
    session: AsyncSession,
    actor: User,
    required_permissions: set[str],
) -> AccessContext:
    """Re-resolve authorization while the actor and active roles remain locked."""

    if actor.status is not UserStatus.ACTIVE:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    # Role policy writers take FOR UPDATE on these rows. Holding NO KEY UPDATE
    # guarantees the authorization snapshot cannot change before this mutation
    # commits, while remaining compatible with ordinary FK KEY SHARE checks.
    list((await session.scalars(locked_actor_roles_statement(actor.id))).all())
    current = await AccessService().resolve(session, actor)
    missing = sorted(code for code in required_permissions if not current.allows(code))
    if missing:
        raise ApiError(
            status_code=403,
            code="permission_denied",
            message=f"Permissions required: {', '.join(missing)}",
        )
    return current


async def lock_and_refresh_actor_access(
    session: AsyncSession,
    access: AccessContext,
    required_permissions: set[str],
) -> AccessContext:
    await acquire_rbac_mutation_lock(session)
    actor = await session.scalar(locked_actor_user_statement(access.user.id))
    if actor is None:
        raise ApiError(status_code=401, code="inactive_user", message="The user is not active")
    return await refresh_locked_actor_access(session, actor, required_permissions)
