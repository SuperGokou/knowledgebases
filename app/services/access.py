from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    LimitDefinition,
    Permission,
    Role,
    RoleLimit,
    RolePermission,
    User,
    UserLimitOverride,
    UserRole,
)
from app.domain.access import LimitValue, has_permission, resolve_effective_limits


@dataclass(frozen=True, slots=True)
class AccessContext:
    user: User
    permissions: frozenset[str]
    limits: dict[str, LimitValue]
    role_ids: frozenset[UUID]
    max_role_priority: int

    def allows(self, permission: str) -> bool:
        return has_permission(self.permissions, permission)


class AccessService:
    async def resolve(self, session: AsyncSession, user: User) -> AccessContext:
        now = datetime.now(UTC)
        active_assignment = or_(UserRole.expires_at.is_(None), UserRole.expires_at > now)

        permission_rows = await session.scalars(
            select(Permission.code)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .join(UserRole, UserRole.role_id == RolePermission.role_id)
            .where(UserRole.user_id == user.id, active_assignment)
            .distinct()
        )
        permissions = set(permission_rows.all())
        if user.is_superuser:
            permissions.add("*")

        limit_rows = (
            await session.execute(
                select(UserRole.role_id, LimitDefinition.key, RoleLimit.value)
                .join(RoleLimit, RoleLimit.role_id == UserRole.role_id)
                .join(
                    LimitDefinition,
                    LimitDefinition.id == RoleLimit.limit_definition_id,
                )
                .where(UserRole.user_id == user.id, active_assignment)
            )
        ).all()
        by_role: dict[UUID, dict[str, LimitValue]] = defaultdict(dict)
        for role_id, key, value in limit_rows:
            by_role[role_id][key] = value

        override_rows = (
            await session.execute(
                select(LimitDefinition.key, UserLimitOverride.value)
                .join(
                    UserLimitOverride,
                    UserLimitOverride.limit_definition_id == LimitDefinition.id,
                )
                .where(UserLimitOverride.user_id == user.id)
            )
        ).all()
        overrides = {key: value for key, value in override_rows}
        limits = resolve_effective_limits(by_role.values(), overrides)
        role_rows = (
            await session.execute(
                select(Role.id, Role.priority)
                .join(UserRole, UserRole.role_id == Role.id)
                .where(UserRole.user_id == user.id, active_assignment)
            )
        ).all()
        return AccessContext(
            user=user,
            permissions=frozenset(permissions),
            limits=limits,
            role_ids=frozenset(role_id for role_id, _ in role_rows),
            max_role_priority=max(
                (priority for _, priority in role_rows),
                default=-10_001,
            ),
        )
