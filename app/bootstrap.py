from __future__ import annotations

import asyncio

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
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
)
from app.db.session import SessionFactory

PERMISSION_CATALOG: dict[str, tuple[str, str]] = {
    "file:read": ("Read own files", "List, inspect, and download files owned by the user"),
    "file:read:any": ("Read all files", "Read files owned by any user"),
    "file:upload": ("Upload files", "Create and complete direct-upload sessions"),
    "file:approve": ("Approve files", "Approve a scanned or manually reviewed file"),
    "file:delete": ("Delete files", "Soft-delete knowledge-base files"),
    "user:manage": ("Manage users", "Create, disable, and update users"),
    "role:read": ("Read roles", "View roles, permissions, and limits"),
    "role:manage": ("Manage roles", "Create and update grantable roles"),
    "role:assign": ("Assign roles", "Assign grantable roles to users"),
    "quota:manage": ("Manage quotas", "Manage limit definitions and overrides"),
    "audit:read": ("Read audit log", "Read security and administration audit events"),
}

LIMIT_CATALOG: dict[str, tuple[str, str, str, str]] = {
    "requests_per_minute": (
        "Requests per minute",
        "requests",
        "minute",
        "Distributed API rate limit",
    ),
    "max_upload_bytes": (
        "Maximum object size",
        "bytes",
        "request",
        "Maximum declared size of one uploaded object",
    ),
    "daily_upload_bytes": (
        "Daily uploaded bytes",
        "bytes",
        "day",
        "Total bytes that can be initiated per UTC day",
    ),
    "storage_bytes": (
        "Stored bytes",
        "bytes",
        "lifetime",
        "Total persistent object storage allowance",
    ),
    "daily_downloads": (
        "Daily download grants",
        "grants",
        "day",
        "Number of short-lived download grants issued per UTC day",
    ),
}


async def seed_database(session: AsyncSession, settings: Settings) -> User:
    bind = session.get_bind()
    if bind.dialect.name == "postgresql":
        # One catalog bootstrap per database, even when multiple startup jobs race.
        await session.execute(text("SELECT pg_advisory_xact_lock(1262836037)"))

    permissions: dict[str, Permission] = {}
    for code, (name, description) in PERMISSION_CATALOG.items():
        permission = await session.scalar(select(Permission).where(Permission.code == code))
        if permission is None:
            permission = Permission(code=code, name=name, description=description)
            session.add(permission)
        else:
            permission.name = name
            permission.description = description
        permissions[code] = permission

    definitions: dict[str, LimitDefinition] = {}
    for key, (name, unit, window, description) in LIMIT_CATALOG.items():
        definition = await session.scalar(select(LimitDefinition).where(LimitDefinition.key == key))
        if definition is None:
            definition = LimitDefinition(
                key=key,
                name=name,
                unit=unit,
                window=window,
                description=description,
            )
            session.add(definition)
        else:
            definition.name = name
            definition.unit = unit
            definition.window = window
            definition.description = description
        definitions[key] = definition
    await session.flush()

    role = await session.scalar(select(Role).where(Role.code == "system_admin"))
    if role is None:
        role = Role(
            code="system_admin",
            name="System Administrator",
            description="Bootstrap role with every catalog permission and unlimited quotas",
            priority=10_000,
            is_system=True,
        )
        session.add(role)
        await session.flush()
    elif not role.is_system or role.priority != 10_000:
        raise RuntimeError(
            "Refusing to reuse a non-system or unexpected-priority role named system_admin"
        )

    existing_permission_ids = set(
        (
            await session.scalars(
                select(RolePermission.permission_id).where(RolePermission.role_id == role.id)
            )
        ).all()
    )
    for permission in permissions.values():
        if permission.id not in existing_permission_ids:
            session.add(RolePermission(role_id=role.id, permission_id=permission.id))

    existing_limits = {
        item.limit_definition_id: item
        for item in (
            await session.scalars(select(RoleLimit).where(RoleLimit.role_id == role.id))
        ).all()
    }
    for definition in definitions.values():
        existing_limit = existing_limits.get(definition.id)
        if existing_limit is None:
            session.add(
                RoleLimit(
                    role_id=role.id,
                    limit_definition_id=definition.id,
                    value=None,
                )
            )
        else:
            existing_limit.value = None

    email = settings.bootstrap_admin_email.strip().lower()
    user = await session.scalar(select(User).where(User.email == email))
    if user is None:
        if settings.bootstrap_admin_password is None:
            raise RuntimeError("KB_BOOTSTRAP_ADMIN_PASSWORD is required for the first bootstrap")
        password_hash = await hash_password(
            PasswordService(),
            settings.bootstrap_admin_password.get_secret_value(),
        )
        user = User(
            email=email,
            display_name="System Administrator",
            password_hash=password_hash,
            is_superuser=True,
        )
        session.add(user)
        await session.flush()
    elif not user.is_superuser:
        raise RuntimeError(
            "Refusing to grant superuser to an existing bootstrap email; "
            "use an explicit recovery flow"
        )

    assignment = await session.scalar(
        select(UserRole.id).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
    )
    if assignment is None:
        session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id))

    await session.commit()
    return user


async def bootstrap() -> None:
    async with SessionFactory() as session:
        user = await seed_database(session, get_settings())
        print(f"Bootstrap complete for administrator: {user.email}")


if __name__ == "__main__":
    asyncio.run(bootstrap())
