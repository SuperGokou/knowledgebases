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
    UserStatus,
)
from app.db.session import SessionFactory
from app.services.audit import AuditResult, add_audit_event
from app.services.rbac_mutation import (
    acquire_rbac_mutation_lock,
    lock_role_union,
    locked_users_statement,
)
from app.services.user_activity import ActivityLockMode, acquire_user_activity_locks

PERMISSION_CATALOG: dict[str, tuple[str, str]] = {
    "file:read": ("查看本人文件", "查看本人拥有的文件列表、详情并获取下载链接"),
    "file:read:any": ("查看全部文件", "查看所有用户拥有的文件，不受文件所有者限制"),
    "file:upload": ("上传文件", "创建并完成文件直传任务，将资料加入知识库"),
    "file:approve": ("审核文件", "批准已完成安全扫描或人工复核的文件"),
    "file:approve:any": ("审核未归属文件", "审核尚未绑定到具体知识库的文件"),
    "file:delete": ("删除文件", "从知识库中软删除文件并保留审计记录"),
    "user:manage": ("管理账号", "创建、更新、禁用或恢复后台登录账号"),
    "role:read": ("查看角色", "查看角色列表、权限能力和资源访问限额"),
    "role:manage": ("管理角色", "创建角色并修改允许授权的角色策略"),
    "role:assign": ("分配角色", "为用户分配或调整允许授予的角色"),
    "quota:manage": ("管理资源额度", "管理限额定义以及用户级别的额度覆盖规则"),
    "audit:read": ("查看审计日志", "查看安全事件和后台管理操作的审计记录"),
    "knowledge:create": ("创建知识库", "创建由当前用户负责管理的企业知识库"),
    "knowledge:read": ("查看知识库", "查看已获授权的知识库、条目和相关资料"),
    "knowledge:update": ("编辑知识库", "更新已获授权的知识库设置和知识条目"),
    "knowledge:grant": ("管理知识库授权", "配置角色对知识库的阅读、编辑或管理等级"),
    "chat:query": ("使用知识问答", "在已获授权的知识库中发起带来源引用的问答"),
    "api-key:manage": ("管理 API 密钥", "签发、查看和吊销限定范围的 API 访问密钥"),
    "llm:manage": ("管理大模型配置", "配置并切换系统允许使用的大模型服务商"),
}

LIMIT_CATALOG: dict[str, tuple[str, str, str, str]] = {
    "requests_per_minute": (
        "每分钟请求次数",
        "requests",
        "minute",
        "每个固定分钟窗口内允许调用受保护接口的次数",
    ),
    "max_upload_bytes": (
        "单个文件大小上限",
        "bytes",
        "request",
        "角色级单文件上限；无限制仅表示不设角色额度，仍受平台安全硬上限与恶意软件扫描上限约束",
    ),
    "daily_upload_bytes": (
        "每日上传总量",
        "bytes",
        "day",
        "每个 UTC 自然日可发起上传的文件总字节数",
    ),
    "storage_bytes": (
        "累计存储写入量",
        "bytes",
        "lifetime",
        "生命周期累计：文件成功上传计入全部字节，"
        "手工知识正文仅计入 UTF-8 字节正增长；"
        "同长度替换、缩小及删除均不返还额度。"
        "无限制只取消角色级额度，计量仍继续且受平台硬上限约束",
    ),
    "daily_downloads": (
        "每日下载授权次数",
        "grants",
        "day",
        "每个 UTC 自然日可签发短期文件下载链接的次数",
    ),
    "file_count": (
        "文件数量上限",
        "files",
        "lifetime",
        "角色生命周期内允许创建的文件数量；角色无限制时仍受平台文件数量硬上限约束",
    ),
}


async def seed_database(session: AsyncSession, settings: Settings) -> User:
    bind = session.get_bind()
    if bind.dialect.name == "postgresql":
        # One catalog bootstrap per database, even when multiple startup jobs race.
        await session.execute(text("SELECT pg_advisory_xact_lock(1262836037)"))
    # Bootstrap mutates the same User/UserRole/Role authorization graph as the
    # administrative APIs. Enter their transaction-scoped lock domain before
    # reading any authorization state so a recovery cannot bypass a concurrent
    # CAS-protected role assignment.
    await acquire_rbac_mutation_lock(session)

    email = settings.bootstrap_admin_email.strip().lower()
    user = await session.scalar(select(User).where(User.email == email))
    user_was_created = user is None
    if user is not None:
        await acquire_user_activity_locks(
            session,
            {user.id: ActivityLockMode.EXCLUSIVE},
        )
        user = await session.scalar(locked_users_statement({user.id}))
        if user is None:
            raise RuntimeError("Bootstrap administrator disappeared while acquiring its row lock")
        if not user.is_superuser:
            raise RuntimeError(
                "Refusing to grant superuser to an existing bootstrap email; "
                "use an explicit recovery flow"
            )
        if user.retired_at is not None or user.status is not UserStatus.ACTIVE:
            raise RuntimeError(
                "Refusing to recover an inactive or retired bootstrap administrator; "
                "use an explicit recovery flow or a different bootstrap email"
            )

    catalog_repaired = False
    permissions: dict[str, Permission] = {}
    for code, (name, description) in PERMISSION_CATALOG.items():
        permission = await session.scalar(select(Permission).where(Permission.code == code))
        if permission is None:
            permission = Permission(code=code, name=name, description=description)
            session.add(permission)
            catalog_repaired = True
        else:
            if permission.name != name or permission.description != description:
                catalog_repaired = True
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
            catalog_repaired = True
        else:
            if (
                definition.name != name
                or definition.unit != unit
                or definition.window != window
                or definition.description != description
            ):
                catalog_repaired = True
            definition.name = name
            definition.unit = unit
            definition.window = window
            definition.description = description
        definitions[key] = definition
    await session.flush()

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
        await acquire_user_activity_locks(
            session,
            {user.id: ActivityLockMode.EXCLUSIVE},
        )
    locked_user = await session.scalar(locked_users_statement({user.id}))
    if locked_user is None:
        raise RuntimeError("Bootstrap administrator disappeared while acquiring its row lock")
    user = locked_user
    if not user.is_superuser:
        raise RuntimeError(
            "Refusing to grant superuser to an existing bootstrap email; "
            "use an explicit recovery flow"
        )

    role = await session.scalar(select(Role).where(Role.code == "system_admin"))
    role_was_created = role is None
    if role is None:
        role = Role(
            code="system_admin",
            name="系统管理员",
            description=(
                "拥有全部系统权限，角色额度不设上限；仍受平台安全硬上限、"
                "恶意软件扫描上限及磁盘水位策略约束"
            ),
            priority=10_000,
            is_system=True,
        )
        session.add(role)
        await session.flush()

    locked_roles = await lock_role_union(
        session,
        user_ids={user.id},
        additional_role_ids={role.id},
    )
    locked_role = locked_roles.get(role.id)
    if locked_role is None:
        raise RuntimeError("System administrator role disappeared while acquiring its row lock")
    role = locked_role
    if not role.is_system or role.priority != 10_000:
        raise RuntimeError(
            "Refusing to reuse a non-system or unexpected-priority role named system_admin"
        )
    expected_role_name = "系统管理员"
    expected_role_description = (
        "拥有全部系统权限，角色额度不设上限；仍受平台安全硬上限、恶意软件扫描上限及磁盘水位策略约束"
    )
    role_policy_repaired = bool(
        not role_was_created
        and (
            catalog_repaired
            or role.name != expected_role_name
            or role.description != expected_role_description
        )
    )
    role.name = expected_role_name
    role.description = expected_role_description

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
            if not role_was_created:
                role_policy_repaired = True

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
            if not role_was_created:
                role_policy_repaired = True
        else:
            if existing_limit.value is not None and not role_was_created:
                role_policy_repaired = True
            existing_limit.value = None

    if role_policy_repaired:
        previous_policy_version = role.policy_version
        role.policy_version += 1
        add_audit_event(
            session,
            action="bootstrap.system_admin_policy_restored",
            result=AuditResult.SUCCESS,
            resource_type="role",
            resource_id=str(role.id),
            details={
                "role_code": role.code,
                "from_version": previous_policy_version,
                "to_version": role.policy_version,
            },
        )

    assignment = await session.scalar(
        select(UserRole.id).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
    )
    if assignment is None:
        session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id))
        if not user_was_created:
            previous_role_assignment_version = user.role_assignment_version
            previous_token_version = user.token_version
            user.role_assignment_version += 1
            user.token_version += 1
            add_audit_event(
                session,
                action="bootstrap.system_admin_role_restored",
                result=AuditResult.SUCCESS,
                resource_type="user",
                resource_id=str(user.id),
                details={
                    "role_code": role.code,
                    "role_id": str(role.id),
                    "from_role_assignment_version": previous_role_assignment_version,
                    "to_role_assignment_version": user.role_assignment_version,
                    "from_token_version": previous_token_version,
                    "to_token_version": user.token_version,
                    "password_reset": False,
                },
            )

    await session.commit()
    return user


async def bootstrap() -> None:
    async with SessionFactory() as session:
        user = await seed_database(session, get_settings())
        print(f"Bootstrap complete for administrator: {user.email}")


if __name__ == "__main__":
    asyncio.run(bootstrap())
