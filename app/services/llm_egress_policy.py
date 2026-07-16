from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import ApiError
from app.db.models import (
    ApiKey,
    KnowledgeBaseAccessLevel,
    User,
    UserRole,
    UserStatus,
)
from app.services.access import AccessService
from app.services.knowledge_bases import require_knowledge_base_access
from app.services.rbac_mutation import acquire_authorization_advisory_lock

_LOCK_NAMESPACE = b"enterprise-kb:external-llm-egress:v1\0"


def llm_egress_lock_key(scope: str, resource_id: UUID) -> int:
    """Map a namespaced authorization dimension to a stable signed PG bigint."""

    digest = hashlib.blake2b(
        _LOCK_NAMESPACE + scope.encode("ascii") + b"\0" + resource_id.bytes,
        digest_size=8,
    ).digest()
    return int.from_bytes(digest, byteorder="big", signed=True)


async def acquire_llm_egress_locks(
    session: AsyncSession,
    scopes: Iterable[tuple[str, UUID]],
) -> None:
    """Acquire deterministic transaction locks; hash collisions fail safely by serialization."""

    keyed_scopes = sorted(
        {
            (llm_egress_lock_key(scope, resource_id), scope, resource_id)
            for scope, resource_id in scopes
        }
    )
    for lock_key, _, _ in keyed_scopes:
        await acquire_authorization_advisory_lock(session, lock_key)


async def external_llm_egress_allowed(
    session: AsyncSession,
    *,
    user_id: UUID,
    knowledge_base_id: UUID,
    api_key_id: UUID | None,
    required_permission: str | None,
    minimum_access: KnowledgeBaseAccessLevel,
) -> bool:
    """Freshly resolve every mutable authorization dimension at the egress boundary."""

    base_scopes = [("knowledge_base", knowledge_base_id), ("user", user_id)]
    if api_key_id is not None:
        base_scopes.append(("api_key", api_key_id))
    try:
        await acquire_llm_egress_locks(session, base_scopes)
        now = datetime.now(UTC)
        role_ids = list(
            (
                await session.scalars(
                    select(UserRole.role_id).where(
                        UserRole.user_id == user_id,
                        or_(UserRole.expires_at.is_(None), UserRole.expires_at > now),
                    )
                )
            ).all()
        )
        await acquire_llm_egress_locks(
            session,
            (("role", role_id) for role_id in role_ids),
        )

        user = await session.scalar(
            select(User).where(User.id == user_id).execution_options(populate_existing=True)
        )
        if user is None or user.status is not UserStatus.ACTIVE or user.retired_at is not None:
            await session.commit()
            return False
        current = await AccessService().resolve(session, user)
        if required_permission is not None and not current.allows(required_permission):
            await session.commit()
            return False

        try:
            kb_access = await require_knowledge_base_access(
                session,
                current,
                knowledge_base_id,
                minimum=minimum_access,
                refresh=True,
            )
        except ApiError:
            await session.commit()
            return False
        if not kb_access.knowledge_base.external_llm_processing_enabled:
            await session.commit()
            return False

        if api_key_id is not None:
            api_key = await session.scalar(
                select(ApiKey)
                .where(ApiKey.id == api_key_id)
                .execution_options(populate_existing=True)
            )
            if (
                api_key is None
                or api_key.user_id != user_id
                or api_key.revoked_at is not None
                or (api_key.expires_at is not None and _as_utc(api_key.expires_at) <= now)
                or required_permission not in api_key.permission_codes
                or str(knowledge_base_id) not in api_key.knowledge_base_ids
            ):
                await session.commit()
                return False
    except Exception:
        await session.rollback()
        raise
    # Transaction-scoped locks end here, before any provider network wait. The
    # already committed HELD record remains the durable egress lease.
    await session.commit()
    return True


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
