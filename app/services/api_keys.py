from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import ApiError
from app.db.models import ApiKey, User, UserStatus
from app.services.access import AccessContext, AccessService

API_KEY_PREFIX = "kb_live_"
PUBLIC_API_PERMISSIONS = frozenset({"chat:query", "knowledge:read"})


@dataclass(frozen=True, slots=True)
class ApiKeyAccess:
    api_key: ApiKey
    access: AccessContext
    knowledge_base_ids: frozenset[UUID]

    def allows_knowledge_base(self, knowledge_base_id: UUID) -> bool:
        return knowledge_base_id in self.knowledge_base_ids


def generate_api_key() -> tuple[str, str, str]:
    cleartext = f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"
    return cleartext, api_key_hash(cleartext), cleartext[:20]


def api_key_hash(cleartext: str) -> str:
    return hashlib.sha256(cleartext.encode("utf-8")).hexdigest()


async def authenticate_api_key(
    session: AsyncSession,
    cleartext: str | None,
) -> ApiKeyAccess:
    if (
        cleartext is None
        or not cleartext.startswith(API_KEY_PREFIX)
        or not 40 <= len(cleartext) <= 128
    ):
        raise _invalid_api_key()
    fingerprint = api_key_hash(cleartext)
    api_key = await session.scalar(select(ApiKey).where(ApiKey.key_hash == fingerprint))
    if api_key is None or not hmac.compare_digest(api_key.key_hash, fingerprint):
        raise _invalid_api_key()

    now = datetime.now(UTC)
    if api_key.revoked_at is not None or (
        api_key.expires_at is not None and _as_utc(api_key.expires_at) <= now
    ):
        raise _invalid_api_key()
    user = await session.get(User, api_key.user_id)
    if user is None or user.status is not UserStatus.ACTIVE:
        raise _invalid_api_key()

    current = await AccessService().resolve(session, user)
    scoped_permissions = frozenset(
        permission
        for permission in api_key.permission_codes
        if permission in PUBLIC_API_PERMISSIONS and current.allows(permission)
    )
    scoped_access = AccessContext(
        user=current.user,
        permissions=scoped_permissions,
        limits=current.limits,
        role_ids=current.role_ids,
        max_role_priority=current.max_role_priority,
    )
    try:
        knowledge_base_ids = frozenset(UUID(value) for value in api_key.knowledge_base_ids)
    except (TypeError, ValueError) as error:
        raise _invalid_api_key() from error

    # Keep administrative visibility useful without turning every API call into a DB write.
    if api_key.last_used_at is None or _as_utc(api_key.last_used_at) < now - timedelta(minutes=1):
        api_key.last_used_at = now
        await session.commit()
    return ApiKeyAccess(
        api_key=api_key,
        access=scoped_access,
        knowledge_base_ids=knowledge_base_ids,
    )


def _invalid_api_key() -> ApiError:
    return ApiError(
        status_code=401,
        code="invalid_api_key",
        message="The API key is invalid, expired, or revoked",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
