from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import ApiError
from app.db.models import ApiKey, KnowledgeBase, User, UserStatus
from app.services.access import AccessContext, AccessService
from app.services.knowledge_bases import require_knowledge_base_access
from app.services.llm_egress_policy import acquire_llm_egress_locks
from app.services.rbac_mutation import acquire_rbac_authorization_lock


@dataclass(frozen=True, slots=True)
class ChatAuthorizationSnapshot:
    knowledge_base_id: UUID
    content_version: int


async def authorize_interactive_chat_snapshot(
    session: AsyncSession,
    *,
    user_id: UUID,
    expected_token_version: int,
    knowledge_base_id: UUID,
) -> ChatAuthorizationSnapshot:
    """Linearize a bearer-token chat decision against every revocation writer."""

    user, current = await _lock_current_access(
        session,
        user_id=user_id,
        expected_token_version=expected_token_version,
    )
    knowledge_base = await _lock_knowledge_base(session, knowledge_base_id)
    await _require_chat_and_knowledge_access(
        session,
        current=current,
        knowledge_base_id=knowledge_base_id,
    )
    await acquire_llm_egress_locks(
        session,
        [
            ("knowledge_base", knowledge_base_id),
            ("user", user.id),
            *(("role", role_id) for role_id in current.role_ids),
        ],
    )
    return ChatAuthorizationSnapshot(
        knowledge_base_id=knowledge_base.id,
        content_version=knowledge_base.content_version,
    )


async def authorize_api_key_chat_snapshot(
    session: AsyncSession,
    *,
    api_key_id: UUID,
    credential_family_id: UUID,
    user_id: UUID,
    knowledge_base_id: UUID,
) -> ChatAuthorizationSnapshot:
    """Linearize an API-key chat decision while preserving rotation lineage."""

    user, current = await _lock_current_access(
        session,
        user_id=user_id,
        expected_token_version=None,
    )
    api_key = await session.scalar(
        select(ApiKey)
        .where(ApiKey.id == api_key_id)
        .with_for_update(read=True)
        .execution_options(populate_existing=True)
    )
    now = datetime.now(UTC)
    if (
        api_key is None
        or api_key.user_id != user.id
        or api_key.credential_family_id != credential_family_id
        or api_key.revoked_at is not None
        or (api_key.expires_at is not None and _as_utc(api_key.expires_at) <= now)
    ):
        raise _invalid_api_key()
    if "chat:query" not in api_key.permission_codes:
        raise ApiError(
            status_code=403,
            code="api_key_scope_denied",
            message="API key permission required: chat:query",
        )
    if str(knowledge_base_id) not in api_key.knowledge_base_ids:
        raise ApiError(
            status_code=404,
            code="knowledge_base_not_found",
            message="Knowledge base not found",
        )

    knowledge_base = await _lock_knowledge_base(session, knowledge_base_id)
    await _require_chat_and_knowledge_access(
        session,
        current=current,
        knowledge_base_id=knowledge_base_id,
    )
    await acquire_llm_egress_locks(
        session,
        [
            ("knowledge_base", knowledge_base_id),
            ("user", user.id),
            ("api_key", api_key.id),
            *(("role", role_id) for role_id in current.role_ids),
        ],
    )
    return ChatAuthorizationSnapshot(
        knowledge_base_id=knowledge_base.id,
        content_version=knowledge_base.content_version,
    )


async def _lock_current_access(
    session: AsyncSession,
    *,
    user_id: UUID,
    expected_token_version: int | None,
) -> tuple[User, AccessContext]:
    # RBAC writers take the exclusive side before their row locks. Readers use
    # the shared side, so concurrent chats remain parallel without a TOCTOU gap.
    await acquire_rbac_authorization_lock(session)
    user = await session.scalar(
        select(User)
        .where(User.id == user_id)
        .with_for_update(read=True)
        .execution_options(populate_existing=True)
    )
    if user is None or user.status is not UserStatus.ACTIVE:
        raise ApiError(
            status_code=401,
            code="inactive_user",
            message="The user is not active",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if expected_token_version is not None and user.token_version != expected_token_version:
        raise ApiError(
            status_code=401,
            code="token_revoked",
            message="The access token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user, await AccessService().resolve(session, user)


async def _lock_knowledge_base(
    session: AsyncSession,
    knowledge_base_id: UUID,
) -> KnowledgeBase:
    knowledge_base = await session.scalar(
        select(KnowledgeBase)
        .where(KnowledgeBase.id == knowledge_base_id)
        .with_for_update(read=True)
        .execution_options(populate_existing=True)
    )
    if knowledge_base is None:
        raise ApiError(
            status_code=404,
            code="knowledge_base_not_found",
            message="Knowledge base not found",
        )
    return knowledge_base


async def _require_chat_and_knowledge_access(
    session: AsyncSession,
    *,
    current: AccessContext,
    knowledge_base_id: UUID,
) -> None:
    if not current.allows("chat:query"):
        raise ApiError(
            status_code=403,
            code="permission_denied",
            message="Permission required: chat:query",
        )
    # The KB row is already held FOR SHARE; refresh=True consumes that same
    # locked identity while resolving current role grants.
    await require_knowledge_base_access(
        session,
        current,
        knowledge_base_id,
        refresh=True,
    )


def _invalid_api_key() -> ApiError:
    return ApiError(
        status_code=401,
        code="invalid_api_key",
        message="The API key is invalid, expired, or revoked",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
