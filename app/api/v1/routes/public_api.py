from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request

from app.api.dependencies import DatabaseSession, require_api_key_permission
from app.api.errors import ApiError
from app.api.idempotency import require_chat_idempotency_key
from app.core.config import Settings, get_settings
from app.schemas.chat import ChatQueryRequest, ChatQueryResponse
from app.schemas.knowledge_bases import KnowledgeSearchRequest, KnowledgeSearchResponse
from app.services.api_keys import ApiKeyAccess
from app.services.chat import answer_knowledge_query
from app.services.chat_idempotency import (
    ChatIdempotencyPrincipal,
    execute_chat_query_idempotently,
)
from app.services.chat_replay_authorization import authorize_api_key_chat_snapshot
from app.services.chat_timeout import run_chat_with_budget
from app.services.knowledge_bases import require_knowledge_base_access, search_knowledge_entries

router = APIRouter()


@router.post("/chat/query", response_model=ChatQueryResponse)
async def query_chat_with_api_key(
    request: Request,
    payload: ChatQueryRequest,
    session: DatabaseSession,
    key_access: Annotated[ApiKeyAccess, Depends(require_api_key_permission("chat:query"))],
    settings: Annotated[Settings, Depends(get_settings)],
    idempotency_key: Annotated[str, Depends(require_chat_idempotency_key)],
) -> ChatQueryResponse:
    _require_key_knowledge_scope(key_access, payload.knowledge_base_id)
    # Re-authorize before any replay so key/user/role revocation remains immediate.
    await require_knowledge_base_access(
        session,
        key_access.access,
        payload.knowledge_base_id,
    )
    return await run_chat_with_budget(
        lambda: execute_chat_query_idempotently(
            session,
            settings,
            principal=ChatIdempotencyPrincipal.for_api_key(key_access.api_key.credential_family_id),
            idempotency_key=idempotency_key,
            request=payload,
            authorize=lambda ledger_session: authorize_api_key_chat_snapshot(
                ledger_session,
                api_key_id=key_access.api_key.id,
                credential_family_id=key_access.api_key.credential_family_id,
                user_id=key_access.api_key.user_id,
                knowledge_base_id=payload.knowledge_base_id,
            ),
            operation=lambda: answer_knowledge_query(
                session,
                settings,
                key_access.access,
                knowledge_base_id=payload.knowledge_base_id,
                message=payload.message,
                limit=payload.limit,
                idempotency_key=idempotency_key,
                api_key_id=key_access.api_key.id,
                api_key_credential_family_id=key_access.api_key.credential_family_id,
            ),
        ),
        is_disconnected=request.is_disconnected,
    )


@router.post(
    "/knowledge-bases/{knowledge_base_id}/search",
    response_model=KnowledgeSearchResponse,
)
async def search_with_api_key(
    knowledge_base_id: UUID,
    payload: KnowledgeSearchRequest,
    session: DatabaseSession,
    key_access: Annotated[ApiKeyAccess, Depends(require_api_key_permission("knowledge:read"))],
) -> KnowledgeSearchResponse:
    _require_key_knowledge_scope(key_access, knowledge_base_id)
    await require_knowledge_base_access(session, key_access.access, knowledge_base_id)
    items = await search_knowledge_entries(
        session, knowledge_base_id, query=payload.query, limit=payload.limit
    )
    return KnowledgeSearchResponse(
        query=payload.query,
        items=items,
        mode="retrieval",
    )


def _require_key_knowledge_scope(key_access: ApiKeyAccess, knowledge_base_id: UUID) -> None:
    if not key_access.allows_knowledge_base(knowledge_base_id):
        # Deliberately conceal whether an unscoped knowledge base exists.
        raise ApiError(
            status_code=404,
            code="knowledge_base_not_found",
            message="Knowledge base not found",
        )
