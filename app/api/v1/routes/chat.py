from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.api.dependencies import DatabaseSession, require_permission
from app.api.idempotency import require_chat_idempotency_key
from app.core.config import Settings, get_settings
from app.schemas.chat import ChatQueryRequest, ChatQueryResponse
from app.services.access import AccessContext
from app.services.chat import answer_knowledge_query
from app.services.chat_idempotency import (
    ChatIdempotencyPrincipal,
    execute_chat_query_idempotently,
)
from app.services.chat_replay_authorization import authorize_interactive_chat_snapshot
from app.services.chat_timeout import run_chat_with_budget
from app.services.knowledge_bases import require_knowledge_base_access

router = APIRouter()


@router.post("/query", response_model=ChatQueryResponse)
async def query_chat(
    request: Request,
    payload: ChatQueryRequest,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("chat:query"))],
    settings: Annotated[Settings, Depends(get_settings)],
    idempotency_key: Annotated[str, Depends(require_chat_idempotency_key)],
) -> ChatQueryResponse:
    # Re-authorize before any replay so a revoked principal cannot recover an old answer.
    await require_knowledge_base_access(session, access, payload.knowledge_base_id)
    return await run_chat_with_budget(
        lambda: execute_chat_query_idempotently(
            session,
            settings,
            principal=ChatIdempotencyPrincipal.for_user(access.user.id),
            idempotency_key=idempotency_key,
            request=payload,
            authorize=lambda ledger_session: authorize_interactive_chat_snapshot(
                ledger_session,
                user_id=access.user.id,
                expected_token_version=access.user.token_version,
                knowledge_base_id=payload.knowledge_base_id,
            ),
            operation=lambda: answer_knowledge_query(
                session,
                settings,
                access,
                knowledge_base_id=payload.knowledge_base_id,
                message=payload.message,
                limit=payload.limit,
                idempotency_key=idempotency_key,
                api_key_id=None,
            ),
        ),
        is_disconnected=request.is_disconnected,
    )
