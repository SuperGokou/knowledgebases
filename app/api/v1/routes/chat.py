from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import DatabaseSession, require_permission
from app.core.config import Settings, get_settings
from app.schemas.chat import ChatQueryRequest, ChatQueryResponse
from app.services.access import AccessContext
from app.services.chat import answer_knowledge_query

router = APIRouter()


@router.post("/query", response_model=ChatQueryResponse)
async def query_chat(
    payload: ChatQueryRequest,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("chat:query"))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ChatQueryResponse:
    return await answer_knowledge_query(
        session,
        settings,
        access,
        knowledge_base_id=payload.knowledge_base_id,
        message=payload.message,
        limit=payload.limit,
    )
