from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import DatabaseSession, require_permission
from app.schemas.chat import ChatQueryRequest, ChatQueryResponse
from app.services.access import AccessContext
from app.services.knowledge_bases import (
    require_knowledge_base_access,
    search_knowledge_entries,
)

router = APIRouter()


@router.post("/query", response_model=ChatQueryResponse)
async def query_chat(
    payload: ChatQueryRequest,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("chat:query"))],
) -> ChatQueryResponse:
    # Database ACL is authoritative. Imported frontmatter/custom metadata never grants access.
    await require_knowledge_base_access(session, access, payload.knowledge_base_id)
    citations = await search_knowledge_entries(
        session,
        payload.knowledge_base_id,
        query=payload.message,
        limit=payload.limit,
    )
    if citations:
        evidence = "\n\n".join(
            f"{index}. {item.title}: {item.excerpt}"
            for index, item in enumerate(citations, start=1)
        )
        answer = f"基于当前知识库检索到 {len(citations)} 条相关内容：\n\n{evidence}"
    else:
        answer = "当前知识库中没有检索到足够相关的内容。"
    return ChatQueryResponse(
        knowledge_base_id=payload.knowledge_base_id,
        answer=answer,
        citations=citations,
    )
