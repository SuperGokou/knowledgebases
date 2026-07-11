from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import case, exists, false, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import ApiError
from app.db.models import (
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
)
from app.schemas.knowledge_bases import KnowledgeSearchHit
from app.services.access import AccessContext

_ACCESS_RANK = {
    KnowledgeBaseAccessLevel.READER: 10,
    KnowledgeBaseAccessLevel.EDITOR: 20,
    KnowledgeBaseAccessLevel.MANAGER: 30,
}


@dataclass(frozen=True, slots=True)
class KnowledgeBaseAccess:
    knowledge_base: KnowledgeBase
    level: KnowledgeBaseAccessLevel


def _highest_level(levels: list[KnowledgeBaseAccessLevel]) -> KnowledgeBaseAccessLevel | None:
    if not levels:
        return None
    return max(levels, key=_ACCESS_RANK.__getitem__)


async def require_knowledge_base_access(
    session: AsyncSession,
    access: AccessContext,
    knowledge_base_id: UUID,
    *,
    minimum: KnowledgeBaseAccessLevel = KnowledgeBaseAccessLevel.READER,
    lock: bool = False,
) -> KnowledgeBaseAccess:
    statement = select(KnowledgeBase).where(KnowledgeBase.id == knowledge_base_id)
    if lock:
        statement = statement.with_for_update()
    knowledge_base = await session.scalar(statement)
    if knowledge_base is None:
        raise ApiError(
            status_code=404,
            code="knowledge_base_not_found",
            message="Knowledge base not found",
        )

    resolved_level: KnowledgeBaseAccessLevel | None
    if access.user.is_superuser or knowledge_base.owner_id == access.user.id:
        resolved_level = KnowledgeBaseAccessLevel.MANAGER
    elif access.role_ids:
        rows = list(
            (
                await session.scalars(
                    select(KnowledgeBaseRoleGrant.access_level).where(
                        KnowledgeBaseRoleGrant.knowledge_base_id == knowledge_base_id,
                        KnowledgeBaseRoleGrant.role_id.in_(access.role_ids),
                    )
                )
            ).all()
        )
        resolved_level = _highest_level(rows)
        if resolved_level is None:
            raise ApiError(
                status_code=404,
                code="knowledge_base_not_found",
                message="Knowledge base not found",
            )
    else:
        raise ApiError(
            status_code=404,
            code="knowledge_base_not_found",
            message="Knowledge base not found",
        )

    level = resolved_level
    if _ACCESS_RANK[level] < _ACCESS_RANK[minimum]:
        raise ApiError(
            status_code=403,
            code="knowledge_base_access_denied",
            message=f"Knowledge base access level required: {minimum.value}",
        )
    return KnowledgeBaseAccess(knowledge_base=knowledge_base, level=level)


async def list_accessible_knowledge_bases(
    session: AsyncSession,
    access: AccessContext,
    *,
    limit: int,
    offset: int,
) -> list[KnowledgeBaseAccess]:
    statement = select(KnowledgeBase)
    if not access.user.is_superuser:
        role_access = (
            exists()
            .where(KnowledgeBaseRoleGrant.knowledge_base_id == KnowledgeBase.id)
            .where(KnowledgeBaseRoleGrant.role_id.in_(access.role_ids))
            if access.role_ids
            else false()
        )
        statement = statement.where(
            or_(KnowledgeBase.owner_id == access.user.id, role_access)
        )
    statement = (
        statement.order_by(KnowledgeBase.updated_at.desc(), KnowledgeBase.id)
        .limit(limit)
        .offset(offset)
    )
    knowledge_bases = list((await session.scalars(statement)).all())
    if not knowledge_bases:
        return []

    levels: dict[UUID, list[KnowledgeBaseAccessLevel]] = {}
    if access.role_ids:
        rows = (
            await session.execute(
                select(
                    KnowledgeBaseRoleGrant.knowledge_base_id,
                    KnowledgeBaseRoleGrant.access_level,
                ).where(
                    KnowledgeBaseRoleGrant.knowledge_base_id.in_(
                        item.id for item in knowledge_bases
                    ),
                    KnowledgeBaseRoleGrant.role_id.in_(access.role_ids),
                )
            )
        ).all()
        for knowledge_base_id, level in rows:
            levels.setdefault(knowledge_base_id, []).append(level)

    result: list[KnowledgeBaseAccess] = []
    for knowledge_base in knowledge_bases:
        if access.user.is_superuser or knowledge_base.owner_id == access.user.id:
            level = KnowledgeBaseAccessLevel.MANAGER
        else:
            level = _highest_level(levels.get(knowledge_base.id, []))
            if level is None:
                continue
        result.append(KnowledgeBaseAccess(knowledge_base=knowledge_base, level=level))
    return result


def _query_terms(query: str) -> list[str]:
    terms: list[str] = []
    for item in re.findall(r"[\w-]+", query, flags=re.UNICODE):
        cjk_sequences = re.findall(r"[\u3400-\u4dbf\u4e00-\u9fff]+", item)
        for sequence in cjk_sequences:
            if len(sequence) <= 2:
                terms.append(sequence)
            else:
                # PostgreSQL ILIKE does not tokenize Chinese. Overlapping bigrams
                # keep ordinary Chinese questions searchable without requiring an
                # external tokenizer in the phase-one retrieval path.
                terms.extend(sequence[index : index + 2] for index in range(len(sequence) - 1))
        non_cjk = re.sub(r"[\u3400-\u4dbf\u4e00-\u9fff]+", " ", item)
        terms.extend(
            token.casefold()
            for token in re.findall(r"[a-zA-Z0-9_-]+", non_cjk)
        )
    if not terms:
        return [query.casefold()]
    meaningful = [
        item
        for item in terms
        if len(item) >= 3 or bool(re.search(r"[\u3400-\u4dbf\u4e00-\u9fff]", item))
    ]
    return list(dict.fromkeys(meaningful or terms))[:12]


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _excerpt(content: str, terms: list[str], *, maximum: int = 280) -> str:
    lowered = content.casefold()
    positions = [lowered.find(term) for term in terms]
    matches = [position for position in positions if position >= 0]
    start = max(0, min(matches, default=0) - 80)
    excerpt = content[start : start + maximum].strip()
    if start:
        excerpt = f"…{excerpt}"
    if start + maximum < len(content):
        excerpt = f"{excerpt}…"
    return excerpt


async def search_knowledge_entries(
    session: AsyncSession,
    knowledge_base_id: UUID,
    *,
    query: str,
    limit: int,
) -> list[KnowledgeSearchHit]:
    terms = _query_terms(query)
    predicates = []
    for term in terms:
        pattern = f"%{_escape_like(term)}%"
        predicates.extend(
            [
                KnowledgeEntry.title.ilike(pattern, escape="\\"),
                KnowledgeEntry.content.ilike(pattern, escape="\\"),
            ]
        )
    bind = session.get_bind()
    if bind.dialect.name == "postgresql":
        primary_term = terms[0]
        match_position = func.strpos(func.lower(KnowledgeEntry.content), primary_term)
        excerpt_start = case((match_position > 80, match_position - 80), else_=1)
        excerpt_expression: Any = func.substr(
            KnowledgeEntry.content, excerpt_start, 280
        )
    else:
        # SQLite is limited to the integration-test harness. Production PostgreSQL
        # projects a bounded snippet so multi-megabyte bodies never cross the wire.
        excerpt_expression = KnowledgeEntry.content

    statement = select(
        KnowledgeEntry.id,
        KnowledgeEntry.source_file_id,
        KnowledgeEntry.title,
        excerpt_expression.label("excerpt"),
        KnowledgeEntry.source_path,
        KnowledgeEntry.format_version,
    ).where(
        KnowledgeEntry.knowledge_base_id == knowledge_base_id,
        KnowledgeEntry.deleted_at.is_(None),
        KnowledgeEntry.publication_status == KnowledgeEntryPublicationStatus.PUBLISHED,
        or_(*predicates),
    )
    statement = statement.order_by(KnowledgeEntry.updated_at.desc(), KnowledgeEntry.id).limit(limit)
    entries = (await session.execute(statement)).mappings().all()
    return [
        KnowledgeSearchHit(
            entry_id=entry["id"],
            source_file_id=entry["source_file_id"],
            title=entry["title"],
            excerpt=(
                entry["excerpt"].strip()
                if bind.dialect.name == "postgresql"
                else _excerpt(entry["excerpt"], terms)
            ),
            source_path=entry["source_path"],
            format_version=entry["format_version"],
        )
        for entry in entries
    ]
