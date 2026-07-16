from __future__ import annotations

import json
import os
from collections.abc import Callable
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.errors import ApiError
from app.api.v1.routes.knowledge_bases import search_entries
from app.db.models import (
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
    Role,
    User,
    UserRole,
)
from app.schemas.knowledge_bases import KnowledgeSearchRequest
from app.services.access import AccessContext
from scripts.postgres_acceptance import assert_acceptance_database
from scripts.rag_retrieval_evaluation import (
    RagRetrievalObservation,
    RagRetrievalThresholds,
    assert_rag_retrieval_thresholds,
    build_synthetic_rag_dataset,
    evaluate_rag_retrieval,
    require_certifying_retrieval_dialect,
)

_POSTGRES_URL = os.getenv("KB_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not _POSTGRES_URL,
    reason="KB_TEST_POSTGRES_URL is required for certifying RAG retrieval evaluation",
)


def _stable_uuid(value: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"https://eval.heyi.invalid/rag/{value}")


@pytest.mark.asyncio
async def test_postgres_chinese_rag_retrieval_quality_gate(
    record_property: Callable[[str, object], None],
) -> None:
    assert _POSTGRES_URL is not None
    dataset = build_synthetic_rag_dataset()
    engine = create_async_engine(_POSTGRES_URL, pool_size=2, max_overflow=0)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as connection:
            await assert_acceptance_database(connection)
            require_certifying_retrieval_dialect(connection.dialect.name)

        async with factory() as session:
            owner = User(
                id=_stable_uuid("owner"),
                email="rag-eval-owner@example.invalid",
                password_hash="not-a-login-secret",
            )
            outsider = User(
                id=_stable_uuid("outsider"),
                email="rag-eval-outsider@example.invalid",
                password_hash="not-a-login-secret",
            )
            restricted_owner = User(
                id=_stable_uuid("restricted-owner"),
                email="rag-eval-restricted-owner@example.invalid",
                password_hash="not-a-login-secret",
            )
            unrelated_role = Role(
                id=_stable_uuid("unrelated-role"),
                code="rag_eval_unrelated_reader",
                name="RAG evaluation unrelated reader",
                priority=-10_000,
            )
            authorized_kb = KnowledgeBase(
                id=_stable_uuid("authorized-kb"),
                owner_id=owner.id,
                name="中文检索合成验收库",
            )
            restricted_kb = KnowledgeBase(
                id=_stable_uuid("restricted-kb"),
                owner_id=restricted_owner.id,
                name="ACL 隔离合成验收库",
            )
            # Persist principals before resources that reference them.  The model
            # intentionally stores owner_id rather than an ORM object relationship,
            # so relying on same-flush ordering would be dialect/version sensitive.
            unrelated_kb = KnowledgeBase(
                id=_stable_uuid("unrelated-kb"),
                owner_id=owner.id,
                name="无关角色授权验收库",
            )
            session.add_all((owner, outsider, restricted_owner))
            await session.flush()
            session.add(unrelated_role)
            await session.flush()
            session.add_all((authorized_kb, restricted_kb, unrelated_kb))
            await session.flush()
            session.add_all(
                (
                    UserRole(
                        user_id=outsider.id,
                        role_id=unrelated_role.id,
                        assigned_by=owner.id,
                    ),
                    KnowledgeBaseRoleGrant(
                        knowledge_base_id=unrelated_kb.id,
                        role_id=unrelated_role.id,
                        access_level=KnowledgeBaseAccessLevel.READER,
                        granted_by=owner.id,
                    ),
                )
            )
            await session.flush()

            entry_key_by_id: dict[UUID, str] = {}
            for synthetic in dataset.entries:
                entry_id = _stable_uuid(synthetic.key)
                entry_key_by_id[entry_id] = synthetic.key
                session.add(
                    KnowledgeEntry(
                        id=entry_id,
                        knowledge_base_id=(
                            authorized_kb.id
                            if synthetic.scope == "authorized"
                            else restricted_kb.id
                        ),
                        entry_type="SyntheticRetrievalEvaluation",
                        title=synthetic.title,
                        content=synthetic.content,
                        source_path=f"synthetic/{synthetic.key}.md",
                        format_version=dataset.version,
                        publication_status=KnowledgeEntryPublicationStatus.PUBLISHED,
                        custom_metadata={"synthetic": True, "dataset": dataset.version},
                    )
                )
            await session.flush()

            owner_access = AccessContext(
                user=owner,
                permissions=frozenset({"knowledge:read"}),
                limits={},
                role_ids=frozenset(),
                max_role_priority=-10_001,
            )
            outsider_access = AccessContext(
                user=outsider,
                permissions=frozenset({"knowledge:read"}),
                limits={},
                role_ids=frozenset({unrelated_role.id}),
                max_role_priority=unrelated_role.priority,
            )
            observations: list[RagRetrievalObservation] = []
            for case in dataset.cases:
                target_kb = restricted_kb if case.scope == "restricted" else authorized_kb
                access = outsider_access if case.kind == "acl_denied" else owner_access
                try:
                    response = await search_entries(
                        target_kb.id,
                        KnowledgeSearchRequest(query=case.query, limit=5),
                        session,
                        access,
                    )
                except ApiError as error:
                    observations.append(
                        RagRetrievalObservation(
                            case_id=case.case_id,
                            ranked_entry_keys=(),
                            access_concealed=(
                                error.status_code == 404
                                and error.code == "knowledge_base_not_found"
                            ),
                        )
                    )
                else:
                    observations.append(
                        RagRetrievalObservation(
                            case_id=case.case_id,
                            ranked_entry_keys=tuple(
                                entry_key_by_id[item.entry_id] for item in response.items
                            ),
                        )
                    )

            metrics = evaluate_rag_retrieval(dataset, observations)
            thresholds = RagRetrievalThresholds()
            report = {
                "metrics": metrics.as_dict(),
                "thresholds": {
                    "recall_at_5": thresholds.recall_at_5,
                    "mean_reciprocal_rank": thresholds.mean_reciprocal_rank,
                    "ndcg_at_5": thresholds.ndcg_at_5,
                    "no_answer_accuracy": thresholds.no_answer_accuracy,
                    "maximum_acl_leakage_count": thresholds.maximum_acl_leakage_count,
                },
            }
            record_property("rag_retrieval_metrics", json.dumps(report, sort_keys=True))
            for name, value in metrics.as_dict().items():
                record_property(f"rag_{name}", value)
            print("RAG_RETRIEVAL_METRICS=" + json.dumps(report, sort_keys=True))
            assert_rag_retrieval_thresholds(metrics, thresholds)
            await session.rollback()
    finally:
        await engine.dispose()
