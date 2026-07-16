from __future__ import annotations

import math
from dataclasses import replace

import pytest

from scripts.rag_retrieval_evaluation import (
    RagRetrievalEvaluationError,
    RagRetrievalObservation,
    RagRetrievalThresholds,
    assert_rag_retrieval_thresholds,
    build_synthetic_rag_dataset,
    evaluate_rag_retrieval,
    rag_retrieval_dataset_fingerprint,
    require_certifying_retrieval_dialect,
)

_EXPECTED_DATASET_FINGERPRINT = "6ccf338e80ea19f7c6a07a471af1678d5260882650951c61db5ba40aa777ba10"


def _perfect_observations() -> list[RagRetrievalObservation]:
    dataset = build_synthetic_rag_dataset()
    return [
        RagRetrievalObservation(
            case_id=case.case_id,
            ranked_entry_keys=case.relevant_entry_keys if case.kind == "answerable" else (),
            access_concealed=case.kind == "acl_denied",
        )
        for case in dataset.cases
    ]


def test_synthetic_chinese_rag_dataset_is_versioned_balanced_and_content_bound() -> None:
    first = build_synthetic_rag_dataset()
    second = build_synthetic_rag_dataset()

    assert first == second
    assert len(first.entries) == 45
    assert len(first.cases) == 120
    assert sum(case.kind == "answerable" for case in first.cases) == 90
    assert sum(case.kind == "no_answer" for case in first.cases) == 15
    assert sum(case.kind == "acl_denied" for case in first.cases) == 15
    assert {case.query for case in first.cases if case.case_id.endswith("-short")} == {
        "合同",
        "报价",
        "权限",
    }
    assert all("本条目是项目自创" in entry.content for entry in first.entries)
    assert rag_retrieval_dataset_fingerprint(first) == _EXPECTED_DATASET_FINGERPRINT


def test_metric_grader_reports_all_release_metrics_and_accepts_a_perfect_run() -> None:
    dataset = build_synthetic_rag_dataset()
    metrics = evaluate_rag_retrieval(dataset, _perfect_observations())

    assert metrics.total_cases == 120
    assert metrics.recall_at_5 == 1.0
    assert metrics.mean_reciprocal_rank == 1.0
    assert metrics.ndcg_at_5 == 1.0
    assert metrics.no_answer_accuracy == 1.0
    assert metrics.acl_leakage_count == 0
    assert_rag_retrieval_thresholds(metrics)


@pytest.mark.parametrize("regression", ["recall", "no_answer", "acl"])
def test_metric_grader_fails_closed_for_quality_or_acl_regressions(regression: str) -> None:
    dataset = build_synthetic_rag_dataset()
    observations = _perfect_observations()
    if regression == "recall":
        answerable_ids = {case.case_id for case in dataset.cases if case.kind == "answerable"}
        observations = [
            replace(observation, ranked_entry_keys=())
            if observation.case_id in set(sorted(answerable_ids)[:10])
            else observation
            for observation in observations
        ]
    elif regression == "no_answer":
        index = next(index for index, case in enumerate(dataset.cases) if case.kind == "no_answer")
        observations[index] = replace(
            observations[index], ranked_entry_keys=(dataset.entries[0].key,)
        )
    else:
        index = next(index for index, case in enumerate(dataset.cases) if case.kind == "acl_denied")
        observations[index] = replace(
            observations[index],
            ranked_entry_keys=dataset.cases[index].relevant_entry_keys,
            access_concealed=False,
        )

    with pytest.raises(RagRetrievalEvaluationError, match="quality gate failed"):
        assert_rag_retrieval_thresholds(evaluate_rag_retrieval(dataset, observations))


def test_metric_grader_rejects_partial_or_duplicate_observation_sets() -> None:
    dataset = build_synthetic_rag_dataset()
    observations = _perfect_observations()

    with pytest.raises(RagRetrievalEvaluationError, match="exact dataset"):
        evaluate_rag_retrieval(dataset, observations[:-1])
    with pytest.raises(RagRetrievalEvaluationError, match="one observation"):
        evaluate_rag_retrieval(dataset, [*observations, observations[0]])


def test_metric_grader_rejects_malformed_datasets_and_ranked_results() -> None:
    dataset = build_synthetic_rag_dataset()
    observations = _perfect_observations()
    answerable_only = replace(
        dataset,
        cases=tuple(case for case in dataset.cases if case.kind == "answerable"),
    )
    with pytest.raises(RagRetrievalEvaluationError, match="answerable, no-answer, and ACL"):
        evaluate_rag_retrieval(answerable_only, observations[:90])

    relevant_key = observations[0].ranked_entry_keys[0]
    repeated = [
        replace(observations[0], ranked_entry_keys=(relevant_key, relevant_key)),
        *observations[1:],
    ]
    with pytest.raises(RagRetrievalEvaluationError, match="cannot repeat"):
        evaluate_rag_retrieval(dataset, repeated)

    unknown = [
        replace(observations[0], ranked_entry_keys=("unknown-entry",)),
        *observations[1:],
    ]
    with pytest.raises(RagRetrievalEvaluationError, match="unknown entry"):
        evaluate_rag_retrieval(dataset, unknown)

    restricted_key = next(entry.key for entry in dataset.entries if entry.scope == "restricted")
    cross_scope = [
        replace(
            observations[0],
            ranked_entry_keys=(*observations[0].ranked_entry_keys, restricted_key),
        ),
        *observations[1:],
    ]
    with pytest.raises(RagRetrievalEvaluationError, match="cannot cross"):
        evaluate_rag_retrieval(dataset, cross_scope)


def test_threshold_assertion_rejects_non_finite_metrics_and_thresholds() -> None:
    metrics = evaluate_rag_retrieval(build_synthetic_rag_dataset(), _perfect_observations())
    with pytest.raises(RagRetrievalEvaluationError, match="recall_at_5=invalid"):
        assert_rag_retrieval_thresholds(replace(metrics, recall_at_5=math.nan))
    with pytest.raises(RagRetrievalEvaluationError, match="invalid.*threshold"):
        assert_rag_retrieval_thresholds(metrics, RagRetrievalThresholds(recall_at_5=math.nan))


def test_sqlite_cannot_certify_the_production_retrieval_gate() -> None:
    require_certifying_retrieval_dialect("postgresql")
    with pytest.raises(RagRetrievalEvaluationError, match="requires.*PostgreSQL"):
        require_certifying_retrieval_dialect("sqlite")
