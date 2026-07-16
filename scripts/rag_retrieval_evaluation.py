from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Literal

RAG_RETRIEVAL_DATASET_VERSION = "heyi-synthetic-zh-rag-v1"
RAG_RETRIEVAL_CERTIFYING_DIALECT = "postgresql"

CaseKind = Literal["answerable", "no_answer", "acl_denied"]
KnowledgeScope = Literal["authorized", "restricted"]


class RagRetrievalEvaluationError(RuntimeError):
    """Raised when the evaluation contract cannot produce trustworthy evidence."""


@dataclass(frozen=True, slots=True)
class SyntheticKnowledgeEntry:
    key: str
    scope: KnowledgeScope
    title: str
    content: str


@dataclass(frozen=True, slots=True)
class RagRetrievalCase:
    case_id: str
    kind: CaseKind
    scope: KnowledgeScope
    query: str
    relevant_entry_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RagRetrievalDataset:
    version: str
    entries: tuple[SyntheticKnowledgeEntry, ...]
    cases: tuple[RagRetrievalCase, ...]


@dataclass(frozen=True, slots=True)
class RagRetrievalObservation:
    case_id: str
    ranked_entry_keys: tuple[str, ...]
    access_concealed: bool = False


@dataclass(frozen=True, slots=True)
class RagRetrievalThresholds:
    recall_at_5: float = 0.95
    mean_reciprocal_rank: float = 0.90
    ndcg_at_5: float = 0.90
    no_answer_accuracy: float = 0.95
    maximum_acl_leakage_count: int = 0


@dataclass(frozen=True, slots=True)
class RagRetrievalMetrics:
    dataset_version: str
    dataset_fingerprint: str
    total_cases: int
    answerable_cases: int
    no_answer_cases: int
    acl_cases: int
    recall_at_5: float
    mean_reciprocal_rank: float
    ndcg_at_5: float
    no_answer_accuracy: float
    acl_leakage_count: int

    def as_dict(self) -> dict[str, str | int | float]:
        return asdict(self)


_AUTHORIZED_WORKSHOPS = (
    "星澜一号车间",
    "云衡二号车间",
    "澄曜三号车间",
    "青岚四号车间",
    "琥珀五号车间",
    "霁川六号车间",
    "银栖七号车间",
    "墨泉八号车间",
    "绯霞九号车间",
    "松影十号车间",
    "砚海十一号车间",
    "岑光十二号车间",
    "竹屿十三号车间",
    "砂庭十四号车间",
    "月汀十五号车间",
    "镜湖十六号车间",
    "雁序十七号车间",
    "稻风十八号车间",
    "青穹十九号车间",
    "珊瑚二十号车间",
    "杉野二十一号车间",
    "晨汐二十二号车间",
    "暮岭二十三号车间",
    "雪浦二十四号车间",
    "铜雀二十五号车间",
    "白榆二十六号车间",
    "蓝桥二十七号车间",
    "紫陌二十八号车间",
    "碧湾二十九号车间",
    "金禾三十号车间",
)

_AUTHORIZED_PROCESSES = (
    "雾银贴合",
    "澄光校准",
    "青墨点检",
    "琉璃封装",
    "霜桥复核",
    "松针清洁",
    "砚池对位",
    "云帆固化",
    "星砂抽检",
    "竹露预热",
    "月轮压合",
    "岚谷分选",
    "银沙烘烤",
    "青瓦复测",
    "晨露覆膜",
    "暮云巡检",
    "雪松装配",
    "珊瑚老化",
    "金桂终检",
    "白鹭包装",
    "松涛备料",
    "碧水清洗",
    "铜铃定位",
    "紫藤量测",
    "蓝鲸转运",
    "稻香复判",
    "雁影入库",
    "镜面除尘",
    "砂砾筛查",
    "琥光放行",
)

_SHORT_QUERY_LABELS = ("合同", "报价", "权限")

_NO_ANSWER_QUERIES = (
    "远洋鲸歌计划的潮汐坐标在哪里？",
    "月面温室的藻类光谱颜色是什么？",
    "北极浮岛的驯鹿迁徙航线如何编号？",
    "深海珊瑚邮局的潜水邮票面值是多少？",
    "沙漠星图馆的陨石借阅期限有多长？",
    "高山云雀站的候鸟鸣声频率是多少？",
    "极夜灯塔的冰川测绘坐标如何登记？",
    "海底花园的潮汐风铃何时开放？",
    "云端蜂场的蜂蜜气象指数怎样计算？",
    "火星茶园的低重力灌溉周期是多少？",
    "鲸背图书馆的海浪目录由谁维护？",
    "森林天文台的萤火观测季节是哪月？",
    "冰原邮递站的雪橇路线经过哪些岛屿？",
    "浮空果园的气囊采摘规范是什么？",
    "珊瑚列车的海沟停靠时刻如何查询？",
)

_RESTRICTED_TOPICS = (
    "玄鹤配方",
    "赤砂参数",
    "苍松报价",
    "墨鲸样机",
    "银杏密钥",
    "紫檀协议",
    "青鸾图纸",
    "白鹿批次",
    "金雀合同",
    "蓝杉审计",
    "雪豹策略",
    "琥珀样本",
    "云狐计划",
    "松鹤底稿",
    "海棠清单",
)


def build_synthetic_rag_dataset() -> RagRetrievalDataset:
    """Build a deterministic, project-authored corpus with no external source text."""

    entries: list[SyntheticKnowledgeEntry] = []
    cases: list[RagRetrievalCase] = []
    for index, (workshop, process) in enumerate(
        zip(_AUTHORIZED_WORKSHOPS, _AUTHORIZED_PROCESSES, strict=True), start=1
    ):
        key = f"authorized-{index:02d}"
        device_code = f"HX-EVAL-{100 + index:03d}"
        owner = f"合成值班员{index:02d}"
        response_minutes = 7 + index
        short_query = _SHORT_QUERY_LABELS[index - 1] if index <= len(_SHORT_QUERY_LABELS) else None
        short_query_fact = f"短词检索标签为{short_query}。" if short_query else ""
        entries.append(
            SyntheticKnowledgeEntry(
                key=key,
                scope="authorized",
                title=f"{workshop}{process}作业卡",
                content=(
                    f"本条目是项目自创的检索评测资料。作业区域为{workshop}，流程名称为"
                    f"{process}工序，责任人为{owner}，响应时限为{response_minutes}分钟，"
                    f"专用设备编号为{device_code}。{short_query_fact}"
                    "资料仅用于自动化质量验证。"
                ),
            )
        )
        cases.extend(
            (
                RagRetrievalCase(
                    case_id=f"answerable-{index:02d}-owner",
                    kind="answerable",
                    scope="authorized",
                    query=f"{workshop}的{process}工序由哪位责任人负责？",
                    relevant_entry_keys=(key,),
                ),
                RagRetrievalCase(
                    case_id=f"answerable-{index:02d}-response",
                    kind="answerable",
                    scope="authorized",
                    query=f"请查询{workshop}{process}工序的响应时限。",
                    relevant_entry_keys=(key,),
                ),
                RagRetrievalCase(
                    case_id=(
                        f"answerable-{index:02d}-short"
                        if short_query
                        else f"answerable-{index:02d}-device"
                    ),
                    kind="answerable",
                    scope="authorized",
                    query=(
                        short_query
                        if short_query
                        else f"{process}工序在{workshop}使用的专用设备编号是什么？"
                    ),
                    relevant_entry_keys=(key,),
                ),
            )
        )

    for index, query in enumerate(_NO_ANSWER_QUERIES, start=1):
        cases.append(
            RagRetrievalCase(
                case_id=f"no-answer-{index:02d}",
                kind="no_answer",
                scope="authorized",
                query=query,
                relevant_entry_keys=(),
            )
        )

    for index, topic in enumerate(_RESTRICTED_TOPICS, start=1):
        key = f"restricted-{index:02d}"
        entries.append(
            SyntheticKnowledgeEntry(
                key=key,
                scope="restricted",
                title=f"{topic}隔离资料",
                content=(
                    f"本条目是项目自创的 ACL 隔离评测资料。受限主题为{topic}，"
                    f"隔离代号为ACL-EVAL-{index:03d}，未授权主体不得检索。"
                ),
            )
        )
        cases.append(
            RagRetrievalCase(
                case_id=f"acl-denied-{index:02d}",
                kind="acl_denied",
                scope="restricted",
                query=f"请检索{topic}的隔离代号。",
                relevant_entry_keys=(key,),
            )
        )

    dataset = RagRetrievalDataset(
        version=RAG_RETRIEVAL_DATASET_VERSION,
        entries=tuple(entries),
        cases=tuple(cases),
    )
    validate_rag_retrieval_dataset(dataset)
    return dataset


def validate_rag_retrieval_dataset(dataset: RagRetrievalDataset) -> None:
    if not dataset.version.strip() or not dataset.entries or not dataset.cases:
        raise RagRetrievalEvaluationError("evaluation dataset must be non-empty and versioned")
    entry_keys = [entry.key for entry in dataset.entries]
    case_ids = [case.case_id for case in dataset.cases]
    queries = [case.query for case in dataset.cases]
    if len(entry_keys) != len(set(entry_keys)):
        raise RagRetrievalEvaluationError("synthetic entry keys must be unique")
    if len(case_ids) != len(set(case_ids)) or len(queries) != len(set(queries)):
        raise RagRetrievalEvaluationError("evaluation case ids and queries must be unique")
    case_kinds = {case.kind for case in dataset.cases}
    if case_kinds != {"answerable", "no_answer", "acl_denied"}:
        raise RagRetrievalEvaluationError(
            "evaluation dataset must contain answerable, no-answer, and ACL cases"
        )
    known_entries = {entry.key: entry for entry in dataset.entries}
    for case in dataset.cases:
        if not case.query.strip():
            raise RagRetrievalEvaluationError("evaluation queries cannot be blank")
        if case.kind == "no_answer" and case.relevant_entry_keys:
            raise RagRetrievalEvaluationError("no-answer cases cannot declare relevant entries")
        if case.kind != "no_answer" and not case.relevant_entry_keys:
            raise RagRetrievalEvaluationError("answerable and ACL cases require relevant entries")
        for key in case.relevant_entry_keys:
            entry = known_entries.get(key)
            if entry is None or entry.scope != case.scope:
                raise RagRetrievalEvaluationError("case relevance must reference its own scope")


def rag_retrieval_dataset_fingerprint(dataset: RagRetrievalDataset) -> str:
    payload = json.dumps(
        asdict(dataset), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def require_certifying_retrieval_dialect(dialect_name: str) -> None:
    if dialect_name != RAG_RETRIEVAL_CERTIFYING_DIALECT:
        raise RagRetrievalEvaluationError(
            "formal RAG retrieval evidence requires the production PostgreSQL dialect"
        )


def _dcg(relevant: frozenset[str], ranked: Sequence[str], *, k: int) -> float:
    return sum(
        1.0 / math.log2(rank + 1) for rank, key in enumerate(ranked[:k], start=1) if key in relevant
    )


def evaluate_rag_retrieval(
    dataset: RagRetrievalDataset,
    observations: Sequence[RagRetrievalObservation],
    *,
    k: int = 5,
) -> RagRetrievalMetrics:
    if k != 5:
        raise RagRetrievalEvaluationError("the release gate is fixed to rank cutoff 5")
    validate_rag_retrieval_dataset(dataset)
    observed = {observation.case_id: observation for observation in observations}
    if len(observed) != len(observations):
        raise RagRetrievalEvaluationError("each evaluation case must have one observation")
    expected_ids = {case.case_id for case in dataset.cases}
    if set(observed) != expected_ids:
        raise RagRetrievalEvaluationError("evaluation observations do not cover the exact dataset")
    entry_scope_by_key = {entry.key: entry.scope for entry in dataset.entries}
    case_by_id = {case.case_id: case for case in dataset.cases}
    for observation in observations:
        ranked = observation.ranked_entry_keys
        if len(ranked) != len(set(ranked)):
            raise RagRetrievalEvaluationError("ranked observations cannot repeat an entry")
        if not set(ranked).issubset(entry_scope_by_key):
            raise RagRetrievalEvaluationError("ranked observations reference an unknown entry")
        expected_scope = case_by_id[observation.case_id].scope
        if any(entry_scope_by_key[key] != expected_scope for key in ranked):
            raise RagRetrievalEvaluationError("ranked observations cannot cross a knowledge scope")
        if observation.access_concealed and ranked:
            raise RagRetrievalEvaluationError(
                "an access-concealed observation cannot expose ranked entries"
            )

    answerable = [case for case in dataset.cases if case.kind == "answerable"]
    no_answer = [case for case in dataset.cases if case.kind == "no_answer"]
    acl_cases = [case for case in dataset.cases if case.kind == "acl_denied"]
    recall_total = 0.0
    reciprocal_rank_total = 0.0
    ndcg_total = 0.0
    for case in answerable:
        observation = observed[case.case_id]
        if observation.access_concealed:
            continue
        relevant = frozenset(case.relevant_entry_keys)
        top_five = observation.ranked_entry_keys[:5]
        recall_total += len(relevant.intersection(top_five)) / len(relevant)
        first_rank = next(
            (
                rank
                for rank, key in enumerate(observation.ranked_entry_keys, start=1)
                if key in relevant
            ),
            None,
        )
        if first_rank is not None:
            reciprocal_rank_total += 1.0 / first_rank
        ideal = sum(1.0 / math.log2(rank + 1) for rank in range(1, min(len(relevant), 5) + 1))
        ndcg_total += _dcg(relevant, observation.ranked_entry_keys, k=5) / ideal

    no_answer_correct = sum(
        not observed[case.case_id].ranked_entry_keys and not observed[case.case_id].access_concealed
        for case in no_answer
    )
    acl_leakage_count = sum(
        not observed[case.case_id].access_concealed
        or bool(observed[case.case_id].ranked_entry_keys)
        for case in acl_cases
    )
    return RagRetrievalMetrics(
        dataset_version=dataset.version,
        dataset_fingerprint=rag_retrieval_dataset_fingerprint(dataset),
        total_cases=len(dataset.cases),
        answerable_cases=len(answerable),
        no_answer_cases=len(no_answer),
        acl_cases=len(acl_cases),
        recall_at_5=recall_total / len(answerable),
        mean_reciprocal_rank=reciprocal_rank_total / len(answerable),
        ndcg_at_5=ndcg_total / len(answerable),
        no_answer_accuracy=no_answer_correct / len(no_answer),
        acl_leakage_count=acl_leakage_count,
    )


def assert_rag_retrieval_thresholds(
    metrics: RagRetrievalMetrics,
    thresholds: RagRetrievalThresholds | None = None,
) -> None:
    thresholds = thresholds or RagRetrievalThresholds()
    failures: list[str] = []
    for name in ("recall_at_5", "mean_reciprocal_rank", "ndcg_at_5", "no_answer_accuracy"):
        actual = float(getattr(metrics, name))
        required = float(getattr(thresholds, name))
        if not math.isfinite(required) or not 0.0 <= required <= 1.0:
            raise RagRetrievalEvaluationError(f"invalid RAG retrieval threshold: {name}")
        if not math.isfinite(actual) or not 0.0 <= actual <= 1.0:
            failures.append(f"{name}=invalid")
        elif actual < required:
            failures.append(f"{name}={actual:.6f} < {required:.6f}")
    if (
        isinstance(thresholds.maximum_acl_leakage_count, bool)
        or thresholds.maximum_acl_leakage_count < 0
    ):
        raise RagRetrievalEvaluationError("invalid RAG retrieval ACL threshold")
    if isinstance(metrics.acl_leakage_count, bool) or metrics.acl_leakage_count < 0:
        failures.append("acl_leakage_count=invalid")
    if metrics.acl_leakage_count > thresholds.maximum_acl_leakage_count:
        failures.append(
            "acl_leakage_count="
            f"{metrics.acl_leakage_count} > {thresholds.maximum_acl_leakage_count}"
        )
    if failures:
        raise RagRetrievalEvaluationError(
            "RAG retrieval quality gate failed: " + "; ".join(failures)
        )
