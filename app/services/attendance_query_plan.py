"""Fail-closed compiler for deterministic attendance aggregation questions.

The compiler deliberately produces a small, typed plan.  It never invents a
column, filter value, or aggregation that the deterministic executor cannot
verify from a trusted workbook.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from typing import Final

__all__ = (
    "AttendanceAggregateDimension",
    "AttendanceAggregateMode",
    "AttendanceAggregateSelection",
    "AttendanceAggregationPlan",
    "AttendanceDateRange",
    "AttendanceQueryPlanParseResult",
    "AttendanceQueryPlanStatus",
    "parse_attendance_query_plan",
)


class AttendanceAggregateMode(StrEnum):
    """The exact aggregation performed by the deterministic executor."""

    TOTAL = "total"
    DISTINCT = "distinct"
    GROUP_COUNT = "group_count"
    PER_CAPITA = "per_capita"
    DEPARTMENT_PROFILE = "department_profile"


class AttendanceAggregateDimension(StrEnum):
    """Whitelisted attendance fields that may be grouped or deduplicated."""

    EMPLOYEE = "employee"
    DEPARTMENT = "department"
    DEVICE = "device"
    EVENT_RESULT = "event_result"
    DATE = "date"


class AttendanceAggregateSelection(StrEnum):
    """How grouped buckets are selected for presentation."""

    ALL = "all"
    MAX = "max"
    MIN = "min"
    TOP_N = "top_n"
    COUNT_VALUES = "count_values"


@dataclass(frozen=True, slots=True)
class AttendanceDateRange:
    """Inclusive absolute-date filter."""

    start: date
    end: date

    def __post_init__(self) -> None:
        if self.start > self.end:
            raise ValueError("attendance date range starts after it ends")


@dataclass(frozen=True, slots=True)
class AttendanceAggregationPlan:
    """A fully validated, executor-ready attendance aggregation plan."""

    mode: AttendanceAggregateMode
    dimension: AttendanceAggregateDimension | None
    selection: AttendanceAggregateSelection
    top_n: int | None = None
    include_values: bool = False
    date_range: AttendanceDateRange | None = None
    count_values: tuple[int, ...] = ()
    device_contains: str | None = None

    def __post_init__(self) -> None:
        if self.mode is AttendanceAggregateMode.TOTAL:
            if self.dimension is not None or self.selection is not AttendanceAggregateSelection.ALL:
                raise ValueError("total aggregation cannot have a dimension or ranked selection")
            if self.include_values:
                raise ValueError("total aggregation cannot include dimension values")
        elif self.mode is AttendanceAggregateMode.DISTINCT:
            if self.dimension is None or self.selection is not AttendanceAggregateSelection.ALL:
                raise ValueError("distinct aggregation requires one dimension and ALL selection")
        elif self.mode is AttendanceAggregateMode.PER_CAPITA:
            if self.dimension is not AttendanceAggregateDimension.DEPARTMENT:
                raise ValueError("per-capita aggregation requires the department dimension")
            if self.selection not in (
                AttendanceAggregateSelection.ALL,
                AttendanceAggregateSelection.MAX,
                AttendanceAggregateSelection.MIN,
            ):
                raise ValueError("per-capita aggregation has an invalid selection")
        elif self.mode is AttendanceAggregateMode.DEPARTMENT_PROFILE:
            if (
                self.dimension is not AttendanceAggregateDimension.DEPARTMENT
                or self.selection is not AttendanceAggregateSelection.ALL
            ):
                raise ValueError("department profile requires department and ALL selection")
        elif self.dimension is None:
            raise ValueError("group-count aggregation requires one dimension")

        if self.selection is AttendanceAggregateSelection.TOP_N:
            if self.top_n is None or not 1 <= self.top_n <= 50:
                raise ValueError("top_n must be between 1 and 50")
        elif self.top_n is not None:
            raise ValueError("top_n is only valid for TOP_N selection")

        if self.selection is AttendanceAggregateSelection.COUNT_VALUES:
            if (
                self.mode is not AttendanceAggregateMode.GROUP_COUNT
                or self.dimension is not AttendanceAggregateDimension.EMPLOYEE
                or not self.count_values
                or len(self.count_values) > 10
                or any(value < 1 or value > 1_000_000 for value in self.count_values)
                or tuple(sorted(set(self.count_values))) != self.count_values
            ):
                raise ValueError("count_values must be a sorted employee frequency set")
        elif self.count_values:
            raise ValueError("count_values is only valid for COUNT_VALUES selection")

        if self.device_contains is not None and not re.fullmatch(
            r"[a-z0-9#._/-]{2,32}", self.device_contains
        ):
            raise ValueError("device_contains is not a safe device fragment")


class AttendanceQueryPlanStatus(StrEnum):
    """Three-state result of compiling a natural-language question."""

    NOT_APPLICABLE = "not_applicable"
    COMPILED = "compiled"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class AttendanceQueryPlanParseResult:
    """A compiled plan, a safe rejection, or a non-attendance question."""

    status: AttendanceQueryPlanStatus
    plan: AttendanceAggregationPlan | None
    rejection_reason: str | None = None

    def __post_init__(self) -> None:
        if self.status is AttendanceQueryPlanStatus.COMPILED and self.plan is None:
            raise ValueError("compiled result requires a plan")
        if self.status is not AttendanceQueryPlanStatus.COMPILED and self.plan is not None:
            raise ValueError("only compiled results may contain a plan")
        if self.status is AttendanceQueryPlanStatus.REJECTED and not self.rejection_reason:
            raise ValueError("rejected result requires a reason")
        if (
            self.status is not AttendanceQueryPlanStatus.REJECTED
            and self.rejection_reason is not None
        ):
            raise ValueError("only rejected results may contain a reason")

    @property
    def applicable(self) -> bool:
        return self.status is not AttendanceQueryPlanStatus.NOT_APPLICABLE


_SPREADSHEET_REFERENCE_PATTERN: Final = re.compile(
    r"[《【“\"']?[^《》【】“”\"'\s，。？！?]{1,200}\.(?:xlsx?|csv)[》】”\"']?",
    flags=re.IGNORECASE,
)
_ABSOLUTE_DATE_PATTERN: Final = re.compile(
    r"(?<!\d)(?P<year>\d{4})\s*(?:"
    r"年\s*(?P<month_cn>\d{1,2})\s*月\s*(?P<day_cn>\d{1,2})\s*日?"
    r"|(?P<separator>[-/.])\s*(?P<month_sep>\d{1,2})\s*(?P=separator)\s*"
    r"(?P<day_sep>\d{1,2})"
    r")(?!\d)"
)
_PARTIAL_DATE_PATTERN: Final = re.compile(
    r"(?<!\d)(?:\d{1,2}\s*月\s*\d{1,2}\s*日?|\d{4}\s*年\s*\d{1,2}\s*月(?!\s*\d))"
)
_TOP_N_PATTERN: Final = re.compile(
    r"(?:(?<![a-z])top\s*|前\s*)(?P<count>\d{1,3}|[一二两三四五六七八九十]{1,3})"
    r"\s*(?:名|位|个|台|条)?",
    flags=re.IGNORECASE,
)
_TOP_MARKER_PATTERN: Final = re.compile(
    r"(?:(?<![a-z])top|前\s*(?:\d|[一二两三四五六七八九十]))",
    flags=re.IGNORECASE,
)
_NAMED_ORGANIZATION_SCOPE_PATTERN: Final = re.compile(
    r"[A-Za-z0-9一-鿿·_-]{1,30}(?:部(?!门)|科|处|组|中心)(?:中|里|内|的)?"
)

_POLICY_TERMS: Final = (
    "制度",
    "规范",
    "政策",
    "流程",
    "办法",
    "手册",
    "定义",
    "职责",
    "维护指南",
    "操作指南",
)
_LOOKUP_FIELD_TERMS: Final = ("工号", "卡号", "编号是多少")
_ATTENDANCE_TERMS: Final = ("考勤", "打卡", "刷卡", "门禁", "通行")
_DIMENSION_TERMS: Final[dict[AttendanceAggregateDimension, tuple[str, ...]]] = {
    AttendanceAggregateDimension.EMPLOYEE: (
        "员工",
        "人员",
        "职工",
        "雇员",
        "哪位",
        "哪名",
        "谁",
    ),
    AttendanceAggregateDimension.DEPARTMENT: ("部门", "科室", "组织单位", "组织单元"),
    AttendanceAggregateDimension.DEVICE: (
        "设备",
        "闸机",
        "门禁机",
        "考勤机",
        "打卡机",
    ),
    AttendanceAggregateDimension.EVENT_RESULT: (
        "事件结果",
        "事件详情",
        "认证结果",
        "验证结果",
        "通行结果",
        "刷卡结果",
        "认证状态",
        "验证状态",
    ),
    AttendanceAggregateDimension.DATE: ("哪一天", "哪天", "日期", "每天", "每日"),
}
_COUNT_TERMS: Final = (
    "多少",
    "几条",
    "几次",
    "几个",
    "几种",
    "总数",
    "数量",
    "合计",
    "累计",
    "总共",
    "一共",
    "共计",
    "共有",
    "统计",
    "汇总",
)
_MAX_TERMS: Final = (
    "次数最多",
    "记录最多",
    "出现最多",
    "使用最多",
    "打卡最多",
    "考勤最多",
    "刷卡最多",
    "频次最高",
    "频率最高",
    "次数最高",
    "记录最高",
    "打卡量最大",
    "记录量最大",
    "最频繁",
    "最常用",
    "最多",
    "最高",
    "最大",
)
_MIN_TERMS: Final = (
    "次数最少",
    "记录最少",
    "出现最少",
    "使用最少",
    "打卡最少",
    "考勤最少",
    "刷卡最少",
    "频次最低",
    "频率最低",
    "次数最低",
    "记录最低",
    "最不频繁",
    "最不常用",
    "最少",
    "最低",
    "最小",
)
_DISTINCT_TERMS: Final = (
    "不同",
    "去重",
    "多少种",
    "几种",
    "种类",
    "名单",
    "清单",
    "列表",
    "有哪些",
    "分别叫什么",
)
_GROUP_ALL_TERMS: Final = (
    "每个",
    "每位",
    "每名",
    "每台",
    "每种",
    "各部门",
    "各员工",
    "各人员",
    "各设备",
    "各闸机",
    "各事件结果",
    "分别有多少",
    "各自有多少",
    "分组",
    "统计表",
)
_RELATIVE_DATE_TERMS: Final = (
    "今天",
    "昨日",
    "昨天",
    "前天",
    "本周",
    "上周",
    "本月",
    "上月",
    "今年",
    "去年",
    "上午",
    "下午",
    "最近",
    "近几天",
)
_UNSUPPORTED_METRIC_TERMS: Final = (
    "平均",
    "均值",
    "中位数",
    "百分比",
    "占比",
    "比例",
    "趋势",
    "同比",
    "环比",
    "方差",
    "标准差",
    "金额",
    "时长",
)
_UNSUPPORTED_SCOPE_TERMS: Final = (
    "排除",
    "剔除",
    "不包括",
    "除了",
    "大于",
    "小于",
    "不少于",
    "不多于",
    "至少",
    "至多",
    "超过",
    "少于",
    "白班",
    "夜班",
    "工作表",
    "sheet",
)
_PUNCTUATION_TRANSLATION: Final = str.maketrans(
    {character: " " for character in "，。？！?!、；;：:()（）《》【】“”‘’\"'"}
)
_COUNT_VALUE_SET_PATTERN: Final = re.compile(
    r"(?P<first>\d{1,6}|[一二两三四五六七八九十]{1,3})\s*次\s*"
    r"(?:或|或者|和|、|以及|至|到|[-~～])\s*"
    r"(?P<second>\d{1,6}|[一二两三四五六七八九十]{1,3})\s*次"
)
_DEVICE_FRAGMENT_PATTERN: Final = re.compile(r"(?P<fragment>\d{1,3}#\d{1,3}f)", re.IGNORECASE)


def parse_attendance_query_plan(question: str) -> AttendanceQueryPlanParseResult:
    """Compile a Chinese attendance aggregation question into a safe plan.

    Questions outside the attendance aggregation domain are ``NOT_APPLICABLE``.
    Questions that look like an aggregation but contain unsupported or ambiguous
    semantics are ``REJECTED`` so callers can prevent an unsafe RAG fallback.
    """

    normalized = _normalize_question(question)
    if not normalized:
        return _not_applicable()
    semantic = _SPREADSHEET_REFERENCE_PATTERN.sub(" ", normalized)
    compact = re.sub(r"\s+", "", semantic.translate(_PUNCTUATION_TRANSLATION))
    if not compact or any(term in compact for term in _POLICY_TERMS):
        return _not_applicable()
    if any(term in compact for term in _LOOKUP_FIELD_TERMS) and not _has_ranked_selection(compact):
        return _not_applicable()

    dimensions = _dimensions_in(compact)
    count_values, count_value_error = _count_value_set(compact)
    if count_value_error is not None:
        return _rejected(count_value_error)
    device_contains = _device_fragment(semantic)
    if (
        device_contains is not None
        and AttendanceAggregateDimension.EMPLOYEE in dimensions
        and AttendanceAggregateDimension.DEVICE in dimensions
    ):
        dimensions = frozenset((AttendanceAggregateDimension.EMPLOYEE,))
    aggregate_cue = (
        _has_aggregate_cue(compact)
        or count_values is not None
        or (
            device_contains is not None
            and AttendanceAggregateDimension.EMPLOYEE in dimensions
            and any(term in compact for term in ("谁", "哪位", "哪些人", "有没有人"))
        )
    )
    attendance_cue = any(term in compact for term in _ATTENDANCE_TERMS)
    domain_cue = (
        attendance_cue
        or AttendanceAggregateDimension.EVENT_RESULT in dimensions
        or any(term in compact for term in ("闸机", "门禁机", "考勤机", "打卡机"))
        or (
            AttendanceAggregateDimension.DEVICE in dimensions
            and any(term in compact for term in ("使用次数", "使用频率", "记录次数"))
        )
    )
    if not (aggregate_cue and domain_cue):
        return _not_applicable()

    if any(term in compact for term in _UNSUPPORTED_METRIC_TERMS):
        return _rejected("unsupported_metric")
    if any(term in compact for term in _UNSUPPORTED_SCOPE_TERMS):
        return _rejected("unsupported_scope")
    if len(dimensions) > 1:
        return _rejected("ambiguous_dimension")
    if AttendanceAggregateDimension.DEPARTMENT in dimensions and re.search(
        r"部门.{0,12}(?:多少人|几人|人数|员工数量|人员数量|职工数量)",
        compact,
    ):
        return _rejected("unsupported_metric")

    date_range, date_error = _absolute_date_range(semantic)
    if date_error is not None:
        return _rejected(date_error)

    top_n, top_error = _top_n(compact)
    if top_error is not None:
        return _rejected(top_error)
    has_max = any(term in compact for term in _MAX_TERMS)
    has_min = any(term in compact for term in _MIN_TERMS)
    if has_max and has_min:
        return _rejected("conflicting_selection")
    if top_n is not None and has_min:
        return _rejected("unsupported_bottom_n")
    if top_n is None and any(term in compact for term in ("排名", "排行", "排行榜", "top")):
        return _rejected("ranking_requires_top_n")

    dimension = next(iter(dimensions), None)

    if "人均" in compact:
        if dimension is not AttendanceAggregateDimension.DEPARTMENT:
            return _rejected("per_capita_requires_department")
        if not (has_max or has_min):
            return _rejected("per_capita_requires_selection")
        return _compiled(
            AttendanceAggregationPlan(
                mode=AttendanceAggregateMode.PER_CAPITA,
                dimension=dimension,
                selection=(
                    AttendanceAggregateSelection.MAX
                    if has_max
                    else AttendanceAggregateSelection.MIN
                ),
                date_range=date_range,
            )
        )

    if count_values is not None:
        if dimension is not AttendanceAggregateDimension.EMPLOYEE:
            return _rejected("count_values_require_employee")
        return _compiled(
            AttendanceAggregationPlan(
                mode=AttendanceAggregateMode.GROUP_COUNT,
                dimension=dimension,
                selection=AttendanceAggregateSelection.COUNT_VALUES,
                count_values=count_values,
                date_range=date_range,
            )
        )

    if (
        device_contains is not None
        and dimension is AttendanceAggregateDimension.EMPLOYEE
        and any(term in compact for term in ("谁", "哪位", "哪些人", "有没有人"))
    ):
        return _compiled(
            AttendanceAggregationPlan(
                mode=AttendanceAggregateMode.GROUP_COUNT,
                dimension=dimension,
                selection=AttendanceAggregateSelection.ALL,
                date_range=date_range,
                device_contains=device_contains,
            )
        )

    if _is_department_profile_request(compact):
        if date_range is not None:
            return _rejected("department_profile_date_scope_not_supported")
        return _compiled(
            AttendanceAggregationPlan(
                mode=AttendanceAggregateMode.DEPARTMENT_PROFILE,
                dimension=AttendanceAggregateDimension.DEPARTMENT,
                selection=AttendanceAggregateSelection.ALL,
            )
        )

    distinct = _is_distinct_request(compact, dimension)
    group_all = _is_group_all_request(compact, dimension)
    ranked = top_n is not None or has_max or has_min
    # In a ranked question, words such as “有哪些/名单/列表” describe the
    # requested presentation rather than a second DISTINCT aggregation.
    # Explicit uniqueness cues still remain conflicting and fail closed.
    if ranked and distinct and not any(term in compact for term in _DISTINCT_TERMS[:5]):
        distinct = False
    if distinct and (ranked or group_all):
        return _rejected("conflicting_aggregation_mode")
    if group_all and ranked:
        return _rejected("conflicting_selection")

    if distinct:
        if dimension is None:
            return _rejected("distinct_requires_dimension")
        plan = AttendanceAggregationPlan(
            mode=AttendanceAggregateMode.DISTINCT,
            dimension=dimension,
            selection=AttendanceAggregateSelection.ALL,
            include_values=True,
            date_range=date_range,
        )
        return _compiled(plan)

    if ranked or group_all:
        if dimension is None:
            return _rejected("group_count_requires_dimension")
        selection = (
            AttendanceAggregateSelection.TOP_N
            if top_n is not None
            else AttendanceAggregateSelection.MAX
            if has_max
            else AttendanceAggregateSelection.MIN
            if has_min
            else AttendanceAggregateSelection.ALL
        )
        plan = AttendanceAggregationPlan(
            mode=AttendanceAggregateMode.GROUP_COUNT,
            dimension=dimension,
            selection=selection,
            top_n=top_n,
            date_range=date_range,
            device_contains=device_contains,
        )
        return _compiled(plan)

    # A dimension word can introduce an exact row filter (for example
    # ``员工“熊小强”`` or ``东门设备``) while the requested metric is still a
    # total row count. The executor resolves such values from the trusted table
    # and rejects unknown or multi-value scopes. A dated named organization is
    # handled the same way; undated department totals retain the legacy route.
    if (
        dimension is None
        and date_range is None
        and _NAMED_ORGANIZATION_SCOPE_PATTERN.search(compact)
    ):
        return _rejected("ambiguous_dimension_count")
    return _compiled(
        AttendanceAggregationPlan(
            mode=AttendanceAggregateMode.TOTAL,
            dimension=None,
            selection=AttendanceAggregateSelection.ALL,
            date_range=date_range,
            device_contains=device_contains,
        )
    )


def _count_value_set(question: str) -> tuple[tuple[int, ...] | None, str | None]:
    matches = tuple(_COUNT_VALUE_SET_PATTERN.finditer(question))
    if not matches:
        return None, None
    if len(matches) != 1:
        return None, "multiple_count_value_sets"
    values = tuple(
        _positive_integer(matches[0].group(name)) for name in ("first", "second")
    )
    if any(value is None or value < 1 or value > 1_000_000 for value in values):
        return None, "invalid_count_value_set"
    return tuple(sorted(set(value for value in values if value is not None))), None


def _device_fragment(question: str) -> str | None:
    matches = tuple(_DEVICE_FRAGMENT_PATTERN.finditer(question))
    if len(matches) != 1:
        return None
    match = matches[0]
    suffix = question[match.end() :].lstrip()
    # ``1#2F人行道闸入口1`` is an exact device label, not a partial 2F scope.
    if suffix and re.match(r"[A-Za-z0-9一-鿿#._/-]", suffix):
        return None
    return match.group("fragment").casefold()


def _is_department_profile_request(question: str) -> bool:
    employee_count = re.search(
        r"(?:有|共|一共|总共)?(?:几|多少)(?:位|名|个)?(?:员工|人员)",
        question,
    )
    total_records = re.search(
        r"(?:一共|总共|共计|累计).{0,12}(?:打卡|考勤).{0,8}(?:多少|几)(?:次|条)?",
        question,
    )
    return employee_count is not None and total_records is not None


def _normalize_question(question: str) -> str:
    normalized = unicodedata.normalize("NFKC", question).casefold()
    without_controls = "".join(
        character
        for character in normalized
        if character.isspace() or not unicodedata.category(character).startswith("C")
    )
    return " ".join(without_controls.split())


def _dimensions_in(question: str) -> frozenset[AttendanceAggregateDimension]:
    return frozenset(
        dimension
        for dimension, terms in _DIMENSION_TERMS.items()
        if any(term in question for term in terms)
    )


def _has_aggregate_cue(question: str) -> bool:
    return bool(
        _TOP_N_PATTERN.search(question)
        or _TOP_MARKER_PATTERN.search(question)
        or any(
            term in question
            for term in (
                *_COUNT_TERMS,
                *_MAX_TERMS,
                *_MIN_TERMS,
                *_DISTINCT_TERMS,
                *_GROUP_ALL_TERMS,
                *_UNSUPPORTED_METRIC_TERMS,
                "排名",
                "排行",
                "排行榜",
            )
        )
    )


def _has_ranked_selection(question: str) -> bool:
    return bool(
        _TOP_MARKER_PATTERN.search(question)
        or any(term in question for term in (*_MAX_TERMS, *_MIN_TERMS))
    )


def _is_distinct_request(
    question: str,
    dimension: AttendanceAggregateDimension | None,
) -> bool:
    if any(term in question for term in _DISTINCT_TERMS):
        return True
    if dimension is None:
        return False
    aliases = _DIMENSION_TERMS[dimension]
    return any(
        re.search(rf"(?:多少|几)(?:个|种|位|名|台)?{re.escape(alias)}", question)
        or re.search(rf"{re.escape(alias)}(?:总数|数量|种类)", question)
        or (
            re.search(rf"{re.escape(alias)}名称", question) is not None
            and any(term in question for term in ("多少", "几个", "几种", "列出", "全部"))
        )
        for alias in aliases
        if alias not in ("谁", "哪位", "哪名")
    )


def _is_group_all_request(
    question: str,
    dimension: AttendanceAggregateDimension | None,
) -> bool:
    if any(term in question for term in _GROUP_ALL_TERMS):
        return True
    if dimension is None:
        return False
    aliases = _DIMENSION_TERMS[dimension]
    return any(
        re.search(rf"按.{0, 8}{re.escape(alias)}.{0, 8}(?:汇总|统计|分组)", question)
        or re.search(rf"按{re.escape(alias)}(?:汇总|统计|分组)", question)
        for alias in aliases
    )


def _is_global_total_scope(
    question: str,
    dimension: AttendanceAggregateDimension,
) -> bool:
    if dimension is AttendanceAggregateDimension.EMPLOYEE:
        return any(term in question for term in ("全部员工", "所有员工", "全体员工", "全部人员"))
    return False


def _absolute_date_range(question: str) -> tuple[AttendanceDateRange | None, str | None]:
    if any(term in question for term in _RELATIVE_DATE_TERMS):
        return None, "relative_date_not_supported"
    matches = tuple(_ABSOLUTE_DATE_PATTERN.finditer(question))
    remaining = _ABSOLUTE_DATE_PATTERN.sub(" ", question)
    if _PARTIAL_DATE_PATTERN.search(remaining):
        return None, "partial_date_not_supported"
    if not matches:
        return None, None
    if len(matches) > 2:
        return None, "too_many_dates"

    parsed: list[date] = []
    for match in matches:
        month_text = match.group("month_cn") or match.group("month_sep")
        day_text = match.group("day_cn") or match.group("day_sep")
        try:
            parsed.append(date(int(match.group("year")), int(month_text), int(day_text)))
        except ValueError:
            return None, "invalid_absolute_date"
    if len(parsed) == 2:
        connector = question[matches[0].end() : matches[1].start()]
        if not re.search(r"(?:至|到|~|～|—|–)", connector):
            return None, "ambiguous_date_range"
    try:
        return AttendanceDateRange(start=parsed[0], end=parsed[-1]), None
    except ValueError:
        return None, "reversed_date_range"


def _top_n(question: str) -> tuple[int | None, str | None]:
    matches = tuple(_TOP_N_PATTERN.finditer(question))
    if len(matches) > 1:
        return None, "multiple_top_n_values"
    if not matches:
        if _TOP_MARKER_PATTERN.search(question):
            return None, "invalid_top_n"
        return None, None
    value = _positive_integer(matches[0].group("count"))
    if value is None or not 1 <= value <= 50:
        return None, "top_n_out_of_range"
    return value, None


def _positive_integer(value: str) -> int | None:
    if value.isdigit():
        return int(value)
    digits = {
        "一": 1,
        "二": 2,
        "两": 2,
        "三": 3,
        "四": 4,
        "五": 5,
        "六": 6,
        "七": 7,
        "八": 8,
        "九": 9,
    }
    if value == "十":
        return 10
    if "十" not in value:
        return digits.get(value)
    left, right = value.split("十", maxsplit=1)
    tens = digits.get(left, 1) if left else 1
    ones = digits.get(right, 0) if right else 0
    return tens * 10 + ones


def _not_applicable() -> AttendanceQueryPlanParseResult:
    return AttendanceQueryPlanParseResult(
        status=AttendanceQueryPlanStatus.NOT_APPLICABLE,
        plan=None,
    )


def _compiled(plan: AttendanceAggregationPlan) -> AttendanceQueryPlanParseResult:
    return AttendanceQueryPlanParseResult(
        status=AttendanceQueryPlanStatus.COMPILED,
        plan=plan,
    )


def _rejected(reason: str) -> AttendanceQueryPlanParseResult:
    return AttendanceQueryPlanParseResult(
        status=AttendanceQueryPlanStatus.REJECTED,
        plan=None,
        rejection_reason=reason,
    )
