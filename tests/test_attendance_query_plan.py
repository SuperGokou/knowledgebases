from __future__ import annotations

from datetime import date

import pytest

from app.services.attendance_query_plan import (
    AttendanceAggregateDimension,
    AttendanceAggregateMode,
    AttendanceAggregateSelection,
    AttendanceAggregationPlan,
    AttendanceDateRange,
    AttendanceQueryPlanStatus,
    parse_attendance_query_plan,
)


def _assert_plan(
    question: str,
    *,
    mode: AttendanceAggregateMode,
    dimension: AttendanceAggregateDimension | None,
    selection: AttendanceAggregateSelection,
    top_n: int | None = None,
    include_values: bool = False,
    date_range: AttendanceDateRange | None = None,
) -> None:
    result = parse_attendance_query_plan(question)

    assert result.status is AttendanceQueryPlanStatus.COMPILED
    assert result.applicable is True
    assert result.rejection_reason is None
    assert result.plan == AttendanceAggregationPlan(
        mode=mode,
        dimension=dimension,
        selection=selection,
        top_n=top_n,
        include_values=include_values,
        date_range=date_range,
    )


@pytest.mark.parametrize(
    "question",
    (
        "这份考勤一共有多少条打卡记录？",
        "整个数据集的考勤记录总数是多少？",
        "全部员工累计打卡多少次？",
        "总共有几次考勤事件？",
    ),
)
def test_compiles_total_attendance_counts(question: str) -> None:
    _assert_plan(
        question,
        mode=AttendanceAggregateMode.TOTAL,
        dimension=None,
        selection=AttendanceAggregateSelection.ALL,
    )


@pytest.mark.parametrize(
    ("question", "dimension"),
    (
        ("考勤记录中有多少位不同员工？请列出名单。", AttendanceAggregateDimension.EMPLOYEE),
        (
            "这份考勤记录中，一共包含多少个不同部门？请列出名称。",
            AttendanceAggregateDimension.DEPARTMENT,
        ),
        ("考勤表一共有多少种设备？请列出设备名称。", AttendanceAggregateDimension.DEVICE),
        ("考勤记录包含多少种认证结果？", AttendanceAggregateDimension.EVENT_RESULT),
    ),
)
def test_compiles_distinct_dimensions(
    question: str,
    dimension: AttendanceAggregateDimension,
) -> None:
    _assert_plan(
        question,
        mode=AttendanceAggregateMode.DISTINCT,
        dimension=dimension,
        selection=AttendanceAggregateSelection.ALL,
        include_values=True,
    )


@pytest.mark.parametrize(
    ("question", "dimension"),
    (
        ("每位员工分别有多少条打卡记录？", AttendanceAggregateDimension.EMPLOYEE),
        ("请按部门汇总考勤次数。", AttendanceAggregateDimension.DEPARTMENT),
        ("各设备分别有多少条门禁记录？", AttendanceAggregateDimension.DEVICE),
        ("请按认证结果分组统计记录数。", AttendanceAggregateDimension.EVENT_RESULT),
    ),
)
def test_compiles_all_group_counts(
    question: str,
    dimension: AttendanceAggregateDimension,
) -> None:
    _assert_plan(
        question,
        mode=AttendanceAggregateMode.GROUP_COUNT,
        dimension=dimension,
        selection=AttendanceAggregateSelection.ALL,
    )


@pytest.mark.parametrize(
    ("question", "dimension", "selection"),
    (
        (
            "考勤次数最高的员工是谁？累计几次？",
            AttendanceAggregateDimension.EMPLOYEE,
            AttendanceAggregateSelection.MAX,
        ),
        (
            "请找出打卡量最大的员工以及打卡总数。",
            AttendanceAggregateDimension.EMPLOYEE,
            AttendanceAggregateSelection.MAX,
        ),
        (
            "认证成功的记录中谁打卡最多？",
            AttendanceAggregateDimension.EMPLOYEE,
            AttendanceAggregateSelection.MAX,
        ),
        (
            "在所有闸机设备中，打卡记录最多的设备是什么？",
            AttendanceAggregateDimension.DEVICE,
            AttendanceAggregateSelection.MAX,
        ),
        (
            "哪个部门的考勤次数最少？",
            AttendanceAggregateDimension.DEPARTMENT,
            AttendanceAggregateSelection.MIN,
        ),
        (
            "哪位员工打卡次数最少？",
            AttendanceAggregateDimension.EMPLOYEE,
            AttendanceAggregateSelection.MIN,
        ),
        (
            "哪种认证结果出现次数最多？",
            AttendanceAggregateDimension.EVENT_RESULT,
            AttendanceAggregateSelection.MAX,
        ),
    ),
)
def test_compiles_group_extrema(
    question: str,
    dimension: AttendanceAggregateDimension,
    selection: AttendanceAggregateSelection,
) -> None:
    _assert_plan(
        question,
        mode=AttendanceAggregateMode.GROUP_COUNT,
        dimension=dimension,
        selection=selection,
    )


@pytest.mark.parametrize(
    ("question", "dimension", "top_n"),
    (
        ("打卡次数最多的前3位员工是谁？", AttendanceAggregateDimension.EMPLOYEE, 3),
        ("请列出考勤频率 top 10 员工。", AttendanceAggregateDimension.EMPLOYEE, 10),
        ("闸机使用次数排名前三的是哪些？", AttendanceAggregateDimension.DEVICE, 3),
        ("请给出考勤次数前五十名员工。", AttendanceAggregateDimension.EMPLOYEE, 50),
    ),
)
def test_compiles_bounded_top_n(
    question: str,
    dimension: AttendanceAggregateDimension,
    top_n: int,
) -> None:
    _assert_plan(
        question,
        mode=AttendanceAggregateMode.GROUP_COUNT,
        dimension=dimension,
        selection=AttendanceAggregateSelection.TOP_N,
        top_n=top_n,
    )


@pytest.mark.parametrize(
    ("question", "expected"),
    (
        (
            "2026年7月17日当天，哪位员工打卡次数最多？",
            AttendanceDateRange(date(2026, 7, 17), date(2026, 7, 17)),
        ),
        (
            "2026-07-01至2026-07-17，哪台设备使用次数最多？",
            AttendanceDateRange(date(2026, 7, 1), date(2026, 7, 17)),
        ),
        (
            "请按部门汇总2026/07/01到2026/07/31的考勤次数。",
            AttendanceDateRange(date(2026, 7, 1), date(2026, 7, 31)),
        ),
    ),
)
def test_compiles_inclusive_absolute_date_filters(
    question: str,
    expected: AttendanceDateRange,
) -> None:
    result = parse_attendance_query_plan(question)

    assert result.status is AttendanceQueryPlanStatus.COMPILED
    assert result.plan is not None
    assert result.plan.date_range == expected


def test_ignores_an_explicit_workbook_name_when_compiling() -> None:
    _assert_plan(
        "在《10级以上考勤.xlsx》中，谁的打卡次数最多？",
        mode=AttendanceAggregateMode.GROUP_COUNT,
        dimension=AttendanceAggregateDimension.EMPLOYEE,
        selection=AttendanceAggregateSelection.MAX,
    )


@pytest.mark.parametrize(
    "question",
    (
        "员工考勤管理制度是什么？",
        "闸机设备维护规范有哪些？",
        "门禁卡办理流程是什么？",
        "员工“熊小强”的人员工号是多少？",
        "请介绍公司的部门职责。",
        "今天天气怎么样？",
    ),
)
def test_non_aggregate_or_policy_questions_are_not_applicable(question: str) -> None:
    result = parse_attendance_query_plan(question)

    assert result.status is AttendanceQueryPlanStatus.NOT_APPLICABLE
    assert result.applicable is False
    assert result.plan is None
    assert result.rejection_reason is None


@pytest.mark.parametrize(
    ("question", "reason"),
    (
        ("今天哪位员工打卡次数最多？", "relative_date_not_supported"),
        ("7月17日哪位员工打卡次数最多？", "partial_date_not_supported"),
        ("2026年2月30日哪位员工打卡次数最多？", "invalid_absolute_date"),
        (
            "2026年7月18日至2026年7月17日哪位员工打卡最多？",
            "reversed_date_range",
        ),
        ("员工平均打卡次数是多少？", "unsupported_metric"),
        ("各部门员工打卡次数分别是多少？", "ambiguous_dimension"),
        ("白班里哪位员工打卡最多？", "unsupported_scope"),
        ("打卡次数排行榜中的员工有哪些？", "ranking_requires_top_n"),
        ("哪个员工打卡次数最多也最少？", "conflicting_selection"),
        ("不同部门中哪个部门打卡最多？", "conflicting_aggregation_mode"),
        ("品质部共有多少条打卡记录？", "ambiguous_dimension_count"),
    ),
)
def test_unsafe_or_ambiguous_aggregates_fail_closed(question: str, reason: str) -> None:
    result = parse_attendance_query_plan(question)

    assert result.status is AttendanceQueryPlanStatus.REJECTED
    assert result.applicable is True
    assert result.plan is None
    assert result.rejection_reason == reason


@pytest.mark.parametrize("question", ("打卡次数前0名员工", "打卡次数前51名员工"))
def test_top_n_outside_the_whitelist_fails_closed(question: str) -> None:
    result = parse_attendance_query_plan(question)

    assert result.status is AttendanceQueryPlanStatus.REJECTED
    assert result.applicable is True
    assert result.plan is None
    assert result.rejection_reason == "top_n_out_of_range"


def test_nfkc_and_punctuation_variants_compile_to_the_same_plan() -> None:
    baseline = parse_attendance_query_plan("哪位员工打卡次数最多？")
    variant = parse_attendance_query_plan("哪位员工，打卡次数最多？！")

    assert baseline.status is AttendanceQueryPlanStatus.COMPILED
    assert variant == baseline


def test_plan_value_objects_reject_invalid_combinations() -> None:
    with pytest.raises(ValueError, match="total aggregation"):
        AttendanceAggregationPlan(
            mode=AttendanceAggregateMode.TOTAL,
            dimension=AttendanceAggregateDimension.EMPLOYEE,
            selection=AttendanceAggregateSelection.ALL,
        )
    with pytest.raises(ValueError, match="between 1 and 50"):
        AttendanceAggregationPlan(
            mode=AttendanceAggregateMode.GROUP_COUNT,
            dimension=AttendanceAggregateDimension.EMPLOYEE,
            selection=AttendanceAggregateSelection.TOP_N,
            top_n=51,
        )
