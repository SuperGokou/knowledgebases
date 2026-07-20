from __future__ import annotations

import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from hashlib import sha256
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import (
    KnowledgeBase,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
    User,
)
from app.services.spreadsheet_query import (
    SpreadsheetQueryStatus,
    answer_spreadsheet_query,
    evaluate_spreadsheet_query,
    is_spreadsheet_query_intent,
)

HEADERS = (
    "组织",
    "部门",
    "人员工号",
    "姓名",
    "卡号",
    "时间",
    "设备",
    "门编号",
    "设备描述",
    "事件类型",
    "事件结果",
)

RowValues = tuple[str, str, str, str, str, str, str, str, str, str, str]


@pytest_asyncio.fixture
async def knowledge_session() -> AsyncIterator[tuple[AsyncSession, UUID]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        user = User(email="spreadsheet@example.com", password_hash="hash")
        session.add(user)
        await session.flush()
        knowledge_base = KnowledgeBase(owner_id=user.id, name="infra")
        session.add(knowledge_base)
        await session.flush()
        yield session, knowledge_base.id
    await engine.dispose()


def _content(
    rows: tuple[tuple[int, RowValues], ...],
    *,
    headers: tuple[str, ...] = HEADERS,
    sheet: str = "Sheet1",
) -> str:
    lines = ["# 考勤记录"]
    for index, value in enumerate(headers):
        column = chr(ord("A") + index)
        lines.append(f"[worksheet:{sheet}!{column}1] {value}")
    for row_number, values in rows:
        for index, value in enumerate(values):
            if value:
                column = chr(ord("A") + index)
                lines.append(f"[worksheet:{sheet}!{column}{row_number}] {value}")
    return "\n\n".join(lines)


async def _add_entry(
    session: AsyncSession,
    knowledge_base_id: UUID,
    content: str,
    *,
    title: str = "10级以上考勤.xlsx",
    publication_status: KnowledgeEntryPublicationStatus = (
        KnowledgeEntryPublicationStatus.PUBLISHED
    ),
    deleted_at: datetime | None = None,
    source_parser: str = "ooxml-xlsx",
) -> KnowledgeEntry:
    source_start = content.index("[worksheet:")
    source_text = content[source_start:]
    cell_locations = re.findall(r"\[(worksheet:[^\]\r\n]+![A-Za-z]{1,3}[1-9]\d*)\]", source_text)
    source_locations: list[str] = []
    seen_sheets: set[str] = set()
    for location in cell_locations:
        sheet_location = location.rsplit("!", maxsplit=1)[0]
        if sheet_location not in seen_sheets:
            seen_sheets.add(sheet_location)
            source_locations.append(sheet_location)
        source_locations.append(location)
    source_location_text = "\n".join(source_locations)
    entry = KnowledgeEntry(
        knowledge_base_id=knowledge_base_id,
        entry_type="document",
        title=title,
        content=content,
        source_path="generated/attendance.md",
        format_version="okf/0.1",
        publication_status=publication_status,
        deleted_at=deleted_at,
        custom_metadata={
            "source_parser": source_parser,
            # Match document_parser._parse_xlsx / okf_conversion production metadata.
            "source_locations": source_locations[:2_048],
            "source_location_count": len(source_locations),
            "source_locations_truncated": len(source_locations) > 2_048,
            "source_text_length": len(source_text),
            "source_text_sha256": sha256(source_text.encode("utf-8")).hexdigest(),
            "source_locations_sha256": sha256(source_location_text.encode("utf-8")).hexdigest(),
            "generator": {
                "provider": "local",
                "model": "local-deterministic-v1",
                "prompt_version": "okf-v1",
            },
        },
    )
    session.add(entry)
    await session.flush()
    return entry


def _record(
    department: str,
    employee_id: str,
    name: str,
    card: str,
    timestamp: str,
    device: str,
    *,
    event_result: str = "认证成功(白名单验证)",
) -> RowValues:
    return (
        "江苏和熠光显科技有限公司",
        department,
        employee_id,
        name,
        card,
        timestamp,
        device,
        "1",
        device,
        "普通消息",
        event_result,
    )


@pytest.mark.asyncio
async def test_answers_the_five_acceptance_questions_with_complete_row_evidence(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (
                    5,
                    _record(
                        "生产部",
                        "EFD2410053",
                        "熊小强",
                        "135265",
                        "2026-07-17 23:00:43",
                        "1#2F人行道闸出口6",
                    ),
                ),
                (
                    2,
                    _record(
                        "前工程科",
                        "EFD2410061",
                        "彭楚亮",
                        "135267",
                        "2026-07-17 23:54:05",
                        "1#2F人行道闸出口3",
                    ),
                ),
                (
                    31,
                    _record(
                        "研发部",
                        "EFD2507003",
                        "许荣蔚",
                        "134190",
                        "2026-07-17 16:00:36",
                        "1#2F人行道闸出口3",
                    ),
                ),
                (
                    20,
                    _record(
                        "研发部",
                        "EFD2507004",
                        "李明",
                        "134191",
                        "2026-07-17 08:00:00",
                        "1#2F人行道闸入口1",
                    ),
                ),
            )
        ),
    )
    await session.commit()

    employee_id = await answer_spreadsheet_query(
        session, knowledge_base_id, "员工“熊小强”的人员工号是多少？"
    )
    card = await answer_spreadsheet_query(session, knowledge_base_id, "员工“彭楚亮”的卡号是多少？")
    department = await answer_spreadsheet_query(
        session, knowledge_base_id, "研发部总共有哪几位员工在考勤记录中？"
    )
    date_range = await answer_spreadsheet_query(
        session, knowledge_base_id, "这份考勤记录涵盖的时间范围是什么？（从哪一天到哪一天）"
    )
    latest = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "2026年7月17日当天，最后一条（最晚）打卡记录是谁？在几点几分通过的哪个设备？",
    )

    assert employee_id is not None
    assert employee_id.answer == "员工“熊小强”的人员工号是 EFD2410053。[1]"
    assert employee_id.table is not None
    assert employee_id.table.rows == (("熊小强", "EFD2410053"),)
    assert "[worksheet:Sheet1!A5]" in employee_id.hits[0].excerpt
    assert "[worksheet:Sheet1!K5]" in employee_id.hits[0].excerpt
    assert employee_id.hits[0].source_path.endswith("#worksheet:Sheet1!A5:K5")

    assert card is not None and "135267。[1]" in card.answer
    assert department is not None
    assert department.table is not None
    assert department.table.columns == ("人员工号", "员工姓名")
    assert department.table.rows == (
        ("EFD2507003", "许荣蔚"),
        ("EFD2507004", "李明"),
    )
    assert date_range is not None
    assert "2026年7月17日至2026年7月17日。[1]" in date_range.answer
    assert latest is not None
    assert "彭楚亮，于23时54分通过“1#2F人行道闸出口3”。[1]" in latest.answer


@pytest.mark.asyncio
async def test_event_result_existence_matches_any_requested_status(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (
                    2,
                    _record(
                        "工程部",
                        "E001",
                        "刘春耀",
                        "135385",
                        "2026-07-17 08:00:00",
                        "1#2F人行道闸出口3",
                    ),
                ),
                (
                    3,
                    _record(
                        "工程部",
                        "E002",
                        "张三",
                        "135386",
                        "2026-07-17 08:05:00",
                        "1#2F人行道闸出口3",
                        event_result="认证失败",
                    ),
                ),
                (
                    4,
                    _record(
                        "工程部",
                        "E003",
                        "李四",
                        "135387",
                        "2026-07-17 08:10:00",
                        "1#2F人行道闸出口3",
                        event_result="黑名单拦截",
                    ),
                ),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "这份考勤数据中，有没有‘认证失败’或‘黑名单拦截’的打卡记录？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None
    assert result.answer.answer.startswith("有。")
    assert "共发现 2 条" in result.answer.answer
    assert "认证失败" in result.answer.answer
    assert "黑名单拦截" in result.answer.answer
    assert "[worksheet:" not in result.answer.answer
    assert result.answer.table is not None
    assert result.answer.table.columns == ("检查条件", "匹配数量", "结论")
    assert result.answer.table.rows == (
        ("认证失败", "1 条", "已发现"),
        ("黑名单拦截", "1 条", "已发现"),
    )
    assert "完整扫描 3 条打卡记录" in result.answer.hits[0].excerpt
    assert "命中行：3、4" in result.answer.hits[0].excerpt
    assert result.answer.hits[0].source_path is not None
    assert result.answer.hits[0].source_path.endswith("#worksheet:Sheet1!K2:K4")


@pytest.mark.asyncio
async def test_event_result_existence_returns_grounded_zero_not_success_false_positive(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", "刘春耀", "1", "2026-07-17 08:00:00", "东门")),
                (3, _record("研发部", "E002", "张三", "2", "2026-07-17 08:05:00", "西门")),
            )
        ),
        title="测试.xlsx",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "这份考勤数据中，有没有‘认证失败’或‘黑名单拦截’的打卡记录？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None
    assert result.answer.answer.startswith("没有。")
    assert "已完整扫描 2 条打卡记录" in result.answer.answer
    assert "共 0 条" in result.answer.answer
    assert "认证成功" not in result.answer.answer
    assert "整理如下" not in result.answer.answer
    assert result.answer.table is not None
    assert result.answer.table.rows == (
        ("认证失败", "0 条", "未发现"),
        ("黑名单拦截", "0 条", "未发现"),
    )
    assert len(result.answer.hits) == 1
    assert result.answer.hits[0].title == "测试.xlsx"
    assert "确定性全量统计" in result.answer.hits[0].excerpt
    assert "完整扫描 2 条打卡记录" in result.answer.hits[0].excerpt
    assert "认证成功" not in result.answer.hits[0].excerpt
    assert result.answer.hits[0].source_path is not None
    assert result.answer.hits[0].source_path.endswith("#worksheet:Sheet1!K2:K3")


@pytest.mark.asyncio
async def test_event_result_existence_uses_or_semantics(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (
                    2,
                    _record(
                        "工程部",
                        "E001",
                        "刘春耀",
                        "1",
                        "2026-07-17 08:00:00",
                        "东门",
                        event_result="认证失败(凭证失效)",
                    ),
                ),
                (3, _record("研发部", "E002", "张三", "2", "2026-07-17 08:05:00", "西门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中是否有认证失败或黑名单拦截记录？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert "共发现 1 条" in result.answer.answer
    assert result.answer.table.rows == (
        ("认证失败", "1 条", "已发现"),
        ("黑名单拦截", "0 条", "未发现"),
    )


@pytest.mark.asyncio
async def test_event_result_existence_with_incomplete_result_column_fails_closed(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    incomplete = list(_record("研发部", "E001", "张三", "1", "2026-07-17 08:00:00", "东门"))
    incomplete[-1] = ""
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, tuple(incomplete)),)),  # type: ignore[arg-type]
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中是否存在认证失败或黑名单拦截记录？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None
    assert result.rejection_message == "当前表格证据不足或存在歧义，无法安全计算答案。"


@pytest.mark.parametrize(
    "question",
    (
        "门禁黑名单管理制度是否存在？",
        "考勤黑名单管理制度是否存在？",
        "考勤制度中是否存在‘黑名单拦截’条款？",
    ),
)
@pytest.mark.asyncio
async def test_blacklist_policy_question_does_not_trigger_spreadsheet_scan(question: str) -> None:
    session = MagicMock(spec=AsyncSession)
    session.scalars = AsyncMock()

    result = await evaluate_spreadsheet_query(
        session,
        UUID("00000000-0000-0000-0000-000000000001"),
        question,
    )

    assert result.status is SpreadsheetQueryStatus.NOT_APPLICABLE
    session.scalars.assert_not_awaited()


@pytest.mark.parametrize(
    "question",
    (
        "考勤记录里有认证失败吗？",
        "考勤记录是否包含认证失败？",
        "考勤记录中是否出现过黑名单拦截？",
        "考勤记录中存在‘认证失败’记录吗？",
    ),
)
def test_event_result_existence_recognizes_natural_question_variants(question: str) -> None:
    assert is_spreadsheet_query_intent(question) is True


@pytest.mark.parametrize(
    "question",
    (
        "研发部考勤记录中有没有认证失败？",
        "销售部考勤记录中有没有认证失败？",
        "2026年7月17日考勤记录中有没有认证失败？",
        "刘春耀的考勤记录中有没有认证失败？",
        "东门考勤记录中有没有认证失败？",
        "今天考勤记录中有没有认证失败？",
        "上午考勤记录中有没有认证失败？",
        "工号E001的考勤记录中有没有认证失败？",
        "卡号1的考勤记录中有没有认证失败？",
        "前1条考勤记录中有没有认证失败？",
        "夜班考勤记录中有没有认证失败？",
    ),
)
@pytest.mark.asyncio
async def test_event_result_existence_rejects_unimplemented_record_filter(
    knowledge_session: tuple[AsyncSession, UUID],
    question: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (
                    2,
                    _record(
                        "工程部",
                        "E001",
                        "刘春耀",
                        "1",
                        "2026-07-17 08:00:00",
                        "东门",
                        event_result="认证失败",
                    ),
                ),
                (3, _record("研发部", "E002", "张三", "2", "2026-07-17 08:05:00", "西门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        question,
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_event_result_existence_uses_only_attendance_sheets(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:考勤!A1] 姓名",
            "[worksheet:考勤!B1] 时间",
            "[worksheet:考勤!C1] 设备",
            "[worksheet:考勤!D1] 事件结果",
            "[worksheet:考勤!A2] 刘春耀",
            "[worksheet:考勤!B2] 2026-07-17 08:00:00",
            "[worksheet:考勤!C2] 东门",
            "[worksheet:考勤!D2] 认证成功(白名单验证)",
            "[worksheet:员工主数据!A1] 姓名",
            "[worksheet:员工主数据!B1] 人员工号",
            "[worksheet:员工主数据!A2] 刘春耀",
            "[worksheet:员工主数据!B2] E001",
            "[worksheet:项目审批!A1] 时间",
            "[worksheet:项目审批!B1] 事件结果",
            "[worksheet:项目审批!A2] 2026-07-17 09:00:00",
            "[worksheet:项目审批!B2] 黑名单拦截",
        )
    )
    await _add_entry(session, knowledge_base_id, content, title="多工作表.xlsx")
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有没有认证失败或黑名单拦截？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None
    assert result.answer.answer.startswith("没有。")
    assert "已完整扫描 1 条打卡记录" in result.answer.answer
    assert result.answer.hits[0].source_path is not None
    assert result.answer.hits[0].source_path.endswith("#worksheet:考勤!D2")


@pytest.mark.asyncio
async def test_event_result_existence_does_not_match_negated_status_text(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (
                    2,
                    _record(
                        "工程部",
                        "E001",
                        "刘春耀",
                        "1",
                        "2026-07-17 08:00:00",
                        "东门",
                        event_result="非黑名单验证通过",
                    ),
                ),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有没有黑名单拦截？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.answer.startswith("没有。")
    assert result.answer.table.rows == (("黑名单拦截", "0 条", "未发现"),)


@pytest.mark.asyncio
async def test_event_result_terms_ignore_quoted_workbook_name_and_quoted_question_clause(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E001", "刘春耀", "1", "2026-07-17 08:00:00", "东门")),)),
        title="考勤异常记录.xlsx",
    )
    await session.commit()

    workbook = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "“考勤异常记录.xlsx”中的考勤数据，有没有认证失败或黑名单拦截？",
    )
    clause = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤数据中“有没有认证失败或黑名单拦截”的记录？",
    )

    assert workbook is not None and workbook.table is not None
    assert clause is not None and clause.table is not None
    expected = (
        ("认证失败", "0 条", "未发现"),
        ("黑名单拦截", "0 条", "未发现"),
    )
    assert workbook.table.rows == expected
    assert clause.table.rows == expected


@pytest.mark.asyncio
async def test_event_result_terms_ignore_unquoted_workbook_name_status_words(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (
                    2,
                    _record(
                        "工程部",
                        "E001",
                        "刘春耀",
                        "1",
                        "2026-07-17 08:00:00",
                        "东门",
                        event_result="认证失败",
                    ),
                ),
            )
        ),
        title="认证失败记录.xlsx",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "认证失败记录.xlsx中的考勤数据，有没有黑名单拦截？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.answer.startswith("没有。")
    assert result.answer.table.rows == (("黑名单拦截", "0 条", "未发现"),)


@pytest.mark.parametrize(
    ("title", "question", "expected_terms"),
    (
        (
            "认证失败.xlsx",
            "这份考勤数据中有没有认证失败或黑名单拦截记录？",
            ("认证失败", "黑名单拦截"),
        ),
        (
            "认证失败记录.xlsx",
            "这份考勤数据中有没有认证失败记录？",
            ("认证失败",),
        ),
    ),
)
@pytest.mark.asyncio
async def test_workbook_title_stem_does_not_remove_real_status_term(
    knowledge_session: tuple[AsyncSession, UUID],
    title: str,
    question: str,
    expected_terms: tuple[str, ...],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E001", "刘春耀", "1", "2026-07-17 08:00:00", "东门")),)),
        title=title,
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(session, knowledge_base_id, question)

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert tuple(row[0] for row in result.answer.table.rows) == expected_terms


@pytest.mark.parametrize(
    "question",
    (
        "考勤流程.xlsx中的考勤记录有没有认证失败？",
        "旧测试.xlsx中的考勤记录有没有认证失败？",
        "测试.csv中的考勤记录有没有认证失败？",
    ),
)
@pytest.mark.asyncio
async def test_single_workbook_rejects_explicit_unknown_filename(
    knowledge_session: tuple[AsyncSession, UUID],
    question: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E001", "刘春耀", "1", "2026-07-17 08:00:00", "东门")),)),
        title="测试.xlsx",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        question,
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_source_title_without_extension_accepts_exact_xlsx_reference(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E001", "刘春耀", "1", "2026-07-17 08:00:00", "东门")),)),
        title="测试",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "请查看这份测试.xlsx中的考勤记录有没有认证失败？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None
    assert result.answer.answer.startswith("没有。")


@pytest.mark.asyncio
async def test_policy_word_inside_workbook_name_does_not_disable_structured_query(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E001", "刘春耀", "1", "2026-07-17 08:00:00", "东门")),)),
        title="考勤制度导出表.xlsx",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤制度导出表.xlsx中有没有认证失败记录？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None
    assert result.answer.answer.startswith("没有。")


@pytest.mark.asyncio
async def test_event_result_coverage_merges_many_sheets_into_one_citation(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    lines: list[str] = []
    for index in range(1, 22):
        sheet = f"考勤{index:02d}"
        lines.extend(
            (
                f"[worksheet:{sheet}!A1] 时间",
                f"[worksheet:{sheet}!B1] 设备",
                f"[worksheet:{sheet}!C1] 事件结果",
                f"[worksheet:{sheet}!D1] 人员工号",
                f"[worksheet:{sheet}!A2] 2026-07-17 08:00:{index:02d}",
                f"[worksheet:{sheet}!B2] 东门{index:02d}",
                f"[worksheet:{sheet}!C2] 认证成功(白名单验证)",
                f"[worksheet:{sheet}!D2] E{index:04d}",
            )
        )
    await _add_entry(session, knowledge_base_id, "\n\n".join(lines), title="多表考勤.xlsx")
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有没有认证失败或黑名单拦截？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None
    assert "已完整扫描 21 条打卡记录" in result.answer.answer
    assert len(result.answer.hits) == 1
    assert result.answer.table is not None
    assert result.answer.table.citation_numbers == (1,)


@pytest.mark.asyncio
async def test_department_deduplicates_repeated_employee_records(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    employee = _record("研发部", "EFD001", "张三", "1001", "2026-07-17 08:00:00", "东门")
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, employee), (8, employee))),
    )
    await session.commit()

    result = await answer_spreadsheet_query(session, knowledge_base_id, "研发部共有哪几位员工？")

    assert result is not None and result.table is not None
    assert result.table.columns == ("人员工号", "员工姓名")
    assert result.table.rows == (("EFD001", "张三"),)
    assert result.answer.startswith("研发部在考勤记录中共有 1 位员工")
    assert "!A2]" in result.hits[0].excerpt
    assert "!A8]" not in result.hits[0].excerpt


@pytest.mark.asyncio
async def test_time_queries_sort_out_of_order_rows_and_span_dates(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("研发部", "E3", "王五", "3", "2026-07-18 00:01:00", "南门")),
                (9, _record("研发部", "E1", "张三", "1", "2026-07-16 23:59:00", "东门")),
                (4, _record("研发部", "E2", "李四", "2", "2026-07-17 12:00:00", "西门")),
            )
        ),
    )
    await session.commit()

    date_range = await answer_spreadsheet_query(
        session, knowledge_base_id, "这份考勤记录的时间范围是什么？"
    )
    latest = await answer_spreadsheet_query(
        session, knowledge_base_id, "2026-07-17最晚的打卡记录是谁？"
    )

    assert date_range is not None
    assert "2026年7月16日至2026年7月18日" in date_range.answer
    assert "!A9]" in date_range.hits[0].excerpt
    assert "!A2]" in date_range.hits[0].excerpt
    assert latest is not None
    assert "李四，于12时00分通过“西门”" in latest.answer


@pytest.mark.asyncio
async def test_conflicting_employee_identifier_and_tied_latest_record_return_none(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("研发部", "E1", "张三", "1", "2026-07-17 23:00:00", "东门")),
                (3, _record("研发部", "E2", "张三", "1", "2026-07-17 22:00:00", "东门")),
                (4, _record("研发部", "E3", "李四", "2", "2026-07-17 23:00:00", "西门")),
            )
        ),
    )
    await session.commit()

    identifier = await answer_spreadsheet_query(
        session, knowledge_base_id, "员工张三的人员工号是多少？"
    )
    latest = await answer_spreadsheet_query(
        session, knowledge_base_id, "2026年7月17日最晚打卡记录是谁？"
    )

    assert identifier is None
    assert latest is None


@pytest.mark.asyncio
async def test_ambiguous_header_and_unpublished_sources_are_not_answered(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    ambiguous_headers = (
        "组织",
        "部门",
        "人员工号",
        "员工工号",
        "姓名",
        "时间",
        "设备",
        "门编号",
        "设备描述",
        "事件类型",
        "事件结果",
    )
    values: RowValues = (
        "和熠",
        "研发部",
        "E1",
        "E2",
        "张三",
        "2026-07-17 08:00:00",
        "东门",
        "1",
        "东门",
        "普通消息",
        "成功",
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, values),), headers=ambiguous_headers),
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((3, _record("研发部", "SECRET", "王五", "9", "2026-07-17 09:00:00", "西门")),)),
        title="draft.xlsx",
        publication_status=KnowledgeEntryPublicationStatus.DRAFT,
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((4, _record("研发部", "DELETED", "赵六", "8", "2026-07-17 10:00:00", "南门")),)),
        title="deleted.xlsx",
        deleted_at=datetime.now(UTC),
    )
    await session.commit()

    ambiguous = await answer_spreadsheet_query(
        session, knowledge_base_id, "员工张三的人员工号是多少？"
    )
    draft = await answer_spreadsheet_query(session, knowledge_base_id, "员工王五的人员工号是多少？")
    deleted = await answer_spreadsheet_query(
        session, knowledge_base_id, "员工赵六的人员工号是多少？"
    )

    assert ambiguous is None
    assert draft is None
    assert deleted is None


@pytest.mark.parametrize(
    "question",
    (
        "公司的联系方式是什么？",
        "公司的工号管理制度是什么？",
        "项目实施的时间范围是什么？",
        "研发部总共有多少项目？",
    ),
)
@pytest.mark.asyncio
async def test_unrelated_question_does_not_query_spreadsheet_entries(question: str) -> None:
    session = MagicMock(spec=AsyncSession)
    session.scalars = AsyncMock()

    result = await answer_spreadsheet_query(
        session, UUID("00000000-0000-0000-0000-000000000001"), question
    )

    assert result is None
    session.scalars.assert_not_awaited()


@pytest.mark.asyncio
async def test_question_requesting_employee_id_and_card_number_is_rejected(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "E001", "张三", "1001", "2026-07-17 08:00:00", "东门")),)),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session, knowledge_base_id, "张三的工号和卡号分别是多少？"
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None
    assert result.rejection_message == "当前表格证据不足或存在歧义，无法安全计算答案。"


@pytest.mark.asyncio
async def test_department_with_more_than_fifty_employees_fails_closed(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    rows = tuple(
        (
            index + 2,
            _record(
                "研发部",
                f"E{index:03d}",
                f"员工{index:03d}",
                str(10_000 + index),
                f"2026-07-17 08:{index % 60:02d}:00",
                "东门",
            ),
        )
        for index in range(51)
    )
    await _add_entry(session, knowledge_base_id, _content(rows))
    await session.commit()

    result = await answer_spreadsheet_query(session, knowledge_base_id, "研发部共有哪几位员工？")

    assert result is None


@pytest.mark.asyncio
async def test_real_parser_locators_and_reordered_headers_map_to_the_exact_row(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    """The parser emits locator/value pairs, not a conventional row serialization."""

    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:考勤 明细 2026!A3] 姓名",
            "[worksheet:考勤 明细 2026!B3] 卡号",
            "[worksheet:考勤 明细 2026!C3] 设备",
            "[worksheet:考勤 明细 2026!D3] 人员工号",
            "[worksheet:考勤 明细 2026!E3] 时间",
            "[worksheet:考勤 明细 2026!F3] 部门",
            "[worksheet:考勤 明细 2026!F9] 生产部",
            "[worksheet:考勤 明细 2026!D9] EFD2410053",
            "[worksheet:考勤 明细 2026!A9] 熊小强",
            "[worksheet:考勤 明细 2026!E9] 2026-07-17 23:00:43",
            "[worksheet:考勤 明细 2026!C9] 1#2F人行道闸出口6",
            "[worksheet:考勤 明细 2026!B9] 135265",
            # A different row must never leak into this lookup's citation.
            "[worksheet:考勤 明细 2026!A10] 其他员工",
            "[worksheet:考勤 明细 2026!D10] OTHER-ID",
        )
    )
    await _add_entry(session, knowledge_base_id, content, title="真实解析结果.xlsx")
    await session.commit()

    result = await answer_spreadsheet_query(
        session, knowledge_base_id, "员工“熊小强”的人员工号是多少？"
    )

    assert result is not None
    assert result.answer == "员工“熊小强”的人员工号是 EFD2410053。[1]"
    assert len(result.hits) == 1
    assert result.hits[0].source_path is not None
    assert result.hits[0].source_path.endswith("#worksheet:考勤 明细 2026!A9:F9")
    assert "[worksheet:考勤 明细 2026!A9] 熊小强" in result.hits[0].excerpt
    assert "OTHER-ID" not in result.hits[0].excerpt
    assert "[worksheet:" not in result.answer


@pytest.mark.asyncio
async def test_department_keeps_same_name_with_distinct_employee_ids_as_two_people(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    """Roster identity is employee-id + name; a name alone is not a unique key."""

    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("研发部", "E001", "张伟", "1001", "2026-07-17 08:00:00", "东门")),
                # Exact duplicate of E001 must be deduplicated.
                (3, _record("研发部", "E001", "张伟", "1001", "2026-07-17 18:00:00", "东门")),
                # A distinct employee may legitimately have the same display name.
                (4, _record("研发部", "E002", "张伟", "1002", "2026-07-17 09:00:00", "西门")),
            )
        ),
    )
    await session.commit()

    result = await answer_spreadsheet_query(
        session, knowledge_base_id, "研发部总共有哪几位员工在考勤记录中？"
    )

    assert result is not None and result.table is not None
    assert "共有 2 位员工" in result.answer
    assert result.table.columns == ("人员工号", "员工姓名")
    assert result.table.rows == (("E001", "张伟"), ("E002", "张伟"))
    assert "!A2]" in result.hits[0].excerpt
    assert "!A3]" not in result.hits[0].excerpt
    assert "!A4]" in result.hits[0].excerpt


@pytest.mark.asyncio
async def test_multiple_workbooks_fail_closed_instead_of_silently_merging_corpora(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((7, _record("研发部", "E002", "李四", "2", "2026-07-17 09:00:00", "西门")),)),
        title="B-考勤.xlsx",
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((5, _record("研发部", "E001", "张三", "1", "2026-07-17 08:00:00", "东门")),)),
        title="A-考勤.xlsx",
    )
    await session.commit()

    result = await answer_spreadsheet_query(
        session, knowledge_base_id, "研发部总共有哪几位员工在考勤记录中？"
    )

    assert result is None


@pytest.mark.asyncio
async def test_identical_workbooks_with_different_titles_are_deduplicated(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = _content(
        ((2, _record("研发部", "E001", "张三", "1", "2026-07-17 08:00:00", "东门")),)
    )
    await _add_entry(session, knowledge_base_id, content, title="考勤副本-A.xlsx")
    await _add_entry(session, knowledge_base_id, content, title="考勤副本-B.xlsx")
    await session.commit()

    result = await answer_spreadsheet_query(session, knowledge_base_id, "张三的人员工号是多少？")

    assert result is not None
    assert result.answer.endswith("[1]")
    assert len(result.hits) == 1
    assert result.hits[0].title == "考勤副本-A.xlsx"
    assert result.hits[0].source_path is not None
    assert result.hits[0].source_path.endswith("#worksheet:Sheet1!A2:K2")


@pytest.mark.asyncio
async def test_explicit_unique_workbook_title_selects_only_that_source(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "JUNE-ID", "张三", "1", "2026-06-17 08:00:00", "东门")),)),
        title="六月考勤.xlsx",
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "JULY-ID", "张三", "1", "2026-07-17 08:00:00", "西门")),)),
        title="七月考勤.xlsx",
    )
    await session.commit()

    result = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "在七月考勤.xlsx中，张三的人员工号是多少？",
    )

    assert result is not None
    assert "JULY-ID" in result.answer
    assert "JUNE-ID" not in result.answer
    assert tuple(hit.title for hit in result.hits) == ("七月考勤.xlsx",)


@pytest.mark.asyncio
async def test_singular_time_range_does_not_silently_merge_multiple_workbooks(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    """For “this record”, either fail closed or explicitly disclose corpus aggregation."""

    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "E001", "张三", "1", "2026-07-01 08:00:00", "东门")),)),
        title="六月考勤.xlsx",
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "E002", "李四", "2", "2026-07-31 08:00:00", "西门")),)),
        title="七月考勤.xlsx",
    )
    await session.commit()

    result = await answer_spreadsheet_query(
        session, knowledge_base_id, "这份考勤记录涵盖的时间范围是什么？"
    )

    assert result is None or (
        len(result.hits) == 2 and ("2 份" in result.answer or "两份" in result.answer)
    )


@pytest.mark.asyncio
async def test_cross_kb_draft_deleted_and_non_xlsx_entries_never_affect_answer(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            ((2, _record("研发部", "LOCAL", "隔离用户", "1", "2026-07-17 08:00:00", "东门")),)
        ),
        title="local.xlsx",
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            ((3, _record("研发部", "DRAFT", "隔离用户", "1", "2026-07-17 09:00:00", "西门")),)
        ),
        title="draft.xlsx",
        publication_status=KnowledgeEntryPublicationStatus.DRAFT,
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            ((4, _record("研发部", "DELETED", "隔离用户", "1", "2026-07-17 10:00:00", "南门")),)
        ),
        title="deleted.xlsx",
        deleted_at=datetime.now(UTC),
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (
                    5,
                    _record(
                        "研发部", "WRONG-PARSER", "隔离用户", "1", "2026-07-17 11:00:00", "北门"
                    ),
                ),
            )
        ),
        title="not-xlsx.txt",
        source_parser="utf8-txt",
    )

    foreign_user = User(email="foreign-spreadsheet@example.com", password_hash="hash")
    session.add(foreign_user)
    await session.flush()
    foreign_kb = KnowledgeBase(owner_id=foreign_user.id, name="foreign")
    session.add(foreign_kb)
    await session.flush()
    await _add_entry(
        session,
        foreign_kb.id,
        _content(
            ((6, _record("研发部", "FOREIGN", "隔离用户", "1", "2026-07-17 12:00:00", "外部")),)
        ),
        title="foreign.xlsx",
    )
    await session.commit()

    local = await answer_spreadsheet_query(session, knowledge_base_id, "隔离用户的人员工号是多少？")
    foreign = await answer_spreadsheet_query(session, foreign_kb.id, "隔离用户的人员工号是多少？")

    assert local is not None and "LOCAL" in local.answer
    assert "DRAFT" not in local.answer
    assert "DELETED" not in local.answer
    assert "WRONG-PARSER" not in local.answer
    assert "FOREIGN" not in local.answer
    assert foreign is not None and "FOREIGN" in foreign.answer


@pytest.mark.asyncio
async def test_tied_latest_same_person_on_different_devices_fails_closed(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("研发部", "E001", "张三", "1", "2026-07-17 23:59:00", "东门")),
                (3, _record("研发部", "E001", "张三", "1", "2026-07-17 23:59:00", "西门")),
            )
        ),
    )
    await session.commit()

    result = await answer_spreadsheet_query(
        session, knowledge_base_id, "2026年7月17日当天最后一条打卡记录是什么？"
    )

    assert result is None


@pytest.mark.asyncio
async def test_unrelated_phrase_containing_the_character_bu_does_not_scan_workbooks() -> None:
    """“全部” contains 部 but is not a department-roster query."""

    session = MagicMock(spec=AsyncSession)
    session.scalars = AsyncMock()

    result = await answer_spreadsheet_query(
        session,
        UUID("00000000-0000-0000-0000-000000000001"),
        "请介绍一下全部员工福利政策。",
    )

    assert result is None
    session.scalars.assert_not_awaited()


@pytest.mark.asyncio
async def test_locator_missing_from_parser_metadata_fails_closed(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    """Generated entry text cannot mint evidence locators absent from parser metadata."""

    session, knowledge_base_id = knowledge_session
    entry = await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "E001", "张三", "1", "2026-07-17 08:00:00", "东门")),)),
    )
    # Simulate a forged locator introduced after deterministic parsing. The whitelist
    # intentionally remains unchanged.
    entry.content += "\n\n[worksheet:Sheet1!C999] FORGED-ID"
    await session.commit()

    result = await answer_spreadsheet_query(session, knowledge_base_id, "张三的人员工号是多少？")

    assert result is None


@pytest.mark.asyncio
async def test_production_truncated_locator_metadata_reconstructs_later_rows(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    """Production stores only the first 2,048 source locations for dense sheets."""

    session, knowledge_base_id = knowledge_session
    rows = tuple(
        (
            row_number,
            _record(
                "研发部",
                f"E{row_number:04d}",
                f"员工{row_number:04d}",
                str(100_000 + row_number),
                f"2026-07-17 08:{row_number % 60:02d}:00",
                "东门",
            ),
        )
        for row_number in range(2, 192)
    )
    entry = await _add_entry(session, knowledge_base_id, _content(rows))
    saved_locations = entry.custom_metadata["source_locations"]
    assert isinstance(saved_locations, list)
    assert len(saved_locations) == 2_048
    assert entry.custom_metadata["source_location_count"] > 2_048
    assert entry.custom_metadata["source_locations_truncated"] is True
    await session.commit()

    result = await answer_spreadsheet_query(
        session, knowledge_base_id, "员工0191的人员工号是多少？"
    )

    assert result is not None
    assert "E0191" in result.answer
    assert result.hits[0].source_path is not None
    assert result.hits[0].source_path.endswith("#worksheet:Sheet1!A191:K191")


@pytest.mark.asyncio
async def test_event_result_existence_scans_beyond_truncated_locator_prefix(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    rows = tuple(
        (
            row_number,
            _record(
                "研发部",
                f"E{row_number:04d}",
                f"员工{row_number:04d}",
                str(100_000 + row_number),
                f"2026-07-17 08:{row_number % 60:02d}:00",
                "东门",
                event_result="黑名单拦截" if row_number == 191 else "认证成功(白名单验证)",
            ),
        )
        for row_number in range(2, 192)
    )
    entry = await _add_entry(session, knowledge_base_id, _content(rows))
    assert entry.custom_metadata["source_locations_truncated"] is True
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中是否有认证失败或黑名单拦截记录？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert "已完整扫描 190 条打卡记录" in result.answer.answer
    assert "共发现 1 条" in result.answer.answer
    assert result.answer.table.rows == (
        ("认证失败", "0 条", "未发现"),
        ("黑名单拦截", "1 条", "已发现"),
    )
    assert result.answer.hits[0].source_path is not None
    assert result.answer.hits[0].source_path.endswith("#worksheet:Sheet1!K2:K191")
    assert "命中行：191" in result.answer.hits[0].excerpt


@pytest.mark.asyncio
async def test_legacy_truncated_local_metadata_fails_closed(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    """A retained prefix alone cannot authenticate cells beyond location 2,048."""

    session, knowledge_base_id = knowledge_session
    rows = tuple(
        (
            row_number,
            _record(
                "研发部",
                f"E{row_number:04d}",
                f"员工{row_number:04d}",
                str(100_000 + row_number),
                f"2026-07-17 08:{row_number % 60:02d}:00",
                "东门",
            ),
        )
        for row_number in range(2, 192)
    )
    entry = await _add_entry(session, knowledge_base_id, _content(rows))
    legacy_metadata = dict(entry.custom_metadata)
    for key in (
        "source_location_count",
        "source_locations_truncated",
        "source_text_length",
        "source_text_sha256",
        "source_locations_sha256",
    ):
        legacy_metadata.pop(key)
    entry.custom_metadata = legacy_metadata
    await session.commit()

    result = await answer_spreadsheet_query(
        session, knowledge_base_id, "员工0191的人员工号是多少？"
    )

    assert result is None


@pytest.mark.asyncio
async def test_event_result_existence_with_legacy_truncated_metadata_fails_closed(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    rows = tuple(
        (
            row_number,
            _record(
                "研发部",
                f"E{row_number:04d}",
                f"员工{row_number:04d}",
                str(100_000 + row_number),
                f"2026-07-17 08:{row_number % 60:02d}:00",
                "东门",
            ),
        )
        for row_number in range(2, 192)
    )
    entry = await _add_entry(session, knowledge_base_id, _content(rows))
    legacy_metadata = dict(entry.custom_metadata)
    for key in (
        "source_location_count",
        "source_locations_truncated",
        "source_text_length",
        "source_text_sha256",
        "source_locations_sha256",
    ):
        legacy_metadata.pop(key)
    entry.custom_metadata = legacy_metadata
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中是否有认证失败或黑名单拦截记录？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None
    assert result.rejection_message == "当前表格证据不足或存在歧义，无法安全计算答案。"


@pytest.mark.asyncio
async def test_external_model_rewritten_sheet_is_not_treated_as_deterministic_evidence(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    """A locator whitelist authenticates coordinates, not model-rewritten values."""

    session, knowledge_base_id = knowledge_session
    entry = await _add_entry(
        session,
        knowledge_base_id,
        _content(
            ((2, _record("研发部", "MODEL-VALUE", "张三", "1", "2026-07-17 08:00:00", "东门")),)
        ),
    )
    entry.custom_metadata = {
        **entry.custom_metadata,
        "generator": {
            "provider": "deepseek",
            "model": "deepseek-chat",
            "prompt_version": "okf-v1",
        },
    }
    await session.commit()

    result = await answer_spreadsheet_query(session, knowledge_base_id, "张三的人员工号是多少？")

    assert result is None


@pytest.mark.asyncio
async def test_overlong_cell_fails_closed_without_returning_oversized_evidence(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            ((2, _record("研发部", "E001", "张三", "1", "2026-07-17 08:00:00", "X" * 1_001)),)
        ),
    )
    await session.commit()

    result = await answer_spreadsheet_query(session, knowledge_base_id, "张三的人员工号是多少？")

    assert result is None


@pytest.mark.asyncio
async def test_citation_source_path_remains_within_database_schema_limit(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    entry = await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "E001", "张三", "1", "2026-07-17 08:00:00", "东门")),)),
    )
    entry.source_path = "s" * 1_000
    await session.commit()

    result = await answer_spreadsheet_query(session, knowledge_base_id, "张三的人员工号是多少？")

    assert result is not None
    assert result.hits[0].source_path is not None
    assert len(result.hits[0].source_path) <= 1_000
    assert result.hits[0].source_path.endswith("#worksheet:Sheet1!A2:K2")
