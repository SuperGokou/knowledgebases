from __future__ import annotations

import re
import unicodedata
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from hashlib import sha256
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import (
    AuditLog,
    AuditResult,
    File,
    FileStatus,
    KnowledgeBase,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
    KnowledgeIngestionStatus,
    MalwareScanStatus,
    OkfConversionJob,
    OkfConversionStatus,
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
    knowledge_base = await session.get(KnowledgeBase, knowledge_base_id)
    assert knowledge_base is not None
    source_file = File(
        owner_id=knowledge_base.owner_id,
        knowledge_base_id=knowledge_base_id,
        bucket="kb",
        object_key=f"objects/spreadsheet-query/{uuid4()}.xlsx",
        original_name=title,
        extension=".xlsx",
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        size_bytes=len(content.encode("utf-8")),
        status=FileStatus.AVAILABLE,
        knowledge_status=KnowledgeIngestionStatus.INDEXED,
        malware_scan_status=MalwareScanStatus.CLEAN,
        available_at=datetime.now(UTC),
    )
    session.add(source_file)
    await session.flush()
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
        source_file_id=source_file.id,
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
    session.add_all(
        (
            OkfConversionJob(
                file_id=source_file.id,
                knowledge_base_id=knowledge_base_id,
                file_version=source_file.version,
                status=OkfConversionStatus.SUCCEEDED,
                prompt_version="okf-v1",
                output_entry_id=entry.id,
                completed_at=datetime.now(UTC),
            ),
            AuditLog(
                actor_id=knowledge_base.owner_id,
                action="file.approved",
                result=AuditResult.SUCCESS,
                resource_type="file",
                resource_id=str(source_file.id),
            ),
        )
    )
    await session.flush()
    return entry


@pytest.mark.asyncio
async def test_self_signed_spreadsheet_entry_without_conversion_job_fails_closed(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    """Self-consistent parser metadata is not proof that the parser produced the entry."""

    session, knowledge_base_id = knowledge_session
    entry = await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "FORGED", "张三", "1", "2026-07-17 08:00:00", "东门")),)),
    )
    conversion = await session.scalar(
        select(OkfConversionJob).where(OkfConversionJob.output_entry_id == entry.id)
    )
    assert conversion is not None
    await session.delete(conversion)
    await session.commit()

    result = await answer_spreadsheet_query(
        session, knowledge_base_id, "员工张三的人员工号是多少？"
    )

    assert result is None


@pytest.mark.asyncio
async def test_successful_manual_entry_update_audit_revokes_deterministic_trust(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    """Historical API edits invalidate an otherwise valid conversion provenance chain."""

    session, knowledge_base_id = knowledge_session
    entry = await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "E001", "张三", "1", "2026-07-17 08:00:00", "东门")),)),
    )
    session.add(
        AuditLog(
            action="knowledge_entry.updated",
            result=AuditResult.SUCCESS,
            resource_type="knowledge_entry",
            resource_id=str(entry.id),
            details={"fields": ["content", "custom_metadata"]},
        )
    )
    await session.commit()

    result = await answer_spreadsheet_query(
        session, knowledge_base_id, "员工张三的人员工号是多少？"
    )

    assert result is None


@pytest.mark.asyncio
async def test_successful_conversion_and_file_approval_provenance_is_accepted(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "E001", "张三", "1", "2026-07-17 08:00:00", "东门")),)),
    )
    await session.commit()

    result = await answer_spreadsheet_query(
        session, knowledge_base_id, "员工张三的人员工号是多少？"
    )

    assert result is not None
    assert "E001" in result.answer


@pytest.mark.asyncio
async def test_legacy_parser_metadata_with_conversion_provenance_remains_supported(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    """Pre-integrity-bundle parser output remains valid when its trusted job chain exists."""

    session, knowledge_base_id = knowledge_session
    entry = await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "E001", "张三", "1", "2026-07-17 08:00:00", "东门")),)),
    )
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
        session, knowledge_base_id, "员工张三的人员工号是多少？"
    )

    assert result is not None
    assert "E001" in result.answer


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
async def test_event_detail_header_supports_production_attendance_exports(
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
                        "东门",
                    ),
                ),
            ),
            headers=(*HEADERS[:-1], "事件详情"),
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
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.answer.startswith("没有。")
    assert result.answer.table.rows == (
        ("认证失败", "0 条", "未发现"),
        ("黑名单拦截", "0 条", "未发现"),
    )


@pytest.mark.asyncio
async def test_employee_frequency_scans_complete_workbook_and_returns_standard_answer(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    winner_rows = tuple(
        (
            row_number,
            _record(
                "生产部",
                "EFD2410053",
                "熊小强",
                "135265",
                f"2026-07-17 {(index // 60):02d}:{(index % 60):02d}:00",
                "东门" if index % 2 == 0 else "西门",
            ),
        )
        for index, row_number in enumerate(range(2, 104))
    )
    other_rows = tuple(
        (
            row_number,
            _record(
                "前工程科",
                "EFD2410061",
                "彭楚亮",
                "135267",
                f"2026-07-17 02:{index:02d}:00",
                "南门",
            ),
        )
        for index, row_number in enumerate(range(104, 107))
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content((*winner_rows, *other_rows)),
        title="测试.xlsx",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "整个数据集中，打卡总次数最多的是哪位员工？总共打卡了多少次？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.answer == (
        "在《测试.xlsx》中已完整扫描 105 条打卡记录，"
        "打卡总次数最多的员工是“熊小强”，共打卡 102 次。[1]"
    )
    assert result.answer.table.title == "员工打卡频次"
    assert result.answer.table.columns == ("人员工号", "员工姓名", "打卡次数")
    assert result.answer.table.rows == (("EFD2410053", "熊小强", "102 次"),)
    assert "完整扫描 105 条打卡记录" in result.answer.hits[0].excerpt
    assert "共 2 位员工" in result.answer.hits[0].excerpt
    assert "“熊小强”（EFD2410053）102 条" in result.answer.hits[0].excerpt
    assert result.answer.hits[0].source_path is not None
    assert result.answer.hits[0].source_path.endswith(
        "#worksheet:Sheet1!C2:C106,worksheet:Sheet1!D2:D106,worksheet:Sheet1!F2:F106"
    )


@pytest.mark.asyncio
async def test_employee_frequency_returns_all_tied_employees(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("生产部", "E002", "熊小强", "2", "2026-07-17 08:00:00", "东门")),
                (3, _record("生产部", "E002", "熊小强", "2", "2026-07-17 09:00:00", "西门")),
                (4, _record("工程部", "E001", "彭楚亮", "1", "2026-07-17 10:00:00", "东门")),
                (5, _record("工程部", "E001", "彭楚亮", "1", "2026-07-17 11:00:00", "西门")),
            )
        ),
        title="测试.xlsx",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "这份考勤数据中，哪位员工打卡次数最多？一共多少次？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert "并列第一：“彭楚亮”（人员工号：E001）、“熊小强”（人员工号：E002）" in (
        result.answer.answer
    )
    assert "各打卡 2 次" in result.answer.answer
    assert result.answer.table.rows == (
        ("E001", "彭楚亮", "2 次"),
        ("E002", "熊小强", "2 次"),
    )


@pytest.mark.parametrize(
    ("first_id", "first_name", "second_id", "second_name"),
    (
        ("E001", "同名员工", "E002", "同名员工"),
        ("E001", "姓名甲", "E001", "姓名乙"),
    ),
)
@pytest.mark.asyncio
async def test_employee_frequency_rejects_ambiguous_employee_identity(
    knowledge_session: tuple[AsyncSession, UUID],
    first_id: str,
    first_name: str,
    second_id: str,
    second_name: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", first_id, first_name, "1", "2026-07-17 08:00:00", "东门")),
                (3, _record("工程部", second_id, second_name, "2", "2026-07-17 09:00:00", "西门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "整个数据集中，打卡总次数最多的是哪位员工？总共打卡了多少次？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.parametrize("placeholder", ("N/A", "#N/A", "NaN", "未设置", "未分配"))
@pytest.mark.asyncio
async def test_employee_frequency_rejects_invalid_employee_names(
    knowledge_session: tuple[AsyncSession, UUID],
    placeholder: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", placeholder, "1", "2026-07-17 08:00:00", "东门")),
                (3, _record("工程部", "E002", "正常员工", "2", "2026-07-17 09:00:00", "西门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "哪位员工打卡次数最多？一共多少次？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.parametrize(
    "question",
    (
        "研发部打卡次数最多的是哪位员工？",
        "2026年7月17日打卡次数最多的是哪位员工？",
        "东门打卡次数最多的是哪位员工？",
        "打卡最多的前3位员工是谁？",
        "打卡次数最少的是哪位员工？",
        "每位员工分别打卡多少次？",
    ),
)
@pytest.mark.asyncio
async def test_employee_frequency_rejects_filters_rankings_and_other_aggregates(
    knowledge_session: tuple[AsyncSession, UUID],
    question: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),)),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(session, knowledge_base_id, question)

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_employee_frequency_aggregates_all_attendance_sheets(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:白班!A1] 人员工号",
            "[worksheet:白班!B1] 姓名",
            "[worksheet:白班!C1] 时间",
            "[worksheet:白班!D1] 设备",
            "[worksheet:白班!A2] E001",
            "[worksheet:白班!B2] 熊小强",
            "[worksheet:白班!C2] 2026-07-17 08:00:00",
            "[worksheet:白班!D2] 东门",
            "[worksheet:白班!A3] E002",
            "[worksheet:白班!B3] 彭楚亮",
            "[worksheet:白班!C3] 2026-07-17 09:00:00",
            "[worksheet:白班!D3] 西门",
            "[worksheet:夜班!A1] 人员工号",
            "[worksheet:夜班!B1] 姓名",
            "[worksheet:夜班!C1] 时间",
            "[worksheet:夜班!D1] 设备",
            "[worksheet:夜班!A2] E001",
            "[worksheet:夜班!B2] 熊小强",
            "[worksheet:夜班!C2] 2026-07-17 20:00:00",
            "[worksheet:夜班!D2] 南门",
            "[worksheet:夜班!A3] E001",
            "[worksheet:夜班!B3] 熊小强",
            "[worksheet:夜班!C3] 2026-07-17 21:00:00",
            "[worksheet:夜班!D3] 北门",
        )
    )
    await _add_entry(session, knowledge_base_id, content, title="多班次.xlsx")
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "整个数据集中，打卡总次数最多的是哪位员工？总共打卡了多少次？",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.rows == (("E001", "熊小强", "3 次"),)
    assert "完整扫描 4 条打卡记录" in answer.answer
    assert answer.hits[0].source_path is not None
    assert "worksheet:白班!A2:A3" in answer.hits[0].source_path
    assert "worksheet:白班!B2:B3" in answer.hits[0].source_path
    assert "worksheet:夜班!A2:A3" in answer.hits[0].source_path
    assert "worksheet:夜班!B2:B3" in answer.hits[0].source_path


@pytest.mark.parametrize(
    "question",
    (
        "整个数据集中，打卡总次数最多的是哪位员工？总共打卡了多少次？",
        "这份考勤数据中，哪位员工打卡次数最多？一共多少次？",
        "所有员工中谁打卡最多？总共多少次？",
    ),
)
def test_employee_frequency_recognizes_supported_question_variants(question: str) -> None:
    assert is_spreadsheet_query_intent(question) is True


@pytest.mark.parametrize(
    "question",
    (
        "员工考勤管理制度是什么？",
        "员工门禁卡如何办理？",
        "公司的人员规模是多少？",
    ),
)
def test_generic_employee_questions_do_not_trigger_spreadsheet_scan(question: str) -> None:
    assert is_spreadsheet_query_intent(question) is False


@pytest.mark.asyncio
async def test_employee_frequency_falls_back_to_card_number_when_employee_id_is_absent(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:Sheet1!A1] 姓名",
            "[worksheet:Sheet1!B1] 卡号",
            "[worksheet:Sheet1!C1] 时间",
            "[worksheet:Sheet1!D1] 设备",
            "[worksheet:Sheet1!A2] 熊小强",
            "[worksheet:Sheet1!B2] 135265",
            "[worksheet:Sheet1!C2] 2026-07-17 08:00:00",
            "[worksheet:Sheet1!D2] 东门",
            "[worksheet:Sheet1!A3] 熊小强",
            "[worksheet:Sheet1!B3] 135265",
            "[worksheet:Sheet1!C3] 2026-07-17 09:00:00",
            "[worksheet:Sheet1!D3] 西门",
            "[worksheet:Sheet1!A4] 彭楚亮",
            "[worksheet:Sheet1!B4] 135267",
            "[worksheet:Sheet1!C4] 2026-07-17 10:00:00",
            "[worksheet:Sheet1!D4] 南门",
        )
    )
    await _add_entry(session, knowledge_base_id, content, title="测试.xlsx")
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "整个数据集中，打卡总次数最多的是哪位员工？总共打卡了多少次？",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.columns == ("卡号", "员工姓名", "打卡次数")
    assert answer.table.rows == (("135265", "熊小强", "2 次"),)
    assert answer.hits[0].source_path is not None
    assert answer.hits[0].source_path.endswith(
        "#worksheet:Sheet1!B2:B4,worksheet:Sheet1!A2:A4,worksheet:Sheet1!C2:C4"
    )


@pytest.mark.parametrize(
    ("employee_id", "employee_name", "timestamp", "device"),
    (
        ("", "熊小强", "2026-07-17 08:00:00", "东门"),
        ("E001", "", "2026-07-17 08:00:00", "东门"),
        ("E001", "熊小强", "", "东门"),
        ("E001", "熊小强", "2026-07-17 08:00:00", ""),
    ),
)
@pytest.mark.asyncio
async def test_employee_frequency_rejects_incomplete_rows(
    knowledge_session: tuple[AsyncSession, UUID],
    employee_id: str,
    employee_name: str,
    timestamp: str,
    device: str,
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
                        employee_id,
                        employee_name,
                        "135265",
                        timestamp,
                        device,
                    ),
                ),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "整个数据集中，打卡总次数最多的是哪位员工？总共打卡了多少次？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_employee_frequency_uses_rows_beyond_truncated_metadata_locator_list(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    rows = tuple(
        (
            row_number,
            _record(
                "工程部",
                "E-WINNER" if row_number >= 202 else f"E{row_number:04d}",
                "熊小强" if row_number >= 202 else f"员工{row_number:04d}",
                "135265" if row_number >= 202 else str(row_number),
                f"2026-07-{((row_number - 2) // (24 * 60)) + 1:02d} "
                f"{((row_number - 2) // 60) % 24:02d}:{(row_number - 2) % 60:02d}:00",
                "东门" if row_number % 2 == 0 else "西门",
            ),
        )
        for row_number in range(2, 252)
    )
    entry = await _add_entry(session, knowledge_base_id, _content(rows), title="大表.xlsx")
    await session.commit()

    assert entry.custom_metadata["source_locations_truncated"] is True
    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "整个数据集中，打卡总次数最多的是哪位员工？总共打卡了多少次？",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.rows == (("E-WINNER", "熊小强", "50 次"),)
    assert answer.hits[0].source_path is not None
    assert answer.hits[0].source_path.endswith(
        "#worksheet:Sheet1!C2:C251,worksheet:Sheet1!D2:D251,worksheet:Sheet1!F2:F251"
    )


@pytest.mark.asyncio
async def test_employee_frequency_rejects_mixed_identifier_schemes_across_sheets(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:白班!A1] 人员工号",
            "[worksheet:白班!B1] 姓名",
            "[worksheet:白班!C1] 时间",
            "[worksheet:白班!D1] 设备",
            "[worksheet:白班!A2] E001",
            "[worksheet:白班!B2] 熊小强",
            "[worksheet:白班!C2] 2026-07-17 08:00:00",
            "[worksheet:白班!D2] 东门",
            "[worksheet:夜班!A1] 卡号",
            "[worksheet:夜班!B1] 姓名",
            "[worksheet:夜班!C1] 时间",
            "[worksheet:夜班!D1] 设备",
            "[worksheet:夜班!A2] 135265",
            "[worksheet:夜班!B2] 熊小强",
            "[worksheet:夜班!C2] 2026-07-17 20:00:00",
            "[worksheet:夜班!D2] 西门",
        )
    )
    await _add_entry(session, knowledge_base_id, content)
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "整个数据集中，打卡总次数最多的是哪位员工？总共打卡了多少次？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_device_frequency_scans_the_complete_device_column(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),
                (3, _record("工程部", "E002", "乙", "2", "2026-07-17 08:05:00", "西门")),
                (4, _record("工程部", "E003", "丙", "3", "2026-07-17 08:10:00", "东门")),
                (5, _record("工程部", "E004", "丁", "4", "2026-07-17 08:15:00", "东门")),
                (6, _record("工程部", "E005", "戊", "5", "2026-07-17 08:20:00", "西门")),
            )
        ),
        title="测试.xlsx",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "在所有闸机设备中，打卡记录最多（使用最频繁）的设备名称是什么？共记录了多少次？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.answer == (
        "在《测试.xlsx》中已完整扫描 5 条打卡记录，使用最频繁的设备是“东门”，共记录 3 次。[1]"
    )
    assert result.answer.table.title == "闸机设备使用频率"
    assert result.answer.table.columns == ("设备名称", "打卡次数")
    assert result.answer.table.rows == (("东门", "3 次"),)
    assert "完整扫描 5 条打卡记录" in result.answer.hits[0].excerpt
    assert "共 2 个设备" in result.answer.hits[0].excerpt
    assert "“东门”3 条" in result.answer.hits[0].excerpt
    assert result.answer.hits[0].source_path is not None
    assert result.answer.hits[0].source_path.endswith("#worksheet:Sheet1!G2:G6")


@pytest.mark.asyncio
async def test_device_frequency_returns_all_tied_winners(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),
                (3, _record("工程部", "E002", "乙", "2", "2026-07-17 08:05:00", "西门")),
                (4, _record("工程部", "E003", "丙", "3", "2026-07-17 08:10:00", "东门")),
                (5, _record("工程部", "E004", "丁", "4", "2026-07-17 08:15:00", "西门")),
            )
        ),
    )
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "哪台门禁设备的打卡次数最多？",
    )

    assert answer is not None and answer.table is not None
    assert "并列第一：“东门”、“西门”，各记录 2 次" in answer.answer
    assert answer.table.rows == (("东门", "2 次"), ("西门", "2 次"))


@pytest.mark.asyncio
async def test_device_frequency_normalizes_equivalent_device_labels(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东 门")),
                (3, _record("工程部", "E002", "乙", "2", "2026-07-17 08:05:00", " 东  门 ")),
                (4, _record("工程部", "E003", "丙", "3", "2026-07-17 08:10:00", "西门")),
            )
        ),
    )
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤设备使用频率最高的是哪一个，共几次？",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.rows == (("东 门", "2 次"),)


@pytest.mark.asyncio
async def test_device_frequency_rejects_incomplete_rows_instead_of_under_counting(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    incomplete = list(_record("工程部", "E002", "乙", "2", "2026-07-17 08:05:00", "西门"))
    incomplete[6] = ""
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),
                (3, tuple(incomplete)),  # type: ignore[arg-type]
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "所有闸机设备中打卡记录最多的是哪个设备？共多少次？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.parametrize("placeholder", ("N/A", "#N/A", "NaN", "未设置", "未分配"))
@pytest.mark.asyncio
async def test_device_frequency_rejects_missing_value_placeholders(
    knowledge_session: tuple[AsyncSession, UUID],
    placeholder: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", placeholder)),
                (3, _record("工程部", "E002", "乙", "2", "2026-07-17 08:05:00", "东门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "哪台闸机打卡次数最多？共多少次？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_device_frequency_uses_rows_beyond_truncated_metadata_locator_list(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    rows = tuple(
        (
            row_number,
            _record(
                "工程部",
                f"E{row_number:04d}",
                f"员工{row_number:04d}",
                str(row_number),
                f"2026-07-17 {((row_number - 2) // 60) % 24:02d}:{(row_number - 2) % 60:02d}:00",
                "后段高频闸机" if row_number >= 202 else f"设备{row_number:04d}",
            ),
        )
        for row_number in range(2, 252)
    )
    entry = await _add_entry(session, knowledge_base_id, _content(rows), title="大表.xlsx")
    await session.commit()

    assert entry.custom_metadata["source_locations_truncated"] is True
    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "在所有闸机设备中，打卡记录最多的设备名称是什么？共记录了多少次？",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.rows == (("后段高频闸机", "50 次"),)
    assert answer.hits[0].source_path is not None
    assert answer.hits[0].source_path.endswith("#worksheet:Sheet1!G2:G251")


@pytest.mark.parametrize(
    "question",
    (
        "在所有闸机设备中，打卡记录最多（使用最频繁）的设备名称是什么？共记录了多少次？",
        "哪台门禁设备的打卡次数最多？",
        "哪台闸机打卡次数最多？共多少次？",
        "考勤设备使用频率最高的是哪一个，共几次？",
        "使用频率最高的门禁设备是哪个？",
        "哪个闸机使用得最频繁？共多少次？",
        "请汇总最常用的闸机以及次数。",
        "打卡量最大的闸机是什么？",
        "闸机打卡次数最高的是哪个？",
        "所有闸机中哪个打卡最多？",
        "这份考勤中使用最多的闸机是哪台？",
    ),
)
def test_device_frequency_recognizes_supported_question_variants(question: str) -> None:
    assert is_spreadsheet_query_intent(question) is True


@pytest.mark.parametrize(
    "question",
    (
        "哪个闸机使用得最频繁？共多少次？",
        "请汇总最常用的闸机以及次数。",
        "打卡量最大的闸机是什么？",
        "闸机打卡次数最高的是哪个？",
        "所有闸机中哪个打卡最多？一共多少次？",
        "这份考勤中使用最多的闸机是哪台？",
    ),
)
@pytest.mark.asyncio
async def test_device_frequency_answers_natural_aggregate_variants(
    knowledge_session: tuple[AsyncSession, UUID],
    question: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),
                (3, _record("工程部", "E002", "乙", "2", "2026-07-17 08:05:00", "东门")),
                (4, _record("工程部", "E003", "丙", "3", "2026-07-17 08:10:00", "西门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(session, knowledge_base_id, question)

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.table.rows == (("东门", "2 次"),)


@pytest.mark.parametrize(
    "question",
    (
        "公司最常使用的生产设备是什么？",
        "目前设备使用频率如何？",
        "闸机设备维护制度是什么？",
    ),
)
def test_generic_device_questions_do_not_trigger_spreadsheet_scan(question: str) -> None:
    assert is_spreadsheet_query_intent(question) is False


@pytest.mark.parametrize(
    "question",
    (
        "研发部打卡记录最多的闸机设备是什么？",
        "2026年7月17日打卡次数最多的设备是什么？",
        "打卡记录最多的前3台闸机设备是什么？",
        "打卡最多的前5台设备有哪些？",
        "闸机设备打卡次数排名是什么？",
        "打卡记录最少的闸机设备是什么？",
        "每台闸机设备分别有多少打卡记录？",
    ),
)
@pytest.mark.asyncio
async def test_device_frequency_rejects_unimplemented_filters_and_rankings(
    knowledge_session: tuple[AsyncSession, UUID],
    question: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),)),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(session, knowledge_base_id, question)

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_device_frequency_aggregates_all_attendance_sheets_in_one_workbook(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:白班!A1] 姓名",
            "[worksheet:白班!B1] 时间",
            "[worksheet:白班!C1] 设备",
            "[worksheet:白班!A2] 甲",
            "[worksheet:白班!B2] 2026-07-17 08:00:00",
            "[worksheet:白班!C2] 东门",
            "[worksheet:白班!A3] 乙",
            "[worksheet:白班!B3] 2026-07-17 08:05:00",
            "[worksheet:白班!C3] 西门",
            "[worksheet:夜班!A1] 姓名",
            "[worksheet:夜班!B1] 时间",
            "[worksheet:夜班!C1] 设备",
            "[worksheet:夜班!A2] 丙",
            "[worksheet:夜班!B2] 2026-07-17 20:00:00",
            "[worksheet:夜班!C2] 东门",
            "[worksheet:夜班!A3] 丁",
            "[worksheet:夜班!B3] 2026-07-17 20:05:00",
            "[worksheet:夜班!C3] 东门",
        )
    )
    await _add_entry(session, knowledge_base_id, content, title="多班次.xlsx")
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "哪台闸机打卡次数最多？共多少次？",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.rows == (("东门", "3 次"),)
    assert "完整扫描 4 条打卡记录" in answer.answer
    assert len(answer.hits) == 1
    assert answer.hits[0].source_path is not None
    assert "worksheet:白班!C2:C3" in answer.hits[0].source_path
    assert "worksheet:夜班!C2:C3" in answer.hits[0].source_path


@pytest.mark.asyncio
async def test_device_frequency_rejects_an_ambiguous_attendance_sheet_in_workbook(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:正常!A1] 姓名",
            "[worksheet:正常!B1] 时间",
            "[worksheet:正常!C1] 设备",
            "[worksheet:正常!A2] 甲",
            "[worksheet:正常!B2] 2026-07-17 08:00:00",
            "[worksheet:正常!C2] 东门",
            "[worksheet:歧义!A1] 姓名",
            "[worksheet:歧义!B1] 时间",
            "[worksheet:歧义!C1] 打卡时间",
            "[worksheet:歧义!D1] 设备",
            "[worksheet:歧义!A2] 乙",
            "[worksheet:歧义!B2] 2026-07-17 08:05:00",
            "[worksheet:歧义!C2] 2026-07-17 08:05:00",
            "[worksheet:歧义!D2] 西门",
        )
    )
    await _add_entry(session, knowledge_base_id, content, title="混合.xlsx")
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "哪台闸机打卡次数最多？共多少次？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_device_frequency_rejects_partial_attendance_sheet_in_workbook(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    valid = "\n\n".join(
        (
            "[worksheet:正常!A1] 姓名",
            "[worksheet:正常!B1] 时间",
            "[worksheet:正常!C1] 设备",
            "[worksheet:正常!A2] 甲",
            "[worksheet:正常!B2] 2026-07-17 08:00:00",
            "[worksheet:正常!C2] 东门",
        )
    )
    partial = "\n\n".join(
        (
            "[worksheet:缺身份!A1] 时间",
            "[worksheet:缺身份!B1] 设备",
            "[worksheet:缺身份!A2] 2026-07-17 08:05:00",
            "[worksheet:缺身份!B2] 西门",
        )
    )
    await _add_entry(session, knowledge_base_id, f"{valid}\n\n{partial}")
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "哪台闸机打卡次数最多？共多少次？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED


@pytest.mark.asyncio
async def test_device_frequency_rejects_bidi_worksheet_name(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        "\n\n".join(
            (
                "[worksheet:safe\u202efake!A1] 姓名",
                "[worksheet:safe\u202efake!B1] 时间",
                "[worksheet:safe\u202efake!C1] 设备",
                "[worksheet:safe\u202efake!A2] 甲",
                "[worksheet:safe\u202efake!B2] 2026-07-17 08:00:00",
                "[worksheet:safe\u202efake!C2] 东门",
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "哪台闸机打卡次数最多？共多少次？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED


@pytest.mark.parametrize(
    ("unsafe_marker", "safe_marker"),
    (("[2]", "［2］"), ("[ 2 ]", "［2］"), ("[0]", "［0］"), ("[-1]", "［-1］")),
)
@pytest.mark.asyncio
async def test_device_frequency_escapes_citation_like_dynamic_labels(
    knowledge_session: tuple[AsyncSession, UUID],
    unsafe_marker: str,
    safe_marker: str,
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
                        "甲",
                        "1",
                        "2026-07-17 08:00:00",
                        f"东门{unsafe_marker}",
                    ),
                ),
            )
        ),
        title=f"测试{unsafe_marker}\n第二行.xlsx",
    )
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "哪台闸机打卡次数最多？共多少次？",
    )

    assert answer is not None and answer.table is not None
    assert f"《测试{safe_marker} 第二行.xlsx》" in answer.answer
    assert f"“东门{safe_marker}”" in answer.answer
    assert answer.answer.count("[1]") == 1
    assert unsafe_marker not in answer.answer
    assert answer.table.rows == ((f"东门{unsafe_marker}", "1 次"),)


@pytest.mark.asyncio
async def test_device_frequency_rejects_multiple_explicit_workbooks(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),)),
        title="一月考勤.xlsx",
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E002", "乙", "2", "2026-07-18 08:00:00", "西门")),)),
        title="二月考勤.xlsx",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "一月考勤.xlsx 和 二月考勤.xlsx 中哪台闸机打卡次数最多？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_common_title_word_does_not_silently_select_one_of_multiple_workbooks(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),)),
        title="测试.xlsx",
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E002", "乙", "2", "2026-07-18 08:00:00", "西门")),)),
        title="设备.xlsx",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "在所有闸机设备中，打卡记录最多的设备是什么？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_department_summary_counts_and_lists_all_departments_with_full_column_evidence(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),
                (3, _record("生产部", "E002", "乙", "2", "2026-07-17 08:05:00", "西门")),
                (4, _record("前工程科", "E003", "丙", "3", "2026-07-17 08:10:00", "东门")),
                (5, _record("整合部", "E004", "丁", "4", "2026-07-17 08:15:00", "南门")),
                (6, _record("研发部", "E005", "戊", "5", "2026-07-17 08:20:00", "北门")),
                (7, _record("电子工程科", "E006", "己", "6", "2026-07-17 08:25:00", "东门")),
                (8, _record("后工程科", "E007", "庚", "7", "2026-07-17 08:30:00", "西门")),
                (9, _record("品质部", "E008", "辛", "8", "2026-07-17 08:35:00", "南门")),
                (10, _record("工程部", "E009", "壬", "9", "2026-07-17 08:40:00", "东门")),
            )
        ),
        title="测试.xlsx",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "这份考勤记录中，一共包含了多少个不同的部门？请列出这些部门的名称。",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.answer == (
        "在《测试.xlsx》中已完整扫描 9 条考勤记录，共包含 8 个不同部门："
        "工程部、生产部、前工程科、整合部、研发部、电子工程科、后工程科、品质部。[1]"
    )
    assert result.answer.table.title == "考勤部门统计"
    assert result.answer.table.columns == ("部门名称",)
    assert result.answer.table.rows == (
        ("工程部",),
        ("生产部",),
        ("前工程科",),
        ("整合部",),
        ("研发部",),
        ("电子工程科",),
        ("后工程科",),
        ("品质部",),
    )
    assert "完整扫描 9 条考勤记录" in result.answer.hits[0].excerpt
    assert "8 个不同部门" in result.answer.hits[0].excerpt
    assert "E001" not in result.answer.hits[0].excerpt
    assert "甲" not in result.answer.hits[0].excerpt
    assert result.answer.hits[0].source_path is not None
    assert result.answer.hits[0].source_path.endswith("#worksheet:Sheet1!B2:B10")


@pytest.mark.asyncio
async def test_department_summary_normalizes_equivalent_labels(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("Ｒ＆Ｄ", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),
                (3, _record("r&d", "E002", "乙", "2", "2026-07-17 08:05:00", "西门")),
                (4, _record("工程　部", "E003", "丙", "3", "2026-07-17 08:10:00", "南门")),
                (5, _record("工程  部", "E004", "丁", "4", "2026-07-17 08:15:00", "北门")),
            )
        ),
    )
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录里有几个不同部门？",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.rows == (("R&D",), ("工程 部",))
    assert "共包含 2 个不同部门" in answer.answer


@pytest.mark.parametrize("placeholder", ("", "N/A", "#N/A", "NaN", "未设置", "未分配"))
@pytest.mark.asyncio
async def test_department_summary_rejects_missing_department_values(
    knowledge_session: tuple[AsyncSession, UUID],
    placeholder: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),
                (3, _record(placeholder, "E002", "乙", "2", "2026-07-17 08:05:00", "西门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有哪些部门？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_department_summary_scans_beyond_truncated_metadata_locator_list(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    rows = tuple(
        (
            row_number,
            _record(
                "后段新增部门" if row_number >= 202 else "工程部",
                f"E{row_number:04d}",
                f"员工{row_number:04d}",
                str(row_number),
                f"2026-07-17 {((row_number - 2) // 60) % 24:02d}:{(row_number - 2) % 60:02d}:00",
                "东门",
            ),
        )
        for row_number in range(2, 252)
    )
    entry = await _add_entry(session, knowledge_base_id, _content(rows), title="大表.xlsx")
    await session.commit()

    assert entry.custom_metadata["source_locations_truncated"] is True
    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "这份考勤记录中有多少个不同部门？请列出部门名称。",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.rows == (("工程部",), ("后段新增部门",))
    assert "完整扫描 250 条考勤记录" in answer.answer
    assert answer.hits[0].source_path is not None
    assert answer.hits[0].source_path.endswith("#worksheet:Sheet1!B2:B251")


@pytest.mark.asyncio
async def test_department_summary_aggregates_all_attendance_sheets(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:白班!A1] 姓名",
            "[worksheet:白班!B1] 时间",
            "[worksheet:白班!C1] 设备",
            "[worksheet:白班!D1] 部门",
            "[worksheet:白班!A2] 甲",
            "[worksheet:白班!B2] 2026-07-17 08:00:00",
            "[worksheet:白班!C2] 东门",
            "[worksheet:白班!D2] 工程部",
            "[worksheet:白班!A3] 乙",
            "[worksheet:白班!B3] 2026-07-17 08:05:00",
            "[worksheet:白班!C3] 西门",
            "[worksheet:白班!D3] 研发部",
            "[worksheet:夜班!A1] 姓名",
            "[worksheet:夜班!B1] 时间",
            "[worksheet:夜班!C1] 设备",
            "[worksheet:夜班!D1] 部门",
            "[worksheet:夜班!A2] 丙",
            "[worksheet:夜班!B2] 2026-07-17 20:00:00",
            "[worksheet:夜班!C2] 东门",
            "[worksheet:夜班!D2] 工程部",
            "[worksheet:夜班!A3] 丁",
            "[worksheet:夜班!B3] 2026-07-17 20:05:00",
            "[worksheet:夜班!C3] 南门",
            "[worksheet:夜班!D3] 生产部",
        )
    )
    await _add_entry(session, knowledge_base_id, content, title="多班次.xlsx")
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "请列出这份考勤数据中的所有部门。",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.rows == (("工程部",), ("研发部",), ("生产部",))
    assert "完整扫描 4 条考勤记录" in answer.answer
    assert len(answer.hits) == 1
    assert answer.hits[0].source_path is not None
    assert "worksheet:白班!D2:D3" in answer.hits[0].source_path
    assert "worksheet:夜班!D2:D3" in answer.hits[0].source_path


@pytest.mark.asyncio
async def test_department_summary_rejects_ambiguous_department_header(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:Sheet1!A1] 姓名",
            "[worksheet:Sheet1!B1] 时间",
            "[worksheet:Sheet1!C1] 设备",
            "[worksheet:Sheet1!D1] 部门",
            "[worksheet:Sheet1!E1] 部门名称",
            "[worksheet:Sheet1!A2] 甲",
            "[worksheet:Sheet1!B2] 2026-07-17 08:00:00",
            "[worksheet:Sheet1!C2] 东门",
            "[worksheet:Sheet1!D2] 工程部",
            "[worksheet:Sheet1!E2] 研发部",
        )
    )
    await _add_entry(session, knowledge_base_id, content, title="歧义.xlsx")
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有哪些部门？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_department_summary_rejects_more_than_fifty_departments(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    rows = tuple(
        (
            index + 2,
            _record(
                f"部门{index:03d}",
                f"E{index:03d}",
                f"员工{index:03d}",
                str(index),
                f"2026-07-17 08:{index % 60:02d}:00",
                "东门",
            ),
        )
        for index in range(51)
    )
    await _add_entry(session, knowledge_base_id, _content(rows))
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有多少个不同部门？请全部列出。",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.parametrize(
    "question",
    (
        "这份考勤记录中，一共包含了多少个不同的部门？请列出名称。",
        "考勤记录里有几个不同部门？",
        "考勤表中有哪些部门？",
        "请列出这份打卡数据中的部门名称。",
        "这份门禁记录涉及的所有部门有哪些？",
        "这份考勤记录涉及的部门去重后有多少？",
        "考勤记录里部门总数是多少？",
        "考勤记录包含多少种部门？",
        "考勤记录里不同的部门有几个？",
        "请汇总考勤记录中的部门。",
        "考勤记录包含哪些部门名称？",
        "门禁记录一共涉及多少个部门？",
        "考勤记录有几个部门，分别是什么？",
        "这份考勤记录的部门数量和名称是什么？",
        "考勤记录涉及多少个组织部门？",
        "考勤记录中有多少个独立部门？",
        "考勤记录有哪些所属部门？",
        "考勤记录里的部门都叫什么？",
        "考勤明细中有哪些部门？",
        "打卡表中列举全部部门名称。",
        "请说明考勤记录中有哪些部门？",
        "请解释考勤记录中有哪些部门？",
        "告诉我考勤记录中有哪些部门？",
    ),
)
def test_department_summary_recognizes_supported_variants(question: str) -> None:
    assert is_spreadsheet_query_intent(question) is True


@pytest.mark.parametrize(
    "question",
    (
        "2026年7月17日考勤记录中有多少个不同部门？",
        "认证成功的考勤记录涉及哪些部门？",
        "考勤记录中每个部门有多少人？",
        "考勤记录中的部门排名是什么？",
        "排除研发部后，考勤记录中有哪些部门？",
        "东门设备的考勤记录涉及哪些部门？",
        "请统计这份考勤记录的部门分布。",
        "2026年7月17日的考勤记录包含多少个不同部门？请列出这些部门的名称。",
        "这份考勤记录包含多少个不同部门？请列出这些部门的名称，但排除研发部。",
        "东门设备的考勤记录包含多少个不同部门？请列出这些部门的名称。",
    ),
)
@pytest.mark.asyncio
async def test_department_summary_rejects_unsupported_scopes(
    knowledge_session: tuple[AsyncSession, UUID],
    question: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),)),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(session, knowledge_base_id, question)

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.parametrize(
    "question",
    (
        "公司的部门管理制度是什么？",
        "公司共有多少个部门？",
        "这份设备说明中有哪些部门？",
        "请列出考勤记录部门管理制度中的审批流程。",
    ),
)
def test_generic_department_questions_do_not_trigger_spreadsheet_summary(question: str) -> None:
    assert is_spreadsheet_query_intent(question) is False


@pytest.mark.parametrize("subject", ("员工考勤记录", "人员考勤记录"))
@pytest.mark.asyncio
async def test_department_summary_accepts_unscoped_employee_attendance_wording(
    knowledge_session: tuple[AsyncSession, UUID],
    subject: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),
                (3, _record("研发部", "E002", "乙", "2", "2026-07-17 08:05:00", "西门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        f"这份{subject}中一共有多少个不同部门？请列出名称。",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.table.rows == (("工程部",), ("研发部",))


@pytest.mark.asyncio
async def test_department_summary_answers_quantity_and_name_wording(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),
                (3, _record("研发部", "E002", "乙", "2", "2026-07-17 08:05:00", "西门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "这份考勤记录的部门数量和名称是什么？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.table.rows == (("工程部",), ("研发部",))


@pytest.mark.parametrize(
    "question",
    (
        "员工考勤记录中有哪些部门？",
        "人员考勤数据中的部门名单是什么？",
        "请说明考勤记录中有哪些部门？",
        "请解释考勤记录中有哪些部门？",
        "告诉我考勤记录中有哪些部门？",
    ),
)
@pytest.mark.asyncio
async def test_department_summary_answers_employee_attendance_and_polite_wording(
    knowledge_session: tuple[AsyncSession, UUID],
    question: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),
                (3, _record("研发部", "E002", "乙", "2", "2026-07-17 08:05:00", "西门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(session, knowledge_base_id, question)

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.table.rows == (("工程部",), ("研发部",))


@pytest.mark.parametrize(
    ("department", "timestamp", "employee_id"),
    (
        ("研发\u200b部", "2026-07-17 08:00:00", "E001"),
        ("研发部", "不是时间", "E001"),
        ("研发部", "2026-07-17 08:00:00", ""),
    ),
)
@pytest.mark.asyncio
async def test_department_summary_rejects_unverifiable_attendance_rows(
    knowledge_session: tuple[AsyncSession, UUID],
    department: str,
    timestamp: str,
    employee_id: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record(department, employee_id, "", "", timestamp, "东门")),)),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有哪些部门？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.parametrize("identity", ("N/A", "unknown", "\u200b", "\u202e"))
@pytest.mark.asyncio
async def test_department_summary_rejects_placeholder_or_control_identity(
    knowledge_session: tuple[AsyncSession, UUID],
    identity: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            ((2, _record("工程部", identity, identity, identity, "2026-07-17 08:00:00", "东门")),)
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有哪些部门？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED


@pytest.mark.parametrize("department", ("#REF!", "#VALUE!", "#DIV/0!", "N / A", "\ufe0f"))
@pytest.mark.asyncio
async def test_department_summary_rejects_error_or_symbol_only_departments(
    knowledge_session: tuple[AsyncSession, UUID],
    department: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record(department, "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),)),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有哪些部门？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED


@pytest.mark.asyncio
async def test_department_summary_ignores_non_attendance_department_sheets(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:组织架构!A1] 部门",
            "[worksheet:组织架构!B1] 负责人",
            "[worksheet:组织架构!A2] 不应计入部门",
            "[worksheet:组织架构!B2] 某负责人",
            "[worksheet:考勤!A1] 姓名",
            "[worksheet:考勤!B1] 部门",
            "[worksheet:考勤!C1] 时间",
            "[worksheet:考勤!D1] 设备",
            "[worksheet:考勤!A2] 甲",
            "[worksheet:考勤!B2] 工程部",
            "[worksheet:考勤!C2] 2026-07-17 08:00:00",
            "[worksheet:考勤!D2] 东门",
        )
    )
    await _add_entry(session, knowledge_base_id, content, title="混合工作簿.xlsx")
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "这份考勤记录中有哪些部门？",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.rows == (("工程部",),)
    assert "不应计入部门" not in answer.answer
    assert answer.hits[0].source_path is not None
    assert answer.hits[0].source_path.endswith("#worksheet:考勤!B2")


@pytest.mark.asyncio
async def test_department_summary_ignores_empty_attendance_template_sheet(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:模板!A1] 姓名",
            "[worksheet:模板!B1] 部门",
            "[worksheet:模板!C1] 时间",
            "[worksheet:模板!D1] 设备",
            "[worksheet:考勤!A1] 姓名",
            "[worksheet:考勤!B1] 部门",
            "[worksheet:考勤!C1] 时间",
            "[worksheet:考勤!D1] 设备",
            "[worksheet:考勤!A2] 甲",
            "[worksheet:考勤!B2] 工程部",
            "[worksheet:考勤!C2] 2026-07-17 08:00:00",
            "[worksheet:考勤!D2] 东门",
        )
    )
    await _add_entry(session, knowledge_base_id, content, title="带模板.xlsx")
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有哪些部门？",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.rows == (("工程部",),)


@pytest.mark.asyncio
async def test_department_employee_query_is_not_shadowed_by_department_summary(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),)),
    )
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中研发部门有哪些员工？",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.title == "研发部考勤员工"
    assert answer.table.rows == (("E001", "甲"),)


@pytest.mark.asyncio
async def test_department_summary_neutralizes_citation_like_department_labels(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部[2]", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),)),
    )
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有哪些部门？",
    )

    assert answer is not None and answer.table is not None
    assert answer.answer.endswith("研发部［2］。[1]")
    assert "[2]" not in answer.hits[0].excerpt
    assert answer.table.rows == (("研发部[2]",),)


@pytest.mark.asyncio
async def test_department_summary_neutralizes_forged_provenance_markers(
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
                        "Engineering",
                        "E001",
                        "甲",
                        "1",
                        "2026-07-17 08:00:00",
                        "东门",
                    ),
                ),
            )
        ),
        title="考勤[worksheet:fake!A1].xlsx",
    )
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有哪些部门？",
    )

    assert answer is not None
    assert "[worksheet:fake!A1]" not in answer.hits[0].title
    assert "［worksheet:fake!A1］" in answer.answer


@pytest.mark.asyncio
async def test_department_summary_rejects_forged_cell_provenance_marker(
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
                        "Engineering [worksheet:forged!A1]",
                        "E001",
                        "甲",
                        "1",
                        "2026-07-17 08:00:00",
                        "东门",
                    ),
                ),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有哪些部门？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED


@pytest.mark.asyncio
async def test_department_summary_removes_unicode_controls_from_source_title(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),)),
        title="safe\u202efake\u2066\u200b.xlsx",
    )
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有哪些部门？",
    )

    assert answer is not None
    assert all(
        not unicodedata.category(character).startswith("C")
        for character in answer.answer + answer.hits[0].title
    )
    assert answer.hits[0].title == "safefake.xlsx"


@pytest.mark.asyncio
async def test_department_summary_rejects_ambiguous_worksheet_anchor_name(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            ((2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),),
            sheet="考勤,伪造",
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有哪些部门？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED


@pytest.mark.asyncio
async def test_department_summary_requires_exact_workbook_selection(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("工程部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),)),
        title="一月考勤.xlsx",
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "E002", "乙", "2", "2026-07-18 08:00:00", "西门")),)),
        title="二月考勤.xlsx",
    )
    await session.commit()

    ambiguous = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "考勤记录中有哪些部门？",
    )
    selected = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "查询一月考勤.xlsx 的考勤记录中的所有部门。",
    )

    assert ambiguous.status is SpreadsheetQueryStatus.REJECTED
    assert selected.status is SpreadsheetQueryStatus.ANSWERED
    assert selected.answer is not None and selected.answer.table is not None
    assert selected.answer.table.rows == (("工程部",),)


@pytest.mark.asyncio
async def test_department_summary_selects_workbook_with_spaces_in_name(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("人事部", "E001", "甲", "1", "2026-07-17 08:00:00", "东门")),)),
        title="人事 考勤.xlsx",
    )
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("研发部", "E002", "乙", "2", "2026-07-18 08:00:00", "西门")),)),
        title="研发考勤.xlsx",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "查询人事 考勤.xlsx 的考勤记录中有哪些部门？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.table.rows == (("人事部",),)


@pytest.mark.asyncio
async def test_department_record_count_scans_complete_attendance_range(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("品质部", "E001", "甲", "1", "2026-07-05 08:00:00", "东门")),
                (3, _record("工程部", "E002", "乙", "2", "2026-07-05 08:05:00", "西门")),
                (4, _record("品质部", "E003", "丙", "3", "2026-07-05 08:10:00", "东门")),
                (5, _record("品质部", "E004", "丁", "4", "2026-07-05 08:15:00", "南门")),
                (6, _record("工程部", "E005", "戊", "5", "2026-07-05 08:20:00", "北门")),
            )
        ),
        title="测试.xlsx",
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "“品质部”在这段时间内一共有多少条打卡记录？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.answer == (
        "在《测试.xlsx》的完整考勤时间范围内，“品质部”共有 3 条打卡记录（已完整扫描 5 条记录）。[1]"
    )
    assert result.answer.table.title == "部门打卡记录统计"
    assert result.answer.table.columns == ("部门名称", "打卡记录数")
    assert result.answer.table.rows == (("品质部", "3 条"),)
    assert result.answer.hits[0].source_path is not None
    assert "worksheet:Sheet1!B2:B6" in result.answer.hits[0].source_path
    assert "worksheet:Sheet1!F2:F6" in result.answer.hits[0].source_path
    assert "完整扫描 5 条考勤记录" in result.answer.hits[0].excerpt
    assert "品质部”命中 3 条" in result.answer.hits[0].excerpt
    assert "E001" not in result.answer.hits[0].excerpt
    assert "甲" not in result.answer.hits[0].excerpt


@pytest.mark.parametrize(
    "question",
    (
        "品质部一共有多少条考勤记录？",
        "请统计品质部的打卡次数。",
        "品质部在该时间段内有几次打卡？",
        "“品质部”这段时间共计多少条门禁记录？",
        "品质部的打卡记录总数是多少？",
        "前工程科的考勤记录有多少？",
        "品质部一共打卡了几次？",
        "品质部累计打卡几次？",
    ),
)
def test_department_record_count_recognizes_supported_variants(question: str) -> None:
    assert is_spreadsheet_query_intent(question) is True


@pytest.mark.parametrize(
    "question",
    (
        "品质部的打卡记录总数是多少？",
        "品质部的考勤数量是多少？",
        "品质部的门禁记录合计是多少？",
        "品质部一共打卡了几次？",
        "品质部总计打卡多少次？",
        "品质部累计有多少条考勤记录？",
        "能否统计品质部有多少条打卡记录？",
        "可以统计一下品质部的打卡次数吗？",
        "帮忙统计品质部有多少条考勤记录？",
    ),
)
@pytest.mark.asyncio
async def test_department_record_count_answers_natural_aggregate_variants(
    knowledge_session: tuple[AsyncSession, UUID],
    question: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("品质部", "E001", "甲", "1", "2026-07-05 08:00:00", "东门")),
                (3, _record("品质部", "E002", "乙", "2", "2026-07-05 08:05:00", "西门")),
                (4, _record("工程部", "E003", "丙", "3", "2026-07-05 08:10:00", "南门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(session, knowledge_base_id, question)

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.table.rows == (("品质部", "2 条"),)


def test_department_record_count_recognizes_organization_names_without_department_suffix() -> None:
    assert is_spreadsheet_query_intent("前工程科共有多少条打卡记录？") is True


@pytest.mark.parametrize("organization", ("前工程科", "研发一组", "品质课", "仓储"))
@pytest.mark.asyncio
async def test_department_record_count_answers_organization_names_without_department_suffix(
    knowledge_session: tuple[AsyncSession, UUID],
    organization: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record(organization, "E001", "甲", "1", "2026-07-05 08:00:00", "东门")),
                (3, _record("品质部", "E002", "乙", "2", "2026-07-05 08:05:00", "西门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        f"“{organization}”共有多少条打卡记录？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.table.rows == ((organization, "1 条"),)


@pytest.mark.parametrize(
    "organization",
    ("流程管理部", "政策研究室", "制度建设处"),
)
@pytest.mark.asyncio
async def test_department_record_count_handles_organization_names_with_prose_terms(
    knowledge_session: tuple[AsyncSession, UUID],
    organization: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record(organization, "E001", "甲", "1", "2026-07-05 08:00:00", "东门")),)),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        f"{organization}共有多少条打卡记录？",
    )

    assert result.status is SpreadsheetQueryStatus.ANSWERED
    assert result.answer is not None and result.answer.table is not None
    assert result.answer.table.rows == ((organization, "1 条"),)


@pytest.mark.parametrize(
    "question",
    (
        "2026年7月5日品质部有多少条打卡记录？",
        "今天品质部有多少条打卡记录？",
        "品质部在东门设备有多少条打卡记录？",
        "品质部有多少条认证成功的打卡记录？",
        "品质部每位员工分别有多少条打卡记录？",
    ),
)
@pytest.mark.asyncio
async def test_department_record_count_rejects_unsupported_filters(
    knowledge_session: tuple[AsyncSession, UUID],
    question: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("品质部", "E001", "甲", "1", "2026-07-05 08:00:00", "东门")),)),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(session, knowledge_base_id, question)

    assert result.status is SpreadsheetQueryStatus.REJECTED
    assert result.answer is None


@pytest.mark.asyncio
async def test_department_record_count_aggregates_all_attendance_sheets(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:白班!A1] 姓名",
            "[worksheet:白班!B1] 部门",
            "[worksheet:白班!C1] 时间",
            "[worksheet:白班!D1] 设备",
            "[worksheet:白班!A2] 甲",
            "[worksheet:白班!B2] 品质部",
            "[worksheet:白班!C2] 2026-07-05 08:00:00",
            "[worksheet:白班!D2] 东门",
            "[worksheet:夜班!A1] 姓名",
            "[worksheet:夜班!B1] 部门",
            "[worksheet:夜班!C1] 时间",
            "[worksheet:夜班!D1] 设备",
            "[worksheet:夜班!A2] 乙",
            "[worksheet:夜班!B2] 品质部",
            "[worksheet:夜班!C2] 2026-07-05 20:00:00",
            "[worksheet:夜班!D2] 西门",
            "[worksheet:夜班!A3] 丙",
            "[worksheet:夜班!B3] 工程部",
            "[worksheet:夜班!C3] 2026-07-05 20:05:00",
            "[worksheet:夜班!D3] 南门",
        )
    )
    await _add_entry(session, knowledge_base_id, content, title="多班次.xlsx")
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "品质部共有多少条打卡记录？",
    )

    assert answer is not None and answer.table is not None
    assert answer.table.rows == (("品质部", "2 条"),)
    assert "完整扫描 3 条记录" in answer.answer
    assert len(answer.hits) == 1
    assert answer.hits[0].source_path is not None
    assert "worksheet:白班!B2" in answer.hits[0].source_path
    assert "worksheet:白班!C2" in answer.hits[0].source_path
    assert "worksheet:夜班!B2:B3" in answer.hits[0].source_path
    assert "worksheet:夜班!C2:C3" in answer.hits[0].source_path


@pytest.mark.parametrize(
    ("department", "timestamp"),
    (("", "2026-07-05 08:00:00"), ("品质部", "不是时间")),
)
@pytest.mark.asyncio
async def test_department_record_count_rejects_incomplete_rows(
    knowledge_session: tuple[AsyncSession, UUID],
    department: str,
    timestamp: str,
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("品质部", "E001", "甲", "1", "2026-07-05 08:00:00", "东门")),
                (3, _record(department, "E002", "乙", "2", timestamp, "西门")),
            )
        ),
    )
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "品质部共有多少条打卡记录？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED


@pytest.mark.asyncio
async def test_department_record_count_rejects_partial_attendance_sheet(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    valid = _content(((2, _record("品质部", "E001", "甲", "1", "2026-07-05 08:00:00", "东门")),))
    partial = "\n\n".join(
        (
            "[worksheet:缺身份!A1] 部门",
            "[worksheet:缺身份!B1] 时间",
            "[worksheet:缺身份!C1] 设备",
            "[worksheet:缺身份!A2] 品质部",
            "[worksheet:缺身份!B2] 2026-07-05 09:00:00",
            "[worksheet:缺身份!C2] 西门",
        )
    )
    await _add_entry(session, knowledge_base_id, f"{valid}\n\n{partial}")
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "品质部共有多少条打卡记录？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED


@pytest.mark.asyncio
async def test_department_record_count_rejects_unrecognized_nonempty_sheet(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    valid = _content(((2, _record("品质部", "E001", "甲", "1", "2026-07-05 08:00:00", "东门")),))
    unrecognized = "\n\n".join(
        (
            "[worksheet:未识别!A1] 组织单元",
            "[worksheet:未识别!B1] 发生时刻",
            "[worksheet:未识别!C1] 通道设备名",
            "[worksheet:未识别!D1] 人员标识",
            "[worksheet:未识别!A2] 品质部",
            "[worksheet:未识别!B2] 2026-07-05 09:00:00",
            "[worksheet:未识别!C2] 西门",
            "[worksheet:未识别!D2] E002",
        )
    )
    await _add_entry(session, knowledge_base_id, f"{valid}\n\n{unrecognized}")
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "品质部共有多少条打卡记录？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED


@pytest.mark.asyncio
async def test_department_record_count_rejects_multiple_table_segments_in_one_sheet(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    content = "\n\n".join(
        (
            "[worksheet:Sheet1!A1] 姓名",
            "[worksheet:Sheet1!B1] 部门",
            "[worksheet:Sheet1!C1] 时间",
            "[worksheet:Sheet1!D1] 设备",
            "[worksheet:Sheet1!A2] 甲",
            "[worksheet:Sheet1!B2] 品质部",
            "[worksheet:Sheet1!C2] 2026-07-05 08:00:00",
            "[worksheet:Sheet1!D2] 东门",
            "[worksheet:Sheet1!A20] 姓名",
            "[worksheet:Sheet1!B20] 部门",
            "[worksheet:Sheet1!C20] 时间",
            "[worksheet:Sheet1!D20] 设备",
            "[worksheet:Sheet1!E20] 事件结果",
            "[worksheet:Sheet1!A21] 乙",
            "[worksheet:Sheet1!B21] 品质部",
            "[worksheet:Sheet1!C21] 2026-07-05 09:00:00",
            "[worksheet:Sheet1!D21] 西门",
            "[worksheet:Sheet1!E21] 认证成功",
        )
    )
    await _add_entry(session, knowledge_base_id, content)
    await session.commit()

    result = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "品质部共有多少条打卡记录？",
    )

    assert result.status is SpreadsheetQueryStatus.REJECTED


@pytest.mark.asyncio
async def test_department_record_count_does_not_shadow_employee_or_summary_queries(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    await _add_entry(
        session,
        knowledge_base_id,
        _content(
            (
                (2, _record("品质部", "E001", "甲", "1", "2026-07-05 08:00:00", "东门")),
                (3, _record("工程部", "E002", "乙", "2", "2026-07-05 08:05:00", "西门")),
            )
        ),
    )
    await session.commit()

    employees = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "品质部有多少位员工在考勤记录中？",
    )
    summary = await evaluate_spreadsheet_query(
        session,
        knowledge_base_id,
        "这份考勤记录中有多少个部门？",
    )

    assert employees.status is SpreadsheetQueryStatus.ANSWERED
    assert employees.answer is not None and employees.answer.table is not None
    assert employees.answer.table.title == "品质部考勤员工"
    assert summary.status is SpreadsheetQueryStatus.ANSWERED
    assert summary.answer is not None and summary.answer.table is not None
    assert summary.answer.table.title == "考勤部门统计"


@pytest.mark.asyncio
async def test_aggregate_citation_sanitizes_source_path_and_format_version(
    knowledge_session: tuple[AsyncSession, UUID],
) -> None:
    session, knowledge_base_id = knowledge_session
    entry = await _add_entry(
        session,
        knowledge_base_id,
        _content(((2, _record("品质部", "E001", "甲", "1", "2026-07-05 08:00:00", "东门")),)),
    )
    entry.source_path = "generated/safe\u202efake#part[1].md"
    entry.format_version = "okf/\u202e0.1"
    await session.commit()

    answer = await answer_spreadsheet_query(
        session,
        knowledge_base_id,
        "品质部共有多少条打卡记录？",
    )

    assert answer is not None
    source_path = answer.hits[0].source_path or ""
    format_version = answer.hits[0].format_version or ""
    assert "%23part%5B1%5D.md#worksheet:" in source_path
    assert all(
        not unicodedata.category(character).startswith("C")
        for character in source_path + format_version
    )


def test_department_record_count_does_not_capture_policy_question() -> None:
    assert is_spreadsheet_query_intent("品质部的考勤管理制度是什么？") is False


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
