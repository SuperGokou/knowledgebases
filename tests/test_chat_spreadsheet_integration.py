from __future__ import annotations

import re
from datetime import UTC, datetime
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.config import Settings
from app.db.base import Base
from app.db.models import (
    AuditLog,
    AuditResult,
    File,
    FileStatus,
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
    KnowledgeIngestionStatus,
    MalwareScanStatus,
    OkfConversionJob,
    OkfConversionStatus,
    User,
)
from app.schemas.chat import ChatQueryResponse
from app.schemas.knowledge_bases import KnowledgeSearchHit
from app.services import chat as chat_service
from app.services.access import AccessContext
from app.services.knowledge_bases import KnowledgeBaseAccess
from app.services.spreadsheet_query import (
    SpreadsheetAnswer,
    SpreadsheetQueryResult,
    SpreadsheetQueryStatus,
    SpreadsheetTable,
)


def _context() -> tuple[KnowledgeBase, AccessContext]:
    user = User(id=uuid4(), email=f"reader-{uuid4()}@example.com", password_hash="hash")
    knowledge_base = KnowledgeBase(
        id=uuid4(),
        owner_id=user.id,
        name="Infra",
        external_llm_processing_enabled=False,
    )
    access = AccessContext(
        user=user,
        permissions=frozenset({"chat:query"}),
        limits={},
        role_ids=frozenset(),
        max_role_priority=0,
    )
    return knowledge_base, access


def _trusted_spreadsheet_metadata(content: str) -> dict[str, object]:
    cell_locations = re.findall(r"\[(worksheet:[^\]\r\n]+![A-Za-z]{1,3}[1-9]\d*)\]", content)
    locations: list[str] = []
    seen_sheets: set[str] = set()
    for location in cell_locations:
        sheet_location = location.rsplit("!", maxsplit=1)[0]
        if sheet_location not in seen_sheets:
            locations.append(sheet_location)
            seen_sheets.add(sheet_location)
        locations.append(location)
    return {
        "source_parser": "ooxml-xlsx",
        "generator": {
            "provider": "local",
            "model": "local-deterministic-v1",
        },
        "source_locations": locations,
        "source_location_count": len(locations),
        "source_locations_truncated": False,
        "source_text_length": len(content),
        "source_text_sha256": sha256(content.encode("utf-8")).hexdigest(),
        "source_locations_sha256": sha256("\n".join(locations).encode("utf-8")).hexdigest(),
    }


async def _persist_trusted_spreadsheet_entry(
    session: AsyncSession,
    *,
    user: User,
    knowledge_base: KnowledgeBase,
    title: str,
    content: str,
    source_path: str = "generated/attendance.md",
) -> KnowledgeEntry:
    source_file = File(
        owner_id=user.id,
        knowledge_base_id=knowledge_base.id,
        bucket="kb",
        object_key=f"objects/chat-spreadsheet/{uuid4()}.xlsx",
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
    entry = KnowledgeEntry(
        knowledge_base_id=knowledge_base.id,
        source_file_id=source_file.id,
        entry_type="document",
        title=title,
        content=content,
        source_path=source_path,
        format_version="okf/0.1",
        publication_status=KnowledgeEntryPublicationStatus.PUBLISHED,
        custom_metadata=_trusted_spreadsheet_metadata(content),
    )
    session.add(entry)
    await session.flush()
    session.add_all(
        (
            OkfConversionJob(
                file_id=source_file.id,
                knowledge_base_id=knowledge_base.id,
                file_version=source_file.version,
                status=OkfConversionStatus.SUCCEEDED,
                prompt_version="okf-v1",
                output_entry_id=entry.id,
                completed_at=datetime.now(UTC),
            ),
            AuditLog(
                actor_id=user.id,
                action="file.approved",
                result=AuditResult.SUCCESS,
                resource_type="file",
                resource_id=str(source_file.id),
            ),
        )
    )
    await session.flush()
    return entry


async def _query(
    knowledge_base: KnowledgeBase,
    access: AccessContext,
    session: object,
    *,
    message: str = "员工熊小强的人员工号是多少？",
) -> ChatQueryResponse:
    return await chat_service.answer_knowledge_query(
        session,  # type: ignore[arg-type]
        Settings(environment="test"),
        access,
        knowledge_base_id=knowledge_base.id,
        message=message,
        limit=5,
        idempotency_key="spreadsheet-structured-test",
        api_key_id=None,
    )


@pytest.mark.asyncio
async def test_spreadsheet_query_runs_only_after_knowledge_base_access_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    knowledge_base, access = _context()
    structured_called = False

    async def deny_access(*_args: object, **_kwargs: object) -> KnowledgeBaseAccess:
        raise PermissionError("denied")

    async def structured(*_args: object, **_kwargs: object) -> SpreadsheetQueryResult:
        nonlocal structured_called
        structured_called = True
        return SpreadsheetQueryResult(
            status=SpreadsheetQueryStatus.NOT_APPLICABLE,
            answer=None,
        )

    monkeypatch.setattr(chat_service, "require_knowledge_base_access", deny_access)
    monkeypatch.setattr(chat_service, "evaluate_spreadsheet_query", structured)

    with pytest.raises(PermissionError, match="denied"):
        await _query(knowledge_base, access, object())

    assert structured_called is False


@pytest.mark.asyncio
async def test_structured_spreadsheet_answer_short_circuits_search_and_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    knowledge_base, access = _context()
    entry_id = uuid4()
    file_id = uuid4()
    events: list[str] = []
    hit = KnowledgeSearchHit(
        entry_id=entry_id,
        source_file_id=file_id,
        title="10级以上考勤.xlsx · Sheet1 第5行",
        excerpt="姓名=熊小强 | 人员工号=EFD2410053",
        source_path="worksheet:Sheet1!C5:D5",
        format_version="okf/0.1",
    )
    result = SpreadsheetAnswer(
        answer="员工“熊小强”的人员工号是 EFD2410053 [1]。",
        hits=(hit,),
        table=SpreadsheetTable(
            title="员工工号查询",
            columns=("姓名", "人员工号"),
            rows=(("熊小强", "EFD2410053"),),
            citation_numbers=(1,),
        ),
    )

    async def require_access(*_args: object, **_kwargs: object) -> KnowledgeBaseAccess:
        events.append("access")
        return KnowledgeBaseAccess(knowledge_base, KnowledgeBaseAccessLevel.READER)

    async def structured(
        _session: object,
        *,
        knowledge_base_id: object,
        question: str,
    ) -> SpreadsheetQueryResult:
        assert knowledge_base_id == knowledge_base.id
        assert question == "员工熊小强的人员工号是多少？"
        events.append("structured")
        return SpreadsheetQueryResult(
            status=SpreadsheetQueryStatus.ANSWERED,
            answer=result,
        )

    async def must_not_run(*_args: object, **_kwargs: object) -> list[KnowledgeSearchHit]:
        raise AssertionError("ordinary retrieval must not run after a structured hit")

    async def must_not_resolve(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("LLM resolution must not run after a structured hit")

    monkeypatch.setattr(chat_service, "require_knowledge_base_access", require_access)
    monkeypatch.setattr(chat_service, "evaluate_spreadsheet_query", structured)
    monkeypatch.setattr(chat_service, "search_knowledge_entries", must_not_run)
    monkeypatch.setattr(chat_service, "resolve_provider_client", must_not_resolve)

    response = await _query(knowledge_base, access, object())

    assert events == ["access", "structured"]
    assert response.mode == "structured"
    assert response.provider is None and response.model is None
    assert response.answer_review.model_dump() == {
        "status": "passed",
        "reason": "deterministic_verified",
    }
    assert response.source_status.model_dump() == {
        "status": "grounded",
        "strategy": "structured",
        "reason": "structured_query",
        "citation_count": 1,
    }
    assert response.citations[0].model_dump() == {
        **hit.model_dump(),
        "citation_number": 1,
        "marker": "[1]",
    }
    assert response.table is not None
    assert response.table.model_dump() == {
        "title": "员工工号查询",
        "columns": ["姓名", "人员工号"],
        "rows": [["熊小强", "EFD2410053"]],
        "citation_numbers": [1],
    }
    assert response.answer.endswith(
        f"答案来源（知识库）：\n[1] {hit.title}（entry:{entry_id} · path:{hit.source_path}）"
    )


@pytest.mark.asyncio
async def test_non_spreadsheet_question_keeps_the_existing_retrieval_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    knowledge_base, access = _context()
    events: list[str] = []

    async def require_access(*_args: object, **_kwargs: object) -> KnowledgeBaseAccess:
        events.append("access")
        return KnowledgeBaseAccess(knowledge_base, KnowledgeBaseAccessLevel.READER)

    async def structured(*_args: object, **_kwargs: object) -> SpreadsheetQueryResult:
        events.append("structured")
        return SpreadsheetQueryResult(
            status=SpreadsheetQueryStatus.NOT_APPLICABLE,
            answer=None,
        )

    async def search(*_args: object, **_kwargs: object) -> list[KnowledgeSearchHit]:
        events.append("search")
        return []

    monkeypatch.setattr(chat_service, "require_knowledge_base_access", require_access)
    monkeypatch.setattr(chat_service, "evaluate_spreadsheet_query", structured)
    monkeypatch.setattr(chat_service, "search_knowledge_entries", search)

    response = await _query(
        knowledge_base,
        access,
        object(),
        message="公司安全制度是什么？",
    )

    assert events == ["access", "structured", "search"]
    assert response.mode == "retrieval"
    assert response.source_status.reason == "no_matching_content"
    assert response.answer_review.model_dump() == {
        "status": "fallback",
        "reason": "retrieval_only",
    }


@pytest.mark.asyncio
async def test_unsafe_spreadsheet_query_is_rejected_without_fuzzy_search_or_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    knowledge_base, access = _context()
    events: list[str] = []

    async def require_access(*_args: object, **_kwargs: object) -> KnowledgeBaseAccess:
        events.append("access")
        return KnowledgeBaseAccess(knowledge_base, KnowledgeBaseAccessLevel.READER)

    async def structured(*_args: object, **_kwargs: object) -> SpreadsheetQueryResult:
        events.append("structured")
        return SpreadsheetQueryResult(
            status=SpreadsheetQueryStatus.REJECTED,
            answer=None,
            rejection_message="当前表格证据存在歧义，无法安全计算答案。",
        )

    async def must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("unsafe spreadsheet evidence must not reach search or an LLM")

    monkeypatch.setattr(chat_service, "require_knowledge_base_access", require_access)
    monkeypatch.setattr(chat_service, "evaluate_spreadsheet_query", structured)
    monkeypatch.setattr(chat_service, "search_knowledge_entries", must_not_run)
    monkeypatch.setattr(chat_service, "resolve_provider_client", must_not_run)

    response = await _query(knowledge_base, access, object())

    assert events == ["access", "structured"]
    assert response.mode == "structured"
    assert response.provider is None and response.model is None
    assert response.table is None and response.citations == []
    assert response.source_status.model_dump() == {
        "status": "no_results",
        "strategy": "structured",
        "reason": "structured_query",
        "citation_count": 0,
    }
    assert response.answer_review.model_dump() == {
        "status": "passed",
        "reason": "deterministic_verified",
    }
    assert response.answer.startswith("当前表格证据存在歧义，无法安全计算答案。")
    assert response.answer.endswith("答案来源：当前知识库未检索到可引用内容。")


@pytest.mark.asyncio
async def test_malformed_answered_result_fails_closed_without_search_or_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    knowledge_base, access = _context()

    async def require_access(*_args: object, **_kwargs: object) -> KnowledgeBaseAccess:
        return KnowledgeBaseAccess(knowledge_base, KnowledgeBaseAccessLevel.READER)

    async def malformed(*_args: object, **_kwargs: object) -> SpreadsheetQueryResult:
        return SpreadsheetQueryResult(
            status=SpreadsheetQueryStatus.ANSWERED,
            answer=None,
        )

    async def must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("malformed structured results must fail closed")

    monkeypatch.setattr(chat_service, "require_knowledge_base_access", require_access)
    monkeypatch.setattr(chat_service, "evaluate_spreadsheet_query", malformed)
    monkeypatch.setattr(chat_service, "search_knowledge_entries", must_not_run)
    monkeypatch.setattr(chat_service, "resolve_provider_client", must_not_run)

    response = await _query(knowledge_base, access, object())

    assert response.mode == "structured"
    assert response.citations == [] and response.table is None
    assert response.source_status.status == "no_results"
    assert response.answer.startswith("当前表格证据不足")


def test_invalid_structured_table_is_rejected_without_crashing_chat() -> None:
    knowledge_base_id = uuid4()
    hit = KnowledgeSearchHit(
        entry_id=uuid4(),
        source_file_id=uuid4(),
        title="超限考勤.xlsx",
        excerpt="[worksheet:Sheet1!A2] 研发部",
        source_path="worksheet:Sheet1!A2:K2",
        format_version="okf/0.1",
    )
    result = SpreadsheetAnswer(
        answer="研发部员工如下 [1]。",
        hits=(hit,),
        table=SpreadsheetTable(
            title="研发部员工",
            columns=("员工姓名",),
            rows=tuple((f"员工{index}",) for index in range(51)),
            citation_numbers=(1,),
        ),
    )

    assert chat_service._structured_spreadsheet_response(knowledge_base_id, result) is None


def test_structured_source_footer_neutralizes_untrusted_citation_like_metadata() -> None:
    knowledge_base_id = uuid4()
    hit = KnowledgeSearchHit(
        entry_id=uuid4(),
        source_file_id=uuid4(),
        title="测试 [ 2 ]",
        excerpt="完整扫描 1 条打卡记录",
        source_path="generated/[0]/attendance.md",
        format_version="okf/0.1",
    )
    result = SpreadsheetAnswer(
        answer="已完成确定性统计。[1]",
        hits=(hit,),
        table=None,
    )

    response = chat_service._structured_spreadsheet_response(knowledge_base_id, result)

    assert response is not None
    assert "[1] 测试 ［2］" in response.answer
    assert "generated/［0］/attendance.md" in response.answer
    assert "[ 2 ]" not in response.answer


@pytest.mark.asyncio
async def test_published_spreadsheet_flows_through_real_acl_query_and_chat_contract() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        async with factory() as session:
            user = User(email=f"owner-{uuid4()}@example.com", password_hash="hash")
            session.add(user)
            await session.flush()
            knowledge_base = KnowledgeBase(owner_id=user.id, name="Infra")
            session.add(knowledge_base)
            await session.flush()
            content = "\n\n".join(
                (
                    "[worksheet:Sheet1!A1] 部门",
                    "[worksheet:Sheet1!B1] 人员工号",
                    "[worksheet:Sheet1!C1] 姓名",
                    "[worksheet:Sheet1!A2] 生产部",
                    "[worksheet:Sheet1!B2] EFD2410053",
                    "[worksheet:Sheet1!C2] 熊小强",
                )
            )
            await _persist_trusted_spreadsheet_entry(
                session,
                user=user,
                knowledge_base=knowledge_base,
                title="10级以上考勤.xlsx",
                content=content,
            )
            await session.commit()
            access = AccessContext(
                user=user,
                permissions=frozenset({"chat:query"}),
                limits={},
                role_ids=frozenset(),
                max_role_priority=0,
            )

            response = await _query(knowledge_base, access, session)

            assert response.mode == "structured"
            assert response.answer.startswith("员工“熊小强”的人员工号是 EFD2410053。[1]")
            assert response.citations[0].source_path == (
                "generated/attendance.md#worksheet:Sheet1!A2:C2"
            )
            assert response.source_status.reason == "structured_query"
            assert response.answer_review.reason == "deterministic_verified"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_event_result_existence_short_circuits_retrieval_and_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        async with factory() as session:
            user = User(email=f"owner-{uuid4()}@example.com", password_hash="hash")
            session.add(user)
            await session.flush()
            knowledge_base = KnowledgeBase(owner_id=user.id, name="Infra")
            session.add(knowledge_base)
            await session.flush()
            content = "\n\n".join(
                (
                    "[worksheet:Sheet1!A1] 部门",
                    "[worksheet:Sheet1!B1] 人员工号",
                    "[worksheet:Sheet1!C1] 姓名",
                    "[worksheet:Sheet1!D1] 时间",
                    "[worksheet:Sheet1!E1] 设备",
                    "[worksheet:Sheet1!F1] 事件结果",
                    "[worksheet:Sheet1!A2] 工程部",
                    "[worksheet:Sheet1!B2] EFD2411027",
                    "[worksheet:Sheet1!C2] 刘春耀",
                    "[worksheet:Sheet1!D2] 2026-07-17 08:00:00",
                    "[worksheet:Sheet1!E2] 1#2F人行道闸出口3",
                    "[worksheet:Sheet1!F2] 认证成功(白名单验证)",
                )
            )
            await _persist_trusted_spreadsheet_entry(
                session,
                user=user,
                knowledge_base=knowledge_base,
                title="测试.xlsx",
                content=content,
            )
            await session.commit()
            access = AccessContext(
                user=user,
                permissions=frozenset({"chat:query"}),
                limits={},
                role_ids=frozenset(),
                max_role_priority=0,
            )

            async def must_not_run(*_args: object, **_kwargs: object) -> object:
                raise AssertionError("existence query must not reach retrieval or an LLM")

            monkeypatch.setattr(chat_service, "search_knowledge_entries", must_not_run)
            monkeypatch.setattr(chat_service, "resolve_provider_client", must_not_run)

            response = await _query(
                knowledge_base,
                access,
                session,
                message="这份考勤数据中，有没有‘认证失败’或‘黑名单拦截’的打卡记录？",
            )

            assert response.mode == "structured"
            assert response.provider is None and response.model is None
            assert response.answer.startswith("没有。")
            assert "已完整扫描 1 条打卡记录" in response.answer
            assert "认证成功" not in response.answer
            assert response.table is not None
            assert response.table.rows == [
                ["认证失败", "0 条", "未发现"],
                ["黑名单拦截", "0 条", "未发现"],
            ]
            assert response.answer_review.model_dump() == {
                "status": "passed",
                "reason": "deterministic_verified",
            }
            assert response.source_status.model_dump() == {
                "status": "grounded",
                "strategy": "structured",
                "reason": "structured_query",
                "citation_count": 1,
            }
            assert "完整扫描 1 条打卡记录" in response.citations[0].excerpt
            assert response.citations[0].source_path == (
                "generated/attendance.md#worksheet:Sheet1!F2"
            )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_device_frequency_short_circuits_retrieval_and_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        async with factory() as session:
            user = User(email=f"owner-{uuid4()}@example.com", password_hash="hash")
            session.add(user)
            await session.flush()
            knowledge_base = KnowledgeBase(owner_id=user.id, name="Infra")
            session.add(knowledge_base)
            await session.flush()
            content = "\n\n".join(
                (
                    "[worksheet:Sheet1!A1] 部门",
                    "[worksheet:Sheet1!B1] 人员工号",
                    "[worksheet:Sheet1!C1] 姓名",
                    "[worksheet:Sheet1!D1] 时间",
                    "[worksheet:Sheet1!E1] 设备",
                    "[worksheet:Sheet1!A2] 工程部",
                    "[worksheet:Sheet1!B2] E001",
                    "[worksheet:Sheet1!C2] 甲",
                    "[worksheet:Sheet1!D2] 2026-07-17 08:00:00",
                    "[worksheet:Sheet1!E2] 东门",
                    "[worksheet:Sheet1!A3] 工程部",
                    "[worksheet:Sheet1!B3] E002",
                    "[worksheet:Sheet1!C3] 乙",
                    "[worksheet:Sheet1!D3] 2026-07-17 08:05:00",
                    "[worksheet:Sheet1!E3] 东门",
                    "[worksheet:Sheet1!A4] 工程部",
                    "[worksheet:Sheet1!B4] E003",
                    "[worksheet:Sheet1!C4] 丙",
                    "[worksheet:Sheet1!D4] 2026-07-17 08:10:00",
                    "[worksheet:Sheet1!E4] 西门",
                )
            )
            await _persist_trusted_spreadsheet_entry(
                session,
                user=user,
                knowledge_base=knowledge_base,
                title="测试.xlsx",
                content=content,
            )
            await session.commit()
            access = AccessContext(
                user=user,
                permissions=frozenset({"chat:query"}),
                limits={},
                role_ids=frozenset(),
                max_role_priority=0,
            )

            async def must_not_run(*_args: object, **_kwargs: object) -> object:
                raise AssertionError("device aggregate must not reach retrieval or an LLM")

            monkeypatch.setattr(chat_service, "search_knowledge_entries", must_not_run)
            monkeypatch.setattr(chat_service, "resolve_provider_client", must_not_run)

            response = await _query(
                knowledge_base,
                access,
                session,
                message=(
                    "在所有闸机设备中，打卡记录最多（使用最频繁）的设备名称是什么？共记录了多少次？"
                ),
            )

            assert response.mode == "structured"
            assert response.provider is None and response.model is None
            assert "使用最频繁的设备是“东门”，共记录 2 次" in response.answer
            assert "模型未提供有效引用" not in response.answer
            assert response.table is not None
            assert response.table.model_dump() == {
                "title": "闸机设备使用频率",
                "columns": ["设备名称", "打卡次数"],
                "rows": [["东门", "2 次"]],
                "citation_numbers": [1],
            }
            assert response.answer_review.model_dump() == {
                "status": "passed",
                "reason": "deterministic_verified",
            }
            assert response.source_status.model_dump() == {
                "status": "grounded",
                "strategy": "structured",
                "reason": "structured_query",
                "citation_count": 1,
            }
            assert response.citations[0].source_path == (
                "generated/attendance.md#worksheet:Sheet1!E2:E4"
            )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_sequential_event_and_department_queries_do_not_reuse_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        async with factory() as session:
            user = User(email=f"owner-{uuid4()}@example.com", password_hash="hash")
            session.add(user)
            await session.flush()
            knowledge_base = KnowledgeBase(owner_id=user.id, name="Infra")
            session.add(knowledge_base)
            await session.flush()
            content = "\n\n".join(
                (
                    "[worksheet:Sheet1!A1] 姓名",
                    "[worksheet:Sheet1!B1] 部门",
                    "[worksheet:Sheet1!C1] 时间",
                    "[worksheet:Sheet1!D1] 设备",
                    "[worksheet:Sheet1!E1] 事件结果",
                    "[worksheet:Sheet1!A2] 甲",
                    "[worksheet:Sheet1!B2] 工程部",
                    "[worksheet:Sheet1!C2] 2026-07-17 08:00:00",
                    "[worksheet:Sheet1!D2] 东门",
                    "[worksheet:Sheet1!E2] 认证成功(白名单验证)",
                    "[worksheet:Sheet1!A3] 乙",
                    "[worksheet:Sheet1!B3] 研发部",
                    "[worksheet:Sheet1!C3] 2026-07-17 08:05:00",
                    "[worksheet:Sheet1!D3] 西门",
                    "[worksheet:Sheet1!E3] 认证成功(白名单验证)",
                )
            )
            await _persist_trusted_spreadsheet_entry(
                session,
                user=user,
                knowledge_base=knowledge_base,
                title="测试.xlsx",
                content=content,
            )
            await session.commit()
            access = AccessContext(
                user=user,
                permissions=frozenset({"chat:query"}),
                limits={},
                role_ids=frozenset(),
                max_role_priority=0,
            )

            async def must_not_run(*_args: object, **_kwargs: object) -> object:
                raise AssertionError("structured queries must not reach retrieval or an LLM")

            monkeypatch.setattr(chat_service, "search_knowledge_entries", must_not_run)
            monkeypatch.setattr(chat_service, "resolve_provider_client", must_not_run)

            event_response = await _query(
                knowledge_base,
                access,
                session,
                message="这份考勤数据中，有没有‘认证失败’或‘黑名单拦截’的打卡记录？",
            )
            department_response = await _query(
                knowledge_base,
                access,
                session,
                message="这份考勤记录中，一共包含了多少个不同的部门？请列出这些部门的名称。",
            )

            assert event_response.answer.startswith("没有。")
            assert department_response.mode == "structured"
            assert department_response.provider is None and department_response.model is None
            assert "共包含 2 个不同部门：工程部、研发部" in department_response.answer
            assert "认证失败" not in department_response.answer
            assert "黑名单拦截" not in department_response.answer
            assert "模型未提供有效引用" not in department_response.answer
            assert department_response.table is not None
            assert department_response.table.model_dump() == {
                "title": "考勤部门统计",
                "columns": ["部门名称"],
                "rows": [["工程部"], ["研发部"]],
                "citation_numbers": [1],
            }
            assert department_response.answer_review.model_dump() == {
                "status": "passed",
                "reason": "deterministic_verified",
            }
            assert department_response.source_status.model_dump() == {
                "status": "grounded",
                "strategy": "structured",
                "reason": "structured_query",
                "citation_count": 1,
            }
            assert department_response.citations[0].source_path == (
                "generated/attendance.md#worksheet:Sheet1!B2:B3"
            )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_conflicting_published_workbooks_reject_without_search_or_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        async with factory() as session:
            user = User(email=f"owner-{uuid4()}@example.com", password_hash="hash")
            session.add(user)
            await session.flush()
            knowledge_base = KnowledgeBase(owner_id=user.id, name="Infra")
            session.add(knowledge_base)
            await session.flush()

            for title, employee_id in (
                ("六月考勤.xlsx", "EFD-JUNE"),
                ("七月考勤.xlsx", "EFD-JULY"),
            ):
                content = "\n\n".join(
                    (
                        "[worksheet:Sheet1!A1] 部门",
                        "[worksheet:Sheet1!B1] 人员工号",
                        "[worksheet:Sheet1!C1] 姓名",
                        "[worksheet:Sheet1!A2] 生产部",
                        f"[worksheet:Sheet1!B2] {employee_id}",
                        "[worksheet:Sheet1!C2] 熊小强",
                    )
                )
                await _persist_trusted_spreadsheet_entry(
                    session,
                    user=user,
                    knowledge_base=knowledge_base,
                    title=title,
                    content=content,
                    source_path=f"generated/{title}.md",
                )
            await session.commit()
            access = AccessContext(
                user=user,
                permissions=frozenset({"chat:query"}),
                limits={},
                role_ids=frozenset(),
                max_role_priority=0,
            )

            async def must_not_run(*_args: object, **_kwargs: object) -> object:
                raise AssertionError("ambiguous spreadsheet evidence must fail closed")

            monkeypatch.setattr(chat_service, "search_knowledge_entries", must_not_run)
            monkeypatch.setattr(chat_service, "resolve_provider_client", must_not_run)

            response = await _query(knowledge_base, access, session)

            assert response.mode == "structured"
            assert response.provider is None and response.model is None
            assert response.table is None and response.citations == []
            assert response.source_status.model_dump() == {
                "status": "no_results",
                "strategy": "structured",
                "reason": "structured_query",
                "citation_count": 0,
            }
            assert response.answer_review.model_dump() == {
                "status": "passed",
                "reason": "deterministic_verified",
            }
            assert response.answer.startswith("当前表格证据不足或存在歧义")
            assert response.answer.endswith("答案来源：当前知识库未检索到可引用内容。")
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_department_record_count_short_circuits_retrieval_and_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        async with factory() as session:
            user = User(email=f"owner-{uuid4()}@example.com", password_hash="hash")
            session.add(user)
            await session.flush()
            knowledge_base = KnowledgeBase(owner_id=user.id, name="Infra")
            session.add(knowledge_base)
            await session.flush()
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
                    "[worksheet:Sheet1!A3] 乙",
                    "[worksheet:Sheet1!B3] 品质部",
                    "[worksheet:Sheet1!C3] 2026-07-05 08:05:00",
                    "[worksheet:Sheet1!D3] 西门",
                    "[worksheet:Sheet1!A4] 丙",
                    "[worksheet:Sheet1!B4] 工程部",
                    "[worksheet:Sheet1!C4] 2026-07-05 08:10:00",
                    "[worksheet:Sheet1!D4] 南门",
                )
            )
            await _persist_trusted_spreadsheet_entry(
                session,
                user=user,
                knowledge_base=knowledge_base,
                title="测试.xlsx",
                content=content,
            )
            await session.commit()
            access = AccessContext(
                user=user,
                permissions=frozenset({"chat:query"}),
                limits={},
                role_ids=frozenset(),
                max_role_priority=0,
            )

            async def must_not_run(*_args: object, **_kwargs: object) -> object:
                raise AssertionError("department count must not reach retrieval or an LLM")

            monkeypatch.setattr(chat_service, "search_knowledge_entries", must_not_run)
            monkeypatch.setattr(chat_service, "resolve_provider_client", must_not_run)

            response = await _query(
                knowledge_base,
                access,
                session,
                message="“品质部”在这段时间内一共有多少条打卡记录？",
            )

            assert response.mode == "structured"
            assert response.provider is None and response.model is None
            assert "品质部”共有 2 条打卡记录" in response.answer
            assert response.table is not None
            assert response.table.model_dump() == {
                "title": "部门打卡记录统计",
                "columns": ["部门名称", "打卡记录数"],
                "rows": [["品质部", "2 条"]],
                "citation_numbers": [1],
            }
            assert response.answer_review.model_dump() == {
                "status": "passed",
                "reason": "deterministic_verified",
            }
            assert response.source_status.model_dump() == {
                "status": "grounded",
                "strategy": "structured",
                "reason": "structured_query",
                "citation_count": 1,
            }
            assert response.citations[0].source_path == (
                "generated/attendance.md#worksheet:Sheet1!B2:B4,worksheet:Sheet1!C2:C4"
            )
    finally:
        await engine.dispose()
