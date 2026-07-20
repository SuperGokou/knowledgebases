from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Final
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import KnowledgeEntry, KnowledgeEntryPublicationStatus
from app.schemas.knowledge_bases import KnowledgeSearchHit

_MAX_ENTRIES: Final = 20
_MAX_TOTAL_CHARACTERS: Final = 8_000_000
_MAX_ROWS: Final = 100_000
_MAX_SOURCE_PATH_CHARACTERS: Final = 1_000
_MAX_TABLE_ROWS: Final = 50
_MAX_CELL_CHARACTERS: Final = 1_000
_MAX_LABEL_CHARACTERS: Final = 100
_MAX_EVIDENCE_CHARACTERS: Final = 100_000
_MAX_EXCEL_ROW: Final = 1_048_576
_MAX_EXCEL_COLUMN: Final = 16_384
_MAX_METADATA_LOCATIONS: Final = 2_048
_SOURCE_PARSERS: Final = ("ooxml-xlsx", "libreoffice-ooxml-xlsx")
SPREADSHEET_REJECTION_MESSAGE: Final = "当前表格证据不足或存在歧义，无法安全计算答案。"
_CELL_PATTERN: Final = re.compile(
    r"\[worksheet:(?P<sheet>[^\]\r\n]{1,31})!"
    r"(?P<column>[A-Za-z]{1,3})(?P<row>[1-9]\d{0,6})\]\s*"
)
_LOCATION_PATTERN: Final = re.compile(
    r"worksheet:(?P<sheet>[^\]\r\n]{1,31})!"
    r"(?P<column>[A-Za-z]{1,3})(?P<row>[1-9]\d{0,6})"
)
_SHEET_LOCATION_PATTERN: Final = re.compile(r"worksheet:[^\]\r\n]{1,31}")
_SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
_QUOTED_TERM_PATTERN: Final = re.compile(r"[“\"'‘]([^”\"'’]{1,50})[”\"'’]")
_EVENT_RESULT_QUERY_TERMS: Final = (
    "认证失败",
    "黑名单拦截",
    "白名单拦截",
    "验证失败",
    "通行失败",
    "刷卡失败",
    "拒绝通行",
    "认证异常",
    "验证异常",
    "认证成功",
    "验证成功",
    "通行成功",
    "允许通行",
    "黑名单",
    "白名单",
    "异常",
)
_EVENT_RESULT_TERM_MARKERS: Final = (
    "失败",
    "拦截",
    "拒绝",
    "成功",
    "通过",
    "允许",
    "禁止",
    "异常",
    "黑名单",
    "白名单",
    "超时",
)
_EVENT_RESULT_POLICY_TERMS: Final = (
    "制度",
    "条款",
    "政策",
    "规范",
    "流程",
    "办法",
    "手册",
)
_EVENT_RESULT_SEGMENT_PATTERN: Final = re.compile(r"[\s()（）/|,，;；:：\-]+")
_SPREADSHEET_FILENAME_PATTERN: Final = re.compile(r"\.(?:xlsx?|csv)\Z", re.IGNORECASE)
_SPREADSHEET_REFERENCE_PATTERN: Final = re.compile(
    r"[^\s，。？！?\"'“”‘’]{1,200}\.(?:xlsx?|csv)", re.IGNORECASE
)
_CITATION_LIKE_PATTERN: Final = re.compile(r"\[\s*-?\d+\s*\]")
_SPREADSHEET_REFERENCE_PREFIXES: Final = tuple(
    sorted(
        (
            "请打开",
            "请查看",
            "查询",
            "根据",
            "基于",
            "参照",
            "请查询",
            "请读取",
            "打开",
            "查看",
            "查询",
            "读取",
            "使用",
            "关于",
            "工作簿",
            "文件",
            "这份",
            "该份",
            "在",
            "从",
        ),
        key=len,
        reverse=True,
    )
)
_EVENT_RESULT_NEUTRAL_PHRASES: Final = tuple(
    sorted(
        (
            "是否出现过",
            "是否发生过",
            "是否存在",
            "是否包含",
            "有没有",
            "是否有",
            "考勤记录",
            "考勤数据",
            "打卡记录",
            "打卡数据",
            "通行记录",
            "门禁记录",
            "事件记录",
            "异常记录",
            "出现过",
            "发生过",
            "这份",
            "该份",
            "当前",
            "本次",
            "这张",
            "该张",
            "考勤表",
            "考勤明细",
            "工作表",
            "工作簿",
            "帮我查一下",
            "请帮我",
            "请问",
            "有无",
            "存在",
            "包含",
            "出现",
            "发生",
            "或者",
            "以及",
            "记录",
            "数据",
            "打卡",
            "考勤",
            "通行",
            "门禁",
            "事件",
            "结果",
            "状态",
            "表格",
            "文件",
            "核验",
            "检查",
            "确认",
            "查询",
            "是否",
            "中的",
            "里面",
            "当中",
            "请",
            "在",
            "中",
            "里",
            "内",
            "有",
            "或",
            "和",
            "与",
            "的",
            "吗",
            "么",
            "呢",
        ),
        key=len,
        reverse=True,
    )
)
_EVENT_RESULT_RESIDUAL_PATTERN: Final = re.compile(
    r"[\s,，。？！?!、；;：:/\"'“”‘’()（）《》【】\[\]]+"
)
_DEVICE_FREQUENCY_ATTENDANCE_TERMS: Final = (
    "打卡",
    "考勤",
    "刷卡",
    "门禁记录",
    "通行记录",
    "门禁设备",
    "闸机设备",
    "考勤设备",
)
_DEVICE_FREQUENCY_DEVICE_TERMS: Final = (
    "闸机设备",
    "门禁设备",
    "考勤设备",
    "打卡设备",
    "闸机",
    "门禁机",
    "考勤机",
    "设备名称",
    "设备",
)
_DEVICE_FREQUENCY_AGGREGATE_TERMS: Final = (
    "使用频率最高",
    "使用最频繁",
    "出现次数最多",
    "打卡次数最多",
    "记录次数最多",
    "记录最多",
    "次数最多",
    "使用最多",
    "频率最高",
    "频次最高",
    "最常使用",
    "最常用",
    "记录最少",
    "次数最少",
    "使用最少",
    "频率最低",
    "频次最低",
    "最不常用",
    "打卡最多",
    "考勤最多",
    "通行最多",
    "排行榜",
    "排行",
    "排名",
    "top",
    "分别有多少",
    "各有多少",
    "每台",
)
_DEVICE_FREQUENCY_NEUTRAL_PHRASES: Final = tuple(
    sorted(
        (
            "在所有闸机设备中",
            "所有闸机设备中",
            "所有闸机设备",
            "哪台门禁设备",
            "哪台闸机",
            "哪个闸机",
            "哪一个考勤设备",
            "打卡记录最多",
            "打卡次数最多",
            "考勤记录最多",
            "通行记录最多",
            "记录次数最多",
            "出现次数最多",
            "使用频率最高",
            "使用最频繁",
            "频率最高",
            "频次最高",
            "使用最多",
            "最常使用",
            "最常用",
            "共记录了多少次",
            "共记录多少次",
            "一共记录了多少次",
            "一共记录多少次",
            "共计多少次",
            "总共多少次",
            "共多少次",
            "共几次",
            "有多少次",
            "多少次",
            "是哪一个",
            "是哪一台",
            "是哪台",
            "是哪个",
            "是什么",
            "哪个设备",
            "哪台设备",
            "设备名称",
            "闸机设备",
            "门禁设备",
            "考勤设备",
            "打卡设备",
            "打卡记录",
            "考勤记录",
            "刷卡记录",
            "通行记录",
            "门禁记录",
            "记录",
            "打卡",
            "考勤",
            "刷卡",
            "设备",
            "闸机",
            "门禁机",
            "考勤机",
            "所有",
            "全部",
            "其中",
            "请问",
            "请",
            "在",
            "中",
            "里",
            "的",
            "了",
            "共",
        ),
        key=len,
        reverse=True,
    )
)
_DEVICE_FREQUENCY_RESIDUAL_PATTERN: Final = re.compile(
    r"[\s,，。？！?!、；;：:/\"'“”‘’()（）《》【】\[\]]+"
)
_MISSING_DEVICE_LABELS: Final = frozenset(
    (
        "-",
        "--",
        "—",
        "n/a",
        "#n/a",
        "na",
        "nan",
        "null",
        "none",
        "unknown",
        "未知",
        "无",
        "不详",
        "未填写",
        "未设置",
        "未分配",
    )
)
_DEPARTMENT_SUMMARY_ATTENDANCE_TERMS: Final = (
    "考勤记录",
    "考勤数据",
    "考勤表",
    "考勤明细",
    "打卡记录",
    "打卡数据",
    "打卡表",
    "门禁记录",
    "通行记录",
)
_DEPARTMENT_SUMMARY_REQUEST_TERMS: Final = (
    "多少个不同",
    "几个不同",
    "多少个部门",
    "几个部门",
    "哪些部门",
    "部门有哪些",
    "所有部门",
    "全部部门",
    "部门名称",
    "部门名单",
    "部门清单",
    "部门列表",
    "每个部门",
    "各部门",
    "部门排名",
    "部门排行",
    "部门总数",
    "部门数量",
    "部门种类",
    "部门分布",
    "多少种",
    "几种",
    "去重",
    "汇总",
    "统计",
)
_DEPARTMENT_SUMMARY_NEUTRAL_PHRASES: Final = tuple(
    sorted(
        (
            "请列出部门名称",
            "请列出名称",
            "请全部列出",
            "请查看",
            "查询",
            "根据",
            "基于",
            "参照",
            "请汇总",
            "请说明",
            "请解释",
            "告诉我",
            "说明",
            "解释",
            "员工考勤记录",
            "人员考勤记录",
            "员工考勤数据",
            "人员考勤数据",
            "部门去重后有多少",
            "部门总数是多少",
            "部门数量和名称是什么",
            "包含多少种部门",
            "多少种不同部门",
            "多少种部门",
            "几种不同部门",
            "几种部门",
            "部门种类有哪些",
            "多少个组织部门",
            "多少个独立部门",
            "几个组织部门",
            "几个独立部门",
            "包含哪些部门名称",
            "多少个部门",
            "几个部门",
            "分别是什么",
            "多少个不同的部门",
            "多少个不同部门",
            "几个不同的部门",
            "几个不同部门",
            "所有部门有哪些",
            "全部部门有哪些",
            "有哪些部门",
            "部门有哪些",
            "请列出",
            "一共包含了",
            "一共包含",
            "总共包含了",
            "总共包含",
            "考勤记录",
            "考勤数据",
            "考勤表",
            "考勤明细",
            "打卡记录",
            "打卡数据",
            "打卡表",
            "门禁记录",
            "通行记录",
            "部门名称",
            "部门名单",
            "部门清单",
            "部门列表",
            "部门总数",
            "部门数量",
            "部门种类",
            "组织部门",
            "所属部门",
            "独立部门",
            "所有部门",
            "全部部门",
            "去重后有多少",
            "去重后",
            "去重",
            "汇总",
            "统计",
            "是多少",
            "是什么",
            "分别",
            "和名称",
            "名称",
            "数量",
            "并",
            "哪些",
            "不同",
            "叫什么",
            "都",
            "多少种",
            "几种",
            "多少",
            "几个",
            "涉及的",
            "涉及",
            "这份",
            "该份",
            "当前",
            "请问",
            "麻烦",
            "帮我",
            "列出",
            "部门",
            "一共",
            "总共",
            "共有",
            "包含",
            "里有",
            "中有",
            "中的",
            "中",
            "里",
            "内",
            "请",
            "的",
            "了",
            "有",
        ),
        key=len,
        reverse=True,
    )
)
_DEPARTMENT_SUMMARY_RESIDUAL_PATTERN: Final = re.compile(
    r"[\s,，。？！?!、；;：:/\"'“”‘’()（）《》【】\[\]]+"
)
_DEPARTMENT_SUMMARY_UNSUPPORTED_TERMS: Final = (
    "每个部门",
    "各部门",
    "多少人",
    "几个人",
    "人数",
    "姓名",
    "工号",
    "卡号",
    "排名",
    "排行",
    "top",
    "排除",
    "剔除",
    "不包括",
    "除了",
    "设备",
    "闸机",
    "门禁机",
    "考勤机",
    "认证",
    "验证",
    "成功",
    "失败",
    "异常",
    "黑名单",
    "白名单",
    "次数",
    "频率",
    "占比",
    "比例",
    "分布",
    "分组",
)
_DEPARTMENT_SUMMARY_PROSE_TERMS: Final = (
    "制度",
    "流程",
    "规范",
    "定义",
    "职责",
    "政策",
    "手册",
    "部门说明",
    "字段说明",
    "数据说明",
)
_MISSING_SPREADSHEET_VALUE_LABELS: Final = frozenset(
    (
        *_MISSING_DEVICE_LABELS,
        "#ref!",
        "#value!",
        "#div/0!",
        "#name?",
        "#num!",
        "#null!",
        "#spill!",
        "#calc!",
    )
)
_MISSING_DEPARTMENT_LABELS: Final = _MISSING_SPREADSHEET_VALUE_LABELS

_HEADER_ALIASES: Final[dict[str, dict[str, int]]] = {
    "employee_id": {
        "人员工号": 0,
        "员工工号": 0,
        "工号": 1,
        "人员编号": 1,
        "员工编号": 1,
    },
    "card_number": {
        "卡号": 0,
        "门禁卡号": 0,
        "考勤卡号": 0,
        "卡片编号": 1,
    },
    "employee_name": {
        "姓名": 0,
        "员工姓名": 0,
        "人员姓名": 0,
    },
    "department": {
        "部门": 0,
        "部门名称": 0,
        "所属部门": 0,
        "组织部门": 1,
    },
    "timestamp": {
        "时间": 0,
        "打卡时间": 0,
        "考勤时间": 0,
        "通行时间": 0,
        "记录时间": 1,
        "事件时间": 1,
        "刷卡时间": 1,
    },
    "device": {
        "设备": 0,
        "设备名称": 0,
        "闸机": 0,
        "闸机名称": 0,
        "门禁闸机名称": 0,
        "通行设备": 0,
        "打卡设备": 0,
        "考勤设备": 0,
        "门禁设备": 0,
        "出入口名称": 1,
        "通道名称": 1,
        "门名称": 1,
        "考勤点": 2,
        "位置": 2,
    },
    "event_result": {
        "事件结果": 0,
        "事件详情": 0,
        "认证结果": 0,
        "验证结果": 0,
        "通行结果": 0,
        "刷卡结果": 0,
        "处理结果": 1,
        "结果": 2,
    },
}


@dataclass(frozen=True, slots=True)
class SpreadsheetTable:
    title: str
    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    citation_numbers: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class SpreadsheetAnswer:
    answer: str
    table: SpreadsheetTable | None
    hits: tuple[KnowledgeSearchHit, ...]


class SpreadsheetQueryStatus(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    REJECTED = "rejected"
    ANSWERED = "answered"


@dataclass(frozen=True, slots=True)
class SpreadsheetQueryResult:
    status: SpreadsheetQueryStatus
    answer: SpreadsheetAnswer | None
    rejection_message: str | None = None

    @property
    def applicable(self) -> bool:
        return self.status is not SpreadsheetQueryStatus.NOT_APPLICABLE


@dataclass(frozen=True, slots=True)
class _EntrySource:
    id: UUID
    source_file_id: UUID | None
    title: str
    source_path: str | None
    format_version: str | None
    source_text: str
    source_locations: tuple[str, ...]
    source_location_count: int | None
    locations_truncated: bool
    source_text_sha256: str
    source_locations_sha256: str | None
    integrity_metadata: bool


@dataclass(frozen=True, slots=True)
class _Cell:
    column: str
    value: str


@dataclass(frozen=True, slots=True)
class _Row:
    entry: _EntrySource
    sheet: str
    number: int
    cells: tuple[_Cell, ...]

    def value(self, column: str | None) -> str | None:
        if column is None:
            return None
        return next((cell.value for cell in self.cells if cell.column == column), None)

    @property
    def excerpt(self) -> str:
        return " ".join(
            f"[worksheet:{self.sheet}!{cell.column}{self.number}] {cell.value}"
            for cell in self.cells
        )


@dataclass(frozen=True, slots=True)
class _Sheet:
    rows: tuple[_Row, ...]
    columns: dict[str, str | None]
    ambiguous: frozenset[str]


@dataclass(frozen=True, slots=True)
class _Record:
    row: _Row
    sheet: _Sheet
    timestamp: datetime | None = None


@dataclass(frozen=True, slots=True)
class _EventResultCoverage:
    entry: _EntrySource
    sheet: str
    column: str
    first_row: int
    last_row: int
    scanned_rows: int
    counts: tuple[tuple[str, int], ...]
    matched_rows: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _DeviceFrequencyCoverage:
    entry: _EntrySource
    sheet: str
    column: str
    first_row: int
    last_row: int
    scanned_rows: int
    counts: tuple[tuple[str, str, int], ...]


@dataclass(frozen=True, slots=True)
class _DepartmentSummaryCoverage:
    entry: _EntrySource
    sheet: str
    column: str
    first_row: int
    last_row: int
    scanned_rows: int
    departments: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _QuestionIntent:
    latest_record: bool
    time_range: bool
    employee_field: str | None
    department_employees: bool
    department_summary: bool
    event_result_existence: bool
    device_frequency: bool

    @property
    def applicable(self) -> bool:
        return any(
            (
                self.latest_record,
                self.time_range,
                self.employee_field,
                self.department_employees,
                self.department_summary,
                self.event_result_existence,
                self.device_frequency,
            )
        )


def is_spreadsheet_query_intent(question: str) -> bool:
    """Return whether a question must stay inside the fail-closed table path."""

    normalized = unicodedata.normalize("NFKC", question).strip()
    return bool(normalized and _question_intent(normalized).applicable)


async def evaluate_spreadsheet_query(
    session: AsyncSession,
    knowledge_base_id: UUID,
    question: str,
) -> SpreadsheetQueryResult:
    """Evaluate table intent without allowing unsafe cases to fall through to RAG."""

    if not is_spreadsheet_query_intent(question):
        return SpreadsheetQueryResult(status=SpreadsheetQueryStatus.NOT_APPLICABLE, answer=None)
    answer = await answer_spreadsheet_query(session, knowledge_base_id, question)
    if answer is None:
        return SpreadsheetQueryResult(
            status=SpreadsheetQueryStatus.REJECTED,
            answer=None,
            rejection_message=SPREADSHEET_REJECTION_MESSAGE,
        )
    return SpreadsheetQueryResult(status=SpreadsheetQueryStatus.ANSWERED, answer=answer)


async def answer_spreadsheet_query(
    session: AsyncSession,
    knowledge_base_id: UUID,
    question: str,
) -> SpreadsheetAnswer | None:
    """Answer supported spreadsheet questions from published XLSX evidence only."""

    normalized_question = unicodedata.normalize("NFKC", question).strip()
    if not normalized_question:
        return None
    intent = _question_intent(normalized_question)
    if not intent.applicable:
        return None
    sources = await _load_sources(session, knowledge_base_id)
    if sources is None:
        return None
    sources = _select_sources(sources, normalized_question)
    if sources is None:
        return None
    sheets = _reconstruct_sheets(sources)
    if not sheets:
        return None

    if intent.device_frequency:
        return _answer_device_frequency(sheets, normalized_question)
    if intent.department_summary:
        return _answer_department_summary(
            sheets,
            _strip_selected_source_filename_mentions(normalized_question, sources),
        )
    if intent.event_result_existence:
        return _answer_event_result_existence(sheets, normalized_question)
    if intent.latest_record:
        return _answer_latest_record(sheets, normalized_question)
    if intent.time_range:
        return _answer_time_range(sheets)
    if intent.employee_field == "employee_id":
        return _answer_employee_field(
            sheets,
            normalized_question,
            field="employee_id",
            field_label="人员工号",
        )
    if intent.employee_field == "card_number":
        return _answer_employee_field(
            sheets,
            normalized_question,
            field="card_number",
            field_label="卡号",
        )
    if intent.department_employees:
        return _answer_department_employees(sheets, normalized_question)
    return None


def _question_intent(question: str) -> _QuestionIntent:
    employee_lookup = _has_employee_field_lookup_shape(question)
    asks_employee_id = employee_lookup and "工号" in question
    asks_card_number = employee_lookup and "卡号" in question
    employee_field = (
        "ambiguous"
        if asks_employee_id and asks_card_number
        else "employee_id"
        if asks_employee_id
        else "card_number"
        if asks_card_number
        else None
    )
    employee_list_request = any(
        token in question for token in ("哪几位", "有谁", "哪些", "名单", "多少位", "总共有")
    ) or (
        any(token in question for token in ("列出", "列举"))
        and re.search(r"部门.{0,4}(?:员工|人员)", question) is not None
    )
    department_employee_scope = (
        re.search(
            r"部(?:门)?.{0,12}(?:员工|人员)",
            question,
        )
        is not None
    )
    department_employees = department_employee_scope and employee_list_request
    return _QuestionIntent(
        latest_record=_is_latest_record_question(question),
        time_range=_is_time_range_question(question),
        employee_field=employee_field,
        department_employees=department_employees,
        department_summary=(_is_department_summary_question(question) and not department_employees),
        event_result_existence=_is_event_result_existence_question(question),
        device_frequency=_is_device_frequency_question(question),
    )


def _has_employee_field_lookup_shape(question: str) -> bool:
    if not any(token in question for token in ("多少", "什么", "是", "为", "查询", "分别")):
        return False
    if re.search(r"[“\"][^”\"]{1,50}[”\"]\s*的", question):
        return True
    if re.search(
        r"(?:员工|人员)\s*[“\"]?[A-Za-z0-9一-鿿·_-]{2,40}[”\"]?\s*的",
        question,
    ):
        return True
    generic_subjects = {"公司", "本公司", "企业", "部门", "项目", "系统", "平台", "员工", "人员"}
    subjects = re.findall(r"([A-Za-z0-9一-鿿·_-]{2,40})的", question)
    return any(subject not in generic_subjects for subject in subjects)


def _is_department_summary_question(question: str) -> bool:
    semantic_question = _strip_spreadsheet_filename_mentions(question).casefold()
    if any(term in semantic_question for term in _DEPARTMENT_SUMMARY_PROSE_TERMS):
        return False
    attendance_context = any(
        term in semantic_question for term in _DEPARTMENT_SUMMARY_ATTENDANCE_TERMS
    )
    department_context = "部门" in semantic_question
    summary_request = any(
        term in semantic_question for term in _DEPARTMENT_SUMMARY_REQUEST_TERMS
    ) or any(term in semantic_question for term in ("多少", "几个", "哪些", "叫什么"))
    list_request = (
        re.search(
            r"(?:列出|列举).{0,24}部门|部门.{0,24}(?:列出|列举)",
            semantic_question,
        )
        is not None
    )
    return attendance_context and department_context and (summary_request or list_request)


def _has_unsupported_department_summary_scope(question: str) -> bool:
    semantic_question = _strip_spreadsheet_filename_mentions(question).casefold()
    if _question_date(semantic_question) is not None:
        return True
    if any(term in semantic_question for term in _DEPARTMENT_SUMMARY_UNSUPPORTED_TERMS):
        return True
    residual = semantic_question
    for phrase in _DEPARTMENT_SUMMARY_NEUTRAL_PHRASES:
        residual = residual.replace(phrase, "")
    return bool(_DEPARTMENT_SUMMARY_RESIDUAL_PATTERN.sub("", residual))


def _is_device_frequency_question(question: str) -> bool:
    semantic_question = _strip_spreadsheet_filename_mentions(question).casefold()
    attendance_context = any(
        term in semantic_question for term in _DEVICE_FREQUENCY_ATTENDANCE_TERMS
    )
    device_context = any(term in semantic_question for term in _DEVICE_FREQUENCY_DEVICE_TERMS)
    aggregate_request = any(term in semantic_question for term in _DEVICE_FREQUENCY_AGGREGATE_TERMS)
    return attendance_context and device_context and aggregate_request


def _has_unsupported_device_frequency_scope(question: str) -> bool:
    residual = _strip_spreadsheet_filename_mentions(question)
    for phrase in _DEVICE_FREQUENCY_NEUTRAL_PHRASES:
        residual = residual.replace(phrase, "")
    return bool(_DEVICE_FREQUENCY_RESIDUAL_PATTERN.sub("", residual))


def _is_event_result_existence_question(question: str) -> bool:
    has_spreadsheet_reference = _has_spreadsheet_filename_mention(question)
    semantic_question = _strip_spreadsheet_filename_mentions(question)
    if any(token in semantic_question for token in _EVENT_RESULT_POLICY_TERMS):
        return False
    existence_query = any(
        token in semantic_question
        for token in (
            "有没有",
            "是否有",
            "有无",
            "是否存在",
            "是否包含",
            "是否出现",
            "是否发生",
        )
    ) or bool(
        re.search(
            r"(?:记录|数据).{0,12}(?:里|中)?(?:有|存在|包含|出现|发生).{0,40}[吗么?？]",
            semantic_question,
        )
        or re.search(
            r"(?:有|存在|包含|出现|发生).{0,40}(?:记录|事件).{0,3}[吗么?？]",
            semantic_question,
        )
    )
    attendance_records = any(
        token in semantic_question
        for token in ("考勤", "打卡", "通行记录", "门禁记录", "考勤数据", "打卡数据")
    ) or (has_spreadsheet_reference and "记录" in semantic_question)
    result_condition = bool(_event_result_terms(semantic_question)) or any(
        token in semantic_question
        for token in ("事件结果", "认证结果", "验证结果", "通行结果", "刷卡结果")
    )
    return existence_query and attendance_records and result_condition


def _strip_spreadsheet_filename_mentions(question: str) -> str:
    without_quoted_files = _QUOTED_TERM_PATTERN.sub(_quoted_filename_replacement, question)
    return _SPREADSHEET_REFERENCE_PATTERN.sub("", without_quoted_files)


def _has_spreadsheet_filename_mention(question: str) -> bool:
    return bool(_mentioned_spreadsheet_filename_candidates(question))


def _mentioned_spreadsheet_filename_candidates(
    question: str,
) -> tuple[frozenset[str], ...]:
    normalized = unicodedata.normalize("NFKC", question)
    mentions: list[frozenset[str]] = []
    for match in _SPREADSHEET_REFERENCE_PATTERN.finditer(normalized):
        raw_name = re.split(r"[/\\]", match.group(0))[-1].strip().casefold()
        candidates = {raw_name}
        candidate = raw_name
        stripped_prefix = True
        while stripped_prefix:
            stripped_prefix = False
            for prefix in _SPREADSHEET_REFERENCE_PREFIXES:
                normalized_prefix = unicodedata.normalize("NFKC", prefix).casefold()
                if candidate.startswith(normalized_prefix) and len(candidate) > len(
                    normalized_prefix
                ):
                    candidate = candidate[len(normalized_prefix) :]
                    candidates.add(candidate)
                    stripped_prefix = True
                    break
        mentions.append(frozenset(candidates))
    return tuple(mentions)


def _quoted_filename_replacement(match: re.Match[str]) -> str:
    value = unicodedata.normalize("NFKC", match.group(1)).strip()
    return "" if _SPREADSHEET_FILENAME_PATTERN.search(value) is not None else value


def _event_result_terms(question: str) -> tuple[str, ...]:
    quoted = tuple(
        value
        for match in _QUOTED_TERM_PATTERN.finditer(question)
        if (value := unicodedata.normalize("NFKC", match.group(1)).strip())
        and any(marker in value for marker in _EVENT_RESULT_TERM_MARKERS)
        and _SPREADSHEET_FILENAME_PATTERN.search(value) is None
        and not value.endswith(("文件", "工作簿", "考勤表", "数据表"))
        and not any(token in value for token in ("有没有", "是否", "有无", "或", "和", "与", "、"))
    )
    discovery_question = _QUOTED_TERM_PATTERN.sub(_quoted_discovery_text, question)
    discovered = tuple(term for term in _EVENT_RESULT_QUERY_TERMS if term in discovery_question)
    candidates = (*quoted, *discovered)
    ordered = tuple(
        sorted(
            candidates,
            key=lambda term: (
                question.find(term) if term in question else len(question),
                -len(term),
            ),
        )
    )
    return _deduplicate_terms(ordered)


def _quoted_discovery_text(match: re.Match[str]) -> str:
    value = unicodedata.normalize("NFKC", match.group(1)).strip()
    if _SPREADSHEET_FILENAME_PATTERN.search(value) is not None or value.endswith(
        ("文件", "工作簿", "考勤表", "数据表")
    ):
        return ""
    return value


def _deduplicate_terms(terms: tuple[str, ...]) -> tuple[str, ...]:
    selected: list[str] = []
    for term in terms:
        if (
            len(term) > _MAX_LABEL_CHARACTERS
            or term in selected
            or any(term in existing for existing in selected)
        ):
            continue
        selected = [existing for existing in selected if existing not in term]
        selected.append(term)
    return tuple(selected)


def _event_result_matches(value: str, term: str) -> bool:
    normalized_value = unicodedata.normalize("NFKC", value).casefold().strip()
    normalized_term = unicodedata.normalize("NFKC", term).casefold().strip()
    if not normalized_value or not normalized_term:
        return False
    if normalized_value == normalized_term or normalized_value.startswith(normalized_term):
        return True
    return any(
        segment.startswith(normalized_term)
        for segment in _EVENT_RESULT_SEGMENT_PATTERN.split(normalized_value)
        if segment
    )


async def _load_sources(
    session: AsyncSession, knowledge_base_id: UUID
) -> tuple[_EntrySource, ...] | None:
    statement = (
        select(KnowledgeEntry)
        .where(
            KnowledgeEntry.knowledge_base_id == knowledge_base_id,
            KnowledgeEntry.deleted_at.is_(None),
            KnowledgeEntry.publication_status == KnowledgeEntryPublicationStatus.PUBLISHED,
            KnowledgeEntry.custom_metadata["source_parser"].as_string().in_(_SOURCE_PARSERS),
        )
        .order_by(KnowledgeEntry.title, KnowledgeEntry.id)
        .limit(_MAX_ENTRIES + 1)
    )
    entries = tuple((await session.scalars(statement)).all())
    if not entries or len(entries) > _MAX_ENTRIES:
        return None
    if sum(len(entry.content) for entry in entries) > _MAX_TOTAL_CHARACTERS:
        return None
    sources: list[_EntrySource] = []
    for entry in entries:
        generator = entry.custom_metadata.get("generator")
        if (
            not isinstance(generator, dict)
            or generator.get("provider") != "local"
            or generator.get("model") != "local-deterministic-v1"
        ):
            return None
        raw_locations = entry.custom_metadata.get("source_locations")
        if not isinstance(raw_locations, list) or not all(
            isinstance(location, str) for location in raw_locations
        ):
            return None
        source_locations = tuple(raw_locations)
        if (
            not source_locations
            or len(source_locations) > _MAX_METADATA_LOCATIONS
            or len(set(source_locations)) != len(source_locations)
            or not all(_valid_source_location(location) for location in source_locations)
        ):
            return None
        source_location_count = entry.custom_metadata.get("source_location_count")
        locations_truncated = entry.custom_metadata.get("source_locations_truncated")
        source_text_length = entry.custom_metadata.get("source_text_length")
        source_text_sha256 = entry.custom_metadata.get("source_text_sha256")
        source_locations_sha256 = entry.custom_metadata.get("source_locations_sha256")
        integrity_values = (
            source_location_count,
            locations_truncated,
            source_text_length,
            source_text_sha256,
            source_locations_sha256,
        )
        integrity_metadata = all(value is not None for value in integrity_values)
        if any(value is not None for value in integrity_values) and not integrity_metadata:
            return None
        if integrity_metadata:
            if (
                not isinstance(source_location_count, int)
                or isinstance(source_location_count, bool)
                or source_location_count < len(source_locations)
                or not isinstance(locations_truncated, bool)
                or locations_truncated != (source_location_count > len(source_locations))
                or not isinstance(source_text_length, int)
                or isinstance(source_text_length, bool)
                or source_text_length <= 0
                or source_text_length > len(entry.content)
                or not isinstance(source_text_sha256, str)
                or _SHA256_PATTERN.fullmatch(source_text_sha256) is None
                or not isinstance(source_locations_sha256, str)
                or _SHA256_PATTERN.fullmatch(source_locations_sha256) is None
            ):
                return None
            source_text = entry.content[-source_text_length:]
            if sha256(source_text.encode("utf-8")).hexdigest() != source_text_sha256:
                return None
        else:
            if len(source_locations) >= _MAX_METADATA_LOCATIONS:
                return None
            legacy_source_text = _legacy_source_text(entry.content)
            if legacy_source_text is None:
                return None
            source_text = legacy_source_text
            source_location_count = None
            locations_truncated = False
            source_text_sha256 = sha256(source_text.encode("utf-8")).hexdigest()
            source_locations_sha256 = None
        sources.append(
            _EntrySource(
                id=entry.id,
                source_file_id=entry.source_file_id,
                title=entry.title,
                source_path=entry.source_path,
                format_version=entry.format_version,
                source_text=source_text,
                source_locations=source_locations,
                source_location_count=source_location_count,
                locations_truncated=locations_truncated,
                source_text_sha256=source_text_sha256,
                source_locations_sha256=source_locations_sha256,
                integrity_metadata=integrity_metadata,
            )
        )
    return tuple(sources)


def _select_sources(
    sources: tuple[_EntrySource, ...], question: str
) -> tuple[_EntrySource, ...] | None:
    normalized_question = unicodedata.normalize("NFKC", question).casefold()
    direct_matches: list[tuple[int, int, _EntrySource]] = []
    for source in sources:
        for filename in _source_spreadsheet_filenames(source):
            if not any(character.isspace() for character in filename):
                continue
            start = normalized_question.find(filename)
            while start >= 0:
                prefix_text = normalized_question[:start]
                has_boundary = start == 0 or normalized_question[start - 1] in (
                    " \t\r\n，。？！?：:；;、/\\\"'“”‘’《》【】()（）"
                )
                has_known_prefix = any(
                    prefix_text.endswith(unicodedata.normalize("NFKC", prefix).casefold())
                    for prefix in _SPREADSHEET_REFERENCE_PREFIXES
                )
                if has_boundary or has_known_prefix:
                    direct_matches.append((start, start + len(filename), source))
                start = normalized_question.find(filename, start + 1)
    if direct_matches:
        visible_matches = tuple(
            match
            for match in direct_matches
            if not any(
                other_start <= match[0]
                and match[1] <= other_end
                and (other_start, other_end) != match[:2]
                for other_start, other_end, _ in direct_matches
            )
        )
        directly_selected = {match[2].id: match[2] for match in visible_matches}
        if len(directly_selected) != 1:
            return None
        return (next(iter(directly_selected.values())),)

    explicit_mentions = _mentioned_spreadsheet_filename_candidates(question)
    if explicit_mentions:
        explicitly_selected: dict[UUID, _EntrySource] = {}
        for mention in explicit_mentions:
            matches = [
                source
                for source in sources
                if not _source_spreadsheet_filenames(source).isdisjoint(mention)
            ]
            if len(matches) != 1:
                return None
            explicitly_selected[matches[0].id] = matches[0]
        if len(explicitly_selected) != 1:
            return None
        return (next(iter(explicitly_selected.values())),)
    if len(sources) == 1:
        return sources
    fingerprints = {_source_fingerprint(source) for source in sources}
    return (sources[0],) if len(fingerprints) == 1 else None


def _source_spreadsheet_filenames(source: _EntrySource) -> frozenset[str]:
    title = unicodedata.normalize("NFKC", source.title).strip().casefold()
    if not title:
        return frozenset()
    if _SPREADSHEET_FILENAME_PATTERN.search(title) is not None:
        return frozenset((title,))
    return frozenset((f"{title}.xlsx", f"{title}.xls"))


def _strip_selected_source_filename_mentions(
    question: str,
    sources: tuple[_EntrySource, ...],
) -> str:
    stripped = unicodedata.normalize("NFKC", question)
    filenames = sorted(
        (filename for source in sources for filename in _source_spreadsheet_filenames(source)),
        key=len,
        reverse=True,
    )
    for filename in filenames:
        stripped = re.sub(re.escape(filename), "", stripped, flags=re.IGNORECASE)
    return stripped


def _source_fingerprint(source: _EntrySource) -> bytes:
    return bytes.fromhex(source.source_text_sha256)


def _reconstruct_sheets(sources: tuple[_EntrySource, ...]) -> tuple[_Sheet, ...]:
    reconstructed: list[_Sheet] = []
    total_rows = 0
    for source in sources:
        grouped: dict[tuple[str, int], dict[str, str]] = {}
        matches = tuple(_CELL_PATTERN.finditer(source.source_text))
        if source.source_text.count("[worksheet:") != len(matches):
            return ()
        seen_locations: set[str] = set()
        full_location_order: list[str] = []
        seen_sheets: set[str] = set()
        for index, match in enumerate(matches):
            marker_prefix = source.source_text[max(0, match.start() - 2) : match.start()]
            if match.start() > 0 and marker_prefix != "\n\n":
                return ()
            end = (
                matches[index + 1].start() if index + 1 < len(matches) else len(source.source_text)
            )
            value = source.source_text[match.end() : end].strip()
            if not value:
                continue
            sheet_name = match.group("sheet")
            row_number = int(match.group("row"))
            column = match.group("column").upper()
            location = f"worksheet:{sheet_name}!{column}{row_number}"
            if (
                location in seen_locations
                or row_number > _MAX_EXCEL_ROW
                or _column_number(column) > _MAX_EXCEL_COLUMN
                or len(value) > _MAX_CELL_CHARACTERS
            ):
                return ()
            seen_locations.add(location)
            if sheet_name not in seen_sheets:
                seen_sheets.add(sheet_name)
                full_location_order.append(f"worksheet:{sheet_name}")
            full_location_order.append(location)
            key = (sheet_name, row_number)
            cells = grouped.setdefault(key, {})
            if column in cells and cells[column] != value:
                return ()
            cells[column] = value
        trusted_locations = source.source_locations
        if tuple(full_location_order[: len(trusted_locations)]) != trusted_locations:
            return ()
        if source.integrity_metadata:
            if len(full_location_order) != source.source_location_count:
                return ()
            location_digest = sha256("\n".join(full_location_order).encode("utf-8")).hexdigest()
            if location_digest != source.source_locations_sha256:
                return ()
        elif not source.locations_truncated and tuple(full_location_order) != trusted_locations:
            return ()
        by_sheet: dict[str, list[_Row]] = {}
        for (sheet_name, row_number), cells in grouped.items():
            row = _Row(
                entry=source,
                sheet=sheet_name,
                number=row_number,
                cells=tuple(
                    _Cell(column=column, value=value)
                    for column, value in sorted(
                        cells.items(), key=lambda item: _column_number(item[0])
                    )
                ),
            )
            by_sheet.setdefault(sheet_name, []).append(row)
        for rows in by_sheet.values():
            ordered = tuple(sorted(rows, key=lambda item: item.number))
            inferred = _infer_sheet(ordered)
            if inferred is not None:
                reconstructed.append(inferred)
                total_rows += len(inferred.rows)
                if total_rows > _MAX_ROWS:
                    return ()
    return tuple(reconstructed)


def _infer_sheet(rows: tuple[_Row, ...]) -> _Sheet | None:
    candidates: list[tuple[int, int, int, _Row, dict[str, str | None], frozenset[str]]] = []
    for row in rows[:50]:
        by_kind: dict[str, list[tuple[int, str]]] = {}
        for cell in row.cells:
            normalized = _normalize_header(cell.value)
            for kind, aliases in _HEADER_ALIASES.items():
                if normalized in aliases:
                    by_kind.setdefault(kind, []).append((aliases[normalized], cell.column))
        if not by_kind:
            continue
        resolved: dict[str, str | None] = {}
        row_ambiguous: set[str] = set()
        for kind, options in by_kind.items():
            best_priority = min(priority for priority, _ in options)
            best_columns = {column for priority, column in options if priority == best_priority}
            if len(best_columns) == 1:
                resolved[kind] = next(iter(best_columns))
            else:
                resolved[kind] = None
                row_ambiguous.add(kind)
        candidates.append(
            (
                len(resolved) - len(row_ambiguous),
                len(by_kind),
                -row.number,
                row,
                resolved,
                frozenset(row_ambiguous),
            )
        )
    if not candidates:
        return None
    _, _, _, header, columns, header_ambiguities = max(candidates, key=lambda item: item[:3])
    if len(columns) < 2:
        return None
    return _Sheet(
        rows=tuple(row for row in rows if row.number > header.number),
        columns=columns,
        ambiguous=header_ambiguities,
    )


def _answer_department_summary(
    sheets: tuple[_Sheet, ...], question: str
) -> SpreadsheetAnswer | None:
    if _has_unsupported_department_summary_scope(question):
        return None

    attendance_sheets: list[_Sheet] = []
    for sheet in sheets:
        timestamp_shape = "timestamp" in sheet.columns
        device_shape = "device" in sheet.columns
        identity_shape = any(
            kind in sheet.columns for kind in ("employee_id", "card_number", "employee_name")
        )
        if not (timestamp_shape and device_shape and identity_shape):
            continue
        if not sheet.rows:
            continue
        if not _valid_coverage_sheet_name(sheet.rows[0].sheet):
            return None
        timestamp_signal = (
            sheet.columns.get("timestamp") is not None and "timestamp" not in sheet.ambiguous
        )
        device_signal = sheet.columns.get("device") is not None and "device" not in sheet.ambiguous
        identity_signal = any(
            sheet.columns.get(kind) is not None and kind not in sheet.ambiguous
            for kind in ("employee_id", "card_number", "employee_name")
        )
        department_column = sheet.columns.get("department")
        if (
            not timestamp_signal
            or not device_signal
            or not identity_signal
            or "department" not in sheet.columns
            or department_column is None
            or "department" in sheet.ambiguous
        ):
            return None
        attendance_sheets.append(sheet)
    if not attendance_sheets:
        return None

    display_labels: dict[str, str] = {}
    coverages: list[_DepartmentSummaryCoverage] = []
    total_scanned = 0
    for sheet in attendance_sheets:
        department_column = sheet.columns.get("department")
        timestamp_column = sheet.columns.get("timestamp")
        device_column = sheet.columns.get("device")
        identity_columns = tuple(
            column
            for kind in ("employee_id", "card_number", "employee_name")
            if kind not in sheet.ambiguous and (column := sheet.columns.get(kind)) is not None
        )
        if (
            department_column is None
            or timestamp_column is None
            or device_column is None
            or not identity_columns
            or not sheet.rows
            or any(not row.entry.integrity_metadata for row in sheet.rows)
        ):
            return None

        sheet_department_keys: dict[str, None] = {}
        for row in sheet.rows:
            raw_timestamp = row.value(timestamp_column)
            raw_device = row.value(device_column)
            raw_department = row.value(department_column)
            if (
                raw_timestamp is None
                or _parse_datetime(raw_timestamp) is None
                or raw_device is None
                or _normalized_device_label(raw_device) is None
                or not any(
                    _normalized_identity_label(row.value(column) or "") is not None
                    for column in identity_columns
                )
                or raw_department is None
            ):
                return None
            normalized_department = _normalized_department_label(raw_department)
            if normalized_department is None:
                return None
            department_key, display_label = normalized_department
            display_labels.setdefault(department_key, display_label)
            sheet_department_keys.setdefault(department_key, None)
            if len(display_labels) > _MAX_TABLE_ROWS:
                return None

        coverages.append(
            _DepartmentSummaryCoverage(
                entry=sheet.rows[0].entry,
                sheet=sheet.rows[0].sheet,
                column=department_column,
                first_row=sheet.rows[0].number,
                last_row=sheet.rows[-1].number,
                scanned_rows=len(sheet.rows),
                departments=tuple(display_labels[key] for key in sheet_department_keys),
            )
        )
        total_scanned += len(sheet.rows)

    if not display_labels or total_scanned <= 0:
        return None
    hits = _build_department_summary_hits(coverages)
    if hits is None or not hits:
        return None

    departments = tuple(display_labels.values())
    safe_departments = "、".join(_citation_safe_text(label) for label in departments)
    titles = {coverage.entry.title for coverage in coverages}
    title = next(iter(titles)) if len(titles) == 1 else "选定考勤工作簿"
    answer = (
        f"在《{_citation_safe_text(title)}》中已完整扫描 {total_scanned} 条考勤记录，"
        f"共包含 {len(departments)} 个不同部门：{safe_departments}。{_citation_marker(hits)}"
    )
    return SpreadsheetAnswer(
        answer=answer,
        table=SpreadsheetTable(
            title="考勤部门统计",
            columns=("部门名称",),
            rows=tuple((department,) for department in departments),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _normalized_department_label(value: str) -> tuple[str, str] | None:
    normalized = unicodedata.normalize("NFKC", value)
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        return None
    display_label = re.sub(r"\s+", " ", normalized).strip()
    department_key = display_label.casefold()
    compact_key = re.sub(r"\s+", "", department_key)
    if (
        not display_label
        or len(display_label) > _MAX_LABEL_CHARACTERS
        or compact_key in _MISSING_DEPARTMENT_LABELS
        or not any(character.isalnum() for character in display_label)
    ):
        return None
    return department_key, display_label


def _valid_coverage_sheet_name(value: str) -> bool:
    normalized = unicodedata.normalize("NFKC", value)
    return bool(
        normalized
        and len(normalized) <= 31
        and not any(
            unicodedata.category(character).startswith("C") or character in ",#![]\r\n"
            for character in normalized
        )
    )


def _normalized_identity_label(value: str) -> str | None:
    normalized = unicodedata.normalize("NFKC", value)
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        return None
    display_label = re.sub(r"\s+", " ", normalized).strip()
    compact_key = re.sub(r"\s+", "", display_label.casefold())
    if (
        not display_label
        or len(display_label) > _MAX_LABEL_CHARACTERS
        or compact_key in _MISSING_SPREADSHEET_VALUE_LABELS
        or not any(character.isalnum() for character in display_label)
    ):
        return None
    return display_label


def _answer_device_frequency(sheets: tuple[_Sheet, ...], question: str) -> SpreadsheetAnswer | None:
    if _has_unsupported_device_frequency_scope(question):
        return None

    attendance_sheets: list[_Sheet] = []
    for sheet in sheets:
        timestamp_shape = "timestamp" in sheet.columns
        device_shape = "device" in sheet.columns
        identity_shape = any(
            kind in sheet.columns
            for kind in ("employee_id", "card_number", "employee_name", "department")
        )
        timestamp_signal = (
            sheet.columns.get("timestamp") is not None and "timestamp" not in sheet.ambiguous
        )
        identity_signal = any(
            sheet.columns.get(kind) is not None and kind not in sheet.ambiguous
            for kind in ("employee_id", "card_number", "employee_name", "department")
        )
        if timestamp_shape and identity_shape and not (timestamp_signal and identity_signal):
            return None
        if not (timestamp_signal and identity_signal):
            continue
        device_column = sheet.columns.get("device")
        if not device_shape or device_column is None or "device" in sheet.ambiguous:
            return None
        attendance_sheets.append(sheet)
    if not attendance_sheets:
        return None

    total_counts: dict[str, int] = {}
    display_labels: dict[str, str] = {}
    coverages: list[_DeviceFrequencyCoverage] = []
    total_scanned = 0
    for sheet in attendance_sheets:
        device_column = sheet.columns.get("device")
        timestamp_column = sheet.columns.get("timestamp")
        identity_columns = tuple(
            column
            for kind in ("employee_id", "card_number", "employee_name", "department")
            if kind not in sheet.ambiguous and (column := sheet.columns.get(kind)) is not None
        )
        if (
            device_column is None
            or timestamp_column is None
            or not identity_columns
            or not sheet.rows
            or any(not row.entry.integrity_metadata for row in sheet.rows)
        ):
            return None

        sheet_counts: dict[str, int] = {}
        for row in sheet.rows:
            raw_timestamp = row.value(timestamp_column)
            raw_device = row.value(device_column)
            if (
                raw_timestamp is None
                or _parse_datetime(raw_timestamp) is None
                or raw_device is None
                or not any((row.value(column) or "").strip() for column in identity_columns)
            ):
                return None
            normalized_device = _normalized_device_label(raw_device)
            if normalized_device is None:
                return None
            device_key, display_label = normalized_device
            display_labels.setdefault(device_key, display_label)
            sheet_counts[device_key] = sheet_counts.get(device_key, 0) + 1
            total_counts[device_key] = total_counts.get(device_key, 0) + 1

        coverages.append(
            _DeviceFrequencyCoverage(
                entry=sheet.rows[0].entry,
                sheet=sheet.rows[0].sheet,
                column=device_column,
                first_row=sheet.rows[0].number,
                last_row=sheet.rows[-1].number,
                scanned_rows=len(sheet.rows),
                counts=tuple(
                    (key, display_labels[key], count)
                    for key, count in sorted(
                        sheet_counts.items(),
                        key=lambda item: (
                            display_labels[item[0]].casefold(),
                            display_labels[item[0]],
                        ),
                    )
                ),
            )
        )
        total_scanned += len(sheet.rows)

    if not total_counts or total_scanned <= 0:
        return None
    highest_count = max(total_counts.values())
    winner_keys = tuple(
        sorted(
            (key for key, count in total_counts.items() if count == highest_count),
            key=lambda key: (display_labels[key].casefold(), display_labels[key]),
        )
    )
    if not winner_keys or len(winner_keys) > _MAX_TABLE_ROWS:
        return None
    hits = _build_device_frequency_hits(coverages, frozenset(winner_keys))
    if hits is None or not hits:
        return None

    citation = _citation_marker(hits)
    titles = {coverage.entry.title for coverage in coverages}
    title = next(iter(titles)) if len(titles) == 1 else "选定考勤工作簿"
    safe_title = _citation_safe_text(title)
    winner_labels = tuple(display_labels[key] for key in winner_keys)
    if len(winner_labels) == 1:
        answer = (
            f"在《{safe_title}》中已完整扫描 {total_scanned} 条打卡记录，"
            f"使用最频繁的设备是“{_citation_safe_text(winner_labels[0])}”，"
            f"共记录 {highest_count} 次。{citation}"
        )
    else:
        displayed_winners = "、".join(f"“{_citation_safe_text(label)}”" for label in winner_labels)
        answer = (
            f"在《{safe_title}》中已完整扫描 {total_scanned} 条打卡记录，"
            f"使用最频繁的设备有 {len(winner_labels)} 个，并列第一：{displayed_winners}，"
            f"各记录 {highest_count} 次。{citation}"
        )
    return SpreadsheetAnswer(
        answer=answer,
        table=SpreadsheetTable(
            title="闸机设备使用频率",
            columns=("设备名称", "打卡次数"),
            rows=tuple((display_labels[key], f"{highest_count} 次") for key in winner_keys),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _normalized_device_label(value: str) -> tuple[str, str] | None:
    normalized = unicodedata.normalize("NFKC", value)
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        return None
    display_label = re.sub(r"\s+", " ", normalized).strip()
    device_key = display_label.casefold()
    if (
        not display_label
        or len(display_label) > _MAX_LABEL_CHARACTERS
        or device_key in _MISSING_DEVICE_LABELS
    ):
        return None
    return device_key, display_label


def _citation_safe_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    without_controls = "".join(
        " " if character.isspace() else character
        for character in normalized
        if character.isspace() or not unicodedata.category(character).startswith("C")
    )
    single_line = " ".join(without_controls.split())
    numeric_markers_sanitized = _CITATION_LIKE_PATTERN.sub(
        lambda match: f"［{match.group(0)[1:-1].strip()}］",
        single_line,
    )
    return numeric_markers_sanitized.replace("[", "［").replace("]", "］")


def _answer_event_result_existence(
    sheets: tuple[_Sheet, ...], question: str
) -> SpreadsheetAnswer | None:
    semantic_question = _strip_spreadsheet_filename_mentions(question)
    terms = _event_result_terms(semantic_question)
    if not terms or len(terms) > _MAX_TABLE_ROWS:
        return None

    total_counts = {term: 0 for term in terms}
    coverages: list[_EventResultCoverage] = []
    total_scanned = 0
    total_matches = 0
    attendance_sheets: list[_Sheet] = []
    for sheet in sheets:
        result_column = sheet.columns.get("event_result")
        timestamp_signal = (
            sheet.columns.get("timestamp") is not None and "timestamp" not in sheet.ambiguous
        )
        device_signal = sheet.columns.get("device") is not None and "device" not in sheet.ambiguous
        identity_signal = any(
            sheet.columns.get(kind) is not None and kind not in sheet.ambiguous
            for kind in ("employee_id", "card_number", "employee_name", "department")
        )
        attendance_signal = timestamp_signal and device_signal and identity_signal
        if result_column is None or "event_result" in sheet.ambiguous:
            if attendance_signal:
                return None
            continue
        if not attendance_signal:
            continue
        attendance_sheets.append(sheet)
    if not attendance_sheets or _has_unsupported_event_result_scope(semantic_question, terms):
        return None

    for sheet in attendance_sheets:
        result_column = sheet.columns.get("event_result")
        if (
            result_column is None
            or "event_result" in sheet.ambiguous
            or not sheet.rows
            or any(not row.entry.integrity_metadata for row in sheet.rows)
        ):
            return None
        sheet_counts = {term: 0 for term in terms}
        matched_rows: list[int] = []
        for row in sheet.rows:
            raw_result = row.value(result_column)
            if raw_result is None or not raw_result.strip():
                return None
            row_matched = False
            for term in terms:
                if _event_result_matches(raw_result, term):
                    sheet_counts[term] += 1
                    total_counts[term] += 1
                    row_matched = True
            if row_matched:
                matched_rows.append(row.number)
        coverages.append(
            _EventResultCoverage(
                entry=sheet.rows[0].entry,
                sheet=sheet.rows[0].sheet,
                column=result_column,
                first_row=sheet.rows[0].number,
                last_row=sheet.rows[-1].number,
                scanned_rows=len(sheet.rows),
                counts=tuple((term, sheet_counts[term]) for term in terms),
                matched_rows=tuple(matched_rows),
            )
        )
        total_scanned += len(sheet.rows)
        total_matches += len(matched_rows)

    if not coverages or total_scanned <= 0:
        return None
    hits = _build_event_result_hits(coverages)
    if hits is None or not hits:
        return None
    citation = _citation_marker(hits)
    titles = {coverage.entry.title for coverage in coverages}
    title = next(iter(titles)) if len(titles) == 1 else "选定考勤工作簿"
    requested = "或".join(f"“{term}”" for term in terms)
    count_summary = "、".join(f"“{term}”{total_counts[term]} 条" for term in terms)
    if total_matches:
        answer = (
            f"有。在《{title}》中已完整扫描 {total_scanned} 条打卡记录，"
            f"共发现 {total_matches} 条符合{requested}条件的记录；"
            f"其中{count_summary}。{citation}"
        )
    else:
        answer = (
            f"没有。在《{title}》中已完整扫描 {total_scanned} 条打卡记录，"
            f"未发现{requested}记录，共 0 条；其中{count_summary}。{citation}"
        )
    return SpreadsheetAnswer(
        answer=answer,
        table=SpreadsheetTable(
            title="异常打卡记录核验",
            columns=("检查条件", "匹配数量", "结论"),
            rows=tuple(
                (
                    term,
                    f"{total_counts[term]} 条",
                    "已发现" if total_counts[term] else "未发现",
                )
                for term in terms
            ),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _has_unsupported_event_result_scope(question: str, terms: tuple[str, ...]) -> bool:
    residual = question
    for term in sorted(terms, key=len, reverse=True):
        residual = residual.replace(term, "")
    for phrase in _EVENT_RESULT_NEUTRAL_PHRASES:
        residual = residual.replace(phrase, "")
    return bool(_EVENT_RESULT_RESIDUAL_PATTERN.sub("", residual))


def _answer_employee_field(
    sheets: tuple[_Sheet, ...], question: str, *, field: str, field_label: str
) -> SpreadsheetAnswer | None:
    names = {
        value
        for sheet in sheets
        if (column := sheet.columns.get("employee_name")) is not None
        for row in sheet.rows
        if (value := row.value(column))
    }
    target_name = _mentioned_value(names, question)
    if target_name is None or len(target_name) > _MAX_LABEL_CHARACTERS:
        return None
    records: list[tuple[str, _Row]] = []
    incomplete = False
    for sheet in sheets:
        name_column = sheet.columns.get("employee_name")
        if name_column is None:
            continue
        matching_rows = [row for row in sheet.rows if row.value(name_column) == target_name]
        if not matching_rows:
            continue
        value_column = sheet.columns.get(field)
        if value_column is None or field in sheet.ambiguous:
            incomplete = True
            continue
        for row in matching_rows:
            value = row.value(value_column)
            if value:
                records.append((value, row))
            else:
                incomplete = True
    values = {value for value, _ in records}
    if incomplete or len(values) != 1:
        return None
    value = next(iter(values))
    evidence = [min((row for _, row in records), key=_row_sort_key)]
    hits = _build_hits(evidence)
    if hits is None:
        return None
    citations = _citation_marker(hits)
    return SpreadsheetAnswer(
        answer=f"员工“{target_name}”的{field_label}是 {value}。{citations}",
        table=SpreadsheetTable(
            title="员工信息",
            columns=("员工姓名", field_label),
            rows=((target_name, value),),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _answer_department_employees(
    sheets: tuple[_Sheet, ...], question: str
) -> SpreadsheetAnswer | None:
    departments = {
        value
        for sheet in sheets
        if (column := sheet.columns.get("department")) is not None
        for row in sheet.rows
        if (value := row.value(column))
    }
    department = _mentioned_value(departments, question)
    if department is None or len(department) > _MAX_LABEL_CHARACTERS:
        return None
    by_identity: dict[tuple[str | None, str], list[_Row]] = {}
    identifiers_by_name: dict[str, set[str]] = {}
    names_with_missing_identifier: set[str] = set()
    names_by_identifier: dict[str, set[str]] = {}
    incomplete = False
    for sheet in sheets:
        department_column = sheet.columns.get("department")
        if department_column is None:
            continue
        matching_rows = [row for row in sheet.rows if row.value(department_column) == department]
        if not matching_rows:
            continue
        name_column = sheet.columns.get("employee_name")
        employee_id_column = sheet.columns.get("employee_id")
        if name_column is None or "employee_name" in sheet.ambiguous:
            incomplete = True
            continue
        for row in matching_rows:
            name = row.value(name_column)
            if not name:
                incomplete = True
                continue
            if len(name) > _MAX_LABEL_CHARACTERS:
                incomplete = True
                continue
            employee_id = row.value(employee_id_column)
            if employee_id:
                identifiers_by_name.setdefault(name, set()).add(employee_id)
                names_by_identifier.setdefault(employee_id, set()).add(name)
            else:
                names_with_missing_identifier.add(name)
            by_identity.setdefault((employee_id, name), []).append(row)
    if (
        incomplete
        or not by_identity
        or len(by_identity) > _MAX_TABLE_ROWS
        or any(len(names) > 1 for names in names_by_identifier.values())
        or any(name in identifiers_by_name for name in names_with_missing_identifier)
    ):
        return None
    identities = tuple(
        sorted(
            by_identity,
            key=lambda identity: (identity[0] is None, identity[0] or "", identity[1]),
        )
    )
    evidence = [min(by_identity[identity], key=_row_sort_key) for identity in identities]
    hits = _build_hits(evidence)
    if hits is None:
        return None
    citations = _citation_marker(hits)
    display_names = tuple(
        f"{name}（{employee_id}）" if employee_id else name for employee_id, name in identities
    )
    return SpreadsheetAnswer(
        answer=(
            f"{department}在考勤记录中共有 {len(identities)} 位员工："
            f"{'、'.join(display_names)}。{citations}"
        ),
        table=SpreadsheetTable(
            title=f"{department}考勤员工",
            columns=("人员工号", "员工姓名"),
            rows=tuple((employee_id or "—", name) for employee_id, name in identities),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _answer_time_range(sheets: tuple[_Sheet, ...]) -> SpreadsheetAnswer | None:
    records, invalid = _timestamp_records(sheets)
    if invalid or not records:
        return None
    earliest = min(
        records,
        key=lambda item: (item.timestamp or datetime.max, _row_sort_key(item.row)),
    )
    latest = max(
        records,
        key=lambda item: (item.timestamp or datetime.min, _row_sort_key(item.row)),
    )
    assert earliest.timestamp is not None and latest.timestamp is not None
    evidence = [earliest.row] if earliest.row == latest.row else [earliest.row, latest.row]
    hits = _build_hits(evidence)
    if hits is None:
        return None
    citations = _citation_marker(hits)
    start = _format_date(earliest.timestamp.date())
    end = _format_date(latest.timestamp.date())
    return SpreadsheetAnswer(
        answer=f"这份考勤记录的日期范围是 {start}至{end}。{citations}",
        table=SpreadsheetTable(
            title="考勤记录时间范围",
            columns=("起始日期", "结束日期"),
            rows=((start, end),),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _answer_latest_record(sheets: tuple[_Sheet, ...], question: str) -> SpreadsheetAnswer | None:
    target_date = _question_date(question)
    if target_date is None:
        return None
    records, invalid = _timestamp_records(sheets, target_date=target_date)
    if invalid or not records:
        return None
    latest_time = max(record.timestamp for record in records if record.timestamp is not None)
    latest = [record for record in records if record.timestamp == latest_time]
    resolved: list[tuple[str, str, _Row]] = []
    incomplete = False
    for record in latest:
        name_column = record.sheet.columns.get("employee_name")
        device_column = record.sheet.columns.get("device")
        name = record.row.value(name_column)
        device = record.row.value(device_column)
        if (
            name_column is None
            or device_column is None
            or "employee_name" in record.sheet.ambiguous
            or "device" in record.sheet.ambiguous
            or not name
            or not device
            or len(name) > _MAX_LABEL_CHARACTERS
        ):
            incomplete = True
            continue
        resolved.append((name, device, record.row))
    identities = {(name, device) for name, device, _ in resolved}
    if incomplete or len(identities) != 1:
        return None
    name, device = next(iter(identities))
    row = min((item[2] for item in resolved), key=_row_sort_key)
    hits = _build_hits([row])
    if hits is None:
        return None
    citations = _citation_marker(hits)
    assert latest_time is not None
    time_text = latest_time.strftime("%H时%M分")
    date_text = _format_date(target_date)
    return SpreadsheetAnswer(
        answer=f"{date_text}当天最晚一条打卡记录是{name}，于{time_text}通过“{device}”。{citations}",
        table=SpreadsheetTable(
            title="当日最晚打卡记录",
            columns=("日期", "时间", "员工姓名", "设备"),
            rows=((date_text, time_text, name, device),),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _timestamp_records(
    sheets: tuple[_Sheet, ...], *, target_date: date | None = None
) -> tuple[list[_Record], bool]:
    records: list[_Record] = []
    invalid = False
    for sheet in sheets:
        timestamp_column = sheet.columns.get("timestamp")
        if timestamp_column is None or "timestamp" in sheet.ambiguous:
            continue
        for row in sheet.rows:
            raw = row.value(timestamp_column)
            if not raw:
                continue
            parsed = _parse_datetime(raw)
            if parsed is None:
                invalid = True
                continue
            if target_date is None or parsed.date() == target_date:
                records.append(_Record(row=row, sheet=sheet, timestamp=parsed))
    return records, invalid


def _build_event_result_hits(
    coverages: list[_EventResultCoverage],
) -> tuple[KnowledgeSearchHit, ...] | None:
    hits: list[KnowledgeSearchHit] = []
    evidence_characters = 0
    grouped: dict[UUID, list[_EventResultCoverage]] = {}
    for coverage in coverages:
        grouped.setdefault(coverage.entry.id, []).append(coverage)
    for entry_coverages in grouped.values():
        entry = entry_coverages[0].entry
        anchors: list[str] = []
        summaries: list[str] = []
        for coverage in entry_coverages:
            anchor = _column_range(
                coverage.sheet,
                coverage.column,
                coverage.first_row,
                coverage.last_row,
            )
            anchors.append(anchor)
            counts = "、".join(f"“{term}”{count} 条" for term, count in coverage.counts)
            matched_rows = ""
            if coverage.matched_rows:
                displayed = "、".join(str(row) for row in coverage.matched_rows[:50])
                omitted = len(coverage.matched_rows) - 50
                suffix = f"，另有 {omitted} 行" if omitted > 0 else ""
                matched_rows = f"；命中行：{displayed}{suffix}"
            summaries.append(
                f"确定性全量统计 [{anchor}]：完整扫描 {coverage.scanned_rows} 条打卡记录；"
                f"{counts}{matched_rows}。"
            )
        excerpt = "\n".join(summaries)
        evidence_characters += len(excerpt)
        if evidence_characters > _MAX_EVIDENCE_CHARACTERS:
            return None
        combined_anchor = _combined_coverage_anchor(anchors)
        hits.append(
            KnowledgeSearchHit(
                entry_id=entry.id,
                source_file_id=entry.source_file_id,
                title=entry.title,
                excerpt=excerpt,
                source_path=_anchored_source_path(entry.source_path, combined_anchor),
                format_version=entry.format_version,
            )
        )
    return tuple(hits)


def _build_device_frequency_hits(
    coverages: list[_DeviceFrequencyCoverage],
    winner_keys: frozenset[str],
) -> tuple[KnowledgeSearchHit, ...] | None:
    hits: list[KnowledgeSearchHit] = []
    evidence_characters = 0
    grouped: dict[UUID, list[_DeviceFrequencyCoverage]] = {}
    for coverage in coverages:
        grouped.setdefault(coverage.entry.id, []).append(coverage)
    for entry_coverages in grouped.values():
        entry = entry_coverages[0].entry
        anchors: list[str] = []
        summaries: list[str] = []
        for coverage in entry_coverages:
            anchor = _column_range(
                coverage.sheet,
                coverage.column,
                coverage.first_row,
                coverage.last_row,
            )
            anchors.append(anchor)
            winner_counts = "、".join(
                f"“{display_label}”{count} 条"
                for key, display_label, count in coverage.counts
                if key in winner_keys
            )
            if not winner_counts:
                winner_counts = "本工作表无最高频设备记录"
            summaries.append(
                f"确定性全量聚合 [{anchor}]：完整扫描 {coverage.scanned_rows} 条打卡记录；"
                f"共 {len(coverage.counts)} 个设备；全局最高频设备在本表的记录数："
                f"{winner_counts}。"
            )
        excerpt = "\n".join(summaries)
        evidence_characters += len(excerpt)
        if evidence_characters > _MAX_EVIDENCE_CHARACTERS:
            return None
        hits.append(
            KnowledgeSearchHit(
                entry_id=entry.id,
                source_file_id=entry.source_file_id,
                title=entry.title,
                excerpt=excerpt,
                source_path=_anchored_source_path(
                    entry.source_path,
                    _combined_coverage_anchor(anchors),
                ),
                format_version=entry.format_version,
            )
        )
    return tuple(hits)


def _build_department_summary_hits(
    coverages: list[_DepartmentSummaryCoverage],
) -> tuple[KnowledgeSearchHit, ...] | None:
    hits: list[KnowledgeSearchHit] = []
    evidence_characters = 0
    grouped: dict[UUID, list[_DepartmentSummaryCoverage]] = {}
    for coverage in coverages:
        grouped.setdefault(coverage.entry.id, []).append(coverage)
    for entry_coverages in grouped.values():
        entry = entry_coverages[0].entry
        anchors: list[str] = []
        summaries: list[str] = []
        for coverage in entry_coverages:
            anchor = _column_range(
                coverage.sheet,
                coverage.column,
                coverage.first_row,
                coverage.last_row,
            )
            anchors.append(anchor)
            departments = "、".join(
                _citation_safe_text(department) for department in coverage.departments
            )
            summaries.append(
                f"确定性全量去重 [{anchor}]：完整扫描 {coverage.scanned_rows} 条考勤记录；"
                f"识别出 {len(coverage.departments)} 个不同部门：{departments}。"
            )
        excerpt = "\n".join(summaries)
        evidence_characters += len(excerpt)
        if evidence_characters > _MAX_EVIDENCE_CHARACTERS:
            return None
        hits.append(
            KnowledgeSearchHit(
                entry_id=entry.id,
                source_file_id=entry.source_file_id,
                title=_citation_safe_text(entry.title),
                excerpt=excerpt,
                source_path=_anchored_source_path(
                    entry.source_path,
                    _combined_coverage_anchor(anchors),
                ),
                format_version=entry.format_version,
            )
        )
    return tuple(hits)


def _build_hits(rows: list[_Row]) -> tuple[KnowledgeSearchHit, ...] | None:
    unique_rows = {(row.entry.id, row.sheet, row.number): row for row in rows}
    grouped: dict[UUID, list[_Row]] = {}
    for row in sorted(unique_rows.values(), key=_row_sort_key):
        grouped.setdefault(row.entry.id, []).append(row)
    hits: list[KnowledgeSearchHit] = []
    evidence_characters = 0
    for entry_rows in grouped.values():
        entry = entry_rows[0].entry
        source_path = _evidence_source_path(entry.source_path, entry_rows)
        excerpt = "\n".join(row.excerpt for row in entry_rows)
        evidence_characters += len(excerpt)
        if evidence_characters > _MAX_EVIDENCE_CHARACTERS:
            return None
        hits.append(
            KnowledgeSearchHit(
                entry_id=entry.id,
                source_file_id=entry.source_file_id,
                title=entry.title,
                excerpt=excerpt,
                source_path=source_path,
                format_version=entry.format_version,
            )
        )
    return tuple(hits)


def _evidence_source_path(base_path: str | None, rows: list[_Row]) -> str:
    locations = [_row_range(row) for row in rows]
    selected: list[str] = []
    for location in locations:
        candidate = ",".join((*selected, location))
        if len(candidate) > _MAX_SOURCE_PATH_CHARACTERS // 2:
            break
        selected.append(location)
    omitted = len(locations) - len(selected)
    suffix = f",...(+{omitted} rows)" if omitted else ""
    evidence_path = f"{','.join(selected)}{suffix}"
    if not base_path:
        return evidence_path[:_MAX_SOURCE_PATH_CHARACTERS]
    base_budget = max(0, _MAX_SOURCE_PATH_CHARACTERS - len(evidence_path) - 1)
    return f"{base_path[:base_budget]}#{evidence_path}"


def _column_range(sheet: str, column: str, first_row: int, last_row: int) -> str:
    start = f"{column}{first_row}"
    end = f"{column}{last_row}"
    cell_range = start if start == end else f"{start}:{end}"
    return f"worksheet:{sheet}!{cell_range}"


def _anchored_source_path(base_path: str | None, anchor: str) -> str:
    if not base_path:
        return anchor[:_MAX_SOURCE_PATH_CHARACTERS]
    base_budget = max(0, _MAX_SOURCE_PATH_CHARACTERS - len(anchor) - 1)
    return f"{base_path[:base_budget]}#{anchor}"


def _combined_coverage_anchor(anchors: list[str]) -> str:
    selected: list[str] = []
    for anchor in anchors:
        candidate = ",".join((*selected, anchor))
        if len(candidate) > _MAX_SOURCE_PATH_CHARACTERS // 2:
            break
        selected.append(anchor)
    omitted = len(anchors) - len(selected)
    suffix = f",...(+{omitted} sheets)" if omitted else ""
    return f"{','.join(selected)}{suffix}"


def _row_range(row: _Row) -> str:
    start = f"{row.cells[0].column}{row.number}"
    end = f"{row.cells[-1].column}{row.number}"
    cell_range = start if start == end else f"{start}:{end}"
    return f"worksheet:{row.sheet}!{cell_range}"


def _mentioned_value(values: set[str], question: str) -> str | None:
    matches = [value for value in values if value and value in question]
    if not matches:
        return None
    longest = max(len(value) for value in matches)
    best = {value for value in matches if len(value) == longest}
    return next(iter(best)) if len(best) == 1 else None


def _normalize_header(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"[\s:：_\-()/（）]+", "", normalized)


def _legacy_source_text(content: str) -> str | None:
    marker_boundary = re.search(r"(?:\A|\n\n)(?=\[worksheet:)", content)
    if marker_boundary is None:
        return None
    source_text = content[marker_boundary.end() :]
    return source_text if _CELL_PATTERN.match(source_text) is not None else None


def _valid_source_location(location: str) -> bool:
    match = _LOCATION_PATTERN.fullmatch(location)
    if match is not None:
        return (
            int(match.group("row")) <= _MAX_EXCEL_ROW
            and _column_number(match.group("column").upper()) <= _MAX_EXCEL_COLUMN
        )
    return _SHEET_LOCATION_PATTERN.fullmatch(location) is not None


def _parse_datetime(value: str) -> datetime | None:
    normalized = unicodedata.normalize("NFKC", value).strip()
    for candidate in (normalized, normalized.replace("/", "-")):
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is not None:
            return None
        return parsed
    match = re.fullmatch(
        r"(20\d{2})年(\d{1,2})月(\d{1,2})日(?:\s*(\d{1,2})[\u65f6:](\d{1,2})(?:[\u5206:](\d{1,2}))?秒?)?",
        normalized,
    )
    if match is None:
        return None
    year, month, day, hour, minute, second = match.groups()
    try:
        return datetime(
            int(year),
            int(month),
            int(day),
            int(hour or 0),
            int(minute or 0),
            int(second or 0),
        )
    except ValueError:
        return None


def _question_date(question: str) -> date | None:
    match = re.search(r"(20\d{2})年(\d{1,2})月(\d{1,2})日", question)
    if match is None:
        match = re.search(r"(20\d{2})[-/.](\d{1,2})[-/.](\d{1,2})", question)
    if match is None:
        return None
    try:
        return date(*(int(value) for value in match.groups()))
    except ValueError:
        return None


def _is_latest_record_question(question: str) -> bool:
    return any(token in question for token in ("最晚", "最后一条", "最后的")) and any(
        token in question for token in ("打卡", "考勤", "通行")
    )


def _is_time_range_question(question: str) -> bool:
    return any(token in question for token in ("考勤", "打卡", "通行")) and any(
        token in question for token in ("时间范围", "日期范围", "从哪一天到哪一天", "起止时间")
    )


def _citation_marker(hits: tuple[KnowledgeSearchHit, ...]) -> str:
    return "".join(f"[{index}]" for index in range(1, len(hits) + 1))


def _format_date(value: date) -> str:
    return f"{value.year}年{value.month}月{value.day}日"


def _column_number(column: str) -> int:
    result = 0
    for character in column:
        result = result * 26 + ord(character) - ord("A") + 1
    return result


def _row_sort_key(row: _Row) -> tuple[str, str, int]:
    return (row.entry.title, row.sheet, row.number)
