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
class _QuestionIntent:
    latest_record: bool
    time_range: bool
    employee_field: str | None
    department_employees: bool

    @property
    def applicable(self) -> bool:
        return any(
            (
                self.latest_record,
                self.time_range,
                self.employee_field,
                self.department_employees,
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
    department_employees = (
        "部" in question
        and any(token in question for token in ("员工", "人员"))
        and any(
            token in question for token in ("哪几位", "有谁", "哪些", "名单", "多少位", "总共有")
        )
    )
    return _QuestionIntent(
        latest_record=_is_latest_record_question(question),
        time_range=_is_time_range_question(question),
        employee_field=employee_field,
        department_employees=department_employees,
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
    if len(sources) == 1:
        return sources
    mentioned: list[tuple[int, _EntrySource]] = []
    for source in sources:
        stem = source.title.rsplit(".", maxsplit=1)[0].strip()
        if source.title in question:
            mentioned.append((len(source.title) + 1_000, source))
        elif len(stem) >= 2 and stem in question:
            mentioned.append((len(stem), source))
    if mentioned:
        best_score = max(score for score, _ in mentioned)
        best = [source for score, source in mentioned if score == best_score]
        return (best[0],) if len(best) == 1 else None
    fingerprints = {_source_fingerprint(source) for source in sources}
    return (sources[0],) if len(fingerprints) == 1 else None


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
