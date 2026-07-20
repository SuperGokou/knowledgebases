from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Final

from defusedxml import ElementTree as SafeElementTree

_OOXML_EXTENSIONS: Final = frozenset({".docx", ".xlsx", ".pptx"})
_LEGACY_EXTENSIONS: Final = frozenset({".doc", ".xls", ".ppt"})
SUPPORTED_DOCUMENT_EXTENSIONS: Final = frozenset(
    {".txt", ".csv", ".pdf"} | _OOXML_EXTENSIONS | _LEGACY_EXTENSIONS
)

_WORD_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_SHEET_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_DRAWING_NS = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_PRESENTATION_NS = "{http://schemas.openxmlformats.org/presentationml/2006/main}"
_REL_NS = "{http://schemas.openxmlformats.org/package/2006/relationships}"
_OFFICE_REL_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_XLSX_CELL_COORDINATE: Final = re.compile(r"(?P<column>[A-Za-z]{1,3})(?P<row>[1-9]\d{0,6})")
_XLSX_FORBIDDEN_SHEET_NAME_CHARACTERS: Final = frozenset("[]:*?/\\")
_SHA256_HEX: Final = re.compile(r"[0-9a-f]{64}")


class DocumentParseError(ValueError):
    """A bounded, non-sensitive document rejection suitable for durable status."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ParseLimits:
    max_source_bytes: int
    max_output_chars: int
    max_archive_entries: int = 2_048
    max_source_locations: int = 2_048
    max_expanded_bytes: int = 16_000_000
    max_single_entry_bytes: int = 4_000_000
    max_compression_ratio: int = 100
    max_pages_or_sheets: int = 1_000
    external_timeout_seconds: int = 30
    external_memory_bytes: int = 512 * 1024 * 1024

    def __post_init__(self) -> None:
        for value in (
            self.max_source_bytes,
            self.max_output_chars,
            self.max_archive_entries,
            self.max_source_locations,
            self.max_expanded_bytes,
            self.max_single_entry_bytes,
            self.max_compression_ratio,
            self.max_pages_or_sheets,
            self.external_timeout_seconds,
            self.external_memory_bytes,
        ):
            if value <= 0:
                raise ValueError("document parser limits must be positive")


@dataclass(frozen=True, slots=True)
class ParsedDocument:
    text: str
    source_locations: tuple[str, ...]
    parser: str
    source_location_count: int = -1
    source_locations_truncated: bool = False
    source_text_sha256: str = ""
    source_locations_sha256: str = ""

    def __post_init__(self) -> None:
        location_count = self.source_location_count
        if location_count == -1:
            location_count = len(self.source_locations)
            object.__setattr__(self, "source_location_count", location_count)
        if location_count < len(self.source_locations):
            raise ValueError("source location count cannot be smaller than retained evidence")
        if self.source_locations_truncated != (location_count > len(self.source_locations)):
            raise ValueError("source location truncation metadata is inconsistent")

        text_digest = self.source_text_sha256 or compute_source_text_sha256(self.text)
        if _SHA256_HEX.fullmatch(text_digest) is None:
            raise ValueError("source text digest must be lowercase SHA-256 hex")
        object.__setattr__(self, "source_text_sha256", text_digest)

        locations_digest = self.source_locations_sha256
        if not locations_digest:
            if self.source_locations_truncated:
                raise ValueError("truncated source locations require a complete digest")
            locations_digest = compute_source_locations_sha256(self.source_locations)
        if _SHA256_HEX.fullmatch(locations_digest) is None:
            raise ValueError("source location digest must be lowercase SHA-256 hex")
        object.__setattr__(self, "source_locations_sha256", locations_digest)


def compute_source_text_sha256(text: str) -> str:
    """Digest the exact normalized parser text as UTF-8 bytes."""

    return sha256(text.encode("utf-8")).hexdigest()


def compute_source_locations_sha256(locations: Iterable[str]) -> str:
    """Digest ordered locations joined by LF, without a trailing separator."""

    return sha256("\n".join(locations).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ParserTools:
    pdf_text_executable: Path = Path("/usr/bin/pdftotext")
    libreoffice_executable: Path = Path("/usr/bin/libreoffice")
    sandbox_executable: Path = Path("/usr/bin/bwrap")
    resource_limit_executable: Path = Path("/usr/bin/prlimit")


DEFAULT_PARSER_TOOLS = ParserTools()


def parser_capabilities(tools: ParserTools = DEFAULT_PARSER_TOOLS) -> dict[str, bool]:
    """Return actual, fail-closed runtime capabilities; never infer from file suffix."""

    sandbox = _trusted_executable_available(
        tools.sandbox_executable
    ) and _trusted_executable_available(tools.resource_limit_executable)
    pdf = sandbox and _trusted_executable_available(tools.pdf_text_executable)
    office = sandbox and _trusted_executable_available(tools.libreoffice_executable)
    return {
        ".txt": True,
        ".csv": True,
        ".docx": True,
        ".xlsx": True,
        ".pptx": True,
        ".pdf": pdf,
        ".doc": office,
        ".xls": office,
        ".ppt": office,
    }


def parse_document(
    raw: bytes,
    extension: str,
    limits: ParseLimits,
    *,
    tools: ParserTools = DEFAULT_PARSER_TOOLS,
) -> ParsedDocument:
    extension = extension.lower()
    if extension not in SUPPORTED_DOCUMENT_EXTENSIONS:
        raise DocumentParseError("parser_unsupported_extension")
    if len(raw) > limits.max_source_bytes:
        raise DocumentParseError("parser_source_too_large")
    if not raw:
        raise DocumentParseError("empty_source")
    if extension in {".txt", ".csv"}:
        return _parse_text(raw, extension, limits)
    if extension in _OOXML_EXTENSIONS:
        return _parse_ooxml(raw, extension, limits)
    if extension == ".pdf":
        return _parse_pdf(raw, limits, tools)
    return _parse_legacy(raw, extension, limits, tools)


def _parse_text(raw: bytes, extension: str, limits: ParseLimits) -> ParsedDocument:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise DocumentParseError("non_utf8_text") from error
    text = _bounded_text(text, limits)
    if extension == ".csv":
        lines = [line for line in text.splitlines() if line.strip()]
        parts = [f"[row:{number}] {line}" for number, line in enumerate(lines, start=1)]
        locations = [f"row:{number}" for number in range(1, len(lines) + 1)]
        return _document(parts, locations, "utf8-csv", limits)
    return ParsedDocument(text=text, source_locations=("document",), parser="utf8-txt")


def _parse_ooxml(raw: bytes, extension: str, limits: ParseLimits) -> ParsedDocument:
    members = _validated_archive(raw, limits)
    if extension == ".docx":
        return _parse_docx(members, limits)
    if extension == ".xlsx":
        return _parse_xlsx(members, limits)
    return _parse_pptx(members, limits)


def _validated_archive(raw: bytes, limits: ParseLimits) -> dict[str, bytes]:
    try:
        archive = zipfile.ZipFile(BytesIO(raw))
    except (zipfile.BadZipFile, OSError) as error:
        raise DocumentParseError("parser_malformed_archive") from error

    members: dict[str, bytes] = {}
    total_expanded = 0
    try:
        infos = archive.infolist()
        if len(infos) > limits.max_archive_entries:
            raise DocumentParseError("parser_archive_entry_limit")
        for info in infos:
            normalized = info.filename.replace("\\", "/")
            path = PurePosixPath(normalized)
            if (
                not normalized
                or normalized.startswith("/")
                or path.is_absolute()
                or ".." in path.parts
                or normalized in members
            ):
                raise DocumentParseError("parser_unsafe_archive_path")
            unix_mode = info.external_attr >> 16
            if stat.S_ISLNK(unix_mode):
                raise DocumentParseError("parser_unsafe_archive_path")
            if info.flag_bits & 0x1:
                raise DocumentParseError("parser_encrypted_package")
            if info.file_size > limits.max_single_entry_bytes:
                raise DocumentParseError("parser_archive_entry_too_large")
            total_expanded += info.file_size
            if total_expanded > limits.max_expanded_bytes:
                raise DocumentParseError("parser_expanded_size_limit")
            if (
                info.file_size
                and info.file_size > max(1, info.compress_size) * limits.max_compression_ratio
            ):
                raise DocumentParseError("parser_compression_ratio_limit")
            if info.is_dir():
                continue
            with archive.open(info, "r") as source:
                data = source.read(info.file_size + 1)
            if len(data) != info.file_size:
                raise DocumentParseError("parser_archive_size_mismatch")
            members[normalized] = data
    except (RuntimeError, zipfile.BadZipFile, OSError, EOFError) as error:
        raise DocumentParseError("parser_malformed_archive") from error
    finally:
        archive.close()

    if "[Content_Types].xml" not in members:
        raise DocumentParseError("parser_invalid_ooxml")
    lowered = {name.lower() for name in members}
    if any(
        name.endswith("vbaproject.bin")
        or "/externallinks/" in f"/{name}"
        or name.endswith(".bin")
        or "/embeddings/" in f"/{name}"
        or "/activex/" in f"/{name}"
        or "/customui/" in f"/{name}"
        for name in lowered
    ):
        raise DocumentParseError("parser_active_content_forbidden")
    for name, data in members.items():
        if name.endswith(".rels"):
            root = _xml(data)
            if any(node.attrib.get("TargetMode", "").lower() == "external" for node in root):
                raise DocumentParseError("parser_external_relationship_forbidden")
    content_types = members["[Content_Types].xml"].lower()
    if b"macroenabled" in content_types or b"vbaproject" in content_types:
        raise DocumentParseError("parser_active_content_forbidden")
    return members


def _parse_docx(members: dict[str, bytes], limits: ParseLimits) -> ParsedDocument:
    data = members.get("word/document.xml")
    if data is None:
        raise DocumentParseError("parser_invalid_docx")
    parts: list[str] = []
    locations: list[str] = []
    paragraph = 0
    table = 0
    roots = [("body", _xml(data))]
    supplemental = sorted(
        name for name in members if re.fullmatch(r"word/(header|footer)\d+\.xml", name)
    )
    roots.extend(
        (name.removeprefix("word/").removesuffix(".xml"), _xml(members[name]))
        for name in supplemental
    )
    for section, root in roots:
        body = root.find(f".//{_WORD_NS}body") if section == "body" else root
        if body is None:
            raise DocumentParseError("parser_invalid_docx")
        for child in body:
            if child.tag == f"{_WORD_NS}p":
                value = "".join(node.text or "" for node in child.iter(f"{_WORD_NS}t")).strip()
                if not value:
                    continue
                paragraph += 1
                location = (
                    f"paragraph:{paragraph}"
                    if section == "body"
                    else f"{section}:paragraph:{paragraph}"
                )
                parts.append(f"[{location}] {value}")
                locations.append(location)
            elif child.tag == f"{_WORD_NS}tbl":
                table += 1
                for row_number, row in enumerate(child.iter(f"{_WORD_NS}tr"), start=1):
                    cells = []
                    for cell in row.iter(f"{_WORD_NS}tc"):
                        cell_text = " ".join(
                            value
                            for value in (
                                "".join(
                                    node.text or "" for node in paragraph_node.iter(f"{_WORD_NS}t")
                                ).strip()
                                for paragraph_node in cell.iter(f"{_WORD_NS}p")
                            )
                            if value
                        )
                        cells.append(cell_text)
                    if any(cells):
                        location = f"table:{table}:row:{row_number}"
                        parts.append(f"[{location}] {' | '.join(cells)}")
                        locations.append(location)
    return _document(parts, locations, "ooxml-docx", limits)


def _parse_xlsx(members: dict[str, bytes], limits: ParseLimits) -> ParsedDocument:
    workbook = members.get("xl/workbook.xml")
    relationships = members.get("xl/_rels/workbook.xml.rels")
    if workbook is None or relationships is None:
        raise DocumentParseError("parser_invalid_xlsx")
    shared_strings: list[str] = []
    if shared := members.get("xl/sharedStrings.xml"):
        shared_root = _xml(shared)
        shared_strings = [
            "".join(node.text or "" for node in item.iter(f"{_SHEET_NS}t"))
            for item in shared_root.iter(f"{_SHEET_NS}si")
        ]
    rel_root = _xml(relationships)
    rels = {
        node.attrib.get("Id", ""): node.attrib.get("Target", "")
        for node in rel_root.iter(f"{_REL_NS}Relationship")
    }
    workbook_root = _xml(workbook)
    parts: list[str] = []
    locations: list[str] = []
    sheets = list(workbook_root.iter(f"{_SHEET_NS}sheet"))
    if len(sheets) > limits.max_pages_or_sheets:
        raise DocumentParseError("parser_page_limit")
    seen_sheet_names: set[str] = set()
    for sheet in sheets:
        name = (sheet.attrib.get("name") or "").strip()
        if (
            not name
            or len(name) > 31
            or any(
                character in _XLSX_FORBIDDEN_SHEET_NAME_CHARACTERS
                or ord(character) < 32
                or 0x7F <= ord(character) <= 0x9F
                or character in {"\u2028", "\u2029"}
                for character in name
            )
            or name.casefold() in seen_sheet_names
        ):
            raise DocumentParseError("parser_invalid_xlsx")
        seen_sheet_names.add(name.casefold())
        rel_id = sheet.attrib.get(f"{_OFFICE_REL_NS}id", "")
        target = rels.get(rel_id, "")
        target_path = _resolve_ooxml_target("xl", target)
        data = members.get(target_path)
        if data is None:
            raise DocumentParseError("parser_invalid_xlsx")
        sheet_location = f"worksheet:{name}"
        sheet_location_added = False
        root = _xml(data)
        for cell in root.iter(f"{_SHEET_NS}c"):
            coordinate_match = _XLSX_CELL_COORDINATE.fullmatch(cell.attrib.get("r", ""))
            if coordinate_match is None:
                raise DocumentParseError("parser_invalid_xlsx")
            column = coordinate_match.group("column").upper()
            row = int(coordinate_match.group("row"))
            if _xlsx_column_number(column) > 16_384 or row > 1_048_576:
                raise DocumentParseError("parser_invalid_xlsx")
            coordinate = f"{column}{row}"
            cell_type = cell.attrib.get("t")
            value_node = cell.find(f"{_SHEET_NS}v")
            inline = cell.find(f"{_SHEET_NS}is")
            value = ""
            if inline is not None:
                value = "".join(node.text or "" for node in inline.iter(f"{_SHEET_NS}t"))
            elif value_node is not None and value_node.text is not None:
                value = value_node.text
                if cell_type == "s":
                    try:
                        value = shared_strings[int(value)]
                    except (ValueError, IndexError) as error:
                        raise DocumentParseError("parser_invalid_xlsx") from error
            value = _single_line_cell_value(value)
            if value:
                if not sheet_location_added:
                    locations.append(sheet_location)
                    sheet_location_added = True
                location = f"worksheet:{name}!{coordinate}"
                parts.append(f"[{location}] {value}")
                locations.append(location)
    return _document(parts, locations, "ooxml-xlsx", limits)


def _parse_pptx(members: dict[str, bytes], limits: ParseLimits) -> ParsedDocument:
    presentation = members.get("ppt/presentation.xml")
    relationships = members.get("ppt/_rels/presentation.xml.rels")
    if presentation is None or relationships is None:
        raise DocumentParseError("parser_invalid_pptx")
    rel_root = _xml(relationships)
    rels = {
        node.attrib.get("Id", ""): node.attrib.get("Target", "")
        for node in rel_root.iter(f"{_REL_NS}Relationship")
    }
    presentation_root = _xml(presentation)
    slide_ids = list(presentation_root.iter(f"{_PRESENTATION_NS}sldId"))
    if not slide_ids:
        raise DocumentParseError("parser_invalid_pptx")
    if len(slide_ids) > limits.max_pages_or_sheets:
        raise DocumentParseError("parser_page_limit")
    parts: list[str] = []
    locations: list[str] = []
    for number, slide_id in enumerate(slide_ids, start=1):
        rel_id = slide_id.attrib.get(f"{_OFFICE_REL_NS}id", "")
        name = _resolve_ooxml_target("ppt", rels.get(rel_id, ""))
        data = members.get(name)
        if data is None:
            raise DocumentParseError("parser_invalid_pptx")
        root = _xml(data)
        values = [
            node.text.strip()
            for node in root.iter(f"{_DRAWING_NS}t")
            if node.text and node.text.strip()
        ]
        location = f"slide:{number}"
        locations.append(location)
        if values:
            parts.append(f"[{location}] {' '.join(values)}")
    return _document(parts, locations, "ooxml-pptx", limits)


def _parse_pdf(raw: bytes, limits: ParseLimits, tools: ParserTools) -> ParsedDocument:
    if not raw.startswith(b"%PDF-") or b"%%EOF" not in raw[-1_024:]:
        raise DocumentParseError("parser_invalid_pdf")
    forbidden = (
        b"/Encrypt",
        b"/JavaScript",
        b"/JS",
        b"/Launch",
        b"/EmbeddedFile",
        b"/RichMedia",
        b"/OpenAction",
        b"/AA",
        b"/URI",
    )
    if any(token in raw for token in forbidden):
        raise DocumentParseError("parser_active_content_forbidden")
    if not (
        _trusted_executable_available(tools.pdf_text_executable)
        and _trusted_executable_available(tools.sandbox_executable)
        and _trusted_executable_available(tools.resource_limit_executable)
    ):
        raise DocumentParseError("parser_pdf_capability_unavailable")
    with tempfile.TemporaryDirectory(prefix="kb-pdf-") as directory:
        root = Path(directory)
        source = root / "source.pdf"
        output = root / "output.txt"
        source.write_bytes(raw)
        _run_external(
            _sandboxed_command(
                [str(tools.pdf_text_executable), "-enc", "UTF-8", str(source), str(output)],
                cwd=root,
                tools=tools,
                limits=limits,
            ),
            cwd=root,
            limits=limits,
        )
        try:
            extracted = output.read_bytes()
        except OSError as error:
            raise DocumentParseError("parser_pdf_failed") from error
    if len(extracted) > limits.max_output_chars * 4:
        raise DocumentParseError("parser_output_too_large")
    try:
        text = extracted.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DocumentParseError("parser_pdf_failed") from error
    pages = text.split("\f")
    if len(pages) > limits.max_pages_or_sheets:
        raise DocumentParseError("parser_page_limit")
    parts = []
    locations = []
    for number, page in enumerate(pages, start=1):
        value = page.strip()
        if value:
            location = f"page:{number}"
            locations.append(location)
            parts.append(f"[{location}] {value}")
    return _document(parts, locations, "poppler-pdftotext", limits)


def _parse_legacy(
    raw: bytes,
    extension: str,
    limits: ParseLimits,
    tools: ParserTools,
) -> ParsedDocument:
    if raw.startswith(b"PK"):
        raise DocumentParseError("parser_extension_mismatch")
    if not raw.startswith(bytes.fromhex("D0CF11E0A1B11AE1")):
        raise DocumentParseError("parser_invalid_legacy_office")
    if not (
        _trusted_executable_available(tools.libreoffice_executable)
        and _trusted_executable_available(tools.sandbox_executable)
        and _trusted_executable_available(tools.resource_limit_executable)
    ):
        raise DocumentParseError("parser_legacy_capability_unavailable")
    target_extension = {".doc": ".docx", ".xls": ".xlsx", ".ppt": ".pptx"}[extension]
    with tempfile.TemporaryDirectory(prefix="kb-office-") as directory:
        root = Path(directory)
        source = root / f"source{extension}"
        output = root / "output"
        profile = root / "profile"
        output.mkdir(mode=0o700)
        profile.mkdir(mode=0o700)
        source.write_bytes(raw)
        _run_external(
            _sandboxed_command(
                [
                    str(tools.libreoffice_executable),
                    "--headless",
                    "--safe-mode",
                    "--nologo",
                    "--nodefault",
                    "--nolockcheck",
                    "--norestore",
                    f"-env:UserInstallation={profile.as_uri()}",
                    "--convert-to",
                    target_extension.removeprefix("."),
                    "--outdir",
                    str(output),
                    str(source),
                ],
                cwd=root,
                tools=tools,
                limits=limits,
            ),
            cwd=root,
            limits=limits,
        )
        results = list(output.glob(f"*{target_extension}"))
        if len(results) != 1 or results[0].is_symlink():
            raise DocumentParseError("parser_legacy_conversion_failed")
        converted = results[0].read_bytes()
    if len(converted) > limits.max_source_bytes:
        raise DocumentParseError("parser_source_too_large")
    parsed = _parse_ooxml(converted, target_extension, limits)
    return ParsedDocument(
        text=parsed.text,
        source_locations=parsed.source_locations,
        parser=f"libreoffice-{parsed.parser}",
        source_location_count=parsed.source_location_count,
        source_locations_truncated=parsed.source_locations_truncated,
        source_text_sha256=parsed.source_text_sha256,
        source_locations_sha256=parsed.source_locations_sha256,
    )


def _run_external(command: list[str], *, cwd: Path, limits: ParseLimits) -> None:
    environment = {
        "HOME": str(cwd),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(cwd),
    }
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=limits.external_timeout_seconds + 2,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DocumentParseError("parser_external_tool_failed") from error
    if completed.returncode != 0:
        raise DocumentParseError("parser_external_tool_failed")


def _sandboxed_command(
    command: list[str],
    *,
    cwd: Path,
    tools: ParserTools,
    limits: ParseLimits,
) -> list[str]:
    """Wrap parser tools in a mount/PID/network namespace with a cleared environment."""

    return [
        str(tools.sandbox_executable),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--clearenv",
        "--ro-bind",
        "/",
        "/",
        "--bind",
        str(cwd),
        str(cwd),
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--chdir",
        str(cwd),
        "--setenv",
        "HOME",
        str(cwd),
        "--setenv",
        "TMPDIR",
        str(cwd),
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--",
        str(tools.resource_limit_executable),
        f"--cpu={limits.external_timeout_seconds}:{limits.external_timeout_seconds}",
        f"--as={limits.external_memory_bytes}:{limits.external_memory_bytes}",
        f"--fsize={limits.max_expanded_bytes}:{limits.max_expanded_bytes}",
        "--nofile=64:64",
        "--",
        *command,
    ]


def _trusted_executable_available(path: Path) -> bool:
    if not path.is_absolute():
        return False
    try:
        metadata = path.stat()
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        return False
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False
    return os.name != "posix" or metadata.st_uid == 0


def _xml(data: bytes):  # type: ignore[no-untyped-def]
    try:
        return SafeElementTree.fromstring(data)
    except Exception as error:
        raise DocumentParseError("parser_malformed_xml") from error


def _resolve_ooxml_target(base: str, target: str) -> str:
    if not target or target.startswith(("/", "\\")):
        raise DocumentParseError("parser_unsafe_relationship")
    path = PurePosixPath(base, target.replace("\\", "/"))
    parts: list[str] = []
    for part in path.parts:
        if part == "..":
            if not parts:
                raise DocumentParseError("parser_unsafe_relationship")
            parts.pop()
        elif part not in {"", "."}:
            parts.append(part)
    resolved = "/".join(parts)
    if not resolved.startswith(f"{base}/"):
        raise DocumentParseError("parser_unsafe_relationship")
    return resolved


def _bounded_text(text: str, limits: ParseLimits) -> str:
    normalized = text.replace("\x00", "").strip()
    if not normalized:
        raise DocumentParseError("empty_source")
    if len(normalized) > limits.max_output_chars:
        raise DocumentParseError("parser_output_too_large")
    return normalized


def _single_line_cell_value(value: str) -> str:
    """Collapse all Unicode whitespace so a cell cannot mint a line-level locator."""

    return " ".join(value.split())


def _xlsx_column_number(column: str) -> int:
    number = 0
    for character in column:
        number = number * 26 + ord(character) - ord("A") + 1
    return number


def _document(
    parts: list[str], locations: list[str], parser: str, limits: ParseLimits
) -> ParsedDocument:
    text = _bounded_text("\n\n".join(parts), limits)
    # Retain a bounded evidence prefix while authenticating the complete ordered
    # manifest. Archive member limits remain independently enforced at ZIP intake.
    unique_locations = tuple(dict.fromkeys(locations))
    retained_locations = unique_locations[: limits.max_source_locations]
    return ParsedDocument(
        text=text,
        source_locations=retained_locations,
        parser=parser,
        source_location_count=len(unique_locations),
        source_locations_truncated=len(retained_locations) < len(unique_locations),
        source_text_sha256=compute_source_text_sha256(text),
        source_locations_sha256=compute_source_locations_sha256(unique_locations),
    )
