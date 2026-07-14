# Compact deterministic OOXML/PDF payload literals intentionally exceed the project line limit.
# ruff: noqa: E501

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Final, Literal
from xml.sax.saxutils import escape

BUILTIN_EXTENSIONS: Final = (".txt", ".csv", ".docx", ".xlsx", ".pptx", ".pdf")
LEGACY_EXTENSIONS: Final = (".doc", ".xls", ".ppt")
REQUIRED_EXTENSIONS: Final = (
    ".txt",
    ".csv",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".pdf",
    ".ppt",
    ".pptx",
)
MANIFEST_NAME: Final = "document-fixtures-v1.json"
LIBREOFFICE: Final = "/usr/bin/libreoffice"
BWRAP: Final = "/usr/bin/bwrap"
PRLIMIT: Final = "/usr/bin/prlimit"
_ZIP_TIMESTAMP: Final = (2026, 1, 1, 0, 0, 0)
_PLACEHOLDER_MARKERS: Final = (b"placeholder", b"todo", b"lorem ipsum", b"dummy")
_OLE_SIGNATURE: Final = bytes.fromhex("D0CF11E0A1B11AE1")
_OOXML_REQUIRED_ENTRY: Final = {
    ".docx": "word/document.xml",
    ".xlsx": "xl/worksheets/sheet1.xml",
    ".pptx": "ppt/slides/slide1.xml",
}


class FixtureBlocked(RuntimeError):
    """Fail-closed acceptance fixture error safe to expose in automation logs."""


@dataclass(frozen=True, slots=True)
class FixturePlan:
    extension: str
    relative_path: str
    token: str
    expected_source_locations: tuple[str, ...]
    generator: Literal["stdlib", "libreoffice"]


def build_plan(root: Path) -> tuple[FixturePlan, ...]:
    del root
    locations = {
        ".txt": ("document",),
        ".csv": ("row:3",),
        ".doc": ("paragraph:2",),
        ".docx": ("paragraph:2",),
        ".xls": ("worksheet:Acceptance!B2",),
        ".xlsx": ("worksheet:Acceptance!B2",),
        ".pdf": ("page:1",),
        ".ppt": ("slide:1",),
        ".pptx": ("slide:1",),
    }
    return tuple(
        FixturePlan(
            extension=extension,
            relative_path=f"golden/enterprise-acceptance-{extension.removeprefix('.')}2026{extension}",
            token=f"KB-E2E-GOLDEN-{extension.removeprefix('.').upper()}-2026-A71C",
            expected_source_locations=locations[extension],
            generator="stdlib" if extension in BUILTIN_EXTENSIONS else "libreoffice",
        )
        for extension in REQUIRED_EXTENSIONS
    )


def _safe_root(root: Path) -> Path:
    if not root.is_absolute():
        raise FixtureBlocked("fixture root must be an explicit absolute path")
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise FixtureBlocked("fixture root must be a non-symlink directory")
    if any(parent.is_symlink() for parent in root.parents):
        raise FixtureBlocked("fixture root must not contain a symlink path component")
    root.mkdir(parents=True, exist_ok=True)
    resolved = root.resolve(strict=True)
    golden = resolved / "golden"
    if golden.is_symlink() or (golden.exists() and not golden.is_dir()):
        raise FixtureBlocked("golden fixture directory must not be a symlink")
    golden.mkdir(mode=0o750, exist_ok=True)
    return resolved


def _atomic_write(root: Path, relative_path: str, payload: bytes) -> Path:
    target = root / relative_path
    if not target.resolve(strict=False).is_relative_to(root):
        raise FixtureBlocked("fixture target escapes the acceptance root")
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise FixtureBlocked("fixture target must be a regular non-symlink file")
    target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp-{os.getpid()}")
    if temporary.exists():
        temporary.unlink()
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return target


def _zip(entries: dict[str, bytes]) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, _ZIP_TIMESTAMP)
            info.create_system = 3
            info.create_version = 20
            info.extract_version = 20
            info.compress_type = zipfile.ZIP_STORED
            info.flag_bits = 0
            info.internal_attr = 0
            info.external_attr = 0o100644 << 16
            archive.writestr(info, entries[name])
    return output.getvalue()


def _docx(token: str) -> bytes:
    body = (
        "Enterprise acceptance synthetic document. "
        "This original content is dedicated to acceptance testing."
    )
    document = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>
<w:p><w:r><w:t>{escape(body)}</w:t></w:r></w:p>
<w:p><w:r><w:t>{escape(token)} service_level=golden metric=137</w:t></w:r></w:p>
<w:sectPr/></w:body></w:document>""".encode()
    return _zip(
        {
            "[Content_Types].xml": b"""<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>""",
            "_rels/.rels": b"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>""",
            "word/document.xml": document,
        }
    )


def _xlsx(token: str) -> bytes:
    sheet = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>
<row r="1"><c r="A1" t="inlineStr"><is><t>field</t></is></c><c r="B1" t="inlineStr"><is><t>value</t></is></c></row>
<row r="2"><c r="A2" t="inlineStr"><is><t>acceptance_token</t></is></c><c r="B2" t="inlineStr"><is><t>{escape(token)}</t></is></c></row>
<row r="3"><c r="A3" t="inlineStr"><is><t>metric</t></is></c><c r="B3"><v>137</v></c></row>
</sheetData></worksheet>""".encode()
    return _zip(
        {
            "[Content_Types].xml": b"""<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>""",
            "_rels/.rels": b"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>""",
            "xl/_rels/workbook.xml.rels": b"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>""",
            "xl/workbook.xml": b"""<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Acceptance" sheetId="1" r:id="rId1"/></sheets></workbook>""",
            "xl/worksheets/sheet1.xml": sheet,
        }
    )


def _pptx(token: str) -> bytes:
    slide = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>{escape(token)}</a:t></a:r><a:r><a:t> service_level=golden metric=137</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>""".encode()
    return _zip(
        {
            "[Content_Types].xml": b"""<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/><Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/></Types>""",
            "_rels/.rels": b"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/></Relationships>""",
            "ppt/_rels/presentation.xml.rels": b"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/></Relationships>""",
            "ppt/presentation.xml": b"""<?xml version="1.0" encoding="UTF-8"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst></p:presentation>""",
            "ppt/slides/slide1.xml": slide,
        }
    )


def _pdf(token: str) -> bytes:
    text = f"{token} service_level=golden metric=137"
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    output = bytearray(b"%PDF-1.4\n% acceptance fixture\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode())
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(output)


def _builtin_payload(extension: str, token: str) -> bytes:
    if extension == ".txt":
        return (
            "Enterprise acceptance synthetic record.\n"
            f"{token} service_level=golden metric=137\n"
            "Original test-only content; no third-party material.\n"
        ).encode()
    if extension == ".csv":
        return (
            "field,value\n"
            "service_level,golden\n"
            f"acceptance_token,{token}\n"
            "metric,137\n"
        ).encode()
    if extension == ".docx":
        return _docx(token)
    if extension == ".xlsx":
        return _xlsx(token)
    if extension == ".pptx":
        return _pptx(token)
    if extension == ".pdf":
        return _pdf(token)
    raise AssertionError(f"unsupported builtin extension: {extension}")


def generate_builtin_fixtures(root: Path) -> tuple[Path, ...]:
    safe_root = _safe_root(root)
    generated = []
    for item in build_plan(safe_root):
        if item.extension in BUILTIN_EXTENSIONS:
            generated.append(
                _atomic_write(
                    safe_root,
                    item.relative_path,
                    _builtin_payload(item.extension, item.token),
                )
            )
    return tuple(generated)


def _trusted_executable(path: str) -> bool:
    candidate = Path(path)
    if os.name != "posix" or not candidate.is_absolute():
        return False
    try:
        metadata = candidate.stat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        and os.access(candidate, os.X_OK)
    )


def _require_legacy_toolchain() -> None:
    unavailable = [
        path for path in (LIBREOFFICE, BWRAP, PRLIMIT) if not _trusted_executable(path)
    ]
    if unavailable:
        raise FixtureBlocked(
            "trusted Linux legacy fixture toolchain is unavailable: " + ", ".join(unavailable)
        )


def _run_libreoffice(source: Path, output: Path, profile: Path, target: str) -> None:
    command = [
        BWRAP,
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--clearenv",
        "--ro-bind",
        "/",
        "/",
        "--bind",
        str(source.parent),
        str(source.parent),
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--chdir",
        str(source.parent),
        "--setenv",
        "HOME",
        str(profile),
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--",
        PRLIMIT,
        "--cpu=60:60",
        "--as=1073741824:1073741824",
        "--fsize=67108864:67108864",
        "--nofile=128:128",
        "--",
        LIBREOFFICE,
        "--headless",
        "--safe-mode",
        "--nologo",
        "--nodefault",
        "--nolockcheck",
        "--norestore",
        f"-env:UserInstallation={profile.as_uri()}",
        "--convert-to",
        target,
        "--outdir",
        str(output),
        str(source),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=source.parent,
            env={
                "HOME": str(profile),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=75,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise FixtureBlocked("trusted LibreOffice conversion failed") from error
    if completed.returncode != 0:
        raise FixtureBlocked("trusted LibreOffice conversion failed")


def generate_legacy_fixtures(root: Path) -> tuple[Path, ...]:
    safe_root = _safe_root(root)
    _require_legacy_toolchain()
    sources = {".doc": (".docx", _docx), ".xls": (".xlsx", _xlsx), ".ppt": (".pptx", _pptx)}
    generated = []
    with tempfile.TemporaryDirectory(prefix="kb-fixture-", dir=safe_root) as raw_directory:
        directory = Path(raw_directory)
        output = directory / "output"
        profile = directory / "profile"
        output.mkdir(mode=0o700)
        profile.mkdir(mode=0o700)
        for item in build_plan(safe_root):
            if item.extension not in LEGACY_EXTENSIONS:
                continue
            modern_extension, factory = sources[item.extension]
            source = directory / f"source{modern_extension}"
            source.write_bytes(factory(item.token))
            _run_libreoffice(source, output, profile, item.extension.removeprefix("."))
            candidates = list(output.glob(f"source{item.extension}"))
            if (
                len(candidates) != 1
                or candidates[0].is_symlink()
                or not candidates[0].is_file()
            ):
                raise FixtureBlocked(f"LibreOffice did not produce a real {item.extension} fixture")
            payload = candidates[0].read_bytes()
            if not _is_valid_format(item, payload) or not _payload_has_token(
                payload, item.token
            ):
                raise FixtureBlocked(f"LibreOffice output is not a real legacy {item.extension} file")
            generated.append(_atomic_write(safe_root, item.relative_path, payload))
            candidates[0].unlink()
    return tuple(generated)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _payload_has_token(payload: bytes, token: str) -> bool:
    return any(
        encoded in payload
        for encoded in (
            token.encode("ascii"),
            token.encode("utf-16le"),
            token.encode("utf-16be"),
        )
    )


def _payload_has_placeholder(payload: bytes) -> bool:
    lowered = payload.lower()
    return any(
        encoded in lowered
        for marker in _PLACEHOLDER_MARKERS
        for encoded in (
            marker,
            marker.decode("ascii").encode("utf-16le"),
            marker.decode("ascii").encode("utf-16be"),
        )
    )


def _is_valid_format(item: FixturePlan, payload: bytes) -> bool:
    extension = item.extension
    if extension == ".txt":
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return b"\x00" not in payload
    if extension == ".csv":
        try:
            rows = list(csv.reader(io.StringIO(payload.decode("utf-8"))))
        except (csv.Error, UnicodeDecodeError):
            return False
        return (
            len(rows) >= 3
            and rows[0] == ["field", "value"]
            and rows[2] == ["acceptance_token", item.token]
        )
    if extension in LEGACY_EXTENSIONS:
        return (
            len(payload) >= 512
            and payload.startswith(_OLE_SIGNATURE)
            and payload[24:26] == bytes.fromhex("FEFF")
            and int.from_bytes(payload[30:32], "little") == 9
            and int.from_bytes(payload[32:34], "little") == 6
        )
    if extension in _OOXML_REQUIRED_ENTRY:
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                required = _OOXML_REQUIRED_ENTRY[extension]
                return required in archive.namelist() and bool(archive.read(required))
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return False
    if extension == ".pdf":
        return payload.startswith(b"%PDF-") and payload.rstrip().endswith(b"%%EOF")
    return False


def verify_fixture_set(
    root: Path,
    *,
    manifest_path: Path | None = None,
    write_manifest: bool = False,
) -> Path:
    safe_root = _safe_root(root)
    plan = build_plan(safe_root)
    missing = [item.extension for item in plan if not (safe_root / item.relative_path).is_file()]
    if missing:
        category = "legacy fixtures are missing" if set(missing) <= set(LEGACY_EXTENSIONS) else "fixtures are missing"
        raise FixtureBlocked(f"{category}: {','.join(missing)}")

    records = []
    for item in plan:
        path = safe_root / item.relative_path
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(safe_root):
            raise FixtureBlocked("fixture must be a regular file beneath the fixture root")
        payload = path.read_bytes()
        if _payload_has_placeholder(payload):
            raise FixtureBlocked(f"placeholder content is forbidden: {item.extension}")
        if not _is_valid_format(item, payload):
            raise FixtureBlocked(f"invalid {item.extension} fixture format")
        if not _payload_has_token(payload, item.token):
            raise FixtureBlocked(f"content token is missing: {item.extension}")
        records.append(
            {
                **asdict(item),
                "expected_source_locations": list(item.expected_source_locations),
                "sha256": _sha256(path),
                "bytes": len(payload),
            }
        )

    target_manifest = manifest_path or safe_root / MANIFEST_NAME
    if not target_manifest.is_absolute():
        raise FixtureBlocked("fixture manifest path must be absolute")
    if target_manifest.is_symlink() or (
        target_manifest.exists() and not target_manifest.is_file()
    ):
        raise FixtureBlocked("fixture manifest must be a regular non-symlink file")
    if not target_manifest.resolve(strict=False).is_relative_to(safe_root):
        raise FixtureBlocked("fixture manifest must remain beneath the fixture root")
    document = {
        "schema_version": 1,
        "fixture_set": "heyi-enterprise-document-acceptance-v1",
        "license": "CC0-1.0",
        "content_origin": "original-synthetic-test-data",
        "network_required": False,
        "fixtures": records,
    }
    if target_manifest.exists() and not write_manifest:
        try:
            existing = json.loads(target_manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise FixtureBlocked("fixture manifest is unreadable") from error
        if existing != document:
            raise FixtureBlocked("fixture manifest hash mismatch or contract drift")
    elif write_manifest:
        _atomic_write(
            safe_root,
            str(target_manifest.relative_to(safe_root)).replace("\\", "/"),
            (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(),
        )
    else:
        raise FixtureBlocked("fixture manifest is missing")
    return target_manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan, generate, and verify nine-format E2E fixtures")
    parser.add_argument("action", nargs="?", choices=("plan", "generate", "verify"), default="plan")
    parser.add_argument("--root", type=Path, help="absolute acceptance-only fixture directory")
    parser.add_argument("--manifest", type=Path, help="absolute manifest path beneath --root")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.action == "plan":
        root = args.root or Path("/var/lib/knowledge-base/acceptance/document-fixtures")
        print(json.dumps([asdict(item) for item in build_plan(root)], ensure_ascii=False, indent=2))
        return 0
    if args.root is None or not args.root.is_absolute():
        print("BLOCKED: generate/verify requires an explicit absolute --root", file=sys.stderr)
        return 2
    try:
        if args.action == "generate":
            _require_legacy_toolchain()
            generate_builtin_fixtures(args.root)
            generate_legacy_fixtures(args.root)
            manifest = verify_fixture_set(args.root, manifest_path=args.manifest, write_manifest=True)
        else:
            manifest = verify_fixture_set(args.root, manifest_path=args.manifest)
    except FixtureBlocked as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "passed",
                "manifest": str(manifest),
                "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
