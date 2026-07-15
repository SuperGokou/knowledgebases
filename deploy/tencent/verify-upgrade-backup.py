from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SCHEMA_HEAD = re.compile(r"^[0-9]{8}_[0-9]{4}$")
_BACKUP_ROOT = Path("/srv/heyi-knowledgebases-offline/backups")


def _protected_regular_file(path: Path, *, max_bytes: int | None = None) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"protected path is not absolute and regular: {path}")
    canonical = path.resolve(strict=True)
    if canonical != path:
        raise ValueError(f"protected path is non-canonical or symbolic: {path}")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
        raise ValueError(f"protected file ownership or type is unsafe: {path}")
    if stat.S_IMODE(info.st_mode) not in {0o400, 0o440, 0o444}:
        raise ValueError(f"protected file permissions are unsafe: {path}")
    if max_bytes is not None and not 1 <= info.st_size <= max_bytes:
        raise ValueError(f"protected file size is outside the accepted boundary: {path}")
    checked = path.parent
    while True:
        ancestor = checked.lstat()
        if (
            checked.is_symlink()
            or not stat.S_ISDIR(ancestor.st_mode)
            or ancestor.st_uid != 0
            or ancestor.st_mode & 0o022
        ):
            raise ValueError(f"protected path ancestor is unsafe: {checked}")
        if checked == Path("/"):
            break
        checked = checked.parent
    return canonical


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must use UTC")
    return parsed.astimezone(UTC)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact(document: dict[str, Any], field: str) -> tuple[Path, str, int]:
    value = document.get(field)
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "size_bytes"}:
        raise ValueError(f"{field} must contain path, sha256 and size_bytes")
    raw_path = value["path"]
    digest = value["sha256"]
    size = value["size_bytes"]
    if (
        not isinstance(raw_path, str)
        or not isinstance(digest, str)
        or not _DIGEST.fullmatch(digest)
    ):
        raise ValueError(f"{field} identity is invalid")
    if not isinstance(size, int) or size <= 0:
        raise ValueError(f"{field} size is invalid")
    path = _protected_regular_file(Path(raw_path))
    try:
        path.relative_to(_BACKUP_ROOT)
    except ValueError as exc:
        raise ValueError(f"{field} is outside the protected backup root") from exc
    if path.stat().st_size != size or _sha256(path) != digest:
        raise ValueError(f"{field} content differs from the signed evidence")
    return path, digest, size


def verify(arguments: argparse.Namespace) -> None:
    evidence = _protected_regular_file(arguments.evidence, max_bytes=65_536)
    signature = _protected_regular_file(arguments.signature, max_bytes=16_384)
    public_key = _protected_regular_file(arguments.public_key, max_bytes=65_536)
    completed = subprocess.run(
        [
            "/usr/bin/openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public_key),
            "-signature",
            str(signature),
            str(evidence),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        cwd="/",
        check=False,
        timeout=20,
    )
    if completed.returncode != 0:
        raise ValueError("upgrade backup evidence signature is invalid")
    document = json.loads(evidence.read_text(encoding="utf-8"))
    expected_keys = {
        "schema_version",
        "kind",
        "project",
        "issued_at",
        "expires_at",
        "target_manifest_sha256",
        "database_backup",
        "object_manifest",
        "restore_evidence",
        "restore_drill",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise ValueError("upgrade backup evidence schema is invalid")
    if (
        document["schema_version"] != 1
        or document["kind"] != "offline-upgrade-backup"
        or document["project"] != "heyi-kb-offline"
        or document["target_manifest_sha256"] != arguments.expected_manifest_sha256
    ):
        raise ValueError("upgrade backup evidence identity differs")
    now = datetime.now(UTC)
    issued_at = _timestamp(document["issued_at"], "issued_at")
    expires_at = _timestamp(document["expires_at"], "expires_at")
    if not now - timedelta(hours=24) <= issued_at <= now + timedelta(minutes=5):
        raise ValueError("upgrade backup evidence is stale or future-dated")
    if not now < expires_at <= issued_at + timedelta(hours=24):
        raise ValueError("upgrade backup evidence has expired or exceeds its validity window")
    _artifact(document, "database_backup")
    _artifact(document, "object_manifest")
    _artifact(document, "restore_evidence")
    drill = document["restore_drill"]
    if not isinstance(drill, dict) or set(drill) != {
        "status",
        "tested_at",
        "source_schema_head",
    }:
        raise ValueError("restore drill evidence schema is invalid")
    tested_at = _timestamp(drill["tested_at"], "restore_drill.tested_at")
    if (
        drill["status"] != "passed"
        or not isinstance(drill["source_schema_head"], str)
        or _SCHEMA_HEAD.fullmatch(drill["source_schema_head"]) is None
        or not now - timedelta(days=30) <= tested_at <= now + timedelta(minutes=5)
    ):
        raise ValueError("restore drill did not satisfy the accepted contract")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    arguments = parser.parse_args()
    if _DIGEST.fullmatch(arguments.expected_manifest_sha256) is None:
        print("backup-evidence: expected manifest digest is invalid", file=sys.stderr)
        return 65
    try:
        verify(arguments)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"backup-evidence: {exc}", file=sys.stderr)
        return 65
    print("backup-evidence: signed backup and restore drill are current and verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
