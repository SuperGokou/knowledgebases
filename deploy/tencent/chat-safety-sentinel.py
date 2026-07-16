#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import cast

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_BYTES = 4096
_MAX_RUN_STATE_BYTES = 1024
_RUN_STATE_FILENAME = "run-state.json"


class SentinelError(RuntimeError):
    pass


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SentinelError("sentinel JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise SentinelError(f"sentinel JSON contains a non-finite constant: {value}")


@dataclass(frozen=True, slots=True)
class VerifiedSentinel:
    digest: str
    inode: int
    device: int


def _validate_parent(path: Path, *, expected_uid: int, expected_gid: int) -> Path:
    if not path.is_absolute():
        raise SentinelError("sentinel path must be absolute")
    parent = path.parent
    parent_metadata = parent.lstat()
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise SentinelError("sentinel parent must be a real directory")
    if (
        parent_metadata.st_uid != expected_uid
        or parent_metadata.st_gid != expected_gid
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
    ):
        raise SentinelError("sentinel parent ownership or mode is invalid")
    return parent


def _lstat_optional(path: Path) -> os.stat_result | None:
    """Return metadata only for a definite path; propagate every non-ENOENT fault."""

    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _open_verified(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> tuple[int, VerifiedSentinel]:
    _validate_parent(path, expected_uid=expected_uid, expected_gid=expected_gid)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size <= 0
            or metadata.st_size > _MAX_BYTES
        ):
            raise SentinelError("sentinel metadata is invalid")
        payload = bytearray()
        while len(payload) <= _MAX_BYTES:
            chunk = os.read(descriptor, min(1024, _MAX_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if not payload or len(payload) > _MAX_BYTES:
            raise SentinelError("sentinel content size is invalid")
        try:
            document = json.loads(
                payload,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeError, json.JSONDecodeError) as error:
            raise SentinelError("sentinel JSON is invalid") from error
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "created_at", "pid", "reason", "error_class"}
            or document.get("schema_version") != 1
            or type(document.get("schema_version")) is not int
            or not isinstance(document.get("created_at"), str)
            or type(document.get("pid")) is not int
            or cast(int, document["pid"]) < 0
            or not isinstance(document.get("reason"), str)
            or not document["reason"]
            or (
                document.get("error_class") is not None
                and not isinstance(document.get("error_class"), str)
            )
        ):
            raise SentinelError("sentinel schema is invalid")
        digest = hashlib.sha256(payload).hexdigest()
        return descriptor, VerifiedSentinel(
            digest=digest,
            inode=metadata.st_ino,
            device=metadata.st_dev,
        )
    except BaseException:
        os.close(descriptor)
        raise


def verify(path: Path, *, expected_uid: int, expected_gid: int) -> VerifiedSentinel:
    descriptor, result = _open_verified(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    os.close(descriptor)
    return result


def status(path: Path, *, expected_uid: int, expected_gid: int) -> VerifiedSentinel | None:
    _validate_parent(path, expected_uid=expected_uid, expected_gid=expected_gid)
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return verify(path, expected_uid=expected_uid, expected_gid=expected_gid)


def verify_and_sync(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> VerifiedSentinel:
    descriptor, result = _open_verified(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent_descriptor = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    return result


def _sync_parent(parent: Path) -> None:
    descriptor = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_run_state(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> str:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode):
        raise SentinelError("chat safety run state must not be symbolic")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_dev != before.st_dev
            or metadata.st_ino != before.st_ino
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size <= 0
            or metadata.st_size > _MAX_RUN_STATE_BYTES
        ):
            raise SentinelError("chat safety run state metadata is invalid")
        payload = bytearray()
        while len(payload) <= _MAX_RUN_STATE_BYTES:
            chunk = os.read(
                descriptor,
                min(512, _MAX_RUN_STATE_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or len(payload) != metadata.st_size
        ):
            raise SentinelError("chat safety run state changed during validation")
    finally:
        os.close(descriptor)
    try:
        document = json.loads(
            payload,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SentinelError("chat safety run state JSON is invalid") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "updated_at", "pid", "phase"}
        or document.get("schema_version") != 1
        or type(document.get("schema_version")) is not int
        or not isinstance(document.get("updated_at"), str)
        or type(document.get("pid")) is not int
        or cast(int, document["pid"]) < 0
        or document.get("phase") not in {"clean", "running"}
    ):
        raise SentinelError("chat safety run state schema is invalid")
    return cast(str, document["phase"])


def mark_run_clean(
    poison_path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_digest: str,
) -> str:
    """Commit a clean restart latch while the exact poison is still present."""

    if _DIGEST.fullmatch(expected_digest) is None:
        raise SentinelError("expected sentinel digest is invalid")
    poison = verify_and_sync(
        poison_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if poison.digest != expected_digest:
        raise SentinelError("sentinel digest changed")
    parent = poison_path.parent
    path = parent / _RUN_STATE_FILENAME
    with suppress(FileNotFoundError):
        _validate_run_state(
            path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    payload = json.dumps(
        {
            "schema_version": 1,
            "updated_at": dt.datetime.now(dt.UTC).isoformat(),
            "pid": 0,
            "phase": "clean",
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    temporary = parent / (f".{_RUN_STATE_FILENAME}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    temporary_created = False
    operation_error: BaseException | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        temporary_created = True
        fchown = getattr(os, "fchown", None)
        fchmod = getattr(os, "fchmod", None)
        if not callable(fchown) or not callable(fchmod):
            raise SentinelError("descriptor ownership controls are unavailable")
        fchown(descriptor, expected_uid, expected_gid)
        fchmod(descriptor, 0o600)
        _sync_parent(parent)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("chat safety run state write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if (
            _validate_run_state(
                temporary,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            != "clean"
        ):
            raise SentinelError("chat safety run state phase changed before publish")
        current = verify(
            poison_path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        if current.digest != expected_digest:
            raise SentinelError("sentinel changed before clean run-state publish")
        os.replace(temporary, path)
        temporary_created = False
        _sync_parent(parent)
    except BaseException as error:
        operation_error = error
        raise
    finally:
        cleanup_error: BaseException | None = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_error = error
        if temporary_created:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
            try:
                _sync_parent(parent)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
        if operation_error is None and cleanup_error is not None:
            raise cleanup_error
    return hashlib.sha256(payload).hexdigest()


def clear(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_digest: str,
) -> VerifiedSentinel:
    if _DIGEST.fullmatch(expected_digest) is None:
        raise SentinelError("expected sentinel digest is invalid")
    descriptor, result = _open_verified(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    try:
        if result.digest != expected_digest:
            raise SentinelError("sentinel digest changed")
        current = path.lstat()
        if current.st_ino != result.inode or current.st_dev != result.device:
            raise SentinelError("sentinel changed during verification")
        path.unlink()
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        parent_descriptor = os.open(path.parent, directory_flags)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        os.close(descriptor)
    return result


def materialize(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    reason: str,
    error_class: str,
) -> VerifiedSentinel:
    parent = _validate_parent(path, expected_uid=expected_uid, expected_gid=expected_gid)
    if re.fullmatch(r"[a-z0-9_]{1,128}", reason) is None:
        raise SentinelError("materialized sentinel reason is invalid")
    if re.fullmatch(r"[A-Za-z0-9_.]{1,128}", error_class) is None:
        raise SentinelError("materialized sentinel error class is invalid")
    temporary = parent / f".{path.name}.materialize"

    def sync_parent() -> None:
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)

    final_metadata = _lstat_optional(path)
    temporary_metadata = _lstat_optional(temporary)
    if final_metadata is not None:
        if temporary_metadata is not None:
            if not (
                stat.S_ISREG(final_metadata.st_mode)
                and stat.S_ISREG(temporary_metadata.st_mode)
                and final_metadata.st_dev == temporary_metadata.st_dev
                and final_metadata.st_ino == temporary_metadata.st_ino
                and final_metadata.st_nlink == 2
                and temporary_metadata.st_nlink == 2
                and final_metadata.st_uid == expected_uid
                and final_metadata.st_gid == expected_gid
                and stat.S_IMODE(final_metadata.st_mode) == 0o600
            ):
                raise SentinelError(
                    "materialization temporary file conflicts with the final sentinel"
                )
            temporary.unlink()
            sync_parent()
        return verify_and_sync(path, expected_uid=expected_uid, expected_gid=expected_gid)
    if temporary_metadata is not None:
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or temporary_metadata.st_nlink != 1
            or temporary_metadata.st_uid != expected_uid
            or temporary_metadata.st_gid != expected_gid
            or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
        ):
            raise SentinelError("materialization temporary file is unsafe")
        temporary.unlink()
        sync_parent()
    payload = json.dumps(
        {
            "schema_version": 1,
            "created_at": dt.datetime.now(dt.UTC).isoformat(),
            "pid": 0,
            "reason": reason,
            "error_class": error_class,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
    except FileExistsError:
        raise SentinelError("materialization temporary file appeared concurrently") from None
    descriptor_metadata = os.fstat(descriptor)
    try:
        fchown = getattr(os, "fchown", None)
        fchmod = getattr(os, "fchmod", None)
        if not callable(fchown) or not callable(fchmod):
            raise SentinelError("descriptor ownership controls are unavailable")
        fchown(descriptor, expected_uid, expected_gid)
        fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("materialized sentinel write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        try:
            current = temporary.lstat()
            if (
                current.st_dev == descriptor_metadata.st_dev
                and current.st_ino == descriptor_metadata.st_ino
            ):
                temporary.unlink()
                sync_parent()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError:
        temporary.unlink()
        sync_parent()
        return verify_and_sync(path, expected_uid=expected_uid, expected_gid=expected_gid)
    temporary.unlink()
    sync_parent()
    return verify_and_sync(path, expected_uid=expected_uid, expected_gid=expected_gid)


def main() -> int:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    for command in ("verify", "status", "clear", "materialize", "mark-run-clean"):
        subcommand = subcommands.add_parser(command)
        subcommand.add_argument("path", type=Path)
        subcommand.add_argument("--expected-uid", type=int, required=True)
        subcommand.add_argument("--expected-gid", type=int, required=True)
        if command in {"clear", "mark-run-clean"}:
            subcommand.add_argument("--expected-sha256", required=True)
        elif command == "materialize":
            subcommand.add_argument("--reason", required=True)
            subcommand.add_argument("--error-class", required=True)
    arguments = parser.parse_args()
    result: VerifiedSentinel | None
    try:
        if arguments.command == "verify":
            result = verify(
                arguments.path,
                expected_uid=arguments.expected_uid,
                expected_gid=arguments.expected_gid,
            )
        elif arguments.command == "status":
            result = status(
                arguments.path,
                expected_uid=arguments.expected_uid,
                expected_gid=arguments.expected_gid,
            )
            if result is None:
                print("absent")
                return 0
        elif arguments.command == "clear":
            result = clear(
                arguments.path,
                expected_uid=arguments.expected_uid,
                expected_gid=arguments.expected_gid,
                expected_digest=arguments.expected_sha256,
            )
        elif arguments.command == "mark-run-clean":
            print(
                mark_run_clean(
                    arguments.path,
                    expected_uid=arguments.expected_uid,
                    expected_gid=arguments.expected_gid,
                    expected_digest=arguments.expected_sha256,
                )
            )
            return 0
        else:
            result = materialize(
                arguments.path,
                expected_uid=arguments.expected_uid,
                expected_gid=arguments.expected_gid,
                reason=arguments.reason,
                error_class=arguments.error_class,
            )
    except (OSError, SentinelError) as error:
        print(f"chat-safety-sentinel: {error}", file=sys.stderr)
        return 65
    assert result is not None
    if arguments.command == "status":
        print(f"present {result.digest}")
    else:
        print(result.digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
