from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

_GIT_HEAD_PATTERN = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_PYTEST_COLLECTION_SUMMARY = re.compile(r"(?m)^(\d+) tests? collected(?:\s+in\s+[^\r\n]+)?$")
_MAX_JUNIT_BYTES = 100 * 1024 * 1024
_SAFE_POSIX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_UNTRUSTED_ENVIRONMENT_NAMES = frozenset(
    {
        "PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "VIRTUAL_ENV",
        "NODE_OPTIONS",
        "NODE_PATH",
        "LIBPATH",
        "SHLIB_PATH",
    }
)
_UNTRUSTED_ENVIRONMENT_PREFIXES = (
    "LD_",
    "DYLD_",
    "PYTEST_",
    "UV_",
    "COVERAGE_",
    "COMPOSE_",
    "DOCKER_",
    "KB_",
)
_RUNNER_OWNED_ENVIRONMENT_OVERRIDES = frozenset(
    {
        "COVERAGE_FILE",
        "KB_DATABASE_URL",
        "KB_E2E_ADMIN_EMAIL",
        "KB_E2E_ADMIN_PASSWORD",
        "KB_E2E_AUDIT_OVERSIZED_ACTION",
        "KB_E2E_AUDIT_PAGE_ACTION",
        "KB_E2E_AUDIT_REDACTION_SENTINEL",
        "KB_E2E_BASE_URL",
        "KB_E2E_CHALLENGE_PATH",
        "KB_E2E_DOCUMENT_FIXTURE_MANIFEST",
        "KB_E2E_DOCUMENT_FIXTURE_ROOT",
        "KB_E2E_EVIDENCE_PATH",
        "KB_E2E_FAULT_CONTROL_ORIGIN",
        "KB_E2E_FAULT_CONTROL_TOKEN",
        "KB_E2E_JOB_TIMEOUT_MS",
        "KB_E2E_MULTIPART_BYTES",
        "KB_E2E_OBJECTS_ORIGIN",
        "KB_E2E_PROFILE",
        "KB_E2E_PUBLIC_API_ORIGIN",
        "KB_E2E_RUN_ID",
        "KB_E2E_SEEDED_KNOWLEDGE_BASE_ID",
        "KB_E2E_SIGNING_KEY_ID",
        "KB_E2E_SIGNING_KEY_PATH",
        "KB_E2E_SUITE_TIMEOUT_MS",
        "KB_E2E_TEST_TIMEOUT_MS",
        "KB_E2E_UNSCOPED_KNOWLEDGE_BASE_ID",
        "KB_OFFLINE_LOCK_HELD",
        "KB_TEST_POSTGRES_URL",
        "KB_TEST_MIGRATION_POSTGRES_URL",
        "KB_POSTGRES_ACCEPTANCE_MARKER",
    }
)


class AcceptanceGateError(RuntimeError):
    """Raised when an acceptance run cannot prove its execution contract."""


@dataclass(frozen=True, slots=True)
class TrustedExecutableBinding:
    """Canonical executable identity carried across a sanitized process boundary."""

    path: str
    sha256: str
    require_root_owner: bool = False


_EXECUTABLE_IDENTITY_FIELDS = (
    "st_dev",
    "st_ino",
    "st_size",
    "st_mtime_ns",
)
_POSIX_EXECUTABLE_SECURITY_FIELDS = ("st_mode", "st_uid", "st_gid", "st_ctime_ns")


def _same_executable_metadata(left: os.stat_result, right: os.stat_result) -> bool:
    fields = _EXECUTABLE_IDENTITY_FIELDS + (
        _POSIX_EXECUTABLE_SECURITY_FIELDS if os.name == "posix" else ()
    )
    return all(getattr(left, field) == getattr(right, field) for field in fields)


def _trusted_executable_digest(path: Path, expected_metadata: os.stat_result) -> str:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AcceptanceGateError(
            "trusted executable cannot be opened without following links"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not _same_executable_metadata(expected_metadata, before):
            raise AcceptanceGateError("trusted executable changed before hashing")
        if not stat.S_ISREG(before.st_mode):
            raise AcceptanceGateError("trusted executable must be a regular file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if not _same_executable_metadata(before, after):
            raise AcceptanceGateError("trusted executable changed while hashing")
        try:
            final_metadata = path.lstat()
        except OSError as exc:
            raise AcceptanceGateError("trusted executable changed after hashing") from exc
        if not _same_executable_metadata(after, final_metadata):
            raise AcceptanceGateError("trusted executable changed after hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _inspect_trusted_executable(
    repository: Path,
    path: Path,
    *,
    expected_sha256: str | None = None,
    require_root_owner: bool = False,
) -> tuple[Path, str]:
    repository = repository.resolve(strict=True)
    if not path.is_absolute():
        raise AcceptanceGateError("trusted executable path must be absolute")
    try:
        supplied_metadata = path.lstat()
    except OSError as exc:
        raise AcceptanceGateError("trusted executable is unavailable") from exc
    if stat.S_ISLNK(supplied_metadata.st_mode):
        raise AcceptanceGateError("trusted executable cannot be a symbolic link")
    try:
        canonical = path.resolve(strict=True)
        metadata = canonical.lstat()
    except OSError as exc:
        raise AcceptanceGateError("trusted executable cannot be resolved") from exc
    if canonical != path or stat.S_ISLNK(metadata.st_mode):
        raise AcceptanceGateError("trusted executable cannot be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise AcceptanceGateError("trusted executable must be a regular file")
    if canonical == repository or repository in canonical.parents:
        raise AcceptanceGateError("trusted executable must be outside the repository")
    if os.name == "posix":
        effective_user = os.geteuid()  # type: ignore[attr-defined, unused-ignore]
        trusted_owners = {0} if require_root_owner else {0, effective_user}
        if not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            raise AcceptanceGateError("trusted executable is not executable")
        if metadata.st_uid not in trusted_owners:
            message = (
                "trusted executable must be root-owned"
                if require_root_owner
                else "trusted executable has an untrusted owner"
            )
            raise AcceptanceGateError(message)
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise AcceptanceGateError("trusted executable is group/world writable")
        for ancestor in canonical.parents:
            ancestor_metadata = ancestor.stat()
            if ancestor_metadata.st_uid not in trusted_owners:
                message = (
                    "trusted executable ancestors must be root-owned"
                    if require_root_owner
                    else "trusted executable has an untrusted ancestor owner"
                )
                raise AcceptanceGateError(message)
            if ancestor_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise AcceptanceGateError("trusted executable has a writable ancestor")
    digest = _trusted_executable_digest(canonical, metadata)
    if expected_sha256 is not None and not secrets.compare_digest(digest, expected_sha256):
        raise AcceptanceGateError("trusted executable digest does not match its binding")
    return canonical, digest


def bind_trusted_executable(
    repository: Path,
    executable: str,
    *,
    search_path: str | None = None,
    require_root_owner: bool = False,
) -> TrustedExecutableBinding:
    """Resolve and attest one executable before sanitizing the child environment."""

    located = shutil.which(executable, path=search_path)
    if located is None:
        raise AcceptanceGateError("trusted executable is unavailable")
    candidate = Path(located)
    if not candidate.is_absolute():
        candidate = candidate.absolute()
    try:
        if stat.S_ISLNK(candidate.lstat().st_mode):
            raise AcceptanceGateError("trusted executable cannot be a symbolic link")
        candidate = candidate.resolve(strict=True)
    except OSError as exc:
        raise AcceptanceGateError("trusted executable cannot be resolved") from exc
    canonical, digest = _inspect_trusted_executable(
        repository,
        candidate,
        require_root_owner=require_root_owner,
    )
    return TrustedExecutableBinding(
        path=str(canonical),
        sha256=digest,
        require_root_owner=require_root_owner,
    )


def bind_trusted_executable_path(
    repository: Path,
    executable: Path,
    *,
    require_root_owner: bool = False,
) -> TrustedExecutableBinding:
    """Attest an explicitly selected executable without consulting PATH."""

    canonical, digest = _inspect_trusted_executable(
        repository,
        executable,
        require_root_owner=require_root_owner,
    )
    return TrustedExecutableBinding(
        path=str(canonical),
        sha256=digest,
        require_root_owner=require_root_owner,
    )


def verify_trusted_executable_binding(
    repository: Path,
    binding: TrustedExecutableBinding,
) -> str:
    """Revalidate executable metadata and content immediately before execution."""

    if _SHA256_PATTERN.fullmatch(binding.sha256) is None:
        raise AcceptanceGateError("trusted executable digest is invalid")
    canonical, _ = _inspect_trusted_executable(
        repository,
        Path(binding.path),
        expected_sha256=binding.sha256,
        require_root_owner=binding.require_root_owner,
    )
    return str(canonical)


class WorktreeIdentity(Protocol):
    git_head: str
    content_fingerprint: str


IdentityCollector = Callable[[Path], WorktreeIdentity]


@dataclass(frozen=True, slots=True)
class GateIdentity:
    git_head: str
    content_fingerprint: str
    run_nonce: str

    def target(self) -> dict[str, str]:
        return {
            "git_head": self.git_head,
            "content_fingerprint": self.content_fingerprint,
            "run_nonce": self.run_nonce,
        }


@dataclass(frozen=True, slots=True)
class PytestJUnitEvidence:
    collected: int
    executed: int
    passed: int
    failed: int
    errors: int
    skipped: int
    xfailed: int
    xpassed: int
    deselected: int
    unexpected: int
    node_ids: tuple[str, ...]
    missing_node_ids: tuple[str, ...]
    unexpected_node_ids: tuple[str, ...]
    test_files: tuple[str, ...]
    sha256: str
    size: int

    @property
    def is_success(self) -> bool:
        return bool(
            self.collected > 0
            and self.executed == self.collected
            and self.passed == self.collected
            and not any(
                (
                    self.failed,
                    self.errors,
                    self.skipped,
                    self.xfailed,
                    self.xpassed,
                    self.deselected,
                    self.unexpected,
                )
            )
        )

    def as_dict(self, *, path: str) -> dict[str, object]:
        return {
            "path": path,
            "sha256": self.sha256,
            "bytes": self.size,
            "collected": self.collected,
            "executed": self.executed,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "skipped": self.skipped,
            "xfailed": self.xfailed,
            "xpassed": self.xpassed,
            "deselected": self.deselected,
            "unexpected": self.unexpected,
            "node_ids": list(self.node_ids),
            "missing_node_ids": list(self.missing_node_ids),
            "unexpected_node_ids": list(self.unexpected_node_ids),
            "test_files": list(self.test_files),
        }


def _collect_worktree_identity(repository: Path) -> WorktreeIdentity:
    module = importlib.import_module("scripts.acceptance")
    collector = cast("object", module.collect_worktree_evidence)
    if not callable(collector):
        raise AcceptanceGateError("worktree evidence collector is unavailable")
    return cast("WorktreeIdentity", collector(repository))


def _valid_nonce(value: str) -> bool:
    return (
        32 <= len(value) <= 128
        and len(value) % 2 == 0
        and re.fullmatch(r"[0-9a-f]+", value) is not None
    )


def start_gate_identity(
    repository: Path,
    *,
    expected_git_head: str | None = None,
    expected_content_fingerprint: str | None = None,
    run_nonce: str | None = None,
    collector: IdentityCollector = _collect_worktree_identity,
) -> GateIdentity:
    supplied = (expected_git_head, expected_content_fingerprint, run_nonce)
    if any(value is not None for value in supplied) and not all(
        value is not None for value in supplied
    ):
        raise AcceptanceGateError("expected identity arguments must be supplied together")
    current = collector(repository.resolve())
    expected_head = expected_git_head or current.git_head
    expected_fingerprint = expected_content_fingerprint or current.content_fingerprint
    nonce = run_nonce or secrets.token_hex(16)
    if _GIT_HEAD_PATTERN.fullmatch(expected_head) is None:
        raise AcceptanceGateError("expected git head is malformed")
    if _SHA256_PATTERN.fullmatch(expected_fingerprint) is None:
        raise AcceptanceGateError("expected content fingerprint is malformed")
    if not _valid_nonce(nonce):
        raise AcceptanceGateError(
            "acceptance run nonce must contain at least 128 bits of lowercase hex"
        )
    contract = GateIdentity(expected_head, expected_fingerprint, nonce)
    assert_gate_identity(repository, contract, collector=collector, stage="start")
    return contract


def assert_gate_identity(
    repository: Path,
    contract: GateIdentity,
    *,
    collector: IdentityCollector = _collect_worktree_identity,
    stage: str = "end",
) -> None:
    current = collector(repository.resolve())
    if (
        current.git_head != contract.git_head
        or current.content_fingerprint != contract.content_fingerprint
    ):
        if stage == "start":
            raise AcceptanceGateError("acceptance target does not match the expected identity")
        raise AcceptanceGateError("repository identity changed during acceptance")


def add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expected-git-head")
    parser.add_argument("--expected-content-fingerprint")
    parser.add_argument("--acceptance-run-nonce")


def _path_contains_symlink(path: Path) -> bool:
    candidate = path.absolute()
    for component in (candidate, *candidate.parents):
        try:
            if stat.S_ISLNK(component.lstat().st_mode):
                return True
        except FileNotFoundError:
            continue
        except OSError:
            return True
    return False


def _trusted_directory_descriptor(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        pinned = os.fstat(descriptor)
        current = path.stat()
        if (
            not stat.S_ISDIR(pinned.st_mode)
            or (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino)
            or (
                os.name == "posix"
                and (
                    pinned.st_uid != os.geteuid()  # type: ignore[attr-defined, unused-ignore]
                    or pinned.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                )
            )
        ):
            raise AcceptanceGateError("acceptance artifact directory is not private")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def atomic_write_bytes(path: Path, raw: bytes) -> None:
    """Durably publish bytes through a pinned directory without following symlinks."""
    path = path.absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    if _path_contains_symlink(path.parent):
        raise AcceptanceGateError("acceptance evidence path cannot contain a symlink")
    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_descriptor: int | None = None
    temporary_path = path.with_name(temporary_name)
    try:
        if os.name == "posix":
            directory_descriptor = _trusted_directory_descriptor(path.parent)
            try:
                destination = os.stat(path.name, dir_fd=directory_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                destination = None
            if destination is not None and stat.S_ISLNK(destination.st_mode):
                raise AcceptanceGateError("acceptance evidence destination cannot be a symlink")
            if destination is not None and not stat.S_ISREG(destination.st_mode):
                raise AcceptanceGateError("acceptance evidence destination is not a regular file")
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
        else:
            if path.is_symlink():
                raise AcceptanceGateError("acceptance evidence destination cannot be a symlink")
            descriptor = os.open(temporary_path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        if directory_descriptor is not None:
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            os.fsync(directory_descriptor)
        else:
            if path.is_symlink():
                raise AcceptanceGateError("acceptance evidence destination cannot be a symlink")
            os.replace(temporary_path, path)
    except (AcceptanceGateError, OSError):
        with suppress(OSError):
            if directory_descriptor is not None:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            else:
                temporary_path.unlink()
        raise
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def atomic_write_text(path: Path, content: str) -> None:
    atomic_write_bytes(path, content.encode("utf-8"))


def write_json_evidence(path: Path, payload: Mapping[str, object]) -> None:
    raw = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    atomic_write_bytes(path, raw)


def read_regular_file_nofollow(path: Path, *, maximum_bytes: int) -> bytes:
    if path.is_symlink() or _path_contains_symlink(path.parent):
        raise AcceptanceGateError("acceptance artifact path cannot contain a symlink")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AcceptanceGateError("acceptance artifact is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise AcceptanceGateError("acceptance artifact is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise AcceptanceGateError("acceptance artifact was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or os.read(descriptor, 1):
            raise AcceptanceGateError("acceptance artifact changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


@contextmanager
def private_artifact_directory(parent: Path, *, prefix: str) -> Iterator[Path]:
    parent.mkdir(parents=True, exist_ok=True)
    if _path_contains_symlink(parent):
        raise AcceptanceGateError("acceptance staging path cannot contain a symlink")
    directory = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    try:
        directory.chmod(0o700)
        metadata = directory.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or (os.name == "posix" and (metadata.st_mode & 0o777) != 0o700)
        ):
            raise AcceptanceGateError("acceptance staging directory is not private")
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def reserve_machine_report(path: Path) -> None:
    if os.name == "posix":
        parent = path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()  # type: ignore[attr-defined, unused-ignore]
            or (parent.st_mode & 0o777) != 0o700
        ):
            raise AcceptanceGateError("machine report parent must be private")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise AcceptanceGateError("machine report cannot be reserved exclusively") from exc
    try:
        if os.name == "posix":
            os.fchmod(  # type: ignore[attr-defined, unused-ignore]
                descriptor,
                0o600,
            )
    finally:
        os.close(descriptor)


def identity_from_arguments(repository: Path, arguments: argparse.Namespace) -> GateIdentity:
    return start_gate_identity(
        repository,
        expected_git_head=arguments.expected_git_head,
        expected_content_fingerprint=arguments.expected_content_fingerprint,
        run_nonce=arguments.acceptance_run_nonce,
    )


def sanitized_test_environment(
    source: Mapping[str, str] | None = None,
    *,
    overrides: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = dict(os.environ if source is None else source)
    original_path = environment.get("PATH")
    for name in tuple(environment):
        upper = name.upper()
        if upper in _UNTRUSTED_ENVIRONMENT_NAMES or upper.startswith(
            _UNTRUSTED_ENVIRONMENT_PREFIXES
        ):
            environment.pop(name, None)
    if os.name == "posix":
        environment["PATH"] = _SAFE_POSIX_PATH
    elif original_path is not None:
        environment["PATH"] = original_path
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if overrides:
        forbidden = [
            name
            for name in overrides
            if (
                name.upper() in _UNTRUSTED_ENVIRONMENT_NAMES
                or name.upper().startswith(_UNTRUSTED_ENVIRONMENT_PREFIXES)
            )
            and name.upper() not in _RUNNER_OWNED_ENVIRONMENT_OVERRIDES
        ]
        if forbidden:
            raise AcceptanceGateError("test control variables cannot be restored by overrides")
        environment.update(overrides)
    return environment


def discover_postgres_test_files(repository: Path) -> tuple[str, ...]:
    """Discover the explicit ``test_*_postgres.py`` acceptance contract."""
    repository = repository.resolve()
    tests = repository / "tests"
    if not tests.is_dir():
        raise AcceptanceGateError("tests directory is unavailable")
    discovered: list[str] = []
    for candidate in sorted(tests.glob("test_*_postgres.py")):
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise AcceptanceGateError(
                "PostgreSQL test discovery cannot inspect a candidate"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise AcceptanceGateError("PostgreSQL test discovery requires regular files")
        discovered.append(candidate.relative_to(repository).as_posix())
    if not discovered:
        raise AcceptanceGateError("no PostgreSQL acceptance tests were discovered")
    return tuple(discovered)


def validate_postgres_test_mapping(repository: Path, mapped: Sequence[str]) -> tuple[str, ...]:
    discovered = discover_postgres_test_files(repository)
    normalized = tuple(sorted(Path(item).as_posix() for item in mapped))
    if normalized != discovered or len(normalized) != len(set(normalized)):
        raise AcceptanceGateError("PostgreSQL acceptance mapping drift detected")
    return discovered


def _pytest_safety_arguments() -> tuple[str, ...]:
    return (
        "-p",
        "no:cacheprovider",
        "--override-ini=addopts=",
        "--override-ini=xfail_strict=true",
    )


def build_pytest_collection_command(command: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(
        token
        for token in command
        if token not in {"-q", "--quiet"} and not re.fullmatch(r"-q{2,}", token)
    )
    return (*normalized, *_pytest_safety_arguments(), "--collect-only", "-q")


def build_pytest_execution_command(command: Sequence[str], junit_path: Path) -> tuple[str, ...]:
    return (*command, *_pytest_safety_arguments(), f"--junitxml={junit_path}")


def _normalize_pytest_node_path(node_id: str) -> str:
    """Normalize only the filesystem portion of a pytest node ID.

    Parameter IDs may legitimately contain escaped backslashes such as ``\\n``,
    ``\\u`` and ``\\x``.  Treating the complete node ID as a path corrupts those
    identities and makes collection evidence disagree with pytest's JUnit output.
    """
    path, separator, remainder = node_id.partition(".py::")
    if not separator:
        return node_id
    normalized_path = path.replace("\\", "/")
    return f"{normalized_path}{separator}{remainder}"


def parse_pytest_collection(output: str) -> tuple[str, ...]:
    nodes = tuple(
        _normalize_pytest_node_path(line.strip())
        for line in output.splitlines()
        if ".py::" in line and line.lstrip().startswith(("tests/", "tests\\"))
    )
    match = _PYTEST_COLLECTION_SUMMARY.search(output)
    if match is None or int(match.group(1)) != len(nodes) or len(nodes) != len(set(nodes)):
        raise AcceptanceGateError("pytest collection output is incomplete or ambiguous")
    if not nodes:
        raise AcceptanceGateError("pytest did not collect any test nodes")
    return nodes


def _junit_key_for_node(node_id: str) -> tuple[str, str]:
    parts = _normalize_pytest_node_path(node_id).split("::")
    if len(parts) < 2 or not parts[0].endswith(".py"):
        raise AcceptanceGateError(f"invalid pytest node id: {node_id}")
    module = parts[0][:-3].replace("/", ".")
    classname = ".".join((module, *parts[1:-1]))
    return classname, parts[-1]


def _element_text(element: Any | None) -> str:
    if element is None:
        return ""
    return " ".join(
        (
            str(element.get("type") or ""),
            str(element.get("message") or ""),
            str(element.text or ""),
        )
    )


def parse_pytest_junit(report_path: Path, expected_nodes: Sequence[str]) -> PytestJUnitEvidence:
    raw = read_regular_file_nofollow(report_path, maximum_bytes=_MAX_JUNIT_BYTES)
    try:
        root = ET.fromstring(raw)
    except (SyntaxError, DefusedXmlException) as exc:
        raise AcceptanceGateError("pytest JUnit artifact is malformed") from exc

    expected = tuple(_normalize_pytest_node_path(node) for node in expected_nodes)
    if not expected or len(expected) != len(set(expected)):
        raise AcceptanceGateError("expected pytest nodes are empty or duplicated")
    key_to_node: dict[tuple[str, str], str] = {}
    for node in expected:
        key = _junit_key_for_node(node)
        if key in key_to_node:
            raise AcceptanceGateError("expected pytest nodes have ambiguous JUnit identities")
        key_to_node[key] = node

    actual_nodes: list[str] = []
    unexpected_nodes: list[str] = []
    passed = failed = errors = skipped = xfailed = xpassed = 0
    for case in root.iter("testcase"):
        classname = case.get("classname") or ""
        name = case.get("name") or ""
        actual_node = key_to_node.get((classname, name))
        if actual_node is None:
            actual_node = f"junit:{classname}::{name}"
            unexpected_nodes.append(actual_node)
        actual_nodes.append(actual_node)
        failure = case.find("failure")
        error = case.find("error")
        skipped_element = case.find("skipped")
        if failure is not None and "xpass" in _element_text(failure).lower():
            xpassed += 1
        elif failure is not None:
            failed += 1
        elif error is not None:
            errors += 1
        elif skipped_element is not None and "xfail" in _element_text(skipped_element).lower():
            xfailed += 1
        elif skipped_element is not None:
            skipped += 1
        else:
            passed += 1

    actual_set = set(actual_nodes)
    expected_set = set(expected)
    missing = tuple(sorted(expected_set - actual_set))
    unexpected = tuple(sorted(set(unexpected_nodes) | (actual_set - expected_set)))
    duplicate_count = len(actual_nodes) - len(actual_set)
    return PytestJUnitEvidence(
        collected=len(expected),
        executed=len(actual_nodes),
        passed=passed,
        failed=failed,
        errors=errors,
        skipped=skipped,
        xfailed=xfailed,
        xpassed=xpassed,
        deselected=len(missing),
        unexpected=len(unexpected) + duplicate_count,
        node_ids=tuple(actual_nodes),
        missing_node_ids=missing,
        unexpected_node_ids=unexpected,
        test_files=tuple(
            sorted({node.split("::", 1)[0] for node in actual_nodes if node.startswith("tests/")})
        ),
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
    )


def verify_file_artifact(path: Path, *, sha256: str, size: int) -> None:
    if (
        _SHA256_PATTERN.fullmatch(sha256) is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > _MAX_JUNIT_BYTES
    ):
        raise AcceptanceGateError("acceptance artifact contract is invalid")
    raw = read_regular_file_nofollow(path, maximum_bytes=_MAX_JUNIT_BYTES)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256:
        raise AcceptanceGateError("acceptance artifact digest mismatch")
