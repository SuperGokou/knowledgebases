from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _bootstrap_repository_import_path() -> None:
    if __package__ not in {None, ""}:
        return
    repository_root = str(Path(__file__).resolve().parents[1])
    if repository_root not in sys.path:
        sys.path.insert(0, repository_root)


_bootstrap_repository_import_path()

from scripts.acceptance_gate import (  # noqa: E402 - direct script bootstrap above
    AcceptanceGateError,
    GateIdentity,
    IdentityCollector,
    TrustedExecutableBinding,
    add_identity_arguments,
    assert_gate_identity,
    atomic_write_text,
    bind_trusted_executable,
    bind_trusted_executable_path,
    sanitized_test_environment,
    start_gate_identity,
)

Severity = Literal["P0", "P1", "P2"]
GateStatus = Literal["passed", "failed", "blocked"]
Verdict = Literal["PASS", "CONDITIONAL", "FAIL"]
Profile = Literal["local", "ci", "final"]
EvidenceKind = Literal["malware", "security-scan"]
OperationalEvidenceKind = Literal["capacity", "disaster-recovery"]
ChildEvidenceKind = Literal[
    "functional-acceptance",
    "postgres-acceptance",
    "backend-acceptance",
]

_SUMMARY_LIMIT = 4_096
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?im)^([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)=.*$"
)
_BEARER = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+")
_URL_PASSWORD = re.compile(r"(?P<prefix>\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@]+@", re.I)
_PRESIGNED_QUERY = re.compile(
    r"(?P<origin>https?://[^\s?]+)\?[^\s]*(?:X-Amz-(?:Signature|Credential)|Signature=)[^\s]*",
    re.I,
)
_DEFAULT_PLAYWRIGHT_ENTERPRISE_TEST_TIMEOUT_MS = 30 * 60_000
_MIN_PLAYWRIGHT_ENTERPRISE_TEST_TIMEOUT_MS = 60_000
_DEFAULT_BROWSER_E2E_SUITE_TIMEOUT_MS = 2 * 60 * 60_000
_MIN_BROWSER_E2E_SUITE_TIMEOUT_MS = 30 * 60_000
_MAX_BROWSER_E2E_SUITE_TIMEOUT_MS = 12 * 60 * 60_000
_BROWSER_E2E_GATE_GRACE_SECONDS = 60
_BROWSER_RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{8,80}\Z")
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
_BROWSER_E2E_TOPOLOGY_ENVIRONMENT = frozenset(
    {
        "KB_E2E_ADMIN_EMAIL",
        "KB_E2E_ADMIN_PASSWORD",
        "KB_E2E_BASE_URL",
        "KB_E2E_DOCUMENT_FIXTURE_MANIFEST",
        "KB_E2E_DOCUMENT_FIXTURE_ROOT",
        "KB_E2E_FAULT_CONTROL_ORIGIN",
        "KB_E2E_FAULT_CONTROL_TOKEN",
        "KB_E2E_JOB_TIMEOUT_MS",
        "KB_E2E_MULTIPART_BYTES",
        "KB_E2E_OBJECTS_ORIGIN",
        "KB_E2E_PUBLIC_API_ORIGIN",
        "KB_E2E_SEEDED_KNOWLEDGE_BASE_ID",
        "KB_E2E_SUITE_TIMEOUT_MS",
        "KB_E2E_TEST_TIMEOUT_MS",
        "KB_E2E_UNSCOPED_KNOWLEDGE_BASE_ID",
    }
)
_FORMAL_EVIDENCE_CONTRACTS: dict[EvidenceKind, dict[str, object]] = {
    "malware": {
        "id": "EXT-MALWARE-001",
        "evidence_schema_version": 2,
        "collector": {"id": "heyi-malware-acceptance", "version": "1.0.0"},
        "max_age_seconds": 24 * 60 * 60,
        "required_checks": [
            "clamav_database_preflight",
            "eicar_quarantined",
            "clean_file_released",
            "minio_scan_approval_download",
        ],
    },
    "security-scan": {
        "id": "EXT-SECURITY-SCAN-001",
        "evidence_schema_version": 2,
        "collector": {"id": "heyi-security-acceptance", "version": "1.0.0"},
        "max_age_seconds": 24 * 60 * 60,
        "required_checks": [
            "security_scan_complete",
            "no_open_critical",
            "no_open_high",
        ],
    },
}
_OPERATIONAL_RELEASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
_OPERATIONAL_EVIDENCE_CONTRACTS: dict[OperationalEvidenceKind, dict[str, object]] = {
    "capacity": {
        "kind": "enterprise-capacity",
        "classification": "combined_control_plane_and_real_model_capacity",
        "max_age": timedelta(hours=24),
        "artifact_ids": frozenset(
            {"control_plane_report", "real_model_benchmark", "provider_quota"}
        ),
    },
    "disaster-recovery": {
        "kind": "enterprise-disaster-recovery",
        "classification": "measured_full_restore_drill",
        "max_age": timedelta(days=30),
        "artifact_ids": frozenset(
            {
                "restore_drill_report",
                "database_integrity",
                "object_integrity",
                "functional_smoke",
            }
        ),
    },
}
_TARGET_TOKENS_PER_DAY = 5_000_000_000
_SECONDS_PER_DAY = 86_400
_MIN_CAPACITY_STEADY_SECONDS = 30 * 60
_MAX_CAPACITY_ERROR_RATE = 0.001
_MAX_DR_RPO_SECONDS = 15 * 60
_MAX_DR_RTO_SECONDS = 4 * 60 * 60
_MIN_DR_OBJECT_HASH_SAMPLES = 1_000
_EXPECTED_RESTORE_SCHEMA_HEAD = "20260715_0021"


@dataclass(frozen=True, slots=True)
class AcceptanceGate:
    gate_id: str
    severity: Severity
    command: tuple[str, ...]
    cwd: str
    timeout_seconds: int
    blocked_reason: str | None = None
    blocked_exit_codes: tuple[int, ...] = ()
    blocked_output_markers: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    required_regular_files: tuple[str, ...] = ()
    missing_executable_is_blocked: bool = False
    child_evidence_path: str | None = None
    child_evidence_kind: ChildEvidenceKind | None = None


@dataclass(frozen=True, slots=True)
class AcceptanceResult:
    gate_id: str
    severity: Severity
    status: GateStatus
    duration_seconds: float
    summary: str


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class WorktreeEvidence:
    git_head: str
    dirty: bool
    status_counts: dict[str, int]
    tracked_diff_sha256: str
    untracked_manifest_sha256: str
    content_fingerprint: str


@dataclass(frozen=True, slots=True)
class BrowserCollectionContract:
    expected_collected_tests: int
    required_projects: tuple[str, ...]
    required_test_titles: tuple[str, ...]


GateExecutor = Callable[[AcceptanceGate], CommandOutcome]
ResultObserver = Callable[[AcceptanceResult], None]

_MACHINE_EVIDENCE_PATHS: dict[ChildEvidenceKind, str] = {
    "functional-acceptance": "artifacts/acceptance/evidence/functional.json",
    "postgres-acceptance": "artifacts/acceptance/evidence/postgres.json",
    "backend-acceptance": "artifacts/acceptance/evidence/backend.json",
}
_OFFLINE_LOCK_DIRECTORY = Path("/run/heyi-kb-offline")
_OFFLINE_LOCK_PATH = _OFFLINE_LOCK_DIRECTORY / "heyi-kb-offline.preflight.lock"
_OFFLINE_LOCK_FD = 9
_OFFLINE_LOCK_TOKEN = "heyi-kb-offline-operation-v2"
_active_offline_lock_fd: int | None = None


def acquire_offline_acceptance_lock() -> int:
    """Acquire the deployment mutex once for the entire final acceptance lifecycle."""
    global _active_offline_lock_fd
    if (
        platform.system().casefold() != "linux"
        or os.name != "posix"
        or not hasattr(os, "geteuid")
        or os.geteuid() != 0
        or _active_offline_lock_fd is not None
    ):
        raise AcceptanceGateError("final deployment lock requires one root Linux controller")
    try:
        import fcntl

        if _OFFLINE_LOCK_DIRECTORY.is_symlink():
            raise AcceptanceGateError("offline lock directory cannot be a symlink")
        _OFFLINE_LOCK_DIRECTORY.mkdir(mode=0o700, parents=False, exist_ok=True)
        directory = _OFFLINE_LOCK_DIRECTORY.lstat()
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != 0
            or (directory.st_mode & 0o777) != 0o700
        ):
            raise AcceptanceGateError("offline lock directory is not root-protected 0700")
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(_OFFLINE_LOCK_PATH, flags, 0o600)
        try:
            os.fchmod(  # type: ignore[attr-defined, unused-ignore]
                descriptor,
                0o600,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or (metadata.st_mode & 0o777) != 0o600
                or metadata.st_nlink != 1
            ):
                raise AcceptanceGateError("offline deployment lock is not root-protected 0600")
            fcntl.flock(  # type: ignore[attr-defined, unused-ignore]
                descriptor,
                fcntl.LOCK_EX  # type: ignore[attr-defined, unused-ignore]
                | fcntl.LOCK_NB,  # type: ignore[attr-defined, unused-ignore]
            )
            if descriptor != _OFFLINE_LOCK_FD:
                os.dup2(descriptor, _OFFLINE_LOCK_FD, inheritable=True)
                os.close(descriptor)
                descriptor = _OFFLINE_LOCK_FD
            else:
                os.set_inheritable(descriptor, True)
            if Path(f"/proc/{os.getpid()}/fd/{descriptor}").resolve() != _OFFLINE_LOCK_PATH:
                raise AcceptanceGateError("offline deployment lock descriptor is not canonical")
        except Exception:
            with suppress(OSError):
                os.close(descriptor)
            raise
    except (BlockingIOError, OSError) as exc:
        raise AcceptanceGateError("another offline deployment operation holds the lock") from exc
    _active_offline_lock_fd = descriptor
    return descriptor


def release_offline_acceptance_lock(descriptor: int) -> None:
    global _active_offline_lock_fd
    if descriptor != _OFFLINE_LOCK_FD or _active_offline_lock_fd != descriptor:
        raise AcceptanceGateError("offline deployment lock release contract is invalid")
    try:
        import fcntl

        fcntl.flock(  # type: ignore[attr-defined, unused-ignore]
            descriptor,
            fcntl.LOCK_UN,  # type: ignore[attr-defined, unused-ignore]
        )
        os.close(descriptor)
    finally:
        _active_offline_lock_fd = None


def _identity_cli_arguments(identity: GateIdentity | None) -> tuple[str, ...]:
    if identity is None:
        return ()
    return (
        "--expected-git-head",
        identity.git_head,
        "--expected-content-fingerprint",
        identity.content_fingerprint,
        "--acceptance-run-nonce",
        identity.run_nonce,
    )


def _child_evidence_cli_arguments(
    identity: GateIdentity | None,
    kind: ChildEvidenceKind,
) -> tuple[str, ...]:
    if identity is None:
        return ()
    return (
        "--evidence-file",
        _MACHINE_EVIDENCE_PATHS[kind],
        *_identity_cli_arguments(identity),
    )


def calculate_verdict(results: Sequence[AcceptanceResult]) -> Verdict:
    if any(item.severity == "P0" and item.status != "passed" for item in results):
        return "FAIL"
    if any(item.severity == "P1" and item.status != "passed" for item in results):
        return "CONDITIONAL"
    return "PASS"


def redact_output(value: str) -> str:
    redacted = _BEARER.sub(r"\1[REDACTED]", value)
    redacted = _URL_PASSWORD.sub(r"\g<prefix>[REDACTED]@", redacted)
    redacted = _SENSITIVE_ASSIGNMENT.sub(r"\1=[REDACTED]", redacted)
    return _PRESIGNED_QUERY.sub(r"\g<origin>?[REDACTED]", redacted)


def _timeout_milliseconds(
    environment: Mapping[str, str | None],
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int | None = None,
) -> int:
    raw = environment.get(name)
    configured = raw.strip() if raw is not None else ""
    if not configured:
        return default
    if re.fullmatch(r"[0-9]+", configured) is None:
        raise ValueError(f"{name} must be an integer number of milliseconds")
    value = int(configured)
    if value < minimum or (maximum is not None and value > maximum):
        if maximum is None:
            raise ValueError(f"{name} must be at least {minimum} milliseconds")
        raise ValueError(f"{name} must be between {minimum} and {maximum} milliseconds")
    return value


def resolve_browser_e2e_suite_timeout_seconds(
    environment: Mapping[str, str | None] = os.environ,
) -> int:
    test_timeout_ms = _timeout_milliseconds(
        environment,
        "KB_E2E_TEST_TIMEOUT_MS",
        default=_DEFAULT_PLAYWRIGHT_ENTERPRISE_TEST_TIMEOUT_MS,
        minimum=_MIN_PLAYWRIGHT_ENTERPRISE_TEST_TIMEOUT_MS,
    )
    suite_timeout_ms = _timeout_milliseconds(
        environment,
        "KB_E2E_SUITE_TIMEOUT_MS",
        default=_DEFAULT_BROWSER_E2E_SUITE_TIMEOUT_MS,
        minimum=_MIN_BROWSER_E2E_SUITE_TIMEOUT_MS,
        maximum=_MAX_BROWSER_E2E_SUITE_TIMEOUT_MS,
    )
    if suite_timeout_ms < test_timeout_ms:
        raise ValueError("KB_E2E_SUITE_TIMEOUT_MS cannot be shorter than KB_E2E_TEST_TIMEOUT_MS")
    return (suite_timeout_ms + 999) // 1_000


def resolve_command(command: tuple[str, ...], *, search_path: str | None = None) -> tuple[str, ...]:
    if not command:
        return command
    executable = (
        shutil.which(command[0])
        if search_path is None
        else shutil.which(command[0], path=search_path)
    ) or command[0]
    return (executable, *command[1:])


def _root_protected_executable(command: tuple[str, ...]) -> tuple[str, ...]:
    if not command or os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return command
    candidate = Path(command[0])
    if not candidate.is_absolute():
        raise PermissionError("acceptance executable is not an absolute path")
    try:
        target = candidate.resolve(strict=True)
        target_metadata = target.stat()
    except OSError as exc:
        raise PermissionError("acceptance executable cannot be resolved") from exc
    if (
        not stat.S_ISREG(target_metadata.st_mode)
        or target_metadata.st_uid != 0
        or target_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise PermissionError("acceptance executable is not root protected")
    for ancestor in (target, *target.parents):
        metadata = ancestor.stat()
        if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError("acceptance executable path is not root protected")
    return command


def _bounded_summary(value: str) -> str:
    if len(value) <= _SUMMARY_LIMIT:
        return value
    marker = "[...earlier output truncated...]\n"
    return marker + value[-(_SUMMARY_LIMIT - len(marker)) :]


def execute_command(gate: AcceptanceGate) -> CommandOutcome:
    overrides = dict(gate.environment)
    pass_fds: tuple[int, ...] = ()
    if _active_offline_lock_fd == _OFFLINE_LOCK_FD:
        overrides["KB_OFFLINE_LOCK_HELD"] = _OFFLINE_LOCK_TOKEN
        pass_fds = (_OFFLINE_LOCK_FD,)
    environment = sanitized_test_environment(overrides=overrides)
    command = _root_protected_executable(
        resolve_command(gate.command, search_path=environment.get("PATH"))
    )
    completed = subprocess.run(  # noqa: S603
        list(command),
        cwd=gate.cwd,
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        env=environment,
        shell=False,
        timeout=gate.timeout_seconds,
        pass_fds=pass_fds,
    )
    return CommandOutcome(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def run_gate(
    gate: AcceptanceGate,
    *,
    executor: GateExecutor = execute_command,
) -> AcceptanceResult:
    started = time.monotonic()
    if gate.blocked_reason is not None:
        return AcceptanceResult(
            gate_id=gate.gate_id,
            severity=gate.severity,
            status="blocked",
            duration_seconds=0.0,
            summary=redact_output(gate.blocked_reason)[:_SUMMARY_LIMIT],
        )
    for raw_path in gate.required_regular_files:
        candidate = Path(raw_path)
        try:
            mode = candidate.lstat().st_mode
        except OSError:
            mode = 0
        if mode == 0 or stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            return AcceptanceResult(
                gate_id=gate.gate_id,
                severity=gate.severity,
                status="blocked",
                duration_seconds=time.monotonic() - started,
                summary="required target evidence is unavailable or is not a regular file",
            )
    try:
        outcome = executor(gate)
    except FileNotFoundError:
        return AcceptanceResult(
            gate_id=gate.gate_id,
            severity=gate.severity,
            status="blocked" if gate.missing_executable_is_blocked else "failed",
            duration_seconds=time.monotonic() - started,
            summary="command executable was not found",
        )
    except OSError:
        return AcceptanceResult(
            gate_id=gate.gate_id,
            severity=gate.severity,
            status="failed",
            duration_seconds=time.monotonic() - started,
            summary="command executable or environment failed safety validation",
        )
    except subprocess.TimeoutExpired:
        return AcceptanceResult(
            gate_id=gate.gate_id,
            severity=gate.severity,
            status="failed",
            duration_seconds=time.monotonic() - started,
            summary=f"command timed out after {gate.timeout_seconds} seconds",
        )
    combined = "\n".join(part for part in (outcome.stdout, outcome.stderr) if part).strip()
    summary = _bounded_summary(redact_output(combined or f"command exited {outcome.returncode}"))
    status: GateStatus
    if outcome.returncode == 0:
        status = "passed"
    elif outcome.returncode in gate.blocked_exit_codes or any(
        marker in combined for marker in gate.blocked_output_markers
    ):
        status = "blocked"
    else:
        status = "failed"
    return AcceptanceResult(
        gate_id=gate.gate_id,
        severity=gate.severity,
        status=status,
        duration_seconds=time.monotonic() - started,
        summary=summary,
    )


def _path_has_symlink(repository: Path, candidate: Path) -> bool:
    current = candidate
    while current != repository:
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                return True
        except OSError:
            return True
        parent = current.parent
        if parent == current:
            return True
        current = parent
    return False


def _read_bounded_regular_file(path: Path, *, maximum_bytes: int) -> bytes | None:
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum_bytes:
            return None
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    try:
        current = path.lstat()
    except OSError:
        return None
    identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if any(getattr(before, name) != getattr(after, name) for name in identity_fields):
        return None
    if any(getattr(after, name) != getattr(current, name) for name in identity_fields):
        return None
    if len(payload) != before.st_size or len(payload) > maximum_bytes:
        return None
    return payload


def verify_bound_child_evidence(
    gate: AcceptanceGate,
    *,
    repository: Path,
    identity: GateIdentity,
) -> tuple[bool, str]:
    """Verify a machine child result against the exact top-level acceptance target."""
    kind = gate.child_evidence_kind
    raw_path = gate.child_evidence_path
    failure = "machine child evidence is missing, unsafe, or does not match this acceptance run"
    if kind is None or raw_path is None:
        return False, failure
    expected_path = _MACHINE_EVIDENCE_PATHS.get(kind)
    if raw_path != expected_path:
        return False, failure
    repository = repository.resolve()
    candidate = repository / raw_path
    try:
        candidate.relative_to(repository)
    except ValueError:
        return False, failure
    if _path_has_symlink(repository, candidate):
        return False, failure
    payload = _read_bounded_regular_file(candidate, maximum_bytes=1024 * 1024)
    if payload is None:
        return False, failure
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False, failure
    if not isinstance(document, dict):
        return False, failure
    if (
        type(document.get("schema_version")) is not int
        or document.get("schema_version") != 2
        or document.get("kind") != kind
        or document.get("status") != "complete"
        or document.get("policy_status") != "passed"
        or document.get("target") != identity.target()
    ):
        return False, failure
    if kind == "functional-acceptance" and (
        document.get("verdict") != "PASS" or document.get("source_verdict") != "PASS"
    ):
        return False, failure
    return True, f"{kind} evidence verified for the exact acceptance target"


def _identity_failure(stage: str, started: float) -> AcceptanceResult:
    return AcceptanceResult(
        gate_id="ACCEPTANCE-IDENTITY-P0-001",
        severity="P0",
        status="failed",
        duration_seconds=time.monotonic() - started,
        summary=f"repository identity verification failed {stage}; acceptance stopped",
    )


def run_gates_bound_to_identity(
    gates: Sequence[AcceptanceGate],
    *,
    repository: Path,
    identity: GateIdentity,
    executor: GateExecutor = execute_command,
    identity_collector: IdentityCollector,
    on_result: ResultObserver | None = None,
) -> list[AcceptanceResult]:
    """Run gates only while the repository remains the exact accepted target."""
    results: list[AcceptanceResult] = []

    def verify(stage: str) -> bool:
        started = time.monotonic()
        try:
            assert_gate_identity(
                repository,
                identity,
                collector=identity_collector,
                stage=stage,
            )
        except (AcceptanceGateError, OSError, RuntimeError, UnicodeError):
            failure = _identity_failure(stage, started)
            results.append(failure)
            if on_result is not None:
                on_result(failure)
            return False
        return True

    for gate in gates:
        if not verify(f"before {gate.gate_id}"):
            return results
        result = run_gate(gate, executor=executor)
        if not verify(f"after {gate.gate_id}"):
            return results
        has_child_contract = (
            gate.child_evidence_path is not None or gate.child_evidence_kind is not None
        )
        if result.status == "passed" and has_child_contract:
            accepted, summary = verify_bound_child_evidence(
                gate,
                repository=repository,
                identity=identity,
            )
            if not accepted:
                failed_result = replace(result, status="failed", summary=summary)
                results.append(failed_result)
                if on_result is not None:
                    on_result(failed_result)
                return results
            if not verify(f"after {gate.gate_id} child evidence verification"):
                return results
            result = replace(result, summary=summary)
        results.append(result)
        if on_result is not None:
            on_result(result)

    verify("at final gate boundary")
    return results


def _browser_e2e_exit_code(outcome: CommandOutcome, *, evidence_verified: bool) -> int:
    if outcome.returncode != 0:
        combined = f"{outcome.stdout}\n{outcome.stderr}"
        return 2 if "E2E_BLOCKED" in combined else 1
    return 0 if evidence_verified else 2


def build_profile(
    profile: Profile,
    *,
    host_disk_path: str = "/srv",
    storage_object_root: str = "/srv/heyi-knowledgebases-offline/data/minio",
    host_io_evidence_path: str | None = None,
    storage_chain_evidence_path: str | None = None,
    offline_runtime_env_file: str | None = None,
    offline_release_env_file: str | None = None,
    offline_env_file: str | None = None,
    offline_image_manifest_path: str | None = None,
    offline_contract_dir: str | None = None,
    offline_contract_sha256: str | None = None,
    offline_contract_blocker: str | None = None,
    offline_runtime_evidence_path: str | None = None,
    e2e_evidence_path: str | None = None,
    functional_trust_store_path: str | None = None,
    functional_challenge_store_path: str | None = None,
    e2e_signing_key_path: str | None = None,
    e2e_signing_key_id: str | None = None,
    malware_evidence_path: str | None = None,
    security_scan_evidence_path: str | None = None,
    release_id: str | None = None,
    capacity_evidence_path: str | None = None,
    capacity_evidence_signature_path: str | None = None,
    capacity_evidence_public_key_path: str | None = None,
    disaster_recovery_evidence_path: str | None = None,
    disaster_recovery_evidence_signature_path: str | None = None,
    disaster_recovery_evidence_public_key_path: str | None = None,
    supply_chain_attestation_path: str | None = None,
    supply_chain_artifact_root: str | None = None,
    functional_node_binding: TrustedExecutableBinding | None = None,
    functional_node_blocker: str | None = None,
    acceptance_identity: GateIdentity | None = None,
) -> tuple[AcceptanceGate, ...]:
    repository = Path(__file__).resolve().parents[1]
    web = repository / "web"
    try:
        browser_e2e_suite_timeout_seconds = resolve_browser_e2e_suite_timeout_seconds()
        browser_e2e_timeout_blocker = None
    except ValueError:
        browser_e2e_suite_timeout_seconds = _DEFAULT_BROWSER_E2E_SUITE_TIMEOUT_MS // 1_000
        browser_e2e_timeout_blocker = "browser E2E timeout configuration is invalid"
    base = (
        AcceptanceGate(
            "CODE-P0-001",
            "P0",
            (sys.executable, "-m", "ruff", "check", "."),
            str(repository),
            120,
        ),
        AcceptanceGate(
            "FUNCTIONAL-P0-001",
            "P0",
            (
                sys.executable,
                str(repository / "scripts/functional_acceptance.py"),
                "--run-tests",
                "--json",
                *(
                    (
                        "--node-executable",
                        functional_node_binding.path,
                        "--node-executable-sha256",
                        functional_node_binding.sha256,
                        *(
                            ("--node-executable-require-root-owner",)
                            if functional_node_binding.require_root_owner
                            else ()
                        ),
                    )
                    if functional_node_binding is not None
                    else ()
                ),
                *_child_evidence_cli_arguments(
                    acceptance_identity,
                    "functional-acceptance",
                ),
            ),
            str(repository),
            900,
            blocked_reason=functional_node_blocker,
            child_evidence_path=(
                _MACHINE_EVIDENCE_PATHS["functional-acceptance"]
                if acceptance_identity is not None
                else None
            ),
            child_evidence_kind=(
                "functional-acceptance" if acceptance_identity is not None else None
            ),
        ),
        AcceptanceGate(
            "TYPE-P1-001",
            "P1",
            (sys.executable, "-m", "mypy", "app", "scripts"),
            str(repository),
            180,
        ),
        AcceptanceGate(
            "BACKEND-P0-001",
            "P0",
            (
                sys.executable,
                "-m",
                "pytest",
                "--cov=app",
                "--cov-report=term-missing",
                "--cov-fail-under=80",
            ),
            str(repository),
            600,
        ),
        AcceptanceGate(
            "FRONTEND-P0-001",
            "P0",
            ("npm", "test"),
            str(web),
            300,
        ),
        AcceptanceGate(
            "FRONTEND-P1-001",
            "P1",
            ("npm", "run", "lint"),
            str(web),
            300,
        ),
        AcceptanceGate(
            "BUILD-P0-001",
            "P0",
            ("npm", "run", "build"),
            str(web),
            600,
        ),
        AcceptanceGate(
            "OFFLINE-P0-001",
            "P0",
            (
                "docker",
                "compose",
                "--project-name",
                "heyi-kb-offline",
                "--env-file",
                str(repository / "deploy/tencent/offline.env.example"),
                "--env-file",
                str(repository / "deploy/tencent/release.env.example"),
                "--file",
                str(repository / "deploy/tencent/compose.offline.yml"),
                "--profile",
                "ops",
                "--profile",
                "maintenance",
                "config",
                "--quiet",
            ),
            str(repository),
            120,
        ),
        AcceptanceGate(
            "SERVER-P1-001",
            "P1",
            (),
            str(repository),
            1,
            blocked_reason=(
                "real 8 vCPU, 16 GB RAM, 300 GB SSD Linux target host is not available; "
                "the discovered host is below the required profile"
            ),
        ),
    )
    if profile == "local":
        return base
    format_gate = AcceptanceGate(
        "FORMAT-P0-001",
        "P0",
        (
            sys.executable,
            "-m",
            "app.document_parser_preflight",
            "--require-all",
        ),
        str(repository),
        60,
        blocked_exit_codes=(2,),
    )
    if profile == "ci":
        return (
            *(gate for gate in base if gate.gate_id != "SERVER-P1-001"),
            format_gate,
        )

    def missing_target_path(value: str | None, option: str) -> str | None:
        if value is None or not value.startswith("/"):
            return f"{option} must be an explicit absolute path on the target Linux host"
        return None

    host_evidence_blocker = missing_target_path(host_io_evidence_path, "--host-io-evidence")
    storage_evidence_blocker = missing_target_path(
        storage_chain_evidence_path, "--storage-chain-evidence"
    )
    offline_runtime_env_blocker = missing_target_path(
        offline_runtime_env_file, "--offline-runtime-env-file"
    )
    offline_release_env_blocker = missing_target_path(
        offline_release_env_file, "--offline-release-env-file"
    )
    deprecated_offline_env_blocker = (
        "--offline-env-file is deprecated and forbidden for the final profile; "
        "provide separate runtime and release environment files"
        if offline_env_file is not None
        else None
    )
    offline_environment_blocker = (
        deprecated_offline_env_blocker or offline_runtime_env_blocker or offline_release_env_blocker
    )
    derived_offline_manifest = (
        f"{offline_release_env_file}.images" if offline_release_env_file is not None else None
    )
    offline_manifest_blocker = (
        "--offline-image-manifest is not an independent input; it must exactly equal "
        "<offline-release-env-file>.images"
        if offline_image_manifest_path is not None
        and offline_image_manifest_path != derived_offline_manifest
        else None
    )
    offline_contract_path_blocker = missing_target_path(
        offline_contract_dir, "canonical offline contract snapshot"
    )
    offline_contract_digest_blocker = (
        None
        if offline_contract_sha256 is not None
        and re.fullmatch(r"[0-9a-f]{64}", offline_contract_sha256)
        else "canonical offline contract SHA-256 is unavailable or invalid"
    )
    offline_contract_gate_blocker = (
        offline_environment_blocker
        or offline_manifest_blocker
        or offline_contract_blocker
        or offline_contract_path_blocker
        or offline_contract_digest_blocker
    )
    offline_runtime_blocker = missing_target_path(
        offline_runtime_evidence_path, "--offline-runtime-evidence"
    )
    e2e_evidence_blocker = missing_target_path(e2e_evidence_path, "--e2e-evidence")
    trust_store_blocker = missing_target_path(
        functional_trust_store_path, "--functional-trust-store"
    )
    challenge_store_blocker = missing_target_path(
        functional_challenge_store_path, "--functional-challenge-store"
    )
    signing_key_blocker = missing_target_path(e2e_signing_key_path, "--e2e-signing-key-path")
    signing_key_id_blocker = (
        None
        if e2e_signing_key_id == "browser-e2e-ed25519"
        else "--e2e-signing-key-id must explicitly select browser-e2e-ed25519"
    )
    malware_evidence_blocker = missing_target_path(malware_evidence_path, "--malware-evidence")
    security_evidence_blocker = missing_target_path(
        security_scan_evidence_path, "--security-scan-evidence"
    )
    release_id_blocker = (
        None
        if release_id is not None and _OPERATIONAL_RELEASE_ID.fullmatch(release_id) is not None
        else "--release-id must be an explicit 1-80 character immutable release token"
    )
    capacity_evidence_blocker = missing_target_path(capacity_evidence_path, "--capacity-evidence")
    capacity_signature_blocker = missing_target_path(
        capacity_evidence_signature_path, "--capacity-evidence-signature"
    )
    capacity_public_key_blocker = missing_target_path(
        capacity_evidence_public_key_path, "--capacity-evidence-public-key"
    )
    disaster_recovery_evidence_blocker = missing_target_path(
        disaster_recovery_evidence_path, "--disaster-recovery-evidence"
    )
    disaster_recovery_signature_blocker = missing_target_path(
        disaster_recovery_evidence_signature_path,
        "--disaster-recovery-evidence-signature",
    )
    disaster_recovery_public_key_blocker = missing_target_path(
        disaster_recovery_evidence_public_key_path,
        "--disaster-recovery-evidence-public-key",
    )
    supply_chain_attestation_blocker = missing_target_path(
        supply_chain_attestation_path, "--supply-chain-attestation"
    )
    supply_chain_artifact_root_blocker = missing_target_path(
        supply_chain_artifact_root, "--supply-chain-artifact-root"
    )
    supply_chain_identity_blocker = (
        None
        if acceptance_identity is not None
        else "supply-chain release acceptance requires an immutable acceptance identity"
    )

    final_gates = (
        AcceptanceGate(
            "SUPPLY-CHAIN-P0-001",
            "P0",
            (
                sys.executable,
                str(repository / "scripts/supply_chain_gate.py"),
                "--repo",
                str(repository),
                "--mode",
                "release",
                "--attestation",
                supply_chain_attestation_path or "",
                "--artifact-root",
                supply_chain_artifact_root or "",
                "--expected-release-id",
                acceptance_identity.git_head if acceptance_identity is not None else "",
            ),
            str(repository),
            120,
            blocked_reason=(
                supply_chain_attestation_blocker
                or supply_chain_artifact_root_blocker
                or supply_chain_identity_blocker
            ),
            required_regular_files=(
                (supply_chain_attestation_path,) if supply_chain_attestation_path else ()
            ),
        ),
        AcceptanceGate(
            "HOST-P0-001",
            "P0",
            (
                sys.executable,
                "-m",
                "scripts.host_preflight",
                "--disk-path",
                host_disk_path,
                "--io-evidence",
                host_io_evidence_path or "",
            ),
            str(repository),
            30,
            blocked_reason=host_evidence_blocker,
            blocked_exit_codes=(2,),
            required_regular_files=(host_io_evidence_path,) if host_io_evidence_path else (),
        ),
        AcceptanceGate(
            "E2E-P0-001",
            "P0",
            (
                sys.executable,
                str(repository / "scripts/acceptance.py"),
                "--run-browser-e2e",
                "--e2e-evidence",
                e2e_evidence_path or "",
                "--functional-trust-store",
                functional_trust_store_path or "",
                "--functional-challenge-store",
                functional_challenge_store_path or "",
                "--e2e-signing-key-path",
                e2e_signing_key_path or "",
                "--e2e-signing-key-id",
                e2e_signing_key_id or "",
                *_identity_cli_arguments(acceptance_identity),
            ),
            str(repository),
            browser_e2e_suite_timeout_seconds + _BROWSER_E2E_GATE_GRACE_SECONDS,
            blocked_reason=(
                browser_e2e_timeout_blocker
                or e2e_evidence_blocker
                or trust_store_blocker
                or challenge_store_blocker
                or signing_key_blocker
                or signing_key_id_blocker
            ),
            blocked_exit_codes=(2,),
            required_regular_files=(
                (functional_trust_store_path, e2e_signing_key_path)
                if functional_trust_store_path and e2e_signing_key_path
                else ()
            ),
            environment=_browser_gate_environment(acceptance_identity),
        ),
        AcceptanceGate(
            "STORAGE-WATERMARK-P0-001",
            "P0",
            (
                sys.executable,
                "-m",
                "scripts.storage_watermark_preflight",
                "--object-root",
                storage_object_root,
                "--disk-path",
                host_disk_path,
                "--chain-evidence",
                storage_chain_evidence_path or "",
            ),
            str(repository),
            300,
            blocked_reason=storage_evidence_blocker,
            blocked_exit_codes=(2,),
            required_regular_files=(
                (storage_chain_evidence_path,) if storage_chain_evidence_path else ()
            ),
        ),
        AcceptanceGate(
            "CAPACITY-P0-001",
            "P0",
            (
                sys.executable,
                str(repository / "scripts/acceptance.py"),
                "--verify-operational-evidence",
                "capacity",
                "--evidence-file",
                capacity_evidence_path or "",
                "--evidence-signature",
                capacity_evidence_signature_path or "",
                "--evidence-public-key",
                capacity_evidence_public_key_path or "",
                "--release-id",
                release_id or "",
                *_identity_cli_arguments(acceptance_identity),
            ),
            str(repository),
            30,
            blocked_reason=(
                release_id_blocker
                or capacity_evidence_blocker
                or capacity_signature_blocker
                or capacity_public_key_blocker
            ),
            blocked_exit_codes=(2,),
            required_regular_files=(
                (
                    capacity_evidence_path,
                    capacity_evidence_signature_path,
                    capacity_evidence_public_key_path,
                )
                if capacity_evidence_path
                and capacity_evidence_signature_path
                and capacity_evidence_public_key_path
                else ()
            ),
        ),
        AcceptanceGate(
            "MALWARE-P0-001",
            "P0",
            (
                sys.executable,
                str(repository / "scripts/acceptance.py"),
                "--verify-evidence",
                "malware",
                "--evidence-file",
                malware_evidence_path or "",
                "--functional-trust-store",
                functional_trust_store_path or "",
                "--functional-challenge-store",
                functional_challenge_store_path or "",
                *_identity_cli_arguments(acceptance_identity),
            ),
            str(repository),
            30,
            blocked_reason=(
                malware_evidence_blocker or trust_store_blocker or challenge_store_blocker
            ),
            blocked_exit_codes=(2,),
            required_regular_files=(
                (malware_evidence_path, functional_trust_store_path)
                if malware_evidence_path and functional_trust_store_path
                else ()
            ),
        ),
        AcceptanceGate(
            "TOKEN-GOV-P0-001",
            "P0",
            (
                sys.executable,
                str(repository / "scripts/postgres_acceptance.py"),
                "--image",
                "postgres:17.5-bookworm",
                *_child_evidence_cli_arguments(
                    acceptance_identity,
                    "postgres-acceptance",
                ),
            ),
            str(repository),
            600,
            blocked_exit_codes=(2,),
            child_evidence_path=(
                _MACHINE_EVIDENCE_PATHS["postgres-acceptance"]
                if acceptance_identity is not None
                else None
            ),
            child_evidence_kind=(
                "postgres-acceptance" if acceptance_identity is not None else None
            ),
        ),
        AcceptanceGate(
            "DR-P0-001",
            "P0",
            (
                sys.executable,
                str(repository / "scripts/acceptance.py"),
                "--verify-operational-evidence",
                "disaster-recovery",
                "--evidence-file",
                disaster_recovery_evidence_path or "",
                "--evidence-signature",
                disaster_recovery_evidence_signature_path or "",
                "--evidence-public-key",
                disaster_recovery_evidence_public_key_path or "",
                "--release-id",
                release_id or "",
                *_identity_cli_arguments(acceptance_identity),
            ),
            str(repository),
            30,
            blocked_reason=(
                release_id_blocker
                or disaster_recovery_evidence_blocker
                or disaster_recovery_signature_blocker
                or disaster_recovery_public_key_blocker
            ),
            blocked_exit_codes=(2,),
            required_regular_files=(
                (
                    disaster_recovery_evidence_path,
                    disaster_recovery_evidence_signature_path,
                    disaster_recovery_evidence_public_key_path,
                )
                if disaster_recovery_evidence_path
                and disaster_recovery_evidence_signature_path
                and disaster_recovery_evidence_public_key_path
                else ()
            ),
        ),
        AcceptanceGate(
            "SECURITY-SCAN-P0-001",
            "P0",
            (
                sys.executable,
                str(repository / "scripts/acceptance.py"),
                "--verify-evidence",
                "security-scan",
                "--evidence-file",
                security_scan_evidence_path or "",
                "--functional-trust-store",
                functional_trust_store_path or "",
                "--functional-challenge-store",
                functional_challenge_store_path or "",
                *_identity_cli_arguments(acceptance_identity),
            ),
            str(repository),
            30,
            blocked_reason=(
                security_evidence_blocker or trust_store_blocker or challenge_store_blocker
            ),
            blocked_exit_codes=(2,),
            required_regular_files=(
                (security_scan_evidence_path, functional_trust_store_path)
                if security_scan_evidence_path and functional_trust_store_path
                else ()
            ),
        ),
        AcceptanceGate(
            "WORKTREE-P0-001",
            "P0",
            (
                sys.executable,
                str(repository / "scripts/acceptance.py"),
                "--verify-clean-worktree",
            ),
            str(repository),
            30,
            blocked_exit_codes=(2,),
        ),
    )
    final_base = (
        *(gate for gate in base if gate.gate_id != "SERVER-P1-001"),
        format_gate,
    )
    target_offline_gate = AcceptanceGate(
        "OFFLINE-P0-001",
        "P0",
        (
            "sh",
            str(repository / "deploy/tencent/preflight-offline.sh"),
            "--upgrade",
            "--contract-dir",
            offline_contract_dir or "",
            "--contract-sha256",
            offline_contract_sha256 or "",
        ),
        str(repository),
        300,
        blocked_reason=offline_contract_gate_blocker,
        blocked_exit_codes=(66, 77),
        required_regular_files=(
            (
                f"{offline_contract_dir}/runtime.env",
                f"{offline_contract_dir}/release.env",
                f"{offline_contract_dir}/release.env.images",
                f"{offline_contract_dir}/contract.sha256",
            )
            if offline_contract_dir
            else ()
        ),
        missing_executable_is_blocked=True,
    )
    target_offline_images_gate = AcceptanceGate(
        "OFFLINE-IMAGES-P0-001",
        "P0",
        (
            "sh",
            str(repository / "deploy/tencent/verify-offline-images.sh"),
            "verify",
            "--contract-dir",
            offline_contract_dir or "",
            "--contract-sha256",
            offline_contract_sha256 or "",
        ),
        str(repository),
        300,
        blocked_reason=offline_contract_gate_blocker,
        blocked_exit_codes=(66,),
        required_regular_files=(
            (
                f"{offline_contract_dir}/runtime.env",
                f"{offline_contract_dir}/release.env",
                f"{offline_contract_dir}/release.env.images",
                f"{offline_contract_dir}/contract.sha256",
            )
            if offline_contract_dir
            else ()
        ),
        missing_executable_is_blocked=True,
    )
    target_offline_runtime_gate = AcceptanceGate(
        "OFFLINE-RUNTIME-P0-001",
        "P0",
        (
            sys.executable,
            str(repository / "scripts/acceptance.py"),
            "--verify-offline-runtime-evidence",
            "--evidence-file",
            offline_runtime_evidence_path or "",
        ),
        str(repository),
        30,
        blocked_reason=offline_runtime_blocker,
        blocked_exit_codes=(2,),
        required_regular_files=(
            (offline_runtime_evidence_path,) if offline_runtime_evidence_path else ()
        ),
    )
    target_backend_gate = AcceptanceGate(
        "BACKEND-P0-001",
        "P0",
        (
            sys.executable,
            str(repository / "scripts/backend_acceptance.py"),
            "--postgres-evidence",
            "artifacts/acceptance/evidence/postgres.json",
            *_child_evidence_cli_arguments(
                acceptance_identity,
                "backend-acceptance",
            ),
        ),
        str(repository),
        600,
        blocked_exit_codes=(2,),
        child_evidence_path=(
            _MACHINE_EVIDENCE_PATHS["backend-acceptance"]
            if acceptance_identity is not None
            else None
        ),
        child_evidence_kind=("backend-acceptance" if acceptance_identity is not None else None),
    )
    final_base = tuple(
        target_offline_gate
        if gate.gate_id == "OFFLINE-P0-001"
        else target_backend_gate
        if gate.gate_id == "BACKEND-P0-001"
        else gate
        for gate in final_base
    )
    token_gate = next(gate for gate in final_gates if gate.gate_id == "TOKEN-GOV-P0-001")
    supply_chain_gate = next(gate for gate in final_gates if gate.gate_id == "SUPPLY-CHAIN-P0-001")
    final_base_without_backend = tuple(
        gate for gate in final_base if gate.gate_id != "BACKEND-P0-001"
    )
    remaining_final_gates = tuple(
        gate
        for gate in final_gates
        if gate.gate_id not in {"SUPPLY-CHAIN-P0-001", "TOKEN-GOV-P0-001"}
    )
    final_base_with_supply_chain = tuple(
        candidate
        for gate in final_base_without_backend
        for candidate in ((gate, supply_chain_gate) if gate.gate_id == "CODE-P0-001" else (gate,))
    )
    return (
        *final_base_with_supply_chain,
        target_offline_images_gate,
        target_offline_runtime_gate,
        token_gate,
        target_backend_gate,
        *remaining_final_gates,
    )


def _atomic_write(path: Path, content: str) -> None:
    atomic_write_text(path, content)


def _git_output(repository: Path, *arguments: str) -> bytes:
    completed = subprocess.run(  # noqa: S603
        ["git", *arguments],
        cwd=repository,
        capture_output=True,
        check=False,
        shell=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError("git worktree evidence could not be collected")
    return completed.stdout


def _status_counts(raw_status: bytes) -> dict[str, int]:
    records = raw_status.split(b"\0")
    counts = {"total": 0, "staged": 0, "unstaged": 0, "untracked": 0, "conflicts": 0}
    conflicts = {b"DD", b"AU", b"UD", b"UA", b"DU", b"AA", b"UU"}
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if len(record) < 3:
            continue
        status = record[:2]
        counts["total"] += 1
        if status == b"??":
            counts["untracked"] += 1
        else:
            if status[:1] != b" ":
                counts["staged"] += 1
            if status[1:2] != b" ":
                counts["unstaged"] += 1
            if status in conflicts:
                counts["conflicts"] += 1
        if b"R" in status or b"C" in status:
            index += 1
    return counts


def _hash_file(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.digest()


def _untracked_manifest_hash(repository: Path) -> str:
    raw_paths = _git_output(repository, "ls-files", "--others", "--exclude-standard", "-z")
    digest = hashlib.sha256()
    for raw_path in sorted(item for item in raw_paths.split(b"\0") if item):
        relative = Path(os.fsdecode(raw_path))
        candidate = repository / relative
        digest.update(len(raw_path).to_bytes(8, "big"))
        digest.update(raw_path)
        if candidate.is_symlink():
            target = os.fsencode(os.readlink(candidate))
            digest.update(b"symlink\0")
            digest.update(hashlib.sha256(target).digest())
        elif candidate.is_file():
            digest.update(b"file\0")
            digest.update(_hash_file(candidate))
        else:
            digest.update(b"special\0")
    return digest.hexdigest()


def collect_worktree_evidence(repository: Path) -> WorktreeEvidence:
    repository = repository.resolve()
    git_head = _git_output(repository, "rev-parse", "HEAD").decode("ascii").strip()
    raw_status = _git_output(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    )
    counts = _status_counts(raw_status)
    tracked_diff_hash = hashlib.sha256(
        _git_output(repository, "diff", "--binary", "HEAD", "--", ".")
    ).hexdigest()
    untracked_hash = _untracked_manifest_hash(repository)
    fingerprint = hashlib.sha256(
        "\0".join((git_head, tracked_diff_hash, untracked_hash)).encode("ascii")
    ).hexdigest()
    return WorktreeEvidence(
        git_head=git_head,
        dirty=counts["total"] > 0,
        status_counts=counts,
        tracked_diff_sha256=tracked_diff_hash,
        untracked_manifest_sha256=untracked_hash,
        content_fingerprint=fingerprint,
    )


def initialize_acceptance_identity(repository: Path) -> tuple[WorktreeEvidence, GateIdentity]:
    """Capture and immediately re-verify the immutable top-level acceptance target."""
    snapshot = collect_worktree_evidence(repository)
    identity = start_gate_identity(
        repository,
        expected_git_head=snapshot.git_head,
        expected_content_fingerprint=snapshot.content_fingerprint,
        run_nonce=secrets.token_hex(16),
        collector=cast(IdentityCollector, collect_worktree_evidence),
    )
    return snapshot, identity


def _load_evidence_document(evidence_file: Path) -> dict[str, object] | None:
    try:
        if evidence_file.stat().st_size > 1024 * 1024:
            return None
        value = json.loads(evidence_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _artifact_matches(
    evidence_file: Path,
    value: object,
) -> bool:
    if not isinstance(value, dict):
        return False
    relative_name = value.get("artifact")
    expected_hash = value.get("sha256")
    if not isinstance(relative_name, str) or not isinstance(expected_hash, str):
        return False
    if re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None:
        return False
    relative_path = Path(relative_name)
    if relative_path.is_absolute():
        return False
    root = evidence_file.parent.resolve()
    unresolved = root
    for part in relative_path.parts:
        unresolved /= part
        if unresolved.is_symlink():
            return False
    try:
        artifact = unresolved.resolve(strict=True)
        artifact.relative_to(root)
    except (OSError, ValueError):
        return False
    if not artifact.is_file():
        return False
    return _hash_file(artifact).hex() == expected_hash


def _target_matches(document: dict[str, object], identity: WorktreeEvidence) -> bool:
    target = document.get("target")
    return bool(
        isinstance(target, dict)
        and target.get("git_head") == identity.git_head
        and target.get("content_fingerprint") == identity.content_fingerprint
    )


def _formal_signature_payload(
    document: Mapping[str, object],
    *,
    key_id: str,
    challenge_id: str,
    challenge_nonce: str,
) -> bytes:
    signed_document = {key: value for key, value in document.items() if key != "attestation"}
    encoded_document = json.dumps(
        signed_document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload = {
        "evidence_sha256": hashlib.sha256(encoded_document).hexdigest(),
        "key_id": key_id,
        "challenge_id": challenge_id,
        "challenge_nonce": challenge_nonce,
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def verify_formal_evidence(
    kind: EvidenceKind,
    evidence_file: Path,
    repository: Path,
    *,
    identity: GateIdentity | None = None,
    trust_context: object | None = None,
    require_protected_evidence: bool = True,
) -> tuple[bool, str]:
    display_kind = "security scan" if kind == "security-scan" else kind
    failure = (
        f"{display_kind} evidence is unsigned, replayed, incomplete, or does not match "
        "this acceptance run"
    )
    if identity is None or trust_context is None:
        return False, failure
    if require_protected_evidence and (
        platform.system().casefold() != "linux"
        or not _protected_regular_file(evidence_file, maximum_bytes=1024 * 1024)
    ):
        return False, failure
    document = _load_evidence_document(evidence_file)
    if document is None:
        return False, failure
    target = document.get("target")
    contract = _FORMAL_EVIDENCE_CONTRACTS[kind]
    expected_run_id = f"acceptance-{identity.run_nonce}"
    if (
        document.get("schema_version") != 2
        or document.get("evidence_id") != contract["id"]
        or document.get("kind") != kind
        or document.get("status") != "complete"
        or not isinstance(target, dict)
        or set(target) != {"git_head", "content_fingerprint", "run_id"}
        or target.get("git_head") != identity.git_head
        or target.get("content_fingerprint") != identity.content_fingerprint
        or target.get("run_id") != expected_run_id
    ):
        return False, failure

    if kind == "malware":
        # The default verification path above requires a protected evidence file
        # on Linux. Signed collector identity and the complete malware chain
        # remain enforced by the formal-evidence contract below; target.os is
        # therefore excluded from the canonical run binding as redundant.
        success = "malware target-host evidence verified (4/4 checks)"
    else:
        summary = document.get("summary")
        count_names = ("open_critical", "open_high", "open_medium", "open_low")
        if (
            document.get("policy_status") != "passed"
            or not isinstance(summary, dict)
            or any(
                not isinstance(summary.get(name), int)
                or isinstance(summary.get(name), bool)
                or int(summary[name]) < 0
                for name in count_names
            )
            or summary.get("open_critical") != 0
            or summary.get("open_high") != 0
        ):
            return False, failure
        success = "signed complete security scan report verified for this acceptance run"

    try:
        from scripts.functional_acceptance import (
            ExternalTrustContext,
            _validate_external_provenance,
        )
    except (ImportError, RuntimeError):
        return False, failure
    if not isinstance(trust_context, ExternalTrustContext):
        return False, failure
    if not _validate_external_provenance(
        repository.resolve(),
        evidence_file,
        contract,
        document,
        policy=None,
        trust_context=trust_context,
        signature_payload_builder=_formal_signature_payload,
    ):
        return False, failure
    return True, success


def verify_browser_e2e_evidence(
    evidence_file: Path,
    trust_store: Path,
    challenge_store: Path,
    repository: Path,
    *,
    expected_key_id: str,
    expected_run_id: str,
) -> tuple[bool, str]:
    failure = "browser E2E evidence is untrusted, invalid, or already consumed"
    try:
        from scripts.functional_acceptance import (
            ContractError,
            load_external_trust_context,
        )

        trust_context = load_external_trust_context(
            repository.resolve(strict=True), trust_store, challenge_store
        )
    except (ContractError, OSError, RuntimeError, UnicodeError, ValueError):
        return False, failure
    if _verify_browser_e2e_document(
        evidence_file,
        repository,
        expected_key_id=expected_key_id,
        expected_run_id=expected_run_id,
        trust_context=trust_context,
    ):
        return True, "signed browser E2E evidence verified and challenge consumed"
    return False, failure


def _verify_browser_e2e_document(
    evidence_file: Path,
    repository: Path,
    *,
    expected_key_id: str,
    expected_run_id: str,
    trust_context: object,
) -> bool:
    document = _load_evidence_document(evidence_file)
    attestation = document.get("attestation") if document is not None else None
    target = document.get("target") if document is not None else None
    if not (
        document is not None
        and document.get("evidence_id") == "EXT-BROWSER-E2E-001"
        and isinstance(attestation, dict)
        and attestation.get("type") == "ed25519-challenge-v1"
        and attestation.get("key_id") == expected_key_id
        and isinstance(target, dict)
        and target.get("run_id") == expected_run_id
        and set(target) == {"git_head", "content_fingerprint", "run_id"}
    ):
        return False
    try:
        from scripts.functional_acceptance import (
            ContractError,
            ExternalTrustContext,
            _trusted_policy,
            _validate_external_provenance,
            load_manifest,
        )

        repository = repository.resolve(strict=True)
        manifest = load_manifest(repository / "docs/functional_acceptance_manifest.json")
        entries = manifest.get("external_evidence")
        if not isinstance(entries, list):
            return False
        browser_entries = [
            dict(item)
            for item in entries
            if isinstance(item, dict) and item.get("id") == "EXT-BROWSER-E2E-001"
        ]
        if len(browser_entries) != 1:
            return False
        policy = _trusted_policy(repository, manifest, required=True)
        accepted = _validate_external_provenance(
            repository,
            evidence_file.resolve(strict=True),
            browser_entries[0],
            document,
            policy=policy,
            trust_context=cast(ExternalTrustContext, trust_context),
        )
    except (ContractError, OSError, RuntimeError, UnicodeError, ValueError):
        return False
    return accepted


def _browser_challenge_path(
    repository: Path,
    trust_store: Path,
    challenge_store: Path,
    *,
    expected_identity: GateIdentity,
    expected_run_id: str,
) -> Path | None:
    try:
        from scripts.functional_acceptance import (
            ContractError,
            load_external_trust_context,
        )

        context = load_external_trust_context(repository, trust_store, challenge_store)
    except (ContractError, OSError, RuntimeError, UnicodeError, ValueError):
        return None
    challenge_ids = [
        challenge_id
        for challenge_id, value in context.challenges.items()
        if value.get("evidence_id") == "EXT-BROWSER-E2E-001"
        and value.get("status") == "issued"
        and value.get("target")
        == {
            "git_head": expected_identity.git_head,
            "content_fingerprint": expected_identity.content_fingerprint,
            "run_id": expected_run_id,
        }
        and challenge_id in context.challenge_paths
    ]
    if len(challenge_ids) != 1:
        return None
    return context.challenge_paths[challenge_ids[0]]


def _browser_collection_contract(repository: Path) -> BrowserCollectionContract:
    from scripts.functional_acceptance import (
        ContractError,
        _trusted_policy,
        load_manifest,
    )

    repository = repository.resolve(strict=True)
    manifest = load_manifest(repository / "docs/functional_acceptance_manifest.json")
    policy = _trusted_policy(repository, manifest, required=True)
    if policy is None:
        raise ContractError("trusted browser collection policy is unavailable")
    external = manifest.get("external_evidence")
    collections = policy.get("external_test_collections")
    if not isinstance(external, list) or not isinstance(collections, dict):
        raise ContractError("trusted browser collection policy is invalid")
    browser_entries = [
        item
        for item in external
        if isinstance(item, dict) and item.get("id") == "EXT-BROWSER-E2E-001"
    ]
    expected = collections.get("EXT-BROWSER-E2E-001")
    if len(browser_entries) != 1 or not isinstance(expected, dict):
        raise ContractError("trusted browser collection policy is incomplete")
    actual = browser_entries[0].get("collection")
    total = expected.get("expected_collected_tests")
    projects = expected.get("required_projects")
    titles = expected.get("required_test_titles")
    if (
        actual != expected
        or not isinstance(total, int)
        or isinstance(total, bool)
        or total <= 0
        or not isinstance(projects, list)
        or not projects
        or not all(isinstance(value, str) and value for value in projects)
        or len(projects) != len(set(projects))
        or not isinstance(titles, list)
        or not titles
        or not all(isinstance(value, str) and value for value in titles)
        or len(titles) != len(set(titles))
    ):
        raise ContractError("trusted browser collection policy is malformed")
    return BrowserCollectionContract(total, tuple(projects), tuple(titles))


def verify_browser_e2e_collection(
    output: str, contract: BrowserCollectionContract
) -> tuple[bool, str]:
    clean = _ANSI_ESCAPE.sub("", output)
    total_matches = re.findall(
        r"(?m)^Total:\s+(\d+)\s+tests?\s+in\s+\d+\s+files?\s*$",
        clean,
    )
    listed: list[tuple[str, str]] = []
    for line in clean.splitlines():
        match = re.match(r"^\s*\[([^\]]+)\]\s+›\s+(.+?)\s*$", line)
        if match is not None:
            listed.append((match.group(1), match.group(2)))
    expected = contract.expected_collected_tests
    if (
        total_matches != [str(expected)]
        or len(listed) != expected
        or len(listed) != len(set(listed))
        or {project for project, _ in listed} != set(contract.required_projects)
    ):
        return False, "browser E2E collection does not match the trusted exact test contract"
    for project in contract.required_projects:
        for title in contract.required_test_titles:
            matches = [
                case
                for candidate_project, case in listed
                if candidate_project == project and case.endswith(title)
            ]
            if len(matches) != 1:
                return False, "browser E2E collection is missing or duplicating a required scenario"
    return True, f"browser E2E collection verified exactly ({expected} test instances)"


def _browser_gate_environment(identity: GateIdentity | None) -> tuple[tuple[str, str], ...]:
    values = {
        name: value
        for name in sorted(_BROWSER_E2E_TOPOLOGY_ENVIRONMENT)
        if (value := os.environ.get(name)) is not None
    }
    if identity is not None:
        values["KB_E2E_RUN_ID"] = f"acceptance-{identity.run_nonce}"
    return tuple(sorted(values.items()))


def run_browser_e2e(
    *,
    repository: Path,
    evidence_file: Path,
    trust_store: Path,
    challenge_store: Path,
    signing_key: Path,
    signing_key_id: str,
    identity: GateIdentity | None = None,
    identity_collector: IdentityCollector | None = None,
) -> tuple[int, str]:
    failure = "browser E2E target trust material or signed evidence is unavailable"
    try:
        suite_timeout_seconds = resolve_browser_e2e_suite_timeout_seconds()
    except ValueError:
        return 2, "browser E2E timeout configuration is invalid"
    if (
        identity is None
        or platform.system().casefold() != "linux"
        or signing_key_id != "browser-e2e-ed25519"
        or not _protected_regular_file(signing_key, maximum_bytes=64 * 1024)  # gitleaks:allow
    ):
        return 2, failure
    try:
        signing_key.resolve(strict=True).relative_to(repository.resolve(strict=True))
    except ValueError:
        pass
    except OSError:
        return 2, failure
    else:
        return 2, failure
    run_id = f"acceptance-{identity.run_nonce}"
    if _BROWSER_RUN_ID_PATTERN.fullmatch(run_id) is None:
        return 2, failure
    try:
        collection_contract = _browser_collection_contract(repository)
    except (ImportError, OSError, RuntimeError, UnicodeError, ValueError):
        return 2, failure
    challenge_path = _browser_challenge_path(
        repository,
        trust_store,
        challenge_store,
        expected_identity=identity,
        expected_run_id=run_id,
    )
    if challenge_path is None:
        return 2, failure
    overrides = {
        name: value
        for name in _BROWSER_E2E_TOPOLOGY_ENVIRONMENT
        if (value := os.environ.get(name)) is not None
    }
    overrides.update(
        {
            "KB_E2E_PROFILE": "enterprise",
            "KB_E2E_EVIDENCE_PATH": str(evidence_file),
            "KB_E2E_SIGNING_KEY_PATH": str(signing_key),
            "KB_E2E_SIGNING_KEY_ID": signing_key_id,
            "KB_E2E_CHALLENGE_PATH": str(challenge_path),
            "KB_E2E_RUN_ID": run_id,
        }
    )
    try:
        environment = sanitized_test_environment(overrides=overrides)
    except AcceptanceGateError:
        return 2, failure
    collector = identity_collector or cast(IdentityCollector, collect_worktree_evidence)
    try:
        assert_gate_identity(
            repository,
            identity,
            collector=collector,
            stage="before E2E collection",
        )
    except (AcceptanceGateError, OSError, RuntimeError, UnicodeError):
        return 2, "repository identity changed before browser E2E collection"
    command = _root_protected_executable(
        resolve_command(("npm", "run", "test:e2e"), search_path=environment.get("PATH"))
    )
    try:
        collected = subprocess.run(  # noqa: S603
            [*command, "--", "--list"],
            cwd=repository / "web",
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="replace",
            env=environment,
            shell=False,
            timeout=min(300, suite_timeout_seconds),
        )
        assert_gate_identity(
            repository,
            identity,
            collector=collector,
            stage="after E2E collection",
        )
        collection_ok, collection_summary = verify_browser_e2e_collection(
            f"{collected.stdout}\n{collected.stderr}", collection_contract
        )
        if collected.returncode != 0 or not collection_ok:
            return 2, collection_summary
        completed = subprocess.run(  # noqa: S603
            list(command),
            cwd=repository / "web",
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="replace",
            env=environment,
            shell=False,
            timeout=suite_timeout_seconds,
        )
        assert_gate_identity(
            repository,
            identity,
            collector=collector,
            stage="after E2E execution",
        )
    except (
        AcceptanceGateError,
        FileNotFoundError,
        OSError,
        RuntimeError,
        UnicodeError,
        subprocess.TimeoutExpired,
    ):
        return 2, failure
    outcome = CommandOutcome(completed.returncode, completed.stdout, completed.stderr)
    if outcome.returncode != 0:
        exit_code = _browser_e2e_exit_code(outcome, evidence_verified=False)
        summary = (
            "enterprise browser topology or evidence prerequisites were blocked"
            if exit_code == 2
            else "enterprise browser tests failed; child-process logs were not copied"
        )
        return exit_code, summary
    verified, summary = verify_browser_e2e_evidence(
        evidence_file,
        trust_store,
        challenge_store,
        repository,
        expected_key_id=signing_key_id,
        expected_run_id=run_id,
    )
    try:
        assert_gate_identity(
            repository,
            identity,
            collector=collector,
            stage="after E2E evidence verification",
        )
    except (AcceptanceGateError, OSError, RuntimeError, UnicodeError):
        return 2, "repository identity changed during browser E2E acceptance"
    return _browser_e2e_exit_code(outcome, evidence_verified=verified), summary


_OFFLINE_RUNTIME_CHECKS = frozenset(
    {
        "offline_network_isolation",
        "cold_start",
        "login",
        "rbac",
        "acl",
        "upload",
        "approval",
        "download",
        "question_answer",
        "restart_persistence",
        "network_recovery",
    }
)
_OFFLINE_RUNTIME_KEYS = frozenset(
    {
        "schema_version",
        "evidence_id",
        "status",
        "result",
        "runner",
        "collector",
        "collected_at",
        "challenge",
        "test_tenant",
        "target",
        "checks",
        "artifacts",
        "result_sha256",
        "attestation",
    }
)


def _canonical_digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()


def _offline_runtime_host_fingerprint() -> str:
    machine_id = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    material = "\0".join(
        (
            machine_id,
            boot_id,
            platform.node(),
            platform.release(),
            platform.machine(),
            str(os.stat("/").st_dev),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _protected_regular_file(path: Path, *, maximum_bytes: int) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or not 0 < metadata.st_size <= maximum_bytes
    ):
        return False
    return not (
        os.name == "posix"
        and (metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    )


def _read_operational_evidence_file(
    path: Path,
    *,
    maximum_bytes: int,
    require_protected: bool,
) -> bytes:
    if require_protected:
        absolute = path.absolute()
        for component in (absolute, *absolute.parents):
            try:
                if stat.S_ISLNK(component.lstat().st_mode):
                    raise ValueError("operational evidence path contains a symbolic link")
            except FileNotFoundError:
                continue
    if require_protected and (
        platform.system().casefold() != "linux"
        or not _protected_regular_file(path, maximum_bytes=maximum_bytes)
    ):
        raise ValueError("operational evidence file is not root-protected")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= maximum_bytes
        ):
            raise ValueError("operational evidence file metadata is invalid")
        if require_protected and (
            metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError("operational evidence file permissions are invalid")
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            block = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        if not payload or len(payload) > maximum_bytes or len(payload) != metadata.st_size:
            raise ValueError("operational evidence file size changed during verification")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _strict_json_object(payload: bytes, *, label: str) -> dict[str, object]:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _exact_object(
    value: object,
    *,
    label: str,
    keys: frozenset[str],
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} schema is invalid")
    return cast(dict[str, object], value)


def _finite_number(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{label} must be finite")
    return result


def _positive_integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _utc_timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must use UTC")
    return parsed.astimezone(UTC)


def _operational_artifacts(
    evidence_file: Path,
    document: Mapping[str, object],
    *,
    expected_ids: frozenset[str],
    require_protected: bool,
) -> dict[str, dict[str, object]]:
    values = document.get("artifacts")
    if not isinstance(values, list) or len(values) != len(expected_ids):
        raise ValueError("operational evidence artifact inventory is incomplete")
    root = evidence_file.parent.resolve(strict=True)
    artifacts: dict[str, dict[str, object]] = {}
    descriptor_keys = frozenset({"id", "path", "sha256", "bytes"})
    for raw_descriptor in values:
        descriptor = _exact_object(
            raw_descriptor,
            label="operational artifact descriptor",
            keys=descriptor_keys,
        )
        artifact_id = descriptor.get("id")
        relative_name = descriptor.get("path")
        digest = descriptor.get("sha256")
        expected_bytes = descriptor.get("bytes")
        if (
            not isinstance(artifact_id, str)
            or artifact_id not in expected_ids
            or artifact_id in artifacts
            or not isinstance(relative_name, str)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or isinstance(expected_bytes, bool)
            or not isinstance(expected_bytes, int)
            or not 0 < expected_bytes <= 8 * 1024 * 1024
        ):
            raise ValueError("operational artifact descriptor values are invalid")
        relative = Path(relative_name)
        if (
            relative.is_absolute()
            or relative.as_posix() != relative_name
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("operational artifact path is unsafe")
        unresolved = evidence_file.parent / relative
        cursor = evidence_file.parent
        for part in relative.parts:
            cursor /= part
            if cursor.is_symlink():
                raise ValueError("operational artifact path contains a symbolic link")
        try:
            artifact_path = unresolved.resolve(strict=True)
            artifact_path.relative_to(root)
        except (OSError, ValueError) as exc:
            raise ValueError("operational artifact escapes its evidence root") from exc
        payload = _read_operational_evidence_file(
            artifact_path,
            maximum_bytes=8 * 1024 * 1024,
            require_protected=require_protected,
        )
        if len(payload) != expected_bytes or not secrets.compare_digest(
            hashlib.sha256(payload).hexdigest(), digest
        ):
            raise ValueError("operational artifact digest or byte count differs")
        artifacts[artifact_id] = _strict_json_object(
            payload,
            label=f"operational artifact {artifact_id}",
        )
    if set(artifacts) != expected_ids:
        raise ValueError("operational artifact ids are incomplete")
    return artifacts


def _validate_capacity_evidence(
    artifacts: Mapping[str, Mapping[str, object]],
    *,
    identity: GateIdentity,
    now: datetime,
) -> None:
    control_plane = artifacts["control_plane_report"]
    checks = control_plane.get("checks")
    claims = control_plane.get("capacity_claims")
    control_binding = control_plane.get("evidence_binding")
    if not (
        control_plane.get("schema_version") == 1
        and control_plane.get("evidence_classification") == "not_model_capacity"
        and control_plane.get("verdict") == "PASS_CONTROL_PLANE"
        and control_plane.get("control_plane_passed") is True
        and isinstance(control_binding, dict)
        and control_binding.get("git_commit") == identity.git_head
        and isinstance(checks, list)
        and checks
        and all(isinstance(item, dict) and item.get("passed") is True for item in checks)
        and isinstance(claims, dict)
        and claims.get("llm_stub_path") in {"MEASURED_STUB_ONLY", "NOT_RUN"}
        and isinstance(claims.get("five_billion_tokens_per_day"), dict)
        and cast(dict[str, object], claims["five_billion_tokens_per_day"]).get("status")
        == "UNVERIFIED_NO_GO"
    ):
        raise ValueError("control-plane capacity evidence is invalid or overclaims model capacity")

    benchmark = _exact_object(
        artifacts["real_model_benchmark"],
        label="real-model benchmark",
        keys=frozenset(
            {
                "schema_version",
                "kind",
                "status",
                "classification",
                "collected_at",
                "traffic",
                "measurements",
                "quality",
            }
        ),
    )
    collected_at = _utc_timestamp(benchmark.get("collected_at"), label="benchmark.collected_at")
    traffic = _exact_object(
        benchmark.get("traffic"),
        label="benchmark.traffic",
        keys=frozenset(
            {
                "mode",
                "response_source",
                "provider_id",
                "model_id",
                "stub_used",
                "synthetic_responses",
                "identities",
            }
        ),
    )
    measurements = _exact_object(
        benchmark.get("measurements"),
        label="benchmark.measurements",
        keys=frozenset(
            {
                "steady_duration_seconds",
                "measured_output_tokens",
                "sustained_output_tokens_per_second",
                "projected_tokens_per_day",
                "error_rate",
            }
        ),
    )
    quality = _exact_object(
        benchmark.get("quality"),
        label="benchmark.quality",
        keys=frozenset({"independent_review_passed", "output_content_logged"}),
    )
    duration = _finite_number(
        measurements.get("steady_duration_seconds"),
        label="benchmark.steady_duration_seconds",
    )
    measured_tokens = _positive_integer(
        measurements.get("measured_output_tokens"),
        label="benchmark.measured_output_tokens",
    )
    sustained_tps = _finite_number(
        measurements.get("sustained_output_tokens_per_second"),
        label="benchmark.sustained_output_tokens_per_second",
    )
    projected_daily = _finite_number(
        measurements.get("projected_tokens_per_day"),
        label="benchmark.projected_tokens_per_day",
    )
    error_rate = _finite_number(measurements.get("error_rate"), label="benchmark.error_rate")
    required_tps = _TARGET_TOKENS_PER_DAY / _SECONDS_PER_DAY
    measured_tps = measured_tokens / duration if duration > 0 else 0.0
    if not (
        benchmark.get("schema_version") == 1
        and benchmark.get("kind") == "enterprise-real-model-benchmark"
        and benchmark.get("status") == "passed"
        and benchmark.get("classification") == "measured_real_model_capacity"
        and now - timedelta(hours=24) <= collected_at <= now + timedelta(minutes=5)
        and traffic.get("mode") == "real_model"
        and traffic.get("response_source")
        in {"approved_external_provider", "private_inference_cluster"}
        and traffic.get("stub_used") is False
        and traffic.get("synthetic_responses") is False
        and _positive_integer(traffic.get("identities"), label="benchmark.identities") >= 1_000
        and duration >= _MIN_CAPACITY_STEADY_SECONDS
        and measured_tps >= required_tps
        and sustained_tps >= required_tps
        and sustained_tps <= measured_tps * 1.001
        and projected_daily >= _TARGET_TOKENS_PER_DAY
        and projected_daily <= measured_tps * _SECONDS_PER_DAY * 1.001
        and 0 <= error_rate <= _MAX_CAPACITY_ERROR_RATE
        and quality.get("independent_review_passed") is True
        and quality.get("output_content_logged") is False
    ):
        raise ValueError("real-model benchmark does not prove the required sustained capacity")

    provider = _exact_object(
        artifacts["provider_quota"],
        label="provider capacity",
        keys=frozenset(
            {
                "schema_version",
                "kind",
                "status",
                "verified_at",
                "provider_type",
                "provider_id",
                "model_id",
                "quota_tokens_per_day",
                "cost_model_verified",
                "data_residency_reviewed",
                "secret_material_included",
            }
        ),
    )
    verified_at = _utc_timestamp(provider.get("verified_at"), label="provider.verified_at")
    provider_id = provider.get("provider_id")
    model_id = provider.get("model_id")
    traffic_provider_id = traffic.get("provider_id")
    traffic_model_id = traffic.get("model_id")
    if not (
        provider.get("schema_version") == 1
        and provider.get("kind") == "enterprise-provider-capacity"
        and provider.get("status") == "verified"
        and now - timedelta(hours=24) <= verified_at <= now + timedelta(minutes=5)
        and provider.get("provider_type")
        in {"approved_external_provider", "private_inference_cluster"}
        and provider.get("provider_type") == traffic.get("response_source")
        and isinstance(provider_id, str)
        and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", provider_id) is not None
        and traffic_provider_id == provider_id
        and isinstance(model_id, str)
        and re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", model_id) is not None
        and traffic_model_id == model_id
        and _positive_integer(
            provider.get("quota_tokens_per_day"), label="provider.quota_tokens_per_day"
        )
        >= _TARGET_TOKENS_PER_DAY
        and provider.get("cost_model_verified") is True
        and provider.get("data_residency_reviewed") is True
        and provider.get("secret_material_included") is False
    ):
        raise ValueError("provider quota, cost, or residency evidence is incomplete")


def _validate_disaster_recovery_evidence(
    artifacts: Mapping[str, Mapping[str, object]],
    *,
    now: datetime,
) -> None:
    drill = _exact_object(
        artifacts["restore_drill_report"],
        label="restore drill",
        keys=frozenset(
            {
                "schema_version",
                "kind",
                "status",
                "started_at",
                "completed_at",
                "source_latest_commit_at",
                "restored_latest_commit_at",
                "rpo_seconds",
                "rto_seconds",
                "actual_restore",
                "simulation",
                "fresh_isolated_host",
                "source_backup_independent",
                "pitr_restored",
                "object_versioning_or_replication_verified",
            }
        ),
    )
    started_at = _utc_timestamp(drill.get("started_at"), label="restore.started_at")
    completed_at = _utc_timestamp(drill.get("completed_at"), label="restore.completed_at")
    source_commit = _utc_timestamp(
        drill.get("source_latest_commit_at"), label="restore.source_latest_commit_at"
    )
    restored_commit = _utc_timestamp(
        drill.get("restored_latest_commit_at"), label="restore.restored_latest_commit_at"
    )
    rpo_seconds = _finite_number(drill.get("rpo_seconds"), label="restore.rpo_seconds")
    rto_seconds = _finite_number(drill.get("rto_seconds"), label="restore.rto_seconds")
    measured_rto = (completed_at - started_at).total_seconds()
    measured_rpo = (source_commit - restored_commit).total_seconds()
    if not (
        drill.get("schema_version") == 1
        and drill.get("kind") == "enterprise-full-restore-drill"
        and drill.get("status") == "passed"
        and now - timedelta(days=30) <= completed_at <= now + timedelta(minutes=5)
        and restored_commit <= source_commit <= started_at <= completed_at
        and 0 < measured_rto <= _MAX_DR_RTO_SECONDS
        and 0 <= measured_rpo <= _MAX_DR_RPO_SECONDS
        and 0 <= rpo_seconds <= _MAX_DR_RPO_SECONDS
        and 0 < rto_seconds <= _MAX_DR_RTO_SECONDS
        and abs(measured_rpo - rpo_seconds) <= 5
        and abs(measured_rto - rto_seconds) <= 5
        and drill.get("actual_restore") is True
        and drill.get("simulation") is False
        and drill.get("fresh_isolated_host") is True
        and drill.get("source_backup_independent") is True
        and drill.get("pitr_restored") is True
        and drill.get("object_versioning_or_replication_verified") is True
    ):
        raise ValueError("restore drill does not satisfy the measured RPO/RTO contract")

    database = _exact_object(
        artifacts["database_integrity"],
        label="restored database integrity",
        keys=frozenset(
            {
                "schema_version",
                "kind",
                "status",
                "source_schema_head",
                "restored_schema_head",
                "source_table_count",
                "restored_table_count",
                "source_row_count",
                "restored_row_count",
                "checksums_match",
            }
        ),
    )
    source_schema = database.get("source_schema_head")
    restored_schema = database.get("restored_schema_head")
    source_tables = _positive_integer(
        database.get("source_table_count"), label="database.source_table_count"
    )
    restored_tables = _positive_integer(
        database.get("restored_table_count"), label="database.restored_table_count"
    )
    source_rows = _positive_integer(
        database.get("source_row_count"), label="database.source_row_count"
    )
    restored_rows = _positive_integer(
        database.get("restored_row_count"), label="database.restored_row_count"
    )
    if not (
        database.get("schema_version") == 1
        and database.get("kind") == "enterprise-restore-database-integrity"
        and database.get("status") == "passed"
        and isinstance(source_schema, str)
        and re.fullmatch(r"[0-9]{8}_[0-9]{4}", source_schema) is not None
        and source_schema == _EXPECTED_RESTORE_SCHEMA_HEAD
        and restored_schema == source_schema
        and restored_tables == source_tables
        and restored_rows == source_rows
        and database.get("checksums_match") is True
    ):
        raise ValueError("restored database integrity evidence differs from its source")

    objects = _exact_object(
        artifacts["object_integrity"],
        label="restored object integrity",
        keys=frozenset(
            {
                "schema_version",
                "kind",
                "status",
                "source_object_count",
                "restored_object_count",
                "sampled_object_count",
                "hash_match_count",
                "hash_match_rate",
                "manifest_sha256",
                "samples",
            }
        ),
    )
    source_objects = _positive_integer(
        objects.get("source_object_count"), label="objects.source_object_count"
    )
    restored_objects = _positive_integer(
        objects.get("restored_object_count"), label="objects.restored_object_count"
    )
    samples = _positive_integer(
        objects.get("sampled_object_count"), label="objects.sampled_object_count"
    )
    matches = _positive_integer(objects.get("hash_match_count"), label="objects.hash_match_count")
    match_rate = _finite_number(objects.get("hash_match_rate"), label="objects.hash_match_rate")
    manifest_sha256 = objects.get("manifest_sha256")
    raw_samples = objects.get("samples")
    if not isinstance(raw_samples, list) or len(raw_samples) != samples:
        raise ValueError("restored object sample inventory is incomplete")
    sample_ids: set[str] = set()
    for raw_sample in raw_samples:
        sample = _exact_object(
            raw_sample,
            label="restored object sample",
            keys=frozenset({"object_id_sha256", "source_sha256", "restored_sha256"}),
        )
        object_id = sample.get("object_id_sha256")
        source_digest = sample.get("source_sha256")
        restored_digest = sample.get("restored_sha256")
        if not (
            isinstance(object_id, str)
            and re.fullmatch(r"[0-9a-f]{64}", object_id) is not None
            and object_id not in sample_ids
            and isinstance(source_digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", source_digest) is not None
            and isinstance(restored_digest, str)
            and secrets.compare_digest(source_digest, restored_digest)
        ):
            raise ValueError("restored object sample hash differs")
        sample_ids.add(object_id)
    sample_manifest = hashlib.sha256(
        json.dumps(
            raw_samples,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if not (
        objects.get("schema_version") == 1
        and objects.get("kind") == "enterprise-restore-object-integrity"
        and objects.get("status") == "passed"
        and restored_objects == source_objects
        and samples >= _MIN_DR_OBJECT_HASH_SAMPLES
        and samples <= source_objects
        and matches == samples
        and match_rate == 1.0
        and isinstance(manifest_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is not None
        and secrets.compare_digest(manifest_sha256, sample_manifest)
    ):
        raise ValueError("restored object hash evidence is incomplete")

    smoke = _exact_object(
        artifacts["functional_smoke"],
        label="restored functional smoke",
        keys=frozenset(
            {
                "schema_version",
                "kind",
                "status",
                "login_passed",
                "search_passed",
                "download_passed",
                "citations_passed",
                "secret_material_included",
            }
        ),
    )
    if not (
        smoke.get("schema_version") == 1
        and smoke.get("kind") == "enterprise-restored-functional-smoke"
        and smoke.get("status") == "passed"
        and smoke.get("login_passed") is True
        and smoke.get("search_passed") is True
        and smoke.get("download_passed") is True
        and smoke.get("citations_passed") is True
        and smoke.get("secret_material_included") is False
    ):
        raise ValueError("restored functional smoke evidence is incomplete")


def verify_signed_operational_evidence(
    kind: OperationalEvidenceKind,
    evidence_file: Path,
    signature_file: Path,
    public_key_file: Path,
    *,
    identity: GateIdentity,
    release_id: str,
    require_protected_files: bool = True,
    now: datetime | None = None,
) -> tuple[bool, str]:
    display = "capacity" if kind == "capacity" else "disaster-recovery"
    failure = (
        f"signed {display} evidence is absent, stale, malformed, stub-only, or does not "
        "match this Git HEAD and release"
    )
    try:
        if _OPERATIONAL_RELEASE_ID.fullmatch(release_id) is None:
            raise ValueError("release id is invalid")
        if require_protected_files:
            trusted_key = public_key_file.resolve(strict=True)
            evidence_root = evidence_file.parent.resolve(strict=True)
            repository_root = Path(__file__).resolve().parents[1]
            if trusted_key.is_relative_to(evidence_root) or trusted_key.is_relative_to(
                repository_root
            ):
                raise ValueError("operational evidence public key is not an independent trust root")
        evidence_payload = _read_operational_evidence_file(
            evidence_file,
            maximum_bytes=1024 * 1024,
            require_protected=require_protected_files,
        )
        signature_payload = _read_operational_evidence_file(
            signature_file,
            maximum_bytes=128,
            require_protected=require_protected_files,
        )
        public_key_payload = _read_operational_evidence_file(
            public_key_file,
            maximum_bytes=16 * 1024,
            require_protected=require_protected_files,
        )
        if len(signature_payload) != 64:
            raise ValueError("detached Ed25519 signature must be exactly 64 bytes")
        loaded_key = serialization.load_pem_public_key(public_key_payload)
        if not isinstance(loaded_key, Ed25519PublicKey):
            raise ValueError("operational evidence requires an Ed25519 public key")
        loaded_key.verify(signature_payload, evidence_payload)
        document = _strict_json_object(evidence_payload, label="operational evidence")
        contract = _OPERATIONAL_EVIDENCE_CONTRACTS[kind]
        if set(document) != {
            "schema_version",
            "kind",
            "status",
            "evidence_classification",
            "issued_at",
            "expires_at",
            "target",
            "signing_key_sha256",
            "artifacts",
        }:
            raise ValueError("operational evidence envelope schema differs")
        target = _exact_object(
            document.get("target"),
            label="operational evidence target",
            keys=frozenset({"git_head", "content_fingerprint", "release_id"}),
        )
        current = (now or datetime.now(UTC)).astimezone(UTC)
        issued_at = _utc_timestamp(document.get("issued_at"), label="evidence.issued_at")
        expires_at = _utc_timestamp(document.get("expires_at"), label="evidence.expires_at")
        max_age = cast(timedelta, contract["max_age"])
        public_der = loaded_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if not (
            document.get("schema_version") == 1
            and document.get("kind") == contract["kind"]
            and document.get("status") == "complete"
            and document.get("evidence_classification") == contract["classification"]
            and current - max_age <= issued_at <= current + timedelta(minutes=5)
            and current < expires_at <= issued_at + max_age
            and target.get("git_head") == identity.git_head
            and target.get("content_fingerprint") == identity.content_fingerprint
            and target.get("release_id") == release_id
            and document.get("signing_key_sha256") == hashlib.sha256(public_der).hexdigest()
        ):
            raise ValueError("operational evidence envelope identity or freshness differs")
        artifacts = _operational_artifacts(
            evidence_file,
            document,
            expected_ids=cast(frozenset[str], contract["artifact_ids"]),
            require_protected=require_protected_files,
        )
        if kind == "capacity":
            _validate_capacity_evidence(artifacts, identity=identity, now=current)
        else:
            _validate_disaster_recovery_evidence(artifacts, now=current)
    except (
        InvalidSignature,
        KeyError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
    ):
        return False, failure
    if kind == "capacity":
        return True, "signed control-plane plus non-stub real-model capacity evidence verified"
    return True, "signed full-restore RPO/RTO and data-integrity evidence verified"


def verify_offline_runtime_evidence(
    evidence_file: Path,
    repository: Path,
) -> tuple[bool, str]:
    failure = "offline runtime evidence is incomplete or does not match this target"
    if platform.system().casefold() != "linux" or not _protected_regular_file(
        evidence_file, maximum_bytes=1024 * 1024
    ):
        return False, failure
    document = _load_evidence_document(evidence_file)
    if document is None or set(document) != _OFFLINE_RUNTIME_KEYS:
        return False, failure
    try:
        identity = collect_worktree_evidence(repository)
        active_host_fingerprint = _offline_runtime_host_fingerprint()
        collected_at_raw = document.get("collected_at")
        if not isinstance(collected_at_raw, str):
            return False, failure
        collected_at = datetime.fromisoformat(collected_at_raw.replace("Z", "+00:00"))
        now = datetime.now(UTC)
        if (
            collected_at.tzinfo is None
            or collected_at > now + timedelta(minutes=5)
            or collected_at < now - timedelta(hours=24)
        ):
            return False, failure
    except (OSError, RuntimeError, UnicodeError, ValueError):
        return False, failure

    collector = document.get("collector")
    target = document.get("target")
    checks = document.get("checks")
    artifacts = document.get("artifacts")
    challenge = document.get("challenge")
    tenant = document.get("test_tenant")
    if not (
        document.get("schema_version") == 1
        and document.get("evidence_id") == "EXT-OFFLINE-RUNTIME-001"
        and document.get("status") == "complete"
        and document.get("result") == "passed"
        and document.get("runner") == "subprocess-v1"
        and collector == {"id": "heyi-offline-runtime", "version": "1.0.0"}
        and isinstance(challenge, str)
        and re.fullmatch(r"[A-Za-z0-9_-]{24,128}", challenge) is not None
        and isinstance(tenant, str)
        and re.fullmatch(r"kb-acceptance-[a-z0-9-]{1,48}", tenant) is not None
        and isinstance(target, dict)
        and set(target)
        == {
            "git_head",
            "content_fingerprint",
            "host_fingerprint",
            "project_name",
            "egress_mode",
        }
        and target.get("git_head") == identity.git_head
        and target.get("content_fingerprint") == identity.content_fingerprint
        and target.get("host_fingerprint") == active_host_fingerprint
        and target.get("project_name") == "heyi-kb-offline"
        and target.get("egress_mode") in {"strict_offline", "controlled_gateway"}
        and isinstance(checks, dict)
        and set(checks) == _OFFLINE_RUNTIME_CHECKS
        and isinstance(artifacts, list)
        and 1 <= len(artifacts) <= 256
    ):
        return False, failure

    artifact_ids: set[str] = set()
    root = evidence_file.parent.resolve()
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"id", "path", "sha256", "bytes"}:
            return False, failure
        artifact_id = item.get("id")
        relative_name = item.get("path")
        expected_hash = item.get("sha256")
        expected_bytes = item.get("bytes")
        if not (
            isinstance(artifact_id, str)
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", artifact_id) is not None
            and artifact_id not in artifact_ids
            and isinstance(relative_name, str)
            and re.fullmatch(r"raw/[0-9]{3}-[A-Za-z0-9_.-]+\.json", relative_name) is not None
            and isinstance(expected_hash, str)
            and re.fullmatch(r"[0-9a-f]{64}", expected_hash) is not None
            and isinstance(expected_bytes, int)
            and 1 <= expected_bytes <= 1024 * 1024
        ):
            return False, failure
        artifact_ids.add(artifact_id)
        unresolved = evidence_file.parent / relative_name
        if any(part.is_symlink() for part in [unresolved.parent, unresolved]):
            return False, failure
        try:
            artifact = unresolved.resolve(strict=True)
            artifact.relative_to(root)
        except (OSError, ValueError):
            return False, failure
        if not _protected_regular_file(artifact, maximum_bytes=1024 * 1024):
            return False, failure
        if artifact.stat().st_size != expected_bytes or _hash_file(artifact).hex() != expected_hash:
            return False, failure

    for value in checks.values():
        if not isinstance(value, dict) or set(value) != {"status", "artifact_ids"}:
            return False, failure
        references = value.get("artifact_ids")
        if not (
            value.get("status") == "passed"
            and isinstance(references, list)
            and references
            and all(isinstance(item, str) and item in artifact_ids for item in references)
        ):
            return False, failure

    expected_result_hash = _canonical_digest(
        {"target": target, "checks": checks, "artifacts": artifacts}
    )
    attestation = document.get("attestation")
    unsigned_document = dict(document)
    unsigned_document.pop("attestation", None)
    if not (
        document.get("result_sha256") == expected_result_hash
        and isinstance(attestation, dict)
        and attestation
        == {"type": "sha256-chain-v1", "digest": _canonical_digest(unsigned_document)}
    ):
        return False, failure
    return True, "offline runtime target evidence verified"


def write_reports(
    results: Sequence[AcceptanceResult],
    *,
    report_dir: Path,
    profile: str,
    revision: str,
    repository: Path,
    acceptance_identity: GateIdentity | None = None,
) -> tuple[Path, Path]:
    safe_results = [replace(item, summary=redact_output(item.summary)) for item in results]
    verdict = calculate_verdict(safe_results)
    try:
        worktree = collect_worktree_evidence(repository)
    except (OSError, RuntimeError, UnicodeError):
        empty_hash = hashlib.sha256(b"").hexdigest()
        worktree = WorktreeEvidence(
            git_head=revision if re.fullmatch(r"[0-9a-f]{40,64}", revision) else "unknown",
            dirty=True,
            status_counts={
                "total": -1,
                "staged": -1,
                "unstaged": -1,
                "untracked": -1,
                "conflicts": -1,
            },
            tracked_diff_sha256=empty_hash,
            untracked_manifest_sha256=empty_hash,
            content_fingerprint=empty_hash,
        )
    identity_verified = bool(
        acceptance_identity is not None
        and worktree.git_head == acceptance_identity.git_head
        and worktree.content_fingerprint == acceptance_identity.content_fingerprint
    )
    if profile == "final" and (worktree.dirty or not identity_verified):
        verdict = "FAIL"
    generated_at = datetime.now(UTC).isoformat()
    evidence_class = (
        "final_signoff_candidate" if profile == "final" else "development_smoke_not_for_signoff"
    )
    payload = {
        "schema_version": 2,
        "generated_at": generated_at,
        "profile": profile,
        "evidence_class": evidence_class,
        "revision": worktree.git_head,
        "target": acceptance_identity.target() if acceptance_identity is not None else None,
        "identity_verified": identity_verified,
        "worktree": asdict(worktree),
        "verdict": verdict,
        "results": [asdict(item) for item in safe_results],
    }
    json_path = report_dir / "acceptance.json"
    markdown_path = report_dir / "acceptance.md"
    _atomic_write(json_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    rows = [
        "# Enterprise Acceptance Evidence",
        "",
        (
            "> **FINAL SIGN-OFF CANDIDATE**"
            if profile == "final"
            else "> **NON-SIGNING DEVELOPMENT SMOKE** — not valid as delivery approval evidence."
        ),
        ("> **DIRTY WORKTREE: NOT SIGNABLE**" if profile == "final" and worktree.dirty else ""),
        "",
        f"- Generated: `{generated_at}`",
        f"- Revision: `{worktree.git_head}`",
        f"- Profile: `{profile}`",
        f"- Worktree dirty: `{str(worktree.dirty).lower()}`",
        f"- Tracked diff SHA-256: `{worktree.tracked_diff_sha256}`",
        f"- Untracked manifest SHA-256: `{worktree.untracked_manifest_sha256}`",
        f"- Content fingerprint: `{worktree.content_fingerprint}`",
        (
            f"- Acceptance run nonce: `{acceptance_identity.run_nonce}`"
            if acceptance_identity is not None
            else "- Acceptance run nonce: `unavailable`"
        ),
        f"- Identity verified: `{str(identity_verified).lower()}`",
        f"- Verdict: **{verdict}**",
        "",
        "| Gate | Severity | Status | Duration | Summary |",
        "|---|---|---|---:|---|",
    ]
    for item in safe_results:
        summary = item.summary.replace("|", "\\|").replace("\r", " ").replace("\n", " ")
        rows.append(
            f"| `{item.gate_id}` | {item.severity} | {item.status} | "
            f"{item.duration_seconds:.2f}s | {summary} |"
        )
    _atomic_write(markdown_path, "\n".join(rows) + "\n")
    return json_path, markdown_path


def _revision(repository: Path) -> str:
    completed = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def _create_offline_contract(
    repository: Path,
    *,
    runtime_env_file: str,
    release_env_file: str,
) -> tuple[str, str]:
    if _active_offline_lock_fd != _OFFLINE_LOCK_FD:
        raise AcceptanceGateError("offline contract creation requires the parent deployment lock")
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "KB_OFFLINE_LOCK_HELD": _OFFLINE_LOCK_TOKEN,
    }
    completed = subprocess.run(  # noqa: S603
        [
            "sh",
            str(repository / "deploy/tencent/create-offline-contract.sh"),
            runtime_env_file,
            release_env_file,
        ],
        cwd=repository,
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        env=environment,
        shell=False,
        timeout=60,
        pass_fds=(_OFFLINE_LOCK_FD,),
    )
    if completed.returncode != 0:
        detail = redact_output(completed.stderr.strip() or "contract creation failed")
        raise RuntimeError(_bounded_summary(detail))
    fields = completed.stdout.strip().split()
    if len(fields) != 2:
        raise RuntimeError("contract creation returned an invalid result")
    contract_dir, contract_sha256 = fields
    if not contract_dir.startswith("/run/heyi-kb-offline/contracts/contract."):
        raise RuntimeError("contract creation returned a path outside the protected runtime root")
    if re.fullmatch(r"[0-9a-f]{64}", contract_sha256) is None:
        raise RuntimeError("contract creation returned an invalid SHA-256")
    return contract_dir, contract_sha256


def _remove_offline_contract(
    repository: Path,
    *,
    contract_dir: str,
    contract_sha256: str,
) -> bool:
    if _active_offline_lock_fd != _OFFLINE_LOCK_FD:
        return False
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "KB_OFFLINE_LOCK_HELD": _OFFLINE_LOCK_TOKEN,
    }
    try:
        completed = subprocess.run(  # noqa: S603
            [
                "sh",
                str(repository / "deploy/tencent/remove-offline-contract.sh"),
                contract_dir,
                contract_sha256,
            ],
            cwd=repository,
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="replace",
            env=environment,
            shell=False,
            timeout=30,
            pass_fds=(_OFFLINE_LOCK_FD,),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run redacted enterprise acceptance gates")
    parser.add_argument("--profile", choices=("local", "ci", "final"), default="local")
    parser.add_argument("--report-dir", type=Path, default=Path("artifacts/acceptance"))
    parser.add_argument("--verify-evidence", choices=("malware", "security-scan"))
    parser.add_argument(
        "--verify-operational-evidence",
        choices=("capacity", "disaster-recovery"),
    )
    parser.add_argument("--verify-offline-runtime-evidence", action="store_true")
    parser.add_argument("--run-browser-e2e", action="store_true")
    parser.add_argument("--evidence-file", type=Path)
    parser.add_argument("--evidence-signature", type=Path)
    parser.add_argument("--evidence-public-key", type=Path)
    parser.add_argument("--verify-clean-worktree", action="store_true")
    parser.add_argument(
        "--host-disk-path",
        default="/srv",
        help="Existing target-host path whose filesystem will hold application data",
    )
    parser.add_argument(
        "--host-io-evidence",
        help="Absolute target-host path to host IO/SSD evidence JSON",
    )
    parser.add_argument(
        "--storage-chain-evidence",
        help="Absolute target-host path to storage watermark chain evidence JSON",
    )
    parser.add_argument(
        "--offline-runtime-env-file",
        help="Absolute target-host path to shared offline runtime settings and secrets",
    )
    parser.add_argument(
        "--offline-release-env-file",
        help="Absolute target-host path to the immutable per-release image environment",
    )
    parser.add_argument(
        "--offline-env-file",
        help=(
            "Deprecated single-file compatibility option for non-final callers; "
            "the final profile rejects it"
        ),
    )
    parser.add_argument(
        "--offline-image-manifest",
        help=(
            "Compatibility assertion only; when supplied it must exactly equal "
            "<offline-release-env-file>.images"
        ),
    )
    parser.add_argument(
        "--offline-runtime-evidence",
        help="Absolute target-host path to formal offline runtime evidence JSON",
    )
    parser.add_argument(
        "--e2e-evidence",
        help="Absolute target-host output path for enterprise Playwright evidence",
    )
    parser.add_argument(
        "--functional-trust-store",
        type=Path,
        help="Root-owned public-key trust store outside the repository",
    )
    parser.add_argument(
        "--functional-challenge-store",
        type=Path,
        help="Root-owned 0700 one-time challenge directory outside the repository",
    )
    parser.add_argument(
        "--e2e-signing-key-path",
        type=Path,
        help="Root-owned browser evidence signing private key outside the repository",
    )
    parser.add_argument(
        "--e2e-signing-key-id",
        help="Explicit browser evidence signing key identifier",
    )
    parser.add_argument(
        "--malware-evidence",
        help="Formal target-host malware-chain evidence document",
    )
    parser.add_argument(
        "--security-scan-evidence",
        help="Formal completed security-scan evidence document",
    )
    parser.add_argument(
        "--release-id",
        help="Immutable deployment release token shared by capacity and recovery evidence",
    )
    parser.add_argument(
        "--capacity-evidence",
        help="Absolute target-host path to signed combined capacity evidence",
    )
    parser.add_argument(
        "--capacity-evidence-signature",
        help="Absolute target-host path to the capacity evidence Ed25519 signature",
    )
    parser.add_argument(
        "--capacity-evidence-public-key",
        help="Absolute target-host path to the trusted capacity evidence public key",
    )
    parser.add_argument(
        "--disaster-recovery-evidence",
        help="Absolute target-host path to signed full-restore evidence",
    )
    parser.add_argument(
        "--disaster-recovery-evidence-signature",
        help="Absolute target-host path to the recovery evidence Ed25519 signature",
    )
    parser.add_argument(
        "--disaster-recovery-evidence-public-key",
        help="Absolute target-host path to the trusted recovery evidence public key",
    )
    parser.add_argument(
        "--supply-chain-attestation",
        help="Absolute target-host path to the approved release-rights attestation",
    )
    parser.add_argument(
        "--supply-chain-artifact-root",
        help="Absolute target-host root containing the release image SBOM artifacts",
    )
    parser.add_argument(
        "--node-executable",
        type=Path,
        help="Explicit trusted Node executable outside the repository",
    )
    add_identity_arguments(parser)
    arguments = parser.parse_args(argv)

    repository = Path(__file__).resolve().parents[1]
    require_root_node = os.name == "posix" and arguments.profile in {"ci", "final"}
    try:
        functional_node_binding = (
            bind_trusted_executable_path(
                repository,
                arguments.node_executable,
                require_root_owner=require_root_node,
            )
            if arguments.node_executable is not None
            else bind_trusted_executable(
                repository,
                "node",
                search_path=os.environ.get("PATH"),
                require_root_owner=require_root_node,
            )
        )
        functional_node_blocker = None
    except AcceptanceGateError as exc:
        functional_node_binding = None
        functional_node_blocker = f"trusted Node executable unavailable: {exc}"
    identity_collector = cast(IdentityCollector, collect_worktree_evidence)
    if arguments.run_browser_e2e:
        if not all(
            (
                arguments.e2e_evidence,
                arguments.functional_trust_store,
                arguments.functional_challenge_store,
                arguments.e2e_signing_key_path,
                arguments.e2e_signing_key_id,
                arguments.expected_git_head,
                arguments.expected_content_fingerprint,
                arguments.acceptance_run_nonce,
            )
        ):
            print(json.dumps({"status": "blocked", "reason": "explicit E2E trust inputs required"}))
            return 2
        try:
            browser_identity = start_gate_identity(
                repository,
                expected_git_head=arguments.expected_git_head,
                expected_content_fingerprint=arguments.expected_content_fingerprint,
                run_nonce=arguments.acceptance_run_nonce,
                collector=identity_collector,
            )
        except (AcceptanceGateError, OSError, RuntimeError, UnicodeError):
            print(json.dumps({"status": "blocked", "reason": "E2E identity is invalid"}))
            return 2
        exit_code, summary = run_browser_e2e(
            repository=repository,
            evidence_file=Path(arguments.e2e_evidence),
            trust_store=arguments.functional_trust_store,
            challenge_store=arguments.functional_challenge_store,
            signing_key=arguments.e2e_signing_key_path,
            signing_key_id=arguments.e2e_signing_key_id,
            identity=browser_identity,
            identity_collector=identity_collector,
        )
        print(
            json.dumps(
                {
                    "status": (
                        "passed" if exit_code == 0 else "blocked" if exit_code == 2 else "failed"
                    ),
                    "summary": redact_output(summary),
                },
                ensure_ascii=True,
            )
        )
        return exit_code
    if arguments.verify_operational_evidence is not None:
        if (
            arguments.evidence_file is None
            or arguments.evidence_signature is None
            or arguments.evidence_public_key is None
            or arguments.release_id is None
            or not all(
                (
                    arguments.expected_git_head,
                    arguments.expected_content_fingerprint,
                    arguments.acceptance_run_nonce,
                )
            )
        ):
            print(
                json.dumps(
                    {
                        "status": "blocked",
                        "reason": "signed operational evidence and release identity are required",
                    }
                )
            )
            return 2
        try:
            operational_identity = start_gate_identity(
                repository,
                expected_git_head=arguments.expected_git_head,
                expected_content_fingerprint=arguments.expected_content_fingerprint,
                run_nonce=arguments.acceptance_run_nonce,
                collector=identity_collector,
            )
        except (AcceptanceGateError, OSError, RuntimeError, UnicodeError):
            print(json.dumps({"status": "blocked", "reason": "operational identity is invalid"}))
            return 2
        accepted, summary = verify_signed_operational_evidence(
            arguments.verify_operational_evidence,
            arguments.evidence_file,
            arguments.evidence_signature,
            arguments.evidence_public_key,
            identity=operational_identity,
            release_id=arguments.release_id,
        )
        try:
            assert_gate_identity(
                repository,
                operational_identity,
                collector=identity_collector,
                stage="after signed operational evidence verification",
            )
        except (AcceptanceGateError, OSError, RuntimeError, UnicodeError):
            accepted = False
            summary = "repository identity changed during operational evidence verification"
        print(
            json.dumps(
                {"status": "passed" if accepted else "blocked", "summary": summary},
                ensure_ascii=True,
            )
        )
        return 0 if accepted else 2
    if arguments.verify_offline_runtime_evidence:
        if arguments.evidence_file is None:
            print(json.dumps({"status": "blocked", "reason": "evidence file is required"}))
            return 2
        accepted, summary = verify_offline_runtime_evidence(
            arguments.evidence_file,
            repository,
        )
        print(
            json.dumps(
                {"status": "passed" if accepted else "blocked", "summary": summary},
                ensure_ascii=True,
            )
        )
        return 0 if accepted else 2
    if arguments.verify_evidence is not None:
        if (
            arguments.evidence_file is None
            or arguments.functional_trust_store is None
            or arguments.functional_challenge_store is None
            or not all(
                (
                    arguments.expected_git_head,
                    arguments.expected_content_fingerprint,
                    arguments.acceptance_run_nonce,
                )
            )
        ):
            print(
                json.dumps(
                    {
                        "status": "blocked",
                        "reason": "signed evidence trust and acceptance identity are required",
                    }
                )
            )
            return 2
        try:
            from scripts.functional_acceptance import (
                load_external_trust_context,
            )

            formal_identity = start_gate_identity(
                repository,
                expected_git_head=arguments.expected_git_head,
                expected_content_fingerprint=arguments.expected_content_fingerprint,
                run_nonce=arguments.acceptance_run_nonce,
                collector=identity_collector,
            )
            trust_context = load_external_trust_context(
                repository,
                arguments.functional_trust_store,
                arguments.functional_challenge_store,
            )
        except (
            AcceptanceGateError,
            ImportError,
            OSError,
            RuntimeError,
            UnicodeError,
            ValueError,
        ):
            print(json.dumps({"status": "blocked", "reason": "formal evidence trust failed"}))
            return 2
        accepted, summary = verify_formal_evidence(
            arguments.verify_evidence,
            arguments.evidence_file,
            repository,
            identity=formal_identity,
            trust_context=trust_context,
        )
        try:
            assert_gate_identity(
                repository,
                formal_identity,
                collector=identity_collector,
                stage="after formal evidence verification",
            )
        except (AcceptanceGateError, OSError, RuntimeError, UnicodeError):
            accepted = False
            summary = "repository identity changed during formal evidence verification"
        print(
            json.dumps(
                {"status": "passed" if accepted else "blocked", "summary": summary},
                ensure_ascii=True,
            )
        )
        return 0 if accepted else 2
    if arguments.verify_clean_worktree:
        try:
            identity = collect_worktree_evidence(repository)
        except (OSError, RuntimeError, UnicodeError):
            print(json.dumps({"status": "blocked", "reason": "worktree identity unavailable"}))
            return 2
        print(
            json.dumps(
                {
                    "status": "blocked" if identity.dirty else "passed",
                    "dirty": identity.dirty,
                    "status_counts": identity.status_counts,
                    "content_fingerprint": identity.content_fingerprint,
                },
                ensure_ascii=True,
            )
        )
        return 2 if identity.dirty else 0

    try:
        initial_worktree, acceptance_identity = initialize_acceptance_identity(repository)
    except (AcceptanceGateError, OSError, RuntimeError, UnicodeError):
        print(json.dumps({"status": "blocked", "reason": "acceptance identity unavailable"}))
        return 2
    if arguments.profile == "final" and initial_worktree.dirty:
        dirty_result = AcceptanceResult(
            gate_id="WORKTREE-P0-001",
            severity="P0",
            status="failed",
            duration_seconds=0.0,
            summary="final acceptance requires a clean worktree before any gate is executed",
        )
        json_path, markdown_path = write_reports(
            [dirty_result],
            report_dir=arguments.report_dir,
            profile=arguments.profile,
            revision=acceptance_identity.git_head,
            repository=repository,
            acceptance_identity=acceptance_identity,
        )
        print(f"{dirty_result.gate_id}: failed (0.00s)")
        print("verdict=FAIL")
        print(f"json_report={json_path}")
        print(f"markdown_report={markdown_path}")
        print(f"acceptance_run_nonce={acceptance_identity.run_nonce}")
        return 1

    deployment_lock_fd: int | None = None
    if arguments.profile == "final":
        try:
            deployment_lock_fd = acquire_offline_acceptance_lock()
        except (AcceptanceGateError, OSError):
            lock_result = AcceptanceResult(
                gate_id="OFFLINE-DEPLOYMENT-LOCK-P0-001",
                severity="P0",
                status="blocked",
                duration_seconds=0.0,
                summary="exclusive root deployment lock is unavailable",
            )
            json_path, markdown_path = write_reports(
                [lock_result],
                report_dir=arguments.report_dir,
                profile=arguments.profile,
                revision=acceptance_identity.git_head,
                repository=repository,
                acceptance_identity=acceptance_identity,
            )
            print(f"{lock_result.gate_id}: blocked (0.00s)")
            print("verdict=FAIL")
            print(f"json_report={json_path}")
            print(f"markdown_report={markdown_path}")
            print(f"acceptance_run_nonce={acceptance_identity.run_nonce}")
            return 1

    offline_contract_dir: str | None = None
    offline_contract_sha256: str | None = None
    offline_contract_blocker: str | None = None
    if arguments.profile == "final":
        expected_manifest = (
            f"{arguments.offline_release_env_file}.images"
            if arguments.offline_release_env_file is not None
            else None
        )
        supplied_inputs_are_eligible = (
            arguments.offline_runtime_env_file is not None
            and arguments.offline_runtime_env_file.startswith("/")
            and arguments.offline_release_env_file is not None
            and arguments.offline_release_env_file.startswith("/")
            and arguments.offline_env_file is None
            and (
                arguments.offline_image_manifest is None
                or arguments.offline_image_manifest == expected_manifest
            )
        )
        if supplied_inputs_are_eligible:
            try:
                offline_contract_dir, offline_contract_sha256 = _create_offline_contract(
                    repository,
                    runtime_env_file=arguments.offline_runtime_env_file,
                    release_env_file=arguments.offline_release_env_file,
                )
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                offline_contract_blocker = f"canonical offline contract unavailable: {exc}"

    gates = build_profile(
        arguments.profile,
        host_disk_path=arguments.host_disk_path,
        host_io_evidence_path=arguments.host_io_evidence,
        storage_chain_evidence_path=arguments.storage_chain_evidence,
        offline_runtime_env_file=arguments.offline_runtime_env_file,
        offline_release_env_file=arguments.offline_release_env_file,
        offline_env_file=arguments.offline_env_file,
        offline_image_manifest_path=arguments.offline_image_manifest,
        offline_contract_dir=offline_contract_dir,
        offline_contract_sha256=offline_contract_sha256,
        offline_contract_blocker=offline_contract_blocker,
        offline_runtime_evidence_path=arguments.offline_runtime_evidence,
        e2e_evidence_path=arguments.e2e_evidence,
        functional_trust_store_path=(
            str(arguments.functional_trust_store)
            if arguments.functional_trust_store is not None
            else None
        ),
        functional_challenge_store_path=(
            str(arguments.functional_challenge_store)
            if arguments.functional_challenge_store is not None
            else None
        ),
        e2e_signing_key_path=(
            str(arguments.e2e_signing_key_path)
            if arguments.e2e_signing_key_path is not None
            else None
        ),
        e2e_signing_key_id=arguments.e2e_signing_key_id,
        malware_evidence_path=arguments.malware_evidence,
        security_scan_evidence_path=arguments.security_scan_evidence,
        release_id=arguments.release_id,
        capacity_evidence_path=arguments.capacity_evidence,
        capacity_evidence_signature_path=arguments.capacity_evidence_signature,
        capacity_evidence_public_key_path=arguments.capacity_evidence_public_key,
        disaster_recovery_evidence_path=arguments.disaster_recovery_evidence,
        disaster_recovery_evidence_signature_path=arguments.disaster_recovery_evidence_signature,
        disaster_recovery_evidence_public_key_path=(
            arguments.disaster_recovery_evidence_public_key
        ),
        supply_chain_attestation_path=arguments.supply_chain_attestation,
        supply_chain_artifact_root=arguments.supply_chain_artifact_root,
        functional_node_binding=functional_node_binding,
        functional_node_blocker=functional_node_blocker,
        acceptance_identity=acceptance_identity,
    )
    results: list[AcceptanceResult] = []
    contract_cleanup_succeeded = True
    try:
        results.extend(
            run_gates_bound_to_identity(
                gates,
                repository=repository,
                identity=acceptance_identity,
                identity_collector=identity_collector,
                on_result=lambda result: print(
                    f"{result.gate_id}: {result.status} ({result.duration_seconds:.2f}s)"
                ),
            )
        )
    finally:
        try:
            assert_gate_identity(
                repository,
                acceptance_identity,
                collector=identity_collector,
                stage="before offline contract cleanup",
            )
        except (AcceptanceGateError, OSError, RuntimeError, UnicodeError):
            if not any(item.gate_id == "ACCEPTANCE-IDENTITY-P0-001" for item in results):
                results.append(
                    _identity_failure("before offline contract cleanup", time.monotonic())
                )
        if offline_contract_dir is not None and offline_contract_sha256 is not None:
            contract_cleanup_succeeded = _remove_offline_contract(
                repository,
                contract_dir=offline_contract_dir,
                contract_sha256=offline_contract_sha256,
            )
    if not contract_cleanup_succeeded:
        cleanup_result = AcceptanceResult(
            gate_id="OFFLINE-CONTRACT-CLEANUP-P1-001",
            severity="P1",
            status="failed",
            duration_seconds=0.0,
            summary="root-only offline contract cleanup could not be verified",
        )
        results.append(cleanup_result)
        print(f"{cleanup_result.gate_id}: failed (0.00s)")

    def record_identity_failure(stage: str) -> None:
        if any(item.gate_id == "ACCEPTANCE-IDENTITY-P0-001" for item in results):
            return
        failure = _identity_failure(stage, time.monotonic())
        results.append(failure)
        print(f"{failure.gate_id}: failed ({failure.duration_seconds:.2f}s)")

    try:
        assert_gate_identity(
            repository,
            acceptance_identity,
            collector=identity_collector,
            stage="after offline contract cleanup",
        )
    except (AcceptanceGateError, OSError, RuntimeError, UnicodeError):
        record_identity_failure("after offline contract cleanup")

    json_path, markdown_path = write_reports(
        results,
        report_dir=arguments.report_dir,
        profile=arguments.profile,
        revision=acceptance_identity.git_head,
        repository=repository,
        acceptance_identity=acceptance_identity,
    )
    try:
        assert_gate_identity(
            repository,
            acceptance_identity,
            collector=identity_collector,
            stage="after report publication",
        )
    except (AcceptanceGateError, OSError, RuntimeError, UnicodeError):
        record_identity_failure("after report publication")
        json_path, markdown_path = write_reports(
            results,
            report_dir=arguments.report_dir,
            profile=arguments.profile,
            revision=acceptance_identity.git_head,
            repository=repository,
            acceptance_identity=acceptance_identity,
        )

    try:
        worktree = collect_worktree_evidence(repository)
    except (OSError, RuntimeError, UnicodeError):
        worktree = None
    verdict = calculate_verdict(results)
    if arguments.profile == "final" and (
        worktree is None
        or worktree.dirty
        or worktree.git_head != acceptance_identity.git_head
        or worktree.content_fingerprint != acceptance_identity.content_fingerprint
    ):
        verdict = "FAIL"
    if deployment_lock_fd is not None:
        try:
            release_offline_acceptance_lock(deployment_lock_fd)
        except (AcceptanceGateError, OSError):
            lock_failure = AcceptanceResult(
                gate_id="OFFLINE-DEPLOYMENT-LOCK-P0-001",
                severity="P0",
                status="failed",
                duration_seconds=0.0,
                summary="exclusive deployment lock could not be released safely",
            )
            results.append(lock_failure)
            json_path, markdown_path = write_reports(
                results,
                report_dir=arguments.report_dir,
                profile=arguments.profile,
                revision=acceptance_identity.git_head,
                repository=repository,
                acceptance_identity=acceptance_identity,
            )
            verdict = "FAIL"
    print(f"verdict={verdict}")
    print(f"json_report={json_path}")
    print(f"markdown_report={markdown_path}")
    print(f"acceptance_run_nonce={acceptance_identity.run_nonce}")
    return {"PASS": 0, "CONDITIONAL": 2, "FAIL": 1}[verdict]


if __name__ == "__main__":
    sys.exit(main())
