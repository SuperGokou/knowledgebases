from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast

Severity = Literal["P0", "P1", "P2"]
GateStatus = Literal["passed", "failed", "blocked"]
Verdict = Literal["PASS", "CONDITIONAL", "FAIL"]
Profile = Literal["local", "ci", "final"]
EvidenceKind = Literal["malware", "security-scan"]

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


GateExecutor = Callable[[AcceptanceGate], CommandOutcome]


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


def resolve_command(command: tuple[str, ...]) -> tuple[str, ...]:
    if not command:
        return command
    executable = shutil.which(command[0]) or command[0]
    return (executable, *command[1:])


def _bounded_summary(value: str) -> str:
    if len(value) <= _SUMMARY_LIMIT:
        return value
    marker = "[...earlier output truncated...]\n"
    return marker + value[-(_SUMMARY_LIMIT - len(marker)) :]


def execute_command(gate: AcceptanceGate) -> CommandOutcome:
    environment = os.environ.copy()
    environment.update(gate.environment)
    completed = subprocess.run(  # noqa: S603
        list(resolve_command(gate.command)),
        cwd=gate.cwd,
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        env=environment,
        shell=False,
        timeout=gate.timeout_seconds,
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


def _browser_e2e_exit_code(
    outcome: CommandOutcome, *, evidence_verified: bool
) -> int:
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
    offline_env_file: str | None = None,
    offline_image_manifest_path: str | None = None,
    offline_runtime_evidence_path: str | None = None,
    e2e_evidence_path: str | None = None,
    functional_trust_store_path: str | None = None,
    functional_challenge_store_path: str | None = None,
    e2e_signing_key_path: str | None = None,
    e2e_signing_key_id: str | None = None,
    malware_evidence_path: str | None = None,
    security_scan_evidence_path: str | None = None,
) -> tuple[AcceptanceGate, ...]:
    repository = Path(__file__).resolve().parents[1]
    web = repository / "web"
    base = (
        AcceptanceGate(
            "CODE-P0-001",
            "P0",
            ("uv", "run", "ruff", "check", "."),
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
            ),
            str(repository),
            900,
        ),
        AcceptanceGate(
            "TYPE-P1-001",
            "P1",
            ("uv", "run", "mypy", "app", "scripts"),
            str(repository),
            180,
        ),
        AcceptanceGate(
            "BACKEND-P0-001",
            "P0",
            (
                "uv",
                "run",
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
                "--file",
                str(repository / "deploy/tencent/compose.offline.yml"),
                "--profile",
                "ops",
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

    host_evidence_blocker = missing_target_path(
        host_io_evidence_path, "--host-io-evidence"
    )
    storage_evidence_blocker = missing_target_path(
        storage_chain_evidence_path, "--storage-chain-evidence"
    )
    offline_env_blocker = missing_target_path(offline_env_file, "--offline-env-file")
    offline_manifest_blocker = missing_target_path(
        offline_image_manifest_path, "--offline-image-manifest"
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
    signing_key_blocker = missing_target_path(
        e2e_signing_key_path, "--e2e-signing-key-path"
    )
    signing_key_id_blocker = (
        None
        if e2e_signing_key_id == "browser-e2e-ed25519"
        else "--e2e-signing-key-id must explicitly select browser-e2e-ed25519"
    )
    malware_evidence_blocker = missing_target_path(
        malware_evidence_path, "--malware-evidence"
    )
    security_evidence_blocker = missing_target_path(
        security_scan_evidence_path, "--security-scan-evidence"
    )

    final_gates = (
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
            ),
            str(repository),
            900,
            blocked_reason=(
                e2e_evidence_blocker
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
            (),
            str(repository),
            1,
            blocked_reason=(
                "No reproducible load-test and provider-capacity evidence demonstrates "
                "5 billion tokens per day under the required 1,000-user workload."
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
            ),
            str(repository),
            30,
            blocked_reason=malware_evidence_blocker,
            blocked_exit_codes=(2,),
        ),
        AcceptanceGate(
            "TOKEN-GOV-P0-001",
            "P0",
            (
                sys.executable,
                str(repository / "scripts/postgres_acceptance.py"),
                "--image",
                "postgres:17.5-bookworm",
            ),
            str(repository),
            600,
            blocked_exit_codes=(2,),
        ),
        AcceptanceGate(
            "DR-P0-001",
            "P0",
            (),
            str(repository),
            1,
            blocked_reason=(
                "A timed disaster-recovery restore drill with measured RPO/RTO and restored "
                "data-integrity evidence has not been completed."
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
            ),
            str(repository),
            30,
            blocked_reason=security_evidence_blocker,
            blocked_exit_codes=(2,),
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
            offline_env_file or "",
        ),
        str(repository),
        300,
        blocked_reason=offline_env_blocker,
        blocked_exit_codes=(66, 77),
        required_regular_files=(offline_env_file,) if offline_env_file else (),
        missing_executable_is_blocked=True,
    )
    target_offline_images_gate = AcceptanceGate(
        "OFFLINE-IMAGES-P0-001",
        "P0",
        (
            "sh",
            str(repository / "deploy/tencent/verify-offline-images.sh"),
            "verify",
            offline_env_file or "",
            offline_image_manifest_path or "",
        ),
        str(repository),
        300,
        blocked_reason=offline_env_blocker or offline_manifest_blocker,
        blocked_exit_codes=(66,),
        required_regular_files=(
            (offline_env_file, offline_image_manifest_path)
            if offline_env_file and offline_image_manifest_path
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
        ),
        str(repository),
        600,
        blocked_exit_codes=(2,),
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
    final_base_without_backend = tuple(
        gate for gate in final_base if gate.gate_id != "BACKEND-P0-001"
    )
    remaining_final_gates = tuple(
        gate for gate in final_gates if gate.gate_id != "TOKEN-GOV-P0-001"
    )
    return (
        *final_base_without_backend,
        target_offline_images_gate,
        target_offline_runtime_gate,
        token_gate,
        target_backend_gate,
        *remaining_final_gates,
    )


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


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


def verify_formal_evidence(
    kind: EvidenceKind,
    evidence_file: Path,
    repository: Path,
) -> tuple[bool, str]:
    display_kind = "security scan" if kind == "security-scan" else kind
    failure = f"{display_kind} evidence is incomplete or does not match this worktree"
    document = _load_evidence_document(evidence_file)
    if document is None:
        return False, failure
    try:
        identity = collect_worktree_evidence(repository)
    except (OSError, RuntimeError, UnicodeError):
        return False, failure
    if (
        document.get("schema_version") != 1
        or document.get("kind") != kind
        or document.get("status") != "complete"
        or not _target_matches(document, identity)
    ):
        return False, failure

    if kind == "malware":
        target = document.get("target")
        checks = document.get("checks")
        required_checks = (
            "clamav_database_preflight",
            "eicar_quarantined",
            "clean_file_released",
            "minio_scan_approval_download",
        )
        if not isinstance(target, dict) or target.get("os") != "linux":
            return False, failure
        if not isinstance(checks, dict):
            return False, failure
        for name in required_checks:
            check = checks.get(name)
            if (
                not isinstance(check, dict)
                or check.get("status") != "passed"
                or not _artifact_matches(evidence_file, check)
            ):
                return False, failure
        return True, "malware target-host evidence verified (4/4 checks)"

    report = document.get("report")
    summary = document.get("summary")
    count_names = ("open_critical", "open_high", "open_medium", "open_low")
    if (
        document.get("policy_status") != "passed"
        or not _artifact_matches(evidence_file, report)
        or not isinstance(summary, dict)
        or any(
            not isinstance(summary.get(name), int) or int(summary[name]) < 0 for name in count_names
        )
        or summary.get("open_critical") != 0
        or summary.get("open_high") != 0
    ):
        return False, failure
    return True, "complete security scan report verified for this worktree"


def verify_browser_e2e_evidence(
    evidence_file: Path,
    trust_store: Path,
    challenge_store: Path,
    repository: Path,
    *,
    expected_key_id: str,
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
        trust_context=trust_context,
    ):
        return True, "signed browser E2E evidence verified and challenge consumed"
    return False, failure


def _verify_browser_e2e_document(
    evidence_file: Path,
    repository: Path,
    *,
    expected_key_id: str,
    trust_context: object,
) -> bool:
    document = _load_evidence_document(evidence_file)
    attestation = document.get("attestation") if document is not None else None
    if not (
        document is not None
        and document.get("evidence_id") == "EXT-BROWSER-E2E-001"
        and isinstance(attestation, dict)
        and attestation.get("type") == "ed25519-challenge-v1"
        and attestation.get("key_id") == expected_key_id
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
    repository: Path, trust_store: Path, challenge_store: Path
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
        and challenge_id in context.challenge_paths
    ]
    if len(challenge_ids) != 1:
        return None
    return context.challenge_paths[challenge_ids[0]]


def run_browser_e2e(
    *,
    repository: Path,
    evidence_file: Path,
    trust_store: Path,
    challenge_store: Path,
    signing_key: Path,
    signing_key_id: str,
) -> tuple[int, str]:
    failure = "browser E2E target trust material or signed evidence is unavailable"
    if (
        platform.system().casefold() != "linux"
        or signing_key_id != "browser-e2e-ed25519"
        or not _protected_regular_file(signing_key, maximum_bytes=64 * 1024)
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
    challenge_path = _browser_challenge_path(repository, trust_store, challenge_store)
    if challenge_path is None:
        return 2, failure
    environment = os.environ.copy()
    environment.update(
        {
            "KB_E2E_PROFILE": "enterprise",
            "KB_E2E_EVIDENCE_PATH": str(evidence_file),
            "KB_E2E_SIGNING_KEY_PATH": str(signing_key),
            "KB_E2E_SIGNING_KEY_ID": signing_key_id,
            "KB_E2E_CHALLENGE_PATH": str(challenge_path),
        }
    )
    try:
        completed = subprocess.run(  # noqa: S603
            list(resolve_command(("npm", "run", "test:e2e"))),
            cwd=repository / "web",
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="replace",
            env=environment,
            shell=False,
            timeout=900,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
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
    )
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
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
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
        and (
            metadata.st_uid != 0
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        )
    )


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
        == {"git_head", "content_fingerprint", "host_fingerprint", "project_name"}
        and target.get("git_head") == identity.git_head
        and target.get("content_fingerprint") == identity.content_fingerprint
        and target.get("host_fingerprint") == active_host_fingerprint
        and isinstance(target.get("project_name"), str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", str(target["project_name"]))
        is not None
        and isinstance(checks, dict)
        and set(checks) == _OFFLINE_RUNTIME_CHECKS
        and isinstance(artifacts, list)
        and 1 <= len(artifacts) <= 128
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
            and re.fullmatch(r"raw/[0-9]{3}-[A-Za-z0-9_.-]+\.json", relative_name)
            is not None
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
    if profile == "final" and worktree.dirty:
        verdict = "FAIL"
    generated_at = datetime.now(UTC).isoformat()
    evidence_class = (
        "final_signoff_candidate" if profile == "final" else "development_smoke_not_for_signoff"
    )
    payload = {
        "schema_version": 1,
        "generated_at": generated_at,
        "profile": profile,
        "evidence_class": evidence_class,
        "revision": worktree.git_head,
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run redacted enterprise acceptance gates")
    parser.add_argument("--profile", choices=("local", "ci", "final"), default="local")
    parser.add_argument("--report-dir", type=Path, default=Path("artifacts/acceptance"))
    parser.add_argument("--verify-evidence", choices=("malware", "security-scan"))
    parser.add_argument("--verify-offline-runtime-evidence", action="store_true")
    parser.add_argument("--run-browser-e2e", action="store_true")
    parser.add_argument("--evidence-file", type=Path)
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
        "--offline-env-file",
        help="Target-host offline deployment environment file",
    )
    parser.add_argument(
        "--offline-image-manifest",
        help="Absolute target-host path to the verified Compose image manifest",
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
    arguments = parser.parse_args(argv)

    repository = Path(__file__).resolve().parents[1]
    if arguments.run_browser_e2e:
        if not all(
            (
                arguments.e2e_evidence,
                arguments.functional_trust_store,
                arguments.functional_challenge_store,
                arguments.e2e_signing_key_path,
                arguments.e2e_signing_key_id,
            )
        ):
            print(json.dumps({"status": "blocked", "reason": "explicit E2E trust inputs required"}))
            return 2
        exit_code, summary = run_browser_e2e(
            repository=repository,
            evidence_file=Path(arguments.e2e_evidence),
            trust_store=arguments.functional_trust_store,
            challenge_store=arguments.functional_challenge_store,
            signing_key=arguments.e2e_signing_key_path,
            signing_key_id=arguments.e2e_signing_key_id,
        )
        print(
            json.dumps(
                {
                    "status": (
                        "passed"
                        if exit_code == 0
                        else "blocked"
                        if exit_code == 2
                        else "failed"
                    ),
                    "summary": redact_output(summary),
                },
                ensure_ascii=True,
            )
        )
        return exit_code
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
        if arguments.evidence_file is None:
            print(json.dumps({"status": "blocked", "reason": "evidence file is required"}))
            return 2
        accepted, summary = verify_formal_evidence(
            arguments.verify_evidence,
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

    gates = build_profile(
        arguments.profile,
        host_disk_path=arguments.host_disk_path,
        host_io_evidence_path=arguments.host_io_evidence,
        storage_chain_evidence_path=arguments.storage_chain_evidence,
        offline_env_file=arguments.offline_env_file,
        offline_image_manifest_path=arguments.offline_image_manifest,
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
    )
    results: list[AcceptanceResult] = []
    for gate in gates:
        result = run_gate(gate)
        results.append(result)
        print(f"{result.gate_id}: {result.status} ({result.duration_seconds:.2f}s)")

    json_path, markdown_path = write_reports(
        results,
        report_dir=arguments.report_dir,
        profile=arguments.profile,
        revision=_revision(repository),
        repository=repository,
    )
    worktree = collect_worktree_evidence(repository)
    verdict = calculate_verdict(results)
    if arguments.profile == "final" and worktree.dirty:
        verdict = "FAIL"
    print(f"verdict={verdict}")
    print(f"json_report={json_path}")
    print(f"markdown_report={markdown_path}")
    return {"PASS": 0, "CONDITIONAL": 2, "FAIL": 1}[verdict]


if __name__ == "__main__":
    sys.exit(main())
