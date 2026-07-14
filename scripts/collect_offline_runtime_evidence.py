from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from scripts.acceptance import collect_worktree_evidence
from scripts.host_preflight import (
    MINIMUM_FILESYSTEM_AVAILABLE_BYTES,
    MINIMUM_FILESYSTEM_TOTAL_BYTES,
    MINIMUM_LOGICAL_CPUS,
    MINIMUM_VISIBLE_MEMORY_BYTES,
    SUPPORTED_ARCHITECTURES,
    collect_host_facts,
)

SCHEMA_VERSION = 1
COLLECTOR_ID = "heyi-offline-runtime"
COLLECTOR_VERSION = "1.0.0"
EXECUTION_CONFIRMATION = "EXECUTE-OFFLINE-RUNTIME-ACCEPTANCE"
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_ARTIFACTS = 128
CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{24,128}$")
TENANT_PATTERN = re.compile(r"^kb-acceptance-[a-z0-9-]{1,48}$")
PROJECT_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GIT_HASH_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
FORBIDDEN_EXECUTABLES = frozenset(
    {
        "ash",
        "bash",
        "busybox",
        "cmd",
        "dash",
        "env",
        "fish",
        "ksh",
        "powershell",
        "pwsh",
        "sh",
        "sudo",
        "su",
        "zsh",
    }
)
SECRET_KEY_PATTERN = re.compile(
    r"(?:authorization|credential|password|private[_-]?key|secret|token)", re.I
)
SECRET_VALUE_PATTERN = re.compile(
    r"(?i)(?:\bbearer\s+\S+|(?:password|secret|token)\s*[:=]|"
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b)"
)

REQUIRED_COMMAND_STEPS = (
    "recovery_preflight",
    "rollback_arm",
    "network_disconnect",
    "cold_start",
    "login",
    "rbac",
    "acl",
    "upload",
    "approval",
    "download",
    "question_answer",
    "persistence_write",
    "restart",
    "persistence_verify",
    "network_restore",
    "rollback_cancel",
    "recovery_verify",
)
BUSINESS_STEPS = (
    "login",
    "rbac",
    "acl",
    "upload",
    "approval",
    "download",
    "question_answer",
    "persistence_write",
    "restart",
    "persistence_verify",
)
SYSTEM_TOOL_NAMES = ("docker", "getent", "ip", "nft", "nsenter", "readlink", "ss")


class CollectionBlocked(RuntimeError):
    """The collector could not prove the acceptance condition safely."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def run(
        self, step_id: str, argv: tuple[str, ...], timeout_seconds: int
    ) -> CommandResult: ...


@dataclass(frozen=True, slots=True)
class SubprocessCommandRunner:
    def run(self, step_id: str, argv: tuple[str, ...], timeout_seconds: int) -> CommandResult:
        del step_id
        try:
            completed = subprocess.run(  # noqa: S603 - validated argv, never a shell
                argv,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                timeout=timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CollectionBlocked("a bounded collector command could not complete") from error
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    challenge: str
    test_tenant: str
    project_name: str
    git_head: str
    content_fingerprint: str
    host_fingerprint: str
    commands: dict[str, dict[str, object]]
    output_dir: Path
    tools: dict[str, str] = field(
        default_factory=lambda: {name: f"/usr/bin/{name}" for name in SYSTEM_TOOL_NAMES}
    )
    resolver_config: str = ""


@dataclass(slots=True)
class ArtifactStore:
    root: Path
    artifacts: list[dict[str, object]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)

    def write_json(self, artifact_id: str, value: object) -> str:
        if len(self.artifacts) >= MAX_ARTIFACTS:
            raise CollectionBlocked("artifact count exceeded its safety bound")
        if SAFE_IDENTIFIER_PATTERN.fullmatch(artifact_id) is None:
            raise CollectionBlocked("artifact identifier is invalid")
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        raw = (payload + "\n").encode("utf-8")
        if len(raw) > MAX_OUTPUT_BYTES:
            raise CollectionBlocked("artifact exceeded its safety bound")
        relative = Path("raw") / f"{len(self.artifacts):03d}-{artifact_id}.json"
        target = self.root / relative
        target.parent.mkdir(mode=0o700, exist_ok=True)
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        self.artifacts.append(
            {
                "id": artifact_id,
                "path": relative.as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
            }
        )
        return artifact_id


def canonical_digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()


def build_plan() -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "collector": COLLECTOR_ID,
        "collector_version": COLLECTOR_VERSION,
        "status": "planned",
        "mutating": False,
        "target": {
            "platform": "Linux amd64/x86_64",
            "logical_cpus_minimum": MINIMUM_LOGICAL_CPUS,
            "visible_memory_bytes_minimum": MINIMUM_VISIBLE_MEMORY_BYTES,
            "filesystem_total_bytes_minimum": MINIMUM_FILESYSTEM_TOTAL_BYTES,
            "filesystem_available_bytes_minimum": MINIMUM_FILESYSTEM_AVAILABLE_BYTES,
        },
        "network_evidence": [
            "host_and_container_public_sockets",
            "dns_resolution_path",
            "default_and_all_routes",
            "host_and_container_network_namespaces",
            "firewall_ruleset",
            "compose_internal_networks",
        ],
        "business_checks": list(BUSINESS_STEPS),
        "required_command_steps": list(REQUIRED_COMMAND_STEPS),
        "execute_confirmation": EXECUTION_CONFIRMATION,
        "execution_requires": [
            "explicit --execute and exact confirmation",
            "root on the target Linux host",
            "matching host, Git and content fingerprints",
            "one-time challenge and dedicated test tenant",
            "root-owned non-writable control plan and executable harnesses",
            "armed rollback and verified recovery",
        ],
    }


def _endpoint_host(endpoint: str) -> str | None:
    endpoint = endpoint.strip()
    if not endpoint or endpoint in {"*", "*:*", "0.0.0.0:*", "[::]:*"}:
        return None
    if endpoint.startswith("["):
        closing = endpoint.find("]")
        return endpoint[1:closing] if closing > 1 else None
    host, separator, _port = endpoint.rpartition(":")
    if not separator:
        return None
    return host.rsplit("%", 1)[0]


def public_remote_endpoints(ss_output: str) -> list[str]:
    endpoints: set[str] = set()
    for line in ss_output.splitlines():
        columns = line.split()
        if len(columns) < 6:
            continue
        endpoint = columns[5]
        host = _endpoint_host(endpoint)
        if host is None:
            continue
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            continue
        if address.is_global:
            endpoints.add(endpoint)
    return sorted(endpoints)


def _bounded_result(step_id: str, result: CommandResult) -> dict[str, object]:
    stdout_raw = result.stdout.encode("utf-8")
    stderr_raw = result.stderr.encode("utf-8")
    if len(stdout_raw) > MAX_OUTPUT_BYTES or len(stderr_raw) > MAX_OUTPUT_BYTES:
        raise CollectionBlocked(f"{step_id} output exceeded its safety bound")
    return {
        "step": step_id,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _contains_secret(value: object, *, parent_key: str = "") -> bool:
    if SECRET_KEY_PATTERN.search(parent_key):
        return True
    if isinstance(value, dict):
        return any(
            not isinstance(key, str)
            or _contains_secret(item, parent_key=key)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret(item, parent_key=parent_key) for item in value)
    return isinstance(value, str) and (
        len(value) > 4096 or SECRET_VALUE_PATTERN.search(value) is not None
    )


def _validated_step_payload(
    context: ExecutionContext, step_id: str, result: CommandResult
) -> dict[str, object]:
    if result.returncode != 0 or result.stderr.strip():
        raise CollectionBlocked(f"{step_id} did not complete successfully")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CollectionBlocked(f"{step_id} did not return bounded JSON evidence") from error
    if not isinstance(payload, dict) or set(payload) != {
        "status",
        "check",
        "challenge",
        "test_tenant",
        "observations",
    }:
        raise CollectionBlocked(f"{step_id} returned an invalid evidence envelope")
    if (
        payload["status"] != "passed"
        or payload["check"] != step_id
        or payload["challenge"] != context.challenge
        or payload["test_tenant"] != context.test_tenant
        or _contains_secret(payload["observations"])
    ):
        raise CollectionBlocked(f"{step_id} evidence did not match the active challenge")
    return cast(dict[str, object], payload)


def _command_spec(context: ExecutionContext, step_id: str) -> tuple[tuple[str, ...], int]:
    raw = context.commands.get(step_id)
    if not isinstance(raw, dict):
        raise CollectionBlocked(f"{step_id} is missing from the control plan")
    argv = raw.get("argv")
    timeout = raw.get("timeout_seconds")
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(item, str) for item in argv)
        or not isinstance(timeout, int)
    ):
        raise CollectionBlocked(f"{step_id} control command is malformed")
    return tuple(argv), timeout


def _run_control_step(
    context: ExecutionContext,
    runner: CommandRunner,
    store: ArtifactStore,
    step_id: str,
) -> str:
    argv, timeout = _command_spec(context, step_id)
    payload = _validated_step_payload(context, step_id, runner.run(step_id, argv, timeout))
    return store.write_json(step_id, payload)


def _run_probe(
    runner: CommandRunner,
    store: ArtifactStore,
    step_id: str,
    argv: tuple[str, ...],
    *,
    expected_returncode: int = 0,
) -> CommandResult:
    result = runner.run(step_id, argv, 30)
    store.write_json(step_id, _bounded_result(step_id, result))
    if result.returncode != expected_returncode:
        raise CollectionBlocked(f"{step_id} could not prove the required state")
    return result


def _lines(value: str) -> list[str]:
    return [item.strip() for item in value.splitlines() if item.strip()]


def _network_snapshot(
    context: ExecutionContext,
    runner: CommandRunner,
    store: ArtifactStore,
    label: str,
    *,
    require_offline: bool,
) -> list[str]:
    tool = context.tools
    public_endpoints: list[str] = []
    host_sockets = _run_probe(
        runner,
        store,
        f"probe_{label}_host_sockets",
        (tool["ss"], "-H", "-tunap"),
    )
    public_endpoints.extend(public_remote_endpoints(host_sockets.stdout))
    _run_probe(
        runner,
        store,
        f"probe_{label}_routes",
        (tool["ip"], "-json", "route", "show", "table", "all"),
    )
    _run_probe(
        runner,
        store,
        f"probe_{label}_netns",
        (tool["ip"], "netns", "list"),
    )
    _run_probe(
        runner,
        store,
        f"probe_{label}_firewall",
        (tool["nft"], "-j", "list", "ruleset"),
    )
    containers = _lines(
        _run_probe(
            runner,
            store,
            f"probe_{label}_containers",
            (
                tool["docker"],
                "ps",
                "--filter",
                f"label=com.docker.compose.project={context.project_name}",
                "--format",
                "{{.ID}}",
            ),
        ).stdout
    )
    if not containers or any(
        SAFE_IDENTIFIER_PATTERN.fullmatch(item) is None for item in containers
    ):
        raise CollectionBlocked("the complete project container set could not be identified")
    for index, container in enumerate(containers):
        pid_result = _run_probe(
            runner,
            store,
            f"probe_{label}_container_pid_{index}",
            (tool["docker"], "inspect", "--format", "{{.State.Pid}}", container),
        )
        pid = pid_result.stdout.strip()
        if not pid.isdigit() or int(pid) <= 1:
            raise CollectionBlocked("a project container network namespace was unavailable")
        namespace = _run_probe(
            runner,
            store,
            f"probe_{label}_container_netns_{index}",
            (tool["readlink"], f"/proc/{pid}/ns/net"),
        )
        if not re.fullmatch(r"net:\[[0-9]+\]\s*", namespace.stdout):
            raise CollectionBlocked("a project container network namespace identity was invalid")
        sockets = _run_probe(
            runner,
            store,
            f"probe_{label}_container_sockets_{index}",
            (tool["nsenter"], "-t", pid, "-n", tool["ss"], "-H", "-tunap"),
        )
        public_endpoints.extend(public_remote_endpoints(sockets.stdout))
    networks = _lines(
        _run_probe(
            runner,
            store,
            f"probe_{label}_networks",
            (
                tool["docker"],
                "network",
                "ls",
                "--filter",
                f"label=com.docker.compose.project={context.project_name}",
                "--format",
                "{{.ID}}",
            ),
        ).stdout
    )
    if not networks or any(SAFE_IDENTIFIER_PATTERN.fullmatch(item) is None for item in networks):
        raise CollectionBlocked("the project network set could not be identified")
    network_result = _run_probe(
        runner,
        store,
        f"probe_{label}_network_inspect",
        (tool["docker"], "network", "inspect", *networks),
    )
    try:
        network_payload = json.loads(network_result.stdout)
    except json.JSONDecodeError as error:
        raise CollectionBlocked("project network inventory was invalid") from error
    if (
        not isinstance(network_payload, list)
        or len(network_payload) != len(networks)
        or not all(
            isinstance(item, dict) and item.get("Internal") is True
            for item in network_payload
        )
    ):
        raise CollectionBlocked("every project network must be declared internal")
    store.write_json(
        f"probe_{label}_resolver_config",
        {"path": "/etc/resolv.conf", "content": context.resolver_config},
    )
    if require_offline:
        dns_result = runner.run(
            f"probe_{label}_dns_external",
            (tool["getent"], "ahosts", "example.com"),
            15,
        )
        store.write_json(
            f"probe_{label}_dns_external",
            _bounded_result(f"probe_{label}_dns_external", dns_result),
        )
        if dns_result.returncode == 0:
            raise CollectionBlocked("external DNS resolution remained available after isolation")
        if public_endpoints:
            raise CollectionBlocked("public sockets remained after network isolation")
    return sorted(set(public_endpoints))


def execute_collection(
    context: ExecutionContext,
    *,
    runner: CommandRunner | None = None,
) -> dict[str, object]:
    formal_evidence = runner is None
    active_runner = runner or SubprocessCommandRunner()
    store = ArtifactStore(context.output_dir)
    checks: dict[str, dict[str, object]] = {}
    disconnect_attempted = False
    restored = False
    recovery_completed = False
    cleanup_error: CollectionBlocked | None = None
    try:
        recovery_id = _run_control_step(
            context, active_runner, store, "recovery_preflight"
        )
        _network_snapshot(context, active_runner, store, "before", require_offline=False)
        rollback_id = _run_control_step(context, active_runner, store, "rollback_arm")
        disconnect_attempted = True
        disconnect_id = _run_control_step(
            context, active_runner, store, "network_disconnect"
        )
        offline_ids_before = len(store.artifacts)
        _network_snapshot(context, active_runner, store, "offline", require_offline=True)
        offline_ids = [
            cast(str, item["id"]) for item in store.artifacts[offline_ids_before:]
        ]
        checks["offline_network_isolation"] = {
            "status": "passed",
            "artifact_ids": [recovery_id, rollback_id, disconnect_id, *offline_ids],
        }
        cold_start_id = _run_control_step(context, active_runner, store, "cold_start")
        checks["cold_start"] = {"status": "passed", "artifact_ids": [cold_start_id]}
        business_artifacts: dict[str, str] = {}
        for step_id in BUSINESS_STEPS:
            business_artifacts[step_id] = _run_control_step(
                context, active_runner, store, step_id
            )
        evidenced_business_steps = (
            "login",
            "rbac",
            "acl",
            "upload",
            "approval",
            "download",
            "question_answer",
        )
        for step_id in evidenced_business_steps:
            checks[step_id] = {
                "status": "passed",
                "artifact_ids": [business_artifacts[step_id]],
            }
        checks["restart_persistence"] = {
            "status": "passed",
            "artifact_ids": [
                business_artifacts["persistence_write"],
                business_artifacts["restart"],
                business_artifacts["persistence_verify"],
            ],
        }
        restore_id = _run_control_step(context, active_runner, store, "network_restore")
        restored = True
        cancel_id = _run_control_step(context, active_runner, store, "rollback_cancel")
        verify_id = _run_control_step(context, active_runner, store, "recovery_verify")
        recovery_completed = True
        _network_snapshot(context, active_runner, store, "restored", require_offline=False)
        checks["network_recovery"] = {
            "status": "passed",
            "artifact_ids": [restore_id, cancel_id, verify_id],
        }
    finally:
        if disconnect_attempted and not recovery_completed:
            try:
                if not restored:
                    _run_control_step(context, active_runner, store, "network_restore")
                    restored = True
                _run_control_step(context, active_runner, store, "rollback_cancel")
                _run_control_step(context, active_runner, store, "recovery_verify")
                recovery_completed = True
            except CollectionBlocked:
                cleanup_error = CollectionBlocked("network restore or rollback verification failed")
        if cleanup_error is not None:
            raise cleanup_error
    document: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "evidence_id": "EXT-OFFLINE-RUNTIME-001",
        "status": "complete",
        "result": "passed" if formal_evidence else "test-only",
        "runner": "subprocess-v1" if formal_evidence else "test-double",
        "collector": {"id": COLLECTOR_ID, "version": COLLECTOR_VERSION},
        "collected_at": datetime.now(UTC).isoformat(),
        "challenge": context.challenge,
        "test_tenant": context.test_tenant,
        "target": {
            "git_head": context.git_head,
            "content_fingerprint": context.content_fingerprint,
            "host_fingerprint": context.host_fingerprint,
            "project_name": context.project_name,
        },
        "checks": checks,
        "artifacts": store.artifacts,
    }
    document["result_sha256"] = canonical_digest(
        {"target": document["target"], "checks": checks, "artifacts": store.artifacts}
    )
    document["attestation"] = {
        "type": "sha256-chain-v1",
        "digest": canonical_digest(document),
    }
    output = context.output_dir / "offline-runtime-evidence.json"
    raw = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return document


def host_fingerprint() -> str:
    try:
        machine_id = Path("/etc/machine-id").read_text(encoding="ascii").strip()
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        root_device = str(os.stat("/").st_dev)
    except (OSError, UnicodeError) as error:
        raise CollectionBlocked("target host identity could not be collected") from error
    material = "\0".join(
        (
            machine_id,
            boot_id,
            platform.node(),
            platform.release(),
            platform.machine(),
            root_device,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _secure_root_file(path: Path, *, executable: bool = False) -> Path:
    if path.is_symlink() or not path.is_file():
        raise CollectionBlocked("a required control artifact is not a regular file")
    metadata = path.stat()
    if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise CollectionBlocked("control artifacts must be root-owned and non-writable")
    if executable and not metadata.st_mode & stat.S_IXUSR:
        raise CollectionBlocked("control harnesses must be directly executable")
    return path.resolve(strict=True)


def _load_control_plan(path: Path) -> dict[str, object]:
    resolved = _secure_root_file(path)
    if resolved.stat().st_size > 256 * 1024:
        raise CollectionBlocked("control plan exceeded its size bound")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CollectionBlocked("control plan is invalid") from error
    if not isinstance(payload, dict):
        raise CollectionBlocked("control plan is invalid")
    return cast(dict[str, object], payload)


def _validate_control_commands(
    value: object, *, challenge: str, test_tenant: str
) -> dict[str, dict[str, object]]:
    if not isinstance(value, dict) or set(value) != set(REQUIRED_COMMAND_STEPS):
        raise CollectionBlocked("control plan must define the exact required command set")
    commands: dict[str, dict[str, object]] = {}
    for step_id, raw in value.items():
        if not isinstance(step_id, str) or not isinstance(raw, dict) or set(raw) != {
            "argv",
            "timeout_seconds",
        }:
            raise CollectionBlocked("control command is malformed")
        argv = raw.get("argv")
        timeout = raw.get("timeout_seconds")
        if (
            not isinstance(argv, list)
            or not (1 <= len(argv) <= 64)
            or not all(
                isinstance(item, str)
                and 0 < len(item) <= 512
                and not any(character in item for character in ("\0", "\r", "\n"))
                for item in argv
            )
            or not isinstance(timeout, int)
            or not 1 <= timeout <= 900
        ):
            raise CollectionBlocked("control command exceeded its safety bounds")
        executable = Path(cast(str, argv[0]))
        if not executable.is_absolute() or executable.name.casefold() in FORBIDDEN_EXECUTABLES:
            raise CollectionBlocked("shells and indirect command launchers are forbidden")
        if challenge not in argv or test_tenant not in argv:
            raise CollectionBlocked("every control command must bind the challenge and test tenant")
        _secure_root_file(executable, executable=True)
        commands[step_id] = {"argv": list(argv), "timeout_seconds": timeout}
    return commands


def _resolve_system_tools() -> dict[str, str]:
    tools: dict[str, str] = {}
    for name in SYSTEM_TOOL_NAMES:
        resolved = shutil.which(name)
        if resolved is None:
            raise CollectionBlocked("a required offline network evidence tool is missing")
        tools[name] = str(_secure_root_file(Path(resolved), executable=True))
    return tools


def _reserve_challenge(state_dir: Path, challenge: str) -> None:
    if state_dir.is_symlink() or not state_dir.is_dir():
        raise CollectionBlocked("challenge state directory is unavailable")
    metadata = state_dir.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise CollectionBlocked("challenge state directory must be root-owned mode 0700")
    marker = state_dir / hashlib.sha256(challenge.encode("ascii")).hexdigest()
    try:
        descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise CollectionBlocked("the one-time challenge has already been consumed") from error
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(datetime.now(UTC).isoformat())
        handle.flush()
        os.fsync(handle.fileno())


def _required_text(value: str | None, label: str) -> str:
    if not value:
        raise CollectionBlocked(f"{label} is required for execution")
    return value


def _execution_context(arguments: argparse.Namespace) -> ExecutionContext:
    if platform.system().casefold() != "linux":
        raise CollectionBlocked("execution is only permitted on the target Linux host")
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise CollectionBlocked("execution requires root")
    if arguments.confirmation != EXECUTION_CONFIRMATION:
        raise CollectionBlocked("explicit execution confirmation did not match")
    challenge = _required_text(arguments.challenge, "challenge")
    tenant = _required_text(arguments.test_tenant, "test tenant")
    project = _required_text(arguments.project_name, "project name")
    expected_host = _required_text(arguments.expected_host_fingerprint, "host fingerprint")
    if CHALLENGE_PATTERN.fullmatch(challenge) is None:
        raise CollectionBlocked("challenge format is invalid")
    if TENANT_PATTERN.fullmatch(tenant) is None:
        raise CollectionBlocked("a dedicated acceptance tenant is required")
    if PROJECT_PATTERN.fullmatch(project) is None or HASH_PATTERN.fullmatch(expected_host) is None:
        raise CollectionBlocked("target identity format is invalid")
    if host_fingerprint() != expected_host:
        raise CollectionBlocked("target host fingerprint did not match")
    repository = Path(_required_text(arguments.repository, "repository")).resolve(strict=True)
    output_dir = Path(_required_text(arguments.output_dir, "output directory"))
    disk_path = Path(_required_text(arguments.disk_path, "disk path")).resolve(strict=True)
    state_dir = Path(_required_text(arguments.challenge_state_dir, "challenge state directory"))
    plan_path = Path(_required_text(arguments.control_plan, "control plan"))
    if output_dir.exists() or output_dir.is_symlink():
        raise CollectionBlocked("evidence output directory must not already exist")
    output_parent = output_dir.parent.resolve(strict=True)
    parent_metadata = output_parent.stat()
    if parent_metadata.st_uid != 0 or parent_metadata.st_mode & stat.S_IWOTH:
        raise CollectionBlocked("evidence parent must be root-owned and not world-writable")
    facts = collect_host_facts(disk_path)
    if (
        facts.platform.casefold() != "linux"
        or facts.architecture.casefold() not in SUPPORTED_ARCHITECTURES
        or facts.logical_cpus < MINIMUM_LOGICAL_CPUS
        or facts.memory_bytes < MINIMUM_VISIBLE_MEMORY_BYTES
        or facts.filesystem_total_bytes < MINIMUM_FILESYSTEM_TOTAL_BYTES
        or facts.filesystem_available_bytes < MINIMUM_FILESYSTEM_AVAILABLE_BYTES
    ):
        raise CollectionBlocked("target host does not meet the 8C/16G/300G acceptance floor")
    identity = collect_worktree_evidence(repository)
    plan = _load_control_plan(plan_path)
    if (
        plan.get("schema_version") != SCHEMA_VERSION
        or plan.get("challenge") != challenge
        or plan.get("test_tenant") != tenant
        or plan.get("project_name") != project
        or plan.get("host_fingerprint") != expected_host
        or plan.get("git_head") != identity.git_head
        or plan.get("content_fingerprint") != identity.content_fingerprint
    ):
        raise CollectionBlocked("control plan is not bound to the active target and source")
    commands = _validate_control_commands(
        plan.get("commands"), challenge=challenge, test_tenant=tenant
    )
    resolver_path = Path("/etc/resolv.conf").resolve(strict=True)
    resolver_metadata = resolver_path.stat()
    if (
        not resolver_path.is_file()
        or resolver_metadata.st_uid != 0
        or resolver_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise CollectionBlocked("resolver configuration is not a protected regular file")
    if resolver_path.stat().st_size > 64 * 1024:
        raise CollectionBlocked("resolver configuration exceeded its safety bound")
    tools = _resolve_system_tools()
    _reserve_challenge(state_dir, challenge)
    return ExecutionContext(
        challenge=challenge,
        test_tenant=tenant,
        project_name=project,
        git_head=identity.git_head,
        content_fingerprint=identity.content_fingerprint,
        host_fingerprint=expected_host,
        commands=commands,
        output_dir=output_dir,
        tools=tools,
        resolver_config=resolver_path.read_text(encoding="utf-8", errors="replace"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan or collect fail-closed offline runtime acceptance evidence"
    )
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirmation")
    parser.add_argument("--challenge")
    parser.add_argument("--test-tenant")
    parser.add_argument("--project-name")
    parser.add_argument("--expected-host-fingerprint")
    parser.add_argument("--repository")
    parser.add_argument("--disk-path")
    parser.add_argument("--control-plan")
    parser.add_argument("--output-dir")
    parser.add_argument(
        "--challenge-state-dir", default="/var/lib/heyi-acceptance/challenges"
    )
    arguments = parser.parse_args(argv)
    if not arguments.execute:
        plan = build_plan()
        if platform.system().casefold() == "linux":
            try:
                plan["observed_host_fingerprint"] = host_fingerprint()
            except CollectionBlocked:
                plan["observed_host_fingerprint"] = None
        print(json.dumps(plan, ensure_ascii=False, sort_keys=True))
        return 0
    try:
        document = execute_collection(_execution_context(arguments))
    except (CollectionBlocked, OSError, ValueError, TypeError):
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "collector": COLLECTOR_ID,
                    "status": "complete",
                    "result": "blocked",
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(document, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
