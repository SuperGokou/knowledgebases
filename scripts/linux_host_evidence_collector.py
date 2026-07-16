#!/usr/bin/env python3
"""Collect signed, fail-closed evidence from the production Linux host.

This collector is deliberately opinionated.  It has no operator supplied command
hooks and never accepts manual check statuses.  Every published check is derived
from a bounded probe against the active ``heyi-kb-offline`` deployment.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import platform
import re
import selectors
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn, cast
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtensionOID

from scripts.acceptance import collect_worktree_evidence
from scripts.acceptance_gate import GateIdentity
from scripts.functional_acceptance import (
    _signature_payload,
    build_deployment_identity,
    external_evidence_target,
    normalize_deployment_base_url,
)
from scripts.host_preflight import (
    MINIMUM_FILESYSTEM_AVAILABLE_BYTES,
    MINIMUM_FILESYSTEM_TOTAL_BYTES,
    MINIMUM_LOGICAL_CPUS,
    MINIMUM_VISIBLE_MEMORY_BYTES,
    collect_host_facts,
)

EVIDENCE_ID = "EXT-LINUX-HOST-001"
COLLECTOR = {"id": "heyi-linux-host", "version": "1.0.0"}
KEY_ID = "linux-host-ed25519"
PROJECT_NAME = "heyi-kb-offline"
OWNER_LABEL = "jiangsu-heyi-knowledgebases"
PERSISTENT_ROOT = Path("/srv/heyi-knowledgebases-offline")
STATE_ROOT = PERSISTENT_ROOT / "state"
RUNTIME_CONTRACT_ROOT = Path("/run/heyi-kb-offline/contracts")
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

REQUIRED_CHECKS = (
    "linux_amd64",
    "cpu_8",
    "memory_16g",
    "filesystem_300g",
    "free_space_240g",
    "offline_images",
    "clamav_database",
    "health_readiness",
    "business_smoke",
    "caddy_ca_persistent_storage",
    "caddy_automatic_certificate_management",
    "caddy_renewal_health",
)

_RUN_ID = re.compile(r"[A-Za-z0-9_-]{8,80}\Z")
_CHALLENGE_ID = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_CHALLENGE_NONCE = re.compile(r"[A-Za-z0-9_-]{32,256}\Z")
_HEX40_64 = re.compile(r"[0-9a-f]{40,64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_MAX_CLOCK_SKEW = timedelta(minutes=5)
_MAX_CHALLENGE_AGE = timedelta(hours=24)
_MINIMUM_LEAF_REMAINING = timedelta(hours=1)
_MAXIMUM_RENEWAL_EVENT_AGE = timedelta(hours=24)
_MAX_COMMAND_OUTPUT = 4 * 1024 * 1024
_MAX_HTTP_BODY = 128 * 1024
_MAX_KEY_BYTES = 32 * 1024
_MAX_CHALLENGE_BYTES = 128 * 1024
_MAX_JSON_BYTES = 4 * 1024 * 1024
_PKCS8_PEM_LABEL = b"PRIVATE" + b" KEY"
_FCHMOD = cast(Callable[[int, int], None] | None, getattr(os, "fchmod", None))


class CollectorBlocked(RuntimeError):
    """A safe, enumerated reason why formal evidence cannot be produced."""

    def __init__(self, code: str) -> None:
        if re.fullmatch(r"[a-z0-9_]{3,80}", code) is None:
            code = "collector_internal_error"
        super().__init__(code)
        self.code = code


def _block(code: str) -> NoReturn:
    raise CollectorBlocked(code)


@dataclass(frozen=True, slots=True)
class CommandResult:
    stdout: bytes
    stderr: bytes


class BoundedCommandRunner:
    """Run fixed argv probes without a shell and without unbounded output."""

    def __init__(self) -> None:
        self.environment = {
            "PATH": SAFE_PATH,
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": "/root",
            "DOCKER_CONFIG": "/run/heyi-kb-offline/docker-config",
        }

    def run(
        self,
        label: str,
        argv: Sequence[str],
        *,
        timeout_seconds: int = 120,
        maximum_output: int = _MAX_COMMAND_OUTPUT,
    ) -> CommandResult:
        if (
            not argv
            or timeout_seconds < 1
            or timeout_seconds > 600
            or maximum_output < 1
            or maximum_output > _MAX_COMMAND_OUTPUT
            or any(not isinstance(item, str) or not item or "\0" in item for item in argv)
        ):
            _block(f"{label}_invalid_command")
        executable = Path(argv[0])
        if not executable.is_absolute() or not _trusted_executable(executable):
            _block(f"{label}_untrusted_executable")

        process = subprocess.Popen(  # noqa: S603 - exact executable and argv are validated above.
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
            close_fds=True,
        )
        if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract.
            process.kill()
            _block(f"{label}_pipe_error")
        streams = {process.stdout: bytearray(), process.stderr: bytearray()}
        selector = selectors.DefaultSelector()
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _terminate(process)
                    _block(f"{label}_timeout")
                for key, _mask in selector.select(min(remaining, 0.25)):
                    stream = cast(Any, key.fileobj)
                    chunk = os.read(stream.fileno(), 64 * 1024)
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    streams[stream].extend(chunk)
                    if sum(len(value) for value in streams.values()) > maximum_output:
                        _terminate(process)
                        _block(f"{label}_output_limit")
            return_code = process.wait(timeout=max(1.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _terminate(process)
            _block(f"{label}_timeout")
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()
        if return_code != 0:
            _block(f"{label}_failed")
        return CommandResult(bytes(streams[process.stdout]), bytes(streams[process.stderr]))


def _terminate(process: subprocess.Popen[bytes]) -> None:
    with suppress_process_errors():
        process.terminate()
        process.wait(timeout=2)
    if process.poll() is None:
        with suppress_process_errors():
            process.kill()
            process.wait(timeout=2)


class suppress_process_errors:
    """Tiny local context manager avoiding exception text in logs."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, *_args: object) -> bool:
        return True


def _trusted_executable(path: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return bool(
        resolved == path
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_nlink == 1
        and not metadata.st_mode & 0o022
        and os.access(path, os.X_OK)
    )


def _tool(name: str) -> str:
    candidate = shutil.which(name, path=SAFE_PATH)
    if candidate is None:
        _block(f"missing_{name.replace('-', '_')}")
    path = Path(candidate).resolve()
    if not _trusted_executable(path):
        _block(f"untrusted_{name.replace('-', '_')}")
    return str(path)


def _inside(parent: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_ancestors(path: Path) -> None:
    current = path.parent
    while True:
        try:
            metadata = current.stat(follow_symlinks=False)
        except OSError:
            _block("protected_input_ancestor_invalid")
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            _block("protected_input_ancestor_invalid")
        if current.parent == current:
            break
        current = current.parent


def read_protected_file(path: Path, repository: Path, maximum_bytes: int) -> bytes:
    if os.name != "posix" or not path.is_absolute():
        _block("protected_input_requires_linux_absolute_path")
    try:
        requested = path
        resolved = path.resolve(strict=True)
        before = path.stat(follow_symlinks=False)
    except OSError:
        _block("protected_input_unavailable")
    if resolved != requested or _inside(repository, resolved):
        _block("protected_input_path_invalid")
    _validate_ancestors(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
        or before.st_size <= 0
        or before.st_size > maximum_bytes
    ):
        _block("protected_input_metadata_invalid")
    nofollow = int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
            or opened.st_uid != 0
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) not in {0o400, 0o600}
        ):
            _block("protected_input_changed")
        payload = b""
        while len(payload) <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload += chunk
        if not payload or len(payload) > maximum_bytes:
            _block("protected_input_size_invalid")
        return payload
    finally:
        os.close(descriptor)


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value or not re.search(r"(?:Z|[+-]\d{2}:\d{2})\Z", value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _validated_deployment_target(target: Mapping[str, object]) -> dict[str, str]:
    if (
        set(target) != {"git_head", "content_fingerprint", "run_id", "deployment"}
        or not isinstance(target.get("git_head"), str)
        or _HEX40_64.fullmatch(cast(str, target["git_head"])) is None
        or not isinstance(target.get("content_fingerprint"), str)
        or _HEX64.fullmatch(cast(str, target["content_fingerprint"])) is None
        or not isinstance(target.get("run_id"), str)
        or _RUN_ID.fullmatch(cast(str, target["run_id"])) is None
    ):
        _block("evidence_target_invalid")
    deployment = target.get("deployment")
    if not isinstance(deployment, Mapping):
        _block("evidence_target_invalid")
    required = {
        "release_id",
        "offline_contract_sha256",
        "image_manifest_sha256",
        "base_url",
        "host_identity",
    }
    if set(deployment) != required or any(
        not isinstance(deployment.get(key), str) for key in required
    ):
        _block("evidence_target_invalid")
    try:
        normalized = build_deployment_identity(
            git_head=cast(str, target["git_head"]),
            offline_contract_sha256=cast(str, deployment["offline_contract_sha256"]),
            image_manifest_sha256=cast(str, deployment["image_manifest_sha256"]),
            base_url=cast(str, deployment["base_url"]),
        )
    except ValueError:
        _block("evidence_target_invalid")
    if dict(deployment) != normalized:
        _block("evidence_target_invalid")
    return normalized


def load_signing_material(
    repository: Path,
    key_path: Path,
    challenge_path: Path,
    target: Mapping[str, object],
    *,
    now: datetime,
) -> tuple[Ed25519PrivateKey, dict[str, object], bytes]:
    _validated_deployment_target(target)
    key_bytes = read_protected_file(key_path, repository, _MAX_KEY_BYTES)
    pkcs8_start = key_bytes.startswith(b"-----BEGIN " + _PKCS8_PEM_LABEL + b"-----\n")
    pkcs8_end = key_bytes.rstrip().endswith(b"-----END " + _PKCS8_PEM_LABEL + b"-----")
    if not pkcs8_start or not pkcs8_end:
        _block("signing_key_not_pkcs8")
    try:
        loaded = serialization.load_pem_private_key(key_bytes, password=None)
    except (TypeError, ValueError):
        _block("signing_key_invalid")
    if not isinstance(loaded, Ed25519PrivateKey):
        _block("signing_key_not_ed25519")

    challenge_bytes = read_protected_file(challenge_path, repository, _MAX_CHALLENGE_BYTES)
    try:
        value = json.loads(challenge_bytes)
    except (UnicodeError, json.JSONDecodeError):
        _block("challenge_json_invalid")
    if not isinstance(value, dict):
        _block("challenge_contract_invalid")
    expected_keys = {
        "schema_version",
        "challenge_id",
        "evidence_id",
        "nonce",
        "issued_at",
        "expires_at",
        "status",
        "target",
    }
    challenge_target = value.get("target")
    challenge_id = value.get("challenge_id")
    nonce = value.get("nonce")
    if (
        set(value) != expected_keys
        or value.get("schema_version") != 1
        or value.get("evidence_id") != EVIDENCE_ID
        or value.get("status") != "issued"
        or not isinstance(challenge_id, str)
        or _CHALLENGE_ID.fullmatch(challenge_id) is None
        or challenge_path.name != f"{challenge_id}.json"
        or not isinstance(nonce, str)
        or _CHALLENGE_NONCE.fullmatch(nonce) is None
        or not isinstance(challenge_target, dict)
        or challenge_target != dict(target)
        or set(challenge_target) != {"git_head", "content_fingerprint", "run_id", "deployment"}
    ):
        _block("challenge_binding_invalid")
    issued_at = _timestamp(value.get("issued_at"))
    expires_at = _timestamp(value.get("expires_at"))
    if (
        issued_at is None
        or expires_at is None
        or issued_at > now + _MAX_CLOCK_SKEW
        or expires_at <= now
        or expires_at <= issued_at
        or expires_at - issued_at > _MAX_CHALLENGE_AGE
    ):
        _block("challenge_time_invalid")
    return loaded, value, challenge_bytes


def claim_challenge(challenge_path: Path, challenge: Mapping[str, object], raw: bytes) -> Path:
    challenge_id = cast(str, challenge["challenge_id"])
    claim_path = challenge_path.with_name(f"{challenge_id}.collector-claimed")
    payload = {
        "schema_version": 1,
        "collector": COLLECTOR,
        "evidence_id": EVIDENCE_ID,
        "challenge_id": challenge_id,
        "challenge_sha256": hashlib.sha256(raw).hexdigest(),
        "target": challenge["target"],
        "claimed_at": datetime.now(UTC).isoformat(),
    }
    descriptor = -1
    try:
        descriptor = os.open(
            claim_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_NOFOLLOW", 0)),
            0o400,
        )
        os.write(descriptor, _json_bytes(payload))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        _fsync_directory(claim_path.parent)
    except FileExistsError:
        _block("challenge_already_claimed")
    except OSError:
        _block("challenge_claim_failed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return claim_path


def _json_bytes(value: object, *, pretty: bool = False) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=None if pretty else (",", ":"),
            indent=2 if pretty else None,
        )
        + "\n"
    ).encode("utf-8")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0)))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _secure_output_parent(path: Path) -> None:
    path.mkdir(mode=0o750, parents=True, exist_ok=True)
    current = path
    repository = path.parents[2]
    while _inside(repository, current):
        metadata = current.stat(follow_symlinks=False)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            _block("evidence_directory_unsafe")
        if current == repository:
            break
        current = current.parent


def _atomic_json(path: Path, value: object, *, mode: int = 0o400) -> None:
    temporary: Path | None = None
    descriptor = -1
    try:
        descriptor, temporary_text = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_text)
        if _FCHMOD is None:
            _block("atomic_publish_requires_fchmod")
        _FCHMOD(descriptor, 0o600)
        payload = _json_bytes(value, pretty=True)
        os.write(descriptor, payload)
        os.fsync(descriptor)
        _FCHMOD(descriptor, mode)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        temporary = None
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _unlink_and_sync(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    _fsync_directory(path.parent)


def _json_result(result: CommandResult, code: str) -> dict[str, Any]:
    if len(result.stdout) > _MAX_JSON_BYTES:
        _block(f"{code}_json_too_large")
    try:
        value = json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError):
        _block(f"{code}_json_invalid")
    if not isinstance(value, dict):
        _block(f"{code}_contract_invalid")
    return value


def _active_release(repository: Path, runner: BoundedCommandRunner) -> dict[str, Any]:
    helper = repository / "deploy/tencent/offline-recovery-state.py"
    result = runner.run(
        "active_release",
        [_tool("python3"), "-I", str(helper), "select"],
        timeout_seconds=30,
    )
    active = _json_result(result, "active_release")
    required = {
        "selection",
        "schema_version",
        "kind",
        "project_name",
        "transaction_id",
        "contract_sha256",
        "runtime_sha256",
        "release_sha256",
        "manifest_sha256",
        "compose_profile",
        "compose_config_sha256",
        "project_inventory_sha256",
        "egress_proof_sha256",
        "active_provider_snapshot",
        "status",
    }
    if (
        set(active) != required
        or active.get("selection") != "active"
        or active.get("schema_version") != 2
        or active.get("kind") != "offline-active-release"
        or active.get("project_name") != PROJECT_NAME
        or active.get("status") != "committed"
        or active.get("compose_profile") not in {"strict-offline", "controlled-egress"}
        or any(
            _HEX64.fullmatch(str(active.get(key, ""))) is None
            for key in (
                "contract_sha256",
                "runtime_sha256",
                "release_sha256",
                "manifest_sha256",
                "compose_config_sha256",
                "project_inventory_sha256",
                "egress_proof_sha256",
            )
        )
    ):
        _block("active_release_contract_invalid")
    return active


def _root_json(path: Path, maximum_bytes: int = _MAX_JSON_BYTES) -> dict[str, Any]:
    try:
        before = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError:
        _block("root_receipt_unavailable")
    if (
        resolved != path
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
        or before.st_size <= 0
        or before.st_size > maximum_bytes
    ):
        _block("root_receipt_unsafe")
    nofollow = int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != before.st_dev or opened.st_ino != before.st_ino:
            _block("root_receipt_changed")
        payload = os.read(descriptor, maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if len(payload) > maximum_bytes:
        _block("root_receipt_too_large")
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError):
        _block("root_receipt_json_invalid")
    if not isinstance(value, dict):
        _block("root_receipt_contract_invalid")
    return value


def _validate_release_binding(active: Mapping[str, Any], git_head: str) -> dict[str, object]:
    receipt_path = STATE_ROOT / f"registry-import-{active['manifest_sha256']}.json"
    receipt = _root_json(receipt_path)
    required = {
        "schema_version",
        "kind",
        "status",
        "release_sequence",
        "release_id",
        "release_git_sha",
        "release_schema_head",
        "release_sha256",
        "manifest_sha256",
        "release_assets_sha256",
        "checksum_set_sha256",
        "signature_sha256",
        "trusted_key_sha256",
    }
    if (
        set(receipt) != required
        or receipt.get("schema_version") != 2
        or receipt.get("kind") != "offline-registry-import"
        or receipt.get("status") != "verified"
        or receipt.get("release_git_sha") != git_head
        or receipt.get("release_sha256") != active.get("release_sha256")
        or receipt.get("manifest_sha256") != active.get("manifest_sha256")
        or not isinstance(receipt.get("release_sequence"), int)
    ):
        _block("active_release_target_mismatch")
    return {
        "release_sequence": receipt["release_sequence"],
        "release_id": receipt["release_id"],
        "release_git_sha": receipt["release_git_sha"],
        "release_schema_head": receipt["release_schema_head"],
    }


def _validate_deployment_binding(
    active: Mapping[str, Any],
    config: Mapping[str, Any],
    target: Mapping[str, object],
) -> dict[str, str]:
    deployment = _validated_deployment_target(target)
    if active.get("contract_sha256") != deployment["offline_contract_sha256"]:
        _block("deployment_contract_mismatch")
    if active.get("manifest_sha256") != deployment["image_manifest_sha256"]:
        _block("deployment_manifest_mismatch")
    origin, _objects_origin, _ca_path = _compose_origins(config)
    normalized_origin = normalize_deployment_base_url(origin)
    if normalized_origin != deployment["base_url"]:
        _block("deployment_base_url_mismatch")
    hostname = urlsplit(normalized_origin).hostname if normalized_origin is not None else None
    if hostname is None or hostname.casefold().rstrip(".") != deployment["host_identity"]:
        _block("deployment_host_identity_mismatch")
    return {
        "release_id": deployment["release_id"],
        "offline_contract_sha256": cast(str, active["contract_sha256"]),
        "image_manifest_sha256": cast(str, active["manifest_sha256"]),
        "base_url": normalized_origin,
        "host_identity": hostname.casefold().rstrip("."),
    }


def _stage_contract(
    repository: Path, active: Mapping[str, Any], runner: BoundedCommandRunner
) -> Path:
    helper = repository / "deploy/tencent/offline-recovery-state.py"
    result = runner.run(
        "stage_contract",
        [
            _tool("python3"),
            "-I",
            str(helper),
            "stage-contract",
            str(active["contract_sha256"]),
            str(RUNTIME_CONTRACT_ROOT),
        ],
        timeout_seconds=120,
    )
    try:
        path = Path(result.stdout.decode("ascii").strip()).resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except (OSError, UnicodeError):
        _block("staged_contract_invalid")
    if (
        not _inside(RUNTIME_CONTRACT_ROOT, path)
        or path.parent != RUNTIME_CONTRACT_ROOT
        or not path.name.startswith("contract.")
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _block("staged_contract_unsafe")
    return path


def _cleanup_staged_contract(path: Path) -> None:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return
    if (
        resolved.parent != RUNTIME_CONTRACT_ROOT
        or not resolved.name.startswith("contract.")
        or resolved.is_symlink()
    ):
        return
    os.chmod(resolved, 0o700)
    for directory in resolved.rglob("*"):
        if directory.is_dir() and not directory.is_symlink():
            os.chmod(directory, 0o700)
    shutil.rmtree(resolved)
    _fsync_directory(RUNTIME_CONTRACT_ROOT)


def _compose_argv(staged: Path, profile: str, *arguments: str) -> list[str]:
    argv = [
        _tool("docker"),
        "compose",
        "--project-name",
        PROJECT_NAME,
        "--env-file",
        str(staged / "runtime.env"),
        "--env-file",
        str(staged / "release.env"),
        "--file",
        str(staged / "release/deploy/tencent/compose.offline.yml"),
    ]
    if profile == "controlled-egress":
        argv.extend(("--profile", "controlled-egress"))
    argv.extend(arguments)
    return argv


def _compose_config(
    staged: Path, active: Mapping[str, Any], runner: BoundedCommandRunner
) -> dict[str, Any]:
    result = runner.run(
        "compose_config",
        _compose_argv(staged, str(active["compose_profile"]), "config", "--format", "json"),
        timeout_seconds=60,
    )
    config = _json_result(result, "compose_config")
    canonical = json.dumps(
        config, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    if hashlib.sha256(canonical).hexdigest() != active["compose_config_sha256"]:
        _block("compose_config_receipt_mismatch")
    return config


def _compose_hashes(
    staged: Path, active: Mapping[str, Any], runner: BoundedCommandRunner
) -> dict[str, str]:
    result = runner.run(
        "compose_hashes",
        _compose_argv(
            staged,
            str(active["compose_profile"]),
            "config",
            "--hash",
            "*",
        ),
        timeout_seconds=60,
    )
    hashes: dict[str, str] = {}
    try:
        lines = result.stdout.decode("ascii").splitlines()
    except UnicodeError:
        _block("compose_hashes_invalid")
    for line in lines:
        parts = line.split()
        if len(parts) != 2 or parts[0] in hashes or _HEX64.fullmatch(parts[1]) is None:
            _block("compose_hashes_invalid")
        hashes[parts[0]] = parts[1]
    if not hashes:
        _block("compose_hashes_invalid")
    return hashes


def _service(config: Mapping[str, Any], name: str) -> dict[str, Any]:
    services = config.get("services")
    value = services.get(name) if isinstance(services, dict) else None
    if not isinstance(value, dict):
        _block(f"compose_service_{name.replace('-', '_')}_missing")
    return value


def _volume_source(service: Mapping[str, Any], target: str) -> Path:
    volumes = service.get("volumes")
    match = (
        next(
            (item for item in volumes if isinstance(item, dict) and item.get("target") == target),
            None,
        )
        if isinstance(volumes, list)
        else None
    )
    source = match.get("source") if isinstance(match, dict) else None
    if not isinstance(source, str) or not Path(source).is_absolute():
        _block("active_data_mount_missing")
    return Path(source)


def _validate_data_filesystem(config: Mapping[str, Any], disk_path: Path) -> dict[str, object]:
    try:
        persistent = PERSISTENT_ROOT.resolve(strict=True)
        requested = disk_path.resolve(strict=True)
        persistent_stat = PERSISTENT_ROOT.stat(follow_symlinks=False)
    except OSError:
        _block("persistent_root_unavailable")
    if (
        persistent != PERSISTENT_ROOT
        or requested != persistent
        or disk_path != PERSISTENT_ROOT
        or not stat.S_ISDIR(persistent_stat.st_mode)
    ):
        _block("disk_path_must_be_persistent_root")
    expected = {
        "postgres": ("/var/lib/postgresql/data", persistent / "data/postgres"),
        "minio": ("/data", persistent / "data/minio"),
        "proxy": ("/data", persistent / "data/caddy-data"),
    }
    observed: dict[str, str] = {}
    for service_name, (target, expected_source) in expected.items():
        source = _volume_source(_service(config, service_name), target)
        try:
            resolved = source.resolve(strict=True)
            metadata = resolved.stat(follow_symlinks=False)
        except OSError:
            _block("active_data_mount_unavailable")
        if (
            resolved != expected_source
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != persistent_stat.st_dev
        ):
            _block("active_data_mount_filesystem_mismatch")
        observed[service_name] = hashlib.sha256(str(resolved).encode()).hexdigest()
    return {
        "persistent_root_sha256": hashlib.sha256(str(persistent).encode()).hexdigest(),
        "filesystem_device": persistent_stat.st_dev,
        "mount_sources_sha256": observed,
    }


def _normalize_command(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    _block("container_command_contract_invalid")


def _image_inspect(image: str, runner: BoundedCommandRunner) -> dict[str, Any]:
    result = runner.run(
        "image_inspect",
        [_tool("docker"), "image", "inspect", image],
        timeout_seconds=30,
    )
    try:
        values = json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError):
        _block("image_inspect_invalid")
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        _block("image_inspect_invalid")
    return values[0]


def _validate_container_binding(
    inspected: Mapping[str, Any],
    service_name: str,
    service: Mapping[str, Any],
    expected_config_hash: str,
    runner: BoundedCommandRunner,
) -> dict[str, object]:
    image = service.get("image")
    if (
        not isinstance(image, str)
        or re.fullmatch(r"127\.0\.0\.1:5000/.+@sha256:[0-9a-f]{64}", image) is None
    ):
        _block(f"{service_name}_expected_image_invalid")
    image_metadata = _image_inspect(image, runner)
    image_id = image_metadata.get("Id")
    image_config = image_metadata.get("Config")
    container_config = inspected.get("Config")
    labels = container_config.get("Labels") if isinstance(container_config, dict) else None
    if (
        not isinstance(image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
        or not isinstance(image_config, dict)
        or not isinstance(container_config, dict)
        or not isinstance(labels, dict)
        or inspected.get("Image") != image_id
        or container_config.get("Image") != image
        or labels.get("com.docker.compose.config-hash") != expected_config_hash
    ):
        _block(f"{service_name}_container_release_binding_invalid")
    expected_entrypoint = (
        service.get("entrypoint") if "entrypoint" in service else image_config.get("Entrypoint")
    )
    expected_command = service.get("command") if "command" in service else image_config.get("Cmd")
    if _normalize_command(container_config.get("Entrypoint")) != _normalize_command(
        expected_entrypoint
    ) or _normalize_command(container_config.get("Cmd")) != _normalize_command(expected_command):
        _block(f"{service_name}_container_command_mismatch")
    return {
        "image_reference_sha256": hashlib.sha256(image.encode()).hexdigest(),
        "image_id": image_id,
        "compose_service_hash": expected_config_hash,
        "entrypoint_sha256": hashlib.sha256(
            json.dumps(_normalize_command(expected_entrypoint)).encode()
        ).hexdigest(),
        "command_sha256": hashlib.sha256(
            json.dumps(_normalize_command(expected_command)).encode()
        ).hexdigest(),
    }


def _offline_images(
    staged: Path,
    active: Mapping[str, Any],
    config: Mapping[str, Any],
    runner: BoundedCommandRunner,
) -> dict[str, object]:
    verifier = staged / "release/deploy/tencent/verify-offline-images.sh"
    runner.run(
        "offline_images",
        [
            _tool("sh"),
            str(verifier),
            "verify",
            "--contract-dir",
            str(staged),
            "--contract-sha256",
            str(active["contract_sha256"]),
        ],
        timeout_seconds=300,
    )
    services = config.get("services")
    if not isinstance(services, dict):
        _block("offline_images_compose_invalid")
    images = sorted(
        {str(value.get("image")) for value in services.values() if isinstance(value, dict)}
    )
    if not images or any(
        re.fullmatch(r"127\.0\.0\.1:5000/.+@sha256:[0-9a-f]{64}", image) is None for image in images
    ):
        _block("offline_images_not_digest_pinned")
    return {
        "probe": "verify-offline-images.sh@active-contract",
        "contract_sha256": active["contract_sha256"],
        "compose_config_sha256": active["compose_config_sha256"],
        "image_count": len(images),
        "image_set_sha256": hashlib.sha256("\n".join(images).encode()).hexdigest(),
        "platform": "linux/amd64",
    }


def _container_id(service: str, runner: BoundedCommandRunner) -> str:
    result = runner.run(
        f"{service}_container_list",
        [
            _tool("docker"),
            "ps",
            "--no-trunc",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={PROJECT_NAME}",
            "--filter",
            f"label=com.docker.compose.service={service}",
            "--filter",
            "status=running",
        ],
        timeout_seconds=30,
        maximum_output=4096,
    )
    identifiers = [
        line.strip()
        for line in result.stdout.decode("ascii", "strict").splitlines()
        if line.strip()
    ]
    if len(identifiers) != 1 or _CONTAINER_ID.fullmatch(identifiers[0]) is None:
        _block(f"{service}_container_not_unique")
    return identifiers[0]


def _container_inspect(service: str, runner: BoundedCommandRunner) -> dict[str, Any]:
    identifier = _container_id(service, runner)
    result = runner.run(
        f"{service}_container_inspect",
        [_tool("docker"), "inspect", identifier],
        timeout_seconds=30,
    )
    try:
        values = json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError):
        _block(f"{service}_inspect_json_invalid")
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        _block(f"{service}_inspect_contract_invalid")
    inspected = values[0]
    labels = inspected.get("Config", {}).get("Labels")
    state = inspected.get("State")
    if (
        inspected.get("Id") != identifier
        or not isinstance(labels, dict)
        or labels.get("com.docker.compose.project") != PROJECT_NAME
        or labels.get("com.docker.compose.service") != service
        or labels.get("io.heyi.knowledgebases.owner") != OWNER_LABEL
        or labels.get("io.heyi.knowledgebases.stack") != "offline"
        or labels.get("com.docker.compose.oneoff") in {"True", "true"}
        or not isinstance(state, dict)
        or state.get("Status") != "running"
    ):
        _block(f"{service}_container_identity_invalid")
    inspected["_verified_id"] = identifier
    return inspected


def _clamav(
    staged: Path,
    active: Mapping[str, Any],
    config: Mapping[str, Any],
    service_hashes: Mapping[str, str],
    runner: BoundedCommandRunner,
) -> dict[str, object]:
    runner.run(
        "clamav_database",
        _compose_argv(
            staged,
            str(active["compose_profile"]),
            "--profile",
            "ops",
            "run",
            "--pull",
            "never",
            "--rm",
            "--no-deps",
            "clamav-db-preflight",
        ),
        timeout_seconds=300,
    )
    inspected = _container_inspect("clamd", runner)
    expected_hash = service_hashes.get("clamd")
    if not isinstance(expected_hash, str):
        _block("clamd_compose_hash_missing")
    binding = _validate_container_binding(
        inspected,
        "clamd",
        _service(config, "clamd"),
        expected_hash,
        runner,
    )
    state = inspected.get("State")
    health = state.get("Health") if isinstance(state, dict) else None
    container_config = inspected.get("Config")
    image = container_config.get("Image") if isinstance(container_config, dict) else None
    if (
        not isinstance(health, dict)
        or health.get("Status") != "healthy"
        or not isinstance(image, str)
        or re.fullmatch(r"127\.0\.0\.1:5000/.+@sha256:[0-9a-f]{64}", image) is None
    ):
        _block("clamav_runtime_unhealthy")
    return {
        "database_probe": "clamav-db-preflight",
        "database_probe_network": "none",
        "runtime_service": "clamd",
        "runtime_health": "healthy",
        "image_reference_sha256": hashlib.sha256(image.encode()).hexdigest(),
        "release_binding": binding,
    }


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _request(
    origin: str,
    path: str,
    context: ssl.SSLContext,
    *,
    method: str = "GET",
    body: bytes | None = None,
) -> tuple[int, str, bytes]:
    request = urllib.request.Request(
        f"{origin}{path}",
        data=body,
        method=method,
        headers={"Accept": "application/json,text/html", "Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _RejectRedirects(),
    )
    try:
        response = opener.open(request, timeout=8)
    except urllib.error.HTTPError as exc:
        payload = exc.read(_MAX_HTTP_BODY + 1)
        return exc.code, exc.headers.get_content_type(), payload
    except (OSError, ssl.SSLError, urllib.error.URLError):
        _block("strict_https_request_failed")
    with response:
        payload = response.read(_MAX_HTTP_BODY + 1)
        return response.status, response.headers.get_content_type(), payload


def _compose_origins(config: Mapping[str, Any]) -> tuple[str, str, Path]:
    web = _service(config, "web")
    proxy = _service(config, "proxy")
    web_environment = web.get("environment")
    proxy_environment = proxy.get("environment")
    if not isinstance(web_environment, dict) or not isinstance(proxy_environment, dict):
        _block("compose_origin_environment_invalid")
    origin = web_environment.get("KB_PUBLIC_ORIGIN")
    objects_port = str(proxy_environment.get("KB_OBJECTS_HTTPS_PORT", ""))
    if not isinstance(origin, str) or not objects_port.isdigit():
        _block("compose_origin_invalid")
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or parsed.hostname is None or parsed.username or parsed.password:
        _block("compose_origin_invalid")
    objects_origin = f"https://{parsed.hostname}:{objects_port}"
    volumes = proxy.get("volumes")
    if not isinstance(volumes, list):
        _block("caddy_data_mount_missing")
    data_mount = next(
        (item for item in volumes if isinstance(item, dict) and item.get("target") == "/data"),
        None,
    )
    source = data_mount.get("source") if isinstance(data_mount, dict) else None
    if not isinstance(source, str) or not Path(source).is_absolute():
        _block("caddy_data_mount_invalid")
    return origin.rstrip("/"), objects_origin, Path(source) / "caddy/pki/authorities/local/root.crt"


def _read_public_ca(path: Path) -> tuple[bytes, os.stat_result]:
    try:
        resolved = path.resolve(strict=True)
        before = path.stat(follow_symlinks=False)
    except OSError:
        _block("caddy_ca_unavailable")
    if (
        resolved != path
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or before.st_size <= 0
        or before.st_size > 1024 * 1024
    ):
        _block("caddy_ca_metadata_invalid")
    descriptor = os.open(path, os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0)))
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != before.st_dev or opened.st_ino != before.st_ino:
            _block("caddy_ca_changed")
        payload = os.read(descriptor, 1024 * 1024 + 1)
    finally:
        os.close(descriptor)
    try:
        x509.load_pem_x509_certificate(payload)
    except ValueError:
        _block("caddy_ca_invalid")
    return payload, before


def _readiness_and_business(
    config: Mapping[str, Any],
) -> tuple[dict[str, object], dict[str, object]]:
    origin, objects_origin, ca_path = _compose_origins(config)
    ca_bytes, _metadata = _read_public_ca(ca_path)
    context = ssl.create_default_context(cafile=str(ca_path))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    ready_status, ready_type, ready_body = _request(origin, "/health/ready", context)
    object_status, _object_type, object_body = _request(
        objects_origin, "/minio/health/ready", context
    )
    try:
        ready_payload = json.loads(ready_body)
    except (UnicodeError, json.JSONDecodeError):
        _block("readiness_payload_invalid")
    if (
        ready_status != 200
        or ready_type != "application/json"
        or ready_payload != {"status": "ready"}
        or object_status != 200
        or len(ready_body) > _MAX_HTTP_BODY
        or len(object_body) > _MAX_HTTP_BODY
    ):
        _block("readiness_failed")

    login_status, login_type, login_body = _request(origin, "/login", context)
    openapi_status, openapi_type, openapi_body = _request(origin, "/openapi.json", context)
    try:
        openapi = json.loads(openapi_body)
    except (UnicodeError, json.JSONDecodeError):
        _block("business_openapi_invalid")
    paths = openapi.get("paths") if isinstance(openapi, dict) else None
    required_paths = {
        "/api/v1/auth/token",
        "/api/v1/public/chat/query",
        "/api/v1/public/knowledge-bases/{knowledge_base_id}/search",
    }
    if (
        login_status != 200
        or login_type != "text/html"
        or not login_body
        or openapi_status != 200
        or openapi_type != "application/json"
        or not isinstance(paths, dict)
        or not required_paths.issubset(paths)
        or len(login_body) > _MAX_HTTP_BODY
        or len(openapi_body) > _MAX_HTTP_BODY
    ):
        _block("business_smoke_failed")
    ca_after, _after_metadata = _read_public_ca(ca_path)
    if hashlib.sha256(ca_bytes).digest() != hashlib.sha256(ca_after).digest():
        _block("caddy_ca_changed_during_probe")
    return (
        {
            "public_readiness": 200,
            "object_readiness": 200,
            "strict_ca_verification": True,
            "ca_sha256": hashlib.sha256(ca_bytes).hexdigest(),
        },
        {
            "login_status": 200,
            "login_content_type": "text/html",
            "openapi_status": 200,
            "required_route_count": len(required_paths),
            "openapi_sha256": hashlib.sha256(openapi_body).hexdigest(),
        },
    )


def _mount(inspected: Mapping[str, Any], destination: str) -> dict[str, Any]:
    mounts = inspected.get("Mounts")
    match = (
        next(
            (
                item
                for item in mounts
                if isinstance(item, dict) and item.get("Destination") == destination
            ),
            None,
        )
        if isinstance(mounts, list)
        else None
    )
    if not isinstance(match, dict):
        _block("caddy_persistent_mount_missing")
    return match


def _tls_leaf(origin: str, ca_path: Path, *, now: datetime) -> dict[str, object]:
    parsed = urlsplit(origin)
    host = parsed.hostname
    port = parsed.port or 443
    if parsed.scheme != "https" or host is None:
        _block("tls_origin_invalid")
    context = ssl.create_default_context(cafile=str(ca_path))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    try:
        with (
            socket.create_connection((host, port), timeout=8) as raw,
            context.wrap_socket(raw, server_hostname=host) as secured,
        ):
            certificate_der = secured.getpeercert(binary_form=True)
            protocol = secured.version()
    except (OSError, ssl.SSLError):
        _block("tls_handshake_failed")
    if not certificate_der or protocol not in {"TLSv1.2", "TLSv1.3"}:
        _block("tls_handshake_contract_invalid")
    certificate = x509.load_der_x509_certificate(certificate_der)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    try:
        extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        _block("tls_san_missing")
    alternative_names = cast(x509.SubjectAlternativeName, extension)
    dns_names = alternative_names.get_values_for_type(x509.DNSName)
    ip_names = [str(value) for value in alternative_names.get_values_for_type(x509.IPAddress)]
    try:
        expected_ip = str(ipaddress.ip_address(host))
    except ValueError:
        expected_ip = None
    if (
        not_before > now + _MAX_CLOCK_SKEW
        or not_after < now + _MINIMUM_LEAF_REMAINING
        or (expected_ip is not None and expected_ip not in ip_names)
        or (expected_ip is None and host not in dns_names)
    ):
        _block("tls_leaf_validity_or_san_invalid")
    return {
        "origin_role": "runtime",
        "host": host,
        "port": port,
        "protocol": protocol,
        "leaf_sha256": hashlib.sha256(certificate_der).hexdigest(),
        "serial_hex": format(certificate.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "san_dns": sorted(dns_names),
        "san_ip": sorted(ip_names),
    }


def _log_timestamp(record: Mapping[str, Any]) -> datetime | None:
    value = record.get("ts")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(float(value), UTC)
        except (OverflowError, OSError, ValueError):
            return None
    return _timestamp(record.get("docker_ts"))


def _caddy_logs(identifier: str, runner: BoundedCommandRunner) -> list[dict[str, Any]]:
    result = runner.run(
        "caddy_logs",
        [
            _tool("docker"),
            "logs",
            "--timestamps",
            "--since",
            "24h",
            identifier,
        ],
        timeout_seconds=60,
    )
    records: list[dict[str, Any]] = []
    for raw in (result.stdout + b"\n" + result.stderr).splitlines():
        try:
            line = raw.decode("utf-8")
        except UnicodeError:
            continue
        brace = line.find("{")
        if brace < 0:
            continue
        try:
            value = json.loads(line[brace:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            prefix = line[:brace].strip()
            if prefix:
                value["docker_ts"] = prefix.split(maxsplit=1)[0]
            records.append(value)
    if not records:
        _block("caddy_structured_logs_unavailable")
    return records


def _subjects(record: Mapping[str, Any]) -> set[str]:
    values: set[str] = set()
    for key in ("identifier", "identifiers", "subjects", "domains"):
        value = record.get(key)
        if isinstance(value, str):
            values.add(value)
        elif isinstance(value, list):
            values.update(item for item in value if isinstance(item, str))
    return values


def _runtime_caddy_config(identifier: str, runner: BoundedCommandRunner) -> dict[str, Any]:
    result = runner.run(
        "caddy_runtime_config",
        [
            _tool("docker"),
            "exec",
            identifier,
            "caddy",
            "adapt",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
        ],
        timeout_seconds=30,
    )
    return _json_result(result, "caddy_runtime_config")


def _contains_internal_issuer(value: object) -> bool:
    if isinstance(value, dict):
        if value.get("module") == "internal":
            return True
        return any(_contains_internal_issuer(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_internal_issuer(item) for item in value)
    return False


def _caddy_evidence(
    staged: Path,
    active: Mapping[str, Any],
    config: Mapping[str, Any],
    service_hashes: Mapping[str, str],
    runner: BoundedCommandRunner,
    *,
    now: datetime,
) -> dict[str, object]:
    origin, objects_origin, ca_path = _compose_origins(config)
    inspected = _container_inspect("proxy", runner)
    identifier = cast(str, inspected["_verified_id"])
    expected_hash = service_hashes.get("proxy")
    if not isinstance(expected_hash, str):
        _block("proxy_compose_hash_missing")
    release_binding = _validate_container_binding(
        inspected,
        "proxy",
        _service(config, "proxy"),
        expected_hash,
        runner,
    )
    data_mount = _mount(inspected, "/data")
    config_mount = _mount(inspected, "/config")
    caddyfile_mount = _mount(inspected, "/etc/caddy/Caddyfile")
    expected_data = ca_path.parents[4]
    if (
        data_mount.get("Type") != "bind"
        or data_mount.get("RW") is not True
        or Path(str(data_mount.get("Source", ""))).resolve() != expected_data.resolve()
        or config_mount.get("Type") != "bind"
        or config_mount.get("RW") is not True
        or caddyfile_mount.get("Type") != "bind"
        or caddyfile_mount.get("RW") is not False
    ):
        _block("caddy_persistent_mount_invalid")
    actual_caddyfile = Path(str(caddyfile_mount.get("Source", "")))
    expected_caddyfile = staged / "release/deploy/tencent/Caddyfile.offline"
    try:
        actual_metadata = actual_caddyfile.stat(follow_symlinks=False)
        expected_metadata = expected_caddyfile.stat(follow_symlinks=False)
        actual_bytes = actual_caddyfile.read_bytes()
        expected_bytes = expected_caddyfile.read_bytes()
    except OSError:
        _block("caddyfile_binding_unavailable")
    if (
        actual_caddyfile.is_symlink()
        or expected_caddyfile.is_symlink()
        or not stat.S_ISREG(actual_metadata.st_mode)
        or not stat.S_ISREG(expected_metadata.st_mode)
        or actual_metadata.st_uid != 0
        or actual_metadata.st_mode & 0o022
        or len(actual_bytes) > 1024 * 1024
        or actual_bytes != expected_bytes
    ):
        _block("caddyfile_binding_mismatch")
    ca_bytes, _ca_metadata = _read_public_ca(ca_path)
    runtime_config = _runtime_caddy_config(identifier, runner)
    if not _contains_internal_issuer(runtime_config):
        _block("caddy_internal_automation_missing")

    parsed_origin = urlsplit(origin)
    expected_host = parsed_origin.hostname
    if expected_host is None:
        _block("caddy_expected_host_invalid")
    leaves = {
        "web": _tls_leaf(origin, ca_path, now=now),
        "api": _tls_leaf(origin, ca_path, now=now),
        "objects": _tls_leaf(objects_origin, ca_path, now=now),
    }
    records = _caddy_logs(identifier, runner)
    automatic = [
        record
        for record in records
        if record.get("msg") == "enabling automatic TLS certificate management"
        and expected_host in _subjects(record)
    ]
    successes = [
        record
        for record in records
        if record.get("logger") == "tls.renew"
        and record.get("msg") == "certificate renewed successfully"
        and expected_host in _subjects(record)
        and _log_timestamp(record) is not None
    ]
    if not automatic or not successes:
        _block("caddy_verified_renewal_event_missing")
    success = max(successes, key=lambda item: cast(datetime, _log_timestamp(item)))
    success_at = cast(datetime, _log_timestamp(success))
    if success_at > now + _MAX_CLOCK_SKEW or now - success_at > _MAXIMUM_RENEWAL_EVENT_AGE:
        _block("caddy_verified_renewal_event_stale")
    reloads = [
        record
        for record in records
        if record.get("logger") == "tls"
        and record.get("msg") == "reloading managed certificate"
        and expected_host in _subjects(record)
        and (_log_timestamp(record) or datetime.min.replace(tzinfo=UTC)) >= success_at
    ]
    replacements = [
        record
        for record in records
        if record.get("logger") == "tls.cache"
        and record.get("msg") == "replaced certificate in cache"
        and expected_host in _subjects(record)
        and (_log_timestamp(record) or datetime.min.replace(tzinfo=UTC)) >= success_at
    ]
    later_errors = [
        record
        for record in records
        if record.get("level") == "error"
        and str(record.get("logger", "")).startswith("tls")
        and (_log_timestamp(record) or datetime.min.replace(tzinfo=UTC)) >= success_at
        and expected_host in _subjects(record)
    ]
    if not reloads or not replacements or later_errors:
        _block("caddy_renewal_reload_unhealthy")
    replacement = max(replacements, key=lambda item: cast(datetime, _log_timestamp(item)))
    new_expiration = replacement.get("new_expiration")
    if not isinstance(new_expiration, (int, float)) or isinstance(new_expiration, bool):
        _block("caddy_renewal_expiration_missing")
    leaf_expirations: set[int] = set()
    for value in leaves.values():
        leaf_expiration = _timestamp(value["not_after"])
        if leaf_expiration is not None:
            leaf_expirations.add(int(leaf_expiration.timestamp()))
    expiration_matches = any(abs(int(new_expiration) - item) <= 300 for item in leaf_expirations)
    if not leaf_expirations or not expiration_matches:
        _block("caddy_renewal_leaf_mismatch")
    ca_after, _after = _read_public_ca(ca_path)
    if ca_after != ca_bytes:
        _block("caddy_ca_changed_during_probe")
    return {
        "container_id_sha256": hashlib.sha256(identifier.encode()).hexdigest(),
        "persistent_data_mount_sha256": hashlib.sha256(str(expected_data).encode()).hexdigest(),
        "persistent_config_mount": True,
        "ca_sha256": hashlib.sha256(ca_bytes).hexdigest(),
        "automatic_internal_issuer": True,
        "automatic_management_log_event": True,
        "renewal_success_at": success_at.isoformat(),
        "renewal_reload_event": True,
        "renewal_cache_replace_event": True,
        "renewed_leaf_expiration": int(new_expiration),
        "leaf_endpoints": leaves,
        "minimum_remaining_seconds": int(_MINIMUM_LEAF_REMAINING.total_seconds()),
        "release_binding": release_binding,
        "caddyfile_sha256": hashlib.sha256(actual_bytes).hexdigest(),
        "active_compose_config_sha256": active["compose_config_sha256"],
    }


def _host_artifact(disk_path: Path) -> dict[str, object]:
    if disk_path != PERSISTENT_ROOT:
        _block("disk_path_must_be_persistent_root")
    try:
        facts = collect_host_facts(disk_path)
    except (OSError, RuntimeError, ValueError):
        _block("host_facts_unavailable")
    checks = {
        "linux_amd64": facts.platform.casefold() == "linux"
        and facts.architecture.casefold() in {"amd64", "x86_64"},
        "cpu_8": facts.logical_cpus >= MINIMUM_LOGICAL_CPUS,
        "memory_16g": facts.memory_bytes >= MINIMUM_VISIBLE_MEMORY_BYTES,
        "filesystem_300g": facts.filesystem_total_bytes >= MINIMUM_FILESYSTEM_TOTAL_BYTES,
        "free_space_240g": facts.filesystem_available_bytes >= MINIMUM_FILESYSTEM_AVAILABLE_BYTES,
    }
    if not all(checks.values()):
        _block("host_capacity_below_baseline")
    return {
        "platform": facts.platform,
        "architecture": facts.architecture,
        "logical_cpus": facts.logical_cpus,
        "memory_bytes": facts.memory_bytes,
        "filesystem_total_bytes": facts.filesystem_total_bytes,
        "filesystem_available_bytes": facts.filesystem_available_bytes,
        "thresholds": {
            "logical_cpus": MINIMUM_LOGICAL_CPUS,
            "memory_bytes": MINIMUM_VISIBLE_MEMORY_BYTES,
            "filesystem_total_bytes": MINIMUM_FILESYSTEM_TOTAL_BYTES,
            "filesystem_available_bytes": MINIMUM_FILESYSTEM_AVAILABLE_BYTES,
        },
        "checks": checks,
    }


def collect_probe_artifacts(
    repository: Path,
    disk_path: Path,
    target: Mapping[str, object],
    runner: BoundedCommandRunner,
    *,
    now: datetime,
) -> dict[str, dict[str, object]]:
    host = _host_artifact(disk_path)
    active = _active_release(repository, runner)
    deployment = _validated_deployment_target(target)
    release_binding = _validate_release_binding(active, deployment["release_id"])
    staged = _stage_contract(repository, active, runner)
    try:
        config = _compose_config(staged, active, runner)
        deployment_binding = _validate_deployment_binding(active, config, target)
        data_filesystem = _validate_data_filesystem(config, disk_path)
        host["active_data_filesystem"] = data_filesystem
        service_hashes = _compose_hashes(staged, active, runner)
        offline = _offline_images(staged, active, config, runner)
        offline["release_binding"] = release_binding
        offline["deployment_binding"] = deployment_binding
        clamav = _clamav(staged, active, config, service_hashes, runner)
        readiness, business = _readiness_and_business(config)
        caddy = _caddy_evidence(
            staged,
            active,
            config,
            service_hashes,
            runner,
            now=now,
        )
    finally:
        _cleanup_staged_contract(staged)
    return {
        "host": host,
        "offline-images": offline,
        "clamav": clamav,
        "readiness": readiness,
        "business-smoke": business,
        "caddy": caddy,
    }


def build_complete_evidence(
    target: Mapping[str, object],
    artifacts: Sequence[Mapping[str, object]],
    private_key: Ed25519PrivateKey,
    challenge: Mapping[str, object],
    *,
    collected_at: datetime,
) -> dict[str, object]:
    _validated_deployment_target(target)
    by_id = {str(item.get("id")): item for item in artifacts}
    expected_artifacts = {
        "host",
        "offline-images",
        "clamav",
        "readiness",
        "business-smoke",
        "caddy",
    }
    if set(by_id) != expected_artifacts or len(artifacts) != len(expected_artifacts):
        _block("evidence_artifacts_incomplete")
    for artifact_id, artifact in by_id.items():
        raw_path = artifact.get("path")
        digest = artifact.get("sha256")
        size = artifact.get("bytes")
        relative = Path(str(raw_path)) if isinstance(raw_path, str) else None
        if (
            artifact.get("id") != artifact_id
            or relative is None
            or relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
            or any(".env" in part.casefold() for part in relative.parts)
            or not isinstance(digest, str)
            or _HEX64.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 1
            or size > 100 * 1024 * 1024
        ):
            _block("evidence_artifact_invalid")
    challenge_target = challenge.get("target")
    if not isinstance(challenge_target, dict) or challenge_target != dict(target):
        _block("evidence_challenge_target_mismatch")
    checks = {
        "linux_amd64": {"status": "passed", "artifact_ids": ["host"]},
        "cpu_8": {"status": "passed", "artifact_ids": ["host"]},
        "memory_16g": {"status": "passed", "artifact_ids": ["host"]},
        "filesystem_300g": {"status": "passed", "artifact_ids": ["host"]},
        "free_space_240g": {"status": "passed", "artifact_ids": ["host"]},
        "offline_images": {"status": "passed", "artifact_ids": ["offline-images"]},
        "clamav_database": {"status": "passed", "artifact_ids": ["clamav"]},
        "health_readiness": {"status": "passed", "artifact_ids": ["readiness"]},
        "business_smoke": {"status": "passed", "artifact_ids": ["business-smoke"]},
        "caddy_ca_persistent_storage": {"status": "passed", "artifact_ids": ["caddy"]},
        "caddy_automatic_certificate_management": {
            "status": "passed",
            "artifact_ids": ["caddy"],
        },
        "caddy_renewal_health": {"status": "passed", "artifact_ids": ["caddy"]},
    }
    if tuple(checks) != REQUIRED_CHECKS:
        _block("evidence_checks_incomplete")
    unsigned: dict[str, object] = {
        "schema_version": 2,
        "evidence_id": EVIDENCE_ID,
        "status": "complete",
        "collector": COLLECTOR,
        "target": dict(target),
        "collected_at": collected_at.isoformat(),
        "artifacts": sorted((dict(item) for item in artifacts), key=lambda item: str(item["id"])),
        "checks": checks,
    }
    challenge_id = cast(str, challenge["challenge_id"])
    nonce = cast(str, challenge["nonce"])
    signature = private_key.sign(
        _signature_payload(
            unsigned,
            key_id=KEY_ID,
            challenge_id=challenge_id,
            challenge_nonce=nonce,
        )
    )
    unsigned["attestation"] = {
        "type": "ed25519-challenge-v1",
        "key_id": KEY_ID,
        "challenge_id": challenge_id,
        "challenge_nonce": nonce,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return unsigned


def _persist_artifacts(
    parent: Path, run_id: str, payloads: Mapping[str, Mapping[str, object]]
) -> tuple[list[dict[str, object]], Path]:
    artifact_root = parent / "linux-host-artifacts"
    artifact_root.mkdir(mode=0o700, exist_ok=True)
    metadata = artifact_root.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _block("artifact_root_unsafe")
    final = artifact_root / run_id
    if final.exists() or final.is_symlink():
        _block("artifact_run_already_exists")
    staging = Path(tempfile.mkdtemp(prefix=f".{run_id}.", dir=artifact_root))
    os.chmod(staging, 0o700)
    records: list[dict[str, object]] = []
    try:
        for artifact_id in sorted(payloads):
            filename = f"{artifact_id}.json"
            path = staging / filename
            _atomic_json(path, payloads[artifact_id], mode=0o400)
            raw = path.read_bytes()
            records.append(
                {
                    "id": artifact_id,
                    "path": f"linux-host-artifacts/{run_id}/{filename}",
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "bytes": len(raw),
                }
            )
        _fsync_directory(staging)
        os.rename(staging, final)
        _fsync_directory(artifact_root)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return records, final


def _remove_artifact_run(path: Path | None) -> None:
    if path is None or not path.exists():
        return
    root = path.parent
    try:
        resolved = path.resolve(strict=True)
        root_resolved = root.resolve(strict=True)
    except OSError:
        return
    if resolved.parent != root_resolved or root.name != "linux-host-artifacts":
        return
    os.chmod(resolved, 0o700)
    shutil.rmtree(resolved)
    _fsync_directory(root)


def _require_runtime() -> None:
    geteuid = getattr(os, "geteuid", None)
    if (
        os.name != "posix"
        or platform.system().casefold() != "linux"
        or platform.machine().casefold() not in {"amd64", "x86_64"}
        or geteuid is None
        or geteuid() != 0
    ):
        _block("collector_requires_linux_amd64_root")


def collect(arguments: argparse.Namespace) -> dict[str, object]:
    _require_runtime()
    repository = arguments.repository.resolve(strict=True)
    if repository != Path(__file__).resolve().parents[1] or not (repository / ".git").exists():
        _block("repository_identity_invalid")
    output_parent = repository / "artifacts/acceptance/functional"
    _secure_output_parent(output_parent)
    output = output_parent / "linux-host.json"
    diagnostic = output_parent / "linux-host.blocked.json"
    _unlink_and_sync(output)
    identity = collect_worktree_evidence(repository)
    if _RUN_ID.fullmatch(arguments.run_id) is None:
        _block("run_id_invalid")
    if arguments.release_id != identity.git_head:
        _block("deployment_release_id_mismatch")
    try:
        deployment = build_deployment_identity(
            git_head=arguments.release_id,
            offline_contract_sha256=arguments.offline_contract_sha256,
            image_manifest_sha256=arguments.image_manifest_sha256,
            base_url=arguments.base_url,
        )
        target = external_evidence_target(
            GateIdentity(
                git_head=identity.git_head,
                content_fingerprint=identity.content_fingerprint,
                run_nonce=arguments.run_id,
            ),
            run_id=arguments.run_id,
            deployment=deployment,
        )
    except ValueError:
        _block("deployment_identity_invalid")
    now = datetime.now(UTC)
    private_key, challenge, challenge_raw = load_signing_material(
        repository,
        arguments.signing_key,
        arguments.challenge,
        target,
        now=now,
    )
    claim_challenge(arguments.challenge, challenge, challenge_raw)
    artifact_run: Path | None = None
    try:
        payloads = collect_probe_artifacts(
            repository,
            arguments.disk_path,
            target,
            BoundedCommandRunner(),
            now=now,
        )
        records, artifact_run = _persist_artifacts(output_parent, arguments.run_id, payloads)
        evidence = build_complete_evidence(
            target,
            records,
            private_key,
            challenge,
            collected_at=datetime.now(UTC),
        )
        _atomic_json(output, evidence, mode=0o400)
        _unlink_and_sync(diagnostic)
        return evidence
    except BaseException:
        _unlink_and_sync(output)
        _remove_artifact_run(artifact_run)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect signed Linux host acceptance evidence")
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="absolute checked-out release repository bound to the evidence",
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--offline-contract-sha256", required=True)
    parser.add_argument("--image-manifest-sha256", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--disk-path", type=Path, default=PERSISTENT_ROOT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    repository = arguments.repository.resolve(strict=False)
    output_parent = repository / "artifacts/acceptance/functional"
    output = output_parent / "linux-host.json"
    diagnostic = output_parent / "linux-host.blocked.json"
    try:
        evidence = collect(arguments)
    except CollectorBlocked as exc:
        with suppress_process_errors():
            output_parent.mkdir(mode=0o750, parents=True, exist_ok=True)
            _unlink_and_sync(output)
            _atomic_json(
                diagnostic,
                {
                    "diagnostic_version": 1,
                    "kind": "linux-host-diagnostic",
                    "status": "blocked",
                    "collector": COLLECTOR,
                    "collected_at": datetime.now(UTC).isoformat(),
                    "reason_code": exc.code,
                    "required_checks": list(REQUIRED_CHECKS),
                },
                mode=0o400,
            )
        print(json.dumps({"status": "BLOCKED", "reason_code": exc.code}, sort_keys=True))
        return 2
    except BaseException:
        with suppress_process_errors():
            output_parent.mkdir(mode=0o750, parents=True, exist_ok=True)
            _unlink_and_sync(output)
            _atomic_json(
                diagnostic,
                {
                    "diagnostic_version": 1,
                    "kind": "linux-host-diagnostic",
                    "status": "blocked",
                    "collector": COLLECTOR,
                    "collected_at": datetime.now(UTC).isoformat(),
                    "reason_code": "collector_internal_error",
                    "required_checks": list(REQUIRED_CHECKS),
                },
                mode=0o400,
            )
        print(json.dumps({"status": "BLOCKED", "reason_code": "collector_internal_error"}))
        return 2
    print(
        json.dumps(
            {
                "status": "PASS",
                "evidence_id": evidence["evidence_id"],
                "collector": COLLECTOR,
                "run_id": arguments.run_id,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
