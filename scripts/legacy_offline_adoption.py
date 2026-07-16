#!/usr/bin/env python3
"""Fail-closed adoption of a legacy ``heyi-kb-offline`` Docker project.

The tool is deliberately separate from the normal release transaction.  It is
used once to prove that a legacy Compose project can be backed up, restored in
isolated containers, and retired without touching its bind-mounted data or any
other application.  Every command uses argv execution; operator-controlled
files are parsed as data and are never sourced by a shell.

The default action is always read-only.  Mutating commands require two exact
confirmations: the fixed project name and the SHA-256 of a protected plan.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.util
import io
import ipaddress
import json
import os
import re
import secrets
import selectors
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, BinaryIO, Final, Never

PROJECT: Final = "heyi-kb-offline"
OWNER: Final = "jiangsu-heyi-knowledgebases"
STACK: Final = "offline"
DATA_ROOT: Final = Path("/srv/heyi-knowledgebases-offline/data")
STATE_ROOT: Final = Path("/srv/heyi-knowledgebases-offline/state")
BACKUP_ROOT: Final = Path("/srv/heyi-knowledgebases-offline/backups")
RELEASE_ROOT: Final = Path("/srv/heyi-knowledgebases-offline/releases")
EXPECTED_PORTS: Final = frozenset({"19443/tcp", "19444/tcp"})
PROTECTED_OTHER_PORT: Final = "10050"
ALLOWED_SERVICES: Final = frozenset(
    {
        "postgres",
        "redis",
        "minio",
        "minio-init",
        "minio-multipart-gc",
        "clamd",
        "api",
        "maintenance",
        "web",
        "proxy",
        "llm-egress",
        "maintenance-page",
    }
)
KNOWN_ONEOFF_SERVICES: Final = frozenset(
    {"api-preflight", "clamav-db-preflight", "migrate", "bootstrap"}
)
REQUIRED_SERVICES: Final = frozenset(
    {"postgres", "redis", "minio", "api", "maintenance", "web", "proxy"}
)
WRITER_STOP_ORDER: Final = (
    "proxy",
    "web",
    "api",
    "maintenance",
    "llm-egress",
    "minio-multipart-gc",
)
START_ORDER: Final = (
    "postgres",
    "redis",
    "minio",
    "clamd",
    "minio-multipart-gc",
    "llm-egress",
    "api",
    "maintenance",
    "web",
    "proxy",
)
LEGACY_STOP_GRACE_SECONDS: Final = 140
LEGACY_STOP_COMMAND_TIMEOUT_SECONDS: Final = 180
REACTIVATION_BOUNDARY: Final = "PRE_MIGRATION_ONLY"
REACTIVATION_HEALTH_TIMEOUT_SECONDS: Final = 300
REACTIVATION_HEALTH_POLL_SECONDS: Final = 2
REACTIVATION_EDGE_TIMEOUT_SECONDS: Final = 120
REACTIVATION_EDGE_POLL_SECONDS: Final = 2
RETIREMENT_INTENT_DIRECTORY: Final = ".retirement-in-progress"
TRUSTED_DOCKER_PROXY_PATHS: Final = frozenset(
    {"/usr/bin/docker-proxy", "/usr/libexec/docker/docker-proxy"}
)
TRUSTED_DOCKER_DAEMON_PATHS: Final = frozenset({"/usr/bin/dockerd", "/usr/libexec/docker/dockerd"})
RECONCILE_UNITS: Final = (
    "heyi-kb-offline-reconcile.timer",
    "heyi-kb-offline-reconcile.service",
)
REQUIRED_RUNTIME_KEYS: Final = frozenset(
    {
        "POSTGRES_DB",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "MINIO_ROOT_USER",
        "MINIO_ROOT_PASSWORD",
        "MINIO_BUCKET",
        "KB_JWT_SECRET",
        "KB_BFF_SHARED_SECRET",
        "KB_LLM_CREDENTIAL_ENCRYPTION_KEY",
        "KB_CHAT_REPLAY_ENCRYPTION_KEYS",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_SCHEMA_HEAD = re.compile(r"^[0-9]{8}_[0-9]{4}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMMUTABLE_IMAGE = re.compile(r"^\S+@sha256:[0-9a-f]{64}$")
_ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
_TRANSACTION_ID = re.compile(r"^[0-9a-f]{32}$")
_DNS_HOST = re.compile(
    r"^(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)
_HTTP_STATUS = re.compile(rb"^HTTP/1\.[01] ([0-9]{3})(?:[ \t]|$)")
MAX_CONTROL_FILE = 8 * 1024 * 1024
MAX_CA_PLAINTEXT = 64 * 1024 * 1024
_ALLOWED_EXECUTABLES: Final = frozenset({"/usr/bin/docker", "/usr/bin/openssl"})
_ALLOWED_EXTRA_ENV: Final = frozenset(
    {
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "POSTGRES_DB",
        "MINIO_ROOT_USER",
        "MINIO_ROOT_PASSWORD",
        "MINIO_BUCKET",
    }
)
TARGET_ABORT_RECEIPT_KEYS: Final = frozenset(
    {
        "schema_version",
        "kind",
        "status",
        "project",
        "issued_at",
        "adoption_transaction_id",
        "journal_sha256",
        "plan_sha256",
        "retirement_receipt_sha256",
        "target_contract_sha256",
        "target_manifest_sha256",
        "target_schema_head",
        "legacy_source_schema_head",
        "last_install_phase",
        "migration_command_invoked",
        "active_release_present",
        "installed_receipt_present",
        "removed_preflight_container_ids",
        "removed_owner_marker_volume",
        "archived_install_state",
        "archived_cutover_intent",
        "reconcile_baseline",
        "reconcile_result",
        "target_resource_counts_after",
        "host_isolation_verification",
        "preserved_bind_root",
        "bind_data_deleted",
        "named_volumes_deleted",
        "global_actions",
        "restore_boundary",
    }
)


class AdoptionError(RuntimeError):
    """The adoption contract could not be proven safely."""


class CommandError(AdoptionError):
    """A redacted external command failed."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise AdoptionError(message)


@dataclass(frozen=True, slots=True)
class ContainerRecord:
    service: str
    container_id: str
    image_id: str
    config_image: str
    config_hash: str
    config_files: tuple[str, ...]
    oneoff: bool
    running: bool
    restart_count: int
    mounts: tuple[tuple[str, str, bool, str], ...]
    networks: tuple[str, ...]
    published_ports: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NetworkRecord:
    name: str
    network_id: str
    internal: bool
    attached_container_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VolumeRecord:
    name: str
    mountpoint: str


@dataclass(frozen=True, slots=True)
class LegacyInventory:
    containers: tuple[ContainerRecord, ...]
    networks: tuple[NetworkRecord, ...]
    volumes: tuple[VolumeRecord, ...]


class Runner:
    """Small argv-only subprocess adapter with deliberately redacted errors."""

    def __init__(self, *, docker: str = "/usr/bin/docker") -> None:
        self.docker = docker
        self.base_env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "HOME": "/root",
        }

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 120,
        input_bytes: bytes | None = None,
        extra_env: Mapping[str, str] | None = None,
        stdout_file: BinaryIO | None = None,
    ) -> bytes:
        if not argv or argv[0] not in _ALLOWED_EXECUTABLES:
            raise CommandError("external executable is outside the fixed allowlist")
        if any(
            not isinstance(argument, str)
            or "\x00" in argument
            or "\r" in argument
            or "\n" in argument
            or len(argument) > 16_384
            for argument in argv
        ):
            raise CommandError("external command contains an unsafe argument")
        environment = self._environment(extra_env)
        try:
            # Security contract: executable and every argument were validated above,
            # the environment is reconstructed from an allowlist, and no shell is used.
            completed = subprocess.run(  # nosec B603
                list(argv),
                input=input_bytes,
                stdout=stdout_file if stdout_file is not None else subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd="/",
                check=False,
                shell=False,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CommandError(f"command failed to execute: {Path(argv[0]).name}") from exc
        if completed.returncode != 0:
            raise CommandError(f"command returned {completed.returncode}: {Path(argv[0]).name}")
        return b"" if stdout_file is not None else completed.stdout

    def _environment(self, extra_env: Mapping[str, str] | None) -> dict[str, str]:
        environment = dict(self.base_env)
        if not extra_env:
            return environment
        if not set(extra_env) <= _ALLOWED_EXTRA_ENV:
            raise CommandError("external command environment contains an unapproved key")
        for key, value in extra_env.items():
            if (
                not isinstance(value, str)
                or not value
                or any(character in value for character in ("\x00", "\r", "\n"))
                or len(value) > 16_384
            ):
                raise CommandError(f"external command environment value is unsafe: {key}")
            environment[key] = value
        return environment

    def docker_json(self, argv: Sequence[str], *, timeout: int = 120) -> Any:
        raw = self.run((self.docker, *argv), timeout=timeout)
        try:
            return json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AdoptionError("Docker returned malformed JSON") from exc

    def sha256_stdout(self, argv: Sequence[str], *, timeout: int = 3_600) -> tuple[str, int]:
        if not argv or argv[0] not in _ALLOWED_EXECUTABLES:
            raise CommandError("external executable is outside the fixed allowlist")
        if any(
            not isinstance(argument, str)
            or any(character in argument for character in ("\x00", "\r", "\n"))
            or len(argument) > 16_384
            for argument in argv
        ):
            raise CommandError("external command contains an unsafe argument")
        try:
            # See run(): this is the same fixed argv-only execution boundary.  Popen is
            # required so multi-terabyte object streams are hashed without buffering.
            process = subprocess.Popen(  # nosec B603
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self.base_env,
                cwd="/",
                shell=False,
            )
        except OSError as exc:
            raise CommandError(f"command failed to execute: {Path(argv[0]).name}") from exc
        digest = hashlib.sha256()
        size = 0
        if process.stdout is None:
            process.kill()
            raise CommandError("streaming command did not expose a stdout pipe")
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        selector = selectors.DefaultSelector()
        selector.register(descriptor, selectors.EVENT_READ)
        try:
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    raise CommandError("streaming command exceeded its deadline")
                events = selector.select(timeout=min(remaining, 1.0))
                if not events:
                    if process.poll() is not None:
                        chunk = os.read(descriptor, 8 * 1024 * 1024)
                        if chunk:
                            size += len(chunk)
                            digest.update(chunk)
                        break
                    continue
                chunk = os.read(descriptor, 8 * 1024 * 1024)
                if chunk:
                    size += len(chunk)
                    digest.update(chunk)
                    continue
                if process.poll() is not None:
                    break
            return_code = process.wait(timeout=30)
        finally:
            selector.close()
            process.stdout.close()
        if return_code != 0:
            raise CommandError(f"command returned {return_code}: {Path(argv[0]).name}")
        return digest.hexdigest(), size


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _posix_chown(path: Path, uid: int, gid: int) -> None:
    operation = getattr(os, "chown", None)
    if operation is None:
        raise AdoptionError("POSIX chown is unavailable")
    operation(path, uid, gid)


def _posix_fchmod(descriptor: int, mode: int) -> None:
    operation = getattr(os, "fchmod", None)
    if operation is None:
        raise AdoptionError("POSIX fchmod is unavailable")
    operation(descriptor, mode)


def _canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hmac_binding(payload: bytes, key: bytes, *, domain: str) -> str:
    message = domain.encode("ascii") + b"\0" + payload
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _require_root() -> None:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise AdoptionError("legacy adoption must run as root on Linux")
    if sys.platform != "linux":
        raise AdoptionError("legacy adoption is supported only on Linux")


def _validate_ancestors(path: Path) -> None:
    current = path
    while True:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise AdoptionError(f"protected path ancestor is unsafe: {current}")
        if stat.S_ISDIR(info.st_mode) and info.st_mode & 0o022:
            raise AdoptionError(f"protected path ancestor is writable: {current}")
        if current == Path("/"):
            break
        current = current.parent


def protected_file(
    path: Path,
    *,
    modes: frozenset[int],
    max_bytes: int = MAX_CONTROL_FILE,
) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise AdoptionError(f"protected file path is unsafe: {path}")
    canonical = path.resolve(strict=True)
    if canonical != path:
        raise AdoptionError(f"protected file path is non-canonical: {path}")
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) not in modes
        or not 0 < info.st_size <= max_bytes
    ):
        raise AdoptionError(f"protected file metadata is unsafe: {path}")
    _validate_ancestors(path.parent)
    return canonical


def protected_directory(path: Path, *, modes: frozenset[int]) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise AdoptionError(f"protected directory path is unsafe: {path}")
    canonical = path.resolve(strict=True)
    if canonical != path:
        raise AdoptionError(f"protected directory path is non-canonical: {path}")
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) not in modes
    ):
        raise AdoptionError(f"protected directory metadata is unsafe: {path}")
    _validate_ancestors(path)
    return canonical


def _open_protected_bytes(path: Path, *, max_bytes: int = MAX_CONTROL_FILE) -> bytes:
    protected_file(path, modes=frozenset({0o400, 0o440, 0o444, 0o600}), max_bytes=max_bytes)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AdoptionError("protected file changed during open")
        payload = os.read(descriptor, max_bytes + 1)
        if not payload or len(payload) > max_bytes:
            raise AdoptionError("protected file size changed during read")
        return payload
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, payload: bytes, *, mode: int) -> None:
    parent = protected_directory(path.parent, modes=frozenset({0o700, 0o750}))
    if path.exists() or path.is_symlink():
        raise AdoptionError(f"refusing to replace an existing artifact: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    temporary = parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(temporary, flags, mode)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        _posix_fchmod(descriptor, mode)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory_descriptor = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def parse_runtime_environment(path: Path, binding_key: bytes) -> tuple[dict[str, str], str]:
    raw = _open_protected_bytes(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise AdoptionError("runtime environment is not UTF-8") from exc
    values: dict[str, str] = {}
    for number, source in enumerate(text.splitlines(), 1):
        line = source.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise AdoptionError(f"runtime environment line {number} is malformed")
        key, value = line.split("=", 1)
        if _ENV_KEY.fullmatch(key) is None or key in values:
            raise AdoptionError(f"runtime environment key at line {number} is invalid")
        if any(character in value for character in ("\x00", "\r", "\n", "`")):
            raise AdoptionError(f"runtime environment value at line {number} is unsafe")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if not value:
            raise AdoptionError(f"runtime environment key {key} is empty")
        values[key] = value
    missing = REQUIRED_RUNTIME_KEYS - values.keys()
    if missing:
        raise AdoptionError("runtime environment is missing required protected values")
    return values, _hmac_binding(raw, binding_key, domain="heyi-runtime-env-v1")


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdoptionError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AdoptionError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AdoptionError(f"{label} must be a non-empty string")
    return value


def _compose_label_paths(value: object) -> tuple[str, ...]:
    raw = _string(value, "Compose config file")
    paths: list[str] = []
    for candidate in raw.split(","):
        if not candidate or candidate != candidate.strip():
            raise AdoptionError("legacy Compose config-file label is malformed")
        path = PurePosixPath(candidate)
        if not path.is_absolute() or str(path) != candidate:
            raise AdoptionError("legacy Compose config-file label is not canonical absolute")
        paths.append(candidate)
    if not paths or len(paths) != len(set(paths)):
        raise AdoptionError("legacy Compose config-file label is empty or duplicated")
    return tuple(paths)


def _container_record(document: object) -> ContainerRecord:
    container = _object(document, "container inspection")
    container_id = _string(container.get("Id"), "container id")
    if _CONTAINER_ID.fullmatch(container_id) is None:
        raise AdoptionError("legacy container id is invalid")
    config = _object(container.get("Config"), "container config")
    labels = _object(config.get("Labels"), "container labels")
    if labels.get("com.docker.compose.project") != PROJECT:
        raise AdoptionError("legacy container project label differs")
    if labels.get("io.heyi.knowledgebases.owner") != OWNER:
        raise AdoptionError("legacy container owner label differs")
    if labels.get("io.heyi.knowledgebases.stack") != STACK:
        raise AdoptionError("legacy container stack label differs")
    service = _string(labels.get("com.docker.compose.service"), "service label")
    raw_oneoff = _string(labels.get("com.docker.compose.oneoff"), "one-off label")
    if raw_oneoff.lower() not in {"true", "false"}:
        raise AdoptionError("legacy container one-off label is malformed")
    oneoff = raw_oneoff.lower() == "true"
    if oneoff:
        if service not in KNOWN_ONEOFF_SERVICES:
            raise AdoptionError("legacy project contains an unknown one-off service")
    elif service not in ALLOWED_SERVICES:
        raise AdoptionError("legacy project contains an unknown service")
    image_id = _string(container.get("Image"), "container image id")
    if _IMAGE_ID.fullmatch(image_id) is None:
        raise AdoptionError("legacy container image id is not immutable")
    config_image = _string(config.get("Image"), "configured image")
    if _IMMUTABLE_IMAGE.fullmatch(config_image) is None:
        raise AdoptionError("legacy configured image is not digest-pinned")
    config_hash = _string(labels.get("com.docker.compose.config-hash"), "config hash")
    if _SHA256.fullmatch(config_hash) is None:
        raise AdoptionError("legacy Compose config hash is malformed")
    state = _object(container.get("State"), "container state")
    running = state.get("Running")
    restart_count = container.get("RestartCount")
    if type(running) is not bool or type(restart_count) is not int or restart_count < 0:
        raise AdoptionError("legacy container state is malformed")
    mounts: list[tuple[str, str, bool, str]] = []
    for raw_mount in _list(container.get("Mounts", []), "container mounts"):
        mount = _object(raw_mount, "container mount")
        kind = _string(mount.get("Type"), "mount type")
        source = _string(mount.get("Source"), "mount source")
        destination = _string(mount.get("Destination"), "mount destination")
        rw = mount.get("RW")
        if type(rw) is not bool or kind not in {"bind", "volume"}:
            raise AdoptionError("legacy container mount is unsafe")
        if kind == "bind" and rw:
            source_path = Path(source)
            try:
                source_path.resolve(strict=True).relative_to(DATA_ROOT)
            except (OSError, ValueError) as exc:
                raise AdoptionError("writable legacy bind is outside the fixed data root") from exc
        mounts.append((source, destination, rw, kind))
    network_settings = _object(container.get("NetworkSettings"), "network settings")
    network_names = tuple(sorted(_object(network_settings.get("Networks"), "container networks")))
    ports: list[str] = []
    raw_ports = network_settings.get("Ports")
    if raw_ports is not None:
        for container_port, bindings in _object(raw_ports, "container ports").items():
            if bindings is None:
                continue
            for binding in _list(bindings, "port bindings"):
                candidate = _object(binding, "port binding")
                host_port = _string(candidate.get("HostPort"), "host port")
                if host_port == PROTECTED_OTHER_PORT:
                    raise AdoptionError("legacy project unexpectedly owns protected port 10050")
                ports.append(f"{host_port}/{container_port}")
    if service not in {"proxy", "maintenance-page"} and ports:
        raise AdoptionError("a non-edge legacy service publishes host ports")
    if oneoff and (running or ports):
        raise AdoptionError("legacy one-off container must be stopped and publish no ports")
    host_ports = {entry.split("/", 1)[0] + "/tcp" for entry in ports}
    if not host_ports <= EXPECTED_PORTS:
        raise AdoptionError("legacy edge publishes an unapproved host port")
    return ContainerRecord(
        service=service,
        container_id=container_id,
        image_id=image_id,
        config_image=config_image,
        config_hash=config_hash,
        config_files=_compose_label_paths(labels.get("com.docker.compose.project.config_files")),
        oneoff=oneoff,
        running=running,
        restart_count=restart_count,
        mounts=tuple(sorted(mounts)),
        networks=network_names,
        published_ports=tuple(sorted(ports)),
    )


def collect_inventory(runner: Runner) -> LegacyInventory:
    raw_ids = runner.run(
        (
            runner.docker,
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
        )
    ).decode("ascii", errors="strict")
    ids = sorted({line.strip() for line in raw_ids.splitlines() if line.strip()})
    if not ids or any(_CONTAINER_ID.fullmatch(value) is None for value in ids):
        raise AdoptionError("legacy project container inventory is empty or malformed")
    containers = tuple(
        sorted(
            (_container_record(item) for item in runner.docker_json(("inspect", *ids))),
            key=lambda item: (item.oneoff, item.service, item.container_id),
        )
    )
    primary_services = [item.service for item in containers if not item.oneoff]
    if (
        len(set(primary_services)) != len(primary_services)
        or not set(primary_services) >= REQUIRED_SERVICES
    ):
        raise AdoptionError("legacy project service inventory is incomplete or ambiguous")
    container_ids = {item.container_id for item in containers}

    raw_network_ids = runner.run(
        (
            runner.docker,
            "network",
            "ls",
            "-q",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
        )
    ).decode("ascii", errors="strict")
    network_ids = sorted({line.strip() for line in raw_network_ids.splitlines() if line.strip()})
    networks: list[NetworkRecord] = []
    if network_ids:
        for raw_network in runner.docker_json(("network", "inspect", *network_ids)):
            network = _object(raw_network, "network inspection")
            labels = _object(network.get("Labels"), "network labels")
            if labels.get("com.docker.compose.project") != PROJECT:
                raise AdoptionError("legacy network project label differs")
            if labels.get("io.heyi.knowledgebases.owner") != OWNER:
                raise AdoptionError("legacy network owner label differs")
            if labels.get("io.heyi.knowledgebases.stack") != STACK:
                raise AdoptionError("legacy network stack label differs")
            attached = tuple(sorted(_object(network.get("Containers", {}), "network endpoints")))
            if not set(attached) <= container_ids:
                raise AdoptionError("legacy project network is shared with another application")
            networks.append(
                NetworkRecord(
                    name=_string(network.get("Name"), "network name"),
                    network_id=_string(network.get("Id"), "network id"),
                    internal=bool(network.get("Internal")),
                    attached_container_ids=attached,
                )
            )

    raw_volume_names = runner.run(
        (
            runner.docker,
            "volume",
            "ls",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
        )
    ).decode("utf-8", errors="strict")
    volume_names = sorted({line.strip() for line in raw_volume_names.splitlines() if line.strip()})
    volumes: list[VolumeRecord] = []
    if volume_names:
        for raw_volume in runner.docker_json(("volume", "inspect", *volume_names)):
            volume = _object(raw_volume, "volume inspection")
            labels = _object(volume.get("Labels"), "volume labels")
            if labels.get("com.docker.compose.project") != PROJECT:
                raise AdoptionError("legacy volume project label differs")
            volumes.append(
                VolumeRecord(
                    name=_string(volume.get("Name"), "volume name"),
                    mountpoint=_string(volume.get("Mountpoint"), "volume mountpoint"),
                )
            )
    return LegacyInventory(
        containers, tuple(sorted(networks, key=lambda item: item.name)), tuple(volumes)
    )


def inventory_document(inventory: LegacyInventory) -> dict[str, Any]:
    return {
        "containers": [asdict(item) for item in inventory.containers],
        "networks": [asdict(item) for item in inventory.networks],
        "volumes": [asdict(item) for item in inventory.volumes],
    }


def inventory_sha256(inventory: LegacyInventory) -> str:
    return _sha256_bytes(_canonical_json(inventory_document(inventory)))


def _source_images(inventory: LegacyInventory) -> dict[str, str]:
    return {
        _container_binding_key(item.service, item.oneoff, item.container_id): item.image_id
        for item in inventory.containers
    }


def _container_binding_key(service: str, oneoff: bool, container_id: str) -> str:
    return f"oneoff:{service}:{container_id}" if oneoff else service


def topology_document(inventory: LegacyInventory) -> dict[str, Any]:
    """Return the stable identity needed to reconstruct the legacy project.

    Container/network IDs and runtime counters deliberately do not participate:
    a rollback after exact retirement legitimately recreates those identities.
    Images, mounts, ports, service set, network names/isolation and named-volume
    identities remain bound.
    """

    return {
        "containers": [
            {
                "service": item.service,
                "image_id": item.image_id,
                "config_image": item.config_image,
                "config_hash": item.config_hash,
                "config_files": item.config_files,
                "oneoff": item.oneoff,
                "mounts": item.mounts,
                "networks": item.networks,
                "published_ports": item.published_ports,
            }
            for item in inventory.containers
        ],
        "networks": [{"name": item.name, "internal": item.internal} for item in inventory.networks],
        "volumes": [asdict(item) for item in inventory.volumes],
    }


def topology_sha256(inventory: LegacyInventory) -> str:
    return _sha256_bytes(_canonical_json(topology_document(inventory)))


def _restorable_inventory(inventory: LegacyInventory) -> LegacyInventory:
    primary_ids = {item.container_id for item in inventory.containers if not item.oneoff}
    return LegacyInventory(
        containers=tuple(item for item in inventory.containers if not item.oneoff),
        networks=tuple(
            replace(
                item,
                attached_container_ids=tuple(
                    value for value in item.attached_container_ids if value in primary_ids
                ),
            )
            for item in inventory.networks
        ),
        volumes=inventory.volumes,
    )


def restorable_topology_sha256(inventory: LegacyInventory) -> str:
    return topology_sha256(_restorable_inventory(inventory))


def _read_binding_key(path: Path) -> bytes:
    payload = _open_protected_bytes(path, max_bytes=4096).strip()
    if len(payload) < 32:
        raise AdoptionError("binding key must contain at least 32 random bytes")
    try:
        decoded = base64.urlsafe_b64decode(payload + b"=" * (-len(payload) % 4))
    except (ValueError, TypeError) as exc:
        raise AdoptionError("binding key must be URL-safe base64") from exc
    if len(decoded) < 32:
        raise AdoptionError("binding key must decode to at least 32 bytes")
    return decoded


def build_plan(
    *,
    inventory: LegacyInventory,
    runtime_env: Path,
    runtime_binding: str,
    compose_files: Sequence[Path],
    legacy_env_files: Sequence[Path],
    legacy_env_bindings: Mapping[str, str],
    target_manifest: Path,
    git_sha: str,
) -> dict[str, Any]:
    if _GIT_SHA.fullmatch(git_sha) is None:
        raise AdoptionError("expected Git SHA is malformed")
    if not compose_files:
        raise AdoptionError("at least one legacy Compose file is required")
    compose_paths = tuple(
        protected_file(path, modes=frozenset({0o400, 0o440, 0o444})) for path in compose_files
    )
    if len(compose_paths) != len(set(compose_paths)):
        raise AdoptionError("legacy Compose file argument is duplicated")
    env_files = [
        protected_file(path, modes=frozenset({0o400, 0o440, 0o444, 0o600}))
        for path in legacy_env_files
    ]
    if set(legacy_env_bindings) != {str(path) for path in env_files}:
        raise AdoptionError("legacy environment binding set is incomplete")
    if any(_SHA256.fullmatch(value) is None for value in legacy_env_bindings.values()):
        raise AdoptionError("legacy environment binding is malformed")
    manifest = protected_file(target_manifest, modes=frozenset({0o400, 0o440, 0o444}))
    protected_file(runtime_env, modes=frozenset({0o400, 0o600}))
    selected_compose = {str(path) for path in compose_paths}
    observed_compose = {path for item in inventory.containers for path in item.config_files}
    if observed_compose != selected_compose:
        raise AdoptionError("legacy Compose file set differs from container bindings")
    service_bindings: dict[str, list[str]] = {}
    for item in inventory.containers:
        binding = list(item.config_files)
        key = _container_binding_key(item.service, item.oneoff, item.container_id)
        if key in service_bindings:
            raise AdoptionError("container Compose binding key is duplicated")
        service_bindings[key] = binding
    guard = protected_file(
        Path(__file__).resolve(strict=True).with_name("host_isolation_guard.py"),
        modes=frozenset({0o400, 0o440, 0o444, 0o644}),
    )
    return {
        "schema_version": 2,
        "kind": "heyi-legacy-adoption-plan",
        "project": PROJECT,
        "created_at": _utc_now().isoformat().replace("+00:00", "Z"),
        "git_sha": git_sha,
        "data_root": str(DATA_ROOT),
        "runtime_env": {
            "path": str(runtime_env),
            "opaque_hmac_sha256": runtime_binding,
        },
        "legacy_compose": {
            "files": [{"path": str(path), "sha256": _sha256_file(path)} for path in compose_paths],
            "service_bindings": service_bindings,
            "env_files": [
                {
                    "path": str(path),
                    "opaque_hmac_sha256": legacy_env_bindings[str(path)],
                }
                for path in env_files
            ],
        },
        "target_manifest": {
            "path": str(manifest),
            "sha256": _sha256_file(manifest),
        },
        "host_isolation_guard": {
            "path": str(guard),
            "sha256": _sha256_file(guard),
        },
        "inventory_sha256": inventory_sha256(inventory),
        "topology_sha256": topology_sha256(inventory),
        "inventory": inventory_document(inventory),
        "safety": {
            "protected_other_port": 10050,
            "delete_containers": True,
            "delete_project_networks": True,
            "delete_named_volumes": False,
            "delete_bind_data": False,
            "global_prune": False,
            "restart_docker_daemon": False,
        },
    }


def _confirm(arguments: argparse.Namespace, plan_digest: str) -> bool:
    requested = bool(arguments.execute)
    valid = arguments.confirm_project == PROJECT and arguments.confirm_plan_sha256 == plan_digest
    if requested and not valid:
        raise AdoptionError("execution requires exact project and plan-digest confirmations")
    return requested


def _plan_digest(document: Mapping[str, Any]) -> str:
    return _sha256_bytes(_canonical_json(document))


def _service(inventory: LegacyInventory, name: str) -> ContainerRecord:
    candidate = next(
        (item for item in inventory.containers if item.service == name and not item.oneoff), None
    )
    if candidate is None:
        raise AdoptionError(f"required legacy service is missing: {name}")
    return candidate


def _create_run_directory(parent: Path, run_id: str) -> Path:
    protected_directory(parent, modes=frozenset({0o700, 0o750}))
    if _SAFE_NAME.fullmatch(run_id) is None:
        raise AdoptionError("run id contains unsafe characters")
    destination = parent / run_id
    if destination.exists() or destination.is_symlink():
        raise AdoptionError("adoption run directory already exists")
    destination.mkdir(mode=0o700)
    _posix_chown(destination, 0, 0)
    directory_descriptor = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return protected_directory(destination, modes=frozenset({0o700}))


def _new_private_directory(parent: Path, name: str) -> Path:
    destination = parent / name
    destination.mkdir(mode=0o700)
    _posix_chown(destination, 0, 0)
    return protected_directory(destination, modes=frozenset({0o700}))


def _command_to_new_file(
    runner: Runner,
    argv: Sequence[str],
    destination: Path,
    *,
    timeout: int,
) -> None:
    parent = protected_directory(destination.parent, modes=frozenset({0o700}))
    if destination.exists() or destination.is_symlink():
        raise AdoptionError("backup artifact already exists")
    temporary = parent / f".{destination.name}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            runner.run(argv, timeout=timeout, stdout_file=stream)
            stream.flush()
            os.fsync(stream.fileno())
        info = temporary.stat()
        if info.st_size <= 0:
            raise AdoptionError("backup command produced an empty artifact")
        os.chmod(temporary, 0o400)
        os.replace(temporary, destination)
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise


def _docker_exec_text(
    runner: Runner,
    container_id: str,
    argv: Sequence[str],
    *,
    timeout: int = 120,
) -> str:
    payload = runner.run((runner.docker, "exec", container_id, *argv), timeout=timeout)
    try:
        return payload.decode("utf-8")
    except UnicodeError as exc:
        raise AdoptionError("container returned non-UTF-8 control output") from exc


def _quote_identifier(value: str) -> str:
    if "\x00" in value:
        raise AdoptionError("database identifier contains NUL")
    return '"' + value.replace('"', '""') + '"'


def _count_statement(schema: str, table: str) -> str:
    """Build one identifier-only query using PostgreSQL's exact quote rules.

    Values are never interpolated as literals, both identifiers double every quote,
    and the resulting SQL is passed as one argv element without a shell. PostgreSQL
    does not support bind parameters for identifiers.
    """

    quoted_schema = _quote_identifier(schema)
    quoted_table = _quote_identifier(table)
    return f"SELECT count(*) FROM {quoted_schema}.{quoted_table};"  # nosec B608


def _database_backup(
    runner: Runner,
    inventory: LegacyInventory,
    runtime: Mapping[str, str],
    output: Path,
) -> tuple[dict[str, int], str, dict[str, Any]]:
    postgres = _service(inventory, "postgres")
    user = runtime["POSTGRES_USER"]
    database = runtime["POSTGRES_DB"]
    dump = output / "database.dump"
    globals_dump = output / "globals.sql"
    schema_dump = output / "schema.sql"
    _command_to_new_file(
        runner,
        (
            runner.docker,
            "exec",
            postgres.container_id,
            "pg_dump",
            "--username",
            user,
            "--dbname",
            database,
            "--format=custom",
            "--compress=9",
            "--no-owner",
            "--no-acl",
        ),
        dump,
        timeout=14_400,
    )
    _command_to_new_file(
        runner,
        (
            runner.docker,
            "exec",
            postgres.container_id,
            "pg_dumpall",
            "--username",
            user,
            "--globals-only",
            "--no-role-passwords",
            "--no-tablespaces",
        ),
        globals_dump,
        timeout=1_800,
    )
    _command_to_new_file(
        runner,
        (
            runner.docker,
            "exec",
            postgres.container_id,
            "pg_dump",
            "--username",
            user,
            "--dbname",
            database,
            "--schema-only",
            "--no-owner",
            "--no-acl",
        ),
        schema_dump,
        timeout=1_800,
    )
    schema_head = _docker_exec_text(
        runner,
        postgres.container_id,
        (
            "psql",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
            "--username",
            user,
            "--dbname",
            database,
            "--command",
            "SELECT version_num FROM alembic_version;",
        ),
    ).strip()
    if _SCHEMA_HEAD.fullmatch(schema_head) is None:
        raise AdoptionError("legacy database schema head is malformed")
    raw_tables = _docker_exec_text(
        runner,
        postgres.container_id,
        (
            "psql",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--field-separator",
            "\t",
            "--set",
            "ON_ERROR_STOP=1",
            "--username",
            user,
            "--dbname",
            database,
            "--command",
            (
                "SELECT schemaname, tablename FROM pg_catalog.pg_tables "
                "WHERE schemaname NOT IN ('pg_catalog','information_schema') "
                "ORDER BY schemaname, tablename;"
            ),
        ),
    )
    counts: dict[str, int] = {}
    for line in raw_tables.splitlines():
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            raise AdoptionError("database table inventory is malformed")
        schema, table = parts
        label = f"{schema}.{table}"
        raw_count = _docker_exec_text(
            runner,
            postgres.container_id,
            (
                "psql",
                "--no-psqlrc",
                "--tuples-only",
                "--no-align",
                "--set",
                "ON_ERROR_STOP=1",
                "--username",
                user,
                "--dbname",
                database,
                "--command",
                _count_statement(schema, table),
            ),
            timeout=3_600,
        ).strip()
        if not raw_count.isdecimal():
            raise AdoptionError("database table count is malformed")
        counts[label] = int(raw_count)
    _atomic_write(output / "table-counts.json", _canonical_json(counts), mode=0o400)
    metadata = {
        "dump_sha256": _sha256_file(dump),
        "globals_sha256": _sha256_file(globals_dump),
        "schema_sha256": _sha256_file(schema_dump),
        "table_counts_sha256": _sha256_file(output / "table-counts.json"),
        "table_count": len(counts),
        "row_count": sum(counts.values()),
    }
    return counts, schema_head, metadata


def _find_shared_network(
    inventory: LegacyInventory, first: ContainerRecord, second: ContainerRecord
) -> str:
    shared = sorted(set(first.networks) & set(second.networks))
    if len(shared) != 1:
        raise AdoptionError("legacy MinIO and mc services lack one exact shared network")
    known = {item.name for item in inventory.networks}
    if shared[0] not in known:
        raise AdoptionError("legacy MinIO shared network is outside the project inventory")
    return shared[0]


def _cleanup_exact_container(runner: Runner, container_id: str) -> None:
    inspection = runner.docker_json(("inspect", container_id))
    if not isinstance(inspection, list) or len(inspection) != 1:
        raise AdoptionError("temporary container identity became ambiguous")
    labels = _object(_object(inspection[0], "container").get("Config"), "config").get("Labels")
    labels = _object(labels, "temporary labels")
    if (
        labels.get("io.heyi.knowledgebases.owner") != OWNER
        or labels.get("io.heyi.knowledgebases.purpose") != "legacy-adoption-drill"
    ):
        raise AdoptionError("temporary container ownership changed")
    state = _object(inspection[0].get("State"), "temporary state")
    if state.get("Running") is True:
        runner.run((runner.docker, "stop", "--time", "30", container_id), timeout=60)
    runner.run((runner.docker, "rm", container_id), timeout=60)


def _run_mc_backup(
    runner: Runner,
    inventory: LegacyInventory,
    runtime: Mapping[str, str],
    objects_dir: Path,
    run_token: str,
) -> None:
    minio = _service(inventory, "minio")
    mc = next(
        (
            item
            for item in inventory.containers
            if item.service in {"minio-multipart-gc", "minio-init"}
        ),
        None,
    )
    if mc is None:
        raise AdoptionError("legacy project has no verified MinIO client image")
    network = _find_shared_network(inventory, minio, mc)
    name = f"heyi-legacy-backup-{run_token[:20]}"
    script = (
        "set -eu; export MC_CONFIG_DIR=/run/heyi-mc/config; "
        'mc alias set source http://minio:9000 "$MINIO_ROOT_USER" '
        '"$MINIO_ROOT_PASSWORD" --api S3v4 --path on >/dev/null; '
        'exec mc mirror --overwrite --preserve "source/$MINIO_BUCKET" /backup/objects'
    )
    environment = {
        "MINIO_ROOT_USER": runtime["MINIO_ROOT_USER"],
        "MINIO_ROOT_PASSWORD": runtime["MINIO_ROOT_PASSWORD"],
        "MINIO_BUCKET": runtime["MINIO_BUCKET"],
    }
    created = (
        runner.run(
            (
                runner.docker,
                "create",
                "--name",
                name,
                "--label",
                f"io.heyi.knowledgebases.owner={OWNER}",
                "--label",
                "io.heyi.knowledgebases.purpose=legacy-adoption-drill",
                "--network",
                network,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--memory",
                "256m",
                "--cpus",
                "0.25",
                "--pids-limit",
                "128",
                "--tmpfs",
                "/run/heyi-mc:size=64m,mode=0700",
                "--mount",
                f"type=bind,source={objects_dir.parent},target=/backup",
                "--env",
                "MINIO_ROOT_USER",
                "--env",
                "MINIO_ROOT_PASSWORD",
                "--env",
                "MINIO_BUCKET",
                "--entrypoint",
                "/bin/sh",
                mc.image_id,
                "-ec",
                script,
            ),
            extra_env=environment,
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    if _CONTAINER_ID.fullmatch(created) is None:
        raise AdoptionError("temporary MinIO backup container id is invalid")
    try:
        with Path(os.devnull).open("wb") as sink:
            runner.run(
                (runner.docker, "start", "--attach", created),
                timeout=86_400,
                stdout_file=sink,
            )
        exit_code = (
            runner.run((runner.docker, "inspect", "--format", "{{.State.ExitCode}}", created))
            .decode("ascii", errors="strict")
            .strip()
        )
        if exit_code != "0":
            raise AdoptionError("MinIO logical backup failed")
    finally:
        _cleanup_exact_container(runner, created)


def _seal_private_tree(root: Path) -> None:
    """Make a newly-created backup tree root-owned and unreadable to other users."""

    protected_directory(root, modes=frozenset({0o700}))
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        current_info = current_path.lstat()
        if not stat.S_ISDIR(current_info.st_mode) or stat.S_ISLNK(current_info.st_mode):
            raise AdoptionError("private backup tree contains an unsafe directory")
        _posix_chown(current_path, 0, 0)
        os.chmod(current_path, 0o700)
        for name in directories:
            candidate = current_path / name
            if candidate.is_symlink() or not candidate.is_dir():
                raise AdoptionError("private backup tree contains an unsafe directory")
        for name in files:
            candidate = current_path / name
            info = candidate.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
                raise AdoptionError("private backup tree contains an unsafe file")
            _posix_chown(candidate, 0, 0)
            os.chmod(candidate, 0o400)


def _object_manifest(objects_dir: Path, destination: Path) -> dict[str, Any]:
    """Stream a deterministic NDJSON manifest without retaining object keys in RAM."""

    protected_directory(objects_dir, modes=frozenset({0o700}))
    parent = protected_directory(destination.parent, modes=frozenset({0o700}))
    if destination.exists() or destination.is_symlink():
        raise AdoptionError("object manifest already exists")
    temporary = parent / f".{destination.name}.{secrets.token_hex(16)}.tmp"
    total_bytes = 0
    object_count = 0
    try:
        with temporary.open("xb") as stream:
            stream.write(
                _canonical_json({"schema_version": 1, "kind": "heyi-minio-object-backup-ndjson"})
            )
            for current, directories, files in os.walk(objects_dir, followlinks=False):
                directories.sort()
                files.sort()
                current_path = Path(current)
                for directory in directories:
                    candidate = current_path / directory
                    if candidate.is_symlink() or not candidate.is_dir():
                        raise AdoptionError("object backup contains an unsafe directory")
                for filename in files:
                    candidate = current_path / filename
                    info = candidate.lstat()
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or stat.S_ISLNK(info.st_mode)
                        or info.st_nlink != 1
                    ):
                        raise AdoptionError("object backup contains an unsafe file")
                    relative = candidate.relative_to(objects_dir).as_posix()
                    pure = PurePosixPath(relative)
                    if pure.is_absolute() or ".." in pure.parts or not relative:
                        raise AdoptionError("object backup path is unsafe")
                    stream.write(
                        _canonical_json(
                            {
                                "key": relative,
                                "size_bytes": info.st_size,
                                "sha256": _sha256_file(candidate),
                            }
                        )
                    )
                    total_bytes += info.st_size
                    object_count += 1
            stream.write(
                _canonical_json(
                    {
                        "type": "summary",
                        "object_count": object_count,
                        "total_bytes": total_bytes,
                    }
                )
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o400)
        os.replace(temporary, destination)
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return {
        "object_count": object_count,
        "total_bytes": total_bytes,
        "manifest_sha256": _sha256_file(destination),
        "manifest_size_bytes": destination.stat().st_size,
    }


def _iter_object_manifest(path: Path) -> Iterable[tuple[str, int, str]]:
    protected_file(path, modes=frozenset({0o400, 0o440, 0o444}), max_bytes=2**63 - 1)
    with path.open("rb") as stream:
        header_raw = stream.readline(MAX_CONTROL_FILE + 1)
        if len(header_raw) > MAX_CONTROL_FILE:
            raise AdoptionError("object manifest header is too large")
        try:
            header = json.loads(header_raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AdoptionError("object manifest header is malformed") from exc
        if header != {"kind": "heyi-minio-object-backup-ndjson", "schema_version": 1}:
            raise AdoptionError("object manifest identity differs")
        observed_count = 0
        observed_bytes = 0
        summary_seen = False
        for raw in stream:
            if len(raw) > MAX_CONTROL_FILE:
                raise AdoptionError("object manifest line is too large")
            try:
                value = json.loads(raw)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise AdoptionError("object manifest row is malformed") from exc
            row = _object(value, "object manifest row")
            if set(row) == {"type", "object_count", "total_bytes"}:
                if summary_seen or row.get("type") != "summary":
                    raise AdoptionError("object manifest has an invalid summary")
                if (
                    row.get("object_count") != observed_count
                    or row.get("total_bytes") != observed_bytes
                ):
                    raise AdoptionError("object manifest summary differs")
                summary_seen = True
                continue
            if summary_seen or set(row) != {"key", "size_bytes", "sha256"}:
                raise AdoptionError("object manifest row schema differs")
            key = _string(row.get("key"), "object key")
            size = row.get("size_bytes")
            digest = row.get("sha256")
            pure = PurePosixPath(key)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or type(size) is not int
                or size < 0
                or not isinstance(digest, str)
                or _SHA256.fullmatch(digest) is None
            ):
                raise AdoptionError("object manifest row identity is unsafe")
            observed_count += 1
            observed_bytes += size
            yield key, size, digest
        if not summary_seen:
            raise AdoptionError("object manifest summary is missing")


def _ca_tar_payload(ca_root: Path) -> tuple[bytes, int]:
    canonical = protected_directory(ca_root, modes=frozenset({0o700, 0o750, 0o755}))
    stream = io.BytesIO()
    count = 0
    total = 0
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for current, directories, files in os.walk(canonical, followlinks=False):
            current_path = Path(current)
            for directory in directories:
                candidate = current_path / directory
                if candidate.is_symlink() or not candidate.is_dir():
                    raise AdoptionError("Caddy CA tree contains an unsafe directory")
            for filename in sorted(files):
                candidate = current_path / filename
                info = candidate.lstat()
                if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    raise AdoptionError("Caddy CA tree contains an unsafe file")
                payload = candidate.read_bytes()
                total += len(payload)
                count += 1
                if total > MAX_CA_PLAINTEXT:
                    raise AdoptionError("Caddy CA plaintext exceeds the encrypted escrow limit")
                relative = candidate.relative_to(canonical).as_posix()
                member = tarfile.TarInfo(relative)
                member.size = len(payload)
                member.mode = 0o600
                member.uid = 0
                member.gid = 0
                member.uname = "root"
                member.gname = "root"
                member.mtime = 0
                archive.addfile(member, io.BytesIO(payload))
    if count == 0:
        raise AdoptionError("Caddy CA tree is empty")
    return stream.getvalue(), count


def _encrypt_ca_escrow(
    runner: Runner,
    *,
    ca_root: Path,
    recipient_certificate: Path,
    binding_key: bytes,
    destination: Path,
) -> dict[str, Any]:
    certificate = protected_file(
        recipient_certificate,
        modes=frozenset({0o400, 0o440, 0o444}),
        max_bytes=65_536,
    )
    plaintext, file_count = _ca_tar_payload(ca_root)
    plaintext_hmac = _hmac_binding(plaintext, binding_key, domain="heyi-caddy-ca-v1")
    parent = protected_directory(destination.parent, modes=frozenset({0o700}))
    temporary = parent / f".{destination.name}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            runner.run(
                (
                    "/usr/bin/openssl",
                    "cms",
                    "-encrypt",
                    "-binary",
                    "-aes256",
                    "-outform",
                    "DER",
                    "-recip",
                    str(certificate),
                ),
                input_bytes=plaintext,
                stdout_file=stream,
                timeout=120,
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o400)
        os.replace(temporary, destination)
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        # Remove all Python references to the plaintext as early as practical.
        plaintext = b""
    runner.run(
        (
            "/usr/bin/openssl",
            "cms",
            "-cmsout",
            "-inform",
            "DER",
            "-in",
            str(destination),
            "-noout",
        ),
        timeout=30,
    )
    return {
        "ciphertext_path": str(destination),
        "ciphertext_sha256": _sha256_file(destination),
        "ciphertext_size_bytes": destination.stat().st_size,
        "plaintext_opaque_hmac_sha256": plaintext_hmac,
        "file_count": file_count,
        "recipient_certificate_sha256": _sha256_file(certificate),
        "private_key_bytes_in_evidence": False,
        "cos_transfer_allowed": False,
    }


def _create_drill_network(runner: Runner, run_token: str) -> tuple[str, str]:
    name = f"heyi-legacy-drill-{run_token[:20]}"
    network_id = (
        runner.run(
            (
                runner.docker,
                "network",
                "create",
                "--internal",
                "--driver",
                "bridge",
                "--label",
                f"io.heyi.knowledgebases.owner={OWNER}",
                "--label",
                "io.heyi.knowledgebases.purpose=legacy-adoption-drill",
                name,
            )
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    if _CONTAINER_ID.fullmatch(network_id) is None:
        raise AdoptionError("restore-drill network id is invalid")
    return name, network_id


def _cleanup_drill_network(runner: Runner, network_id: str, expected_name: str) -> None:
    raw = runner.docker_json(("network", "inspect", network_id))
    if not isinstance(raw, list) or len(raw) != 1:
        raise AdoptionError("restore-drill network identity became ambiguous")
    network = _object(raw[0], "restore-drill network")
    labels = _object(network.get("Labels"), "restore-drill network labels")
    if (
        network.get("Name") != expected_name
        or labels.get("io.heyi.knowledgebases.owner") != OWNER
        or labels.get("io.heyi.knowledgebases.purpose") != "legacy-adoption-drill"
        or network.get("Internal") is not True
        or _object(network.get("Containers", {}), "restore-drill endpoints")
    ):
        raise AdoptionError("restore-drill network ownership or isolation changed")
    runner.run((runner.docker, "network", "rm", network_id), timeout=60)


def _wait_for_postgres(runner: Runner, container_id: str, user: str) -> None:
    for _ in range(60):
        try:
            runner.run(
                (
                    runner.docker,
                    "exec",
                    container_id,
                    "pg_isready",
                    "--username",
                    user,
                    "--dbname",
                    user,
                ),
                timeout=5,
            )
            return
        except CommandError:
            time.sleep(1)
    raise AdoptionError("isolated PostgreSQL did not become ready")


def _query_database_counts(
    runner: Runner,
    container_id: str,
    *,
    user: str,
    database: str,
    expected_tables: Iterable[str],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for label in sorted(expected_tables):
        if "." not in label:
            raise AdoptionError("expected table identity is malformed")
        schema, table = label.split(".", 1)
        raw = _docker_exec_text(
            runner,
            container_id,
            (
                "psql",
                "--no-psqlrc",
                "--tuples-only",
                "--no-align",
                "--set",
                "ON_ERROR_STOP=1",
                "--username",
                user,
                "--dbname",
                database,
                "--command",
                _count_statement(schema, table),
            ),
            timeout=3_600,
        ).strip()
        if not raw.isdecimal():
            raise AdoptionError("restored table count is malformed")
        counts[label] = int(raw)
    return counts


def _start_restore_postgres(
    runner: Runner,
    *,
    inventory: LegacyInventory,
    network: str,
    scratch: Path,
    database_backup: Path,
    run_token: str,
) -> tuple[str, str, str, str]:
    postgres = _service(inventory, "postgres")
    data = _new_private_directory(scratch, "postgres-data")
    restore_user = f"restore_{run_token[:12]}"
    restore_password = secrets.token_urlsafe(48)
    restore_database = "legacy_restore"
    name = f"heyi-legacy-pg-{run_token[:20]}"
    environment = {
        "POSTGRES_USER": restore_user,
        "POSTGRES_PASSWORD": restore_password,
        "POSTGRES_DB": restore_user,
    }
    container_id = (
        runner.run(
            (
                runner.docker,
                "create",
                "--name",
                name,
                "--label",
                f"io.heyi.knowledgebases.owner={OWNER}",
                "--label",
                "io.heyi.knowledgebases.purpose=legacy-adoption-drill",
                "--network",
                network,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--memory",
                "2g",
                "--cpus",
                "1.0",
                "--pids-limit",
                "256",
                "--shm-size",
                "256m",
                "--mount",
                f"type=bind,source={data},target=/var/lib/postgresql/data",
                "--mount",
                f"type=bind,source={database_backup},target=/backup,readonly",
                "--env",
                "POSTGRES_USER",
                "--env",
                "POSTGRES_PASSWORD",
                "--env",
                "POSTGRES_DB",
                postgres.image_id,
            ),
            extra_env=environment,
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    if _CONTAINER_ID.fullmatch(container_id) is None:
        raise AdoptionError("restore PostgreSQL container id is invalid")
    runner.run((runner.docker, "start", container_id), timeout=60)
    _wait_for_postgres(runner, container_id, restore_user)
    runner.run(
        (
            runner.docker,
            "exec",
            container_id,
            "psql",
            "--no-psqlrc",
            "--set",
            "ON_ERROR_STOP=1",
            "--username",
            restore_user,
            "--dbname",
            restore_user,
            "--file",
            "/backup/globals.sql",
        ),
        timeout=1_800,
    )
    runner.run(
        (
            runner.docker,
            "exec",
            container_id,
            "createdb",
            "--username",
            restore_user,
            restore_database,
        ),
        timeout=120,
    )
    runner.run(
        (
            runner.docker,
            "exec",
            container_id,
            "pg_restore",
            "--exit-on-error",
            "--no-owner",
            "--no-acl",
            "--username",
            restore_user,
            "--dbname",
            restore_database,
            "/backup/database.dump",
        ),
        timeout=14_400,
    )
    return container_id, restore_user, restore_password, restore_database


def _wait_for_minio(runner: Runner, container_id: str) -> None:
    for _ in range(60):
        try:
            runner.run(
                (
                    runner.docker,
                    "exec",
                    container_id,
                    "curl",
                    "--fail",
                    "--silent",
                    "http://127.0.0.1:9000/minio/health/ready",
                ),
                timeout=5,
            )
            return
        except CommandError:
            time.sleep(1)
    raise AdoptionError("isolated MinIO did not become ready")


def _start_restore_minio(
    runner: Runner,
    *,
    inventory: LegacyInventory,
    network: str,
    scratch: Path,
    objects_dir: Path,
    bucket: str,
    run_token: str,
) -> tuple[str, str, str]:
    minio = _service(inventory, "minio")
    mc = next(
        (
            item
            for item in inventory.containers
            if item.service in {"minio-multipart-gc", "minio-init"}
        ),
        None,
    )
    if mc is None:
        raise AdoptionError("legacy project has no verified MinIO client image")
    data = _new_private_directory(scratch, "minio-data")
    root_user = f"restore{run_token[:12]}"
    root_password = secrets.token_urlsafe(48)
    minio_name = f"heyi-legacy-minio-{run_token[:18]}"
    environment = {"MINIO_ROOT_USER": root_user, "MINIO_ROOT_PASSWORD": root_password}
    minio_id = (
        runner.run(
            (
                runner.docker,
                "create",
                "--name",
                minio_name,
                "--label",
                f"io.heyi.knowledgebases.owner={OWNER}",
                "--label",
                "io.heyi.knowledgebases.purpose=legacy-adoption-drill",
                "--network",
                network,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--memory",
                "1280m",
                "--cpus",
                "0.75",
                "--pids-limit",
                "256",
                "--mount",
                f"type=bind,source={data},target=/data",
                "--env",
                "MINIO_ROOT_USER",
                "--env",
                "MINIO_ROOT_PASSWORD",
                minio.image_id,
                "server",
                "/data",
                "--console-address",
                ":9001",
            ),
            extra_env=environment,
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    if _CONTAINER_ID.fullmatch(minio_id) is None:
        raise AdoptionError("restore MinIO container id is invalid")
    runner.run((runner.docker, "start", minio_id), timeout=60)
    _wait_for_minio(runner, minio_id)

    mc_name = f"heyi-legacy-mc-{run_token[:20]}"
    mc_script = (
        "set -eu; export MC_CONFIG_DIR=/run/heyi-mc/config; "
        "mc alias set restore http://" + minio_name + ':9000 "$MINIO_ROOT_USER" '
        '"$MINIO_ROOT_PASSWORD" --api S3v4 --path on >/dev/null; '
        'mc mb --ignore-existing "restore/$MINIO_BUCKET" >/dev/null; '
        'mc mirror --overwrite --preserve /backup/objects "restore/$MINIO_BUCKET"; '
        "touch /run/heyi-mc/restore-complete; "
        "exec sleep 86400"
    )
    mc_environment = {
        "MINIO_ROOT_USER": root_user,
        "MINIO_ROOT_PASSWORD": root_password,
        "MINIO_BUCKET": bucket,
    }
    mc_id = (
        runner.run(
            (
                runner.docker,
                "create",
                "--name",
                mc_name,
                "--label",
                f"io.heyi.knowledgebases.owner={OWNER}",
                "--label",
                "io.heyi.knowledgebases.purpose=legacy-adoption-drill",
                "--network",
                network,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--memory",
                "256m",
                "--cpus",
                "0.25",
                "--pids-limit",
                "128",
                "--tmpfs",
                "/run/heyi-mc:size=64m,mode=0700",
                "--mount",
                f"type=bind,source={objects_dir.parent},target=/backup,readonly",
                "--env",
                "MINIO_ROOT_USER",
                "--env",
                "MINIO_ROOT_PASSWORD",
                "--env",
                "MINIO_BUCKET",
                "--entrypoint",
                "/bin/sh",
                mc.image_id,
                "-ec",
                mc_script,
            ),
            extra_env=mc_environment,
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    if _CONTAINER_ID.fullmatch(mc_id) is None:
        raise AdoptionError("restore MinIO client container id is invalid")
    runner.run((runner.docker, "start", mc_id), timeout=60)
    for _ in range(60):
        state = (
            runner.run(
                (
                    runner.docker,
                    "inspect",
                    "--format",
                    "{{.State.Running}} {{.State.ExitCode}}",
                    mc_id,
                )
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        if state == "true 0":
            try:
                runner.run(
                    (
                        runner.docker,
                        "exec",
                        mc_id,
                        "/bin/busybox",
                        "test",
                        "-f",
                        "/run/heyi-mc/restore-complete",
                    ),
                    timeout=5,
                )
                break
            except CommandError:
                time.sleep(1)
                continue
        if state.startswith("false "):
            raise AdoptionError("isolated MinIO restore client exited early")
        time.sleep(1)
    else:
        raise AdoptionError("isolated MinIO restore did not complete")
    return minio_id, mc_id, f"restore/{bucket}"


def _verify_restored_objects(
    runner: Runner,
    *,
    mc_container_id: str,
    alias_bucket: str,
    manifest: Path,
) -> tuple[int, int]:
    total = 0
    count = 0
    for key, expected_size, digest in _iter_object_manifest(manifest):
        observed_digest, observed_size = runner.sha256_stdout(
            (
                runner.docker,
                "exec",
                mc_container_id,
                "mc",
                "cat",
                f"{alias_bucket}/{key}",
            ),
            timeout=7_200,
        )
        if not hmac.compare_digest(observed_digest, digest):
            raise AdoptionError("restored MinIO object digest differs")
        if observed_size != expected_size:
            raise AdoptionError("restored MinIO object size differs")
        total += observed_size
        count += 1
    return count, total


def _safe_remove_scratch(path: Path, parent: Path, marker: str) -> None:
    canonical_parent = protected_directory(parent, modes=frozenset({0o700, 0o750}))
    canonical = protected_directory(path, modes=frozenset({0o700}))
    if canonical.parent != canonical_parent or canonical.name != f"drill-{marker}":
        raise AdoptionError("refusing to clean an unverified restore-drill directory")
    marker_path = canonical / ".heyi-legacy-drill"
    if marker_path.read_text(encoding="ascii").strip() != marker:
        raise AdoptionError("restore-drill cleanup marker differs")
    shutil.rmtree(canonical)
    directory_descriptor = os.open(canonical_parent, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _run_restore_drill(
    runner: Runner,
    *,
    inventory: LegacyInventory,
    scratch_parent: Path,
    database_backup: Path,
    objects_dir: Path,
    bucket: str,
    expected_counts: Mapping[str, int],
    expected_schema_head: str,
    object_manifest: Path,
    expected_object_count: int,
    expected_object_bytes: int,
    run_token: str,
) -> dict[str, Any]:
    protected_directory(scratch_parent, modes=frozenset({0o700, 0o750}))
    database_bytes = sum(
        path.stat().st_size for path in database_backup.iterdir() if path.is_file()
    )
    required = expected_object_bytes + database_bytes * 3 + 5 * 1024**3
    if shutil.disk_usage(scratch_parent).free < required:
        raise AdoptionError("restore scratch lacks full-restore capacity plus 5 GiB reserve")
    scratch = scratch_parent / f"drill-{run_token}"
    scratch.mkdir(mode=0o700)
    _posix_chown(scratch, 0, 0)
    _atomic_write(scratch / ".heyi-legacy-drill", (run_token + "\n").encode("ascii"), mode=0o400)
    network_name = ""
    network_id = ""
    postgres_id = ""
    minio_id = ""
    mc_id = ""
    try:
        network_name, network_id = _create_drill_network(runner, run_token)
        postgres_id, restore_user, _, restore_database = _start_restore_postgres(
            runner,
            inventory=inventory,
            network=network_name,
            scratch=scratch,
            database_backup=database_backup,
            run_token=run_token,
        )
        restored_schema = _docker_exec_text(
            runner,
            postgres_id,
            (
                "psql",
                "--no-psqlrc",
                "--tuples-only",
                "--no-align",
                "--set",
                "ON_ERROR_STOP=1",
                "--username",
                restore_user,
                "--dbname",
                restore_database,
                "--command",
                "SELECT version_num FROM alembic_version;",
            ),
        ).strip()
        if restored_schema != expected_schema_head:
            raise AdoptionError("restored PostgreSQL schema head differs")
        restored_counts = _query_database_counts(
            runner,
            postgres_id,
            user=restore_user,
            database=restore_database,
            expected_tables=expected_counts,
        )
        if restored_counts != dict(expected_counts):
            raise AdoptionError("restored PostgreSQL table counts differ")
        minio_id, mc_id, alias_bucket = _start_restore_minio(
            runner,
            inventory=inventory,
            network=network_name,
            scratch=scratch,
            objects_dir=objects_dir,
            bucket=bucket,
            run_token=run_token,
        )
        object_count, restored_bytes = _verify_restored_objects(
            runner,
            mc_container_id=mc_id,
            alias_bucket=alias_bucket,
            manifest=object_manifest,
        )
        if object_count != expected_object_count or restored_bytes != expected_object_bytes:
            raise AdoptionError("restored MinIO byte count differs")
        return {
            "status": "passed",
            "tested_at": _utc_now().isoformat().replace("+00:00", "Z"),
            "source_schema_head": expected_schema_head,
            "database_table_count": len(expected_counts),
            "database_row_count": sum(expected_counts.values()),
            "object_count": object_count,
            "object_bytes": restored_bytes,
            "network_internal": True,
            "published_ports": 0,
        }
    finally:
        for container_id in (mc_id, minio_id, postgres_id):
            if container_id:
                _cleanup_exact_container(runner, container_id)
        if network_id:
            _cleanup_drill_network(runner, network_id, network_name)
        _safe_remove_scratch(scratch, scratch_parent, run_token)


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise AdoptionError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdoptionError(f"{label} must be an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise AdoptionError(f"{label} must use UTC")
    return parsed.astimezone(UTC)


def _read_json_file(path: Path, *, max_bytes: int = MAX_CONTROL_FILE) -> dict[str, Any]:
    payload = _open_protected_bytes(path, max_bytes=max_bytes)
    try:
        return _object(json.loads(payload), "JSON document")
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AdoptionError("protected JSON document is malformed") from exc


def _descriptor(path: Path) -> dict[str, Any]:
    protected_file(
        path,
        modes=frozenset({0o400, 0o440, 0o444}),
        max_bytes=2**63 - 1,
    )
    return {
        "path": str(path),
        "sha256": _sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def _verify_descriptor(value: object, *, root: Path | None = None) -> Path:
    document = _object(value, "artifact descriptor")
    if set(document) != {"path", "sha256", "size_bytes"}:
        raise AdoptionError("artifact descriptor schema differs")
    raw_path = document.get("path")
    digest = document.get("sha256")
    size = document.get("size_bytes")
    if (
        not isinstance(raw_path, str)
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or type(size) is not int
        or size <= 0
    ):
        raise AdoptionError("artifact descriptor identity is malformed")
    path = protected_file(
        Path(raw_path),
        modes=frozenset({0o400, 0o440, 0o444}),
        max_bytes=2**63 - 1,
    )
    if root is not None:
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise AdoptionError("artifact lies outside its protected root") from exc
    if path.stat().st_size != size or not hmac.compare_digest(_sha256_file(path), digest):
        raise AdoptionError("artifact differs from its recorded descriptor")
    return path


def _env_binding(path: Path, binding_key: bytes) -> str:
    return _hmac_binding(
        _open_protected_bytes(path),
        binding_key,
        domain="heyi-legacy-compose-env-v1",
    )


def _load_plan_identity(
    path: Path, *, enforce_freshness: bool = True
) -> tuple[dict[str, Any], str]:
    plan = _read_json_file(path)
    expected = {
        "schema_version",
        "kind",
        "project",
        "created_at",
        "git_sha",
        "data_root",
        "runtime_env",
        "legacy_compose",
        "host_isolation_guard",
        "target_manifest",
        "inventory_sha256",
        "topology_sha256",
        "inventory",
        "safety",
    }
    if set(plan) != expected:
        raise AdoptionError("legacy adoption plan schema differs")
    if (
        plan.get("schema_version") != 2
        or plan.get("kind") != "heyi-legacy-adoption-plan"
        or plan.get("project") != PROJECT
        or plan.get("data_root") != str(DATA_ROOT)
        or not isinstance(plan.get("git_sha"), str)
        or _GIT_SHA.fullmatch(str(plan.get("git_sha"))) is None
    ):
        raise AdoptionError("legacy adoption plan identity differs")
    created_at = _timestamp(plan.get("created_at"), "plan.created_at")
    now = _utc_now()
    if enforce_freshness and not (
        now - timedelta(days=30) <= created_at <= now + timedelta(minutes=5)
    ):
        raise AdoptionError("legacy adoption plan is stale or future-dated")
    expected_safety = {
        "protected_other_port": 10050,
        "delete_containers": True,
        "delete_project_networks": True,
        "delete_named_volumes": False,
        "delete_bind_data": False,
        "global_prune": False,
        "restart_docker_daemon": False,
    }
    if plan.get("safety") != expected_safety:
        raise AdoptionError("legacy adoption plan safety contract differs")
    inventory_digest = plan.get("inventory_sha256")
    topology_digest = plan.get("topology_sha256")
    if (
        not isinstance(inventory_digest, str)
        or _SHA256.fullmatch(inventory_digest) is None
        or not isinstance(topology_digest, str)
        or _SHA256.fullmatch(topology_digest) is None
    ):
        raise AdoptionError("legacy adoption inventory binding is malformed")
    if not hmac.compare_digest(
        _sha256_bytes(_canonical_json(plan.get("inventory"))), inventory_digest
    ):
        raise AdoptionError("legacy adoption plan inventory was modified")
    return plan, _plan_digest(plan)


def _validate_plan(
    path: Path,
    binding_key: bytes,
    *,
    enforce_freshness: bool = True,
) -> tuple[dict[str, Any], str, dict[str, str], tuple[Path, ...], tuple[Path, ...]]:
    plan, plan_digest = _load_plan_identity(path, enforce_freshness=enforce_freshness)

    runtime_entry = _object(plan.get("runtime_env"), "runtime environment binding")
    if set(runtime_entry) != {"path", "opaque_hmac_sha256"}:
        raise AdoptionError("runtime environment binding schema differs")
    runtime_path = Path(_string(runtime_entry.get("path"), "runtime environment path"))
    runtime, runtime_binding = parse_runtime_environment(runtime_path, binding_key)
    expected_runtime_binding = _string(
        runtime_entry.get("opaque_hmac_sha256"), "runtime environment HMAC"
    )
    if not hmac.compare_digest(runtime_binding, expected_runtime_binding):
        raise AdoptionError("runtime environment opaque binding differs")

    compose_entry = _object(plan.get("legacy_compose"), "legacy Compose binding")
    if set(compose_entry) != {"files", "service_bindings", "env_files"}:
        raise AdoptionError("legacy Compose binding schema differs")
    compose_paths: list[Path] = []
    for raw_file in _list(compose_entry.get("files"), "legacy Compose files"):
        entry = _object(raw_file, "legacy Compose file binding")
        if set(entry) != {"path", "sha256"}:
            raise AdoptionError("legacy Compose file binding schema differs")
        compose_path = protected_file(
            Path(_string(entry.get("path"), "legacy Compose path")),
            modes=frozenset({0o400, 0o440, 0o444}),
        )
        compose_digest = _string(entry.get("sha256"), "legacy Compose digest")
        if _SHA256.fullmatch(compose_digest) is None or not hmac.compare_digest(
            _sha256_file(compose_path), compose_digest
        ):
            raise AdoptionError("legacy Compose file differs from its plan")
        compose_paths.append(compose_path)
    if not compose_paths or len(compose_paths) != len(set(compose_paths)):
        raise AdoptionError("legacy Compose file set is empty or duplicated")
    service_bindings = _object(compose_entry.get("service_bindings"), "service bindings")
    planned_containers = _list(
        _object(plan.get("inventory"), "planned inventory").get("containers"),
        "planned containers",
    )
    expected_bindings: dict[str, list[str]] = {}
    for raw_container in planned_containers:
        container = _object(raw_container, "planned container")
        service = _string(container.get("service"), "planned service")
        oneoff = container.get("oneoff")
        container_id = _string(container.get("container_id"), "planned container id")
        if type(oneoff) is not bool:
            raise AdoptionError("planned one-off marker is malformed")
        files = [
            _string(value, "planned Compose binding")
            for value in _list(container.get("config_files"), "planned Compose bindings")
        ]
        key = _container_binding_key(service, oneoff, container_id)
        if key in expected_bindings:
            raise AdoptionError("planned container Compose binding is duplicated")
        expected_bindings[key] = files
    if service_bindings != expected_bindings:
        raise AdoptionError("legacy per-service Compose binding differs")
    if {value for files in expected_bindings.values() for value in files} != {
        str(value) for value in compose_paths
    }:
        raise AdoptionError("legacy per-service Compose binding is incomplete")
    env_paths: list[Path] = []
    seen_env_paths: set[Path] = set()
    for raw_entry in _list(compose_entry.get("env_files"), "legacy environment files"):
        entry = _object(raw_entry, "legacy environment binding")
        if set(entry) != {"path", "opaque_hmac_sha256"}:
            raise AdoptionError("legacy environment binding schema differs")
        env_path = protected_file(
            Path(_string(entry.get("path"), "legacy environment path")),
            modes=frozenset({0o400, 0o440, 0o444, 0o600}),
        )
        if env_path in seen_env_paths:
            raise AdoptionError("legacy environment path is duplicated")
        seen_env_paths.add(env_path)
        observed_binding = _env_binding(env_path, binding_key)
        expected_binding = _string(entry.get("opaque_hmac_sha256"), "legacy environment HMAC")
        if not hmac.compare_digest(observed_binding, expected_binding):
            raise AdoptionError("legacy environment opaque binding differs")
        env_paths.append(env_path)

    target_entry = _object(plan.get("target_manifest"), "target manifest binding")
    if set(target_entry) != {"path", "sha256"}:
        raise AdoptionError("target manifest binding schema differs")
    target_path = protected_file(
        Path(_string(target_entry.get("path"), "target manifest path")),
        modes=frozenset({0o400, 0o440, 0o444}),
    )
    target_digest = _string(target_entry.get("sha256"), "target manifest digest")
    if _SHA256.fullmatch(target_digest) is None or not hmac.compare_digest(
        _sha256_file(target_path), target_digest
    ):
        raise AdoptionError("target manifest differs from its plan")
    guard_entry = _object(plan.get("host_isolation_guard"), "host-isolation guard binding")
    if set(guard_entry) != {"path", "sha256"}:
        raise AdoptionError("host-isolation guard binding schema differs")
    guard_path = protected_file(
        Path(_string(guard_entry.get("path"), "host-isolation guard path")),
        modes=frozenset({0o400, 0o440, 0o444, 0o644}),
    )
    if guard_path != Path(__file__).resolve(strict=True).with_name("host_isolation_guard.py"):
        raise AdoptionError("host-isolation guard is not from this release")
    guard_digest = _string(guard_entry.get("sha256"), "host-isolation guard digest")
    if _SHA256.fullmatch(guard_digest) is None or not hmac.compare_digest(
        _sha256_file(guard_path), guard_digest
    ):
        raise AdoptionError("host-isolation guard differs from its plan")
    protected_directory(DATA_ROOT, modes=frozenset({0o700, 0o750, 0o755}))
    return plan, plan_digest, runtime, tuple(compose_paths), tuple(env_paths)


def _planned_inventory(plan: Mapping[str, Any]) -> LegacyInventory:
    document = _object(plan.get("inventory"), "planned inventory")
    if set(document) != {"containers", "networks", "volumes"}:
        raise AdoptionError("planned inventory schema differs")
    containers: list[ContainerRecord] = []
    container_keys = {
        "service",
        "container_id",
        "image_id",
        "config_image",
        "config_hash",
        "config_files",
        "oneoff",
        "running",
        "restart_count",
        "mounts",
        "networks",
        "published_ports",
    }
    for raw in _list(document.get("containers"), "planned containers"):
        item = _object(raw, "planned container")
        if set(item) != container_keys:
            raise AdoptionError("planned container schema differs")
        oneoff = item.get("oneoff")
        running = item.get("running")
        restart_count = item.get("restart_count")
        if type(oneoff) is not bool or type(running) is not bool or type(restart_count) is not int:
            raise AdoptionError("planned container state is malformed")
        service = _string(item.get("service"), "planned service")
        if (oneoff and service not in KNOWN_ONEOFF_SERVICES) or (
            not oneoff and service not in ALLOWED_SERVICES
        ):
            raise AdoptionError("planned container service is not approved")
        if oneoff and running:
            raise AdoptionError("planned one-off container is running")
        mounts: list[tuple[str, str, bool, str]] = []
        for raw_mount in _list(item.get("mounts"), "planned mounts"):
            mount = _list(raw_mount, "planned mount")
            if len(mount) != 4 or type(mount[2]) is not bool:
                raise AdoptionError("planned mount schema differs")
            mounts.append(
                (
                    _string(mount[0], "planned mount source"),
                    _string(mount[1], "planned mount destination"),
                    mount[2],
                    _string(mount[3], "planned mount type"),
                )
            )
        if any(mount[3] not in {"bind", "volume"} for mount in mounts):
            raise AdoptionError("planned mount type is unsafe")
        container_id = _string(item.get("container_id"), "planned container id")
        image_id = _string(item.get("image_id"), "planned image id")
        config_image = _string(item.get("config_image"), "planned configured image")
        config_hash = _string(item.get("config_hash"), "planned config hash")
        config_files = tuple(
            _string(value, "planned Compose path")
            for value in _list(item.get("config_files"), "planned Compose paths")
        )
        if (
            _CONTAINER_ID.fullmatch(container_id) is None
            or _IMAGE_ID.fullmatch(image_id) is None
            or _IMMUTABLE_IMAGE.fullmatch(config_image) is None
            or _SHA256.fullmatch(config_hash) is None
            or config_files != _compose_label_paths(",".join(config_files))
        ):
            raise AdoptionError("planned container immutable identity is malformed")
        containers.append(
            ContainerRecord(
                service=service,
                container_id=container_id,
                image_id=image_id,
                config_image=config_image,
                config_hash=config_hash,
                config_files=config_files,
                oneoff=oneoff,
                running=running,
                restart_count=restart_count,
                mounts=tuple(mounts),
                networks=tuple(
                    _string(value, "planned network")
                    for value in _list(item.get("networks"), "planned networks")
                ),
                published_ports=tuple(
                    _string(value, "planned published port")
                    for value in _list(item.get("published_ports"), "planned ports")
                ),
            )
        )
    networks: list[NetworkRecord] = []
    for raw in _list(document.get("networks"), "planned networks"):
        item = _object(raw, "planned network")
        if set(item) != {"name", "network_id", "internal", "attached_container_ids"}:
            raise AdoptionError("planned network schema differs")
        internal = item.get("internal")
        if type(internal) is not bool:
            raise AdoptionError("planned network isolation is malformed")
        networks.append(
            NetworkRecord(
                name=_string(item.get("name"), "planned network name"),
                network_id=_string(item.get("network_id"), "planned network id"),
                internal=internal,
                attached_container_ids=tuple(
                    _string(value, "planned network endpoint")
                    for value in _list(
                        item.get("attached_container_ids"), "planned network endpoints"
                    )
                ),
            )
        )
    volumes: list[VolumeRecord] = []
    for raw in _list(document.get("volumes"), "planned volumes"):
        item = _object(raw, "planned volume")
        if set(item) != {"name", "mountpoint"}:
            raise AdoptionError("planned volume schema differs")
        volumes.append(
            VolumeRecord(
                name=_string(item.get("name"), "planned volume name"),
                mountpoint=_string(item.get("mountpoint"), "planned volume mountpoint"),
            )
        )
    result = LegacyInventory(tuple(containers), tuple(networks), tuple(volumes))
    primary_services = [item.service for item in containers if not item.oneoff]
    if (
        len({item.container_id for item in containers}) != len(containers)
        or len(set(primary_services)) != len(primary_services)
        or not set(primary_services) >= REQUIRED_SERVICES
    ):
        raise AdoptionError("planned primary service inventory is incomplete or ambiguous")
    if inventory_sha256(result) != plan.get("inventory_sha256"):
        raise AdoptionError("planned inventory does not round-trip exactly")
    return result


def _signature(
    runner: Runner,
    *,
    payload: Path,
    signing_key: Path,
    destination: Path,
) -> None:
    key = protected_file(signing_key, modes=frozenset({0o400, 0o600}), max_bytes=65_536)
    try:
        key.relative_to(BACKUP_ROOT)
    except ValueError:
        pass
    else:
        raise AdoptionError("evidence signing key must not reside in the backup root")
    _command_to_new_file(
        runner,
        (
            "/usr/bin/openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(key),
            str(payload),
        ),
        destination,
        timeout=30,
    )


def _verify_signature(
    runner: Runner,
    *,
    payload: Path,
    signature: Path,
    public_key: Path,
) -> None:
    protected_file(payload, modes=frozenset({0o400, 0o440, 0o444}), max_bytes=2**63 - 1)
    protected_file(signature, modes=frozenset({0o400, 0o440, 0o444}), max_bytes=65_536)
    public = protected_file(
        public_key,
        modes=frozenset({0o400, 0o440, 0o444}),
        max_bytes=65_536,
    )
    runner.run(
        (
            "/usr/bin/openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public),
            "-signature",
            str(signature),
            str(payload),
        ),
        timeout=30,
    )


def _database_archive(source: Path, destination: Path) -> None:
    protected_directory(source, modes=frozenset({0o700}))
    required = ("database.dump", "globals.sql", "schema.sql", "table-counts.json")
    paths = [
        protected_file(source / name, modes=frozenset({0o400}), max_bytes=2**63 - 1)
        for name in required
    ]
    parent = protected_directory(destination.parent, modes=frozenset({0o700}))
    if destination.exists() or destination.is_symlink():
        raise AdoptionError("database backup archive already exists")
    temporary = parent / f".{destination.name}.{secrets.token_hex(16)}.tmp"
    try:
        with tarfile.open(temporary, "w", format=tarfile.PAX_FORMAT) as archive:
            for path in paths:
                info = path.lstat()
                member = tarfile.TarInfo(path.name)
                member.size = info.st_size
                member.mode = 0o400
                member.uid = 0
                member.gid = 0
                member.uname = "root"
                member.gname = "root"
                member.mtime = 0
                with path.open("rb") as source_stream:
                    archive.addfile(member, source_stream)
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o400)
        os.replace(temporary, destination)
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _running_services(inventory: LegacyInventory) -> frozenset[str]:
    return frozenset(
        item.service for item in inventory.containers if item.running and not item.oneoff
    )


def _verify_data_bindings(inventory: LegacyInventory) -> None:
    expectations = {
        "postgres": (DATA_ROOT / "postgres", "/var/lib/postgresql/data"),
        "minio": (DATA_ROOT / "minio", "/data"),
    }
    for service, (source, destination) in expectations.items():
        record = _service(inventory, service)
        matches = [
            mount
            for mount in record.mounts
            if mount[1] == destination and mount[2] and mount[3] == "bind"
        ]
        if len(matches) != 1 or Path(matches[0][0]) != source:
            raise AdoptionError(f"legacy {service} data bind path differs")


def _postgres_control_value(
    runner: Runner,
    postgres: ContainerRecord,
    runtime: Mapping[str, str],
    statement: str,
) -> str:
    return _docker_exec_text(
        runner,
        postgres.container_id,
        (
            "psql",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
            "--username",
            runtime["POSTGRES_USER"],
            "--dbname",
            runtime["POSTGRES_DB"],
            "--command",
            statement,
        ),
    ).strip()


def _verify_postgres_17_and_schema(
    runner: Runner,
    inventory: LegacyInventory,
    runtime: Mapping[str, str],
    expected_schema_head: str,
) -> None:
    postgres = _service(inventory, "postgres")
    if not postgres.running:
        raise AdoptionError("legacy PostgreSQL must be running for retirement validation")
    version = _postgres_control_value(runner, postgres, runtime, "SHOW server_version_num;")
    if not version.isdecimal() or not 170_000 <= int(version) < 180_000:
        raise AdoptionError("legacy PostgreSQL major version is not 17")
    schema_head = _postgres_control_value(
        runner, postgres, runtime, "SELECT version_num FROM alembic_version;"
    )
    if schema_head != expected_schema_head or _SCHEMA_HEAD.fullmatch(schema_head) is None:
        raise AdoptionError("legacy PostgreSQL schema differs from signed backup evidence")


def _quiesce_legacy(runner: Runner, inventory: LegacyInventory) -> frozenset[str]:
    original_running = _running_services(inventory)
    data_services = {"postgres", "minio"}
    ordered = list(WRITER_STOP_ORDER)
    ordered.extend(sorted(ALLOWED_SERVICES - set(ordered) - data_services))
    records = {item.service: item for item in inventory.containers}
    for service in ordered:
        record = records.get(service)
        if record is not None and record.running:
            runner.run(
                (
                    runner.docker,
                    "stop",
                    "--time",
                    str(LEGACY_STOP_GRACE_SECONDS),
                    record.container_id,
                ),
                timeout=LEGACY_STOP_COMMAND_TIMEOUT_SECONDS,
            )
    current = collect_inventory(runner)
    still_running = _running_services(current) - data_services
    if still_running:
        raise AdoptionError("legacy writer/edge quiescence did not complete")
    if not {"postgres", "minio"} <= _running_services(current):
        raise AdoptionError("legacy data services are unavailable for logical backup")
    return original_running


def _compose_argv(
    compose_paths: Sequence[Path],
    runtime_path: Path,
    env_paths: Sequence[Path],
) -> tuple[str, ...]:
    values: list[str] = [
        "/usr/bin/docker",
        "compose",
        "--project-name",
        PROJECT,
        "--env-file",
        str(runtime_path),
    ]
    for path in env_paths:
        if path != runtime_path:
            values.extend(("--env-file", str(path)))
    for path in compose_paths:
        values.extend(("--file", str(path)))
    return tuple(values)


def _ordered_primary_services(inventory: LegacyInventory) -> tuple[str, ...]:
    services = {item.service for item in inventory.containers if not item.oneoff}
    ordered = [service for service in START_ORDER if service in services and service != "proxy"]
    ordered.extend(sorted(services - set(ordered) - {"proxy"}))
    if "proxy" in services:
        ordered.append("proxy")
    return tuple(ordered)


def _compose_for_service(
    expected: LegacyInventory,
    service: str,
    available_paths: Sequence[Path],
    runtime_path: Path,
    env_paths: Sequence[Path],
) -> tuple[str, ...]:
    record = _service(expected, service)
    allowed = {str(path): path for path in available_paths}
    if not record.config_files or any(path not in allowed for path in record.config_files):
        raise AdoptionError("service Compose binding differs from the signed plan")
    return _compose_argv(
        tuple(allowed[path] for path in record.config_files), runtime_path, env_paths
    )


def _resume_or_recreate_legacy(
    runner: Runner,
    *,
    expected: LegacyInventory,
    compose_paths: Sequence[Path],
    runtime_path: Path,
    env_paths: Sequence[Path],
    originally_running: frozenset[str],
) -> LegacyInventory:
    expected_ids = {item.container_id for item in expected.containers}
    raw_ids = runner.run(
        (
            runner.docker,
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
        )
    ).decode("ascii", errors="strict")
    current_ids = {line.strip() for line in raw_ids.splitlines() if line.strip()}
    if current_ids == expected_ids:
        current_inventory = collect_inventory(runner)
        if restorable_topology_sha256(current_inventory) != restorable_topology_sha256(expected):
            raise AdoptionError("legacy topology changed while it was quiesced")
        records = {item.service: item for item in current_inventory.containers}
        ordered = list(START_ORDER)
        ordered.extend(sorted(ALLOWED_SERVICES - set(ordered)))
        for service in ordered:
            record = records.get(service)
            if service in originally_running and record is not None and not record.running:
                runner.run((runner.docker, "start", record.container_id), timeout=120)
    else:
        for service in _ordered_primary_services(expected):
            base = _compose_for_service(expected, service, compose_paths, runtime_path, env_paths)
            runner.run((*base, "config", "--quiet"), timeout=120)
            if service in originally_running:
                runner.run(
                    (*base, "up", "-d", "--no-build", "--pull", "never", "--no-deps", service),
                    timeout=900,
                )
            else:
                runner.run(
                    (
                        *base,
                        "up",
                        "--no-start",
                        "--no-deps",
                        "--no-build",
                        "--pull",
                        "never",
                        service,
                    ),
                    timeout=900,
                )

    deadline = time.monotonic() + 900
    last_error: AdoptionError | None = None
    while time.monotonic() < deadline:
        try:
            current = collect_inventory(runner)
            if restorable_topology_sha256(current) != restorable_topology_sha256(expected):
                raise AdoptionError("restored legacy topology differs")
            current_running = _running_services(current)
            if originally_running <= current_running:
                extras = current_running - originally_running
                if extras:
                    for record in current.containers:
                        if record.service in extras:
                            runner.run(
                                (
                                    runner.docker,
                                    "stop",
                                    "--time",
                                    str(LEGACY_STOP_GRACE_SECONDS),
                                    record.container_id,
                                ),
                                timeout=LEGACY_STOP_COMMAND_TIMEOUT_SECONDS,
                            )
                    current = collect_inventory(runner)
                if _running_services(current) == originally_running:
                    return current
        except AdoptionError as exc:
            last_error = exc
        time.sleep(2)
    if last_error is not None:
        raise AdoptionError("legacy stack restoration failed validation") from last_error
    raise AdoptionError("legacy stack restoration exceeded its deadline")


def _write_bound_state(path: Path, payload: Mapping[str, Any], binding_key: bytes) -> None:
    canonical_payload = _canonical_json(payload)
    wrapper = {
        "payload": payload,
        "opaque_hmac_sha256": _hmac_binding(
            canonical_payload,
            binding_key,
            domain="heyi-legacy-prepared-state-v1",
        ),
    }
    _atomic_write(path, _canonical_json(wrapper), mode=0o400)


def _read_bound_state(path: Path, binding_key: bytes) -> dict[str, Any]:
    wrapper = _read_json_file(path)
    if set(wrapper) != {"payload", "opaque_hmac_sha256"}:
        raise AdoptionError("prepared-state wrapper schema differs")
    payload = _object(wrapper.get("payload"), "prepared-state payload")
    expected = _string(wrapper.get("opaque_hmac_sha256"), "prepared-state HMAC")
    if _SHA256.fullmatch(expected) is None or not hmac.compare_digest(
        _hmac_binding(
            _canonical_json(payload),
            binding_key,
            domain="heyi-legacy-prepared-state-v1",
        ),
        expected,
    ):
        raise AdoptionError("prepared-state opaque binding differs")
    return payload


def _ca_challenge(
    *,
    run_id: str,
    plan_digest: str,
    ca_escrow: Mapping[str, Any],
) -> dict[str, Any]:
    issued = _utc_now()
    return {
        "schema_version": 1,
        "kind": "heyi-caddy-ca-restore-challenge",
        "project": PROJECT,
        "run_id": run_id,
        "plan_sha256": plan_digest,
        "nonce": secrets.token_hex(32),
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "encrypted_archive_sha256": ca_escrow["ciphertext_sha256"],
        "encrypted_archive_size_bytes": ca_escrow["ciphertext_size_bytes"],
        "plaintext_opaque_hmac_sha256": ca_escrow["plaintext_opaque_hmac_sha256"],
        "file_count": ca_escrow["file_count"],
        "recipient_certificate_sha256": ca_escrow["recipient_certificate_sha256"],
        "cos_transfer_allowed": False,
    }


def _verify_ca_attestation(
    runner: Runner,
    *,
    challenge: Path,
    attestation: Path,
    signature: Path,
    public_key: Path,
) -> dict[str, Any]:
    _verify_signature(
        runner,
        payload=attestation,
        signature=signature,
        public_key=public_key,
    )
    challenge_document = _read_json_file(challenge)
    document = _read_json_file(attestation)
    expected_keys = {
        "schema_version",
        "kind",
        "project",
        "challenge_sha256",
        "encrypted_archive_sha256",
        "plaintext_opaque_hmac_sha256",
        "file_count",
        "recipient_certificate_sha256",
        "status",
        "tested_at",
        "private_key_location",
        "server_private_key_present",
        "cos_used",
    }
    if set(document) != expected_keys:
        raise AdoptionError("offline CA restore attestation schema differs")
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "heyi-caddy-ca-restore-drill"
        or document.get("project") != PROJECT
        or document.get("status") != "passed"
        or document.get("private_key_location") != "offline-only"
        or document.get("server_private_key_present") is not False
        or document.get("cos_used") is not False
        or document.get("challenge_sha256") != _sha256_file(challenge)
        or document.get("encrypted_archive_sha256")
        != challenge_document.get("encrypted_archive_sha256")
        or document.get("plaintext_opaque_hmac_sha256")
        != challenge_document.get("plaintext_opaque_hmac_sha256")
        or document.get("file_count") != challenge_document.get("file_count")
        or document.get("recipient_certificate_sha256")
        != challenge_document.get("recipient_certificate_sha256")
    ):
        raise AdoptionError("offline CA restore attestation does not match its challenge")
    tested_at = _timestamp(document.get("tested_at"), "CA restore tested_at")
    now = _utc_now()
    issued = _timestamp(challenge_document.get("issued_at"), "CA challenge issued_at")
    expires = _timestamp(challenge_document.get("expires_at"), "CA challenge expires_at")
    if (
        not now - timedelta(days=30) <= tested_at <= now + timedelta(minutes=5)
        or not issued <= tested_at <= expires
        or now > expires
    ):
        raise AdoptionError("offline CA restore attestation is stale or outside its challenge")
    return {
        "status": "passed",
        "tested_at": document["tested_at"],
        "attestation": _descriptor(attestation),
        "signature": _descriptor(signature),
        "signer_public_key_sha256": _sha256_file(
            protected_file(
                public_key,
                modes=frozenset({0o400, 0o440, 0o444}),
                max_bytes=65_536,
            )
        ),
        "private_key_location": "offline-only",
        "server_private_key_present": False,
        "cos_used": False,
    }


def _prepare(arguments: argparse.Namespace, runner: Runner) -> None:
    binding_key = _read_binding_key(arguments.binding_key)
    plan, plan_digest, runtime, compose_paths, env_paths = _validate_plan(
        arguments.plan, binding_key
    )
    inventory = collect_inventory(runner)
    if inventory_sha256(inventory) != plan["inventory_sha256"]:
        raise AdoptionError("live legacy inventory differs from the approved plan")
    runtime_path = Path(plan["runtime_env"]["path"])
    recipient = protected_file(
        arguments.ca_recipient_certificate,
        modes=frozenset({0o400, 0o440, 0o444}),
        max_bytes=65_536,
    )
    ca_root = protected_directory(
        arguments.ca_root,
        modes=frozenset({0o700, 0o750, 0o755}),
    )
    try:
        ca_root.relative_to(DATA_ROOT)
    except ValueError as exc:
        raise AdoptionError("Caddy CA root must be inside the fixed legacy data root") from exc
    signing_key = protected_file(
        arguments.evidence_signing_key,
        modes=frozenset({0o400, 0o600}),
        max_bytes=65_536,
    )
    public_key = protected_file(
        arguments.evidence_public_key,
        modes=frozenset({0o400, 0o440, 0o444}),
        max_bytes=65_536,
    )
    execute = _confirm(arguments, plan_digest)
    if not execute:
        print(
            json.dumps(
                {
                    "status": "dry-run",
                    "operation": "prepare",
                    "project": PROJECT,
                    "plan_sha256": plan_digest,
                    "would_stop": sorted(_running_services(inventory) - {"postgres", "minio"}),
                    "would_delete": [],
                    "backup_root": str(BACKUP_ROOT),
                    "ca_plaintext_written": False,
                    "cos_transfer_allowed": False,
                },
                sort_keys=True,
            )
        )
        return

    if arguments.backup_root != BACKUP_ROOT:
        raise AdoptionError("backup root must equal the fixed protected backup root")
    protected_directory(BACKUP_ROOT, modes=frozenset({0o700, 0o750}))
    run = _create_run_directory(BACKUP_ROOT, arguments.run_id)
    private = _new_private_directory(run, "private")
    evidence_dir = _new_private_directory(run, "evidence")
    database_dir = _new_private_directory(private, "database")
    minio_dir = _new_private_directory(private, "minio")
    objects_dir = _new_private_directory(minio_dir, "objects")
    ca_dir = _new_private_directory(private, "ca")
    _atomic_write(
        run / ".NO_COS_PRIVATE_DATA",
        b"runtime.env, database, object bytes, and CA escrow are forbidden on COS\n",
        mode=0o400,
    )

    originally_running = _running_services(inventory)
    quiescence_started = False
    backup_error: BaseException | None = None
    try:
        quiescence_started = True
        _quiesce_legacy(runner, inventory)
        counts, schema_head, database_metadata = _database_backup(
            runner, inventory, runtime, database_dir
        )
        _database_archive(database_dir, private / "database-backup.tar")
        _run_mc_backup(runner, inventory, runtime, objects_dir, arguments.run_id)
        _seal_private_tree(objects_dir)
        object_summary = _object_manifest(objects_dir, evidence_dir / "object-manifest.ndjson")
        ca_metadata = _encrypt_ca_escrow(
            runner,
            ca_root=ca_root,
            recipient_certificate=recipient,
            binding_key=binding_key,
            destination=ca_dir / "caddy-ca.cms.p7m",
        )
    except BaseException as exc:
        backup_error = exc
    finally:
        if quiescence_started:
            try:
                _resume_or_recreate_legacy(
                    runner,
                    expected=inventory,
                    compose_paths=compose_paths,
                    runtime_path=runtime_path,
                    env_paths=env_paths,
                    originally_running=originally_running,
                )
            except BaseException as restore_exc:
                raise AdoptionError(
                    "backup failed and the legacy stack could not be restored"
                ) from restore_exc
    if backup_error is not None:
        raise AdoptionError(
            "legacy logical backup failed; the old stack was restored"
        ) from backup_error

    challenge_document = _ca_challenge(
        run_id=arguments.run_id,
        plan_digest=plan_digest,
        ca_escrow=ca_metadata,
    )
    challenge_path = evidence_dir / "ca-restore-challenge.json"
    challenge_signature = evidence_dir / "ca-restore-challenge.sig"
    _atomic_write(challenge_path, _canonical_json(challenge_document), mode=0o400)
    _signature(
        runner,
        payload=challenge_path,
        signing_key=signing_key,
        destination=challenge_signature,
    )
    _verify_signature(
        runner,
        payload=challenge_path,
        signature=challenge_signature,
        public_key=public_key,
    )
    state_payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": "heyi-legacy-prepared-state",
        "project": PROJECT,
        "run_id": arguments.run_id,
        "created_at": _utc_now().isoformat().replace("+00:00", "Z"),
        "plan_sha256": plan_digest,
        "git_sha": plan["git_sha"],
        "target_manifest_sha256": plan["target_manifest"]["sha256"],
        "source_inventory_sha256": plan["inventory_sha256"],
        "source_topology_sha256": plan["topology_sha256"],
        "source_images": _source_images(inventory),
        "originally_running": sorted(originally_running),
        "runtime": {
            "required_keys_present": True,
            "required_key_count": len(REQUIRED_RUNTIME_KEYS),
            "opaque_hmac_sha256": plan["runtime_env"]["opaque_hmac_sha256"],
            "secret_values_in_state": False,
        },
        "legacy_environment_bindings": plan["legacy_compose"]["env_files"],
        "database": {
            "directory": str(database_dir),
            "archive": _descriptor(private / "database-backup.tar"),
            "schema_head": schema_head,
            "table_counts": counts,
            **database_metadata,
        },
        "objects": {
            "directory": str(objects_dir),
            "manifest": _descriptor(evidence_dir / "object-manifest.ndjson"),
            **object_summary,
        },
        "ca_escrow": ca_metadata,
        "ca_challenge": {
            "document": _descriptor(challenge_path),
            "signature": _descriptor(challenge_signature),
            "signer_public_key_sha256": _sha256_file(public_key),
        },
        "cos_policy": {
            "runtime_env_allowed": False,
            "database_backup_allowed": False,
            "object_bytes_allowed": False,
            "ca_escrow_allowed": False,
            "signed_public_evidence_allowed": True,
        },
    }
    state_path = evidence_dir / "prepared-state.json"
    _write_bound_state(state_path, state_payload, binding_key)
    print(
        json.dumps(
            {
                "status": "prepared-awaiting-offline-ca-restore-attestation",
                "project": PROJECT,
                "plan_sha256": plan_digest,
                "prepared_state": str(state_path),
                "encrypted_ca_escrow": ca_metadata["ciphertext_path"],
                "ca_restore_challenge": str(challenge_path),
                "ca_restore_challenge_signature": str(challenge_signature),
                "legacy_stack_restored": True,
                "cos_transfer_allowed": False,
            },
            sort_keys=True,
        )
    )


def _validate_prepared_state(
    path: Path,
    *,
    binding_key: bytes,
    plan: Mapping[str, Any],
    plan_digest: str,
) -> tuple[dict[str, Any], Path]:
    state = _read_bound_state(path, binding_key)
    expected_keys = {
        "schema_version",
        "kind",
        "project",
        "run_id",
        "created_at",
        "plan_sha256",
        "git_sha",
        "target_manifest_sha256",
        "source_inventory_sha256",
        "source_topology_sha256",
        "source_images",
        "originally_running",
        "runtime",
        "legacy_environment_bindings",
        "database",
        "objects",
        "ca_escrow",
        "ca_challenge",
        "cos_policy",
    }
    if set(state) != expected_keys:
        raise AdoptionError("prepared-state payload schema differs")
    if (
        state.get("schema_version") != 1
        or state.get("kind") != "heyi-legacy-prepared-state"
        or state.get("project") != PROJECT
        or state.get("plan_sha256") != plan_digest
        or state.get("git_sha") != plan.get("git_sha")
        or state.get("target_manifest_sha256")
        != _object(plan.get("target_manifest"), "target manifest").get("sha256")
        or state.get("source_inventory_sha256") != plan.get("inventory_sha256")
        or state.get("source_topology_sha256") != plan.get("topology_sha256")
    ):
        raise AdoptionError("prepared-state identity differs from the approved plan")
    created = _timestamp(state.get("created_at"), "prepared-state.created_at")
    if not _utc_now() - timedelta(days=7) <= created <= _utc_now() + timedelta(minutes=5):
        raise AdoptionError("prepared-state is stale or future-dated")
    run_id = _string(state.get("run_id"), "prepared-state run id")
    if _SAFE_NAME.fullmatch(run_id) is None:
        raise AdoptionError("prepared-state run id is malformed")
    run = path.parent.parent
    canonical_run = protected_directory(run, modes=frozenset({0o700}))
    if canonical_run != BACKUP_ROOT / run_id or path != run / "evidence" / "prepared-state.json":
        raise AdoptionError("prepared-state is outside its exact protected run path")
    marker = protected_file(
        run / ".NO_COS_PRIVATE_DATA",
        modes=frozenset({0o400}),
        max_bytes=4096,
    )
    if b"forbidden on COS" not in _open_protected_bytes(marker, max_bytes=4096):
        raise AdoptionError("private backup COS prohibition marker differs")
    runtime = _object(state.get("runtime"), "prepared-state runtime binding")
    plan_runtime = _object(plan.get("runtime_env"), "plan runtime binding")
    if (
        runtime.get("required_keys_present") is not True
        or runtime.get("required_key_count") != len(REQUIRED_RUNTIME_KEYS)
        or runtime.get("secret_values_in_state") is not False
        or runtime.get("opaque_hmac_sha256") != plan_runtime.get("opaque_hmac_sha256")
    ):
        raise AdoptionError("prepared-state runtime binding differs")
    if state.get("legacy_environment_bindings") != _object(
        plan.get("legacy_compose"), "plan Compose binding"
    ).get("env_files"):
        raise AdoptionError("prepared-state legacy environment bindings differ")
    expected_cos = {
        "runtime_env_allowed": False,
        "database_backup_allowed": False,
        "object_bytes_allowed": False,
        "ca_escrow_allowed": False,
        "signed_public_evidence_allowed": True,
    }
    if state.get("cos_policy") != expected_cos:
        raise AdoptionError("prepared-state COS isolation policy differs")
    return state, canonical_run


def _validate_backup_artifacts(
    state: Mapping[str, Any], run: Path
) -> tuple[Path, Path, Path, dict[str, int], str, dict[str, Any]]:
    database = _object(state.get("database"), "prepared database evidence")
    database_dir = protected_directory(
        Path(_string(database.get("directory"), "database backup directory")),
        modes=frozenset({0o700}),
    )
    if database_dir != run / "private" / "database":
        raise AdoptionError("database backup directory is outside the exact run path")
    database_archive = _verify_descriptor(database.get("archive"), root=run)
    for name, field in (
        ("database.dump", "dump_sha256"),
        ("globals.sql", "globals_sha256"),
        ("schema.sql", "schema_sha256"),
        ("table-counts.json", "table_counts_sha256"),
    ):
        artifact = protected_file(
            database_dir / name,
            modes=frozenset({0o400}),
            max_bytes=2**63 - 1,
        )
        expected_digest = _string(database.get(field), field)
        if _SHA256.fullmatch(expected_digest) is None or not hmac.compare_digest(
            _sha256_file(artifact), expected_digest
        ):
            raise AdoptionError("database backup component differs")
    counts = _object(database.get("table_counts"), "database table counts")
    typed_counts: dict[str, int] = {}
    for table, count in counts.items():
        if not isinstance(table, str) or "." not in table or type(count) is not int or count < 0:
            raise AdoptionError("database table-count evidence is malformed")
        typed_counts[table] = count
    if database.get("table_count") != len(typed_counts) or database.get("row_count") != sum(
        typed_counts.values()
    ):
        raise AdoptionError("database table-count summary differs")
    schema_head = _string(database.get("schema_head"), "database schema head")
    if _SCHEMA_HEAD.fullmatch(schema_head) is None:
        raise AdoptionError("database schema head is malformed")

    objects = _object(state.get("objects"), "prepared object evidence")
    objects_dir = protected_directory(
        Path(_string(objects.get("directory"), "object backup directory")),
        modes=frozenset({0o700}),
    )
    if objects_dir != run / "private" / "minio" / "objects":
        raise AdoptionError("object backup directory is outside the exact run path")
    object_manifest = _verify_descriptor(objects.get("manifest"), root=run)
    if (
        objects.get("manifest_sha256") != _sha256_file(object_manifest)
        or objects.get("manifest_size_bytes") != object_manifest.stat().st_size
        or type(objects.get("object_count")) is not int
        or int(objects["object_count"]) < 0
        or type(objects.get("total_bytes")) is not int
        or int(objects["total_bytes"]) < 0
    ):
        raise AdoptionError("object manifest summary differs")

    ca = _object(state.get("ca_escrow"), "prepared CA escrow")
    ca_path = protected_file(
        Path(_string(ca.get("ciphertext_path"), "CA escrow path")),
        modes=frozenset({0o400}),
        max_bytes=MAX_CA_PLAINTEXT * 2,
    )
    if ca_path != run / "private" / "ca" / "caddy-ca.cms.p7m":
        raise AdoptionError("encrypted CA escrow is outside its exact run path")
    if (
        ca.get("ciphertext_sha256") != _sha256_file(ca_path)
        or ca.get("ciphertext_size_bytes") != ca_path.stat().st_size
        or ca.get("private_key_bytes_in_evidence") is not False
        or ca.get("cos_transfer_allowed") is not False
        or not isinstance(ca.get("plaintext_opaque_hmac_sha256"), str)
        or _SHA256.fullmatch(str(ca.get("plaintext_opaque_hmac_sha256"))) is None
    ):
        raise AdoptionError("encrypted CA escrow evidence differs")
    return (
        database_dir,
        database_archive,
        objects_dir,
        typed_counts,
        schema_head,
        {
            "manifest": object_manifest,
            "object_count": int(objects["object_count"]),
            "total_bytes": int(objects["total_bytes"]),
            "ca_path": ca_path,
        },
    )


def _ensure_scratch_root(path: Path, *, create: bool) -> Path:
    expected = STATE_ROOT / "legacy-adoption-drills"
    if path != expected:
        raise AdoptionError("restore scratch root must equal its fixed isolated path")
    if path.exists():
        return protected_directory(path, modes=frozenset({0o700}))
    if not create:
        return path
    protected_directory(STATE_ROOT, modes=frozenset({0o700, 0o750}))
    path.mkdir(mode=0o700)
    _posix_chown(path, 0, 0)
    return protected_directory(path, modes=frozenset({0o700}))


def _finalize(arguments: argparse.Namespace, runner: Runner) -> None:
    binding_key = _read_binding_key(arguments.binding_key)
    plan, plan_digest, runtime, _, _ = _validate_plan(arguments.plan, binding_key)
    state, run = _validate_prepared_state(
        arguments.prepared_state,
        binding_key=binding_key,
        plan=plan,
        plan_digest=plan_digest,
    )
    (
        database_dir,
        database_archive,
        objects_dir,
        table_counts,
        schema_head,
        artifact_context,
    ) = _validate_backup_artifacts(state, run)
    evidence_public = protected_file(
        arguments.evidence_public_key,
        modes=frozenset({0o400, 0o440, 0o444}),
        max_bytes=65_536,
    )
    challenge_state = _object(state.get("ca_challenge"), "CA challenge evidence")
    challenge = _verify_descriptor(challenge_state.get("document"), root=run)
    challenge_signature = _verify_descriptor(challenge_state.get("signature"), root=run)
    if challenge_state.get("signer_public_key_sha256") != _sha256_file(evidence_public):
        raise AdoptionError("CA challenge signer public key differs")
    _verify_signature(
        runner,
        payload=challenge,
        signature=challenge_signature,
        public_key=evidence_public,
    )
    ca_attestation = _verify_ca_attestation(
        runner,
        challenge=challenge,
        attestation=arguments.ca_restore_attestation,
        signature=arguments.ca_restore_attestation_signature,
        public_key=arguments.ca_restore_attestation_public_key,
    )
    inventory = collect_inventory(runner)
    if topology_sha256(inventory) != state["source_topology_sha256"]:
        raise AdoptionError("live legacy topology differs from the prepared backup source")
    if _object(state.get("source_images"), "source images") != _source_images(inventory):
        raise AdoptionError("live legacy images differ from the prepared backup source")

    execute = _confirm(arguments, plan_digest)
    scratch = _ensure_scratch_root(arguments.scratch_root, create=execute)
    if not execute:
        print(
            json.dumps(
                {
                    "status": "dry-run",
                    "operation": "finalize",
                    "project": PROJECT,
                    "plan_sha256": plan_digest,
                    "ca_restore_attestation": "verified",
                    "would_create_isolated_restore_containers": True,
                    "would_publish_ports": False,
                    "would_delete_legacy_resources": False,
                },
                sort_keys=True,
            )
        )
        return
    restore = _run_restore_drill(
        runner,
        inventory=inventory,
        scratch_parent=scratch,
        database_backup=database_dir,
        objects_dir=objects_dir,
        bucket=runtime["MINIO_BUCKET"],
        expected_counts=table_counts,
        expected_schema_head=schema_head,
        object_manifest=artifact_context["manifest"],
        expected_object_count=artifact_context["object_count"],
        expected_object_bytes=artifact_context["total_bytes"],
        run_token=_string(state.get("run_id"), "prepared-state run id"),
    )
    detailed = {
        "schema_version": 1,
        "kind": "heyi-legacy-adoption-restore-evidence",
        "project": PROJECT,
        "run_id": state["run_id"],
        "generated_at": _utc_now().isoformat().replace("+00:00", "Z"),
        "git_sha": state["git_sha"],
        "plan_sha256": plan_digest,
        "target_manifest_sha256": state["target_manifest_sha256"],
        "source_inventory_sha256": state["source_inventory_sha256"],
        "source_topology_sha256": state["source_topology_sha256"],
        "source_images": state["source_images"],
        "runtime": state["runtime"],
        "legacy_environment_bindings": state["legacy_environment_bindings"],
        "database": {
            "archive": _descriptor(database_archive),
            "schema_head": schema_head,
            "table_count": len(table_counts),
            "row_count": sum(table_counts.values()),
            "table_counts_sha256": _object(state["database"], "database")["table_counts_sha256"],
        },
        "objects": {
            "manifest": _descriptor(artifact_context["manifest"]),
            "object_count": artifact_context["object_count"],
            "total_bytes": artifact_context["total_bytes"],
        },
        "ca_escrow": state["ca_escrow"],
        "ca_restore_attestation": ca_attestation,
        "isolated_restore_drill": restore,
        "secret_policy": {
            "runtime_secret_values_recorded": False,
            "low_entropy_secret_sha256_recorded": False,
            "ca_private_key_plaintext_on_server": False,
            "ca_recipient_private_key_on_server": False,
            "private_artifacts_on_cos": False,
        },
    }
    detailed_path = run / "evidence" / "restore-evidence.json"
    _atomic_write(detailed_path, _canonical_json(detailed), mode=0o400)
    issued = _utc_now()
    top_evidence = {
        "schema_version": 1,
        "kind": "offline-upgrade-backup",
        "project": PROJECT,
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued + timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
        "target_manifest_sha256": state["target_manifest_sha256"],
        "database_backup": _descriptor(database_archive),
        "object_manifest": _descriptor(artifact_context["manifest"]),
        "restore_evidence": _descriptor(detailed_path),
        "restore_drill": {
            "status": "passed",
            "tested_at": restore["tested_at"],
            "source_schema_head": schema_head,
        },
    }
    evidence_path = run / "evidence" / "upgrade-backup-evidence.json"
    signature_path = run / "evidence" / "upgrade-backup-evidence.sig"
    _atomic_write(evidence_path, _canonical_json(top_evidence), mode=0o400)
    _signature(
        runner,
        payload=evidence_path,
        signing_key=arguments.evidence_signing_key,
        destination=signature_path,
    )
    _verify_signature(
        runner,
        payload=evidence_path,
        signature=signature_path,
        public_key=evidence_public,
    )
    print(
        json.dumps(
            {
                "status": "passed",
                "project": PROJECT,
                "plan_sha256": plan_digest,
                "evidence": str(evidence_path),
                "signature": str(signature_path),
                "public_key": str(evidence_public),
                "legacy_stack_unchanged": True,
                "ready_for_separate_retirement_transaction": True,
            },
            sort_keys=True,
        )
    )


def _verify_upgrade_evidence(
    runner: Runner,
    *,
    evidence_path: Path,
    signature_path: Path,
    public_key: Path,
    plan: Mapping[str, Any],
    plan_digest: str,
) -> tuple[dict[str, Any], dict[str, Any], Path]:
    _verify_signature(
        runner,
        payload=evidence_path,
        signature=signature_path,
        public_key=public_key,
    )
    evidence = _read_json_file(evidence_path, max_bytes=65_536)
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
    if set(evidence) != expected_keys:
        raise AdoptionError("signed upgrade evidence schema differs")
    target_digest = _object(plan.get("target_manifest"), "target manifest").get("sha256")
    if (
        evidence.get("schema_version") != 1
        or evidence.get("kind") != "offline-upgrade-backup"
        or evidence.get("project") != PROJECT
        or evidence.get("target_manifest_sha256") != target_digest
    ):
        raise AdoptionError("signed upgrade evidence identity differs")
    issued = _timestamp(evidence.get("issued_at"), "upgrade evidence issued_at")
    expires = _timestamp(evidence.get("expires_at"), "upgrade evidence expires_at")
    now = _utc_now()
    if not now - timedelta(hours=24) <= issued <= now + timedelta(
        minutes=5
    ) or not now < expires <= issued + timedelta(hours=24):
        raise AdoptionError("signed upgrade evidence is stale or expired")
    run = evidence_path.parent.parent
    protected_directory(run, modes=frozenset({0o700}))
    try:
        run.relative_to(BACKUP_ROOT)
    except ValueError as exc:
        raise AdoptionError("signed upgrade evidence lies outside the backup root") from exc
    _verify_descriptor(evidence.get("database_backup"), root=run)
    _verify_descriptor(evidence.get("object_manifest"), root=run)
    detailed_path = _verify_descriptor(evidence.get("restore_evidence"), root=run)
    detailed = _read_json_file(detailed_path)
    if (
        detailed.get("schema_version") != 1
        or detailed.get("kind") != "heyi-legacy-adoption-restore-evidence"
        or detailed.get("project") != PROJECT
        or detailed.get("plan_sha256") != plan_digest
        or detailed.get("git_sha") != plan.get("git_sha")
        or detailed.get("target_manifest_sha256") != target_digest
        or _object(detailed.get("isolated_restore_drill"), "restore drill").get("status")
        != "passed"
        or _object(detailed.get("ca_restore_attestation"), "CA attestation").get("status")
        != "passed"
        or _object(detailed.get("secret_policy"), "secret policy")
        != {
            "runtime_secret_values_recorded": False,
            "low_entropy_secret_sha256_recorded": False,
            "ca_private_key_plaintext_on_server": False,
            "ca_recipient_private_key_on_server": False,
            "private_artifacts_on_cos": False,
        }
    ):
        raise AdoptionError("detailed restore evidence does not satisfy adoption policy")
    drill = _object(evidence.get("restore_drill"), "upgrade restore drill")
    if set(drill) != {"status", "tested_at", "source_schema_head"}:
        raise AdoptionError("upgrade restore drill schema differs")
    tested = _timestamp(drill.get("tested_at"), "restore drill tested_at")
    if (
        drill.get("status") != "passed"
        or not isinstance(drill.get("source_schema_head"), str)
        or _SCHEMA_HEAD.fullmatch(str(drill.get("source_schema_head"))) is None
        or not now - timedelta(days=30) <= tested <= now + timedelta(minutes=5)
    ):
        raise AdoptionError("upgrade restore drill is stale or invalid")
    return evidence, detailed, run


def _inspect_exact_legacy_container(
    runner: Runner,
    expected: ContainerRecord,
) -> ContainerRecord:
    raw = runner.docker_json(("inspect", expected.container_id))
    if not isinstance(raw, list) or len(raw) != 1:
        raise AdoptionError("legacy container identity became ambiguous")
    current = _container_record(raw[0])
    normalized = replace(
        current,
        running=expected.running,
        restart_count=expected.restart_count,
    )
    if normalized != expected:
        raise AdoptionError("legacy container identity changed before retirement")
    return current


def _verify_named_volumes(
    runner: Runner,
    expected: Sequence[VolumeRecord],
) -> None:
    if not expected:
        return
    raw = runner.docker_json(("volume", "inspect", *(item.name for item in expected)))
    observed: list[VolumeRecord] = []
    for value in _list(raw, "named volume inspections"):
        volume = _object(value, "named volume inspection")
        labels = _object(volume.get("Labels"), "named volume labels")
        if labels.get("com.docker.compose.project") != PROJECT:
            raise AdoptionError("preserved named volume project label differs")
        observed.append(
            VolumeRecord(
                name=_string(volume.get("Name"), "named volume name"),
                mountpoint=_string(volume.get("Mountpoint"), "named volume mountpoint"),
            )
        )
    if sorted(observed, key=lambda item: item.name) != sorted(expected, key=lambda item: item.name):
        raise AdoptionError("preserved named volume inventory differs")


def _project_container_ids(runner: Runner) -> set[str]:
    raw = runner.run(
        (
            runner.docker,
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
        )
    ).decode("ascii", errors="strict")
    values = {line.strip() for line in raw.splitlines() if line.strip()}
    if any(_CONTAINER_ID.fullmatch(value) is None for value in values):
        raise AdoptionError("project container identity is malformed")
    return values


def _project_network_ids(runner: Runner) -> set[str]:
    raw = runner.run(
        (
            runner.docker,
            "network",
            "ls",
            "-q",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
        )
    ).decode("ascii", errors="strict")
    values = {line.strip() for line in raw.splitlines() if line.strip()}
    if any(_CONTAINER_ID.fullmatch(value) is None for value in values):
        raise AdoptionError("project network identity is malformed")
    return values


def _remove_exact_legacy_network(runner: Runner, expected: NetworkRecord) -> None:
    raw = runner.docker_json(("network", "inspect", expected.network_id))
    if not isinstance(raw, list) or len(raw) != 1:
        raise AdoptionError("legacy network identity became ambiguous")
    network = _object(raw[0], "legacy network")
    labels = _object(network.get("Labels"), "legacy network labels")
    if (
        network.get("Name") != expected.name
        or network.get("Id") != expected.network_id
        or labels.get("com.docker.compose.project") != PROJECT
        or labels.get("io.heyi.knowledgebases.owner") != OWNER
        or labels.get("io.heyi.knowledgebases.stack") != STACK
        or _object(network.get("Containers", {}), "legacy network endpoints")
    ):
        raise AdoptionError("legacy network is no longer exact or exclusive")
    runner.run((runner.docker, "network", "rm", expected.network_id), timeout=120)


def _retire_exact_resources(
    runner: Runner,
    inventory: LegacyInventory,
    *,
    allow_missing: bool = False,
) -> tuple[list[str], list[str]]:
    expected_container_ids = {item.container_id for item in inventory.containers}
    current_container_ids = _project_container_ids(runner)
    unknown_containers = current_container_ids - expected_container_ids
    missing_containers = expected_container_ids - current_container_ids
    if unknown_containers:
        raise AdoptionError("unknown project container appeared during retirement")
    if missing_containers and not allow_missing:
        raise AdoptionError("legacy container disappeared before retirement intent")
    expected_network_ids = {item.network_id for item in inventory.networks}
    current_network_ids = _project_network_ids(runner)
    unknown_networks = current_network_ids - expected_network_ids
    missing_networks = expected_network_ids - current_network_ids
    if unknown_networks:
        raise AdoptionError("unknown project network appeared during retirement")
    if missing_networks and not allow_missing:
        raise AdoptionError("legacy network disappeared before retirement intent")

    records = {item.service: item for item in inventory.containers if not item.oneoff}
    stop_order = list(WRITER_STOP_ORDER)
    stop_order.extend(sorted(ALLOWED_SERVICES - set(stop_order) - {"postgres", "minio"}))
    stop_order.extend(("postgres", "minio"))
    stopped: set[str] = set()
    for record in inventory.containers:
        if not record.oneoff:
            continue
        if record.container_id not in current_container_ids:
            stopped.add(record.container_id)
            continue
        current = _inspect_exact_legacy_container(runner, record)
        if current.running:
            raise AdoptionError("legacy one-off started before retirement")
        stopped.add(record.container_id)
    for service in stop_order:
        expected_record = records.get(service)
        if expected_record is None or expected_record.container_id in stopped:
            continue
        if expected_record.container_id not in current_container_ids:
            stopped.add(expected_record.container_id)
            continue
        current = _inspect_exact_legacy_container(runner, expected_record)
        if current.running:
            runner.run(
                (
                    runner.docker,
                    "stop",
                    "--time",
                    str(LEGACY_STOP_GRACE_SECONDS),
                    expected_record.container_id,
                ),
                timeout=LEGACY_STOP_COMMAND_TIMEOUT_SECONDS,
            )
        stopped.add(expected_record.container_id)
    if stopped != {item.container_id for item in inventory.containers}:
        raise AdoptionError("not every exact legacy container was quiesced")

    removed_containers: list[str] = []
    for record in inventory.containers:
        if record.container_id not in current_container_ids:
            removed_containers.append(record.container_id)
            continue
        current = _inspect_exact_legacy_container(runner, record)
        if current.running:
            raise AdoptionError("legacy container restarted during retirement")
        runner.run((runner.docker, "rm", record.container_id), timeout=120)
        removed_containers.append(record.container_id)

    removed_networks: list[str] = []
    for expected in inventory.networks:
        if expected.network_id in current_network_ids:
            _remove_exact_legacy_network(runner, expected)
        removed_networks.append(expected.network_id)
    return removed_containers, removed_networks


def _assert_legacy_resources_absent(runner: Runner) -> None:
    for argv in (
        (
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
        ),
        (
            "network",
            "ls",
            "-q",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
        ),
    ):
        if runner.run((runner.docker, *argv)).strip():
            raise AdoptionError("legacy project resources remain after exact retirement")


def _atomic_publish_receipt_directory(parent: Path, pending: Path, final: Path) -> None:
    protected_directory(parent, modes=frozenset({0o700}))
    protected_directory(pending, modes=frozenset({0o700}))
    if final.exists() or final.is_symlink():
        raise AdoptionError("final retirement receipt directory already exists")
    os.replace(pending, final)
    directory_descriptor = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _release_state_binding() -> dict[str, Any]:
    state = protected_directory(STATE_ROOT, modes=frozenset({0o700, 0o750}))
    control_names = {"install-in-progress.json", "active-release.json", "cutover-intent.json"}
    control_paths = sorted(
        {
            *(
                path
                for name in control_names
                if (path := state / name).exists() or path.is_symlink()
            ),
            *state.glob("installed-*.json"),
        },
        key=lambda path: path.name,
    )
    control_files: list[dict[str, Any]] = []
    for path in control_paths:
        if path.parent != state or _SAFE_NAME.fullmatch(path.name) is None:
            raise AdoptionError("release-state control path is unsafe")
        canonical = protected_file(
            path,
            modes=frozenset({0o400, 0o440, 0o444, 0o600}),
        )
        control_files.append(
            {
                "name": canonical.name,
                "sha256": _sha256_file(canonical),
                "size_bytes": canonical.stat().st_size,
            }
        )
    release_entries: list[dict[str, str]] = []
    if RELEASE_ROOT.exists() or RELEASE_ROOT.is_symlink():
        releases = protected_directory(RELEASE_ROOT, modes=frozenset({0o700, 0o750, 0o755}))
        for path in sorted(releases.iterdir(), key=lambda value: value.name):
            if _SAFE_NAME.fullmatch(path.name) is None or path.is_symlink():
                raise AdoptionError("materialized release entry is unsafe")
            metadata = path.lstat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise AdoptionError("materialized release entry permissions are unsafe")
            if stat.S_ISDIR(metadata.st_mode):
                kind = "directory"
            elif stat.S_ISREG(metadata.st_mode):
                kind = "file"
            else:
                raise AdoptionError("materialized release entry type is unsafe")
            release_entries.append({"name": path.name, "type": kind})
    return {
        "schema_version": 1,
        "control_files": control_files,
        "release_root_present": RELEASE_ROOT.exists(),
        "release_entries": release_entries,
    }


def _load_host_isolation_guard(plan: Mapping[str, Any]) -> ModuleType:
    entry = _object(plan.get("host_isolation_guard"), "host-isolation guard binding")
    path = Path(_string(entry.get("path"), "host-isolation guard path"))
    name = f"heyi_host_isolation_guard_{_string(entry.get('sha256'), 'guard digest')}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AdoptionError("host-isolation guard could not be loaded")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise AdoptionError("host-isolation guard failed to load") from exc
    return module


def _verify_host_isolation(
    plan: Mapping[str, Any], baseline_path: Path, hmac_key_path: Path
) -> ModuleType:
    guard = _load_host_isolation_guard(plan)
    try:
        key = guard.load_hmac_key(hmac_key_path)
        if key is None:
            raise AdoptionError("host-isolation HMAC key is required")
        baseline = guard.load_json_evidence(baseline_path)
        report = guard.verify_against_baseline(baseline, integrity_key=key)
    except AdoptionError:
        raise
    except Exception as exc:
        raise AdoptionError("host-isolation verification was blocked") from exc
    if not isinstance(report, dict) or report.get("status") != "PASS":
        raise AdoptionError("host-isolation baseline has drifted")
    for unit in RECONCILE_UNITS:
        try:
            state = guard._systemctl_show(unit)
        except Exception as exc:
            raise AdoptionError("offline reconcile unit state could not be verified") from exc
        if not isinstance(state, dict):
            raise AdoptionError("offline reconcile unit state is malformed")
        if state.get("LoadState") == "not-found":
            continue
        if state.get("ActiveState") != "inactive" or state.get("UnitFileState") not in {
            "disabled",
            "masked",
            "static",
        }:
            raise AdoptionError("offline reconcile timer/service must be inactive and disabled")
    return guard


def _verify_retirement_receipt(
    runner: Runner,
    *,
    receipt_path: Path,
    signature_path: Path,
    public_key: Path,
    plan: Mapping[str, Any],
    plan_digest: str,
    inventory: LegacyInventory,
    expected_directory_name: str = "retirement",
    enforce_freshness: bool = True,
) -> dict[str, Any]:
    if expected_directory_name not in {"retirement", RETIREMENT_INTENT_DIRECTORY}:
        raise AdoptionError("retirement receipt directory contract is invalid")
    receipt = protected_file(receipt_path, modes=frozenset({0o400}))
    signature = protected_file(signature_path, modes=frozenset({0o400, 0o440, 0o444}))
    if receipt.name != "receipt.json" or signature != receipt.parent / "receipt.sig":
        raise AdoptionError("retirement receipt paths are not canonical siblings")
    retirement = protected_directory(receipt.parent, modes=frozenset({0o700}))
    if retirement.name != expected_directory_name or retirement.parent.name != "evidence":
        raise AdoptionError("retirement receipt is outside its fixed evidence directory")
    try:
        retirement.relative_to(BACKUP_ROOT)
    except ValueError as exc:
        raise AdoptionError("retirement receipt is outside the backup root") from exc
    _verify_signature(runner, payload=receipt, signature=signature, public_key=public_key)
    document = _read_json_file(receipt, max_bytes=256 * 1024)
    expected = {
        "schema_version",
        "kind",
        "status",
        "project",
        "issued_at",
        "git_sha",
        "plan_sha256",
        "upgrade_evidence_sha256",
        "target_manifest_sha256",
        "source_schema_head",
        "source_postgres_major",
        "source_topology_sha256",
        "restorable_topology_sha256",
        "release_state_binding",
        "removed_container_ids",
        "stopped_oneoff_container_ids_not_restored",
        "removed_network_ids",
        "preserved_named_volumes",
        "preserved_bind_root",
        "named_volumes_deleted",
        "bind_data_deleted",
        "global_prune_used",
        "docker_daemon_restarted",
        "restore_boundary",
        "post_migration_rollback_policy",
    }
    if set(document) != expected:
        raise AdoptionError("signed retirement receipt schema differs")
    issued = _timestamp(document.get("issued_at"), "retirement receipt issued_at")
    now = _utc_now()
    planned_ids = [item.container_id for item in inventory.containers]
    oneoff_ids = [item.container_id for item in inventory.containers if item.oneoff]
    network_ids = [item.network_id for item in inventory.networks]
    preserved_volumes = [asdict(item) for item in inventory.volumes]
    target_digest = _object(plan.get("target_manifest"), "target manifest").get("sha256")
    upgrade_digest = document.get("upgrade_evidence_sha256")
    if (
        document.get("schema_version") != 2
        or document.get("kind") != "heyi-legacy-retirement-receipt"
        or document.get("status") != "retired"
        or document.get("project") != PROJECT
        or document.get("git_sha") != plan.get("git_sha")
        or document.get("plan_sha256") != plan_digest
        or document.get("target_manifest_sha256") != target_digest
        or not isinstance(upgrade_digest, str)
        or _SHA256.fullmatch(upgrade_digest) is None
        or document.get("source_postgres_major") != 17
        or document.get("source_topology_sha256") != plan.get("topology_sha256")
        or document.get("restorable_topology_sha256") != restorable_topology_sha256(inventory)
        or document.get("removed_container_ids") != planned_ids
        or document.get("stopped_oneoff_container_ids_not_restored") != oneoff_ids
        or document.get("removed_network_ids") != network_ids
        or document.get("preserved_named_volumes") != preserved_volumes
        or document.get("preserved_bind_root") != str(DATA_ROOT)
        or document.get("named_volumes_deleted") is not False
        or document.get("bind_data_deleted") is not False
        or document.get("global_prune_used") is not False
        or document.get("docker_daemon_restarted") is not False
        or document.get("restore_boundary") != REACTIVATION_BOUNDARY
        or document.get("post_migration_rollback_policy") != "forward-only"
        or (
            enforce_freshness
            and expected_directory_name != RETIREMENT_INTENT_DIRECTORY
            and not now - timedelta(days=30) <= issued <= now + timedelta(minutes=5)
        )
    ):
        raise AdoptionError("signed retirement receipt identity differs")
    schema_head = document.get("source_schema_head")
    if not isinstance(schema_head, str) or _SCHEMA_HEAD.fullmatch(schema_head) is None:
        raise AdoptionError("signed retirement schema head is malformed")
    return document


def _verify_optional_abort_archive(value: object, expected_path: Path) -> None:
    if value is None:
        return
    descriptor = _object(value, "target abort archived artifact")
    if set(descriptor) != {"path", "sha256"}:
        raise AdoptionError("target abort archived artifact schema differs")
    path = protected_file(
        Path(_string(descriptor.get("path"), "target abort archived artifact path")),
        modes=frozenset({0o400}),
        max_bytes=256 * 1024,
    )
    digest = _string(descriptor.get("sha256"), "target abort archived artifact digest")
    if (
        path != expected_path
        or _SHA256.fullmatch(digest) is None
        or not hmac.compare_digest(_sha256_file(path), digest)
    ):
        raise AdoptionError("target abort archived artifact differs")


def _verify_target_abort_authorization(
    runner: Runner,
    *,
    receipt_path: Path,
    signature_path: Path,
    public_key: Path,
    adoption_transaction: str,
    plan_digest: str,
    retirement_receipt_path: Path,
    retirement_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    if _TRANSACTION_ID.fullmatch(adoption_transaction) is None:
        raise AdoptionError("adoption transaction identifier is malformed")
    transaction_root = STATE_ROOT / "legacy-adoption" / "transactions" / adoption_transaction
    expected_directory = transaction_root / "target-pre-migration-abort"
    receipt = protected_file(receipt_path, modes=frozenset({0o400}), max_bytes=256 * 1024)
    signature = protected_file(
        signature_path,
        modes=frozenset({0o400}),
        max_bytes=65_536,
    )
    directory = protected_directory(receipt.parent, modes=frozenset({0o700}))
    if (
        directory != expected_directory
        or receipt.name != "receipt.json"
        or signature != directory / "receipt.sig"
    ):
        raise AdoptionError("target abort authorization is outside its fixed transaction path")
    _verify_signature(
        runner,
        payload=receipt,
        signature=signature,
        public_key=public_key,
    )
    document = _read_json_file(receipt, max_bytes=256 * 1024)
    if set(document) != TARGET_ABORT_RECEIPT_KEYS:
        raise AdoptionError("target abort authorization schema differs")
    _timestamp(document.get("issued_at"), "target abort authorization issued_at")
    retirement = protected_file(
        retirement_receipt_path,
        modes=frozenset({0o400}),
        max_bytes=256 * 1024,
    )
    retirement_digest = _sha256_file(retirement)
    journal = protected_file(
        transaction_root / "journal.json",
        modes=frozenset({0o400}),
        max_bytes=256 * 1024,
    )
    journal_digest = _sha256_file(journal)
    legacy_schema = _string(
        retirement_receipt.get("source_schema_head"), "retirement source schema head"
    )
    target_schema = document.get("target_schema_head")
    removed_ids = document.get("removed_preflight_container_ids")
    if (
        not isinstance(removed_ids, list)
        or any(
            not isinstance(value, str) or _CONTAINER_ID.fullmatch(value) is None
            for value in removed_ids
        )
        or len(removed_ids) != len(set(removed_ids))
    ):
        raise AdoptionError("target abort removed-container inventory is malformed")
    expected_reconcile = {
        unit: {
            "load_state": "not-found",
            "active_state": "inactive",
            "unit_file_state": "not-found",
        }
        for unit in RECONCILE_UNITS
    }
    target_contract = document.get("target_contract_sha256")
    target_manifest = document.get("target_manifest_sha256")
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "heyi-target-pre-migration-abort-receipt"
        or document.get("status") != "aborted_pre_migration"
        or document.get("project") != PROJECT
        or document.get("adoption_transaction_id") != adoption_transaction
        or document.get("journal_sha256") != journal_digest
        or document.get("plan_sha256") != plan_digest
        or document.get("retirement_receipt_sha256") != retirement_digest
        or not isinstance(target_contract, str)
        or _SHA256.fullmatch(target_contract) is None
        or not isinstance(target_manifest, str)
        or _SHA256.fullmatch(target_manifest) is None
        or not isinstance(target_schema, str)
        or _SCHEMA_HEAD.fullmatch(target_schema) is None
        or document.get("legacy_source_schema_head") != legacy_schema
        or document.get("last_install_phase") not in {"not_started", "prepared", "preflight_passed"}
        or document.get("migration_command_invoked") is not False
        or document.get("active_release_present") is not False
        or document.get("installed_receipt_present") is not False
        or type(document.get("removed_owner_marker_volume")) is not bool
        or document.get("reconcile_baseline") != expected_reconcile
        or document.get("reconcile_result") != expected_reconcile
        or document.get("target_resource_counts_after")
        != {"containers": 0, "networks": 0, "project_volumes": 0, "owner_marker": 0}
        or document.get("preserved_bind_root") != str(DATA_ROOT)
        or document.get("bind_data_deleted") is not False
        or document.get("named_volumes_deleted") is not False
        or document.get("global_actions") != []
        or document.get("restore_boundary") != REACTIVATION_BOUNDARY
    ):
        raise AdoptionError("target abort authorization identity differs")
    _verify_optional_abort_archive(
        document.get("archived_install_state"),
        directory / "archived" / "install-in-progress.json",
    )
    _verify_optional_abort_archive(
        document.get("archived_cutover_intent"),
        directory / "archived" / "cutover-intent.json",
    )
    host = _object(
        document.get("host_isolation_verification"),
        "target abort host-isolation verification",
    )
    if set(host) != {"path", "sha256", "status"}:
        raise AdoptionError("target abort host-isolation descriptor schema differs")
    host_path = protected_file(
        Path(_string(host.get("path"), "target abort host-isolation path")),
        modes=frozenset({0o400}),
        max_bytes=8 * 1024 * 1024,
    )
    host_digest = _string(host.get("sha256"), "target abort host-isolation digest")
    if (
        host.get("status") != "PASS"
        or host_path != directory / "host-isolation-after-abort.json"
        or _SHA256.fullmatch(host_digest) is None
        or not hmac.compare_digest(_sha256_file(host_path), host_digest)
    ):
        raise AdoptionError("target abort host-isolation verification differs")
    return document


def _publish_retirement_intent(
    runner: Runner,
    *,
    receipt_parent: Path,
    receipt: Mapping[str, Any],
    signing_key: Path,
    public_key: Path,
) -> Path:
    """Atomically publish the durable signed intent before any Docker mutation."""

    parent = protected_directory(receipt_parent, modes=frozenset({0o700}))
    intent = parent / RETIREMENT_INTENT_DIRECTORY
    final = parent / "retirement"
    if intent.exists() or intent.is_symlink() or final.exists() or final.is_symlink():
        raise AdoptionError("retirement intent or final receipt already exists")
    pending = _new_private_directory(
        parent, f".{RETIREMENT_INTENT_DIRECTORY}.{secrets.token_hex(16)}.pending"
    )
    receipt_path = pending / "receipt.json"
    signature_path = pending / "receipt.sig"
    _atomic_write(receipt_path, _canonical_json(receipt), mode=0o400)
    _signature(
        runner,
        payload=receipt_path,
        signing_key=signing_key,
        destination=signature_path,
    )
    _verify_signature(
        runner,
        payload=receipt_path,
        signature=signature_path,
        public_key=public_key,
    )
    _atomic_publish_receipt_directory(parent, pending, intent)
    return protected_directory(intent, modes=frozenset({0o700}))


def _print_retirement_result(
    *,
    final: Path,
    inventory: LegacyInventory,
    already_retired: bool,
) -> None:
    print(
        json.dumps(
            {
                "status": "already-retired" if already_retired else "retired",
                "project": PROJECT,
                "receipt": str(final / "receipt.json"),
                "receipt_signature": str(final / "receipt.sig"),
                "preserved_bind_root": str(DATA_ROOT),
                "preserved_named_volumes": [item.name for item in inventory.volumes],
                "next_step": "run the separate target release transaction",
                "rollback_boundary": "after target migration use forward-only repair",
            },
            sort_keys=True,
        )
    )


def _locate_upgrade_evidence_run(evidence_path: Path) -> tuple[Path, Path]:
    evidence = protected_file(
        evidence_path,
        modes=frozenset({0o400}),
        max_bytes=65_536,
    )
    evidence_directory = protected_directory(evidence.parent, modes=frozenset({0o700}))
    run = protected_directory(evidence_directory.parent, modes=frozenset({0o700}))
    if evidence.name != "upgrade-backup-evidence.json" or evidence_directory.name != "evidence":
        raise AdoptionError("upgrade evidence is outside its fixed run path")
    try:
        run.relative_to(BACKUP_ROOT)
    except ValueError as exc:
        raise AdoptionError("upgrade evidence is outside the backup root") from exc
    return evidence, run


def _retire(arguments: argparse.Namespace, runner: Runner) -> None:
    binding_key = _read_binding_key(arguments.binding_key)
    evidence_path, run = _locate_upgrade_evidence_run(arguments.evidence)
    evidence_digest = _sha256_file(evidence_path)
    receipt_parent = protected_directory(run / "evidence", modes=frozenset({0o700}))
    intent = receipt_parent / RETIREMENT_INTENT_DIRECTORY
    final = receipt_parent / "retirement"
    intent_exists = intent.exists() or intent.is_symlink()
    final_exists = final.exists() or final.is_symlink()
    if intent_exists and final_exists:
        raise AdoptionError("retirement intent and final receipt coexist ambiguously")
    durable_receipt_exists = intent_exists or final_exists
    if durable_receipt_exists:
        plan, plan_digest = _load_plan_identity(
            arguments.plan,
            enforce_freshness=False,
        )
        runtime: dict[str, str] = {}
    else:
        plan, plan_digest, runtime, _, _ = _validate_plan(arguments.plan, binding_key)
    planned = _planned_inventory(plan)
    execute = _confirm(arguments, plan_digest)
    if execute and arguments.confirm_preserve_data != "PRESERVE_BIND_DATA_AND_NAMED_VOLUMES":
        raise AdoptionError("retirement requires the exact preserve-data confirmation")

    if final_exists:
        receipt = _verify_retirement_receipt(
            runner,
            receipt_path=final / "receipt.json",
            signature_path=final / "receipt.sig",
            public_key=arguments.evidence_public_key,
            plan=plan,
            plan_digest=plan_digest,
            inventory=planned,
            enforce_freshness=False,
        )
        if receipt["upgrade_evidence_sha256"] != evidence_digest:
            raise AdoptionError("retirement receipt upgrade-evidence binding differs")
        if _release_state_binding() != receipt["release_state_binding"]:
            raise AdoptionError("release state differs from the signed retirement receipt")
        _verify_named_volumes(runner, planned.volumes)
        protected_directory(DATA_ROOT, modes=frozenset({0o700, 0o750, 0o755}))
        _assert_legacy_resources_absent(runner)
        _print_retirement_result(final=final, inventory=planned, already_retired=True)
        return

    if intent_exists:
        receipt = _verify_retirement_receipt(
            runner,
            receipt_path=intent / "receipt.json",
            signature_path=intent / "receipt.sig",
            public_key=arguments.evidence_public_key,
            plan=plan,
            plan_digest=plan_digest,
            inventory=planned,
            expected_directory_name=RETIREMENT_INTENT_DIRECTORY,
            enforce_freshness=False,
        )
        if receipt["upgrade_evidence_sha256"] != evidence_digest:
            raise AdoptionError("retirement intent upgrade-evidence binding differs")
        if _release_state_binding() != receipt["release_state_binding"]:
            raise AdoptionError("release state differs from the signed retirement intent")
        inventory = planned
        _verify_named_volumes(runner, inventory.volumes)
        protected_directory(DATA_ROOT, modes=frozenset({0o700, 0o750, 0o755}))
        if not execute:
            print(
                json.dumps(
                    {
                        "status": "retirement-in-progress",
                        "operation": "retire",
                        "project": PROJECT,
                        "plan_sha256": plan_digest,
                        "resume_requires_execute": True,
                        "global_actions": [],
                    },
                    sort_keys=True,
                )
            )
            return
    else:
        evidence, detailed, verified_run = _verify_upgrade_evidence(
            runner,
            evidence_path=evidence_path,
            signature_path=arguments.evidence_signature,
            public_key=arguments.evidence_public_key,
            plan=plan,
            plan_digest=plan_digest,
        )
        if verified_run != run:
            raise AdoptionError("signed upgrade evidence run path changed")
        if _object(detailed.get("source_images"), "evidence source images") != _source_images(
            planned
        ):
            raise AdoptionError("planned legacy images differ from signed restore evidence")
        source_schema_head = _string(
            _object(detailed.get("database"), "evidence database").get("schema_head"),
            "source schema head",
        )
        inventory = collect_inventory(runner)
        if topology_sha256(inventory) != plan["topology_sha256"]:
            raise AdoptionError("live legacy topology differs from the approved plan")
        if _source_images(inventory) != _source_images(planned):
            raise AdoptionError("live legacy images differ from signed restore evidence")
        _verify_data_bindings(inventory)
        _verify_postgres_17_and_schema(runner, inventory, runtime, source_schema_head)
        _verify_named_volumes(runner, inventory.volumes)
        protected_directory(DATA_ROOT, modes=frozenset({0o700, 0o750, 0o755}))
        if not execute:
            print(
                json.dumps(
                    {
                        "status": "dry-run",
                        "operation": "retire",
                        "project": PROJECT,
                        "plan_sha256": plan_digest,
                        "exact_container_ids": [item.container_id for item in inventory.containers],
                        "exact_network_ids": [item.network_id for item in inventory.networks],
                        "preserved_named_volumes": [item.name for item in inventory.volumes],
                        "preserved_bind_root": str(DATA_ROOT),
                        "global_actions": [],
                    },
                    sort_keys=True,
                )
            )
            return
        public_key = protected_file(
            arguments.evidence_public_key,
            modes=frozenset({0o400, 0o440, 0o444}),
            max_bytes=65_536,
        )
        signing_key = protected_file(
            arguments.evidence_signing_key,
            modes=frozenset({0o400, 0o600}),
            max_bytes=65_536,
        )
        receipt = {
            "schema_version": 2,
            "kind": "heyi-legacy-retirement-receipt",
            "status": "retired",
            "project": PROJECT,
            "issued_at": _utc_now().isoformat().replace("+00:00", "Z"),
            "git_sha": plan["git_sha"],
            "plan_sha256": plan_digest,
            "upgrade_evidence_sha256": evidence_digest,
            "target_manifest_sha256": evidence["target_manifest_sha256"],
            "source_schema_head": source_schema_head,
            "source_postgres_major": 17,
            "source_topology_sha256": plan["topology_sha256"],
            "restorable_topology_sha256": restorable_topology_sha256(inventory),
            "release_state_binding": _release_state_binding(),
            "removed_container_ids": [item.container_id for item in inventory.containers],
            "stopped_oneoff_container_ids_not_restored": [
                item.container_id for item in inventory.containers if item.oneoff
            ],
            "removed_network_ids": [item.network_id for item in inventory.networks],
            "preserved_named_volumes": [asdict(item) for item in inventory.volumes],
            "preserved_bind_root": str(DATA_ROOT),
            "named_volumes_deleted": False,
            "bind_data_deleted": False,
            "global_prune_used": False,
            "docker_daemon_restarted": False,
            "restore_boundary": REACTIVATION_BOUNDARY,
            "post_migration_rollback_policy": "forward-only",
        }
        intent = _publish_retirement_intent(
            runner,
            receipt_parent=receipt_parent,
            receipt=receipt,
            signing_key=signing_key,
            public_key=public_key,
        )

    removed_containers, removed_networks = _retire_exact_resources(
        runner, inventory, allow_missing=True
    )
    if (
        removed_containers != receipt["removed_container_ids"]
        or removed_networks != receipt["removed_network_ids"]
    ):
        raise AdoptionError("retired resource set differs from the signed receipt")
    _verify_named_volumes(runner, inventory.volumes)
    protected_directory(DATA_ROOT, modes=frozenset({0o700, 0o750, 0o755}))
    _assert_legacy_resources_absent(runner)
    _atomic_publish_receipt_directory(receipt_parent, intent, final)
    _print_retirement_result(final=final, inventory=inventory, already_retired=False)


def _collect_partial_project_inventory(runner: Runner) -> LegacyInventory:
    container_ids = _project_container_ids(runner)
    containers: tuple[ContainerRecord, ...] = ()
    if container_ids:
        inspected = runner.docker_json(("inspect", *sorted(container_ids)))
        containers = tuple(
            sorted(
                (_container_record(item) for item in _list(inspected, "project containers")),
                key=lambda item: (item.oneoff, item.service, item.container_id),
            )
        )
        if {item.container_id for item in containers} != container_ids:
            raise AdoptionError("partial project container inventory changed during inspection")
    network_ids = _project_network_ids(runner)
    networks: list[NetworkRecord] = []
    if network_ids:
        inspected_networks = runner.docker_json(("network", "inspect", *sorted(network_ids)))
        for raw in _list(inspected_networks, "project networks"):
            network = _object(raw, "project network")
            labels = _object(network.get("Labels"), "project network labels")
            network_id = _string(network.get("Id"), "project network id")
            attached = tuple(sorted(_object(network.get("Containers", {}), "network endpoints")))
            if (
                labels.get("com.docker.compose.project") != PROJECT
                or labels.get("io.heyi.knowledgebases.owner") != OWNER
                or labels.get("io.heyi.knowledgebases.stack") != STACK
                or network_id not in network_ids
                or not set(attached) <= container_ids
            ):
                raise AdoptionError("partial project network identity differs")
            networks.append(
                NetworkRecord(
                    name=_string(network.get("Name"), "project network name"),
                    network_id=network_id,
                    internal=bool(network.get("Internal")),
                    attached_container_ids=attached,
                )
            )
        if {item.network_id for item in networks} != network_ids:
            raise AdoptionError("partial project network inventory changed during inspection")
    return LegacyInventory(containers, tuple(sorted(networks, key=lambda item: item.name)), ())


def _same_reactivation_contract(current: ContainerRecord, expected: ContainerRecord) -> bool:
    return (
        replace(
            current,
            container_id=expected.container_id,
            running=expected.running,
            restart_count=expected.restart_count,
        )
        == expected
    )


def _validate_reactivation_subset(current: LegacyInventory, expected: LegacyInventory) -> None:
    expected_services = {item.service: item for item in expected.containers if not item.oneoff}
    seen: set[str] = set()
    for record in current.containers:
        expected_record = expected_services.get(record.service)
        if record.oneoff or expected_record is None:
            raise AdoptionError("partial reactivation contains an unknown service")
        if record.service in seen:
            raise AdoptionError("partial reactivation service is ambiguous")
        seen.add(record.service)
        if not _same_reactivation_contract(record, expected_record):
            raise AdoptionError("partial reactivation service contract differs")
        if record.running and not expected_record.running:
            raise AdoptionError("a signed-stopped legacy service is unexpectedly running")
    ordered_services = _ordered_primary_services(expected)
    expected_prefix = set(ordered_services[: len(seen)])
    if seen != expected_prefix:
        raise AdoptionError("partial reactivation is not an exact start-order prefix")
    expected_networks = {item.name: item for item in expected.networks}
    seen_networks: set[str] = set()
    for network in current.networks:
        expected_network = expected_networks.get(network.name)
        if expected_network is None:
            raise AdoptionError("partial reactivation contains an unknown network")
        if network.name in seen_networks:
            raise AdoptionError("partial reactivation network is ambiguous")
        seen_networks.add(network.name)
        if network.internal is not expected_network.internal:
            raise AdoptionError("partial reactivation network isolation differs")


def _edge_contracts_for_port(
    runner: Runner, proxy: ContainerRecord, port: str
) -> dict[tuple[str, str], frozenset[tuple[str, int]]]:
    inspected = runner.docker_json(("inspect", proxy.container_id))
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise AdoptionError("legacy proxy inspection is ambiguous")
    if _container_record(inspected[0]) != proxy:
        raise AdoptionError("legacy proxy changed during edge-port verification")
    container = _object(inspected[0], "legacy proxy inspection")
    network = _object(container.get("NetworkSettings"), "legacy proxy network settings")
    raw_ports = _object(network.get("Ports"), "legacy proxy port bindings")
    raw_networks = _object(network.get("Networks"), "legacy proxy networks")
    container_addresses: set[str] = set()
    for raw_network in raw_networks.values():
        network_entry = _object(raw_network, "legacy proxy network")
        for field in ("IPAddress", "GlobalIPv6Address"):
            raw_address = network_entry.get(field)
            if raw_address in {None, ""}:
                continue
            if not isinstance(raw_address, str):
                raise AdoptionError("legacy proxy container IP is malformed")
            try:
                container_addresses.add(str(ipaddress.ip_address(raw_address)))
            except ValueError as exc:
                raise AdoptionError("legacy proxy container IP is malformed") from exc
    if not container_addresses:
        raise AdoptionError("legacy proxy has no verifiable container IP")

    contracts: dict[tuple[str, str], set[tuple[str, int]]] = {}
    for raw_container_port, raw_values in raw_ports.items():
        if not isinstance(raw_container_port, str):
            raise AdoptionError("legacy proxy container port is malformed")
        container_port, separator, protocol = raw_container_port.partition("/")
        if (
            not separator
            or protocol != "tcp"
            or not container_port.isdecimal()
            or not 1 <= int(container_port) <= 65_535
        ):
            raise AdoptionError("legacy proxy container port is malformed")
        if raw_values is None:
            continue
        for raw_binding in _list(raw_values, "legacy proxy host bindings"):
            binding = _object(raw_binding, "legacy proxy host binding")
            host_port = _string(binding.get("HostPort"), "legacy proxy host port")
            if host_port != port:
                continue
            host_ip = _string(binding.get("HostIp"), "legacy proxy host IP")
            try:
                address = ipaddress.ip_address(host_ip)
            except ValueError as exc:
                raise AdoptionError("legacy proxy host IP is malformed") from exc
            family = "ipv4" if address.version == 4 else "ipv6"
            key = (family, str(address))
            targets = {(value, int(container_port)) for value in container_addresses}
            if key in contracts:
                raise AdoptionError(f"legacy edge port {port} binding is ambiguous")
            contracts[key] = targets
    if not contracts:
        raise AdoptionError(f"legacy edge port {port} binding is missing or ambiguous")
    return {key: frozenset(value) for key, value in contracts.items()}


def _listener_owner_pids(guard: ModuleType, socket_inode: int) -> tuple[int, ...]:
    owners: list[int] = []
    try:
        with os.scandir("/proc") as entries:
            pids = sorted(
                int(entry.name)
                for entry in entries
                if entry.name.isdecimal() and entry.is_dir(follow_symlinks=False)
            )
    except OSError as exc:
        raise AdoptionError("host process inventory could not be enumerated") from exc
    for pid in pids:
        try:
            inodes = guard._socket_inodes_for_pid(pid)
        except Exception as exc:
            if not Path(f"/proc/{pid}").exists():
                continue
            raise AdoptionError("host socket ownership could not be verified") from exc
        if not isinstance(inodes, set) or any(type(value) is not int for value in inodes):
            raise AdoptionError("host socket ownership inventory is malformed")
        if socket_inode in inodes:
            owners.append(pid)
    return tuple(owners)


def _process_cmdline(guard: ModuleType, pid: int) -> tuple[str, ...]:
    try:
        before = guard._process_start_ticks(pid)
        descriptor = os.open(
            Path(f"/proc/{pid}/cmdline"),
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            payload = os.read(descriptor, 65_537)
        finally:
            os.close(descriptor)
        after = guard._process_start_ticks(pid)
    except Exception as exc:
        raise AdoptionError("host listener process command line could not be verified") from exc
    if before != after or not payload or len(payload) > 65_536:
        raise AdoptionError("host listener process changed during verification")
    try:
        arguments = tuple(
            value.decode("utf-8", errors="strict") for value in payload.rstrip(b"\0").split(b"\0")
        )
    except UnicodeError as exc:
        raise AdoptionError("host listener process command line is malformed") from exc
    if not arguments or any(not value or "\x00" in value for value in arguments):
        raise AdoptionError("host listener process command line is malformed")
    return arguments


def _root_process_parent(guard: ModuleType, pid: int) -> int:
    try:
        before = guard._process_start_ticks(pid)
        metadata = Path(f"/proc/{pid}").stat(follow_symlinks=False)
        descriptor = os.open(
            Path(f"/proc/{pid}/status"),
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            payload = os.read(descriptor, 65_537)
        finally:
            os.close(descriptor)
        after = guard._process_start_ticks(pid)
    except Exception as exc:
        raise AdoptionError("host listener process provenance could not be verified") from exc
    if before != after or metadata.st_uid != 0 or not payload or len(payload) > 65_536:
        raise AdoptionError("host listener process provenance is unsafe")
    try:
        decoded = payload.decode("ascii", errors="strict")
    except UnicodeError as exc:
        raise AdoptionError("host listener process provenance is malformed") from exc
    fields: dict[str, str] = {}
    for line in decoded.splitlines():
        name, separator, value = line.partition(":")
        if separator:
            fields[name] = value.strip()
    uid_values = fields.get("Uid", "").split()
    parent_value = fields.get("PPid", "")
    if (
        len(uid_values) != 4
        or any(value != "0" for value in uid_values)
        or not parent_value.isdecimal()
        or int(parent_value) <= 0
    ):
        raise AdoptionError("host listener process is not a root Docker child")
    return int(parent_value)


def _verified_process_executable(
    guard: ModuleType,
    pid: int,
    *,
    allowed_paths: frozenset[str],
    label: str,
) -> Path:
    try:
        identity = guard._process_identity(pid)
    except Exception as exc:
        raise AdoptionError(f"{label} executable could not be verified") from exc
    process = _object(identity, f"{label} process")
    if process.get("pid") != pid:
        raise AdoptionError(f"{label} process identity differs")
    executable = _object(process.get("executable"), f"{label} executable")
    resolved_value = _string(executable.get("resolved_path"), f"{label} executable path")
    digest = _string(executable.get("sha256"), f"{label} executable digest")
    if resolved_value not in allowed_paths or _SHA256.fullmatch(digest) is None:
        raise AdoptionError(f"{label} executable is outside the trusted installation")
    resolved_path = Path(resolved_value)
    _validate_ancestors(resolved_path.parent)
    return resolved_path


def _single_process_option(arguments: Sequence[str], option: str) -> str:
    positions = [index for index, value in enumerate(arguments) if value == option]
    if len(positions) != 1 or positions[0] + 1 >= len(arguments):
        raise AdoptionError("docker-proxy process contract is malformed")
    return arguments[positions[0] + 1]


def _verify_listener_owned_by_proxy(
    guard: ModuleType,
    listener: Mapping[str, Any],
    contracts: Mapping[tuple[str, str], frozenset[tuple[str, int]]],
) -> None:
    inode = listener.get("socket_inode")
    if type(inode) is not int or inode <= 0:
        raise AdoptionError("host TCP listener identity is malformed")
    owners = _listener_owner_pids(guard, inode)
    if len(owners) != 1:
        raise AdoptionError("host TCP listener is not exclusively owned by Docker proxy")
    pid = owners[0]
    proxy_executable = _verified_process_executable(
        guard,
        pid,
        allowed_paths=TRUSTED_DOCKER_PROXY_PATHS,
        label="docker-proxy",
    )
    parent_pid = _root_process_parent(guard, pid)
    _verified_process_executable(
        guard,
        parent_pid,
        allowed_paths=TRUSTED_DOCKER_DAEMON_PATHS,
        label="Docker daemon",
    )
    arguments = _process_cmdline(guard, pid)
    if Path(arguments[0]).name != proxy_executable.name:
        raise AdoptionError("host listener process is not docker-proxy")
    if _single_process_option(arguments, "-proto") != "tcp":
        raise AdoptionError("docker-proxy protocol differs")
    host_port = _single_process_option(arguments, "-host-port")
    container_port = _single_process_option(arguments, "-container-port")
    if not host_port.isdecimal() or not container_port.isdecimal():
        raise AdoptionError("docker-proxy port contract is malformed")
    try:
        host_ip = str(ipaddress.ip_address(_single_process_option(arguments, "-host-ip")))
        container_ip = str(ipaddress.ip_address(_single_process_option(arguments, "-container-ip")))
    except ValueError as exc:
        raise AdoptionError("docker-proxy address contract is malformed") from exc
    family = _string(listener.get("family"), "host TCP listener family")
    key = (family, host_ip)
    if (
        listener.get("local_port") != int(host_port)
        or listener.get("local_address") != host_ip
        or (container_ip, int(container_port)) not in contracts.get(key, frozenset())
    ):
        raise AdoptionError("docker-proxy listener differs from the exact proxy container")


def _verify_edge_ports_available(
    runner: Runner,
    current: LegacyInventory,
    expected: LegacyInventory,
    guard: ModuleType,
) -> None:
    current_proxy = next(
        (item for item in current.containers if item.service == "proxy" and not item.oneoff),
        None,
    )
    expected_proxy = _service(expected, "proxy")
    for port in sorted(value.split("/", 1)[0] for value in EXPECTED_PORTS):
        raw_owners = runner.run(
            (runner.docker, "ps", "-q", "--no-trunc", "--filter", f"publish={port}")
        ).decode("ascii", errors="strict")
        owners = {line.strip() for line in raw_owners.splitlines() if line.strip()}
        if any(_CONTAINER_ID.fullmatch(value) is None for value in owners):
            raise AdoptionError("edge-port Docker owner identity is malformed")
        allowed: set[str] = set()
        if (
            current_proxy is not None
            and current_proxy.running
            and _same_reactivation_contract(current_proxy, expected_proxy)
            and any(value.startswith(f"{port}/") for value in current_proxy.published_ports)
        ):
            allowed.add(current_proxy.container_id)
        if owners - allowed:
            raise AdoptionError(f"legacy edge port {port} has an unknown Docker owner")
        try:
            listeners = guard._tcp_listeners(int(port))
        except Exception as exc:
            raise AdoptionError("host TCP listener inventory could not be verified") from exc
        if not isinstance(listeners, list):
            raise AdoptionError("host TCP listener inventory is malformed")
        if listeners and not owners:
            raise AdoptionError(f"legacy edge port {port} has a non-Docker host listener")
        if not listeners:
            continue
        if current_proxy is None:
            raise AdoptionError(f"legacy edge port {port} has no exact proxy owner")
        configured = _edge_contracts_for_port(runner, current_proxy, port)
        observed: list[tuple[str, str]] = []
        for raw_listener in listeners:
            listener = _object(raw_listener, "host TCP listener")
            family = _string(listener.get("family"), "host TCP listener family")
            address_value = _string(listener.get("local_address"), "host TCP listener address")
            local_port = listener.get("local_port")
            state = listener.get("state")
            inode = listener.get("socket_inode")
            try:
                address = ipaddress.ip_address(address_value)
            except ValueError as exc:
                raise AdoptionError("host TCP listener address is malformed") from exc
            expected_family = "ipv4" if address.version == 4 else "ipv6"
            if (
                family != expected_family
                or local_port != int(port)
                or state != "LISTEN"
                or type(inode) is not int
                or inode <= 0
            ):
                raise AdoptionError("host TCP listener identity is malformed")
            observed.append((family, str(address)))
            _verify_listener_owned_by_proxy(guard, listener, configured)
        if len(observed) != len(set(observed)) or not set(observed) <= set(configured):
            raise AdoptionError(f"legacy edge port {port} has an extra non-Docker listener")
        try:
            after = guard._tcp_listeners(int(port))
        except Exception as exc:
            raise AdoptionError("host TCP listener recheck could not be verified") from exc
        if after != listeners:
            raise AdoptionError("host TCP listener inventory changed during verification")


def _legacy_proxy_root_ca(inventory: LegacyInventory) -> Path:
    proxy = _service(inventory, "proxy")
    data_mounts = [
        mount
        for mount in proxy.mounts
        if mount[1] == "/data" and mount[2] and mount[3] in {"bind", "volume"}
    ]
    if len(data_mounts) != 1:
        raise AdoptionError("legacy proxy Caddy data mount is ambiguous")
    root = Path(data_mounts[0][0]) / "caddy/pki/authorities/local/root.crt"
    return protected_file(
        root,
        modes=frozenset({0o400, 0o440, 0o444, 0o644}),
        max_bytes=256 * 1024,
    )


def _legacy_tls_identity(runtime: Mapping[str, str]) -> tuple[str, str, str, str]:
    public_host = _string(runtime.get("KB_PUBLIC_HOST"), "legacy public host")
    try:
        public_address = ipaddress.ip_address(public_host)
    except ValueError as exc:
        if _DNS_HOST.fullmatch(public_host) is None:
            raise AdoptionError("legacy public host is malformed") from exc
        verify_option = "-verify_hostname"
        host_header = public_host
    else:
        verify_option = "-verify_ip"
        host_header = f"[{public_host}]" if public_address.version == 6 else public_host
    bind_value = runtime.get("KB_BIND_ADDRESS", "127.0.0.1")
    try:
        bind_address = ipaddress.ip_address(bind_value)
    except ValueError as exc:
        raise AdoptionError("legacy bind address is not an IP address") from exc
    if bind_address.is_unspecified:
        bind_address = ipaddress.ip_address("::1" if bind_address.version == 6 else "127.0.0.1")
    connect_host = f"[{bind_address}]" if bind_address.version == 6 else str(bind_address)
    return public_host, verify_option, host_header, connect_host


def _openssl_http_probe(
    runner: Runner,
    *,
    ca_file: Path,
    public_host: str,
    verify_option: str,
    host_header: str,
    connect_host: str,
    port: int,
    path: str,
    accepted_statuses: frozenset[int],
) -> None:
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}:{port}\r\n"
        "Connection: close\r\n"
        "User-Agent: heyi-legacy-reactivation-probe/1\r\n\r\n"
    ).encode("ascii", errors="strict")
    output = runner.run(
        (
            "/usr/bin/openssl",
            "s_client",
            "-connect",
            f"{connect_host}:{port}",
            "-servername",
            public_host,
            "-CAfile",
            str(ca_file),
            "-verify_return_error",
            verify_option,
            public_host,
            "-quiet",
            "-no_ign_eof",
        ),
        timeout=10,
        input_bytes=request,
    )
    status: int | None = None
    for line in output.splitlines():
        match = _HTTP_STATUS.match(line)
        if match is not None:
            status = int(match.group(1))
            break
    if status not in accepted_statuses:
        raise AdoptionError(f"legacy TLS readiness probe failed: {path}")


def _verify_legacy_edge_readiness(
    runner: Runner,
    inventory: LegacyInventory,
    runtime: Mapping[str, str],
) -> None:
    public_host, verify_option, host_header, connect_host = _legacy_tls_identity(runtime)
    probes = (
        (19443, "/health/ready", frozenset({200})),
        (19443, "/", frozenset(range(200, 400))),
        (19444, "/minio/health/ready", frozenset({200})),
    )
    deadline = time.monotonic() + REACTIVATION_EDGE_TIMEOUT_SECONDS
    while True:
        try:
            ca_file = _legacy_proxy_root_ca(inventory)
            for port, path, accepted in probes:
                _openssl_http_probe(
                    runner,
                    ca_file=ca_file,
                    public_host=public_host,
                    verify_option=verify_option,
                    host_header=host_header,
                    connect_host=connect_host,
                    port=port,
                    path=path,
                    accepted_statuses=accepted,
                )
        except AdoptionError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AdoptionError("legacy TLS business readiness timed out") from exc
            time.sleep(min(REACTIVATION_EDGE_POLL_SECONDS, remaining))
            continue
        return


def _assert_reactivation_surface(
    runner: Runner,
    expected: LegacyInventory,
    guard: ModuleType,
) -> LegacyInventory:
    current = _collect_partial_project_inventory(runner)
    _validate_reactivation_subset(current, expected)
    raw_names = runner.run(
        (
            runner.docker,
            "volume",
            "ls",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
        )
    ).decode("utf-8", errors="strict")
    observed = {line.strip() for line in raw_names.splitlines() if line.strip()}
    expected_names = {item.name for item in expected.volumes}
    if observed != expected_names:
        raise AdoptionError("project volume set drifted after retirement")
    _verify_named_volumes(runner, expected.volumes)
    _verify_edge_ports_available(runner, current, expected, guard)
    return current


def _collect_exact_primary_service(runner: Runner, service: str) -> ContainerRecord:
    raw_ids = runner.run(
        (
            runner.docker,
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
            "--filter",
            f"label=com.docker.compose.service={service}",
        )
    ).decode("ascii", errors="strict")
    ids = [line.strip() for line in raw_ids.splitlines() if line.strip()]
    if len(ids) != 1 or _CONTAINER_ID.fullmatch(ids[0]) is None:
        raise AdoptionError(f"reactivated service identity is ambiguous: {service}")
    inspected = runner.docker_json(("inspect", ids[0]))
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise AdoptionError(f"reactivated service inspection is ambiguous: {service}")
    record = _container_record(inspected[0])
    if record.service != service or record.oneoff:
        raise AdoptionError(f"reactivated service label differs: {service}")
    return record


def _same_recreated_container(current: ContainerRecord, expected: ContainerRecord) -> bool:
    return current.running is expected.running and (
        replace(
            current,
            container_id=expected.container_id,
            restart_count=expected.restart_count,
        )
        == expected
    )


def _reactivated_health_status(
    runner: Runner,
    *,
    current: ContainerRecord,
    expected: ContainerRecord,
) -> str | None:
    inspected = runner.docker_json(("inspect", current.container_id))
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise AdoptionError(f"reactivated health inspection is ambiguous: {current.service}")
    observed = _container_record(inspected[0])
    if not _same_recreated_container(observed, expected):
        raise AdoptionError(f"reactivated service changed during health wait: {current.service}")
    container = _object(inspected[0], "reactivated container")
    config = _object(container.get("Config"), "reactivated container config")
    raw_healthcheck = config.get("Healthcheck")
    healthcheck_enabled = False
    if raw_healthcheck is not None:
        healthcheck = _object(raw_healthcheck, "reactivated healthcheck")
        test = _list(healthcheck.get("Test"), "reactivated healthcheck test")
        if (
            not test
            or any(not isinstance(value, str) or not value for value in test)
            or test[0] not in {"NONE", "CMD", "CMD-SHELL"}
            or (test[0] == "NONE" and len(test) != 1)
        ):
            raise AdoptionError("reactivated healthcheck test is malformed")
        healthcheck_enabled = bool(test and test[0] != "NONE")
    state = _object(container.get("State"), "reactivated container state")
    raw_health = state.get("Health")
    if not healthcheck_enabled:
        if raw_health is not None:
            raise AdoptionError("container health state exists without a defined healthcheck")
        return None
    health = _object(raw_health, "reactivated health state")
    status = _string(health.get("Status"), "reactivated health status")
    if status not in {"starting", "healthy", "unhealthy"}:
        raise AdoptionError("reactivated health status is invalid")
    return status


def _wait_reactivated_service_ready(
    runner: Runner,
    *,
    current: ContainerRecord,
    expected: ContainerRecord,
) -> None:
    if not expected.running:
        return
    deadline = time.monotonic() + REACTIVATION_HEALTH_TIMEOUT_SECONDS
    while True:
        status = _reactivated_health_status(
            runner,
            current=current,
            expected=expected,
        )
        if status in {None, "healthy"}:
            return
        if status == "unhealthy":
            raise AdoptionError(f"reactivated service is unhealthy: {current.service}")
        if time.monotonic() >= deadline:
            raise AdoptionError(f"reactivated service health timed out: {current.service}")
        time.sleep(REACTIVATION_HEALTH_POLL_SECONDS)


def _run_exact_compose_service(
    runner: Runner,
    *,
    expected: LegacyInventory,
    service: str,
    compose_paths: Sequence[Path],
    runtime_path: Path,
    env_paths: Sequence[Path],
) -> None:
    record = _service(expected, service)
    base = _compose_for_service(expected, service, compose_paths, runtime_path, env_paths)
    runner.run((*base, "config", "--quiet"), timeout=120)
    operation: tuple[str, ...]
    if record.running:
        operation = ("up", "-d", "--no-build", "--pull", "never", "--no-deps", service)
    else:
        operation = (
            "up",
            "--no-start",
            "--no-deps",
            "--no-build",
            "--pull",
            "never",
            service,
        )
    runner.run((*base, *operation), timeout=900)
    current = _collect_exact_primary_service(runner, service)
    if not _same_recreated_container(current, record):
        raise AdoptionError(f"reactivated service contract differs: {service}")
    _wait_reactivated_service_ready(runner, current=current, expected=record)


def _reactivate(arguments: argparse.Namespace, runner: Runner) -> None:
    binding_key = _read_binding_key(arguments.binding_key)
    plan, plan_digest, runtime, compose_paths, env_paths = _validate_plan(
        arguments.plan,
        binding_key,
        enforce_freshness=False,
    )
    expected = _planned_inventory(plan)
    receipt = _verify_retirement_receipt(
        runner,
        receipt_path=arguments.retirement_receipt,
        signature_path=arguments.retirement_signature,
        public_key=arguments.evidence_public_key,
        plan=plan,
        plan_digest=plan_digest,
        inventory=expected,
        enforce_freshness=False,
    )
    _verify_target_abort_authorization(
        runner,
        receipt_path=arguments.target_abort_receipt,
        signature_path=arguments.target_abort_signature,
        public_key=arguments.evidence_public_key,
        adoption_transaction=arguments.adoption_transaction,
        plan_digest=plan_digest,
        retirement_receipt_path=arguments.retirement_receipt,
        retirement_receipt=receipt,
    )
    _verify_data_bindings(expected)
    if _release_state_binding() != receipt["release_state_binding"]:
        raise AdoptionError("install or materialized-release state drifted after retirement")
    guard = _verify_host_isolation(
        plan, arguments.host_isolation_baseline, arguments.host_isolation_hmac_key
    )
    _assert_reactivation_surface(runner, expected, guard)
    execute = _confirm(arguments, plan_digest)
    if execute and arguments.confirm_restore_boundary != REACTIVATION_BOUNDARY:
        raise AdoptionError("reactivation requires the exact pre-migration-only boundary")
    if not execute:
        print(
            json.dumps(
                {
                    "status": "dry-run",
                    "operation": "reactivate",
                    "project": PROJECT,
                    "plan_sha256": plan_digest,
                    "restore_boundary": REACTIVATION_BOUNDARY,
                    "adoption_transaction": arguments.adoption_transaction,
                    "host_isolation": "verified",
                    "oneoff_containers_restored": False,
                    "global_actions": [],
                },
                sort_keys=True,
            )
        )
        return

    runtime_path = Path(_object(plan["runtime_env"], "runtime environment")["path"])
    postgres_expected = _service(expected, "postgres")
    if not postgres_expected.running:
        raise AdoptionError("signed legacy PostgreSQL was not running at retirement")
    _run_exact_compose_service(
        runner,
        expected=expected,
        service="postgres",
        compose_paths=compose_paths,
        runtime_path=runtime_path,
        env_paths=env_paths,
    )
    postgres = _collect_exact_primary_service(runner, "postgres")
    postgres_inventory = LegacyInventory((postgres,), (), ())
    _verify_postgres_17_and_schema(
        runner,
        postgres_inventory,
        runtime,
        _string(receipt.get("source_schema_head"), "retirement schema head"),
    )
    for service in _ordered_primary_services(expected):
        if service == "postgres":
            continue
        _run_exact_compose_service(
            runner,
            expected=expected,
            service=service,
            compose_paths=compose_paths,
            runtime_path=runtime_path,
            env_paths=env_paths,
        )
    current = collect_inventory(runner)
    if any(item.oneoff for item in current.containers):
        raise AdoptionError("reactivation unexpectedly restored a one-off container")
    if restorable_topology_sha256(current) != receipt["restorable_topology_sha256"]:
        raise AdoptionError("reactivated legacy topology differs from signed retirement state")
    _verify_data_bindings(current)
    for service in _ordered_primary_services(expected):
        _wait_reactivated_service_ready(
            runner,
            current=_service(current, service),
            expected=_service(expected, service),
        )
    _verify_named_volumes(runner, expected.volumes)
    if _release_state_binding() != receipt["release_state_binding"]:
        raise AdoptionError("release state changed during legacy reactivation")
    final_guard = _verify_host_isolation(
        plan, arguments.host_isolation_baseline, arguments.host_isolation_hmac_key
    )
    _verify_edge_ports_available(runner, current, expected, final_guard)
    _verify_legacy_edge_readiness(runner, current, runtime)
    print(
        json.dumps(
            {
                "status": "reactivated-pre-migration-only",
                "project": PROJECT,
                "plan_sha256": plan_digest,
                "restore_boundary": REACTIVATION_BOUNDARY,
                "adoption_transaction": arguments.adoption_transaction,
                "restored_services": list(_ordered_primary_services(current)),
                "oneoff_containers_restored": False,
                "retirement_receipt_preserved": str(arguments.retirement_receipt),
                "runtime_healthchecks": "passed-or-not-defined",
                "business_readiness": "ca-verified-edge-probes-passed",
                "global_actions": [],
            },
            sort_keys=True,
        )
    )


def _plan_command(arguments: argparse.Namespace, runner: Runner) -> None:
    binding_key = _read_binding_key(arguments.binding_key)
    runtime_path = protected_file(
        arguments.runtime_env,
        modes=frozenset({0o400, 0o600}),
    )
    _, runtime_binding = parse_runtime_environment(runtime_path, binding_key)
    env_paths = tuple(arguments.legacy_env_file)
    bindings = {str(path): _env_binding(path, binding_key) for path in env_paths}
    inventory = collect_inventory(runner)
    document = build_plan(
        inventory=inventory,
        runtime_env=runtime_path,
        runtime_binding=runtime_binding,
        compose_files=tuple(arguments.compose_file),
        legacy_env_files=env_paths,
        legacy_env_bindings=bindings,
        target_manifest=arguments.target_manifest,
        git_sha=arguments.git_sha,
    )
    output = arguments.output_plan
    adoption_state = STATE_ROOT / "legacy-adoption"
    if output.parent != adoption_state or _SAFE_NAME.fullmatch(output.name) is None:
        raise AdoptionError("plan output must be a safe file in the fixed adoption-state root")
    protected_directory(STATE_ROOT, modes=frozenset({0o700, 0o750}))
    if not adoption_state.exists():
        adoption_state.mkdir(mode=0o700)
        _posix_chown(adoption_state, 0, 0)
    protected_directory(adoption_state, modes=frozenset({0o700}))
    _atomic_write(output, _canonical_json(document), mode=0o400)
    print(
        json.dumps(
            {
                "status": "planned",
                "project": PROJECT,
                "plan": str(output),
                "plan_sha256": _plan_digest(document),
                "next_step": "run prepare without --execute, then repeat with both confirmations",
            },
            sort_keys=True,
        )
    )


def _add_execution_confirmation(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-project", default="")
    parser.add_argument("--confirm-plan-sha256", default="")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        description=(
            "Fail-closed preserve-data adoption of the exact heyi-kb-offline project; "
            "all mutating operations default to dry-run."
        )
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)

    plan = subparsers.add_parser("plan", help="capture a protected immutable adoption plan")
    plan.add_argument("--binding-key", type=Path, required=True)
    plan.add_argument("--runtime-env", type=Path, required=True)
    plan.add_argument("--compose-file", type=Path, action="append", required=True)
    plan.add_argument("--legacy-env-file", type=Path, action="append", default=[])
    plan.add_argument("--target-manifest", type=Path, required=True)
    plan.add_argument("--git-sha", required=True)
    plan.add_argument(
        "--output-plan",
        type=Path,
        default=STATE_ROOT / "legacy-adoption" / "plan.json",
    )

    prepare = subparsers.add_parser(
        "prepare", help="quiesce, back up, encrypt CA material, and restore the old stack"
    )
    prepare.add_argument("--plan", type=Path, required=True)
    prepare.add_argument("--binding-key", type=Path, required=True)
    prepare.add_argument("--run-id", required=True)
    prepare.add_argument("--backup-root", type=Path, default=BACKUP_ROOT)
    prepare.add_argument("--ca-root", type=Path, required=True)
    prepare.add_argument("--ca-recipient-certificate", type=Path, required=True)
    prepare.add_argument("--evidence-signing-key", type=Path, required=True)
    prepare.add_argument("--evidence-public-key", type=Path, required=True)
    _add_execution_confirmation(prepare)

    finalize = subparsers.add_parser(
        "finalize", help="verify offline CA attestation and run isolated full restore drills"
    )
    finalize.add_argument("--plan", type=Path, required=True)
    finalize.add_argument("--binding-key", type=Path, required=True)
    finalize.add_argument("--prepared-state", type=Path, required=True)
    finalize.add_argument("--ca-restore-attestation", type=Path, required=True)
    finalize.add_argument("--ca-restore-attestation-signature", type=Path, required=True)
    finalize.add_argument("--ca-restore-attestation-public-key", type=Path, required=True)
    finalize.add_argument("--evidence-signing-key", type=Path, required=True)
    finalize.add_argument("--evidence-public-key", type=Path, required=True)
    finalize.add_argument(
        "--scratch-root",
        type=Path,
        default=STATE_ROOT / "legacy-adoption-drills",
    )
    _add_execution_confirmation(finalize)

    retire = subparsers.add_parser(
        "retire", help="remove only exact project containers/networks after signed restore proof"
    )
    retire.add_argument("--plan", type=Path, required=True)
    retire.add_argument("--binding-key", type=Path, required=True)
    retire.add_argument("--evidence", type=Path, required=True)
    retire.add_argument("--evidence-signature", type=Path, required=True)
    retire.add_argument("--evidence-public-key", type=Path, required=True)
    retire.add_argument("--evidence-signing-key", type=Path, required=True)
    retire.add_argument("--confirm-preserve-data", default="")
    _add_execution_confirmation(retire)

    reactivate = subparsers.add_parser(
        "reactivate",
        help="restore only the signed legacy topology before any target migration",
    )
    reactivate.add_argument("--plan", type=Path, required=True)
    reactivate.add_argument("--binding-key", type=Path, required=True)
    reactivate.add_argument("--retirement-receipt", type=Path, required=True)
    reactivate.add_argument("--retirement-signature", type=Path, required=True)
    reactivate.add_argument("--target-abort-receipt", type=Path, required=True)
    reactivate.add_argument("--target-abort-signature", type=Path, required=True)
    reactivate.add_argument("--adoption-transaction", required=True)
    reactivate.add_argument("--evidence-public-key", type=Path, required=True)
    reactivate.add_argument("--host-isolation-baseline", type=Path, required=True)
    reactivate.add_argument("--host-isolation-hmac-key", type=Path, required=True)
    reactivate.add_argument("--confirm-restore-boundary", default="")
    _add_execution_confirmation(reactivate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        _require_root()
        runner = Runner()
        operations = {
            "plan": _plan_command,
            "prepare": _prepare,
            "finalize": _finalize,
            "retire": _retire,
            "reactivate": _reactivate,
        }
        operations[arguments.operation](arguments, runner)
    except (AdoptionError, OSError, UnicodeError, tarfile.TarError) as exc:
        print(f"legacy-adoption: {exc}", file=sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
