from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat

# Required for read-only Docker/systemd probes; both executable paths are verified below.
import subprocess  # nosec B404
import sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn, cast

SCHEMA_VERSION = 1
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
MAX_HMAC_KEY_BYTES = 4096
MIN_HMAC_KEY_BYTES = 32
DOCKER_TIMEOUT_SECONDS = 30
SYSTEMCTL_TIMEOUT_SECONDS = 15
MAX_SYSTEMCTL_OUTPUT_BYTES = 64 * 1024
MAX_VIRTUAL_FILE_BYTES = 4 * 1024 * 1024
TRUSTED_DOCKER_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
LOCAL_DOCKER_SOCKET = Path("/var/run/docker.sock")
REQUIRED_HOST_PORTS = (10050,)
REQUIRED_SYSTEMD_UNIT = "zabbix-agent.service"
EXCLUDED_COMPOSE_PROJECTS = ("heyi-kb-acceptance", "heyi-kb-offline")
EXCLUDED_COMPOSE_PROJECT_PREFIXES = ("heyi-kb-acceptance-",)
SYSTEMCTL_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "FragmentPath",
    "MainPID",
    "ExecMainPID",
    "NRestarts",
    "InvocationID",
    "ControlGroup",
    "User",
    "Group",
    "DynamicUser",
    "ActiveEnterTimestampMonotonic",
    "ExecMainStartTimestampMonotonic",
)

DockerRunner = Callable[[Sequence[str]], str]
HostProbe = Callable[[bool], dict[str, object]]
JsonObject = dict[str, Any]

_CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_PORT_KEY = re.compile(r"[1-9][0-9]{0,4}/(?:tcp|udp|sctp)")
_COMPOSE_PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}")
_SYSTEMD_UNIT = re.compile(r"[A-Za-z0-9_.@:-]{1,255}\.service")
_SYSTEMD_INVOCATION_ID = re.compile(r"[0-9a-f]{32}")
_CONTROL_GROUP = re.compile(r"/(?:[A-Za-z0-9_.@:-]+/?)+")
_SOCKET_LINK = re.compile(r"socket:\[([1-9][0-9]*)\]")

# The Docker daemon renders only this explicit allowlist. Config.Env, command/args,
# generic labels, secrets and network DriverOpts are never requested.
CONTAINER_INSPECT_TEMPLATE = (
    '{"id":{{json .Id}},"name":{{json .Name}},"image_id":{{json .Image}},'
    '"image_ref":{{json .Config.Image}},"created_at":{{json .Created}},'
    '"state_status":{{json .State.Status}},"state_running":{{json .State.Running}},'
    '"state_paused":{{json .State.Paused}},'
    '"state_restarting":{{json .State.Restarting}},'
    '"state_oom_killed":{{json .State.OOMKilled}},"state_dead":{{json .State.Dead}},'
    '"started_at":{{json .State.StartedAt}},"finished_at":{{json .State.FinishedAt}},'
    '"exit_code":{{json .State.ExitCode}},"restart_count":{{json .RestartCount}},'
    '"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}},'
    '"restart_policy":{{json .HostConfig.RestartPolicy}},'
    '"network_mode":{{json .HostConfig.NetworkMode}},'
    '"configured_ports":{{json .HostConfig.PortBindings}},'
    '"runtime_ports":{{json .NetworkSettings.Ports}},"mounts":{{json .Mounts}},'
    '"networks":{{json .NetworkSettings.Networks}},'
    '"compose_project":{{with index .Config.Labels '
    '"com.docker.compose.project"}}{{json .}}{{else}}null{{end}}}'
)

DOCKER_INFO_TEMPLATE = (
    '{"daemon_id":{{json .ID}},"daemon_name":{{json .Name}},'
    '"server_version":{{json .ServerVersion}},'
    '"operating_system":{{json .OperatingSystem}},'
    '"architecture":{{json .Architecture}}}'
)


class GuardError(RuntimeError):
    """A fail-closed error safe to disclose without Docker or secret payloads."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise GuardError("invalid_arguments", message)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise GuardError("invalid_evidence", "evidence is not canonical JSON") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _without_integrity(document: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in document.items() if key != "integrity"}


def attach_integrity(document: Mapping[str, object], key: bytes | None = None) -> dict[str, object]:
    body = _without_integrity(document)
    canonical = _canonical_bytes(body)
    if key is None:
        integrity: dict[str, object] = {
            "algorithm": "sha256",
            "digest": hashlib.sha256(canonical).hexdigest(),
        }
    else:
        if len(key) < MIN_HMAC_KEY_BYTES:
            raise GuardError("weak_hmac_key", "HMAC key must contain at least 32 bytes")
        integrity = {
            "algorithm": "hmac-sha256",
            "digest": hmac.new(key, canonical, hashlib.sha256).hexdigest(),
            "key_id": hashlib.sha256(key).hexdigest(),
        }
    return {**body, "integrity": integrity}


def verify_integrity(document: Mapping[str, object], key: bytes | None = None) -> None:
    integrity = document.get("integrity")
    if not isinstance(integrity, dict):
        raise GuardError("invalid_integrity", "evidence integrity metadata is missing")
    algorithm = integrity.get("algorithm")
    digest = integrity.get("digest")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise GuardError("invalid_integrity", "evidence digest is malformed")
    canonical = _canonical_bytes(_without_integrity(document))
    if algorithm == "sha256":
        expected = hashlib.sha256(canonical).hexdigest()
    elif algorithm == "hmac-sha256":
        if key is None:
            raise GuardError("hmac_key_required", "HMAC-protected evidence requires its key")
        if len(key) < MIN_HMAC_KEY_BYTES:
            raise GuardError("weak_hmac_key", "HMAC key must contain at least 32 bytes")
        key_id = integrity.get("key_id")
        actual_key_id = hashlib.sha256(key).hexdigest()
        if not isinstance(key_id, str) or not hmac.compare_digest(key_id, actual_key_id):
            raise GuardError("hmac_key_mismatch", "HMAC key identity does not match evidence")
        expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    else:
        raise GuardError("invalid_integrity", "unsupported evidence integrity algorithm")
    if not hmac.compare_digest(digest, expected):
        raise GuardError("integrity_mismatch", "evidence integrity verification failed")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GuardError("invalid_json", "JSON contains duplicate object keys")
        result[key] = value
    return result


def _parse_json_object(raw: str, *, source: str) -> JsonObject:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except GuardError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise GuardError("invalid_json", f"{source} did not return valid JSON") from exc
    if not isinstance(value, dict):
        raise GuardError("invalid_json", f"{source} JSON must be an object")
    return cast(JsonObject, value)


def _is_reparse_or_symlink(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _absolute_without_resolution(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _assert_no_symlink_ancestors(path: Path) -> None:
    absolute = _absolute_without_resolution(path)
    parent = absolute.parent
    chain = list(reversed((parent, *parent.parents)))
    for component in chain:
        try:
            metadata = component.lstat()
        except OSError as exc:
            raise GuardError("unsafe_path", "evidence parent directory is unavailable") from exc
        if _is_reparse_or_symlink(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise GuardError(
                "unsafe_path", "evidence paths may not traverse links or non-directories"
            )


def _open_posix_directory_nofollow(path: Path) -> int:
    absolute = _absolute_without_resolution(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_fd: int | None = None
    try:
        directory_fd = os.open("/", flags)
        for component in absolute.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
    except OSError as exc:
        if directory_fd is not None:
            with suppress(OSError):
                os.close(directory_fd)
        raise GuardError(
            "unsafe_path", "evidence paths may not traverse links or non-directories"
        ) from exc
    if directory_fd is None:
        raise GuardError("unsafe_path", "evidence directory could not be opened safely")
    return directory_fd


def _validate_regular_metadata(
    metadata: os.stat_result,
    *,
    maximum_bytes: int,
    private: bool,
) -> None:
    if _is_reparse_or_symlink(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise GuardError("unsafe_file", "evidence input must be a regular non-link file")
    if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
        raise GuardError("unsafe_file", "evidence input has an invalid size")
    if os.name == "posix":
        forbidden_mode = 0o077 if private else 0o022
        if stat.S_IMODE(metadata.st_mode) & forbidden_mode:
            raise GuardError("unsafe_permissions", "evidence input permissions are too broad")
        get_effective_uid = getattr(os, "geteuid", None)
        if get_effective_uid is None:
            raise GuardError("unsafe_owner", "POSIX owner verification is unavailable")
        current_uid = cast(Callable[[], int], get_effective_uid)()
        if metadata.st_uid not in {0, current_uid}:
            raise GuardError("unsafe_owner", "evidence input has an untrusted owner")


def safe_read_bytes(path: Path, *, maximum_bytes: int, private: bool) -> bytes:
    absolute = _absolute_without_resolution(path)
    if os.name == "posix":
        directory_fd = _open_posix_directory_nofollow(absolute.parent)
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                file_fd = os.open(absolute.name, flags, dir_fd=directory_fd)
            except OSError as exc:
                raise GuardError(
                    "unsafe_file", "evidence input must be a regular non-link file"
                ) from exc
            try:
                metadata = os.fstat(file_fd)
                _validate_regular_metadata(metadata, maximum_bytes=maximum_bytes, private=private)
                chunks: list[bytes] = []
                remaining = maximum_bytes + 1
                while remaining > 0:
                    chunk = os.read(file_fd, min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                value = b"".join(chunks)
            finally:
                os.close(file_fd)
        finally:
            os.close(directory_fd)
    else:
        _assert_no_symlink_ancestors(absolute)
        metadata = absolute.lstat()
        _validate_regular_metadata(metadata, maximum_bytes=maximum_bytes, private=private)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        file_fd = os.open(absolute, flags)
        try:
            opened_metadata = os.fstat(file_fd)
            _validate_regular_metadata(
                opened_metadata, maximum_bytes=maximum_bytes, private=private
            )
            value = os.read(file_fd, maximum_bytes + 1)
        finally:
            os.close(file_fd)
    if not value or len(value) > maximum_bytes:
        raise GuardError("unsafe_file", "evidence input has an invalid size")
    return value


def safe_write_json(path: Path, document: Mapping[str, object]) -> None:
    absolute = _absolute_without_resolution(path)
    serialized = (
        json.dumps(document, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True).encode(
            "utf-8"
        )
        + b"\n"
    )
    if len(serialized) > MAX_EVIDENCE_BYTES:
        raise GuardError("evidence_too_large", "evidence exceeds the size limit")
    temporary_name = f".{absolute.name}.{secrets.token_hex(16)}.tmp"
    if os.name == "posix":
        directory_fd = _open_posix_directory_nofollow(absolute.parent)
        try:
            try:
                existing = os.stat(absolute.name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None and (
                _is_reparse_or_symlink(existing) or not stat.S_ISREG(existing.st_mode)
            ):
                raise GuardError("unsafe_output", "evidence output may replace only a regular file")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0)
            file_fd = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
            try:
                with os.fdopen(file_fd, "wb", closefd=False) as output:
                    output.write(serialized)
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                os.close(file_fd)
            os.replace(
                temporary_name,
                absolute.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.chmod(
                absolute.name,
                0o600,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.fsync(directory_fd)
        except BaseException:
            with suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory_fd)
            raise
        finally:
            os.close(directory_fd)
    else:
        _assert_no_symlink_ancestors(absolute)
        try:
            existing = absolute.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            _is_reparse_or_symlink(existing) or not stat.S_ISREG(existing.st_mode)
        ):
            raise GuardError("unsafe_output", "evidence output is not a regular file")
        temporary = absolute.with_name(temporary_name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        file_fd = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(file_fd, "wb", closefd=False) as output:
                output.write(serialized)
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(file_fd)
        try:
            os.replace(temporary, absolute)
            os.chmod(absolute, 0o600)
        except BaseException:
            with suppress(OSError):
                temporary.unlink()
            raise


def load_json_evidence(path: Path) -> JsonObject:
    raw = safe_read_bytes(path, maximum_bytes=MAX_EVIDENCE_BYTES, private=False)
    try:
        decoded = raw.decode("utf-8")
    except UnicodeError as exc:
        raise GuardError("invalid_json", "evidence must be UTF-8 JSON") from exc
    return _parse_json_object(decoded, source="evidence")


def load_hmac_key(path: Path | None) -> bytes | None:
    if path is None:
        return None
    value = safe_read_bytes(path, maximum_bytes=MAX_HMAC_KEY_BYTES, private=True)
    if len(value) < MIN_HMAC_KEY_BYTES:
        raise GuardError("weak_hmac_key", "HMAC key must contain at least 32 bytes")
    return value


def _resolve_docker_executable() -> Path:
    executable_name = "docker" if os.name == "posix" else "docker.exe"
    search_path = TRUSTED_DOCKER_PATH if os.name == "posix" else None
    candidate = shutil.which(executable_name, path=search_path)
    if candidate is None:
        raise GuardError("docker_unavailable", "Docker executable is unavailable")
    try:
        executable = Path(candidate).resolve(strict=True)
        metadata = executable.stat()
    except OSError as exc:
        raise GuardError("docker_unavailable", "Docker executable is unavailable") from exc
    if not executable.is_absolute() or not stat.S_ISREG(metadata.st_mode):
        raise GuardError("untrusted_docker", "Docker executable is not a regular file")
    if os.name == "posix" and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022):
        raise GuardError(
            "untrusted_docker", "Docker executable ownership or permissions are unsafe"
        )
    return executable


def _resolve_systemctl_executable() -> Path:
    if os.name != "posix":
        raise GuardError("host_probe_unsupported", "Host service probe requires Linux")
    candidate = shutil.which("systemctl", path=TRUSTED_DOCKER_PATH)
    if candidate is None:
        raise GuardError("systemctl_unavailable", "systemctl executable is unavailable")
    try:
        executable = Path(candidate).resolve(strict=True)
        metadata = executable.stat()
    except OSError as exc:
        raise GuardError("systemctl_unavailable", "systemctl executable is unavailable") from exc
    if (
        not executable.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise GuardError("untrusted_systemctl", "systemctl ownership or permissions are unsafe")
    return executable


def _trusted_subprocess_environment() -> dict[str, str]:
    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": TRUSTED_DOCKER_PATH,
    }


def _resolve_local_docker_endpoint() -> str:
    if os.name != "posix":
        return "npipe:////./pipe/docker_engine"
    try:
        socket_path = LOCAL_DOCKER_SOCKET.resolve(strict=True)
        metadata = socket_path.stat()
    except OSError as exc:
        raise GuardError("docker_unavailable", "Local Docker socket is unavailable") from exc
    if (
        not socket_path.is_absolute()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o002
    ):
        raise GuardError(
            "untrusted_docker", "Local Docker socket ownership or permissions are unsafe"
        )
    return f"unix://{socket_path}"


def _system_docker_runner(arguments: Sequence[str]) -> str:
    docker_executable = _resolve_docker_executable()
    docker_endpoint = _resolve_local_docker_endpoint()
    try:
        # The executable is absolute/root-owned and shell execution is disabled.
        completed = subprocess.run(  # nosec B603
            [
                os.fspath(docker_executable),
                "--host",
                docker_endpoint,
                *arguments,
            ],
            capture_output=True,
            check=False,
            encoding="utf-8",
            env=_trusted_subprocess_environment(),
            errors="strict",
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise GuardError("docker_unavailable", "Docker inventory could not be collected") from exc
    if completed.returncode != 0:
        # Deliberately do not relay daemon output: it can contain host paths or credentials.
        raise GuardError("docker_failed", "Docker inventory command failed")
    return completed.stdout


def _systemctl_show(unit: str) -> dict[str, str]:
    if _SYSTEMD_UNIT.fullmatch(unit) is None:
        raise GuardError("invalid_systemd_unit", "Systemd unit name is invalid")
    executable = _resolve_systemctl_executable()
    try:
        # The executable is absolute/root-owned and shell execution is disabled.
        completed = subprocess.run(  # nosec B603
            [
                os.fspath(executable),
                "--system",
                "show",
                unit,
                "--no-pager",
                f"--property={','.join(SYSTEMCTL_PROPERTIES)}",
            ],
            capture_output=True,
            check=False,
            encoding="utf-8",
            env=_trusted_subprocess_environment(),
            errors="strict",
            timeout=SYSTEMCTL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise GuardError(
            "systemctl_unavailable", "Systemd unit state could not be collected"
        ) from exc
    if completed.returncode != 0:
        raise GuardError("systemctl_failed", "Systemd unit state command failed")
    if len(completed.stdout.encode("utf-8")) > MAX_SYSTEMCTL_OUTPUT_BYTES:
        raise GuardError("invalid_systemd_state", "Systemd unit state output is too large")
    properties: dict[str, str] = {}
    allowed = set(SYSTEMCTL_PROPERTIES)
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in allowed or key in properties:
            raise GuardError("invalid_systemd_state", "Systemd unit state is malformed")
        properties[key] = value
    if set(properties) != allowed:
        raise GuardError("invalid_systemd_state", "Systemd unit state is incomplete")
    return properties


def _require_string(value: object, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise GuardError("invalid_docker_inventory", f"Docker field {field} is invalid")
    return value


def _require_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise GuardError("invalid_docker_inventory", f"Docker field {field} is invalid")
    return value


def _require_int(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise GuardError("invalid_docker_inventory", f"Docker field {field} is invalid")
    return value


def _optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _require_string(value, field, allow_empty=True)


def _normalize_string_list(value: object, field: str) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise GuardError("invalid_docker_inventory", f"Docker field {field} is invalid")
    return sorted(cast(list[str], value))


def _normalize_port_bindings(
    value: object, field: str, *, allow_empty_host_port: bool = False
) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise GuardError("invalid_docker_inventory", f"Docker field {field} is invalid")
    result: dict[str, object] = {}
    for raw_port, raw_bindings in value.items():
        if not isinstance(raw_port, str) or _PORT_KEY.fullmatch(raw_port) is None:
            raise GuardError("invalid_docker_inventory", f"Docker field {field} is invalid")
        if raw_bindings is None:
            result[raw_port] = None
            continue
        if not isinstance(raw_bindings, list):
            raise GuardError("invalid_docker_inventory", f"Docker field {field} is invalid")
        bindings: list[dict[str, str]] = []
        for raw_binding in raw_bindings:
            if not isinstance(raw_binding, dict):
                raise GuardError("invalid_docker_inventory", f"Docker field {field} is invalid")
            host_ip = _require_string(
                raw_binding.get("HostIp", ""), f"{field}.HostIp", allow_empty=True
            )
            host_port = _require_string(
                raw_binding.get("HostPort", ""),
                f"{field}.HostPort",
                allow_empty=allow_empty_host_port,
            )
            if host_port and (not host_port.isdecimal() or not 1 <= int(host_port) <= 65535):
                raise GuardError("invalid_docker_inventory", f"Docker field {field} is invalid")
            bindings.append({"host_ip": host_ip, "host_port": host_port})
        result[raw_port] = sorted(bindings, key=_canonical_bytes)
    return dict(sorted(result.items()))


def _normalize_mounts(value: object) -> list[dict[str, object]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise GuardError("invalid_docker_inventory", "Docker mounts are invalid")
    result: list[dict[str, object]] = []
    for raw_mount in value:
        if not isinstance(raw_mount, dict):
            raise GuardError("invalid_docker_inventory", "Docker mounts are invalid")
        result.append(
            {
                "type": _require_string(raw_mount.get("Type"), "mount.Type"),
                "name": _optional_string(raw_mount.get("Name"), "mount.Name"),
                "source": _require_string(
                    raw_mount.get("Source", ""), "mount.Source", allow_empty=True
                ),
                "destination": _require_string(raw_mount.get("Destination"), "mount.Destination"),
                "driver": _optional_string(raw_mount.get("Driver"), "mount.Driver"),
                "mode": _require_string(raw_mount.get("Mode", ""), "mount.Mode", allow_empty=True),
                "read_write": _require_bool(raw_mount.get("RW"), "mount.RW"),
                "propagation": _require_string(
                    raw_mount.get("Propagation", ""),
                    "mount.Propagation",
                    allow_empty=True,
                ),
            }
        )
    return sorted(result, key=_canonical_bytes)


def _normalize_ipam(value: object, field: str) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise GuardError("invalid_docker_inventory", f"Docker field {field} is invalid")
    return {
        "ipv4_address": _optional_string(value.get("IPv4Address"), f"{field}.IPv4"),
        "ipv6_address": _optional_string(value.get("IPv6Address"), f"{field}.IPv6"),
        "link_local_ips": _normalize_string_list(
            value.get("LinkLocalIPs"), f"{field}.LinkLocalIPs"
        ),
    }


def _normalize_networks(value: object) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise GuardError("invalid_docker_inventory", "Docker networks are invalid")
    result: dict[str, object] = {}
    for network_name, raw_network in value.items():
        if not isinstance(network_name, str) or not network_name:
            raise GuardError("invalid_docker_inventory", "Docker network name is invalid")
        if not isinstance(raw_network, dict):
            raise GuardError("invalid_docker_inventory", "Docker network is invalid")
        result[network_name] = {
            "network_id": _require_string(
                raw_network.get("NetworkID"), "network.NetworkID", allow_empty=True
            ),
            "endpoint_id": _require_string(
                raw_network.get("EndpointID"), "network.EndpointID", allow_empty=True
            ),
            "gateway": _require_string(
                raw_network.get("Gateway", ""), "network.Gateway", allow_empty=True
            ),
            "ip_address": _require_string(
                raw_network.get("IPAddress", ""),
                "network.IPAddress",
                allow_empty=True,
            ),
            "ip_prefix_length": _require_int(
                raw_network.get("IPPrefixLen", 0), "network.IPPrefixLen"
            ),
            "ipv6_gateway": _require_string(
                raw_network.get("IPv6Gateway", ""),
                "network.IPv6Gateway",
                allow_empty=True,
            ),
            "global_ipv6_address": _require_string(
                raw_network.get("GlobalIPv6Address", ""),
                "network.GlobalIPv6Address",
                allow_empty=True,
            ),
            "global_ipv6_prefix_length": _require_int(
                raw_network.get("GlobalIPv6PrefixLen", 0),
                "network.GlobalIPv6PrefixLen",
            ),
            "mac_address": _require_string(
                raw_network.get("MacAddress", ""),
                "network.MacAddress",
                allow_empty=True,
            ),
            "aliases": _normalize_string_list(raw_network.get("Aliases"), "network.Aliases"),
            "dns_names": _normalize_string_list(raw_network.get("DNSNames"), "network.DNSNames"),
            "links": _normalize_string_list(raw_network.get("Links"), "network.Links"),
            "ipam": _normalize_ipam(raw_network.get("IPAMConfig"), "network.IPAMConfig"),
        }
    return dict(sorted(result.items()))


def _normalize_restart_policy(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise GuardError("invalid_docker_inventory", "Docker restart policy is invalid")
    return {
        "name": _require_string(value.get("Name", ""), "restart_policy.Name", allow_empty=True),
        "maximum_retry_count": _require_int(
            value.get("MaximumRetryCount", 0), "restart_policy.MaximumRetryCount"
        ),
    }


def _normalize_container(raw: Mapping[str, object]) -> dict[str, object]:
    identifier = _require_string(raw.get("id"), "id")
    if _CONTAINER_ID.fullmatch(identifier) is None:
        raise GuardError("invalid_docker_inventory", "Docker container ID is invalid")
    image_id = _require_string(raw.get("image_id"), "image_id")
    if _IMAGE_ID.fullmatch(image_id) is None:
        raise GuardError("invalid_docker_inventory", "Docker image ID is invalid")
    raw_name = _require_string(raw.get("name"), "name")
    name = raw_name.removeprefix("/")
    if not name:
        raise GuardError("invalid_docker_inventory", "Docker container name is invalid")
    compose_project = _optional_string(raw.get("compose_project"), "compose_project")
    if compose_project is not None and _COMPOSE_PROJECT.fullmatch(compose_project) is None:
        raise GuardError("invalid_docker_inventory", "Docker compose project label is invalid")
    return {
        "id": identifier,
        "name": name,
        "compose_project": compose_project,
        "image_id": image_id,
        "image_ref": _require_string(raw.get("image_ref"), "image_ref"),
        "created_at": _require_string(raw.get("created_at"), "created_at"),
        "state": {
            "status": _require_string(raw.get("state_status"), "state_status"),
            "running": _require_bool(raw.get("state_running"), "state_running"),
            "paused": _require_bool(raw.get("state_paused"), "state_paused"),
            "restarting": _require_bool(raw.get("state_restarting"), "state_restarting"),
            "oom_killed": _require_bool(raw.get("state_oom_killed"), "state_oom_killed"),
            "dead": _require_bool(raw.get("state_dead"), "state_dead"),
            "started_at": _require_string(raw.get("started_at"), "started_at"),
            "finished_at": _require_string(raw.get("finished_at"), "finished_at"),
            "exit_code": _require_int(raw.get("exit_code"), "exit_code"),
            "restart_count": _require_int(raw.get("restart_count"), "restart_count"),
            "health": _optional_string(raw.get("health"), "health"),
        },
        "restart_policy": _normalize_restart_policy(raw.get("restart_policy")),
        "network_mode": _require_string(raw.get("network_mode"), "network_mode"),
        "configured_ports": _normalize_port_bindings(
            raw.get("configured_ports"),
            "configured_ports",
            allow_empty_host_port=True,
        ),
        "runtime_ports": _normalize_port_bindings(raw.get("runtime_ports"), "runtime_ports"),
        "mounts": _normalize_mounts(raw.get("mounts")),
        "networks": _normalize_networks(raw.get("networks")),
    }


def _project_is_excluded(project: str | None) -> bool:
    if project is None:
        return False
    return project in EXCLUDED_COMPOSE_PROJECTS or any(
        project.startswith(prefix) for prefix in EXCLUDED_COMPOSE_PROJECT_PREFIXES
    )


def _host_ports(container: Mapping[str, object]) -> set[int]:
    result: set[int] = set()
    for ports_key in ("configured_ports", "runtime_ports"):
        raw_ports = container.get(ports_key)
        if not isinstance(raw_ports, dict):
            continue
        for bindings in raw_ports.values():
            if not isinstance(bindings, list):
                continue
            for binding in bindings:
                if isinstance(binding, dict):
                    raw_host_port = binding.get("host_port")
                    if isinstance(raw_host_port, str) and raw_host_port.isdecimal():
                        result.add(int(raw_host_port))
    return result


def _parse_decimal(value: str, field: str, *, positive: bool = False) -> int:
    if not value.isdecimal():
        raise GuardError("invalid_host_state", f"Host field {field} is invalid")
    parsed = int(value)
    if positive and parsed <= 0:
        raise GuardError("invalid_host_state", f"Host field {field} is invalid")
    return parsed


def _read_virtual_text(path: Path, *, maximum_bytes: int = MAX_VIRTUAL_FILE_BYTES) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        file_fd = os.open(path, flags)
    except OSError as exc:
        raise GuardError("host_probe_failed", "Linux host state could not be read") from exc
    try:
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError as exc:
        raise GuardError("host_probe_failed", "Linux host state could not be read") from exc
    finally:
        os.close(file_fd)
    raw = b"".join(chunks)
    if len(raw) > maximum_bytes:
        raise GuardError("host_probe_failed", "Linux host state exceeds the size limit")
    try:
        return raw.decode("ascii")
    except UnicodeError as exc:
        raise GuardError("host_probe_failed", "Linux host state is not ASCII") from exc


def _process_start_ticks(pid: int) -> int:
    if pid <= 0:
        raise GuardError("invalid_host_state", "Process ID is invalid")
    raw = _read_virtual_text(Path(f"/proc/{pid}/stat"), maximum_bytes=16 * 1024).strip()
    closing_parenthesis = raw.rfind(")")
    if closing_parenthesis <= 0:
        raise GuardError("invalid_host_state", "Process stat record is malformed")
    raw_pid = raw[: raw.find(" ")]
    fields_after_name = raw[closing_parenthesis + 1 :].split()
    if raw_pid != str(pid) or len(fields_after_name) <= 19:
        raise GuardError("invalid_host_state", "Process stat record is malformed")
    return _parse_decimal(fields_after_name[19], "process.start_ticks", positive=True)


def _hash_file_descriptor(file_fd: int) -> str:
    digest = hashlib.sha256()
    try:
        os.lseek(file_fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    except OSError as exc:
        raise GuardError("host_probe_failed", "Protected executable hash failed") from exc
    return digest.hexdigest()


def _identity_from_open_file(
    file_fd: int,
    *,
    declared_path: str,
    resolved_path: Path,
    require_root_owner: bool,
) -> dict[str, object]:
    metadata = os.fstat(file_fd)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or (require_root_owner and metadata.st_uid != 0)
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise GuardError("unsafe_protected_file", "Protected executable or unit file is unsafe")
    try:
        resolved_metadata = resolved_path.stat()
    except OSError as exc:
        raise GuardError(
            "unsafe_protected_file", "Protected executable or unit file is unavailable"
        ) from exc
    if (metadata.st_dev, metadata.st_ino) != (
        resolved_metadata.st_dev,
        resolved_metadata.st_ino,
    ):
        raise GuardError("unstable_host_snapshot", "Protected file identity changed during capture")
    digest = _hash_file_descriptor(file_fd)
    after_metadata = os.fstat(file_fd)
    try:
        after_resolved_metadata = resolved_path.stat()
    except OSError as exc:
        raise GuardError("unstable_host_snapshot", "Protected file changed during capture") from exc
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(
        getattr(metadata, field) != getattr(after_metadata, field)
        or getattr(metadata, field) != getattr(after_resolved_metadata, field)
        for field in stable_fields
    ):
        raise GuardError("unstable_host_snapshot", "Protected file changed during capture")
    return {
        "declared_path": declared_path,
        "resolved_path": os.fspath(resolved_path),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "sha256": digest,
    }


def _regular_file_identity(path_value: str) -> dict[str, object]:
    if not path_value.startswith("/") or "\x00" in path_value:
        raise GuardError("invalid_host_state", "Systemd fragment path is invalid")
    declared = Path(path_value)
    try:
        resolved = declared.resolve(strict=True)
        file_fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise GuardError("unsafe_protected_file", "Systemd unit file is unavailable") from exc
    try:
        return _identity_from_open_file(
            file_fd,
            declared_path=path_value,
            resolved_path=resolved,
            require_root_owner=True,
        )
    finally:
        os.close(file_fd)


def _process_identity(pid: int) -> dict[str, object]:
    before_ticks = _process_start_ticks(pid)
    proc_executable = Path(f"/proc/{pid}/exe")
    try:
        declared_path = os.readlink(proc_executable)
        resolved_path = proc_executable.resolve(strict=True)
        file_fd = os.open(proc_executable, os.O_RDONLY)
    except OSError as exc:
        raise GuardError("host_probe_failed", "Protected process identity is unavailable") from exc
    try:
        executable = _identity_from_open_file(
            file_fd,
            declared_path=declared_path,
            resolved_path=resolved_path,
            require_root_owner=True,
        )
    finally:
        os.close(file_fd)
    after_ticks = _process_start_ticks(pid)
    if before_ticks != after_ticks:
        raise GuardError("unstable_host_snapshot", "Protected process changed during capture")
    return {"pid": pid, "start_ticks": before_ticks, "executable": executable}


def _unit_cgroup_pids(control_group: str) -> list[int]:
    if _CONTROL_GROUP.fullmatch(control_group) is None or ".." in control_group:
        raise GuardError("invalid_host_state", "Systemd control group path is invalid")
    relative = control_group.lstrip("/")
    candidates = (
        Path("/sys/fs/cgroup") / relative / "cgroup.procs",
        Path("/sys/fs/cgroup/systemd") / relative / "cgroup.procs",
    )
    last_error: GuardError | None = None
    for candidate in candidates:
        try:
            raw = _read_virtual_text(candidate, maximum_bytes=1024 * 1024)
        except GuardError as exc:
            last_error = exc
            continue
        pids: list[int] = []
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped:
                pids.append(_parse_decimal(stripped, "cgroup.pid", positive=True))
        if len(pids) != len(set(pids)):
            raise GuardError("invalid_host_state", "Systemd control group PID list is invalid")
        return sorted(pids)
    raise GuardError(
        "host_probe_failed", "Systemd control group membership is unavailable"
    ) from last_error


def _socket_inodes_for_pid(pid: int) -> set[int]:
    directory = Path(f"/proc/{pid}/fd")
    result: set[int] = set()
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if not entry.name.isdecimal():
                    continue
                try:
                    link = os.readlink(entry.path)
                except FileNotFoundError:
                    continue
                match = _SOCKET_LINK.fullmatch(link)
                if match is not None:
                    result.add(int(match.group(1)))
    except OSError as exc:
        raise GuardError("host_probe_failed", "Protected process sockets are unavailable") from exc
    return result


def _decode_proc_address(encoded: str, family: str) -> str:
    try:
        raw = bytes.fromhex(encoded)
        if family == "ipv4" and len(raw) == 4:
            return str(ipaddress.IPv4Address(raw[::-1]))
        if family == "ipv6" and len(raw) == 16:
            reordered = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
            return str(ipaddress.IPv6Address(reordered))
    except ValueError as exc:
        raise GuardError("invalid_host_state", "TCP listener address is malformed") from exc
    raise GuardError("invalid_host_state", "TCP listener address is malformed")


def _parse_proc_tcp(raw: str, *, family: str, required_port: int) -> list[dict[str, object]]:
    if family not in {"ipv4", "ipv6"}:
        raise GuardError("invalid_host_state", "TCP listener family is invalid")
    listeners: list[dict[str, object]] = []
    for line in raw.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            if line.strip():
                raise GuardError("invalid_host_state", "TCP listener table is malformed")
            continue
        address_hex, separator, port_hex = fields[1].partition(":")
        if not separator:
            raise GuardError("invalid_host_state", "TCP listener table is malformed")
        try:
            local_port = int(port_hex, 16)
        except ValueError as exc:
            raise GuardError("invalid_host_state", "TCP listener port is malformed") from exc
        if fields[3] != "0A" or local_port != required_port:
            continue
        uid = _parse_decimal(fields[7], "listener.uid")
        socket_inode = _parse_decimal(fields[9], "listener.inode", positive=True)
        listeners.append(
            {
                "family": family,
                "local_address": _decode_proc_address(address_hex, family),
                "local_port": local_port,
                "state": "LISTEN",
                "uid": uid,
                "socket_inode": socket_inode,
            }
        )
    return sorted(listeners, key=_canonical_bytes)


def _tcp_listeners(required_port: int) -> list[dict[str, object]]:
    if not 1 <= required_port <= 65535:
        raise GuardError("invalid_host_state", "Required TCP port is invalid")
    listeners = _parse_proc_tcp(
        _read_virtual_text(Path("/proc/net/tcp")),
        family="ipv4",
        required_port=required_port,
    )
    listeners.extend(
        _parse_proc_tcp(
            _read_virtual_text(Path("/proc/net/tcp6")),
            family="ipv6",
            required_port=required_port,
        )
    )
    return sorted(listeners, key=_canonical_bytes)


def _systemd_service_snapshot(unit: str) -> dict[str, object]:
    before = _systemctl_show(unit)
    main_pid = _parse_decimal(before["MainPID"], "systemd.MainPID")
    exec_main_pid = _parse_decimal(before["ExecMainPID"], "systemd.ExecMainPID")
    restart_count = _parse_decimal(before["NRestarts"], "systemd.NRestarts")
    active_enter = _parse_decimal(
        before["ActiveEnterTimestampMonotonic"], "systemd.ActiveEnterTimestampMonotonic"
    )
    exec_start = _parse_decimal(
        before["ExecMainStartTimestampMonotonic"],
        "systemd.ExecMainStartTimestampMonotonic",
    )
    dynamic_user_value = before["DynamicUser"]
    if dynamic_user_value not in {"yes", "no"}:
        raise GuardError("invalid_host_state", "Systemd DynamicUser state is invalid")
    fragment = _regular_file_identity(before["FragmentPath"]) if before["FragmentPath"] else None
    control_group = before["ControlGroup"]
    pids = _unit_cgroup_pids(control_group) if control_group else []
    if main_pid > 0 and main_pid not in pids:
        raise GuardError(
            "invalid_host_state", "Systemd MainPID is outside the protected control group"
        )
    processes = [_process_identity(pid) for pid in pids]
    after = _systemctl_show(unit)
    after_pids = _unit_cgroup_pids(control_group) if control_group else []
    if before != after or pids != after_pids:
        raise GuardError("unstable_host_snapshot", "Systemd unit changed during host capture")
    for process in processes:
        pid = cast(int, process["pid"])
        if _process_start_ticks(pid) != process["start_ticks"]:
            raise GuardError(
                "unstable_host_snapshot", "Protected process changed during host capture"
            )
    invocation_id = before["InvocationID"]
    if invocation_id and _SYSTEMD_INVOCATION_ID.fullmatch(invocation_id) is None:
        raise GuardError("invalid_host_state", "Systemd invocation identity is invalid")
    return {
        "unit": before["Id"],
        "load_state": before["LoadState"],
        "active_state": before["ActiveState"],
        "sub_state": before["SubState"],
        "unit_file_state": before["UnitFileState"],
        "fragment": fragment,
        "main_pid": main_pid,
        "exec_main_pid": exec_main_pid,
        "restart_count": restart_count,
        "invocation_id": invocation_id,
        "control_group": control_group,
        "user": before["User"],
        "group": before["Group"],
        "dynamic_user": dynamic_user_value == "yes",
        "active_enter_timestamp_monotonic": active_enter,
        "exec_main_start_timestamp_monotonic": exec_start,
        "processes": processes,
    }


def _assert_service_still_matches(service: Mapping[str, object]) -> None:
    unit = cast(str, service["unit"])
    current = _systemctl_show(unit)
    fragment = service["fragment"]
    declared_fragment = cast(str, fragment["declared_path"]) if isinstance(fragment, dict) else ""
    expected = {
        "Id": unit,
        "LoadState": cast(str, service["load_state"]),
        "ActiveState": cast(str, service["active_state"]),
        "SubState": cast(str, service["sub_state"]),
        "UnitFileState": cast(str, service["unit_file_state"]),
        "FragmentPath": declared_fragment,
        "MainPID": str(cast(int, service["main_pid"])),
        "ExecMainPID": str(cast(int, service["exec_main_pid"])),
        "NRestarts": str(cast(int, service["restart_count"])),
        "InvocationID": cast(str, service["invocation_id"]),
        "ControlGroup": cast(str, service["control_group"]),
        "User": cast(str, service["user"]),
        "Group": cast(str, service["group"]),
        "DynamicUser": "yes" if service["dynamic_user"] is True else "no",
        "ActiveEnterTimestampMonotonic": str(
            cast(int, service["active_enter_timestamp_monotonic"])
        ),
        "ExecMainStartTimestampMonotonic": str(
            cast(int, service["exec_main_start_timestamp_monotonic"])
        ),
    }
    if current != expected:
        raise GuardError("unstable_host_snapshot", "Systemd unit changed during host capture")
    processes = cast(list[dict[str, object]], service["processes"])
    expected_pids = sorted(cast(int, process["pid"]) for process in processes)
    control_group = cast(str, service["control_group"])
    current_pids = _unit_cgroup_pids(control_group) if control_group else []
    if current_pids != expected_pids:
        raise GuardError("unstable_host_snapshot", "Systemd cgroup changed during host capture")
    for process in processes:
        pid = cast(int, process["pid"])
        if _process_start_ticks(pid) != process["start_ticks"]:
            raise GuardError(
                "unstable_host_snapshot", "Protected process changed during host capture"
            )


def _owned_tcp_listeners(
    processes: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    socket_owners: dict[int, list[int]] = {}
    for process in processes:
        pid = cast(int, process["pid"])
        for socket_inode in _socket_inodes_for_pid(pid):
            socket_owners.setdefault(socket_inode, []).append(pid)
    listeners: list[dict[str, object]] = []
    for listener in _tcp_listeners(REQUIRED_HOST_PORTS[0]):
        inode = cast(int, listener["socket_inode"])
        owners = sorted(set(socket_owners.get(inode, [])))
        listeners.append(
            {
                **listener,
                "owner_unit": REQUIRED_SYSTEMD_UNIT if owners else None,
                "owner_pids": owners,
            }
        )
    return sorted(listeners, key=_canonical_bytes)


def _collect_required_host_resources(enforce_required: bool) -> dict[str, object]:
    service = _systemd_service_snapshot(REQUIRED_SYSTEMD_UNIT)
    processes = cast(list[dict[str, object]], service["processes"])
    listeners = _owned_tcp_listeners(processes)
    service_ready = bool(
        service["unit"] == REQUIRED_SYSTEMD_UNIT
        and service["load_state"] == "loaded"
        and service["active_state"] == "active"
        and service["sub_state"] == "running"
        and service["unit_file_state"] in {"enabled", "enabled-runtime"}
        and cast(int, service["main_pid"]) > 0
        and service["fragment"] is not None
        and processes
        and _SYSTEMD_INVOCATION_ID.fullmatch(cast(str, service["invocation_id"])) is not None
    )
    listeners_ready = bool(
        listeners
        and all(
            listener["owner_unit"] == REQUIRED_SYSTEMD_UNIT
            and cast(list[int], listener["owner_pids"])
            for listener in listeners
        )
    )
    _assert_service_still_matches(service)
    if listeners != _owned_tcp_listeners(processes):
        raise GuardError("unstable_host_snapshot", "TCP listener changed during host capture")
    if enforce_required and not service_ready:
        raise GuardError(
            "required_service_unprotected",
            "required zabbix-agent systemd service is not protected",
        )
    if enforce_required and not listeners_ready:
        raise GuardError(
            "required_port_unprotected",
            "required TCP port 10050 is not owned by zabbix-agent.service",
        )
    return {
        "systemd_services": [service],
        "tcp_listeners": listeners,
        "requirements_satisfied": service_ready and listeners_ready,
    }


def _require_exact_keys(value: object, expected: set[str], *, field: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise GuardError("invalid_host_state", f"Protected host field {field} is malformed")
    return cast(dict[str, object], value)


def _validate_host_resource_shape(host_resources: Mapping[str, object]) -> None:
    if set(host_resources) != {
        "systemd_services",
        "tcp_listeners",
        "requirements_satisfied",
    }:
        raise GuardError("invalid_host_state", "Protected host resource snapshot is malformed")
    services = host_resources.get("systemd_services")
    listeners = host_resources.get("tcp_listeners")
    if (
        not isinstance(services, list)
        or len(services) != 1
        or not isinstance(listeners, list)
        or not isinstance(host_resources.get("requirements_satisfied"), bool)
    ):
        raise GuardError("invalid_host_state", "Protected host resource snapshot is malformed")
    service_keys = {
        "unit",
        "load_state",
        "active_state",
        "sub_state",
        "unit_file_state",
        "fragment",
        "main_pid",
        "exec_main_pid",
        "restart_count",
        "invocation_id",
        "control_group",
        "user",
        "group",
        "dynamic_user",
        "active_enter_timestamp_monotonic",
        "exec_main_start_timestamp_monotonic",
        "processes",
    }
    file_keys = {
        "declared_path",
        "resolved_path",
        "device",
        "inode",
        "size",
        "mtime_ns",
        "ctime_ns",
        "uid",
        "gid",
        "mode",
        "sha256",
    }
    service = _require_exact_keys(services[0], service_keys, field="systemd_service")
    if service["unit"] != REQUIRED_SYSTEMD_UNIT:
        raise GuardError("invalid_host_state", "Protected systemd unit identity is invalid")
    fragment = service["fragment"]
    if fragment is not None:
        _require_exact_keys(fragment, file_keys, field="systemd_fragment")
    processes = service["processes"]
    if not isinstance(processes, list):
        raise GuardError("invalid_host_state", "Protected process list is malformed")
    for process_value in processes:
        process = _require_exact_keys(
            process_value,
            {"pid", "start_ticks", "executable"},
            field="systemd_process",
        )
        _require_exact_keys(process["executable"], file_keys, field="process_executable")
    listener_keys = {
        "family",
        "local_address",
        "local_port",
        "state",
        "uid",
        "socket_inode",
        "owner_unit",
        "owner_pids",
    }
    for listener in listeners:
        normalized_listener = _require_exact_keys(listener, listener_keys, field="tcp_listener")
        if (
            normalized_listener["local_port"] != REQUIRED_HOST_PORTS[0]
            or normalized_listener["state"] != "LISTEN"
            or normalized_listener["owner_unit"] not in {None, REQUIRED_SYSTEMD_UNIT}
        ):
            raise GuardError("invalid_host_state", "Protected TCP listener is invalid")


def _policy() -> dict[str, object]:
    return {
        "excluded_compose_projects": list(EXCLUDED_COMPOSE_PROJECTS),
        "excluded_compose_project_prefixes": list(EXCLUDED_COMPOSE_PROJECT_PREFIXES),
        "required_protected_host_ports": list(REQUIRED_HOST_PORTS),
        "required_systemd_units": [REQUIRED_SYSTEMD_UNIT],
        "required_tcp_listeners": [
            {
                "protocol": "tcp",
                "port": REQUIRED_HOST_PORTS[0],
                "owner_unit": REQUIRED_SYSTEMD_UNIT,
            }
        ],
        "process_identity_comparison": "exact",
        "service_restart_tolerance": "none",
        "comparison": "exact",
    }


def collect_snapshot(
    runner: DockerRunner = _system_docker_runner,
    host_probe: HostProbe = _collect_required_host_resources,
    *,
    captured_at: str | None = None,
    integrity_key: bytes | None = None,
    enforce_required_resources: bool = True,
) -> dict[str, object]:
    info = _parse_json_object(
        runner(("info", "--format", DOCKER_INFO_TEMPLATE)).strip(), source="docker info"
    )
    docker_host = {
        "daemon_id": _require_string(info.get("daemon_id"), "daemon_id"),
        "daemon_name": _require_string(info.get("daemon_name"), "daemon_name"),
        "server_version": _require_string(info.get("server_version"), "server_version"),
        "operating_system": _require_string(info.get("operating_system"), "operating_system"),
        "architecture": _require_string(info.get("architecture"), "architecture"),
    }
    raw_ids = runner(("container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}"))
    identifiers = sorted({line.strip() for line in raw_ids.splitlines() if line.strip()})
    if any(_CONTAINER_ID.fullmatch(identifier) is None for identifier in identifiers):
        raise GuardError("invalid_docker_inventory", "Docker returned an invalid container ID")
    protected: list[dict[str, object]] = []
    if identifiers:
        inspect_output = runner(
            ("container", "inspect", "--format", CONTAINER_INSPECT_TEMPLATE, *identifiers)
        )
        lines = [line for line in inspect_output.splitlines() if line.strip()]
        if len(lines) != len(identifiers):
            raise GuardError(
                "incomplete_docker_inventory", "Docker did not inspect every container"
            )
        for line in lines:
            raw_container = _parse_json_object(line, source="docker container inspect")
            container = _normalize_container(raw_container)
            project = cast(str | None, container["compose_project"])
            if not _project_is_excluded(project):
                protected.append(container)
    protected.sort(key=lambda item: cast(str, item["name"]))
    names = [cast(str, item["name"]) for item in protected]
    ids = [cast(str, item["id"]) for item in protected]
    if len(names) != len(set(names)) or len(ids) != len(set(ids)):
        raise GuardError("invalid_docker_inventory", "Docker container identity is duplicated")
    image_ids = sorted({cast(str, item["image_id"]) for item in protected})
    if image_ids:
        image_output = runner(("image", "inspect", "--format", "{{json .Id}}", *image_ids))
        inspected_image_ids: set[str] = set()
        for line in image_output.splitlines():
            if not line.strip():
                continue
            try:
                image_id = json.loads(line)
            except json.JSONDecodeError as exc:
                raise GuardError(
                    "invalid_docker_inventory", "Docker image identity is invalid"
                ) from exc
            if not isinstance(image_id, str) or _IMAGE_ID.fullmatch(image_id) is None:
                raise GuardError("invalid_docker_inventory", "Docker image identity is invalid")
            inspected_image_ids.add(image_id)
        if inspected_image_ids != set(image_ids):
            raise GuardError(
                "incomplete_docker_inventory", "A protected container image is unavailable"
            )
    host_resources = host_probe(enforce_required_resources)
    _validate_host_resource_shape(host_resources)
    services = host_resources.get("systemd_services")
    listeners = host_resources.get("tcp_listeners")
    requirements_satisfied = host_resources.get("requirements_satisfied")
    if (
        not isinstance(services, list)
        or not isinstance(listeners, list)
        or not isinstance(requirements_satisfied, bool)
    ):
        raise GuardError("invalid_host_state", "Protected host resource snapshot is malformed")
    required_port_owners: dict[str, object] = {}
    for port in REQUIRED_HOST_PORTS:
        docker_owners = sorted(
            cast(str, container["name"])
            for container in protected
            if port in _host_ports(container)
        )
        systemd_owners = sorted(
            {
                cast(str, listener["owner_unit"])
                for listener in listeners
                if isinstance(listener, dict)
                and listener.get("local_port") == port
                and isinstance(listener.get("owner_unit"), str)
            }
        )
        if enforce_required_resources and (
            not requirements_satisfied or REQUIRED_SYSTEMD_UNIT not in systemd_owners
        ):
            raise GuardError(
                "required_port_unprotected",
                f"required host port {port} has no protected systemd owner",
            )
        required_port_owners[str(port)] = {
            "docker_containers": docker_owners,
            "systemd_units": systemd_owners,
        }
    document: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "evidence_type": "host_isolation_snapshot",
        "status": "CAPTURED",
        "captured_at": captured_at or _utc_now(),
        "policy": _policy(),
        "docker_host": docker_host,
        "protected_containers": protected,
        "protected_image_ids": image_ids,
        "protected_host_resources": host_resources,
        "required_port_owners": required_port_owners,
    }
    return attach_integrity(document, integrity_key)


def _validate_baseline(document: Mapping[str, object], key: bytes | None) -> None:
    verify_integrity(document, key)
    if document.get("schema_version") != SCHEMA_VERSION:
        raise GuardError("unsupported_schema", "baseline schema version is unsupported")
    if document.get("evidence_type") != "host_isolation_snapshot":
        raise GuardError("invalid_baseline", "baseline evidence type is invalid")
    if document.get("status") != "CAPTURED":
        raise GuardError("invalid_baseline", "baseline was not captured successfully")
    if document.get("policy") != _policy():
        raise GuardError("invalid_policy", "baseline isolation policy is not approved")
    if not isinstance(document.get("docker_host"), dict):
        raise GuardError("invalid_baseline", "baseline Docker host is missing")
    if not isinstance(document.get("protected_containers"), list):
        raise GuardError("invalid_baseline", "baseline container inventory is missing")
    if not isinstance(document.get("protected_image_ids"), list):
        raise GuardError("invalid_baseline", "baseline image inventory is missing")
    if not isinstance(document.get("protected_host_resources"), dict):
        raise GuardError("invalid_baseline", "baseline host resource inventory is missing")
    if not isinstance(document.get("required_port_owners"), dict):
        raise GuardError("invalid_baseline", "baseline port ownership is missing")


def _comparison_projection(document: Mapping[str, object]) -> dict[str, object]:
    return {
        "policy": document.get("policy"),
        "docker_host": document.get("docker_host"),
        "protected_containers": document.get("protected_containers"),
        "protected_image_ids": document.get("protected_image_ids"),
        "protected_host_resources": document.get("protected_host_resources"),
        "required_port_owners": document.get("required_port_owners"),
    }


def _diff_hashes(before: object, after: object, *, path: str = "$") -> list[dict[str, str | None]]:
    if isinstance(before, dict) and isinstance(after, dict):
        changes: list[dict[str, str | None]] = []
        for key in sorted(set(before) | set(after)):
            child_path = f"{path}.{key}"
            if key not in before:
                changes.append(
                    {
                        "path": child_path,
                        "change": "added",
                        "before_sha256": None,
                        "after_sha256": _sha256(after[key]),
                    }
                )
            elif key not in after:
                changes.append(
                    {
                        "path": child_path,
                        "change": "removed",
                        "before_sha256": _sha256(before[key]),
                        "after_sha256": None,
                    }
                )
            else:
                changes.extend(_diff_hashes(before[key], after[key], path=child_path))
        return changes
    if isinstance(before, list) and isinstance(after, list):
        changes = []
        for index in range(max(len(before), len(after))):
            child_path = f"{path}[{index}]"
            if index >= len(before):
                changes.append(
                    {
                        "path": child_path,
                        "change": "added",
                        "before_sha256": None,
                        "after_sha256": _sha256(after[index]),
                    }
                )
            elif index >= len(after):
                changes.append(
                    {
                        "path": child_path,
                        "change": "removed",
                        "before_sha256": _sha256(before[index]),
                        "after_sha256": None,
                    }
                )
            else:
                changes.extend(_diff_hashes(before[index], after[index], path=child_path))
        return changes
    if before == after and type(before) is type(after):
        return []
    return [
        {
            "path": path,
            "change": "changed",
            "before_sha256": _sha256(before),
            "after_sha256": _sha256(after),
        }
    ]


def verify_against_baseline(
    baseline: Mapping[str, object],
    runner: DockerRunner = _system_docker_runner,
    host_probe: HostProbe = _collect_required_host_resources,
    *,
    verified_at: str | None = None,
    integrity_key: bytes | None = None,
) -> dict[str, object]:
    _validate_baseline(baseline, integrity_key)
    current = collect_snapshot(
        runner,
        host_probe,
        captured_at=verified_at or _utc_now(),
        integrity_key=integrity_key,
        enforce_required_resources=False,
    )
    before = _comparison_projection(baseline)
    after = _comparison_projection(current)
    changes = _diff_hashes(before, after)
    status = "PASS" if not changes else "FAIL"
    baseline_integrity = baseline["integrity"]
    current_integrity = current["integrity"]
    if not isinstance(baseline_integrity, dict) or not isinstance(current_integrity, dict):
        raise GuardError("invalid_integrity", "snapshot integrity metadata is missing")
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "evidence_type": "host_isolation_verification",
        "status": status,
        "verified_at": verified_at or _utc_now(),
        "baseline_captured_at": baseline.get("captured_at"),
        "baseline_digest": baseline_integrity.get("digest"),
        "current_snapshot_digest": current_integrity.get("digest"),
        "policy": _policy(),
        "protected_container_count": len(cast(list[object], current["protected_containers"])),
        "change_count": len(changes),
        "changes": changes,
        "current_snapshot": current,
    }
    return attach_integrity(report, integrity_key)


def _write_if_requested(path: Path | None, document: Mapping[str, object]) -> None:
    if path is not None:
        safe_write_json(path, document)


def _print_json(document: Mapping[str, object], *, stream: Any = sys.stdout) -> None:
    print(
        json.dumps(document, allow_nan=False, ensure_ascii=False, sort_keys=True),
        file=stream,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = JsonArgumentParser(
        description="Protect non-project Docker resources during an offline deployment"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    snapshot = subparsers.add_parser("snapshot", help="capture the pre-deployment baseline")
    snapshot.add_argument("--output", type=Path)
    snapshot.add_argument("--hmac-key-file", type=Path)
    verify = subparsers.add_parser("verify", help="compare the host with a baseline")
    verify.add_argument("--baseline", required=True, type=Path)
    verify.add_argument("--output", type=Path)
    verify.add_argument("--hmac-key-file", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _build_parser().parse_args(argv)
        key = load_hmac_key(arguments.hmac_key_file)
        if arguments.command == "snapshot":
            document = collect_snapshot(integrity_key=key)
            _write_if_requested(arguments.output, document)
            _print_json(document)
            return 0
        baseline = load_json_evidence(arguments.baseline)
        report = verify_against_baseline(baseline, integrity_key=key)
        _write_if_requested(arguments.output, report)
        _print_json(report)
        return 0 if report["status"] == "PASS" else 1
    except GuardError as exc:
        _print_json(
            {
                "schema_version": SCHEMA_VERSION,
                "evidence_type": "host_isolation_error",
                "status": "BLOCKED",
                "code": exc.code,
                "message": str(exc),
            },
            stream=sys.stderr,
        )
        return 2
    except Exception:
        _print_json(
            {
                "schema_version": SCHEMA_VERSION,
                "evidence_type": "host_isolation_error",
                "status": "BLOCKED",
                "code": "internal_error",
                "message": "host isolation verification failed closed",
            },
            stream=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
