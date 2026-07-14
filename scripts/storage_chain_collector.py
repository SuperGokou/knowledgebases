from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import stat
import sys
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import urlsplit

import httpx

from scripts.acceptance import collect_worktree_evidence

PRODUCER = "heyi-storage-watermark-harness"
PRODUCER_VERSION = "2.0.0"
MARKER_NAME = ".kb-acceptance-destroyable-volume"
MAX_TOPOLOGY_BYTES = 128 * 1024
MAX_SECRET_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
DECIMAL_GB = 1_000_000_000
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_GIT_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
_CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
_SENSITIVE_KEYS = {
    "authorization",
    "access_token",
    "refresh_token",
    "secret_key",
    "password",
    "presigned_url",
    "upload_url",
}


class CollectionBlocked(RuntimeError):
    """The target or its dependencies cannot safely produce acceptance evidence."""


class CollectionFailed(RuntimeError):
    """The real target executed but violated the required storage behavior."""


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    scenario_id: str
    watermark_percent: int
    operation: str
    expected_reason_code: str | None


def build_execution_plan() -> tuple[ScenarioSpec, ...]:
    scenarios: list[ScenarioSpec] = []
    for percent in (69, 70, 79, 80, 89, 90):
        for operation in ("single", "multipart", "retry", "concurrent_reservation"):
            expected_reason: str | None = None
            if percent >= 90:
                expected_reason = "storage_capacity_critical"
            elif percent >= 80 and operation != "single":
                expected_reason = "storage_bulk_uploads_paused"
            scenarios.append(
                ScenarioSpec(
                    scenario_id=f"wm-{percent}-{operation.replace('_', '-')}",
                    watermark_percent=percent,
                    operation=operation,
                    expected_reason_code=expected_reason,
                )
            )
    scenarios.append(
        ScenarioSpec(
            scenario_id="object-stop-180gb",
            watermark_percent=1,
            operation="object_stop_180gb",
            expected_reason_code="object_storage_stop_line_reached",
        )
    )
    return tuple(scenarios)


SCENARIO_PLAN = build_execution_plan()


@dataclass(frozen=True, slots=True)
class CollectionContext:
    challenge: str
    volume_id: str
    mount_target: str
    object_root: str
    knowledge_base_id: str
    api_url: str
    deployment_id: str
    git_head: str
    content_fingerprint: str
    output_directory: Path


@dataclass(frozen=True, slots=True)
class RealTopology:
    api_url: str
    control_url: str
    volume_id: str
    mount_target: Path
    object_root: Path
    knowledge_base_id: str
    deployment_id: str
    repository: Path
    token_file: Path
    ca_bundle: Path | None


class StorageChainTransport(Protocol):
    collector_mode: str

    def open(self, context: CollectionContext) -> dict[str, object]: ...

    def execute(self, context: CollectionContext, scenario: ScenarioSpec) -> dict[str, object]: ...

    def cleanup(self, context: CollectionContext) -> dict[str, object]: ...

    def close(self) -> None: ...


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_atomic(path: Path, value: object) -> None:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise


def _prepare_output_directory(path: Path) -> Path:
    if path.is_symlink():
        raise CollectionBlocked("evidence output directory must not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = path.resolve(strict=True)
    with os.scandir(resolved) as entries:
        if next(entries, None) is not None:
            raise CollectionBlocked("evidence output directory must be empty")
    (resolved / "raw").mkdir(mode=0o700)
    return resolved


def _mapping(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CollectionBlocked(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _integer(mapping: dict[str, object], key: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CollectionBlocked(f"real storage probe returned invalid {key}")
    return value


def _assert_no_sensitive_material(value: object, *, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).casefold()
            if normalized in _SENSITIVE_KEYS or "x-amz-signature" in normalized:
                raise CollectionBlocked(f"sensitive field is forbidden in {path}")
            _assert_no_sensitive_material(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_sensitive_material(item, path=f"{path}[{index}]")
    elif isinstance(value, str) and "x-amz-signature=" in value.casefold():
        raise CollectionBlocked(f"presigned credentials are forbidden in {path}")


def _validate_session(context: CollectionContext, session: dict[str, object]) -> str:
    expected: dict[str, object] = {
        "challenge": context.challenge,
        "volume_id": context.volume_id,
        "mount_target": context.mount_target,
        "object_root": context.object_root,
        "knowledge_base_id": context.knowledge_base_id,
        "api_url": context.api_url,
        "deployment_id": context.deployment_id,
        "object_store": "minio",
        "destructive_volume": True,
        "collector_mode": "real",
    }
    if any(session.get(key) != value for key, value in expected.items()):
        raise CollectionBlocked("acceptance controller target identity did not match the request")
    session_id = session.get("session_id")
    if not isinstance(session_id, str) or not 8 <= len(session_id) <= 200:
        raise CollectionBlocked("acceptance controller did not return a bounded session identity")
    _assert_no_sensitive_material(session, path="session")
    return session_id


def _validate_probe_result(
    context: CollectionContext,
    spec: ScenarioSpec,
    result: dict[str, object],
) -> dict[str, object]:
    _assert_no_sensitive_material(result)
    scenario = _mapping(result.get("scenario"), label="scenario result")
    filesystem = _mapping(result.get("filesystem_probe"), label="filesystem probe")
    minio = _mapping(result.get("minio_probe"), label="MinIO probe")
    quota = _mapping(result.get("quota_probe"), label="quota probe")
    api = _mapping(result.get("business_api_probe"), label="business API probe")
    if (
        scenario.get("watermark_percent") != spec.watermark_percent
        or scenario.get("operation") != spec.operation
        or filesystem.get("used_percent") != spec.watermark_percent
        or filesystem.get("mount_target") != context.mount_target
        or filesystem.get("volume_id") != context.volume_id
        or minio.get("backend") != "minio"
        or quota.get("knowledge_base_id") != context.knowledge_base_id
        or api.get("api_url") != context.api_url
        or api.get("operation") != spec.operation
    ):
        raise CollectionBlocked("scenario probes are not bound to the requested target identity")
    total_bytes = _integer(filesystem, "total_bytes")
    if total_bytes <= 0:
        raise CollectionBlocked("filesystem probe did not report a real target volume")
    request_ids = api.get("request_ids")
    if (
        not isinstance(request_ids, list)
        or not request_ids
        or not all(isinstance(item, str) and 8 <= len(item) <= 200 for item in request_ids)
    ):
        raise CollectionBlocked("business API request trace is incomplete")
    request_count = _integer(api, "request_count")
    if request_count <= 0:
        raise CollectionBlocked("business API was not exercised")
    if spec.operation in {"retry", "concurrent_reservation"} and request_count < 2:
        raise CollectionFailed(f"{spec.operation} did not exercise multiple real HTTP requests")

    http_status = _integer(scenario, "http_status")
    api_status = _integer(api, "http_status")
    reason = scenario.get("reason_code")
    api_reason = api.get("reason_code")
    if http_status != api_status or reason != api_reason:
        raise CollectionBlocked("business API trace and scenario result disagree")
    fields = {
        "watermark_percent": spec.watermark_percent,
        "operation": spec.operation,
        "http_status": http_status,
        "reason_code": reason,
        "quota_before_bytes": _integer(scenario, "quota_before_bytes"),
        "quota_after_bytes": _integer(scenario, "quota_after_bytes"),
        "object_count_before": _integer(scenario, "object_count_before"),
        "object_count_after": _integer(scenario, "object_count_after"),
        "object_bytes_before": _integer(scenario, "object_bytes_before"),
        "object_bytes_after": _integer(scenario, "object_bytes_after"),
        "multipart_sessions_before": _integer(scenario, "multipart_sessions_before"),
        "multipart_sessions_after": _integer(scenario, "multipart_sessions_after"),
    }
    if (
        minio.get("object_count") != fields["object_count_after"]
        or minio.get("object_bytes") != fields["object_bytes_after"]
        or minio.get("multipart_sessions") != fields["multipart_sessions_after"]
        or quota.get("reserved_bytes") != fields["quota_after_bytes"]
    ):
        raise CollectionBlocked("filesystem, MinIO, quota, and scenario probes did not cross-check")
    allowed = spec.expected_reason_code is None
    if allowed:
        quota_before = cast(int, fields["quota_before_bytes"])
        quota_after = cast(int, fields["quota_after_bytes"])
        object_count_before = cast(int, fields["object_count_before"])
        object_count_after = cast(int, fields["object_count_after"])
        object_bytes_before = cast(int, fields["object_bytes_before"])
        object_bytes_after = cast(int, fields["object_bytes_after"])
        multipart_before = cast(int, fields["multipart_sessions_before"])
        multipart_after = cast(int, fields["multipart_sessions_after"])
        if not (
            200 <= http_status < 300
            and reason is None
            and quota_after > quota_before
            and object_count_after == object_count_before + 1
            and object_bytes_after > object_bytes_before
            and multipart_after == multipart_before
            and _integer(api, "object_storage_requests") > 0
        ):
            raise CollectionFailed(f"allowed scenario {spec.scenario_id} did not complete cleanly")
    else:
        no_side_effects = all(
            fields[after] == fields[before]
            for before, after in (
                ("quota_before_bytes", "quota_after_bytes"),
                ("object_count_before", "object_count_after"),
                ("object_bytes_before", "object_bytes_after"),
                ("multipart_sessions_before", "multipart_sessions_after"),
            )
        )
        if not (
            http_status >= 400
            and reason == spec.expected_reason_code
            and no_side_effects
            and _integer(api, "object_storage_requests") == 0
        ):
            raise CollectionFailed(f"rejected scenario {spec.scenario_id} leaked state")
    if spec.operation == "object_stop_180gb" and fields["object_bytes_before"] != 179 * DECIMAL_GB:
        raise CollectionFailed("object stop-line scenario did not begin at 179 GB")
    return fields


def _validate_cleanup(context: CollectionContext, raw: dict[str, object]) -> None:
    _assert_no_sensitive_material(raw, path="cleanup")
    if raw.get("challenge") != context.challenge or raw.get("volume_id") != context.volume_id:
        raise CollectionBlocked("cleanup proof is not bound to this challenge and volume")
    if raw.get("completed") is not True:
        raise CollectionBlocked("dedicated acceptance volume cleanup did not complete")
    for key in (
        "objects_remaining",
        "object_bytes_remaining",
        "multipart_sessions_remaining",
        "quota_reservations_remaining",
        "test_records_remaining",
    ):
        if _integer(raw, key) != 0:
            raise CollectionBlocked("dedicated acceptance volume cleanup left residual state")


def _attestation_payload(manifest: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": manifest["schema_version"],
        "producer": manifest["producer"],
        "producer_version": manifest["producer_version"],
        "collector_mode": manifest["collector_mode"],
        "challenge": manifest["challenge"],
        "target": manifest["target"],
        "volume_id": manifest["volume_id"],
        "mount_target": manifest["mount_target"],
        "object_root": manifest["object_root"],
        "knowledge_base_id": manifest["knowledge_base_id"],
        "started_at": manifest["started_at"],
        "finished_at": manifest["finished_at"],
        "artifacts": [
            {
                "artifact": item["artifact"],
                "sha256": item["artifact_sha256"],
            }
            for item in cast(list[dict[str, object]], manifest["scenarios"])
        ]
        + [
            {
                "artifact": cast(dict[str, object], manifest["cleanup"])["artifact"],
                "sha256": cast(dict[str, object], manifest["cleanup"])["artifact_sha256"],
            }
        ],
    }


def collect_chain(
    context: CollectionContext,
    transport: StorageChainTransport,
    *,
    allow_test_transport: bool = False,
) -> dict[str, object]:
    if not allow_test_transport and (
        transport.collector_mode != "real" or not isinstance(transport, RealHttpTransport)
    ):
        raise CollectionBlocked("formal evidence requires the real HTTP collector transport")
    if _CHALLENGE_PATTERN.fullmatch(context.challenge) is None:
        raise CollectionBlocked("challenge must be a safe 16-128 character one-time value")
    if not _GIT_PATTERN.fullmatch(context.git_head) or not _SHA256_PATTERN.fullmatch(
        context.content_fingerprint
    ):
        raise CollectionBlocked("Git/content target fingerprint is invalid")
    output = _prepare_output_directory(context.output_directory)
    started = datetime.now(UTC)
    scenario_records: list[dict[str, object]] = []
    cleanup_raw: dict[str, object] | None = None
    opened = False
    cleanup_error: Exception | None = None
    close_error: Exception | None = None
    try:
        session = _mapping(transport.open(context), label="acceptance session")
        opened = True
        if transport.collector_mode == "real":
            _validate_session(context, session)
        for spec in SCENARIO_PLAN:
            result = _mapping(transport.execute(context, spec), label="scenario execution")
            fields = _validate_probe_result(context, spec, result)
            raw_payload: dict[str, object] = {
                "schema_version": 2,
                "producer": PRODUCER,
                "producer_version": PRODUCER_VERSION,
                "collector_mode": transport.collector_mode,
                "challenge": context.challenge,
                "target": {
                    "deployment_id": context.deployment_id,
                    "git_head": context.git_head,
                    "content_fingerprint": context.content_fingerprint,
                },
                "scenario_id": spec.scenario_id,
                **result,
            }
            raw_path = output / "raw" / f"{spec.scenario_id}.json"
            _write_json_atomic(raw_path, raw_payload)
            scenario_records.append(
                {
                    **fields,
                    "artifact": raw_path.relative_to(output).as_posix(),
                    "artifact_sha256": _sha256_file(raw_path),
                }
            )
        cleanup_raw = _mapping(transport.cleanup(context), label="cleanup proof")
        _validate_cleanup(context, cleanup_raw)
    finally:
        if opened and cleanup_raw is None:
            try:
                recovery_cleanup = _mapping(
                    transport.cleanup(context), label="recovery cleanup proof"
                )
                _validate_cleanup(context, recovery_cleanup)
            except Exception as error:
                cleanup_error = error
        try:
            transport.close()
        except Exception as error:
            close_error = error
        if cleanup_error is not None:
            raise CollectionBlocked(
                "dedicated acceptance volume cleanup failed after execution"
            ) from cleanup_error
        if close_error is not None:
            raise CollectionBlocked("acceptance controller session close failed") from close_error

    cleanup_path = output / "raw" / "cleanup.json"
    _write_json_atomic(
        cleanup_path,
        {
            "schema_version": 2,
            "producer": PRODUCER,
            "producer_version": PRODUCER_VERSION,
            "collector_mode": transport.collector_mode,
            "challenge": context.challenge,
            "target": {
                "deployment_id": context.deployment_id,
                "git_head": context.git_head,
                "content_fingerprint": context.content_fingerprint,
            },
            "cleanup": cleanup_raw,
        },
    )
    finished = datetime.now(UTC)
    manifest: dict[str, object] = {
        "schema_version": 2,
        "producer": PRODUCER,
        "producer_version": PRODUCER_VERSION,
        "collector_mode": transport.collector_mode,
        "status": "passed" if transport.collector_mode == "real" else "test-only",
        "verified_artifacts": True,
        "destructive_volume": True,
        "volume_id": context.volume_id,
        "mount_target": context.mount_target,
        "object_root": context.object_root,
        "knowledge_base_id": context.knowledge_base_id,
        "challenge": context.challenge,
        "target": {
            "deployment_id": context.deployment_id,
            "git_head": context.git_head,
            "content_fingerprint": context.content_fingerprint,
        },
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "filesystem_cross_check": True,
        "minio_cross_check": True,
        "scenarios": scenario_records,
        "cleanup": {
            "artifact": cleanup_path.relative_to(output).as_posix(),
            "artifact_sha256": _sha256_file(cleanup_path),
        },
    }
    payload = _attestation_payload(manifest)
    manifest["attestation"] = {
        "type": "sha256-chain-v1",
        "artifact_count": len(scenario_records) + 1,
        "digest": _sha256_bytes(_canonical_json(payload)),
    }
    _assert_no_sensitive_material(manifest, path="manifest")
    _write_json_atomic(output / "watermark-chain.json", manifest)
    return manifest


def _bounded_regular_file(path: Path, maximum_bytes: int, *, label: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    metadata = resolved.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CollectionBlocked(f"{label} must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
        raise CollectionBlocked(f"{label} size is outside the accepted range")
    return resolved


def _secure_url(value: object, *, label: str) -> str:
    raw = str(value or "").rstrip("/")
    parsed = urlsplit(raw)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (parsed.scheme != "https" and not loopback)
    ):
        raise CollectionBlocked(f"{label} must be an absolute HTTPS or loopback URL")
    return raw


def _absolute_path(value: object, *, label: str) -> Path:
    path = Path(str(value or ""))
    if not path.is_absolute():
        raise CollectionBlocked(f"{label} must be an absolute path")
    return path


def load_topology(path: Path) -> RealTopology:
    source = _bounded_regular_file(path, MAX_TOPOLOGY_BYTES, label="topology")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CollectionBlocked("topology is not valid UTF-8 JSON") from error
    raw = _mapping(payload, label="topology")
    required = {
        "schema_version",
        "collector_mode",
        "api_url",
        "control_url",
        "volume_id",
        "mount_target",
        "object_root",
        "knowledge_base_id",
        "deployment_id",
        "repository",
        "token_file",
    }
    if set(raw) - (required | {"ca_bundle"}) or required - set(raw):
        raise CollectionBlocked("topology keys do not match the controlled collector contract")
    if raw["schema_version"] != 1 or raw["collector_mode"] != "real":
        raise CollectionBlocked("topology must request collector_mode=real schema v1")
    try:
        uuid.UUID(str(raw["knowledge_base_id"]))
    except ValueError as error:
        raise CollectionBlocked("test knowledge-base identity is invalid") from error
    for label, value in (
        ("volume identity", raw["volume_id"]),
        ("deployment identity", raw["deployment_id"]),
    ):
        if not 1 <= len(str(value).strip()) <= 256:
            raise CollectionBlocked(f"{label} is missing or exceeds 256 characters")
    ca_bundle = raw.get("ca_bundle")
    return RealTopology(
        api_url=_secure_url(raw["api_url"], label="business API URL"),
        control_url=_secure_url(raw["control_url"], label="acceptance control URL"),
        volume_id=str(raw["volume_id"]),
        mount_target=_absolute_path(raw["mount_target"], label="mount target"),
        object_root=_absolute_path(raw["object_root"], label="object root"),
        knowledge_base_id=str(raw["knowledge_base_id"]),
        deployment_id=str(raw["deployment_id"]),
        repository=_absolute_path(raw["repository"], label="repository"),
        token_file=_absolute_path(raw["token_file"], label="controller token file"),
        ca_bundle=(_absolute_path(ca_bundle, label="CA bundle") if ca_bundle is not None else None),
    )


def validate_destructive_target(
    topology: RealTopology,
    *,
    challenge: str,
    output_directory: Path,
) -> tuple[Path, Path, Path]:
    if platform.system().casefold() != "linux":
        raise CollectionBlocked("real storage-chain evidence must run on the target Linux host")
    if _CHALLENGE_PATTERN.fullmatch(challenge) is None:
        raise CollectionBlocked("challenge must be a safe 16-128 character one-time value")
    mount = topology.mount_target.resolve(strict=True)
    object_root = topology.object_root.resolve(strict=True)
    repository = topology.repository.resolve(strict=True)
    if mount == Path("/") or mount.is_symlink() or not mount.is_dir() or not os.path.ismount(mount):
        raise CollectionBlocked("destructive acceptance mount must be a dedicated directory")
    try:
        object_root.relative_to(mount)
    except ValueError as error:
        raise CollectionBlocked(
            "object root must be inside the dedicated acceptance mount"
        ) from error
    if object_root == mount or object_root.is_symlink() or not object_root.is_dir():
        raise CollectionBlocked("object root must be a dedicated non-symlink subdirectory")
    if os.stat(mount).st_dev != os.stat(object_root).st_dev:
        raise CollectionBlocked("object root is not on the declared acceptance volume")
    marker = mount / MARKER_NAME
    marker = _bounded_regular_file(marker, 256, label="destroyable-volume marker")
    if marker.read_text(encoding="utf-8").strip() != challenge:
        raise CollectionBlocked("destroyable-volume marker does not match the one-time challenge")
    output = output_directory.expanduser().resolve()
    try:
        output.relative_to(mount)
    except ValueError:
        pass
    else:
        raise CollectionBlocked("evidence output must be outside the destroyable volume")
    if not (repository / ".git").exists() and not (repository / ".git").is_file():
        raise CollectionBlocked("target repository identity is unavailable")
    return mount, object_root, repository


def _read_token(path: Path) -> str:
    source = _bounded_regular_file(path, MAX_SECRET_BYTES, label="controller token file")
    if platform.system().casefold() == "linux":
        metadata = source.stat()
        get_effective_uid = getattr(os, "geteuid", None)
        if not callable(get_effective_uid):
            raise CollectionBlocked("controller token owner cannot be verified")
        if metadata.st_uid != get_effective_uid() or stat.S_IMODE(metadata.st_mode) not in {
            0o400,
            0o600,
        }:
            raise CollectionBlocked("controller token file owner or mode is unsafe")
    token = source.read_text(encoding="utf-8").strip()
    if not 32 <= len(token) <= 4096 or any(character.isspace() for character in token):
        raise CollectionBlocked("controller token file is malformed")
    return token


class RealHttpTransport:
    collector_mode = "real"

    def __init__(self, topology: RealTopology, *, challenge: str) -> None:
        token = _read_token(topology.token_file)
        verify: bool | str = True
        if topology.ca_bundle is not None:
            verify = str(_bounded_regular_file(topology.ca_bundle, 1024 * 1024, label="CA bundle"))
        self._topology = topology
        self._challenge = challenge
        self._client = httpx.Client(
            base_url=topology.control_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": f"{PRODUCER}/{PRODUCER_VERSION}",
                "X-KB-Acceptance-Challenge": challenge,
            },
            follow_redirects=False,
            timeout=httpx.Timeout(300.0, connect=15.0),
            verify=verify,
            trust_env=False,
        )
        self._session_id: str | None = None

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        try:
            with self._client.stream(
                "POST",
                path,
                json=payload,
                headers={"X-Request-ID": str(uuid.uuid4())},
            ) as response:
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise CollectionBlocked("acceptance controller response exceeded 4 MiB")
                    chunks.append(chunk)
                if response.status_code < 200 or response.status_code >= 300:
                    raise CollectionBlocked("acceptance controller request failed")
            value = json.loads(b"".join(chunks).decode("utf-8"))
        except CollectionBlocked:
            raise
        except (httpx.HTTPError, UnicodeError, json.JSONDecodeError, OSError) as error:
            raise CollectionBlocked("acceptance controller dependency is unavailable") from error
        return _mapping(value, label="acceptance controller response")

    def open(self, context: CollectionContext) -> dict[str, object]:
        response = self._post(
            "/v1/storage-acceptance/sessions",
            {
                "challenge": context.challenge,
                "volume_id": context.volume_id,
                "mount_target": context.mount_target,
                "object_root": context.object_root,
                "knowledge_base_id": context.knowledge_base_id,
                "api_url": context.api_url,
                "deployment_id": context.deployment_id,
                "target": {
                    "git_head": context.git_head,
                    "content_fingerprint": context.content_fingerprint,
                },
                "destructive_volume": True,
                "scenario_count": len(SCENARIO_PLAN),
            },
        )
        session_id = response.get("session_id")
        if isinstance(session_id, str):
            self._session_id = session_id
        return response

    def execute(self, context: CollectionContext, scenario: ScenarioSpec) -> dict[str, object]:
        del context
        if self._session_id is None:
            raise CollectionBlocked("acceptance controller session is not open")
        return self._post(
            f"/v1/storage-acceptance/sessions/{self._session_id}/scenarios",
            {"scenario": asdict(scenario)},
        )

    def cleanup(self, context: CollectionContext) -> dict[str, object]:
        del context
        if self._session_id is None:
            raise CollectionBlocked("acceptance controller session is not open")
        return self._post(
            f"/v1/storage-acceptance/sessions/{self._session_id}/cleanup",
            {"destroy_test_knowledge_base": True, "destroy_volume_contents": True},
        )

    def close(self) -> None:
        try:
            if self._session_id is not None:
                self._post(
                    f"/v1/storage-acceptance/sessions/{self._session_id}/close",
                    {"challenge": self._challenge},
                )
        finally:
            self._client.close()


def _plan_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "mode": "dry-run",
        "destructive": False,
        "required_confirmation": "--execute-destructive",
        "scenario_count": len(SCENARIO_PLAN),
        "scenarios": [asdict(item) for item in SCENARIO_PLAN],
        "safety": {
            "requires_target_linux": True,
            "requires_empty_output_directory": True,
            "requires_dedicated_destroyable_volume": True,
            "requires_matching_one_time_challenge_marker": True,
            "requires_test_knowledge_base": True,
            "cleanup_failure_status": "blocked",
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect real 25-scenario storage-chain evidence on a destroyable target volume"
    )
    parser.add_argument("--list-plan", action="store_true")
    parser.add_argument("--execute-destructive", action="store_true")
    parser.add_argument("--topology", type=Path)
    parser.add_argument("--challenge")
    parser.add_argument("--output-directory", type=Path)
    arguments = parser.parse_args(argv)
    if arguments.list_plan or not arguments.execute_destructive:
        print(json.dumps(_plan_document(), ensure_ascii=False, sort_keys=True))
        return 0
    try:
        if not arguments.challenge:
            raise CollectionBlocked("--challenge is required for destructive execution")
        if arguments.topology is None:
            raise CollectionBlocked("--topology is required for destructive execution")
        if arguments.output_directory is None:
            raise CollectionBlocked("--output-directory is required for destructive execution")
        topology = load_topology(arguments.topology)
        mount, object_root, repository = validate_destructive_target(
            topology,
            challenge=arguments.challenge,
            output_directory=arguments.output_directory,
        )
        identity = collect_worktree_evidence(repository)
        context = CollectionContext(
            challenge=arguments.challenge,
            volume_id=topology.volume_id,
            mount_target=str(mount),
            object_root=str(object_root),
            knowledge_base_id=topology.knowledge_base_id,
            api_url=topology.api_url,
            deployment_id=topology.deployment_id,
            git_head=identity.git_head,
            content_fingerprint=identity.content_fingerprint,
            output_directory=arguments.output_directory,
        )
        manifest = collect_chain(
            context,
            RealHttpTransport(topology, challenge=arguments.challenge),
        )
        print(json.dumps(manifest, ensure_ascii=False, sort_keys=True))
        return 0
    except CollectionFailed as error:
        print(
            json.dumps(
                {"schema_version": 2, "status": "failed", "reason": str(error)},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 1
    except (CollectionBlocked, KeyError, TypeError, ValueError, OSError) as error:
        print(
            json.dumps(
                {"schema_version": 2, "status": "blocked", "reason": str(error)},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
