#!/usr/bin/env python3
"""Sample Linux, Docker, PostgreSQL and Redis during a formal load run.

The sampler never reads or emits clear-text credentials. Database commands expand
their existing container environment, and only aggregate counters are persisted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class SamplerError(RuntimeError):
    pass


SAFE_CONFIG_NAMES = {
    "COMPOSE_PROJECT_NAME",
    "KB_ALLOWED_HOSTS",
    "KB_CAPACITY_ACCEPTANCE_MODE",
    "KB_CAPACITY_ACCEPTANCE_RUN_ID",
    "KB_CORS_ORIGINS",
    "KB_DATA_ROOT",
    "KB_HTTP_BIND",
    "KB_HTTPS_BIND",
    "KB_PUBLIC_HOST",
    "MINIO_BUCKET",
    "POSTGRES_DB",
}


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_config_sha256(path: Path) -> str:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise SamplerError("environment file contains a malformed assignment")
        name, value = line.split("=", maxsplit=1)
        name = name.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if name in SAFE_CONFIG_NAMES:
            values[name] = value
    return hashlib.sha256(_canonical_json(values)).hexdigest()


def _load_manifest(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SamplerError("capacity manifest is not valid JSON") from error
    if not isinstance(value, Mapping):
        raise SamplerError("capacity manifest must be an object")
    return value


def _host_fingerprint(data_path: Path) -> str:
    machine_id = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    if not machine_id:
        raise SamplerError("/etc/machine-id is empty")
    total_memory, _ = _memory()
    public = {
        "architecture": platform.machine().lower(),
        "disk_total_bytes": shutil.disk_usage(data_path).total,
        "logical_cpus": os.cpu_count() or 0,
        "memory_total_bytes": total_memory,
        "operating_system": platform.system(),
    }
    private = {
        "machine_id": machine_id,
        "node": platform.node(),
        "kernel": platform.release(),
        "public": public,
    }
    return hashlib.sha256(_canonical_json(private)).hexdigest()


def _run(command: Sequence[str], *, timeout: float = 8.0) -> str:
    try:
        completed = subprocess.run(
            list(command),
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise SamplerError(
            f"command failed without exposing its arguments: {command[0]}"
        ) from error
    return completed.stdout.strip()


def _percent(value: object) -> float:
    if not isinstance(value, str) or not value.endswith("%"):
        raise SamplerError("Docker percentage is malformed")
    return float(value[:-1])


def _read_cpu_ticks() -> tuple[int, int]:
    fields = Path("/proc/stat").read_text(encoding="ascii").splitlines()[0].split()
    if not fields or fields[0] != "cpu" or len(fields) < 8:
        raise SamplerError("/proc/stat has an unsupported format")
    values = [int(item) for item in fields[1:]]
    idle = values[3] + values[4]
    return sum(values), idle


def _cpu_percent(previous: tuple[int, int], current: tuple[int, int]) -> float:
    total_delta = current[0] - previous[0]
    idle_delta = current[1] - previous[1]
    if total_delta <= 0 or idle_delta < 0:
        raise SamplerError("host CPU counters did not advance monotonically")
    return max(0.0, min(100.0, 100.0 * (total_delta - idle_delta) / total_delta))


def _memory() -> tuple[int, float]:
    values: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        name, raw = line.split(":", maxsplit=1)
        fields = raw.split()
        if fields:
            values[name] = int(fields[0]) * 1024
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    if total <= 0 or not 0 <= available <= total:
        raise SamplerError("/proc/meminfo is missing usable totals")
    return total, 100.0 * (total - available) / total


def _load_average_1m() -> float:
    fields = Path("/proc/loadavg").read_text(encoding="ascii").split()
    if not fields:
        raise SamplerError("/proc/loadavg has an unsupported format")
    return float(fields[0])


def _compose_command(
    *, project: str, compose_file: Path, env_file: Path, arguments: Sequence[str]
) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-name",
        project,
        "--file",
        str(compose_file),
        "--env-file",
        str(env_file),
        *arguments,
    ]


def _container_inventory(project: str) -> list[dict[str, str]]:
    output = _run(
        [
            "docker",
            "ps",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{json .}}",
        ]
    )
    rows: list[dict[str, str]] = []
    for raw in output.splitlines():
        if not raw:
            continue
        value = json.loads(raw)
        if not isinstance(value, Mapping):
            raise SamplerError("Docker inventory row must be an object")
        container_id = value.get("ID")
        name = value.get("Names")
        if not isinstance(container_id, str) or not isinstance(name, str):
            raise SamplerError("Docker inventory row is incomplete")
        rows.append({"id": container_id, "name": name})
    if not rows:
        raise SamplerError("no running containers belong to the requested Compose project")
    return sorted(rows, key=lambda item: item["name"])


def _inspect_containers(container_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    value = json.loads(_run(["docker", "inspect", *container_ids]))
    if not isinstance(value, list):
        raise SamplerError("Docker inspect output must be an array")
    result: dict[str, dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, Mapping):
            raise SamplerError("Docker inspect entry must be an object")
        identifier = item.get("Id")
        state = item.get("State")
        config = item.get("Config")
        image_id = item.get("Image")
        if (
            not isinstance(identifier, str)
            or not isinstance(state, Mapping)
            or not isinstance(config, Mapping)
            or not isinstance(image_id, str)
        ):
            raise SamplerError("Docker inspect entry is incomplete")
        labels = config.get("Labels")
        service = labels.get("com.docker.compose.service") if isinstance(labels, Mapping) else None
        if not isinstance(service, str) or not service:
            raise SamplerError("Docker inspect entry has no Compose service label")
        result[identifier[:12]] = {
            "restart_count": int(item.get("RestartCount", 0)),
            "oom_killed": bool(state.get("OOMKilled")),
            "running": bool(state.get("Running")),
            "image_id": image_id,
            "service": service,
        }
    return result


def _container_stats(container_ids: Sequence[str]) -> dict[str, dict[str, float]]:
    output = _run(
        [
            "docker",
            "stats",
            "--no-stream",
            "--format",
            "{{json .}}",
            *container_ids,
        ],
        timeout=15,
    )
    result: dict[str, dict[str, float]] = {}
    for raw in output.splitlines():
        value = json.loads(raw)
        if not isinstance(value, Mapping):
            raise SamplerError("Docker stats row must be an object")
        identifier = value.get("ID") or value.get("Container")
        if not isinstance(identifier, str):
            raise SamplerError("Docker stats row has no container identifier")
        result[identifier[:12]] = {
            "cpu_percent": _percent(value.get("CPUPerc")),
            "memory_percent": _percent(value.get("MemPerc")),
        }
    return result


def _postgres_metrics(command_base: Sequence[str]) -> dict[str, int]:
    sql = (
        "SELECT json_build_object("
        "'active_connections', count(*) FILTER (WHERE state <> 'idle'),"
        "'long_transactions', count(*) FILTER (WHERE xact_start < now() - interval '30 seconds'),"
        "'deadlocks', (SELECT coalesce(sum(deadlocks), 0) FROM pg_stat_database)) "
        "FROM pg_stat_activity;"
    )
    output = _run(
        [
            *command_base,
            "exec",
            "-T",
            "postgres",
            "sh",
            "-eu",
            "-c",
            'psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "$1"',
            "capacity-sampler",
            sql,
        ]
    )
    value = json.loads(output)
    if not isinstance(value, Mapping):
        raise SamplerError("PostgreSQL metrics must be an object")
    return {
        "active_connections": int(value["active_connections"]),
        "long_transactions": int(value["long_transactions"]),
        "deadlocks": int(value["deadlocks"]),
    }


def _redis_metrics(command_base: Sequence[str]) -> dict[str, int]:
    output = _run(
        [
            *command_base,
            "exec",
            "-T",
            "redis",
            "sh",
            "-eu",
            "-c",
            (
                'export REDISCLI_AUTH="$REDIS_PASSWORD"; '
                "redis-cli --no-auth-warning INFO stats; "
                "redis-cli --no-auth-warning INFO clients"
            ),
        ]
    )
    values: dict[str, int] = {}
    for raw in output.splitlines():
        line = raw.strip().rstrip("\r")
        if ":" not in line or line.startswith("#"):
            continue
        name, raw_value = line.split(":", maxsplit=1)
        if name in {"evicted_keys", "rejected_connections", "connected_clients"}:
            values[name] = int(raw_value)
    required = {"evicted_keys", "rejected_connections", "connected_clients"}
    if set(values) != required:
        raise SamplerError("Redis INFO output is missing required counters")
    return values


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sample target resources during a load run.")
    parser.add_argument("--project", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--compose-file", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--data-path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=int, required=True)
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if platform.system() != "Linux":
        raise SystemExit("capacity resource sampling is formal only on Linux")
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        raise SystemExit("the accepted target architecture is Linux amd64/x86_64")
    if arguments.duration_seconds < 1:
        raise SystemExit("duration must be positive")
    if not 1.0 <= arguments.interval_seconds <= 60.0:
        raise SystemExit("interval must be between 1 and 60 seconds")
    if arguments.output.exists():
        raise SystemExit("refusing to overwrite existing resource evidence")
    for path in (
        arguments.manifest,
        arguments.compose_file,
        arguments.env_file,
        arguments.data_path,
    ):
        if not path.exists():
            raise SystemExit(f"required path does not exist: {path}")

    manifest_path = arguments.manifest.resolve()
    manifest = _load_manifest(manifest_path)
    if (
        manifest.get("schema_version") != 1
        or manifest.get("classification") != "isolated_capacity_acceptance"
        or manifest.get("evidence_classification") != "not_model_capacity"
    ):
        raise SystemExit("resource sampling requires an isolated not_model_capacity manifest")
    run_id = manifest.get("run_id")
    manifest_project = manifest.get("project")
    acceptance = manifest.get("acceptance")
    fingerprints = manifest.get("fingerprints")
    sampling = manifest.get("resource_sampling")
    images = manifest.get("images")
    if (
        not isinstance(run_id, str)
        or not isinstance(manifest_project, str)
        or not isinstance(acceptance, Mapping)
        or not isinstance(fingerprints, Mapping)
        or not isinstance(sampling, Mapping)
        or not isinstance(images, list)
    ):
        raise SystemExit("capacity manifest is incomplete")
    if arguments.project != manifest_project or not manifest_project.startswith(
        "heyi-kb-acceptance-"
    ):
        raise SystemExit("sampler project is not the bound isolated acceptance project")
    if manifest_project == "heyi-kb-offline":
        raise SystemExit("the delivery/production project can never be sampled by this gate")
    if str(arguments.data_path.resolve()) != acceptance.get("data_root"):
        raise SystemExit("sampler data path differs from the acceptance manifest")
    if _sha256_file(arguments.compose_file.resolve()) != fingerprints.get("compose_sha256"):
        raise SystemExit("Compose file differs from the acceptance manifest")
    if _safe_config_sha256(arguments.env_file.resolve()) != fingerprints.get(
        "non_secret_config_sha256"
    ):
        raise SystemExit("non-secret environment contract differs from the manifest")
    if _host_fingerprint(arguments.data_path.resolve()) != fingerprints.get("host_sha256"):
        raise SystemExit("host fingerprint differs from the acceptance manifest")
    expected_duration = int(sampling.get("duration_seconds", 0))
    expected_interval = float(sampling.get("interval_seconds", 0))
    expected_samples = int(sampling.get("expected_samples", 0))
    if arguments.duration_seconds != expected_duration:
        raise SystemExit("sampling duration differs from the acceptance manifest")
    if arguments.interval_seconds != expected_interval:
        raise SystemExit("sampling interval differs from the acceptance manifest")
    if expected_samples != int(expected_duration // expected_interval) or expected_samples < 2:
        raise SystemExit("manifest resource sample count is invalid")

    inventory = _container_inventory(arguments.project)
    container_ids = [item["id"] for item in inventory]
    baseline = _inspect_containers(container_ids)
    if set(baseline) != {identifier[:12] for identifier in container_ids}:
        raise SystemExit("Docker inspect inventory does not match the Compose inventory")
    if any(not item["running"] for item in baseline.values()):
        raise SystemExit("all project containers must be running before sampling")
    manifest_images: dict[str, str] = {}
    for raw_image in images:
        if not isinstance(raw_image, Mapping):
            raise SystemExit("manifest image inventory is invalid")
        service = raw_image.get("service")
        image_id = raw_image.get("image_id")
        if not isinstance(service, str) or not isinstance(image_id, str):
            raise SystemExit("manifest image inventory is incomplete")
        manifest_images[service] = image_id
    baseline_images = {str(state["service"]): str(state["image_id"]) for state in baseline.values()}
    if baseline_images != manifest_images:
        raise SystemExit("running service image IDs differ from the acceptance manifest")
    manifest_sha256 = _sha256_file(manifest_path)
    evidence_binding = {
        "manifest_sha256": manifest_sha256,
        "run_id": run_id,
        "project": manifest_project,
        "git_commit": manifest.get("git_commit"),
        "compose_sha256": fingerprints.get("compose_sha256"),
        "non_secret_config_sha256": fingerprints.get("non_secret_config_sha256"),
        "host_sha256": fingerprints.get("host_sha256"),
        "image_inventory_sha256": fingerprints.get("image_inventory_sha256"),
    }
    compose_base = _compose_command(
        project=arguments.project,
        compose_file=arguments.compose_file.resolve(),
        env_file=arguments.env_file.resolve(),
        arguments=[],
    )

    stop = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    previous_cpu = _read_cpu_ticks()
    with arguments.output.open("x", encoding="utf-8", newline="\n") as evidence:
        for sample_index in range(1, expected_samples + 1):
            if stop:
                break
            deadline = started + sample_index * arguments.interval_seconds
            time.sleep(max(0.0, deadline - time.monotonic()))
            now = time.monotonic()
            current_cpu = _read_cpu_ticks()
            sample_errors: list[str] = []
            if _sha256_file(arguments.compose_file.resolve()) != fingerprints.get("compose_sha256"):
                sample_errors.append("Compose file changed during the load run")
            if _safe_config_sha256(arguments.env_file.resolve()) != fingerprints.get(
                "non_secret_config_sha256"
            ):
                sample_errors.append("non-secret configuration changed during the load run")
            total_memory, memory_percent = _memory()
            disk = shutil.disk_usage(arguments.data_path)
            current_inventory = _container_inventory(arguments.project)
            current_ids = [item["id"] for item in current_inventory]
            try:
                inspected = _inspect_containers(current_ids)
                stats = _container_stats(current_ids)
            except SamplerError as error:
                inspected = {}
                stats = {}
                sample_errors.append(str(error))

            containers: list[dict[str, Any]] = []
            for item in current_inventory:
                short_id = item["id"][:12]
                state = inspected.get(short_id, {})
                baseline_state = baseline.get(short_id)
                if baseline_state is None:
                    restart_delta = -1
                    sample_errors.append("container replacement detected")
                else:
                    restart_delta = int(state.get("restart_count", -1)) - int(
                        baseline_state["restart_count"]
                    )
                service = state.get("service")
                image_id = state.get("image_id")
                if not isinstance(service, str) or manifest_images.get(service) != image_id:
                    sample_errors.append("container image binding changed during the load run")
                container_stats = stats.get(short_id, {})
                containers.append(
                    {
                        "id": short_id,
                        "name": item["name"],
                        "service": service,
                        "image_id": image_id,
                        "cpu_percent": container_stats.get("cpu_percent"),
                        "memory_percent": container_stats.get("memory_percent"),
                        "restart_delta": restart_delta,
                        "oom_killed": bool(state.get("oom_killed", False)),
                        "running": bool(state.get("running", False)),
                    }
                )

            postgres: dict[str, int] | None = None
            redis: dict[str, int] | None = None
            try:
                postgres = _postgres_metrics(compose_base)
            except SamplerError as error:
                sample_errors.append(str(error))
            try:
                redis = _redis_metrics(compose_base)
            except SamplerError as error:
                sample_errors.append(str(error))

            sample = {
                "schema_version": 2,
                "sample_index": sample_index,
                "monotonic_seconds": round(now - started, 6),
                "observed_at_utc": datetime.now(UTC).isoformat(),
                "evidence_binding": evidence_binding,
                "host": {
                    "logical_cpus": os.cpu_count() or 0,
                    "cpu_percent": round(_cpu_percent(previous_cpu, current_cpu), 4),
                    "memory_total_bytes": total_memory,
                    "memory_percent": round(memory_percent, 4),
                    "disk_total_bytes": disk.total,
                    "disk_free_bytes": disk.free,
                    "disk_free_percent": round(100.0 * disk.free / disk.total, 4),
                    "load_average_1m": _load_average_1m(),
                },
                "containers": containers,
                "postgres": postgres,
                "redis": redis,
                "errors": sample_errors,
            }
            evidence.write(json.dumps(sample, ensure_ascii=True, sort_keys=True) + "\n")
            evidence.flush()
            os.fsync(evidence.fileno())
            previous_cpu = current_cpu
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
