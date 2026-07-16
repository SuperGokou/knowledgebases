#!/usr/bin/env python3
"""Create and close a tamper-evident, isolated capacity-acceptance run.

Only non-secret configuration is admitted to the manifest.  The tool deliberately
does not hash or copy identity fixtures, passwords, tokens, CA private material, or
secret environment values: those are inputs to the run, never evidence artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RUN_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{6,30}[a-z0-9])$")
GIT_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PROJECT_PREFIX = "heyi-kb-acceptance-"
OWNERSHIP_MARKER = ".capacity-acceptance-owned.json"
OWNER_LABEL = "jiangsu-heyi-knowledgebases"
REQUIRED_SERVICES = {
    "api",
    "caddy",
    "clamd",
    "maintenance",
    "minio",
    "postgres",
    "redis",
    "web",
}
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


class ManifestError(RuntimeError):
    """The acceptance isolation or evidence binding is invalid."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as destination:
        destination.write(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
        destination.write("\n")
        destination.flush()
        os.fsync(destination.fileno())


def _run(command: Sequence[str], *, timeout: float = 20.0) -> str:
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
        raise ManifestError(
            f"command failed without exposing its arguments: {command[0]}"
        ) from error
    return completed.stdout.strip()


def _read_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ManifestError(f"invalid JSON: {path}") from error
    if not isinstance(value, Mapping):
        raise ManifestError(f"JSON document must be an object: {path}")
    return value


def _parse_env_files(paths: Sequence[Path]) -> dict[str, str]:
    values: dict[str, str] = {}
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8-sig").splitlines()
        except OSError as error:
            raise ManifestError(f"cannot read environment file: {path}") from error
        for line_number, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            if "=" not in line:
                raise ManifestError(f"malformed environment assignment at {path}:{line_number}")
            name, value = line.split("=", maxsplit=1)
            name = name.strip()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ManifestError(f"malformed environment name at {path}:{line_number}")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            values[name] = value
    return values


def _expected_names(run_id: str) -> tuple[str, str, str]:
    project = f"{PROJECT_PREFIX}{run_id}"
    database = f"knowledge_acceptance_{run_id.replace('-', '_')}"
    bucket = f"knowledge-acceptance-{run_id}"
    return project, database, bucket


def _resolved_child(root: Path, child: Path) -> tuple[Path, Path]:
    resolved_root = root.resolve(strict=True)
    resolved_child = child.resolve(strict=True)
    if resolved_root == Path(resolved_root.anchor):
        raise ManifestError("acceptance root cannot be a filesystem root")
    if resolved_child.parent != resolved_root:
        raise ManifestError("data root must be the direct run-id child of acceptance root")
    return resolved_root, resolved_child


def _validate_marker(data_root: Path, *, run_id: str, project: str) -> str:
    marker_path = data_root / OWNERSHIP_MARKER
    marker = _read_json(marker_path)
    expected = {
        "kind": "capacity_acceptance_owned",
        "project": project,
        "run_id": run_id,
        "schema_version": 1,
    }
    if dict(marker) != expected:
        raise ManifestError("acceptance ownership marker has unexpected fields or values")
    return _sha256_file(marker_path)


def _docker_inventory(project: str) -> list[dict[str, str]]:
    output = _run(
        [
            "docker",
            "ps",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{.ID}}",
        ]
    )
    identifiers = [line.strip() for line in output.splitlines() if line.strip()]
    if not identifiers:
        raise ManifestError("the isolated acceptance Compose project has no running containers")
    try:
        inspected = json.loads(_run(["docker", "inspect", *identifiers]))
    except json.JSONDecodeError as error:
        raise ManifestError("Docker inspect returned invalid JSON") from error
    if not isinstance(inspected, list):
        raise ManifestError("Docker inspect result must be an array")
    inventory: list[dict[str, str]] = []
    services: set[str] = set()
    for raw in inspected:
        if not isinstance(raw, Mapping):
            raise ManifestError("Docker inspect entry must be an object")
        config = raw.get("Config")
        if not isinstance(config, Mapping):
            raise ManifestError("Docker inspect entry has no configuration")
        labels = config.get("Labels")
        if not isinstance(labels, Mapping):
            raise ManifestError("acceptance container has no labels")
        if labels.get("com.docker.compose.project") != project:
            raise ManifestError("container project label escaped the acceptance project")
        if labels.get("io.heyi.knowledgebases.owner") != OWNER_LABEL:
            raise ManifestError("container owner label is not the knowledge-base stack")
        if labels.get("io.heyi.knowledgebases.stack") != "offline":
            raise ManifestError("formal capacity evidence requires the offline stack")
        service = labels.get("com.docker.compose.service")
        image_id = raw.get("Image")
        image_reference = config.get("Image")
        if (
            not isinstance(service, str)
            or not service
            or not isinstance(image_id, str)
            or not image_id
            or not isinstance(image_reference, str)
            or not image_reference
        ):
            raise ManifestError("container service or image binding is incomplete")
        if service in services:
            raise ManifestError("capacity gate currently requires one container per service")
        services.add(service)
        inventory.append(
            {
                "service": service,
                "image_id": image_id,
                "image_reference": image_reference,
            }
        )
    missing = sorted(REQUIRED_SERVICES - services)
    if missing:
        raise ManifestError(f"required acceptance services are not running: {', '.join(missing)}")
    return sorted(inventory, key=lambda item: item["service"])


def _host_binding(data_root: Path) -> tuple[str, dict[str, int | str]]:
    machine_id = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    if not machine_id:
        raise ManifestError("/etc/machine-id is empty")
    disk = shutil.disk_usage(data_root)
    total_memory = 0
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemTotal:"):
            total_memory = int(line.split()[1]) * 1024
            break
    if total_memory <= 0:
        raise ManifestError("cannot read host memory total")
    public: dict[str, int | str] = {
        "architecture": platform.machine().lower(),
        "disk_total_bytes": disk.total,
        "logical_cpus": os.cpu_count() or 0,
        "memory_total_bytes": total_memory,
        "operating_system": platform.system(),
    }
    private_binding = {
        "machine_id": machine_id,
        "node": platform.node(),
        "kernel": platform.release(),
        "public": public,
    }
    return _sha256_bytes(_canonical_json(private_binding)), public


def create_manifest(arguments: argparse.Namespace) -> int:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise ManifestError("formal capacity evidence is accepted only on Linux amd64")
    run_id = arguments.run_id
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise ManifestError("run id must be 8-32 lowercase alphanumeric/hyphen characters")
    if GIT_COMMIT_PATTERN.fullmatch(arguments.git_commit) is None:
        raise ManifestError("git commit must be an exact lowercase 40-hex revision")
    expected_project, expected_database, expected_bucket = _expected_names(run_id)
    if arguments.project != expected_project:
        raise ManifestError(f"project must equal {expected_project}")
    if arguments.project == "heyi-kb-offline":
        raise ManifestError("the delivery/production project can never be load tested")
    if arguments.duration_seconds < 1_800:
        raise ManifestError(
            "formal steady-state resource sampling must run for at least 1800 seconds"
        )
    if not 1.0 <= arguments.interval_seconds <= 10.0:
        raise ManifestError("formal resource sampling interval must be 1-10 seconds")

    compose_file = arguments.compose_file.resolve(strict=True)
    env_files = [path.resolve(strict=True) for path in arguments.env_file]
    acceptance_root, data_root = _resolved_child(arguments.acceptance_root, arguments.data_root)
    if data_root.name != run_id:
        raise ManifestError("acceptance data-root basename must equal the run id")
    environment = _parse_env_files(env_files)
    required_environment = {
        "COMPOSE_PROJECT_NAME": expected_project,
        "KB_CAPACITY_ACCEPTANCE_MODE": "true",
        "KB_CAPACITY_ACCEPTANCE_RUN_ID": run_id,
        "KB_DATA_ROOT": str(data_root),
        "MINIO_BUCKET": expected_bucket,
        "POSTGRES_DB": expected_database,
    }
    for name, expected in required_environment.items():
        if environment.get(name) != expected:
            raise ManifestError(f"isolated acceptance environment requires {name}={expected}")
    marker_sha256 = _validate_marker(data_root, run_id=run_id, project=expected_project)

    inventory = _docker_inventory(expected_project)
    inventory_sha256 = _sha256_bytes(_canonical_json(inventory))
    host_sha256, host = _host_binding(data_root)
    safe_configuration = {
        name: environment[name] for name in sorted(SAFE_CONFIG_NAMES) if name in environment
    }
    config_sha256 = _sha256_bytes(_canonical_json(safe_configuration))
    expected_samples = int(arguments.duration_seconds // arguments.interval_seconds)
    if expected_samples < 2:
        raise ManifestError("resource sample count is too small")

    manifest = {
        "schema_version": 1,
        "classification": "isolated_capacity_acceptance",
        "evidence_classification": "not_model_capacity",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "run_id": run_id,
        "project": expected_project,
        "git_commit": arguments.git_commit,
        "acceptance": {
            "isolated": True,
            "acceptance_root": str(acceptance_root),
            "data_root": str(data_root),
            "database": expected_database,
            "object_bucket": expected_bucket,
            "ownership_marker_sha256": marker_sha256,
            "cleanup_required": True,
        },
        "fingerprints": {
            "compose_sha256": _sha256_file(compose_file),
            "non_secret_config_sha256": config_sha256,
            "host_sha256": host_sha256,
            "image_inventory_sha256": inventory_sha256,
        },
        "host": host,
        "images": inventory,
        "resource_sampling": {
            "duration_seconds": arguments.duration_seconds,
            "interval_seconds": arguments.interval_seconds,
            "expected_samples": expected_samples,
            "maximum_gap_seconds": arguments.interval_seconds * 1.5,
        },
        "safe_configuration": safe_configuration,
        "secret_material_included": False,
        "identity_material_included": False,
    }
    _write_exclusive(arguments.output, manifest)
    return 0


def verify_cleanup(arguments: argparse.Namespace) -> int:
    manifest_path = arguments.manifest.resolve(strict=True)
    manifest = _read_json(manifest_path)
    if (
        manifest.get("schema_version") != 1
        or manifest.get("classification") != "isolated_capacity_acceptance"
    ):
        raise ManifestError("cleanup requires an isolated capacity manifest")
    run_id = manifest.get("run_id")
    project = manifest.get("project")
    acceptance = manifest.get("acceptance")
    if (
        not isinstance(run_id, str)
        or not isinstance(project, str)
        or not isinstance(acceptance, Mapping)
    ):
        raise ManifestError("manifest isolation identity is incomplete")
    expected_project, _, _ = _expected_names(run_id)
    if project != expected_project or project == "heyi-kb-offline":
        raise ManifestError("cleanup manifest does not identify a safe acceptance project")
    data_root_value = acceptance.get("data_root")
    acceptance_root_value = acceptance.get("acceptance_root")
    if not isinstance(data_root_value, str) or not isinstance(acceptance_root_value, str):
        raise ManifestError("cleanup paths are missing")
    data_root = Path(data_root_value)
    acceptance_root = Path(acceptance_root_value)
    if data_root.parent != acceptance_root or data_root.name != run_id:
        raise ManifestError("cleanup path binding is unsafe")

    running = _run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{.ID}}",
        ]
    )
    containers_absent = not bool(running.strip())
    data_root_absent = not data_root.exists()
    passed = containers_absent and data_root_absent
    evidence = {
        "schema_version": 1,
        "classification": "isolated_capacity_cleanup",
        "evidence_classification": "not_model_capacity",
        "run_id": run_id,
        "project": project,
        "manifest_sha256": _sha256_file(manifest_path),
        "checked_at_utc": datetime.now(UTC).isoformat(),
        "containers_absent": containers_absent,
        "data_root_absent": data_root_absent,
        "passed": passed,
        "secret_material_included": False,
        "identity_material_included": False,
    }
    _write_exclusive(arguments.output, evidence)
    return 0 if passed else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bind and close an isolated capacity run.")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--run-id", required=True)
    create.add_argument("--project", required=True)
    create.add_argument("--compose-file", type=Path, required=True)
    create.add_argument("--env-file", type=Path, action="append", required=True)
    create.add_argument("--acceptance-root", type=Path, required=True)
    create.add_argument("--data-root", type=Path, required=True)
    create.add_argument("--duration-seconds", type=int, required=True)
    create.add_argument("--interval-seconds", type=float, required=True)
    create.add_argument("--git-commit", required=True)
    create.add_argument("--output", type=Path, required=True)
    cleanup = commands.add_parser("verify-cleanup")
    cleanup.add_argument("--manifest", type=Path, required=True)
    cleanup.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "create":
            return create_manifest(arguments)
        return verify_cleanup(arguments)
    except ManifestError as error:
        sys.stderr.write(f"capacity manifest rejected: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
