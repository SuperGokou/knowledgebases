from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from scripts.host_preflight import (
    GIB,
    MAX_FIO_FILE_BYTES,
    MAX_FIO_RUNTIME_SECONDS,
    REQUIRED_FIO_WORKLOADS,
)

MARKER_NAME = ".kb-acceptance-destroyable-volume"
MIN_TEST_FILE_BYTES = 64 * 1024**2
MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024


class CollectionBlocked(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_test_directory(disk_path: Path, test_directory: Path, challenge: str) -> Path:
    if len(challenge) < 16 or len(challenge) > 128:
        raise CollectionBlocked("challenge must contain between 16 and 128 characters")
    if test_directory.is_symlink() or not test_directory.is_dir():
        raise CollectionBlocked("test directory must be an existing non-symlink directory")
    disk = disk_path.resolve(strict=True)
    target = test_directory.resolve(strict=True)
    try:
        target.relative_to(disk)
    except ValueError as error:
        raise CollectionBlocked("test directory must be inside the target data mount") from error
    if target == disk:
        raise CollectionBlocked("fio must not run at the target data-mount root")
    if os.stat(disk).st_dev != os.stat(target).st_dev:
        raise CollectionBlocked("test directory is not on the target data filesystem")
    marker = target / MARKER_NAME
    if not marker.exists():
        raise CollectionBlocked("destroyable-volume marker is missing")
    metadata = marker.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CollectionBlocked("destroyable-volume marker must be a regular file")
    if metadata.st_size > 256 or marker.read_text(encoding="utf-8").strip() != challenge:
        raise CollectionBlocked("destroyable-volume marker does not match the challenge")
    unexpected = [entry.name for entry in os.scandir(target) if entry.name != MARKER_NAME]
    if unexpected:
        raise CollectionBlocked("test directory must be empty except for its marker")
    return target


def build_fio_command(
    *,
    fio_binary: str,
    workload: str,
    filename: Path,
    file_bytes: int,
    runtime_seconds: int,
) -> list[str]:
    if workload not in REQUIRED_FIO_WORKLOADS:
        raise ValueError("unsupported fio workload")
    if not MIN_TEST_FILE_BYTES <= file_bytes <= MAX_FIO_FILE_BYTES:
        raise ValueError("fio test-file size is outside the bounded range")
    if not 1 <= runtime_seconds <= MAX_FIO_RUNTIME_SECONDS:
        raise ValueError("fio runtime is outside the bounded range")
    workload_options = {
        "sequential_write": ("write", "1m", []),
        "random_read": ("randread", "4k", []),
        "random_write": ("randwrite", "4k", []),
        "fsync": ("write", "4k", ["--fsync=1"]),
    }
    rw, block_size, extra = workload_options[workload]
    return [
        fio_binary,
        f"--name={workload}",
        f"--filename={filename}",
        f"--size={file_bytes}",
        f"--runtime={runtime_seconds}",
        "--time_based=1",
        "--direct=1",
        "--ioengine=libaio",
        "--iodepth=1",
        "--numjobs=1",
        "--group_reporting=1",
        "--output-format=json",
        f"--rw={rw}",
        f"--bs={block_size}",
        *extra,
    ]


def _run_json(command: list[str], *, timeout: int) -> dict[str, Any]:
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise CollectionBlocked("target-host evidence command failed")
    if len(completed.stdout.encode("utf-8")) > MAX_COMMAND_OUTPUT_BYTES:
        raise CollectionBlocked("target-host evidence command output exceeded its bound")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise CollectionBlocked("target-host evidence command returned invalid JSON")
    return value


def _flatten_block_devices(devices: list[object]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    pending = list(devices)
    while pending:
        raw = pending.pop()
        if not isinstance(raw, dict):
            continue
        flattened.append(raw)
        children = raw.get("children")
        if isinstance(children, list):
            pending.extend(children)
    return flattened


def collect_storage_device(disk_path: Path, *, provider_spec_verified: bool) -> dict[str, object]:
    findmnt = shutil.which("findmnt")
    lsblk = shutil.which("lsblk")
    if findmnt is None or lsblk is None:
        raise CollectionBlocked("findmnt and lsblk are required on the target Linux host")
    mount_payload = _run_json(
        [findmnt, "--json", "--target", str(disk_path), "--output", "SOURCE,TARGET,FSTYPE,OPTIONS"],
        timeout=15,
    )
    filesystems = mount_payload.get("filesystems")
    if (
        not isinstance(filesystems, list)
        or len(filesystems) != 1
        or not isinstance(filesystems[0], dict)
    ):
        raise CollectionBlocked("target mount identity could not be determined")
    mount = filesystems[0]
    source = str(mount.get("source", ""))
    if not source.startswith("/dev/"):
        raise CollectionBlocked("target data path is not backed by an identifiable block device")
    block_payload = _run_json(
        [
            lsblk,
            "--json",
            "--bytes",
            "--paths",
            "--output",
            "PATH,TYPE,ROTA,MODEL,TRAN",
        ],
        timeout=15,
    )
    raw_devices = block_payload.get("blockdevices")
    if not isinstance(raw_devices, list):
        raise CollectionBlocked("block-device inventory could not be determined")
    device = next(
        (item for item in _flatten_block_devices(raw_devices) if str(item.get("path")) == source),
        None,
    )
    if device is None:
        raise CollectionBlocked("mounted block device was not present in lsblk inventory")
    rota = device.get("rota")
    rotational = None if rota is None else bool(rota)
    return {
        "source": source,
        "mount_target": str(mount.get("target", "")),
        "filesystem_type": str(mount.get("fstype", "")),
        "mount_options": sorted(
            option for option in str(mount.get("options", "")).split(",") if option
        ),
        "device_type": str(device.get("type", "")),
        "rotational": rotational,
        "provider_spec_verified": provider_spec_verified,
        "model": str(device.get("model", "")).strip(),
        "transport": str(device.get("tran", "")).strip(),
    }


def _percentile_ns(section: dict[str, Any], percentile: str) -> float:
    latency = section.get("clat_ns")
    if not isinstance(latency, dict):
        raise CollectionBlocked("fio completion-latency evidence is missing")
    percentiles = latency.get("percentile")
    if not isinstance(percentiles, dict) or percentile not in percentiles:
        raise CollectionBlocked("fio latency percentile evidence is missing")
    return float(percentiles[percentile])


def _parse_fio_result(payload: dict[str, Any], workload: str) -> tuple[float, float, float]:
    jobs = payload.get("jobs")
    if not isinstance(jobs, list) or len(jobs) != 1 or not isinstance(jobs[0], dict):
        raise CollectionBlocked("fio job evidence is incomplete")
    job = jobs[0]
    direction = "read" if workload == "random_read" else "write"
    section = job.get(direction)
    if not isinstance(section, dict):
        raise CollectionBlocked("fio direction evidence is incomplete")
    return (
        float(section.get("iops", 0)),
        _percentile_ns(section, "95.000000") / 1_000_000,
        _percentile_ns(section, "99.000000") / 1_000_000,
    )


def _load_thresholds(path: Path) -> tuple[dict[str, dict[str, float]], str, bool]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise CollectionBlocked("fio threshold evidence must be a bounded regular file")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise CollectionBlocked("fio threshold evidence uses an unsupported schema")
    if not str(payload.get("capacity_test_reference", "")).strip():
        raise CollectionBlocked("fio thresholds must reference an approved capacity test")
    _verify_policy_artifact(
        policy_path=path,
        artifact_value=payload.get("capacity_test_artifact"),
        sha256_value=payload.get("capacity_test_sha256"),
        label="capacity-test",
    )
    raw = payload.get("workloads")
    if not isinstance(raw, dict) or set(raw) != REQUIRED_FIO_WORKLOADS:
        raise CollectionBlocked("fio thresholds must cover every required workload")
    thresholds: dict[str, dict[str, float]] = {}
    for name, value in raw.items():
        if not isinstance(value, dict):
            raise CollectionBlocked("fio threshold entry is malformed")
        minimum_iops = float(value["minimum_iops"])
        maximum_p99 = float(value["maximum_p99_latency_ms"])
        if minimum_iops <= 0 or maximum_p99 <= 0:
            raise CollectionBlocked("fio thresholds must be positive")
        thresholds[name] = {
            "minimum_iops": minimum_iops,
            "maximum_p99_latency_ms": maximum_p99,
        }
    provider_spec_verified = payload.get("provider_spec_verified") is True
    if provider_spec_verified:
        _verify_policy_artifact(
            policy_path=path,
            artifact_value=payload.get("provider_spec_artifact"),
            sha256_value=payload.get("provider_spec_sha256"),
            label="provider-specification",
        )
    return thresholds, _sha256(path), provider_spec_verified


def _verify_policy_artifact(
    *,
    policy_path: Path,
    artifact_value: object,
    sha256_value: object,
    label: str,
) -> None:
    relative = Path(str(artifact_value or ""))
    expected = str(sha256_value or "")
    if not relative.parts or relative.is_absolute():
        raise CollectionBlocked(f"{label} artifact must be a relative file")
    root = policy_path.parent.resolve(strict=True)
    artifact = (root / relative).resolve(strict=True)
    try:
        artifact.relative_to(root)
    except ValueError as error:
        raise CollectionBlocked(f"{label} artifact escapes the policy directory") from error
    if artifact.is_symlink() or not artifact.is_file() or artifact.stat().st_size > 16 * 1024**2:
        raise CollectionBlocked(f"{label} artifact must be a bounded regular file")
    if len(expected) != 64 or _sha256(artifact) != expected:
        raise CollectionBlocked(f"{label} artifact hash mismatch")


def collect_fio(
    *,
    disk_path: Path,
    test_directory: Path,
    block_device: str,
    thresholds: dict[str, dict[str, float]],
    threshold_sha256: str,
    file_bytes: int,
    runtime_seconds: int,
) -> dict[str, object]:
    fio_binary = shutil.which("fio")
    if fio_binary is None:
        raise CollectionBlocked("fio is required on the target Linux host")
    filename = test_directory / f"fio-{uuid.uuid4().hex}.bin"
    descriptor = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    results: list[dict[str, object]] = []
    try:
        for workload in sorted(REQUIRED_FIO_WORKLOADS):
            payload = _run_json(
                build_fio_command(
                    fio_binary=fio_binary,
                    workload=workload,
                    filename=filename,
                    file_bytes=file_bytes,
                    runtime_seconds=runtime_seconds,
                ),
                timeout=runtime_seconds + 30,
            )
            iops, p95, p99 = _parse_fio_result(payload, workload)
            results.append(
                {
                    "name": workload,
                    "observed_iops": iops,
                    "observed_p95_latency_ms": p95,
                    "observed_p99_latency_ms": p99,
                    **thresholds[workload],
                }
            )
    finally:
        filename.unlink(missing_ok=True)
    return {
        "schema_version": 1,
        "test_file_bytes": file_bytes,
        "runtime_seconds": runtime_seconds,
        "direct": True,
        "completed": len(results) == len(REQUIRED_FIO_WORKLOADS),
        "disk_path": str(disk_path.resolve(strict=True)),
        "block_device": block_device,
        "threshold_source_sha256": threshold_sha256,
        "workloads": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect bounded target-host SSD and fio evidence")
    parser.add_argument("--disk-path", type=Path, required=True)
    parser.add_argument("--test-directory", type=Path, required=True)
    parser.add_argument("--challenge", required=True)
    parser.add_argument("--thresholds", type=Path, required=True)
    parser.add_argument("--test-file-gib", type=int, default=1, choices=range(1, 5))
    parser.add_argument("--runtime-seconds", type=int, default=30, choices=range(1, 121))
    arguments = parser.parse_args(argv)
    try:
        if platform.system().casefold() != "linux":
            raise CollectionBlocked("host IO evidence must be collected on the target Linux host")
        directory = validate_test_directory(
            arguments.disk_path, arguments.test_directory, arguments.challenge
        )
        thresholds, threshold_sha256, provider_spec_verified = _load_thresholds(
            arguments.thresholds
        )
        storage = collect_storage_device(
            arguments.disk_path, provider_spec_verified=provider_spec_verified
        )
        fio = collect_fio(
            disk_path=arguments.disk_path,
            test_directory=directory,
            block_device=str(storage["source"]),
            thresholds=thresholds,
            threshold_sha256=threshold_sha256,
            file_bytes=arguments.test_file_gib * GIB,
            runtime_seconds=arguments.runtime_seconds,
        )
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "passed",
                    "storage_device": storage,
                    "fio": fio,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    except (CollectionBlocked, KeyError, TypeError, ValueError, json.JSONDecodeError, OSError):
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "blocked",
                    "reason": "target-host SSD/fio evidence could not be collected safely",
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
