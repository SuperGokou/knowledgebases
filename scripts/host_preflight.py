from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

GIB = 1024**3
GB = 1000**3

MINIMUM_LOGICAL_CPUS = 8
MINIMUM_VISIBLE_MEMORY_BYTES = 15 * GIB
MINIMUM_FILESYSTEM_TOTAL_BYTES = 300 * GB
MINIMUM_FILESYSTEM_AVAILABLE_BYTES = 240 * GB
SUPPORTED_ARCHITECTURES = frozenset({"amd64", "x86_64"})

Status = Literal["passed", "failed", "blocked"]
REQUIRED_FIO_WORKLOADS = frozenset(
    {"sequential_write", "random_read", "random_write", "fsync"}
)
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_FIO_FILE_BYTES = 4 * GIB
MAX_FIO_RUNTIME_SECONDS = 120


@dataclass(frozen=True, slots=True)
class StorageDeviceEvidence:
    source: str
    mount_target: str
    filesystem_type: str
    mount_options: tuple[str, ...]
    device_type: str
    rotational: bool | None
    provider_spec_verified: bool

    def as_mapping(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FioWorkloadEvidence:
    name: str
    observed_iops: float
    observed_p95_latency_ms: float
    observed_p99_latency_ms: float
    minimum_iops: float
    maximum_p99_latency_ms: float

    def as_mapping(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FioEvidence:
    schema_version: int
    test_file_bytes: int
    runtime_seconds: int
    direct: bool
    completed: bool
    disk_path: str
    block_device: str
    threshold_source_sha256: str
    workloads: tuple[FioWorkloadEvidence, ...]

    def as_mapping(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class HostFacts:
    platform: str
    architecture: str
    logical_cpus: int
    memory_bytes: int
    filesystem_total_bytes: int
    filesystem_available_bytes: int
    disk_path: Path
    storage_device: StorageDeviceEvidence | None = None
    fio: FioEvidence | None = None

    def as_mapping(self) -> dict[str, object]:
        return {
            "platform": self.platform,
            "architecture": self.architecture,
            "logical_cpus": self.logical_cpus,
            "memory_bytes": self.memory_bytes,
            "filesystem_total_bytes": self.filesystem_total_bytes,
            "filesystem_available_bytes": self.filesystem_available_bytes,
            "disk_path": self.disk_path,
            "storage_device": self.storage_device,
            "fio": self.fio,
        }


@dataclass(frozen=True, slots=True)
class HostCheck:
    name: str
    passed: bool
    observed: str | int
    required: str | int


@dataclass(frozen=True, slots=True)
class HostAssessment:
    status: Status
    reason: str
    facts: HostFacts
    checks: tuple[HostCheck, ...]


def evaluate_host(facts: HostFacts) -> HostAssessment:
    base_checks = (
        HostCheck("platform", facts.platform.casefold() == "linux", facts.platform, "Linux"),
        HostCheck(
            "architecture",
            facts.architecture.casefold() in SUPPORTED_ARCHITECTURES,
            facts.architecture,
            "amd64 or x86_64",
        ),
        HostCheck(
            "logical_cpus",
            facts.logical_cpus >= MINIMUM_LOGICAL_CPUS,
            facts.logical_cpus,
            MINIMUM_LOGICAL_CPUS,
        ),
        HostCheck(
            "visible_memory",
            facts.memory_bytes >= MINIMUM_VISIBLE_MEMORY_BYTES,
            facts.memory_bytes,
            MINIMUM_VISIBLE_MEMORY_BYTES,
        ),
        HostCheck(
            "filesystem_total",
            facts.filesystem_total_bytes >= MINIMUM_FILESYSTEM_TOTAL_BYTES,
            facts.filesystem_total_bytes,
            MINIMUM_FILESYSTEM_TOTAL_BYTES,
        ),
        HostCheck(
            "filesystem_available",
            facts.filesystem_available_bytes >= MINIMUM_FILESYSTEM_AVAILABLE_BYTES,
            facts.filesystem_available_bytes,
            MINIMUM_FILESYSTEM_AVAILABLE_BYTES,
        ),
    )
    evidence_available = facts.storage_device is not None and facts.fio is not None
    device_passed = evidence_available and _storage_device_matches(facts)
    ssd_passed = evidence_available and _solid_state_verified(facts.storage_device)
    fio_passed = evidence_available and _fio_verified(facts)
    evidence_checks = (
        HostCheck(
            "storage_device_identity",
            bool(device_passed),
            facts.storage_device.source if facts.storage_device else "unavailable",
            "target mount and block device identity",
        ),
        HostCheck(
            "solid_state_storage",
            bool(ssd_passed),
            _rotational_observation(facts.storage_device),
            "non-rotational device or provider specification evidence",
        ),
        HostCheck(
            "bounded_fio",
            bool(fio_passed),
            len(facts.fio.workloads) if facts.fio else 0,
            len(REQUIRED_FIO_WORKLOADS),
        ),
    )
    checks = (*base_checks, *evidence_checks)
    if facts.platform.casefold() != "linux":
        return HostAssessment(
            status="blocked",
            reason="preflight must run on the target Linux host",
            facts=facts,
            checks=checks,
        )
    if not evidence_available:
        return HostAssessment(
            status="blocked",
            reason="target storage device and bounded fio evidence are required",
            facts=facts,
            checks=checks,
        )
    if any(not check.passed for check in checks):
        return HostAssessment(
            status="failed",
            reason="target Linux host does not meet the deployment baseline",
            facts=facts,
            checks=checks,
        )
    return HostAssessment(
        status="passed",
        reason="target Linux host meets the deployment baseline",
        facts=facts,
        checks=checks,
    )


def _path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
    except ValueError:
        return False
    return True


def _storage_device_matches(facts: HostFacts) -> bool:
    device = facts.storage_device
    fio = facts.fio
    if device is None or fio is None:
        return False
    return bool(
        device.source.startswith("/dev/")
        and device.mount_target.startswith("/")
        and device.filesystem_type
        and device.device_type in {"disk", "part", "lvm", "crypt"}
        and "rw" in device.mount_options
        and _path_is_within(facts.disk_path, Path(device.mount_target))
        and fio.block_device == device.source
        and Path(fio.disk_path).resolve(strict=False)
        == facts.disk_path.resolve(strict=False)
    )


def _solid_state_verified(device: StorageDeviceEvidence | None) -> bool:
    if device is None or device.rotational is True:
        return False
    return device.rotational is False or device.provider_spec_verified


def _rotational_observation(device: StorageDeviceEvidence | None) -> str:
    if device is None:
        return "unavailable"
    if device.rotational is None:
        return "unknown/provider-verified" if device.provider_spec_verified else "unknown"
    return "rotational" if device.rotational else "non-rotational"


def _fio_verified(facts: HostFacts) -> bool:
    fio = facts.fio
    if fio is None:
        return False
    names = [item.name for item in fio.workloads]
    return bool(
        fio.schema_version == 1
        and fio.completed
        and fio.direct
        and 64 * 1024**2 <= fio.test_file_bytes <= MAX_FIO_FILE_BYTES
        and 1 <= fio.runtime_seconds <= MAX_FIO_RUNTIME_SECONDS
        and re.fullmatch(r"[0-9a-f]{64}", fio.threshold_source_sha256)
        and len(names) == len(REQUIRED_FIO_WORKLOADS)
        and set(names) == REQUIRED_FIO_WORKLOADS
        and all(
            item.observed_iops >= item.minimum_iops > 0
            and 0 <= item.observed_p95_latency_ms <= item.observed_p99_latency_ms
            <= item.maximum_p99_latency_ms
            for item in fio.workloads
        )
    )


def _load_evidence_json(path: Path) -> dict[str, object]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("host IO evidence must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_EVIDENCE_BYTES:
        raise ValueError("host IO evidence has an invalid size")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("host IO evidence must be a JSON object")
    return value


def load_host_io_evidence(
    evidence_path: Path,
) -> tuple[StorageDeviceEvidence, FioEvidence]:
    payload = _load_evidence_json(evidence_path)
    if payload.get("schema_version") != 1 or payload.get("status") != "passed":
        raise ValueError("host IO evidence is not a completed collector result")
    storage = payload.get("storage_device")
    fio_value = payload.get("fio")
    if not isinstance(storage, dict) or not isinstance(fio_value, dict):
        raise ValueError("host IO evidence is incomplete")
    raw_workloads = fio_value.get("workloads")
    if not isinstance(raw_workloads, list):
        raise ValueError("fio workloads are missing")
    rotational_value = storage.get("rotational")
    if rotational_value is not None and not isinstance(rotational_value, bool):
        raise ValueError("rotational evidence must be boolean or null")
    if not isinstance(storage.get("mount_options"), list):
        raise ValueError("mount options are malformed")
    if not isinstance(fio_value.get("direct"), bool) or not isinstance(
        fio_value.get("completed"), bool
    ):
        raise ValueError("fio completion flags are malformed")
    device = StorageDeviceEvidence(
        source=str(storage["source"]),
        mount_target=str(storage["mount_target"]),
        filesystem_type=str(storage["filesystem_type"]),
        mount_options=tuple(str(item) for item in storage["mount_options"]),
        device_type=str(storage["device_type"]),
        rotational=rotational_value,
        provider_spec_verified=storage.get("provider_spec_verified") is True,
    )
    workloads = tuple(
        FioWorkloadEvidence(
            name=str(item["name"]),
            observed_iops=float(item["observed_iops"]),
            observed_p95_latency_ms=float(item["observed_p95_latency_ms"]),
            observed_p99_latency_ms=float(item["observed_p99_latency_ms"]),
            minimum_iops=float(item["minimum_iops"]),
            maximum_p99_latency_ms=float(item["maximum_p99_latency_ms"]),
        )
        for item in raw_workloads
        if isinstance(item, dict)
    )
    fio = FioEvidence(
        schema_version=int(fio_value["schema_version"]),
        test_file_bytes=int(fio_value["test_file_bytes"]),
        runtime_seconds=int(fio_value["runtime_seconds"]),
        direct=fio_value["direct"],
        completed=fio_value["completed"],
        disk_path=str(fio_value["disk_path"]),
        block_device=str(fio_value["block_device"]),
        threshold_source_sha256=str(fio_value["threshold_source_sha256"]),
        workloads=workloads,
    )
    return device, fio


def _linux_memory_bytes() -> int:
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024
    raise RuntimeError("Linux visible memory could not be determined")


def collect_host_facts(disk_path: Path) -> HostFacts:
    system = platform.system()
    if system.casefold() != "linux":
        return HostFacts(
            platform=system,
            architecture=platform.machine(),
            logical_cpus=os.cpu_count() or 0,
            memory_bytes=0,
            filesystem_total_bytes=0,
            filesystem_available_bytes=0,
            disk_path=disk_path,
        )

    usage = shutil.disk_usage(disk_path)
    affinity = getattr(os, "sched_getaffinity", None)
    logical_cpus = len(affinity(0)) if affinity is not None else (os.cpu_count() or 0)
    return HostFacts(
        platform=system,
        architecture=platform.machine(),
        logical_cpus=logical_cpus,
        memory_bytes=_linux_memory_bytes(),
        filesystem_total_bytes=usage.total,
        filesystem_available_bytes=usage.free,
        disk_path=disk_path,
    )


def render_report(assessment: HostAssessment) -> str:
    payload = {
        "schema_version": 2,
        "status": assessment.status,
        "reason": assessment.reason,
        "target": {
            "platform": "Linux",
            "architecture": ["amd64", "x86_64"],
            "minimum_logical_cpus": MINIMUM_LOGICAL_CPUS,
            "minimum_visible_memory_bytes": MINIMUM_VISIBLE_MEMORY_BYTES,
            "minimum_filesystem_total_bytes": MINIMUM_FILESYSTEM_TOTAL_BYTES,
            "minimum_filesystem_available_bytes": MINIMUM_FILESYSTEM_AVAILABLE_BYTES,
            "required_fio_workloads": sorted(REQUIRED_FIO_WORKLOADS),
        },
        "observed": {
            "platform": assessment.facts.platform,
            "architecture": assessment.facts.architecture,
            "logical_cpus": assessment.facts.logical_cpus,
            "memory_bytes": assessment.facts.memory_bytes,
            "filesystem_total_bytes": assessment.facts.filesystem_total_bytes,
            "filesystem_available_bytes": assessment.facts.filesystem_available_bytes,
            "disk_path": str(assessment.facts.disk_path),
        },
        "checks": [asdict(check) for check in assessment.checks],
        "storage_device": (
            asdict(assessment.facts.storage_device)
            if assessment.facts.storage_device is not None
            else None
        ),
        "fio": (
            asdict(assessment.facts.fio) if assessment.facts.fio is not None else None
        ),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def exit_code_for(assessment: HostAssessment) -> int:
    return {"passed": 0, "failed": 1, "blocked": 2}[assessment.status]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Linux deployment-host acceptance preflight"
    )
    parser.add_argument(
        "--disk-path",
        type=Path,
        default=Path("/srv"),
        help="Existing path on the filesystem that will hold deployment data",
    )
    parser.add_argument(
        "--io-evidence",
        type=Path,
        help="JSON emitted by collect_host_io_evidence.py on the target data mount",
    )
    arguments = parser.parse_args(argv)
    try:
        facts = collect_host_facts(arguments.disk_path)
        if arguments.io_evidence is not None:
            storage_device, fio = load_host_io_evidence(arguments.io_evidence)
            facts = HostFacts(
                platform=facts.platform,
                architecture=facts.architecture,
                logical_cpus=facts.logical_cpus,
                memory_bytes=facts.memory_bytes,
                filesystem_total_bytes=facts.filesystem_total_bytes,
                filesystem_available_bytes=facts.filesystem_available_bytes,
                disk_path=facts.disk_path,
                storage_device=storage_device,
                fio=fio,
            )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError, RuntimeError):
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "blocked",
                    "reason": "target host facts could not be collected",
                    "disk_path": str(arguments.disk_path),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2
    assessment = evaluate_host(facts)
    print(render_report(assessment))
    return exit_code_for(assessment)


if __name__ == "__main__":
    sys.exit(main())
