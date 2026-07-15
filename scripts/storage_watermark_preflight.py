from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from app.services.storage_capacity import (
    DECIMAL_GB,
    FilesystemCapacity,
    assess_storage_capacity,
)

Status = Literal["passed", "failed", "blocked"]
WATERMARKS = (69, 70, 79, 80, 89, 90)
OPERATIONS = ("single", "multipart", "retry", "concurrent_reservation")
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class WatermarkScenarioEvidence:
    watermark_percent: int
    operation: str
    http_status: int
    reason_code: str | None
    quota_before_bytes: int
    quota_after_bytes: int
    object_count_before: int
    object_count_after: int
    object_bytes_before: int
    object_bytes_after: int
    multipart_sessions_before: int
    multipart_sessions_after: int
    artifact: str
    artifact_sha256: str

    def as_mapping(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class WatermarkChainEvidence:
    schema_version: int
    verified_artifacts: bool
    destructive_volume: bool
    volume_id: str
    mount_target: str
    challenge: str
    filesystem_cross_check: bool
    minio_cross_check: bool
    scenarios: tuple[WatermarkScenarioEvidence, ...]
    collector_mode: str = ""
    status: str = ""
    object_root: str = ""
    knowledge_base_id: str = ""
    deployment_id: str = ""
    git_head: str = ""
    content_fingerprint: str = ""
    started_at: str = ""
    finished_at: str = ""
    cleanup_artifact: str = ""
    cleanup_artifact_sha256: str = ""
    attestation_digest: str = ""

    def as_mapping(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RuntimeStorageFacts:
    platform: str
    disk_path: Path
    object_root: Path
    filesystem: FilesystemCapacity
    object_used_bytes: int
    same_filesystem: bool
    chain_evidence: WatermarkChainEvidence | None = None

    def as_mapping(self) -> dict[str, object]:
        return {
            "platform": self.platform,
            "disk_path": self.disk_path,
            "object_root": self.object_root,
            "filesystem": self.filesystem,
            "object_used_bytes": self.object_used_bytes,
            "same_filesystem": self.same_filesystem,
            "chain_evidence": self.chain_evidence,
        }


@dataclass(frozen=True, slots=True)
class RuntimeStorageAssessment:
    status: Status
    reason: str
    facts: RuntimeStorageFacts
    boundary_controls_verified: bool


def _scenario_expected_allowed(percent: int, operation: str) -> bool:
    return percent < 80 or (percent < 90 and operation == "single")


def _scenario_has_no_rejected_side_effects(item: WatermarkScenarioEvidence) -> bool:
    return bool(
        item.quota_after_bytes == item.quota_before_bytes
        and item.object_count_after == item.object_count_before
        and item.object_bytes_after == item.object_bytes_before
        and item.multipart_sessions_after == item.multipart_sessions_before
    )


def _chain_evidence_verified(evidence: WatermarkChainEvidence | None) -> bool:
    if evidence is None:
        return False
    expected = {(percent, operation) for percent in WATERMARKS for operation in OPERATIONS}
    expected.add((1, "object_stop_180gb"))
    observed = {(item.watermark_percent, item.operation) for item in evidence.scenarios}
    artifacts = [item.artifact for item in evidence.scenarios]
    if not (
        evidence.schema_version == 2
        and evidence.collector_mode == "real"
        and evidence.status == "passed"
        and evidence.verified_artifacts
        and evidence.destructive_volume
        and evidence.volume_id.strip()
        and PurePosixPath(evidence.mount_target).is_absolute()
        and len(evidence.challenge) >= 16
        and evidence.filesystem_cross_check
        and evidence.minio_cross_check
        and PurePosixPath(evidence.object_root).is_absolute()
        and evidence.knowledge_base_id.strip()
        and evidence.deployment_id.strip()
        and re.fullmatch(r"[0-9a-f]{40,64}", evidence.git_head)
        and re.fullmatch(r"[0-9a-f]{64}", evidence.content_fingerprint)
        and evidence.started_at
        and evidence.finished_at
        and evidence.cleanup_artifact
        and re.fullmatch(r"[0-9a-f]{64}", evidence.cleanup_artifact_sha256)
        and re.fullmatch(r"[0-9a-f]{64}", evidence.attestation_digest)
        and observed == expected
        and len(evidence.scenarios) == len(expected)
        and len(set(artifacts)) == len(artifacts)
    ):
        return False
    for item in evidence.scenarios:
        if not item.artifact or not re.fullmatch(r"[0-9a-f]{64}", item.artifact_sha256):
            return False
        if item.operation == "object_stop_180gb":
            if not (
                item.reason_code == "object_storage_stop_line_reached"
                and item.http_status >= 400
                and item.object_bytes_before == 179 * DECIMAL_GB
                and _scenario_has_no_rejected_side_effects(item)
            ):
                return False
            continue
        allowed = _scenario_expected_allowed(item.watermark_percent, item.operation)
        if allowed:
            if not (
                200 <= item.http_status < 300
                and item.reason_code is None
                and item.quota_after_bytes > item.quota_before_bytes
                and item.object_count_after == item.object_count_before + 1
                and item.object_bytes_after > item.object_bytes_before
                and item.multipart_sessions_after == item.multipart_sessions_before
            ):
                return False
        else:
            expected_reason = (
                "storage_capacity_critical"
                if item.watermark_percent == 90
                else "storage_bulk_uploads_paused"
            )
            if not (
                item.http_status >= 400
                and item.reason_code == expected_reason
                and _scenario_has_no_rejected_side_effects(item)
            ):
                return False
    return True


def evaluate_runtime_storage(facts: RuntimeStorageFacts) -> RuntimeStorageAssessment:
    controls_verified = _chain_evidence_verified(facts.chain_evidence)
    if facts.platform.casefold() != "linux":
        return RuntimeStorageAssessment(
            status="blocked",
            reason="storage evidence must be collected on the target Linux host",
            facts=facts,
            boundary_controls_verified=controls_verified,
        )
    if not facts.same_filesystem:
        return RuntimeStorageAssessment(
            status="failed",
            reason="disk path and object root are on different filesystems",
            facts=facts,
            boundary_controls_verified=controls_verified,
        )
    if facts.chain_evidence is None:
        return RuntimeStorageAssessment(
            status="blocked",
            reason="real storage watermark chain evidence is required",
            facts=facts,
            boundary_controls_verified=False,
        )
    if not controls_verified:
        return RuntimeStorageAssessment(
            status="failed",
            reason="storage watermark chain evidence is incomplete or inconsistent",
            facts=facts,
            boundary_controls_verified=False,
        )
    assessment = assess_storage_capacity(
        filesystem=facts.filesystem,
        object_used_bytes=facts.object_used_bytes,
        incoming_bytes=1,
        is_bulk=False,
    )
    if not controls_verified or not assessment.allowed:
        return RuntimeStorageAssessment(
            status="failed",
            reason=assessment.reason_code or "storage boundary controls failed",
            facts=facts,
            boundary_controls_verified=controls_verified,
        )
    return RuntimeStorageAssessment(
        status="passed",
        reason="target storage is below enforced platform stop lines",
        facts=facts,
        boundary_controls_verified=controls_verified,
    )


def _directory_size(root: Path) -> int:
    total = 0
    pending = [root]
    while pending:
        current = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
    return total


def collect_runtime_storage(disk_path: Path, object_root: Path) -> RuntimeStorageFacts:
    system = platform.system()
    if system.casefold() != "linux":
        return RuntimeStorageFacts(
            platform=system,
            disk_path=disk_path,
            object_root=object_root,
            filesystem=FilesystemCapacity(total_bytes=0, used_bytes=0, free_bytes=0),
            object_used_bytes=0,
            same_filesystem=False,
        )
    if not object_root.is_dir():
        raise FileNotFoundError("object storage root is unavailable")
    return RuntimeStorageFacts(
        platform=system,
        disk_path=disk_path,
        object_root=object_root,
        filesystem=FilesystemCapacity.from_path(disk_path),
        object_used_bytes=_directory_size(object_root),
        same_filesystem=os.stat(disk_path).st_dev == os.stat(object_root).st_dev,
    )


def _regular_bounded_file(path: Path, maximum_bytes: int) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("evidence artifact must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
        raise ValueError("evidence artifact size is outside the accepted range")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _raw_artifact_matches(
    artifact: Path,
    raw: dict[str, object],
    *,
    challenge: str,
    target: dict[str, object],
) -> bool:
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return False
    if not (
        payload.get("schema_version") == 2
        and payload.get("producer") == "heyi-storage-watermark-harness"
        and isinstance(payload.get("producer_version"), str)
        and bool(str(payload.get("producer_version", "")).strip())
        and payload.get("collector_mode") == "real"
        and payload.get("challenge") == challenge
        and payload.get("target") == target
    ):
        return False
    result = payload.get("scenario")
    filesystem = payload.get("filesystem_probe")
    minio = payload.get("minio_probe")
    quota = payload.get("quota_probe")
    if not all(isinstance(value, dict) for value in (result, filesystem, minio, quota)):
        return False
    result = cast(dict[str, object], result)
    filesystem = cast(dict[str, object], filesystem)
    minio = cast(dict[str, object], minio)
    quota = cast(dict[str, object], quota)
    filesystem_total_bytes = filesystem.get("total_bytes")
    scenario_keys = (
        "watermark_percent",
        "operation",
        "http_status",
        "reason_code",
        "quota_before_bytes",
        "quota_after_bytes",
        "object_count_before",
        "object_count_after",
        "object_bytes_before",
        "object_bytes_after",
        "multipart_sessions_before",
        "multipart_sessions_after",
    )
    if any(result.get(key) != raw.get(key) for key in scenario_keys):
        return False
    return bool(
        filesystem.get("used_percent") == raw.get("watermark_percent")
        and isinstance(filesystem_total_bytes, int)
        and filesystem_total_bytes > 0
        and minio.get("object_count") == raw.get("object_count_after")
        and minio.get("object_bytes") == raw.get("object_bytes_after")
        and minio.get("multipart_sessions") == raw.get("multipart_sessions_after")
        and quota.get("reserved_bytes") == raw.get("quota_after_bytes")
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _relative_artifact(root: Path, raw_path: object, expected_hash: object) -> Path:
    relative = Path(str(raw_path))
    if relative.is_absolute():
        raise ValueError("evidence artifact must be relative")
    artifact = (root / relative).resolve(strict=True)
    try:
        artifact.relative_to(root)
    except ValueError as error:
        raise ValueError("evidence artifact escapes the evidence directory") from error
    _regular_bounded_file(artifact, MAX_ARTIFACT_BYTES)
    digest = str(expected_hash)
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or _sha256(artifact) != digest:
        raise ValueError("evidence artifact hash mismatch")
    return artifact


def _target_mapping(payload: dict[str, object]) -> dict[str, object]:
    target = payload.get("target")
    if not isinstance(target, dict):
        raise ValueError("storage watermark target identity is missing")
    expected = {"deployment_id", "git_head", "content_fingerprint"}
    if set(target) != expected:
        raise ValueError("storage watermark target identity is malformed")
    if not (
        str(target["deployment_id"]).strip()
        and re.fullmatch(r"[0-9a-f]{40,64}", str(target["git_head"]))
        and re.fullmatch(r"[0-9a-f]{64}", str(target["content_fingerprint"]))
    ):
        raise ValueError("storage watermark target fingerprint is invalid")
    return cast(dict[str, object], target)


def _verify_attestation(payload: dict[str, object]) -> str:
    attestation = payload.get("attestation")
    cleanup = payload.get("cleanup")
    scenarios = payload.get("scenarios")
    if (
        not isinstance(attestation, dict)
        or not isinstance(cleanup, dict)
        or not isinstance(scenarios, list)
    ):
        raise ValueError("storage watermark attestation is missing")
    digest = str(attestation.get("digest", ""))
    if not (
        attestation.get("type") == "sha256-chain-v1"
        and attestation.get("artifact_count") == len(scenarios) + 1
        and re.fullmatch(r"[0-9a-f]{64}", digest)
    ):
        raise ValueError("storage watermark attestation is malformed")
    chain = {
        "schema_version": payload.get("schema_version"),
        "producer": payload.get("producer"),
        "producer_version": payload.get("producer_version"),
        "collector_mode": payload.get("collector_mode"),
        "challenge": payload.get("challenge"),
        "target": payload.get("target"),
        "volume_id": payload.get("volume_id"),
        "mount_target": payload.get("mount_target"),
        "object_root": payload.get("object_root"),
        "knowledge_base_id": payload.get("knowledge_base_id"),
        "started_at": payload.get("started_at"),
        "finished_at": payload.get("finished_at"),
        "artifacts": [
            {"artifact": item.get("artifact"), "sha256": item.get("artifact_sha256")}
            for item in scenarios
            if isinstance(item, dict)
        ]
        + [
            {
                "artifact": cleanup.get("artifact"),
                "sha256": cleanup.get("artifact_sha256"),
            }
        ],
    }
    if hashlib.sha256(_canonical_json(chain)).hexdigest() != digest:
        raise ValueError("storage watermark attestation digest mismatch")
    return digest


def load_chain_evidence(path: Path) -> WatermarkChainEvidence:
    _regular_bounded_file(path, MAX_EVIDENCE_BYTES)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("scenarios"), list):
        raise ValueError("storage watermark evidence is malformed")
    challenge = str(payload.get("challenge", ""))
    if not (
        payload.get("schema_version") == 2
        and payload.get("producer") == "heyi-storage-watermark-harness"
        and isinstance(payload.get("producer_version"), str)
        and payload.get("collector_mode") == "real"
        and payload.get("status") == "passed"
        and challenge
    ):
        raise ValueError("storage watermark evidence requires a completed real collector")
    target = _target_mapping(payload)
    attestation_digest = _verify_attestation(payload)
    root = path.parent.resolve(strict=True)
    scenarios: list[WatermarkScenarioEvidence] = []
    for raw in payload["scenarios"]:
        if not isinstance(raw, dict):
            raise ValueError("storage watermark scenario is malformed")
        relative = Path(str(raw["artifact"]))
        expected_hash = str(raw["artifact_sha256"])
        artifact = _relative_artifact(root, relative, expected_hash)
        if not _raw_artifact_matches(artifact, raw, challenge=challenge, target=target):
            raise ValueError("raw evidence artifact does not match its scenario")
        scenarios.append(
            WatermarkScenarioEvidence(
                watermark_percent=int(raw["watermark_percent"]),
                operation=str(raw["operation"]),
                http_status=int(raw["http_status"]),
                reason_code=(str(raw["reason_code"]) if raw.get("reason_code") else None),
                quota_before_bytes=int(raw["quota_before_bytes"]),
                quota_after_bytes=int(raw["quota_after_bytes"]),
                object_count_before=int(raw["object_count_before"]),
                object_count_after=int(raw["object_count_after"]),
                object_bytes_before=int(raw["object_bytes_before"]),
                object_bytes_after=int(raw["object_bytes_after"]),
                multipart_sessions_before=int(raw["multipart_sessions_before"]),
                multipart_sessions_after=int(raw["multipart_sessions_after"]),
                artifact=str(relative.as_posix()),
                artifact_sha256=expected_hash,
            )
        )
    cleanup = payload.get("cleanup")
    if not isinstance(cleanup, dict):
        raise ValueError("storage watermark cleanup proof is missing")
    cleanup_relative = Path(str(cleanup.get("artifact", "")))
    cleanup_hash = str(cleanup.get("artifact_sha256", ""))
    cleanup_artifact = _relative_artifact(root, cleanup_relative, cleanup_hash)
    cleanup_payload = json.loads(cleanup_artifact.read_text(encoding="utf-8"))
    if not isinstance(cleanup_payload, dict) or not (
        cleanup_payload.get("schema_version") == 2
        and cleanup_payload.get("producer") == "heyi-storage-watermark-harness"
        and cleanup_payload.get("collector_mode") == "real"
        and cleanup_payload.get("challenge") == challenge
        and cleanup_payload.get("target") == target
        and isinstance(cleanup_payload.get("cleanup"), dict)
    ):
        raise ValueError("storage watermark cleanup artifact is invalid")
    cleanup_result = cast(dict[str, object], cleanup_payload["cleanup"])
    if cleanup_result.get("completed") is not True or any(
        cleanup_result.get(key) != 0
        for key in (
            "objects_remaining",
            "object_bytes_remaining",
            "multipart_sessions_remaining",
            "quota_reservations_remaining",
            "test_records_remaining",
        )
    ):
        raise ValueError("storage watermark cleanup left residual state")
    evidence = WatermarkChainEvidence(
        schema_version=int(payload["schema_version"]),
        verified_artifacts=True,
        destructive_volume=payload.get("destructive_volume") is True,
        volume_id=str(payload["volume_id"]),
        mount_target=str(payload["mount_target"]),
        challenge=challenge,
        filesystem_cross_check=payload.get("filesystem_cross_check") is True,
        minio_cross_check=payload.get("minio_cross_check") is True,
        scenarios=tuple(scenarios),
        collector_mode=str(payload.get("collector_mode", "")),
        status=str(payload.get("status", "")),
        object_root=str(payload.get("object_root", "")),
        knowledge_base_id=str(payload.get("knowledge_base_id", "")),
        deployment_id=str(target["deployment_id"]),
        git_head=str(target["git_head"]),
        content_fingerprint=str(target["content_fingerprint"]),
        started_at=str(payload.get("started_at", "")),
        finished_at=str(payload.get("finished_at", "")),
        cleanup_artifact=cleanup_relative.as_posix(),
        cleanup_artifact_sha256=cleanup_hash,
        attestation_digest=attestation_digest,
    )
    if not _chain_evidence_verified(evidence):
        raise ValueError("storage watermark chain evidence does not satisfy the contract")
    return evidence


def render_report(assessment: RuntimeStorageAssessment) -> str:
    facts = assessment.facts
    payload = {
        "schema_version": 2,
        "status": assessment.status,
        "reason": assessment.reason,
        "policy": {
            "warning_percent": 70,
            "bulk_stop_percent": 80,
            "reject_percent": 90,
            "object_stop_bytes": 180 * DECIMAL_GB,
            "boundary_controls_verified": assessment.boundary_controls_verified,
        },
        "observed": {
            "platform": facts.platform,
            "disk_path": str(facts.disk_path),
            "object_root": str(facts.object_root),
            "filesystem_total_bytes": facts.filesystem.total_bytes,
            "filesystem_used_bytes": facts.filesystem.used_bytes,
            "filesystem_free_bytes": facts.filesystem.free_bytes,
            "object_used_bytes": facts.object_used_bytes,
            "same_filesystem": facts.same_filesystem,
            "chain_scenario_count": (
                len(facts.chain_evidence.scenarios) if facts.chain_evidence else 0
            ),
            "destructive_volume_id": (
                facts.chain_evidence.volume_id if facts.chain_evidence else None
            ),
        },
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def exit_code_for(assessment: RuntimeStorageAssessment) -> int:
    return {"passed": 0, "failed": 1, "blocked": 2}[assessment.status]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Linux storage watermark acceptance preflight"
    )
    parser.add_argument("--disk-path", type=Path, required=True)
    parser.add_argument("--object-root", type=Path, required=True)
    parser.add_argument(
        "--chain-evidence",
        type=Path,
        help="real API-chain evidence bundle from a dedicated destroyable target volume",
    )
    arguments = parser.parse_args(argv)
    try:
        facts = collect_runtime_storage(arguments.disk_path, arguments.object_root)
        if arguments.chain_evidence is not None:
            evidence = load_chain_evidence(arguments.chain_evidence)
            facts = RuntimeStorageFacts(
                platform=facts.platform,
                disk_path=facts.disk_path,
                object_root=facts.object_root,
                filesystem=facts.filesystem,
                object_used_bytes=facts.object_used_bytes,
                same_filesystem=facts.same_filesystem,
                chain_evidence=evidence,
            )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError, RuntimeError):
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "blocked",
                    "reason": "target Linux storage evidence could not be collected",
                    "disk_path": str(arguments.disk_path),
                    "object_root": str(arguments.object_root),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2
    assessment = evaluate_runtime_storage(facts)
    print(render_report(assessment))
    return exit_code_for(assessment)


if __name__ == "__main__":
    sys.exit(main())
