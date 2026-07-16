from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from app.services.storage_capacity import DECIMAL_GB, FilesystemCapacity
from scripts.storage_watermark_preflight import (
    RuntimeStorageFacts,
    WatermarkChainEvidence,
    WatermarkScenarioEvidence,
    evaluate_runtime_storage,
    exit_code_for,
    load_chain_evidence,
    render_report,
)


def compliant_facts() -> RuntimeStorageFacts:
    return RuntimeStorageFacts(
        platform="Linux",
        disk_path=Path("/srv/data"),
        object_root=Path("/srv/data/minio"),
        filesystem=FilesystemCapacity(
            total_bytes=300 * DECIMAL_GB,
            used_bytes=69 * 3 * DECIMAL_GB,
            free_bytes=93 * DECIMAL_GB,
        ),
        object_used_bytes=100 * DECIMAL_GB,
        same_filesystem=True,
        chain_evidence=valid_chain_evidence(),
    )


def valid_chain_evidence() -> WatermarkChainEvidence:
    scenarios: list[WatermarkScenarioEvidence] = []
    for percent in (69, 70, 79, 80, 89, 90):
        for operation in ("single", "multipart", "retry", "concurrent_reservation"):
            allowed = percent < 80 or (percent < 90 and operation == "single")
            scenarios.append(
                WatermarkScenarioEvidence(
                    watermark_percent=percent,
                    operation=operation,
                    http_status=201 if allowed else 409,
                    reason_code=None
                    if allowed
                    else (
                        "storage_capacity_critical"
                        if percent == 90
                        else "storage_bulk_uploads_paused"
                    ),
                    quota_before_bytes=100,
                    quota_after_bytes=101 if allowed else 100,
                    object_count_before=10,
                    object_count_after=11 if allowed else 10,
                    object_bytes_before=1000,
                    object_bytes_after=1001 if allowed else 1000,
                    multipart_sessions_before=0,
                    multipart_sessions_after=0,
                    artifact=f"raw/{percent}-{operation}.json",
                    artifact_sha256="b" * 64,
                )
            )
    scenarios.append(
        WatermarkScenarioEvidence(
            watermark_percent=1,
            operation="object_stop_180gb",
            http_status=409,
            reason_code="object_storage_stop_line_reached",
            quota_before_bytes=100,
            quota_after_bytes=100,
            object_count_before=10,
            object_count_after=10,
            object_bytes_before=179 * DECIMAL_GB,
            object_bytes_after=179 * DECIMAL_GB,
            multipart_sessions_before=0,
            multipart_sessions_after=0,
            artifact="raw/object-stop.json",
            artifact_sha256="c" * 64,
        )
    )
    return WatermarkChainEvidence(
        schema_version=2,
        verified_artifacts=True,
        destructive_volume=True,
        volume_id="acceptance-volume-01",
        mount_target="/srv/acceptance-volume",
        challenge="challenge-1234567890",
        filesystem_cross_check=True,
        minio_cross_check=True,
        scenarios=tuple(scenarios),
        collector_mode="real",
        status="passed",
        object_root="/srv/acceptance-volume/minio",
        knowledge_base_id="00000000-0000-4000-8000-000000000001",
        deployment_id="deployment-001",
        git_head="a" * 40,
        content_fingerprint="b" * 64,
        started_at="2026-07-13T00:00:00+00:00",
        finished_at="2026-07-13T00:01:00+00:00",
        cleanup_artifact="raw/cleanup.json",
        cleanup_artifact_sha256="d" * 64,
        attestation_digest="e" * 64,
    )


def test_target_linux_storage_evidence_passes_below_enforced_stop_lines() -> None:
    assessment = evaluate_runtime_storage(compliant_facts())

    assert assessment.status == "passed"
    assert assessment.boundary_controls_verified is True
    assert exit_code_for(assessment) == 0


def test_non_linux_storage_evidence_is_blocked() -> None:
    facts = compliant_facts()
    assessment = evaluate_runtime_storage(
        RuntimeStorageFacts(
            platform="Windows",
            disk_path=facts.disk_path,
            object_root=facts.object_root,
            filesystem=facts.filesystem,
            object_used_bytes=facts.object_used_bytes,
            same_filesystem=True,
            chain_evidence=facts.chain_evidence,
        )
    )

    assert assessment.status == "blocked"
    assert exit_code_for(assessment) == 2


def test_critical_filesystem_or_object_stop_line_fails() -> None:
    facts = compliant_facts()
    for filesystem, object_used in (
        (
            FilesystemCapacity(
                total_bytes=300 * DECIMAL_GB,
                used_bytes=270 * DECIMAL_GB,
                free_bytes=30 * DECIMAL_GB,
            ),
            facts.object_used_bytes,
        ),
        (facts.filesystem, 180 * DECIMAL_GB),
    ):
        assessment = evaluate_runtime_storage(
            RuntimeStorageFacts(
                platform="Linux",
                disk_path=facts.disk_path,
                object_root=facts.object_root,
                filesystem=filesystem,
                object_used_bytes=object_used,
                same_filesystem=True,
                chain_evidence=facts.chain_evidence,
            )
        )
        assert assessment.status == "failed"
        assert exit_code_for(assessment) == 1


def test_unrelated_disk_path_cannot_be_used_as_storage_evidence() -> None:
    facts = compliant_facts()
    assessment = evaluate_runtime_storage(
        RuntimeStorageFacts(
            platform="Linux",
            disk_path=facts.disk_path,
            object_root=facts.object_root,
            filesystem=facts.filesystem,
            object_used_bytes=facts.object_used_bytes,
            same_filesystem=False,
            chain_evidence=facts.chain_evidence,
        )
    )

    assert assessment.status == "failed"
    assert assessment.reason == "disk path and object root are on different filesystems"


def test_runtime_capacity_without_real_chain_evidence_is_blocked() -> None:
    facts = compliant_facts()
    assessment = evaluate_runtime_storage(
        RuntimeStorageFacts(
            platform=facts.platform,
            disk_path=facts.disk_path,
            object_root=facts.object_root,
            filesystem=facts.filesystem,
            object_used_bytes=facts.object_used_bytes,
            same_filesystem=facts.same_filesystem,
            chain_evidence=None,
        )
    )

    assert assessment.status == "blocked"
    assert assessment.boundary_controls_verified is False


def test_rejected_scenario_with_quota_or_object_leak_fails() -> None:
    facts = compliant_facts()
    assert facts.chain_evidence is not None
    scenarios = list(facts.chain_evidence.scenarios)
    rejected = next(index for index, item in enumerate(scenarios) if item.http_status >= 400)
    scenarios[rejected] = WatermarkScenarioEvidence(
        **{**scenarios[rejected].as_mapping(), "object_count_after": 11}
    )
    evidence = WatermarkChainEvidence(
        **{**facts.chain_evidence.as_mapping(), "scenarios": tuple(scenarios)}
    )
    assessment = evaluate_runtime_storage(
        RuntimeStorageFacts(**{**facts.as_mapping(), "chain_evidence": evidence})
    )

    assert assessment.status == "failed"
    assert assessment.boundary_controls_verified is False


def test_report_is_machine_readable_and_does_not_expose_host_identity() -> None:
    payload = json.loads(render_report(evaluate_runtime_storage(compliant_facts())))

    assert payload["schema_version"] == 2
    assert payload["policy"] == {
        "warning_percent": 70,
        "bulk_stop_percent": 80,
        "reject_percent": 90,
        "object_stop_bytes": 180 * DECIMAL_GB,
        "boundary_controls_verified": True,
    }
    serialized = json.dumps(payload).lower()
    for forbidden in ("hostname", "ip_address", "password", "credential", "token"):
        assert forbidden not in serialized


def test_chain_evidence_loader_verifies_every_raw_artifact(tmp_path: Path) -> None:
    evidence = valid_chain_evidence()
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    scenarios: list[dict[str, object]] = []
    for scenario in evidence.scenarios:
        artifact = tmp_path / scenario.artifact
        value = asdict(scenario)
        raw_scenario = {
            key: item for key, item in value.items() if key not in {"artifact", "artifact_sha256"}
        }
        artifact.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "producer": "heyi-storage-watermark-harness",
                    "producer_version": "2.0.0",
                    "collector_mode": "real",
                    "challenge": evidence.challenge,
                    "target": {
                        "deployment_id": evidence.deployment_id,
                        "git_head": evidence.git_head,
                        "content_fingerprint": evidence.content_fingerprint,
                    },
                    "scenario": raw_scenario,
                    "filesystem_probe": {
                        "used_percent": scenario.watermark_percent,
                        "total_bytes": 300 * DECIMAL_GB,
                    },
                    "minio_probe": {
                        "object_count": scenario.object_count_after,
                        "object_bytes": scenario.object_bytes_after,
                        "multipart_sessions": scenario.multipart_sessions_after,
                    },
                    "quota_probe": {"reserved_bytes": scenario.quota_after_bytes},
                }
            ),
            encoding="utf-8",
        )
        value["artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
        scenarios.append(value)
    manifest = tmp_path / "watermark-chain.json"
    payload = asdict(evidence)
    payload["scenarios"] = scenarios
    payload.pop("verified_artifacts")
    payload["producer"] = "heyi-storage-watermark-harness"
    payload["producer_version"] = "2.0.0"
    payload["status"] = "passed"
    payload["target"] = {
        "deployment_id": evidence.deployment_id,
        "git_head": evidence.git_head,
        "content_fingerprint": evidence.content_fingerprint,
    }
    for key in (
        "deployment_id",
        "git_head",
        "content_fingerprint",
        "cleanup_artifact",
        "cleanup_artifact_sha256",
        "attestation_digest",
    ):
        payload.pop(key)
    cleanup = raw_dir / "cleanup.json"
    cleanup.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "producer": "heyi-storage-watermark-harness",
                "producer_version": "2.0.0",
                "collector_mode": "real",
                "challenge": evidence.challenge,
                "target": payload["target"],
                "cleanup": {
                    "completed": True,
                    "objects_remaining": 0,
                    "object_bytes_remaining": 0,
                    "multipart_sessions_remaining": 0,
                    "quota_reservations_remaining": 0,
                    "test_records_remaining": 0,
                },
            }
        ),
        encoding="utf-8",
    )
    payload["cleanup"] = {
        "artifact": "raw/cleanup.json",
        "artifact_sha256": hashlib.sha256(cleanup.read_bytes()).hexdigest(),
    }
    chain = {
        "schema_version": payload["schema_version"],
        "producer": payload["producer"],
        "producer_version": payload["producer_version"],
        "collector_mode": payload["collector_mode"],
        "challenge": payload["challenge"],
        "target": payload["target"],
        "volume_id": payload["volume_id"],
        "mount_target": payload["mount_target"],
        "object_root": payload["object_root"],
        "knowledge_base_id": payload["knowledge_base_id"],
        "started_at": payload["started_at"],
        "finished_at": payload["finished_at"],
        "artifacts": [
            {"artifact": item["artifact"], "sha256": item["artifact_sha256"]} for item in scenarios
        ]
        + [
            {
                "artifact": payload["cleanup"]["artifact"],
                "sha256": payload["cleanup"]["artifact_sha256"],
            }
        ],
    }
    payload["attestation"] = {
        "type": "sha256-chain-v1",
        "artifact_count": 26,
        "digest": hashlib.sha256(
            json.dumps(chain, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    loaded = load_chain_evidence(manifest)

    assert loaded.verified_artifacts is True
    assert len(loaded.scenarios) == 25

    first_artifact = tmp_path / loaded.scenarios[0].artifact
    first_artifact.write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        load_chain_evidence(manifest)
