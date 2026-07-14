from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from scripts.storage_chain_collector import (
    SCENARIO_PLAN,
    CollectionBlocked,
    CollectionContext,
    ScenarioSpec,
    build_execution_plan,
    collect_chain,
    main,
)
from scripts.storage_watermark_preflight import load_chain_evidence


class FakeTransport:
    collector_mode = "fake"

    def __init__(self, *, cleanup_ok: bool = True) -> None:
        self.cleanup_ok = cleanup_ok
        self.executed: list[str] = []
        self.opened = False
        self.closed = False
        self.fail_execution = False

    def open(self, context: CollectionContext) -> dict[str, object]:
        self.opened = True
        return {
            "session_id": "session-acceptance-001",
            "challenge": context.challenge,
            "volume_id": context.volume_id,
            "mount_target": context.mount_target,
            "object_root": context.object_root,
            "knowledge_base_id": context.knowledge_base_id,
            "api_url": context.api_url,
            "deployment_id": context.deployment_id,
            "object_store": "minio",
            "destructive_volume": True,
            "collector_mode": self.collector_mode,
        }

    def execute(self, context: CollectionContext, scenario: ScenarioSpec) -> dict[str, object]:
        if self.fail_execution:
            raise RuntimeError("scenario transport failed")
        self.executed.append(scenario.scenario_id)
        allowed = scenario.expected_reason_code is None
        before = {
            "quota_bytes": 100,
            "object_count": 10,
            "object_bytes": (
                179_000_000_000 if scenario.operation == "object_stop_180gb" else 1_000
            ),
            "multipart_sessions": 0,
        }
        after = dict(before)
        if allowed:
            after.update(
                quota_bytes=101,
                object_count=11,
                object_bytes=int(before["object_bytes"]) + 1,
            )
        return {
            "scenario": {
                "watermark_percent": scenario.watermark_percent,
                "operation": scenario.operation,
                "http_status": 201 if allowed else 507,
                "reason_code": scenario.expected_reason_code,
                "quota_before_bytes": before["quota_bytes"],
                "quota_after_bytes": after["quota_bytes"],
                "object_count_before": before["object_count"],
                "object_count_after": after["object_count"],
                "object_bytes_before": before["object_bytes"],
                "object_bytes_after": after["object_bytes"],
                "multipart_sessions_before": before["multipart_sessions"],
                "multipart_sessions_after": after["multipart_sessions"],
            },
            "filesystem_probe": {
                "used_percent": scenario.watermark_percent,
                "total_bytes": 300_000_000_000,
                "mount_target": context.mount_target,
                "volume_id": context.volume_id,
            },
            "minio_probe": {
                "object_count": after["object_count"],
                "object_bytes": after["object_bytes"],
                "multipart_sessions": after["multipart_sessions"],
                "backend": "minio",
                "bucket": "acceptance",
            },
            "quota_probe": {
                "reserved_bytes": after["quota_bytes"],
                "knowledge_base_id": context.knowledge_base_id,
            },
            "business_api_probe": {
                "api_url": context.api_url,
                "request_ids": [f"request-{scenario.scenario_id}"],
                "request_count": (
                    2 if scenario.operation in {"retry", "concurrent_reservation"} else 1
                ),
                "object_storage_requests": 1 if allowed else 0,
                "operation": scenario.operation,
                "http_status": 201 if allowed else 507,
                "reason_code": scenario.expected_reason_code,
            },
        }

    def cleanup(self, context: CollectionContext) -> dict[str, object]:
        if not self.cleanup_ok:
            raise CollectionBlocked("dedicated acceptance volume cleanup failed")
        return {
            "challenge": context.challenge,
            "volume_id": context.volume_id,
            "objects_remaining": 0,
            "object_bytes_remaining": 0,
            "multipart_sessions_remaining": 0,
            "quota_reservations_remaining": 0,
            "test_records_remaining": 0,
            "completed": True,
        }

    def close(self) -> None:
        self.closed = True


def context(tmp_path: Path) -> CollectionContext:
    return CollectionContext(
        challenge="one-time-challenge-1234567890",
        volume_id="destroyable-volume-01",
        mount_target="/srv/heyi-acceptance",
        object_root="/srv/heyi-acceptance/minio",
        knowledge_base_id="00000000-0000-4000-8000-000000000001",
        api_url="https://kb.internal.example/api/v1",
        deployment_id="deployment-20260713-001",
        git_head="a" * 40,
        content_fingerprint="b" * 64,
        output_directory=tmp_path,
    )


def test_plan_contains_exactly_the_25_required_real_chain_scenarios() -> None:
    plan = build_execution_plan()

    assert len(plan) == 25
    assert len({item.scenario_id for item in plan}) == 25
    assert {(item.watermark_percent, item.operation) for item in plan} == {
        (percent, operation)
        for percent in (69, 70, 79, 80, 89, 90)
        for operation in ("single", "multipart", "retry", "concurrent_reservation")
    } | {(1, "object_stop_180gb")}
    assert plan == SCENARIO_PLAN


def test_cli_defaults_to_non_destructive_dry_run(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["--list-plan"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["mode"] == "dry-run"
    assert payload["destructive"] is False
    assert len(payload["scenarios"]) == 25


def test_destructive_cli_refuses_to_start_without_all_explicit_safety_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        [
            "--execute-destructive",
            "--output-directory",
            str(tmp_path),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["status"] == "blocked"
    assert "challenge" in payload["reason"]
    assert list(tmp_path.iterdir()) == []


def test_fake_transport_can_only_exercise_orchestration_and_never_emit_formal_pass(
    tmp_path: Path,
) -> None:
    transport = FakeTransport()

    manifest = collect_chain(context(tmp_path), transport, allow_test_transport=True)

    assert transport.opened is True
    assert transport.closed is True
    assert transport.executed == [item.scenario_id for item in SCENARIO_PLAN]
    assert manifest["status"] == "test-only"
    assert manifest["collector_mode"] == "fake"
    assert len(manifest["scenarios"]) == 25
    for scenario in manifest["scenarios"]:
        artifact = tmp_path / str(scenario["artifact"])
        assert artifact.is_file()
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == scenario["artifact_sha256"]
    attestation = manifest["attestation"]
    assert isinstance(attestation, dict)
    assert len(str(attestation["digest"])) == 64


def test_cleanup_failure_is_blocked_and_no_pass_manifest_is_written(tmp_path: Path) -> None:
    transport = FakeTransport(cleanup_ok=False)

    with pytest.raises(CollectionBlocked, match="cleanup failed"):
        collect_chain(context(tmp_path), transport, allow_test_transport=True)

    assert transport.closed is True
    assert not (tmp_path / "watermark-chain.json").exists()


def test_cleanup_failure_overrides_an_execution_error_and_remains_blocked(tmp_path: Path) -> None:
    transport = FakeTransport(cleanup_ok=False)
    transport.fail_execution = True

    with pytest.raises(CollectionBlocked, match="cleanup failed"):
        collect_chain(context(tmp_path), transport, allow_test_transport=True)

    assert transport.closed is True
    assert not (tmp_path / "watermark-chain.json").exists()


def test_real_mode_manifest_has_target_identity_artifact_chain_and_zero_leak_cleanup(
    tmp_path: Path,
) -> None:
    transport = FakeTransport()
    transport.collector_mode = "real"

    manifest = collect_chain(context(tmp_path), transport, allow_test_transport=True)

    assert manifest["status"] == "passed"
    assert manifest["target"] == {
        "deployment_id": "deployment-20260713-001",
        "git_head": "a" * 40,
        "content_fingerprint": "b" * 64,
    }
    cleanup = manifest["cleanup"]
    assert isinstance(cleanup, dict)
    cleanup_artifact = tmp_path / str(cleanup["artifact"])
    assert hashlib.sha256(cleanup_artifact.read_bytes()).hexdigest() == cleanup["artifact_sha256"]
    assert manifest["attestation"]["type"] == "sha256-chain-v1"
    assert manifest["attestation"]["artifact_count"] == 26

    loaded = load_chain_evidence(tmp_path / "watermark-chain.json")
    assert loaded.schema_version == 2
    assert loaded.collector_mode == "real"
    assert loaded.git_head == "a" * 40
    assert loaded.content_fingerprint == "b" * 64


def test_preflight_rejects_test_only_fake_collector_evidence(tmp_path: Path) -> None:
    manifest = collect_chain(
        context(tmp_path),
        FakeTransport(),
        allow_test_transport=True,
    )
    assert manifest["status"] == "test-only"

    with pytest.raises(ValueError, match="real collector"):
        load_chain_evidence(tmp_path / "watermark-chain.json")


def test_fake_transport_cannot_self_declare_real_for_formal_collection(tmp_path: Path) -> None:
    transport = FakeTransport()
    transport.collector_mode = "real"

    with pytest.raises(CollectionBlocked, match="real HTTP collector"):
        collect_chain(context(tmp_path), transport)


def test_raw_artifact_never_contains_authorization_or_presigned_credentials(tmp_path: Path) -> None:
    transport = FakeTransport()
    transport.collector_mode = "real"

    manifest = collect_chain(context(tmp_path), transport, allow_test_transport=True)
    serialized = json.dumps(manifest, ensure_ascii=False).casefold()
    for scenario in manifest["scenarios"]:
        serialized += (tmp_path / str(scenario["artifact"])).read_text(encoding="utf-8").casefold()

    for forbidden in (
        "authorization",
        "access_token",
        "refresh_token",
        "secret_key",
        "x-amz-signature",
        "password",
    ):
        assert forbidden not in serialized


def test_scenario_dataclass_serializes_stable_plan_fields() -> None:
    raw = asdict(SCENARIO_PLAN[0])
    assert raw == {
        "scenario_id": "wm-69-single",
        "watermark_percent": 69,
        "operation": "single",
        "expected_reason_code": None,
    }
