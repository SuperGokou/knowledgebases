from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import scripts.enterprise_capacity_gate as capacity_gate
from scripts.enterprise_capacity_gate import GateInputError, evaluate, token_capacity_model
from scripts.load.openai_capacity_stub import CapacityStubServer


def _manifest() -> dict[str, Any]:
    digest = "a" * 64
    return {
        "schema_version": 1,
        "classification": "isolated_capacity_acceptance",
        "evidence_classification": "not_model_capacity",
        "run_id": "cap-20260714-a1b2c3d4",
        "project": "heyi-kb-acceptance-cap-20260714-a1b2c3d4",
        "git_commit": "b" * 40,
        "acceptance": {"isolated": True, "cleanup_required": True},
        "fingerprints": {
            "compose_sha256": digest,
            "non_secret_config_sha256": digest,
            "host_sha256": digest,
            "image_inventory_sha256": digest,
        },
        "resource_sampling": {
            "duration_seconds": 1_800,
            "interval_seconds": 5,
            "expected_samples": 360,
            "maximum_gap_seconds": 7.5,
        },
        "secret_material_included": False,
        "identity_material_included": False,
    }


def _manifest_digest(manifest: Mapping[str, Any], path: Path) -> str:
    path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _binding(manifest: Mapping[str, Any], manifest_sha256: str) -> dict[str, str]:
    fingerprints = manifest["fingerprints"]
    assert isinstance(fingerprints, Mapping)
    return {
        "manifest_sha256": manifest_sha256,
        "run_id": str(manifest["run_id"]),
        "project": str(manifest["project"]),
        "git_commit": str(manifest["git_commit"]),
        "compose_sha256": str(fingerprints["compose_sha256"]),
        "non_secret_config_sha256": str(fingerprints["non_secret_config_sha256"]),
        "host_sha256": str(fingerprints["host_sha256"]),
        "image_inventory_sha256": str(fingerprints["image_inventory_sha256"]),
    }


def _metric(*, count: float | None = None, rate: float | None = None) -> dict[str, float]:
    result: dict[str, float] = {"p95": 100, "p99": 200}
    if count is not None:
        result["count"] = count
    if rate is not None:
        result["rate"] = rate
    return result


def _evidence(
    tmp_path: Path,
) -> tuple[dict[str, Any], list[Mapping[str, Any]], dict[str, Any], dict[str, Any], str]:
    manifest = _manifest()
    digest = _manifest_digest(manifest, tmp_path / "manifest.json")
    binding = _binding(manifest, digest)
    metrics = {
        "identity_attempts": _metric(count=1_000),
        "identity_successes": _metric(count=1_000),
        "control_plane_latency": _metric(),
        "control_plane_success": _metric(rate=1),
        "retrieval_latency": _metric(),
        "retrieval_success": _metric(rate=1),
        "unexpected_5xx": _metric(rate=0),
        "stub_rag_latency": _metric(),
        "stub_rag_success": _metric(rate=1),
        "backpressure_safe": _metric(rate=1),
        "request_rate_limit_contract": _metric(rate=1),
        "upload_limit_contract": _metric(rate=1),
        "download_limit_contract": _metric(rate=1),
        "multipart_attempts": _metric(count=8),
        "multipart_latency": _metric(),
        "multipart_success": _metric(rate=1),
    }
    summary = {
        "schema_version": 1,
        "profile": "formal",
        "classification": "not_model_capacity",
        "isolated_acceptance": True,
        "credential_material_included": False,
        "evidence_binding": binding,
        "configuration": {
            "identity_count": 1_000,
            "steady_duration_seconds": 1_800,
            "chat_mode": "stub",
            "multipart_enabled": True,
        },
        "metrics": metrics,
        "k6_thresholds_passed": True,
    }
    resources: list[Mapping[str, Any]] = []
    for index in range(1, 361):
        resources.append(
            {
                "schema_version": 2,
                "sample_index": index,
                "monotonic_seconds": index * 5,
                "evidence_binding": binding,
                "host": {
                    "logical_cpus": 8,
                    "memory_total_bytes": 16 * 1024**3,
                    "disk_total_bytes": 300_000_000_000,
                    "cpu_percent": 50,
                    "memory_percent": 60,
                    "disk_free_percent": 50,
                },
                "containers": [
                    {
                        "name": "capacity-api-1",
                        "restart_delta": 0,
                        "oom_killed": False,
                    }
                ],
                "postgres": {
                    "active_connections": 20,
                    "deadlocks": 0,
                    "long_transactions": 0,
                },
                "redis": {"evicted_keys": 0, "rejected_connections": 0},
                "errors": [],
            }
        )
    cleanup = {
        "schema_version": 1,
        "classification": "isolated_capacity_cleanup",
        "evidence_classification": "not_model_capacity",
        "run_id": manifest["run_id"],
        "project": manifest["project"],
        "manifest_sha256": digest,
        "containers_absent": True,
        "data_root_absent": True,
        "passed": True,
    }
    return summary, resources, manifest, cleanup, digest


def test_formal_gate_passes_control_plane_without_promoting_stub_claims(tmp_path: Path) -> None:
    summary, resources, manifest, cleanup, digest = _evidence(tmp_path)
    result = evaluate(
        summary,
        resources,
        manifest,
        cleanup,
        manifest_sha256=digest,
        require_llm_stub=True,
        require_quota_contracts=True,
        require_multipart=True,
    )

    assert result["verdict"] == "PASS_CONTROL_PLANE"
    claims = result["capacity_claims"]
    assert claims["five_billion_tokens_per_day"]["status"] == "UNVERIFIED_NO_GO"
    assert claims["ten_tb_storage"]["status"] == "UNVERIFIED_NO_GO"
    assert result["evidence_classification"] == "not_model_capacity"


@pytest.mark.parametrize("mutation", ["sample_gap", "binding", "cleanup"])
def test_formal_gate_rejects_incomplete_or_unbound_evidence(tmp_path: Path, mutation: str) -> None:
    summary, resources, manifest, cleanup, digest = _evidence(tmp_path)
    if mutation == "sample_gap":
        resources.pop(100)
    elif mutation == "binding":
        summary["evidence_binding"]["manifest_sha256"] = "0" * 64
    else:
        cleanup["passed"] = False

    with pytest.raises(GateInputError):
        evaluate(
            summary,
            resources,
            manifest,
            cleanup,
            manifest_sha256=digest,
            require_llm_stub=True,
            require_quota_contracts=True,
            require_multipart=True,
        )


def test_token_model_is_demand_math_not_measured_capacity() -> None:
    model = token_capacity_model()
    assert model["classification"] == "MODELLED_NOT_MEASURED"
    assert model["target_tokens_per_day"] == 5_000_000_000
    assert model["tokens_per_second_24h_average"] == pytest.approx(57_870.37037)


def test_capacity_stub_marks_every_response_not_model_capacity() -> None:
    token = "test-only-capacity-token-32-bytes-long"
    server = CapacityStubServer(
        ("127.0.0.1", 0),
        token=token,
        maximum_concurrency=2,
        default_delay_ms=0,
        allow_markers=True,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        with urllib.request.urlopen(f"{origin}/healthz", timeout=2) as response:
            health = json.load(response)
            assert response.headers["X-Capacity-Classification"] == "not_model_capacity"
            assert health["classification"] == "not_model_capacity"
            assert health["model_evidence"] is False

        request = urllib.request.Request(
            f"{origin}/v1/chat/completions",
            data=json.dumps({"messages": [{"role": "user", "content": "test"}]}).encode(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            body = json.load(response)
            assert response.headers["X-Capacity-Classification"] == "not_model_capacity"
            assert body["capacity_classification"] == "not_model_capacity"

        unauthorized = urllib.request.Request(
            f"{origin}/v1/chat/completions",
            data=b'{"messages":[]}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(unauthorized, timeout=2)
        assert caught.value.code == 401
        assert caught.value.headers["X-Capacity-Classification"] == "not_model_capacity"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_runner_encodes_isolation_cleanup_and_credential_non_leak_contract() -> None:
    runner = Path("scripts/run_enterprise_capacity_gate.sh").read_text(encoding="utf-8")
    assert 'project" != heyi-kb-offline' in runner
    assert "another knowledge-base project is running" in runner
    assert 'rm -rf --one-file-system -- "$data_root"' in runner
    assert "verify-cleanup" in runner
    assert "credential leaked into artifact" in runner
    assert "KB_LOAD_ISOLATED_ACCEPTANCE=1" in runner


def test_capacity_report_is_atomically_published_as_a_private_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "capacity-report.json"
    open_calls: list[tuple[int, int]] = []
    real_open = os.open

    def recording_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if flags & os.O_CREAT:
            open_calls.append((flags, mode))
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("scripts.enterprise_capacity_gate.os.open", recording_open)
    capacity_gate._write_json(output, {"verdict": "PASS_CONTROL_PLANE"})

    assert json.loads(output.read_text(encoding="utf-8")) == {"verdict": "PASS_CONTROL_PLANE"}
    assert len(open_calls) == 1
    flags, mode = open_calls[0]
    assert flags & os.O_CREAT
    assert flags & os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        assert flags & os.O_NOFOLLOW
    assert stat.S_IMODE(mode) == 0o600
    if os.name == "posix":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(tmp_path.glob(f".{output.name}.*.tmp")) == []


def test_capacity_report_rejects_a_symlink_destination(tmp_path: Path) -> None:
    victim = tmp_path / "victim.json"
    victim.write_text("untouched", encoding="utf-8")
    output = tmp_path / "capacity-report.json"
    try:
        output.symlink_to(victim)
    except OSError as error:
        pytest.skip(f"symlink creation unavailable: {error}")

    with pytest.raises(capacity_gate.GateOutputError, match="regular file"):
        capacity_gate._write_json(output, {"verdict": "PASS_CONTROL_PLANE"})

    assert output.is_symlink()
    assert victim.read_text(encoding="utf-8") == "untouched"


def test_capacity_report_preserves_previous_file_when_atomic_publish_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "capacity-report.json"
    output.write_text("previous\n", encoding="utf-8")

    def fail_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr("scripts.enterprise_capacity_gate.os.replace", fail_replace)
    with pytest.raises(capacity_gate.GateOutputError, match="atomically"):
        capacity_gate._write_json(output, {"verdict": "PASS_CONTROL_PLANE"})

    assert output.read_text(encoding="utf-8") == "previous\n"
    assert list(tmp_path.glob(f".{output.name}.*.tmp")) == []
