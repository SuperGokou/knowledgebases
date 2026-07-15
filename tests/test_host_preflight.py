from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from scripts.host_preflight import (
    FioEvidence,
    FioWorkloadEvidence,
    HostFacts,
    StorageDeviceEvidence,
    evaluate_host,
    exit_code_for,
    load_host_io_evidence,
    main,
    render_report,
)

GIB = 1024**3
GB = 1000**3


def compliant_facts() -> HostFacts:
    return HostFacts(
        platform="Linux",
        architecture="x86_64",
        logical_cpus=8,
        memory_bytes=15 * GIB,
        filesystem_total_bytes=300 * GB,
        filesystem_available_bytes=240 * GB,
        disk_path=Path("/srv"),
        storage_device=StorageDeviceEvidence(
            source="/dev/vdb1",
            mount_target="/srv",
            filesystem_type="xfs",
            mount_options=("rw", "noatime"),
            device_type="disk",
            rotational=False,
            provider_spec_verified=False,
        ),
        fio=FioEvidence(
            schema_version=1,
            test_file_bytes=1024**3,
            runtime_seconds=30,
            direct=True,
            completed=True,
            disk_path="/srv",
            block_device="/dev/vdb1",
            threshold_source_sha256="a" * 64,
            workloads=tuple(
                FioWorkloadEvidence(
                    name=name,
                    observed_iops=1000.0,
                    observed_p95_latency_ms=2.0,
                    observed_p99_latency_ms=4.0,
                    minimum_iops=500.0,
                    maximum_p99_latency_ms=10.0,
                )
                for name in ("sequential_write", "random_read", "random_write", "fsync")
            ),
        ),
    )


def test_exact_linux_host_thresholds_pass() -> None:
    assessment = evaluate_host(compliant_facts())

    assert assessment.status == "passed"
    assert exit_code_for(assessment) == 0
    assert all(check.passed for check in assessment.checks)


def test_capacity_only_host_is_blocked_without_storage_identity_and_fio() -> None:
    facts = compliant_facts()
    assessment = evaluate_host(
        HostFacts(
            **{
                **facts.as_mapping(),
                "storage_device": None,
                "fio": None,
            }
        )
    )

    assert assessment.status == "blocked"
    assert "storage device and bounded fio evidence" in assessment.reason


def test_rotational_disk_cannot_pass_as_ssd() -> None:
    facts = compliant_facts()
    assert facts.storage_device is not None
    hdd = StorageDeviceEvidence(**{**facts.storage_device.as_mapping(), "rotational": True})
    assessment = evaluate_host(HostFacts(**{**facts.as_mapping(), "storage_device": hdd}))

    assert assessment.status == "failed"
    assert "solid_state_storage" in {check.name for check in assessment.checks if not check.passed}


def test_unknown_virtual_disk_requires_provider_spec_and_fio() -> None:
    facts = compliant_facts()
    assert facts.storage_device is not None
    unknown = StorageDeviceEvidence(
        **{
            **facts.storage_device.as_mapping(),
            "rotational": None,
            "provider_spec_verified": False,
        }
    )

    assessment = evaluate_host(HostFacts(**{**facts.as_mapping(), "storage_device": unknown}))

    assert assessment.status == "failed"


def test_incomplete_or_under_threshold_fio_fails_closed() -> None:
    facts = compliant_facts()
    assert facts.fio is not None
    workloads = list(facts.fio.workloads)
    workloads[0] = FioWorkloadEvidence(**{**workloads[0].as_mapping(), "observed_iops": 499.0})
    fio = FioEvidence(**{**facts.fio.as_mapping(), "workloads": tuple(workloads)})

    assessment = evaluate_host(HostFacts(**{**facts.as_mapping(), "fio": fio}))

    assert assessment.status == "failed"
    assert "bounded_fio" in {check.name for check in assessment.checks if not check.passed}


@pytest.mark.parametrize(
    ("field", "value", "failed_check"),
    [
        ("architecture", "aarch64", "architecture"),
        ("logical_cpus", 7, "logical_cpus"),
        ("memory_bytes", 15 * GIB - 1, "visible_memory"),
        ("filesystem_total_bytes", 300 * GB - 1, "filesystem_total"),
        ("filesystem_available_bytes", 240 * GB - 1, "filesystem_available"),
    ],
)
def test_target_linux_host_below_any_threshold_fails(
    field: str,
    value: str | int,
    failed_check: str,
) -> None:
    facts = compliant_facts()
    assessment = evaluate_host(
        HostFacts(**{**facts.as_mapping(), field: value})  # type: ignore[arg-type]
    )

    assert assessment.status == "failed"
    assert exit_code_for(assessment) == 1
    assert failed_check in {check.name for check in assessment.checks if not check.passed}


def test_non_linux_environment_is_blocked_even_when_capacity_is_sufficient() -> None:
    facts = compliant_facts()
    assessment = evaluate_host(HostFacts(**{**facts.as_mapping(), "platform": "Windows"}))

    assert assessment.status == "blocked"
    assert assessment.reason == "preflight must run on the target Linux host"
    assert exit_code_for(assessment) == 2


def test_json_report_is_machine_readable_and_contains_no_network_or_secret_fields() -> None:
    payload = json.loads(render_report(evaluate_host(compliant_facts())))

    assert payload["schema_version"] == 2
    assert payload["status"] == "passed"
    assert payload["target"] == {
        "platform": "Linux",
        "architecture": ["amd64", "x86_64"],
        "minimum_logical_cpus": 8,
        "minimum_visible_memory_bytes": 15 * GIB,
        "minimum_filesystem_total_bytes": 300 * GB,
        "minimum_filesystem_available_bytes": 240 * GB,
        "required_fio_workloads": [
            "fsync",
            "random_read",
            "random_write",
            "sequential_write",
        ],
    }
    serialized = json.dumps(payload).lower()
    for forbidden in ("ip_address", "hostname", "password", "credential", "token"):
        assert forbidden not in serialized


def test_unavailable_linux_target_disk_is_blocked_instead_of_fabricating_pass(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("scripts.host_preflight.platform.system", lambda: "Linux")

    def unreadable(_path: Path) -> object:
        raise FileNotFoundError("sensitive operating-system detail")

    monkeypatch.setattr("scripts.host_preflight.shutil.disk_usage", unreadable)

    assert main(["--disk-path", "/missing-data-mount"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert payload["status"] == "blocked"
    assert payload["reason"] == "target host facts could not be collected"
    assert payload["disk_path"].replace("\\", "/").endswith("/missing-data-mount")


def test_io_evidence_loader_rejects_self_reported_or_malformed_booleans(
    tmp_path: Path,
) -> None:
    facts = compliant_facts()
    assert facts.storage_device is not None
    assert facts.fio is not None
    evidence = tmp_path / "host-io.json"
    payload = {
        "schema_version": 1,
        "status": "passed",
        "storage_device": asdict(facts.storage_device),
        "fio": asdict(facts.fio),
    }
    payload["fio"]["direct"] = "false"
    evidence.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="flags"):
        load_host_io_evidence(evidence)

    payload["fio"]["direct"] = True
    payload["status"] = "blocked"
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="completed collector"):
        load_host_io_evidence(evidence)
