from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.collect_host_io_evidence import (
    MARKER_NAME,
    CollectionBlocked,
    _load_thresholds,
    build_fio_command,
    main,
    validate_test_directory,
)


def test_destroyable_directory_requires_matching_marker_and_no_other_files(
    tmp_path: Path,
) -> None:
    challenge = "target-volume-challenge"
    test_directory = tmp_path / "acceptance"
    test_directory.mkdir()

    with pytest.raises(CollectionBlocked, match="marker"):
        validate_test_directory(tmp_path, test_directory, challenge)

    (test_directory / MARKER_NAME).write_text(challenge, encoding="utf-8")
    assert validate_test_directory(tmp_path, test_directory, challenge) == test_directory

    (test_directory / "business-data.txt").write_text("do not touch", encoding="utf-8")
    with pytest.raises(CollectionBlocked, match="empty"):
        validate_test_directory(tmp_path, test_directory, challenge)


def test_fio_command_is_direct_bounded_and_uses_only_the_dedicated_file(
    tmp_path: Path,
) -> None:
    target = tmp_path / "fio.bin"
    command = build_fio_command(
        fio_binary="/usr/bin/fio",
        workload="random_write",
        filename=target,
        file_bytes=1024**3,
        runtime_seconds=30,
    )

    assert command[0] == "/usr/bin/fio"
    assert f"--filename={target}" in command
    assert "--direct=1" in command
    assert "--runtime=30" in command
    assert "--size=1073741824" in command
    assert "--rw=randwrite" in command
    assert all("--directory=" not in item for item in command)


def test_fio_command_rejects_unbounded_inputs(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="size"):
        build_fio_command(
            fio_binary="fio",
            workload="fsync",
            filename=tmp_path / "fio.bin",
            file_bytes=5 * 1024**3,
            runtime_seconds=30,
        )


def test_collector_on_non_linux_is_blocked_without_touching_a_disk(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "scripts.collect_host_io_evidence.platform.system", lambda: "Windows"
    )

    result = main(
        [
            "--disk-path",
            "/srv",
            "--test-directory",
            "/srv/acceptance",
            "--challenge",
            "target-volume-challenge",
            "--thresholds",
            "thresholds.json",
        ]
    )

    assert result == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "blocked"
    assert "hostname" not in payload


def test_thresholds_require_hashed_capacity_and_provider_artifacts(tmp_path: Path) -> None:
    capacity = tmp_path / "capacity.json"
    provider = tmp_path / "provider.pdf"
    capacity.write_text('{"approved":true}', encoding="utf-8")
    provider.write_bytes(b"approved-volume-spec")
    policy = tmp_path / "thresholds.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "capacity_test_reference": "CAP-2026-001",
                "capacity_test_artifact": capacity.name,
                "capacity_test_sha256": hashlib.sha256(capacity.read_bytes()).hexdigest(),
                "provider_spec_verified": True,
                "provider_spec_artifact": provider.name,
                "provider_spec_sha256": hashlib.sha256(provider.read_bytes()).hexdigest(),
                "workloads": {
                    name: {"minimum_iops": 1, "maximum_p99_latency_ms": 100}
                    for name in (
                        "sequential_write",
                        "random_read",
                        "random_write",
                        "fsync",
                    )
                },
            }
        ),
        encoding="utf-8",
    )

    thresholds, digest, provider_verified = _load_thresholds(policy)

    assert set(thresholds) == {
        "sequential_write",
        "random_read",
        "random_write",
        "fsync",
    }
    assert len(digest) == 64
    assert provider_verified is True

    provider.write_bytes(b"tampered")
    with pytest.raises(CollectionBlocked, match="hash mismatch"):
        _load_thresholds(policy)
