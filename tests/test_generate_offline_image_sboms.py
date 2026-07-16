from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from scripts.generate_offline_image_sboms import (
    ImageSbomContractError,
    generate_image_sboms,
    parse_image_manifest,
)

RELEASE_GIT_SHA = "a" * 40
RELEASE_ID = "2026.07.14-1"
REPOSITORIES_AND_TAGS = (
    ("heyi-mirror/docker.io/clamav/clamav", "1.4.3"),
    ("heyi-mirror/docker.io/library/caddy", "2.10.2-alpine"),
    ("heyi-mirror/docker.io/library/postgres", "17.5-bookworm"),
    ("heyi-mirror/docker.io/library/redis", "8.0.3-bookworm"),
    ("heyi-mirror/quay.io/minio/mc", "RELEASE.2025-04-16T18-13-26Z"),
    ("heyi-mirror/quay.io/minio/minio", "RELEASE.2025-04-22T22-12-26Z"),
    ("heyi-release/api", "r1"),
    ("heyi-release/migration", "r1"),
    ("heyi-release/web", "r1"),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest_rows() -> list[str]:
    manifest_digests = "123456789"
    config_digests = "abcdef012"
    return [
        (
            f"127.0.0.1:5000/{repository}:{tag}"
            f"@sha256:{manifest_digests[index] * 64}"
            f"\tsha256:{config_digests[index] * 64}\tlinux\tamd64"
        )
        for index, (repository, tag) in enumerate(REPOSITORIES_AND_TAGS)
    ]


def _write_manifest(root: Path, rows: list[str] | None = None) -> Path:
    manifest = root / "release.env.images"
    manifest.write_text("\n".join(rows or _manifest_rows()) + "\n", encoding="utf-8")
    return manifest


def _write_scanner(parent: Path) -> tuple[Path, str]:
    scanner = (parent / "syft").resolve()
    scanner.write_bytes(b"pinned-test-scanner\n")
    return scanner, _sha256(scanner)


def _fake_runner(command: Sequence[str], environment: dict[str, str], timeout: int) -> None:
    assert command[1] == "scan"
    assert command[3] == "-o"
    assert environment["SYFT_CHECK_FOR_APP_UPDATE"] == "false"
    assert not {key.casefold() for key in environment} & {
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
    assert timeout == 900
    output = Path(command[4].removeprefix("cyclonedx-json="))
    output.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"bom-ref": "z", "name": "z", "type": "library"},
                    {"bom-ref": "a", "name": "a", "type": "library"},
                ],
                "metadata": {
                    "timestamp": "2026-07-14T00:00:00Z",
                    "properties": [{"name": "scanner.property", "value": "stable"}],
                },
                "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
                "specVersion": "1.6",
                "version": 1,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _generate(root: Path, scanner: Path, scanner_sha256: str) -> dict[str, object]:
    return generate_image_sboms(
        artifact_root=root,
        image_manifest=_write_manifest(root),
        output_dir=root / "sbom",
        scanner=scanner,
        scanner_sha256=scanner_sha256,
        release_id=RELEASE_ID,
        release_git_sha=RELEASE_GIT_SHA,
        runner=_fake_runner,
    )


def test_manifest_contract_covers_the_complete_nine_image_release_set(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)

    images = parse_image_manifest(manifest)

    assert len(images) == 9
    assert [
        image.reference.split("@", 1)[0].removeprefix("127.0.0.1:5000/").rsplit(":", 1)[0]
        for image in images
    ] == [repository for repository, _tag in REPOSITORIES_AND_TAGS]
    assert len({image.reference for image in images}) == 9
    assert len({image.manifest_digest for image in images}) == 9
    assert len({image.config_id for image in images}) == 9


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        (_manifest_rows()[:-1], None),
        (_manifest_rows() + [_manifest_rows()[0]], "duplicate reference"),
        (
            [*_manifest_rows()[:-1], _manifest_rows()[-1].replace("9" * 64, "8" * 64)],
            "duplicate manifest digest",
        ),
        ([_manifest_rows()[0].replace("\tlinux\tamd64", "\tlinux\tarm64")], "linux/amd64"),
        ([_manifest_rows()[0].rsplit("\t", 1)[0]], "exactly four"),
    ],
)
def test_manifest_rejects_duplicates_and_invalid_rows(
    tmp_path: Path, rows: list[str], message: str | None
) -> None:
    manifest = _write_manifest(tmp_path, rows)
    if message is None:
        assert len(parse_image_manifest(manifest)) == 8
        return

    with pytest.raises(ImageSbomContractError, match=message):
        parse_image_manifest(manifest)


def test_generation_binds_every_manifest_image_and_is_byte_stable(tmp_path: Path) -> None:
    scanner, scanner_sha256 = _write_scanner(tmp_path)
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()

    first_report = _generate(first_root, scanner, scanner_sha256)
    second_report = _generate(second_root, scanner, scanner_sha256)

    assert first_report["status"] == "PASS"
    assert first_report["image_count"] == 9
    assert first_report["index_sha256"] == second_report["index_sha256"]
    first_files = sorted(
        path.relative_to(first_root / "sbom") for path in (first_root / "sbom").iterdir()
    )
    second_files = sorted(
        path.relative_to(second_root / "sbom") for path in (second_root / "sbom").iterdir()
    )
    assert first_files == second_files
    assert all(
        (first_root / "sbom" / relative).read_bytes()
        == (second_root / "sbom" / relative).read_bytes()
        for relative in first_files
    )

    index = json.loads((first_root / "sbom" / "image-sbom-index.json").read_text())
    assert index["release_git_sha"] == RELEASE_GIT_SHA
    assert index["source_manifest_sha256"] == _sha256(first_root / "release.env.images")
    assert len(index["images"]) == 9
    for record in index["images"]:
        sbom_path = first_root / record["sbom_path"]
        assert _sha256(sbom_path) == record["sbom_sha256"]
        sbom = json.loads(sbom_path.read_text())
        assert "serialNumber" not in sbom
        assert "timestamp" not in sbom["metadata"]
        properties = {item["name"]: item["value"] for item in sbom["metadata"]["properties"]}
        assert properties["io.heyi.image.reference"] == record["reference"]
        assert properties["io.heyi.image.manifest_digest"] == record["manifest_digest"]
        assert properties["io.heyi.image.config_id"] == record["config_id"]
        assert properties["io.heyi.release.git_sha"] == RELEASE_GIT_SHA
        assert properties["io.heyi.source_manifest.sha256"] == index["source_manifest_sha256"]


def test_scanner_hash_mismatch_fails_before_creating_output(tmp_path: Path) -> None:
    scanner, _ = _write_scanner(tmp_path)
    manifest = _write_manifest(tmp_path)

    with pytest.raises(ImageSbomContractError, match="does not match"):
        generate_image_sboms(
            artifact_root=tmp_path,
            image_manifest=manifest,
            output_dir=tmp_path / "sbom",
            scanner=scanner,
            scanner_sha256="0" * 64,
            release_id=RELEASE_ID,
            release_git_sha=RELEASE_GIT_SHA,
        )

    assert not (tmp_path / "sbom").exists()


def test_scan_failure_removes_all_staging_output(tmp_path: Path) -> None:
    scanner, scanner_sha256 = _write_scanner(tmp_path)
    manifest = _write_manifest(tmp_path)

    def fail_runner(_command: Sequence[str], _env: dict[str, str], _timeout: int) -> None:
        raise ImageSbomContractError("simulated scan failure")

    with pytest.raises(ImageSbomContractError, match="simulated"):
        generate_image_sboms(
            artifact_root=tmp_path,
            image_manifest=manifest,
            output_dir=tmp_path / "sbom",
            scanner=scanner,
            scanner_sha256=scanner_sha256,
            release_id=RELEASE_ID,
            release_git_sha=RELEASE_GIT_SHA,
            runner=fail_runner,
        )

    assert not (tmp_path / "sbom").exists()
    assert not list(tmp_path.glob(".sbom.staging-*"))


def test_dry_run_is_non_mutating_and_does_not_execute_scanner(tmp_path: Path) -> None:
    scanner, scanner_sha256 = _write_scanner(tmp_path)
    manifest = _write_manifest(tmp_path)

    def unexpected_runner(_command: Sequence[str], _env: dict[str, str], _timeout: int) -> None:
        raise AssertionError("dry-run must not execute the scanner")

    report = generate_image_sboms(
        artifact_root=tmp_path,
        image_manifest=manifest,
        output_dir=tmp_path / "sbom",
        scanner=scanner,
        scanner_sha256=scanner_sha256,
        release_id=RELEASE_ID,
        release_git_sha=RELEASE_GIT_SHA,
        dry_run=True,
        runner=unexpected_runner,
    )

    assert report["status"] == "DRY_RUN"
    assert report["image_count"] == 9
    assert not (tmp_path / "sbom").exists()
