from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
from collections.abc import Sequence
from pathlib import Path

import pytest

from scripts.generate_offline_image_sboms import generate_image_sboms
from scripts.supply_chain_gate import (
    GateConfigurationError,
    _asset_media_type,
    _write_report,
    main,
    run_gate,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_FILES = (
    "pyproject.toml",
    "uv.lock",
    "web/package.json",
    "web/package-lock.json",
    "web/src/app/layout.tsx",
    "web/src/app/favicon.ico",
    "web/src/app/icon.png",
    "web/public/brand/heyi-display-logo.webp",
    "docs/assets/design-qa/prism-comparison.png",
    "docs/assets/design-qa/prism-implementation.png",
    "docs/assets/design-qa/prism-mobile.png",
    "docs/assets/design-qa/prism-reference.png",
    "docs/THIRD-PARTY-NOTICES.md",
    "artifacts/acceptance/sbom-python.cdx.json",
    "artifacts/acceptance/sbom-web.cdx.json",
)


def _copy_gate_fixture(tmp_path: Path) -> Path:
    fixture = tmp_path / "repository"
    shutil.copytree(REPO_ROOT / "compliance", fixture / "compliance")
    for relative_path in FIXTURE_FILES:
        source = REPO_ROOT / relative_path
        destination = fixture / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    return fixture


def _finding_codes(report: dict[str, object]) -> set[str]:
    findings = report["findings"]
    assert isinstance(findings, list)
    return {str(finding["code"]) for finding in findings if isinstance(finding, dict)}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rebind_snapshot_input(fixture: Path, relative_path: str) -> None:
    snapshot_path = fixture / "compliance" / "dependency-snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    entry = next(item for item in snapshot["inputs"] if item["path"] == relative_path)
    entry["sha256"] = _sha256(fixture / relative_path)
    snapshot_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _remove_sbom_component_and_rebind(
    fixture: Path,
    *,
    ecosystem: str,
    component_name: str,
) -> None:
    sbom_path = fixture / "artifacts" / "acceptance" / f"sbom-{ecosystem}.cdx.json"
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    component = next(item for item in sbom["components"] if item["name"] == component_name)
    component_reference = component["bom-ref"]
    sbom["components"] = [
        item for item in sbom["components"] if item["bom-ref"] != component_reference
    ]
    sbom["dependencies"] = [
        {
            **item,
            "dependsOn": [
                reference
                for reference in item.get("dependsOn", [])
                if reference != component_reference
            ],
        }
        for item in sbom["dependencies"]
        if item.get("ref") != component_reference
    ]
    sbom_path.write_text(
        json.dumps(sbom, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    snapshot_path = fixture / "compliance" / "dependency-snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    entry = next(item for item in snapshot["sboms"] if item["ecosystem"] == ecosystem)
    entry["component_count"] = len(sbom["components"])
    entry["dependency_count"] = len(sbom["dependencies"])
    entry["sha256"] = _sha256(sbom_path)
    snapshot_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_bound_image_evidence(fixture: Path) -> Path:
    release_git_sha = "a" * 40
    manifest = fixture / "release.env.images"
    manifest.write_text(
        "\n".join(
            (
                f"127.0.0.1:5000/heyi-release/api:r1@sha256:{'1' * 64}"
                f"\tsha256:{'a' * 64}\tlinux\tamd64",
                f"127.0.0.1:5000/heyi-release/web:r1@sha256:{'2' * 64}"
                f"\tsha256:{'b' * 64}\tlinux\tamd64",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    scanner = fixture / "test-syft"
    scanner.write_bytes(b"pinned-test-scanner\n")
    local_image_map = fixture.parent / "local-image-map.tsv"
    local_image_map.write_text(
        "\n".join(
            f"{line.split(chr(9), 1)[0]}\t{line.split(chr(9), 1)[0].rsplit('@', 1)[1]}"
            for line in manifest.read_text(encoding="utf-8").splitlines()
        )
        + "\n",
        encoding="ascii",
    )

    def fake_runner(command: Sequence[str], _environment: dict[str, str], _timeout: int) -> None:
        output = Path(command[-1].removeprefix("cyclonedx-json="))
        output.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "components": [{"bom-ref": "pkg:test", "name": "test", "type": "library"}],
                    "metadata": {"properties": []},
                    "specVersion": "1.6",
                    "version": 1,
                }
            ),
            encoding="utf-8",
        )

    generate_image_sboms(
        artifact_root=fixture,
        image_manifest=manifest,
        local_image_map=local_image_map,
        output_dir=fixture / "sbom",
        scanner=scanner.resolve(),
        scanner_sha256=_sha256(scanner),
        release_id="r1",
        release_git_sha=release_git_sha,
        runner=fake_runner,
    )
    attestation_path = fixture / "compliance" / "release-rights.template.json"
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    attestation["release_id"] = release_git_sha
    attestation["image_sbom_index"] = {
        "status": "approved",
        "path": "sbom/image-sbom-index.json",
        "sha256": "0" * 64,
        "image_manifest_path": "release.env.images",
        "image_manifest_sha256": _sha256(manifest),
        "bundle_checksum_manifest_path": "SHA256SUMS",
        "bundle_checksum_manifest_sha256": "0" * 64,
    }
    attestation_path.write_text(
        json.dumps(attestation, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _rebind_image_evidence(fixture)
    return attestation_path


def _rebind_image_evidence(fixture: Path) -> None:
    index_path = fixture / "sbom" / "image-sbom-index.json"
    manifest = fixture / "release.env.images"
    checksum_entries = {
        "release.env.images": _sha256(manifest),
        "sbom/image-sbom-index.json": _sha256(index_path),
    }
    for sbom_path in sorted((fixture / "sbom").glob("image-*.cdx.json")):
        checksum_entries[sbom_path.relative_to(fixture).as_posix()] = _sha256(sbom_path)
    checksum_path = fixture / "SHA256SUMS"
    checksum_path.write_text(
        "".join(f"{digest}  {path}\n" for path, digest in sorted(checksum_entries.items())),
        encoding="ascii",
    )
    attestation_path = fixture / "compliance" / "release-rights.template.json"
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    attestation["image_sbom_index"]["sha256"] = _sha256(index_path)
    attestation["image_sbom_index"]["image_manifest_sha256"] = _sha256(manifest)
    attestation["image_sbom_index"]["bundle_checksum_manifest_sha256"] = _sha256(checksum_path)
    attestation_path.write_text(
        json.dumps(attestation, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_inventory_gate_passes_integrity_but_does_not_claim_release_approval() -> None:
    report = run_gate(REPO_ROOT, mode="inventory")

    assert report["status"] == "PASS"
    assert report["release_eligible"] is False
    assert report["summary"] == {
        "errors": 0,
        "manual_reviews": 18,
        "sboms": 2,
        "declared_assets": 8,
        "manual_license_expressions": 7,
    }
    assert {
        "PROJECT_LICENSE_FILE_PENDING",
        "ASSET_RIGHTS_APPROVAL_PENDING",
        "IMAGE_SBOM_APPROVAL_PENDING",
        "LICENSE_MANUAL_REVIEW_REQUIRED",
    } <= _finding_codes(report)
    assert "not legal advice" in " ".join(report["limitations"])


def test_asset_media_type_is_independent_of_the_host_mime_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "scripts.supply_chain_gate.mimetypes.guess_type",
        lambda _name: ("image/vnd.microsoft.icon", None),
    )

    assert _asset_media_type(Path("favicon.ico")) == "image/x-icon"


def test_inventory_report_is_deterministic() -> None:
    first = run_gate(REPO_ROOT, mode="inventory")
    second = run_gate(REPO_ROOT, mode="inventory")

    assert first == second
    assert first["report_sha256"] == second["report_sha256"]


def test_release_gate_fails_closed_while_signatures_and_image_sboms_are_pending() -> None:
    report = run_gate(REPO_ROOT, mode="release")

    assert report["status"] == "FAIL"
    assert report["release_eligible"] is False
    assert report["summary"]["errors"] > 0
    assert {
        "RELEASE_RIGHTS_ATTESTATION_PENDING",
        "PROJECT_LICENSE_APPROVAL_PENDING",
        "LICENSE_MANUAL_REVIEW_PENDING",
        "ASSET_RIGHTS_APPROVAL_PENDING",
        "IMAGE_SBOM_APPROVAL_PENDING",
        "MANUAL_SIGNOFF_PENDING",
    } <= _finding_codes(report)


def test_release_image_sbom_index_accepts_an_exact_fully_bound_manifest_set(
    tmp_path: Path,
) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    attestation_path = _write_bound_image_evidence(fixture)

    report = run_gate(
        fixture,
        mode="release",
        attestation_path=attestation_path,
        artifact_root=fixture,
        expected_release_id="a" * 40,
    )

    assert not {code for code in _finding_codes(report) if code.startswith("IMAGE_SBOM_")}


def test_release_image_sbom_index_rejects_a_coordinated_third_scan_identity(
    tmp_path: Path,
) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    attestation_path = _write_bound_image_evidence(fixture)
    index_path = fixture / "sbom" / "image-sbom-index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    record = index["images"][0]
    third_identity = f"sha256:{'f' * 64}"
    assert third_identity not in {record["manifest_digest"], record["config_id"]}
    record["scan_identity"] = third_identity

    sbom_path = fixture / record["sbom_path"]
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    scan_property = next(
        item
        for item in sbom["metadata"]["properties"]
        if item["name"] == "io.heyi.image.scan_identity"
    )
    scan_property["value"] = third_identity
    sbom_path.write_text(
        json.dumps(sbom, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    record["sbom_sha256"] = _sha256(sbom_path)
    index_path.write_text(
        json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _rebind_image_evidence(fixture)

    report = run_gate(
        fixture,
        mode="release",
        attestation_path=attestation_path,
        artifact_root=fixture,
        expected_release_id="a" * 40,
    )

    assert "IMAGE_SBOM_BINDING_INVALID" in _finding_codes(report)


def test_release_image_sbom_index_rejects_scan_identity_property_drift(
    tmp_path: Path,
) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    attestation_path = _write_bound_image_evidence(fixture)
    index_path = fixture / "sbom" / "image-sbom-index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    record = index["images"][0]
    alternate_identity = (
        record["config_id"]
        if record["scan_identity"] != record["config_id"]
        else record["manifest_digest"]
    )

    sbom_path = fixture / record["sbom_path"]
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    scan_property = next(
        item
        for item in sbom["metadata"]["properties"]
        if item["name"] == "io.heyi.image.scan_identity"
    )
    scan_property["value"] = alternate_identity
    sbom_path.write_text(
        json.dumps(sbom, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    record["sbom_sha256"] = _sha256(sbom_path)
    index_path.write_text(
        json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _rebind_image_evidence(fixture)

    report = run_gate(
        fixture,
        mode="release",
        attestation_path=attestation_path,
        artifact_root=fixture,
        expected_release_id="a" * 40,
    )

    assert "IMAGE_SBOM_BINDING_INVALID" in _finding_codes(report)


@pytest.mark.parametrize("mutation", ["missing", "extra", "duplicate"])
def test_release_image_sbom_index_rejects_set_drift(tmp_path: Path, mutation: str) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    attestation_path = _write_bound_image_evidence(fixture)
    index_path = fixture / "sbom" / "image-sbom-index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if mutation == "missing":
        index["images"].pop()
    elif mutation == "duplicate":
        index["images"].append(index["images"][0].copy())
    else:
        extra = index["images"][0].copy()
        extra["reference"] = f"127.0.0.1:5000/heyi-release/extra:r1@sha256:{'3' * 64}"
        extra["manifest_digest"] = f"sha256:{'3' * 64}"
        extra["config_id"] = f"sha256:{'c' * 64}"
        extra["sbom_path"] = f"sbom/image-{'3' * 64}.cdx.json"
        index["images"].append(extra)
    index_path.write_text(
        json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _rebind_image_evidence(fixture)

    report = run_gate(
        fixture,
        mode="release",
        attestation_path=attestation_path,
        artifact_root=fixture,
        expected_release_id="a" * 40,
    )

    assert "IMAGE_SBOM_SET_MISMATCH" in _finding_codes(report)


def test_release_image_sbom_index_rejects_a_coordinated_digest_rebinding(
    tmp_path: Path,
) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    attestation_path = _write_bound_image_evidence(fixture)
    index_path = fixture / "sbom" / "image-sbom-index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    record = index["images"][0]
    sbom_path = fixture / record["sbom_path"]
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    digest_property = next(
        item
        for item in sbom["metadata"]["properties"]
        if item["name"] == "io.heyi.image.manifest_digest"
    )
    digest_property["value"] = f"sha256:{'f' * 64}"
    sbom_path.write_text(
        json.dumps(sbom, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    record["sbom_sha256"] = _sha256(sbom_path)
    index_path.write_text(
        json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _rebind_image_evidence(fixture)

    report = run_gate(
        fixture,
        mode="release",
        attestation_path=attestation_path,
        artifact_root=fixture,
        expected_release_id="a" * 40,
    )

    assert "IMAGE_SBOM_BINDING_INVALID" in _finding_codes(report)


def test_release_image_sbom_index_rejects_missing_signed_checksum_binding(
    tmp_path: Path,
) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    attestation_path = _write_bound_image_evidence(fixture)
    checksum_path = fixture / "SHA256SUMS"
    lines = checksum_path.read_text(encoding="ascii").splitlines()
    checksum_path.write_text(
        "\n".join(line for line in lines if "image-" not in line) + "\n",
        encoding="ascii",
    )
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    attestation["image_sbom_index"]["bundle_checksum_manifest_sha256"] = _sha256(checksum_path)
    attestation_path.write_text(
        json.dumps(attestation, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    report = run_gate(
        fixture,
        mode="release",
        attestation_path=attestation_path,
        artifact_root=fixture,
        expected_release_id="a" * 40,
    )

    assert "IMAGE_SBOM_CHECKSUM_BINDING_INVALID" in _finding_codes(report)


def test_lock_file_drift_invalidates_the_bound_snapshot(tmp_path: Path) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    lock_path = fixture / "web" / "package-lock.json"
    lock_path.write_bytes(lock_path.read_bytes() + b"\n")

    report = run_gate(fixture, mode="inventory")

    assert report["status"] == "FAIL"
    assert "LOCK_INPUT_HASH_MISMATCH" in _finding_codes(report)


@pytest.mark.parametrize(
    ("ecosystem", "component_name", "expected_code"),
    [
        ("python", "Mako", "PYTHON_SBOM_PRODUCTION_COMPONENT_MISSING"),
        ("python", "hiredis", "PYTHON_SBOM_PRODUCTION_COMPONENT_MISSING"),
        ("python", "tzdata", "PYTHON_SBOM_PRODUCTION_COMPONENT_MISSING"),
        ("web", "scheduler", "WEB_SBOM_PRODUCTION_COMPONENT_MISSING"),
        ("web", "sharp-linux-x64", "WEB_SBOM_PRODUCTION_COMPONENT_MISSING"),
    ],
)
def test_transitive_production_component_cannot_be_omitted_from_a_rebound_sbom(
    tmp_path: Path,
    ecosystem: str,
    component_name: str,
    expected_code: str,
) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    _remove_sbom_component_and_rebind(
        fixture,
        ecosystem=ecosystem,
        component_name=component_name,
    )

    report = run_gate(fixture, mode="inventory")

    assert report["status"] == "FAIL"
    assert expected_code in _finding_codes(report)


def test_sbom_purl_must_match_the_declared_component_identity(tmp_path: Path) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    sbom_path = fixture / "artifacts" / "acceptance" / "sbom-python.cdx.json"
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    component = next(item for item in sbom["components"] if item["name"] == "Mako")
    component["purl"] = f"pkg:pypi/not-mako@{component['version']}"
    sbom_path.write_text(
        json.dumps(sbom, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    snapshot_path = fixture / "compliance" / "dependency-snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    entry = next(item for item in snapshot["sboms"] if item["ecosystem"] == "python")
    entry["sha256"] = _sha256(sbom_path)
    snapshot_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    report = run_gate(fixture, mode="inventory")

    assert report["status"] == "FAIL"
    assert "SBOM_COMPONENT_IDENTITY_INVALID" in _finding_codes(report)


@pytest.mark.parametrize("section", ["inputs", "sboms"])
def test_snapshot_cannot_omit_a_required_ecosystem_binding(
    tmp_path: Path,
    section: str,
) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    snapshot_path = fixture / "compliance" / "dependency-snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    if section == "inputs":
        snapshot["inputs"] = [
            item for item in snapshot["inputs"] if item["path"] != "web/package-lock.json"
        ]
    else:
        snapshot["sboms"] = [item for item in snapshot["sboms"] if item["ecosystem"] != "web"]
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")

    with pytest.raises(GateConfigurationError, match="must bind"):
        run_gate(fixture, mode="inventory")


def test_unreachable_dev_only_lock_components_are_not_required_in_production_sboms(
    tmp_path: Path,
) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    uv_lock = fixture / "uv.lock"
    uv_lock.write_text(
        uv_lock.read_text(encoding="utf-8")
        + '\n[[package]]\nname = "acceptance-dev-only"\nversion = "1.0.0"\n'
        + 'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    _rebind_snapshot_input(fixture, "uv.lock")

    web_lock_path = fixture / "web" / "package-lock.json"
    web_lock = json.loads(web_lock_path.read_text(encoding="utf-8"))
    web_lock["packages"]["node_modules/acceptance-dev-only"] = {
        "version": "1.0.0",
        "dev": True,
    }
    web_lock_path.write_text(
        json.dumps(web_lock, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    _rebind_snapshot_input(fixture, "web/package-lock.json")

    report = run_gate(fixture, mode="inventory")

    assert report["status"] == "PASS"


def test_unregistered_binary_asset_fails_inventory(tmp_path: Path) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    unexpected = fixture / "web" / "public" / "brand" / "unregistered.png"
    unexpected.write_bytes(b"not-a-real-png-but-still-a-distributed-binary")

    report = run_gate(fixture, mode="inventory")

    assert report["status"] == "FAIL"
    assert "ASSET_UNREGISTERED" in _finding_codes(report)


def test_unregistered_embedded_asset_fails_inventory(tmp_path: Path) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    source = fixture / "web" / "src" / "embedded.ts"
    source.write_text(
        'export const image = "data:image/png;base64,aGVsbG8=";\n',
        encoding="utf-8",
    )

    report = run_gate(fixture, mode="inventory")

    assert report["status"] == "FAIL"
    assert "ASSET_UNREGISTERED" in _finding_codes(report)


def test_asset_byte_drift_fails_inventory(tmp_path: Path) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    logo = fixture / "web" / "public" / "brand" / "heyi-display-logo.webp"
    logo.write_bytes(logo.read_bytes() + b"tampered")

    report = run_gate(fixture, mode="inventory")

    assert report["status"] == "FAIL"
    assert "ASSET_CONTENT_DRIFT" in _finding_codes(report)


def test_denied_license_marker_fails_even_when_sbom_hash_is_rebound(tmp_path: Path) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    sbom_path = fixture / "artifacts" / "acceptance" / "sbom-python.cdx.json"
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    sbom["components"][0]["licenses"] = [
        {"license": {"id": "AGPL-3.0-only", "acknowledgement": "declared"}}
    ]
    sbom_path.write_text(
        json.dumps(sbom, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    snapshot_path = fixture / "compliance" / "dependency-snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    python_entry = next(entry for entry in snapshot["sboms"] if entry["ecosystem"] == "python")
    python_entry["sha256"] = _sha256(sbom_path)
    snapshot_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    report = run_gate(fixture, mode="inventory")

    assert report["status"] == "FAIL"
    assert "LICENSE_POLICY_DENIED" in _finding_codes(report)


def test_unsafe_manifest_path_is_rejected(tmp_path: Path) -> None:
    fixture = _copy_gate_fixture(tmp_path)
    snapshot_path = fixture / "compliance" / "dependency-snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    snapshot["inputs"][0]["path"] = "../outside.toml"
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")

    with pytest.raises(GateConfigurationError, match="unsafe relative path"):
        run_gate(fixture, mode="inventory")


def test_cli_writes_the_same_machine_readable_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "supply-chain-report.json"

    exit_code = main(
        [
            "--repo",
            str(REPO_ROOT),
            "--mode",
            "inventory",
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    stdout_report = json.loads(capsys.readouterr().out)
    assert json.loads(output.read_text(encoding="utf-8")) == stdout_report


def test_report_writer_rejects_a_symlink_without_touching_its_victim(tmp_path: Path) -> None:
    victim = tmp_path / "victim.json"
    victim.write_text("unchanged", encoding="utf-8")
    output = tmp_path / "report.json"
    try:
        output.symlink_to(victim)
    except OSError:
        pytest.skip("creating symlinks is unavailable on this host")

    with pytest.raises(GateConfigurationError, match="regular file"):
        _write_report(output, '{"status":"PASS"}\n')

    assert victim.read_text(encoding="utf-8") == "unchanged"


def test_report_writer_rejects_a_symlinked_ancestor_without_creating_children(
    tmp_path: Path,
) -> None:
    victim_directory = tmp_path / "victim-directory"
    victim_directory.mkdir()
    linked_directory = tmp_path / "linked-directory"
    try:
        linked_directory.symlink_to(victim_directory, target_is_directory=True)
    except OSError:
        pytest.skip("creating directory symlinks is unavailable on this host")

    with pytest.raises(GateConfigurationError, match="cannot contain a symlink"):
        _write_report(linked_directory / "nested" / "report.json", "blocked\n")

    assert not (victim_directory / "nested").exists()


def test_report_writer_does_not_delete_or_overwrite_a_precreated_temp_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "report.json"
    monkeypatch.setattr(secrets, "token_hex", lambda _length: "fixed")
    collision = tmp_path / ".report.json.fixed.tmp"
    collision.write_text("attacker-owned", encoding="utf-8")

    with pytest.raises(FileExistsError):
        _write_report(output, '{"status":"PASS"}\n')

    assert collision.read_text(encoding="utf-8") == "attacker-owned"
    assert not output.exists()


def test_report_writer_atomically_replaces_a_regular_file_with_private_mode(
    tmp_path: Path,
) -> None:
    output = tmp_path / "report.json"
    output.write_text("old", encoding="utf-8")

    _write_report(output, '{"status":"PASS"}\n')

    assert output.read_text(encoding="utf-8") == '{"status":"PASS"}\n'
    if os.name == "posix":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_all_committed_compliance_json_and_schemas_are_valid_json() -> None:
    json_files = sorted((REPO_ROOT / "compliance").rglob("*.json"))

    assert len(json_files) == 9
    for path in json_files:
        document = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(document, dict)
        assert document.get("$schema") or document.get("$id")
