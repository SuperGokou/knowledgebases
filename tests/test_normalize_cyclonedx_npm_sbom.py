from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts.normalize_cyclonedx_npm_sbom import (
    NormalizationError,
    _unknown_dependency_references,
    main,
    normalize_bom,
)

REPOSITORY = Path(__file__).resolve().parents[1]
WEB_SBOM = REPOSITORY / "artifacts/acceptance/sbom-web.cdx.json"
PACKAGE_LOCK = REPOSITORY / "web/package-lock.json"
EXPECTED_REPAIRS = {
    "enterprise-knowledge-base-web@0.1.0|playwright@1.61.1|fsevents@2.3.2",
    "enterprise-knowledge-base-web@0.1.0|sharp@0.34.5|semver@7.8.5",
}


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _generator_style_omission() -> dict[str, object]:
    bom = copy.deepcopy(_load(WEB_SBOM))
    components = bom["components"]
    assert isinstance(components, list)
    bom["components"] = [
        component
        for component in components
        if isinstance(component, dict) and component.get("bom-ref") not in EXPECTED_REPAIRS
    ]
    return bom


def test_committed_web_sbom_has_no_dangling_dependency_references() -> None:
    bom = _load(WEB_SBOM)

    assert _unknown_dependency_references(bom) == set()
    components = bom.get("components")
    dependencies = bom.get("dependencies")
    assert isinstance(components, list)
    assert isinstance(dependencies, list)
    assert len(components) == 56
    assert len(dependencies) == 57


def test_normalizer_restores_only_lock_backed_missing_components() -> None:
    bom = _generator_style_omission()
    lock = _load(PACKAGE_LOCK)

    added = normalize_bom(bom, lock)

    assert set(added) == EXPECTED_REPAIRS
    assert _unknown_dependency_references(bom) == set()
    components = bom.get("components")
    assert isinstance(components, list)
    repaired = {
        component["bom-ref"]: component
        for component in components
        if isinstance(component, dict) and component.get("bom-ref") in EXPECTED_REPAIRS
    }
    assert repaired[sorted(EXPECTED_REPAIRS)[0]]["licenses"] == [
        {"license": {"id": "MIT", "acknowledgement": "declared"}}
    ]
    assert repaired[sorted(EXPECTED_REPAIRS)[1]]["licenses"] == [
        {"license": {"id": "ISC", "acknowledgement": "declared"}}
    ]
    assert all(component["scope"] == "optional" for component in repaired.values())
    assert all(
        component["externalReferences"][0]["hashes"][0]["alg"] == "SHA-512"
        for component in repaired.values()
    )


def test_normalizer_is_idempotent_for_the_committed_sbom() -> None:
    bom = _load(WEB_SBOM)
    lock = _load(PACKAGE_LOCK)
    expected = copy.deepcopy(bom)

    assert normalize_bom(bom, lock) == []
    assert bom == expected


def test_normalizer_refuses_to_guess_when_lock_license_is_missing() -> None:
    bom = _generator_style_omission()
    lock = _load(PACKAGE_LOCK)
    packages = lock["packages"]
    assert isinstance(packages, dict)
    package = packages["node_modules/sharp/node_modules/semver"]
    assert isinstance(package, dict)
    package.pop("license")

    with pytest.raises(NormalizationError, match="SPDX license"):
        normalize_bom(bom, lock)


def test_normalizer_refuses_integrity_values_that_do_not_bind_package_bytes() -> None:
    bom = _generator_style_omission()
    lock = _load(PACKAGE_LOCK)
    packages = lock["packages"]
    assert isinstance(packages, dict)
    package = packages["node_modules/playwright/node_modules/fsevents"]
    assert isinstance(package, dict)
    package["integrity"] = "sha512-not-base64"

    with pytest.raises(NormalizationError, match="base64"):
        normalize_bom(bom, lock)


def test_cli_output_is_byte_stable_on_repeated_normalization(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    input_path = tmp_path / "input.cdx.json"
    first_output = tmp_path / "first.cdx.json"
    second_output = tmp_path / "second.cdx.json"
    input_path.write_text(
        json.dumps(_generator_style_omission(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    first_exit = main(
        [
            "--input",
            str(input_path),
            "--package-lock",
            str(PACKAGE_LOCK),
            "--output",
            str(first_output),
        ]
    )
    first_report = json.loads(capsys.readouterr().out)
    second_exit = main(
        [
            "--input",
            str(first_output),
            "--package-lock",
            str(PACKAGE_LOCK),
            "--output",
            str(second_output),
        ]
    )
    second_report = json.loads(capsys.readouterr().out)

    assert first_exit == second_exit == 0
    assert first_output.read_bytes() == second_output.read_bytes()
    digest = hashlib.sha256(first_output.read_bytes()).hexdigest()
    assert first_report["output_sha256"] == second_report["output_sha256"] == digest
    assert set(first_report["added_components"]) == EXPECTED_REPAIRS
    assert second_report["added_components"] == []
