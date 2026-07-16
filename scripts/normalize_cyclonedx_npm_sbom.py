from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

REFERENCE_SEGMENT = re.compile(r"^(?P<name>@?[A-Za-z0-9._/-]+)@(?P<version>[^@|]+)$")
SPDX_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
INTEGRITY_ALGORITHMS = {
    "sha256": ("SHA-256", 32),
    "sha384": ("SHA-384", 48),
    "sha512": ("SHA-512", 64),
}


class NormalizationError(ValueError):
    """Raised when a missing component cannot be reconstructed without guessing."""


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NormalizationError(f"cannot read JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise NormalizationError(f"expected JSON object in {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_segment(value: str) -> tuple[str, str]:
    match = REFERENCE_SEGMENT.fullmatch(value)
    if match is None:
        raise NormalizationError(f"unsupported npm bom-ref segment: {value!r}")
    return match.group("name"), match.group("version")


def _candidate_package_paths(reference: str, root_reference: str) -> list[tuple[str, str, str]]:
    prefix = f"{root_reference}|"
    if not reference.startswith(prefix):
        raise NormalizationError(f"dependency ref is outside the SBOM root: {reference!r}")
    coordinates = [_parse_segment(segment) for segment in reference[len(prefix) :].split("|")]
    names = [name for name, _ in coordinates]
    nested = "node_modules/" + "/node_modules/".join(names)
    leaf_name, leaf_version = coordinates[-1]
    return [(nested, leaf_name, leaf_version)]


def _resolve_lock_package(
    reference: str,
    root_reference: str,
    packages: dict[str, Any],
) -> tuple[str, str, str, dict[str, Any]]:
    nested_path, leaf_name, leaf_version = _candidate_package_paths(reference, root_reference)[0]
    nested_value = packages.get(nested_path)
    if isinstance(nested_value, dict) and nested_value.get("version") == leaf_version:
        return nested_path, leaf_name, leaf_version, nested_value

    suffix = f"/node_modules/{leaf_name}"
    candidates: list[tuple[str, dict[str, Any]]] = []
    for package_path, package in packages.items():
        if (
            isinstance(package_path, str)
            and isinstance(package, dict)
            and package.get("version") == leaf_version
            and (package_path == f"node_modules/{leaf_name}" or package_path.endswith(suffix))
        ):
            candidates.append((package_path, package))
    if len(candidates) != 1:
        raise NormalizationError(
            f"dependency ref {reference!r} has {len(candidates)} exact lock candidates"
        )
    package_path, package = candidates[0]
    return package_path, leaf_name, leaf_version, package


def _integrity_hash(value: Any) -> tuple[str, str]:
    if not isinstance(value, str) or "-" not in value:
        raise NormalizationError("lock package has no supported Subresource Integrity value")
    algorithm_name, encoded = value.split("-", maxsplit=1)
    algorithm = INTEGRITY_ALGORITHMS.get(algorithm_name.lower())
    if algorithm is None:
        raise NormalizationError(f"unsupported integrity algorithm: {algorithm_name!r}")
    cyclonedx_name, expected_bytes = algorithm
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise NormalizationError("lock package integrity is not valid base64") from exc
    if len(decoded) != expected_bytes:
        raise NormalizationError("lock package integrity has an invalid digest length")
    return cyclonedx_name, decoded.hex()


def _component_from_lock(
    reference: str,
    package_path: str,
    package_name: str,
    package_version: str,
    package: dict[str, Any],
) -> dict[str, Any]:
    license_expression = package.get("license")
    if (
        not isinstance(license_expression, str)
        or SPDX_IDENTIFIER.fullmatch(license_expression) is None
    ):
        raise NormalizationError(
            f"lock package {package_path!r} lacks one unambiguous SPDX license identifier"
        )
    resolved = package.get("resolved")
    if not isinstance(resolved, str) or not resolved.startswith("https://"):
        raise NormalizationError(f"lock package {package_path!r} lacks an HTTPS distribution URL")
    hash_algorithm, hash_content = _integrity_hash(package.get("integrity"))

    group: str | None = None
    name = package_name
    if package_name.startswith("@"):
        parts = package_name.split("/", maxsplit=1)
        if len(parts) != 2 or not parts[1]:
            raise NormalizationError(f"invalid scoped npm package name: {package_name!r}")
        group, name = parts
    purl_name = quote(package_name, safe="/")
    component: dict[str, Any] = {
        "type": "library",
        "name": name,
        "version": package_version,
        "bom-ref": reference,
    }
    if group is not None:
        component["group"] = group
    if package.get("optional") is True:
        component["scope"] = "optional"
    component.update(
        {
            "licenses": [
                {
                    "license": {
                        "id": license_expression,
                        "acknowledgement": "declared",
                    }
                }
            ],
            "purl": (
                f"pkg:npm/{purl_name}@{package_version}?download_url={quote(resolved, safe='')}"
            ),
            "externalReferences": [
                {
                    "url": resolved,
                    "type": "distribution",
                    "hashes": [{"alg": hash_algorithm, "content": hash_content}],
                    "comment": (
                        'as detected from npm package-lock properties "resolved" and "integrity"'
                    ),
                }
            ],
            "properties": [{"name": "cdx:npm:package:path", "value": package_path}],
        }
    )
    return component


def _unknown_dependency_references(bom: dict[str, Any]) -> set[str]:
    metadata = bom.get("metadata")
    root = metadata.get("component") if isinstance(metadata, dict) else None
    root_reference = root.get("bom-ref") if isinstance(root, dict) else None
    if not isinstance(root_reference, str) or not root_reference:
        raise NormalizationError("SBOM metadata.component.bom-ref is missing")
    components = bom.get("components")
    dependencies = bom.get("dependencies")
    if not isinstance(components, list) or not all(isinstance(item, dict) for item in components):
        raise NormalizationError("SBOM components must be an array of objects")
    if not isinstance(dependencies, list) or not all(
        isinstance(item, dict) for item in dependencies
    ):
        raise NormalizationError("SBOM dependencies must be an array of objects")
    known = {root_reference}
    for component in components:
        reference = component.get("bom-ref")
        if not isinstance(reference, str) or not reference or reference in known:
            raise NormalizationError("SBOM component bom-ref is missing or duplicated")
        known.add(reference)
    referenced: set[str] = set()
    for dependency in dependencies:
        reference = dependency.get("ref")
        depends_on = dependency.get("dependsOn", [])
        if (
            not isinstance(reference, str)
            or not isinstance(depends_on, list)
            or not all(isinstance(item, str) for item in depends_on)
        ):
            raise NormalizationError("SBOM dependency node is malformed")
        referenced.add(reference)
        referenced.update(depends_on)
    return referenced - known


def normalize_bom(bom: dict[str, Any], package_lock: dict[str, Any]) -> list[str]:
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
        raise NormalizationError("expected a CycloneDX 1.6 SBOM")
    metadata = bom.get("metadata")
    root = metadata.get("component") if isinstance(metadata, dict) else None
    root_reference = root.get("bom-ref") if isinstance(root, dict) else None
    if not isinstance(root_reference, str):
        raise NormalizationError("SBOM root reference is missing")
    if package_lock.get("lockfileVersion") != 3:
        raise NormalizationError("expected npm package-lock lockfileVersion 3")
    packages = package_lock.get("packages")
    if not isinstance(packages, dict):
        raise NormalizationError("package-lock packages object is missing")

    missing_references = sorted(_unknown_dependency_references(bom))
    components = bom["components"]
    for reference in missing_references:
        package_path, package_name, version, package = _resolve_lock_package(
            reference,
            root_reference,
            packages,
        )
        components.append(
            _component_from_lock(reference, package_path, package_name, version, package)
        )
    remaining = _unknown_dependency_references(bom)
    if remaining:
        raise NormalizationError(
            f"SBOM still has dangling dependency refs: {', '.join(sorted(remaining))}"
        )
    return missing_references


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Deterministically add CycloneDX npm components referenced by the dependency graph "
            "but omitted from components, using only package-lock metadata."
        )
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--package-lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        bom = _load_object(args.input)
        package_lock = _load_object(args.package_lock)
        added = normalize_bom(bom, package_lock)
        _write_json_atomic(args.output, bom)
        report = {
            "status": "PASS",
            "added_components": added,
            "component_count": len(bom["components"]),
            "dependency_count": len(bom["dependencies"]),
            "output_sha256": _sha256(args.output),
        }
    except (KeyError, NormalizationError, OSError, TypeError) as exc:
        report = {"status": "FAIL", "error": str(exc)}
    sys.stdout.write(json.dumps(report, ensure_ascii=False, sort_keys=True) + "\n")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
