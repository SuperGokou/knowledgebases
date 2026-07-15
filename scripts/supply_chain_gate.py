from __future__ import annotations

import argparse
import base64
import hashlib
import json
import mimetypes
import os
import re
import secrets
import stat
import sys
import tomllib
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

Mode = Literal["inventory", "release"]
Severity = Literal["error", "review", "info"]

DATA_URI_PATTERN = re.compile(
    rb"data:((?:image|font)/[A-Za-z0-9.+-]+);base64,([A-Za-z0-9+/=\r\n]+)"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
RELEASE_ID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_REFERENCE_PATTERN = re.compile(
    r"^127\.0\.0\.1:5000/"
    r"(?P<name>[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?)"
    r"@(?P<digest>sha256:[0-9a-f]{64})$"
)
CHECKSUM_LINE_PATTERN = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$")
IMAGE_SBOM_INDEX_SCHEMA = "https://knowledgebases.local/schemas/image-sbom-index-v1.schema.json"
PLACEHOLDER_MARKERS = ("pending", "replace", "todo", "待补", "待签", "待填")


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    severity: Severity
    subject: str
    message: str


@dataclass(frozen=True, order=True)
class ReleaseImage:
    reference: str
    manifest_digest: str
    config_id: str
    os: str
    architecture: str


class GateConfigurationError(ValueError):
    """Raised when committed gate configuration is malformed."""


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GateConfigurationError(f"cannot read JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise GateConfigurationError(f"expected JSON object in {path}")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256_bytes(payload)


def _resolve_beneath(root: Path, relative_path: str) -> Path:
    posix_path = PurePosixPath(relative_path)
    if posix_path.is_absolute() or ".." in posix_path.parts:
        raise GateConfigurationError(f"unsafe relative path: {relative_path!r}")
    candidate = root.joinpath(*posix_path.parts).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise GateConfigurationError(f"path escapes configured root: {relative_path!r}") from exc
    return candidate


def _require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GateConfigurationError(f"{label} must be a JSON array")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GateConfigurationError(f"{label} must be a non-empty string")
    return value.strip()


def _validate_configuration(
    snapshot: dict[str, Any],
    policy: dict[str, Any],
    assets: dict[str, Any],
) -> None:
    _require_list(snapshot.get("inputs"), "snapshot.inputs")
    _require_list(snapshot.get("sboms"), "snapshot.sboms")
    policy_lists = (
        "allowed",
        "manual_review",
        "denied_substrings",
        "project_license_files",
    )
    for key in policy_lists:
        values = _require_list(policy.get(key), f"license-policy.{key}")
        if not values or not all(isinstance(value, str) and value.strip() for value in values):
            raise GateConfigurationError(f"license-policy.{key} must contain strings")
        if len(values) != len(set(values)):
            raise GateConfigurationError(f"license-policy.{key} must not contain duplicates")
    if set(policy["allowed"]) & set(policy["manual_review"]):
        raise GateConfigurationError("allowed and manual_review license sets must be disjoint")
    for key in (
        "inventory_roots",
        "asset_extensions",
        "embedded_text_extensions",
        "excluded_directories",
        "assets",
    ):
        _require_list(assets.get(key), f"assets-manifest.{key}")


def _severity(mode: Mode) -> Severity:
    return "error" if mode == "release" else "review"


def _normalise_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _extract_licenses(component: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for item in component.get("licenses", []):
        if not isinstance(item, dict):
            continue
        expression = item.get("expression")
        if isinstance(expression, str) and expression.strip():
            result.append(expression.strip())
            continue
        license_value = item.get("license")
        if not isinstance(license_value, dict):
            continue
        identifier = license_value.get("id") or license_value.get("name")
        if isinstance(identifier, str) and identifier.strip():
            result.append(identifier.strip())
    return result


def _classify_license(expression: str, policy: dict[str, Any]) -> str:
    denied_markers = [str(value).casefold() for value in policy["denied_substrings"]]
    folded = expression.casefold()
    if any(marker in folded for marker in denied_markers):
        return "denied"
    if expression in policy["manual_review"]:
        return "manual_review"
    if expression in policy["allowed"]:
        return "allowed"
    return "unknown"


def _check_bound_file(
    repo: Path,
    entry: dict[str, Any],
    findings: list[Finding],
    code_prefix: str,
) -> Path | None:
    relative_path = _require_string(entry.get("path"), f"{code_prefix}.path")
    expected_hash = _require_string(entry.get("sha256"), f"{code_prefix}.sha256").lower()
    if not SHA256_PATTERN.fullmatch(expected_hash):
        raise GateConfigurationError(f"{code_prefix}.sha256 must be lowercase SHA-256")
    path = _resolve_beneath(repo, relative_path)
    if not path.is_file():
        findings.append(
            Finding(
                f"{code_prefix}_MISSING",
                "error",
                relative_path,
                "Bound release input is missing.",
            )
        )
        return None
    actual_hash = _sha256_file(path)
    if actual_hash != expected_hash:
        findings.append(
            Finding(
                f"{code_prefix}_HASH_MISMATCH",
                "error",
                relative_path,
                f"Expected {expected_hash}, observed {actual_hash}.",
            )
        )
    return path


def _check_python_lock_coverage(
    repo: Path,
    components: list[dict[str, Any]],
    findings: list[Finding],
) -> None:
    lock_path = repo / "uv.lock"
    project_path = repo / "pyproject.toml"
    try:
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        project = tomllib.loads(project_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        findings.append(Finding("PYTHON_LOCK_INVALID", "error", "uv.lock", str(exc)))
        return

    packages = lock.get("package")
    if not isinstance(packages, list):
        findings.append(
            Finding("PYTHON_LOCK_INVALID", "error", "uv.lock", "Missing package array.")
        )
        return
    project_name = project.get("project", {}).get("name")
    project_version = project.get("project", {}).get("version")
    roots = [
        package
        for package in packages
        if isinstance(package, dict) and package.get("name") == project_name
    ]
    if len(roots) != 1 or roots[0].get("version") != project_version:
        findings.append(
            Finding(
                "PYTHON_ROOT_METADATA_DRIFT",
                "error",
                "pyproject.toml",
                "pyproject.toml and uv.lock root package metadata do not match.",
            )
        )
        return

    locked = {
        (_normalise_python_name(str(package["name"])), str(package["version"]))
        for package in packages
        if isinstance(package, dict)
        and package.get("name") != project_name
        and isinstance(package.get("name"), str)
        and isinstance(package.get("version"), str)
    }
    sbom_coordinates = {
        (_normalise_python_name(str(component.get("name", ""))), str(component.get("version", "")))
        for component in components
    }
    for name, version in sorted(sbom_coordinates - locked):
        findings.append(
            Finding(
                "PYTHON_SBOM_COMPONENT_NOT_LOCKED",
                "error",
                f"{name}@{version}",
                "Python SBOM component is not present in uv.lock.",
            )
        )

    direct_dependencies = {
        _normalise_python_name(str(dependency["name"]))
        for dependency in roots[0].get("dependencies", [])
        if isinstance(dependency, dict) and isinstance(dependency.get("name"), str)
    }
    sbom_names = {name for name, _ in sbom_coordinates}
    for name in sorted(direct_dependencies - sbom_names):
        findings.append(
            Finding(
                "PYTHON_DIRECT_DEPENDENCY_MISSING_FROM_SBOM",
                "error",
                name,
                "A direct production dependency is absent from the Python SBOM.",
            )
        )


def _npm_lock_name(package_path: str) -> str:
    return package_path.rsplit("node_modules/", maxsplit=1)[-1]


def _check_web_lock_coverage(
    repo: Path,
    components: list[dict[str, Any]],
    findings: list[Finding],
) -> None:
    package_path = repo / "web" / "package.json"
    lock_path = repo / "web" / "package-lock.json"
    try:
        package = _load_json_object(package_path)
        lock = _load_json_object(lock_path)
    except GateConfigurationError as exc:
        findings.append(Finding("WEB_LOCK_INVALID", "error", "web/package-lock.json", str(exc)))
        return
    packages = lock.get("packages")
    if lock.get("lockfileVersion") != 3 or not isinstance(packages, dict):
        findings.append(
            Finding(
                "WEB_LOCK_INVALID",
                "error",
                "web/package-lock.json",
                "Expected npm lockfileVersion 3 with a packages object.",
            )
        )
        return
    root = packages.get("")
    if not isinstance(root, dict) or any(
        root.get(field) != package.get(field) for field in ("name", "version")
    ):
        findings.append(
            Finding(
                "WEB_ROOT_METADATA_DRIFT",
                "error",
                "web/package.json",
                "package.json and package-lock.json root metadata do not match.",
            )
        )
        return

    locked: set[tuple[str, str]] = set()
    for dependency_path, value in packages.items():
        if not dependency_path or not isinstance(value, dict) or value.get("dev") is True:
            continue
        version = value.get("version")
        if isinstance(version, str):
            locked.add((_npm_lock_name(dependency_path), version))
    sbom_coordinates = {
        (
            f"{component['group']}/{component['name']}"
            if component.get("group")
            else str(component.get("name", "")),
            str(component.get("version", "")),
        )
        for component in components
    }
    for name, version in sorted(sbom_coordinates - locked):
        findings.append(
            Finding(
                "WEB_SBOM_COMPONENT_NOT_LOCKED",
                "error",
                f"{name}@{version}",
                "Web SBOM component is not present in the production npm lock set.",
            )
        )

    direct_dependencies = set(package.get("dependencies", {}))
    sbom_names = {name for name, _ in sbom_coordinates}
    for name in sorted(direct_dependencies - sbom_names):
        findings.append(
            Finding(
                "WEB_DIRECT_DEPENDENCY_MISSING_FROM_SBOM",
                "error",
                name,
                "A direct production dependency is absent from the Web SBOM.",
            )
        )


def _check_sbom(
    repo: Path,
    entry: dict[str, Any],
    policy: dict[str, Any],
    mode: Mode,
    findings: list[Finding],
    license_subjects: dict[str, set[str]],
) -> None:
    path = _check_bound_file(repo, entry, findings, "SBOM")
    if path is None:
        return
    try:
        bom = _load_json_object(path)
    except GateConfigurationError as exc:
        findings.append(Finding("SBOM_INVALID_JSON", "error", entry["path"], str(exc)))
        return
    if bom.get("bomFormat") != entry.get("format") or bom.get("specVersion") != entry.get(
        "spec_version"
    ):
        findings.append(
            Finding(
                "SBOM_FORMAT_DRIFT",
                "error",
                entry["path"],
                "SBOM format or specification version differs from the bound snapshot.",
            )
        )
    components = bom.get("components")
    dependencies = bom.get("dependencies")
    if not isinstance(components, list) or not all(isinstance(item, dict) for item in components):
        findings.append(
            Finding("SBOM_COMPONENTS_INVALID", "error", entry["path"], "Invalid components.")
        )
        return
    if not isinstance(dependencies, list):
        findings.append(
            Finding("SBOM_DEPENDENCIES_INVALID", "error", entry["path"], "Invalid dependencies.")
        )
        return
    if len(components) != entry.get("component_count") or len(dependencies) != entry.get(
        "dependency_count"
    ):
        findings.append(
            Finding(
                "SBOM_COUNT_DRIFT",
                "error",
                entry["path"],
                "Component or dependency count differs from the bound snapshot.",
            )
        )

    metadata = bom.get("metadata")
    root = metadata.get("component", {}) if isinstance(metadata, dict) else {}
    expected_root = entry.get("root", {})
    if not isinstance(root, dict) or any(
        root.get(field) != expected_root.get(field) for field in ("name", "version")
    ):
        findings.append(
            Finding(
                "SBOM_ROOT_DRIFT",
                "error",
                entry["path"],
                "SBOM root component differs from the expected project package.",
            )
        )

    references = [str(component.get("bom-ref", "")) for component in components]
    root_reference = root.get("bom-ref") if isinstance(root, dict) else None
    known_references = set(references)
    if isinstance(root_reference, str):
        known_references.add(root_reference)
    if "" in references or len(references) != len(set(references)):
        findings.append(
            Finding(
                "SBOM_REFERENCE_INVALID",
                "error",
                entry["path"],
                "Every component must have a unique non-empty bom-ref.",
            )
        )
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            findings.append(
                Finding(
                    "SBOM_DEPENDENCY_NODE_INVALID",
                    "error",
                    entry["path"],
                    "Dependency node is not an object.",
                )
            )
            continue
        depends_on = dependency.get("dependsOn", [])
        if not isinstance(depends_on, list):
            findings.append(
                Finding(
                    "SBOM_DEPENDENCY_NODE_INVALID",
                    "error",
                    entry["path"],
                    "dependsOn must be an array.",
                )
            )
            continue
        referenced = [dependency.get("ref"), *depends_on]
        for reference in referenced:
            if not isinstance(reference, str) or reference not in known_references:
                findings.append(
                    Finding(
                        "SBOM_DANGLING_REFERENCE",
                        _severity(mode),
                        entry["path"],
                        f"Dependency graph references unknown component {reference!r}.",
                    )
                )

    for component in components:
        group = f"{component['group']}/" if component.get("group") else ""
        subject = f"{group}{component.get('name')}@{component.get('version')}"
        licenses = _extract_licenses(component)
        if not licenses:
            findings.append(
                Finding(
                    "SBOM_LICENSE_MISSING",
                    "error",
                    subject,
                    "Component has no declared license metadata.",
                )
            )
            continue
        for expression in licenses:
            classification = _classify_license(expression, policy)
            if classification == "denied":
                findings.append(
                    Finding(
                        "LICENSE_POLICY_DENIED",
                        "error",
                        subject,
                        f"Declared license {expression!r} matches a denied policy marker.",
                    )
                )
            elif classification == "unknown":
                findings.append(
                    Finding(
                        "LICENSE_POLICY_UNKNOWN",
                        "error",
                        subject,
                        f"Declared license {expression!r} is not classified by policy.",
                    )
                )
            elif classification == "manual_review":
                license_subjects.setdefault(expression, set()).add(subject)

    ecosystem = entry.get("ecosystem")
    if ecosystem == "python":
        _check_python_lock_coverage(repo, components, findings)
    elif ecosystem == "web":
        _check_web_lock_coverage(repo, components, findings)
    else:
        raise GateConfigurationError(f"unsupported SBOM ecosystem: {ecosystem!r}")


def _is_excluded(path: Path, root: Path, excluded: set[str]) -> bool:
    relative_parts = path.relative_to(root).parts
    return any(part in excluded for part in relative_parts)


def _discover_assets(repo: Path, manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    extensions = {str(value).lower() for value in manifest["asset_extensions"]}
    text_extensions = {str(value).lower() for value in manifest["embedded_text_extensions"]}
    excluded = {str(value) for value in manifest["excluded_directories"]}
    roots = [_resolve_beneath(repo, str(value)) for value in manifest["inventory_roots"]]
    discovered: dict[str, dict[str, Any]] = {}

    for inventory_root in roots:
        if not inventory_root.is_dir():
            raise GateConfigurationError(f"asset inventory root is missing: {inventory_root}")
        for path in sorted(inventory_root.rglob("*")):
            if _is_excluded(path, repo, excluded):
                continue
            if path.is_symlink():
                relative_path = path.relative_to(repo).as_posix()
                raise GateConfigurationError(
                    f"symbolic links are not permitted in asset inventory: {relative_path}"
                )
            if not path.is_file():
                continue
            relative_path = path.relative_to(repo).as_posix()
            if path.suffix.lower() in extensions:
                payload = path.read_bytes()
                identifier = f"file:{relative_path}"
                discovered[identifier] = {
                    "id": identifier,
                    "path": relative_path,
                    "bytes": len(payload),
                    "sha256": _sha256_bytes(payload),
                    "media_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
                }
            if path.suffix.lower() not in text_extensions or path.stat().st_size > 10_000_000:
                continue
            payload = path.read_bytes()
            for match in DATA_URI_PATTERN.finditer(payload):
                media_type = match.group(1).decode("ascii")
                encoded = re.sub(rb"\s+", b"", match.group(2))
                try:
                    decoded = base64.b64decode(encoded, validate=True)
                except ValueError as exc:
                    raise GateConfigurationError(
                        f"invalid embedded base64 asset in {relative_path}"
                    ) from exc
                digest = _sha256_bytes(decoded)
                identifier = f"embedded:{relative_path}#{media_type}:{digest}"
                discovered[identifier] = {
                    "id": identifier,
                    "source_path": relative_path,
                    "bytes": len(decoded),
                    "sha256": digest,
                    "media_type": media_type,
                }
    return discovered


def _check_assets(
    repo: Path,
    manifest: dict[str, Any],
    findings: list[Finding],
) -> set[str]:
    assets = _require_list(manifest.get("assets"), "assets-manifest.assets")
    declared: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(assets):
        if not isinstance(value, dict):
            raise GateConfigurationError(f"assets[{index}] must be an object")
        identifier = _require_string(value.get("id"), f"assets[{index}].id")
        if identifier in declared:
            findings.append(
                Finding(
                    "ASSET_MANIFEST_DUPLICATE",
                    "error",
                    identifier,
                    "Asset identifier occurs more than once.",
                )
            )
        declared[identifier] = value
    discovered = _discover_assets(repo, manifest)
    for identifier in sorted(discovered.keys() - declared.keys()):
        findings.append(
            Finding(
                "ASSET_UNREGISTERED",
                "error",
                identifier,
                "Repository asset is absent from the provenance manifest.",
            )
        )
    for identifier in sorted(declared.keys() - discovered.keys()):
        findings.append(
            Finding(
                "ASSET_DECLARATION_STALE",
                "error",
                identifier,
                "Provenance manifest entry does not correspond to a repository asset.",
            )
        )
    for identifier in sorted(declared.keys() & discovered.keys()):
        expected = declared[identifier]
        actual = discovered[identifier]
        expected_hash = str(expected.get("sha256", "")).lower()
        expected_bytes = expected.get("bytes")
        if expected_hash != actual["sha256"] or expected_bytes != actual["bytes"]:
            findings.append(
                Finding(
                    "ASSET_CONTENT_DRIFT",
                    "error",
                    identifier,
                    "Asset bytes or SHA-256 differ from the provenance manifest.",
                )
            )
        if expected.get("media_type") != actual["media_type"]:
            findings.append(
                Finding(
                    "ASSET_MEDIA_TYPE_DRIFT",
                    "error",
                    identifier,
                    "Detected media type differs from the provenance manifest.",
                )
            )
        status = expected.get("provenance_status")
        if status not in {"verified", "unverified"}:
            findings.append(
                Finding(
                    "ASSET_PROVENANCE_STATUS_INVALID",
                    "error",
                    identifier,
                    "provenance_status must be verified or unverified.",
                )
            )
    return set(declared)


def _has_evidence(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    reference = value.get("reference")
    digest = value.get("sha256")
    if not isinstance(reference, str) or not reference.strip():
        return False
    if any(marker in reference.casefold() for marker in PLACEHOLDER_MARKERS):
        return False
    return isinstance(digest, str) and SHA256_PATTERN.fullmatch(digest) is not None


def _approval_is_complete(value: Any) -> bool:
    if not isinstance(value, dict) or value.get("status") != "approved":
        return False
    required_strings = ("name", "organization", "role", "signed_at")
    if any(
        not isinstance(value.get(field), str) or not value[field].strip()
        for field in required_strings
    ):
        return False
    signed_at = value["signed_at"].replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(signed_at)
    except ValueError:
        return False
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return False
    return _has_evidence(value.get("evidence"))


def _contains_digest(value: Any, digest: str) -> bool:
    candidates = {digest, digest.removeprefix("sha256:")}
    if isinstance(value, str):
        return value in candidates
    if isinstance(value, list):
        return any(_contains_digest(item, digest) for item in value)
    if isinstance(value, dict):
        return any(_contains_digest(item, digest) for item in value.values())
    return False


def _load_release_image_manifest(path: Path) -> list[ReleaseImage]:
    if not path.is_file() or path.is_symlink():
        raise GateConfigurationError("release.env.images must be a regular, non-symlink file")
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise GateConfigurationError(f"cannot read release.env.images: {exc}") from exc
    if content.startswith("\ufeff"):
        raise GateConfigurationError("release.env.images must not contain a byte-order mark")
    lines = content.splitlines()
    if not lines or any(not line for line in lines):
        raise GateConfigurationError("release.env.images must contain non-empty rows")

    images: list[ReleaseImage] = []
    for line_number, line in enumerate(lines, start=1):
        fields = line.split("\t")
        if len(fields) != 4 or any(not field for field in fields):
            raise GateConfigurationError(
                f"release.env.images row {line_number} must have four tab-separated fields"
            )
        reference, config_id, operating_system, architecture = fields
        match = IMAGE_REFERENCE_PATTERN.fullmatch(reference)
        if match is None:
            raise GateConfigurationError(
                f"release.env.images row {line_number} has an invalid immutable reference"
            )
        repository = match.group("name").rsplit(":", 1)[0]
        if any(part in {"", ".", ".."} for part in repository.split("/")):
            raise GateConfigurationError(
                f"release.env.images row {line_number} has an unsafe repository path"
            )
        if IMAGE_DIGEST_PATTERN.fullmatch(config_id) is None:
            raise GateConfigurationError(
                f"release.env.images row {line_number} has an invalid config digest"
            )
        if operating_system != "linux" or architecture != "amd64":
            raise GateConfigurationError(
                f"release.env.images row {line_number} must target linux/amd64"
            )
        images.append(
            ReleaseImage(
                reference=reference,
                manifest_digest=match.group("digest"),
                config_id=config_id,
                os=operating_system,
                architecture=architecture,
            )
        )

    for label, values in (
        ("reference", [image.reference for image in images]),
        ("manifest digest", [image.manifest_digest for image in images]),
        ("config digest", [image.config_id for image in images]),
    ):
        if len(values) != len(set(values)):
            raise GateConfigurationError(f"release.env.images contains a duplicate {label}")
    if [image.reference for image in images] != sorted(image.reference for image in images):
        raise GateConfigurationError("release.env.images rows must be sorted by reference")
    return images


def _load_checksum_manifest(path: Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        raise GateConfigurationError("SHA256SUMS must be a regular, non-symlink file")
    try:
        content = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise GateConfigurationError(f"cannot read SHA256SUMS: {exc}") from exc
    lines = content.splitlines()
    if not lines or any(not line for line in lines):
        raise GateConfigurationError("SHA256SUMS must contain non-empty rows")
    result: dict[str, str] = {}
    ordered_paths: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        match = CHECKSUM_LINE_PATTERN.fullmatch(line)
        if match is None:
            raise GateConfigurationError(f"SHA256SUMS row {line_number} is malformed")
        digest, relative_path = match.groups()
        path_value = PurePosixPath(relative_path)
        if path_value.is_absolute() or ".." in path_value.parts or "//" in relative_path:
            raise GateConfigurationError(f"SHA256SUMS row {line_number} has an unsafe path")
        if relative_path in result:
            raise GateConfigurationError(f"SHA256SUMS repeats path {relative_path}")
        result[relative_path] = digest
        ordered_paths.append(relative_path)
    if ordered_paths != sorted(ordered_paths):
        raise GateConfigurationError("SHA256SUMS rows must be sorted by path")
    return result


def _metadata_property_map(document: dict[str, Any]) -> dict[str, str]:
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise GateConfigurationError("image SBOM metadata must be an object")
    raw_properties = metadata.get("properties")
    if not isinstance(raw_properties, list):
        raise GateConfigurationError("image SBOM metadata.properties must be an array")
    properties: dict[str, str] = {}
    for item in raw_properties:
        if not isinstance(item, dict):
            raise GateConfigurationError("image SBOM property must be an object")
        name = item.get("name")
        value = item.get("value")
        if not isinstance(name, str) or not isinstance(value, str):
            raise GateConfigurationError("image SBOM property name and value must be strings")
        if name in properties:
            raise GateConfigurationError(f"image SBOM repeats metadata property {name}")
        properties[name] = value
    return properties


def _check_image_sbom_index(
    *,
    artifact_root: Path,
    attestation: dict[str, Any],
    attested_release_id: Any,
    mode: Mode,
    findings: list[Finding],
) -> None:
    pending_severity = _severity(mode)
    raw_binding = attestation.get("image_sbom_index")
    binding = raw_binding if isinstance(raw_binding, dict) else {}
    if binding.get("status") != "approved":
        findings.append(
            Finding(
                "IMAGE_SBOM_APPROVAL_PENDING",
                pending_severity,
                "image-sbom-index",
                (
                    "The complete release.env.images set is not bound to an approved image "
                    "SBOM index and signed bundle checksum manifest."
                ),
            )
        )
        return

    required_fields = (
        "path",
        "sha256",
        "image_manifest_path",
        "image_manifest_sha256",
        "bundle_checksum_manifest_path",
        "bundle_checksum_manifest_sha256",
    )
    if any(not isinstance(binding.get(field), str) for field in required_fields):
        findings.append(
            Finding(
                "IMAGE_SBOM_INDEX_INVALID",
                pending_severity,
                "image-sbom-index",
                "Approved image SBOM evidence is missing a required path or SHA-256 binding.",
            )
        )
        return
    for field in (
        "sha256",
        "image_manifest_sha256",
        "bundle_checksum_manifest_sha256",
    ):
        if SHA256_PATTERN.fullmatch(str(binding[field])) is None:
            findings.append(
                Finding(
                    "IMAGE_SBOM_INDEX_INVALID",
                    pending_severity,
                    field,
                    "Approved image SBOM evidence contains an invalid SHA-256 digest.",
                )
            )
            return

    try:
        index_path = _resolve_beneath(artifact_root, str(binding["path"]))
        manifest_path = _resolve_beneath(artifact_root, str(binding["image_manifest_path"]))
        checksum_path = _resolve_beneath(
            artifact_root, str(binding["bundle_checksum_manifest_path"])
        )
        if any(
            path.is_symlink() or not path.is_file()
            for path in (index_path, manifest_path, checksum_path)
        ):
            raise GateConfigurationError("bound image evidence file is missing or is a symlink")
        if _sha256_file(index_path) != binding["sha256"]:
            raise GateConfigurationError("image SBOM index hash does not match the attestation")
        if _sha256_file(manifest_path) != binding["image_manifest_sha256"]:
            raise GateConfigurationError("release.env.images hash does not match the attestation")
        if _sha256_file(checksum_path) != binding["bundle_checksum_manifest_sha256"]:
            raise GateConfigurationError("SHA256SUMS hash does not match the attestation")
        index = _load_json_object(index_path)
        manifest_images = _load_release_image_manifest(manifest_path)
        checksums = _load_checksum_manifest(checksum_path)
    except (GateConfigurationError, OSError) as exc:
        findings.append(
            Finding(
                "IMAGE_SBOM_INDEX_INVALID",
                pending_severity,
                "image-sbom-index",
                str(exc),
            )
        )
        return

    index_relative = str(binding["path"])
    manifest_relative = str(binding["image_manifest_path"])
    required_checksum_bindings = {
        index_relative: str(binding["sha256"]),
        manifest_relative: str(binding["image_manifest_sha256"]),
    }
    checksum_mismatches = [
        relative_path
        for relative_path, digest in required_checksum_bindings.items()
        if checksums.get(relative_path) != digest
    ]
    if checksum_mismatches:
        findings.append(
            Finding(
                "IMAGE_SBOM_CHECKSUM_BINDING_INVALID",
                pending_severity,
                ", ".join(sorted(checksum_mismatches)),
                "The signed bundle checksum manifest does not bind the image identity inputs.",
            )
        )

    structural_ok = (
        index.get("$schema") == IMAGE_SBOM_INDEX_SCHEMA
        and index.get("schema_version") == 1
        and index.get("release_git_sha") == attested_release_id
        and index.get("source_manifest_path") == manifest_relative
        and index.get("source_manifest_sha256") == binding["image_manifest_sha256"]
        and isinstance(index.get("release_id"), str)
        and bool(index.get("release_id"))
    )
    raw_scanner = index.get("scanner")
    scanner = raw_scanner if isinstance(raw_scanner, dict) else {}
    structural_ok = (
        structural_ok
        and isinstance(scanner.get("name"), str)
        and bool(scanner.get("name"))
        and isinstance(scanner.get("sha256"), str)
        and SHA256_PATTERN.fullmatch(str(scanner.get("sha256"))) is not None
    )
    raw_records = index.get("images")
    if not structural_ok or not isinstance(raw_records, list) or not raw_records:
        findings.append(
            Finding(
                "IMAGE_SBOM_INDEX_INVALID",
                pending_severity,
                "image-sbom-index",
                "Image SBOM index metadata is incomplete or is not bound to this release.",
            )
        )
        return

    records = [record for record in raw_records if isinstance(record, dict)]
    record_references = [record.get("reference") for record in records]
    record_digests = [record.get("manifest_digest") for record in records]
    record_config_ids = [record.get("config_id") for record in records]
    record_sbom_paths = [record.get("sbom_path") for record in records]
    identity_columns = (
        record_references,
        record_digests,
        record_config_ids,
        record_sbom_paths,
    )
    duplicate_or_malformed = len(records) != len(raw_records) or any(
        not all(isinstance(value, str) for value in values) or len(values) != len(set(values))
        for values in identity_columns
    )
    manifest_by_reference = {image.reference: image for image in manifest_images}
    record_by_reference = {
        str(record.get("reference")): record
        for record in records
        if isinstance(record.get("reference"), str)
    }
    if duplicate_or_malformed or set(record_by_reference) != set(manifest_by_reference):
        findings.append(
            Finding(
                "IMAGE_SBOM_SET_MISMATCH",
                pending_severity,
                "image-sbom-index",
                (
                    "Image SBOM records must match every release.env.images entry exactly once; "
                    "missing, extra, duplicate, or malformed records are forbidden."
                ),
            )
        )
        return

    invalid_references: list[str] = []
    checksum_binding_failures: list[str] = []
    for reference in sorted(manifest_by_reference):
        identity = manifest_by_reference[reference]
        record = record_by_reference[reference]
        sbom_relative = record.get("sbom_path")
        sbom_sha256 = record.get("sbom_sha256")
        expected_file_name = f"image-{identity.manifest_digest.removeprefix('sha256:')}.cdx.json"
        valid = (
            record.get("manifest_digest") == identity.manifest_digest
            and record.get("config_id") == identity.config_id
            and record.get("os") == identity.os
            and record.get("architecture") == identity.architecture
            and isinstance(sbom_relative, str)
            and PurePosixPath(sbom_relative).name == expected_file_name
            and isinstance(sbom_sha256, str)
            and SHA256_PATTERN.fullmatch(sbom_sha256) is not None
            and isinstance(record.get("component_count"), int)
            and record.get("component_count", -1) >= 0
        )
        if valid:
            try:
                sbom_path = _resolve_beneath(artifact_root, str(sbom_relative))
                if sbom_path.is_symlink() or not sbom_path.is_file():
                    raise GateConfigurationError("image SBOM is missing or is a symlink")
                if _sha256_file(sbom_path) != sbom_sha256:
                    raise GateConfigurationError("image SBOM hash does not match its index record")
                document = _load_json_object(sbom_path)
                components = document.get("components")
                if (
                    document.get("bomFormat") != "CycloneDX"
                    or document.get("specVersion") != "1.6"
                    or not isinstance(components, list)
                    or len(components) != record["component_count"]
                ):
                    raise GateConfigurationError("image SBOM is not a bound CycloneDX 1.6 document")
                properties = _metadata_property_map(document)
                expected_properties = {
                    "io.heyi.image.architecture": identity.architecture,
                    "io.heyi.image.config_id": identity.config_id,
                    "io.heyi.image.manifest_digest": identity.manifest_digest,
                    "io.heyi.image.os": identity.os,
                    "io.heyi.image.reference": identity.reference,
                    "io.heyi.release.git_sha": str(attested_release_id),
                    "io.heyi.release.id": str(index["release_id"]),
                    "io.heyi.scanner.sha256": str(scanner["sha256"]),
                    "io.heyi.source_manifest.sha256": str(binding["image_manifest_sha256"]),
                }
                if any(properties.get(key) != value for key, value in expected_properties.items()):
                    raise GateConfigurationError(
                        "image SBOM release-binding properties do not match"
                    )
                if not _contains_digest(document, identity.manifest_digest):
                    raise GateConfigurationError("image SBOM does not contain its manifest digest")
            except (GateConfigurationError, OSError):
                valid = False
        if not valid:
            invalid_references.append(reference)
        if (
            isinstance(sbom_relative, str)
            and isinstance(sbom_sha256, str)
            and checksums.get(sbom_relative) != sbom_sha256
        ):
            checksum_binding_failures.append(reference)

    if invalid_references:
        findings.append(
            Finding(
                "IMAGE_SBOM_BINDING_INVALID",
                pending_severity,
                f"{len(invalid_references)} image(s)",
                (
                    "One or more image SBOMs are missing, altered, or not bound to exact "
                    "image identity."
                ),
            )
        )
    if checksum_binding_failures:
        findings.append(
            Finding(
                "IMAGE_SBOM_CHECKSUM_BINDING_INVALID",
                pending_severity,
                f"{len(checksum_binding_failures)} image(s)",
                "One or more image SBOMs are absent or mismatched in the signed checksum set.",
            )
        )


def _check_project_license_metadata(
    repo: Path,
    policy: dict[str, Any],
    mode: Mode,
    findings: list[Finding],
) -> tuple[str | None, str | None, list[Path]]:
    try:
        pyproject = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
        package = _load_json_object(repo / "web" / "package.json")
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, GateConfigurationError) as exc:
        findings.append(Finding("PROJECT_METADATA_INVALID", "error", "project", str(exc)))
        return None, None, []
    python_license = pyproject.get("project", {}).get("license")
    if isinstance(python_license, dict):
        python_license = python_license.get("text") or python_license.get("file")
    web_license = package.get("license")
    license_files = [
        repo / str(relative_path)
        for relative_path in policy["project_license_files"]
        if (repo / str(relative_path)).is_file()
    ]
    if not isinstance(python_license, str) or not python_license.strip():
        findings.append(
            Finding(
                "PROJECT_PYTHON_LICENSE_PENDING",
                _severity(mode),
                "pyproject.toml",
                "The Python root project does not declare its governing license.",
            )
        )
        python_license = None
    if not isinstance(web_license, str) or not web_license.strip():
        findings.append(
            Finding(
                "PROJECT_WEB_LICENSE_PENDING",
                _severity(mode),
                "web/package.json",
                "The Web root project does not declare its governing license.",
            )
        )
        web_license = None
    if not license_files:
        findings.append(
            Finding(
                "PROJECT_LICENSE_FILE_PENDING",
                _severity(mode),
                "LICENSE",
                "No project-level license file approved by the rights owner is present.",
            )
        )
    return python_license, web_license, license_files


def _check_release_attestation(
    repo: Path,
    artifact_root: Path,
    attestation: dict[str, Any],
    asset_ids: set[str],
    manual_licenses: set[str],
    metadata_licenses: tuple[str | None, str | None],
    mode: Mode,
    expected_release_id: str | None,
    findings: list[Finding],
) -> None:
    pending_severity = _severity(mode)
    if attestation.get("status") != "approved":
        findings.append(
            Finding(
                "RELEASE_RIGHTS_ATTESTATION_PENDING",
                pending_severity,
                "release-rights-attestation",
                "Release-specific rights and license attestation is not approved.",
            )
        )
    release_id = attestation.get("release_id")
    if not isinstance(release_id, str) or RELEASE_ID_PATTERN.fullmatch(release_id) is None:
        findings.append(
            Finding(
                "RELEASE_ID_NOT_IMMUTABLE",
                pending_severity,
                "release-rights-attestation",
                "release_id must be a 40- or 64-character lowercase hexadecimal digest.",
            )
        )
    if mode == "release" and expected_release_id is None:
        findings.append(
            Finding(
                "EXPECTED_RELEASE_ID_REQUIRED",
                "error",
                "release-rights-attestation",
                "Release mode requires --expected-release-id to bind evidence to the candidate.",
            )
        )
    elif expected_release_id is not None and release_id != expected_release_id:
        findings.append(
            Finding(
                "RELEASE_ID_MISMATCH",
                _severity(mode),
                "release-rights-attestation",
                "Attested release_id does not match the expected immutable candidate ID.",
            )
        )

    raw_project_license = attestation.get("project_license")
    project_license: dict[str, Any] = (
        raw_project_license if isinstance(raw_project_license, dict) else {}
    )
    project_license_ok = project_license.get("status") == "approved"
    if project_license_ok:
        expression = project_license.get("expression")
        relative_path = project_license.get("path")
        expected_hash = project_license.get("sha256")
        python_license, web_license = metadata_licenses
        if (
            not isinstance(expression, str)
            or python_license != expression
            or web_license != expression
        ):
            project_license_ok = False
        if not isinstance(relative_path, str) or not isinstance(expected_hash, str):
            project_license_ok = False
        else:
            try:
                path = _resolve_beneath(repo, relative_path)
            except GateConfigurationError:
                project_license_ok = False
            else:
                project_license_ok = (
                    path.is_file()
                    and SHA256_PATTERN.fullmatch(expected_hash) is not None
                    and _sha256_file(path) == expected_hash
                )
        project_license_ok = project_license_ok and _has_evidence(project_license.get("evidence"))
    if not project_license_ok:
        findings.append(
            Finding(
                "PROJECT_LICENSE_APPROVAL_PENDING",
                pending_severity,
                "project-license",
                "Project license selection is not bound to matching package metadata and evidence.",
            )
        )

    reviews = attestation.get("license_reviews")
    review_by_expression = (
        {
            item.get("expression"): item
            for item in reviews
            if isinstance(reviews, list) and isinstance(item, dict)
        }
        if isinstance(reviews, list)
        else {}
    )
    if (
        not isinstance(reviews, list)
        or len(reviews) != len(review_by_expression)
        or set(review_by_expression) != manual_licenses
    ):
        findings.append(
            Finding(
                "LICENSE_REVIEW_SET_MISMATCH",
                pending_severity,
                "license-reviews",
                "Attestation must cover each current manual-review expression exactly once.",
            )
        )
    for expression in sorted(manual_licenses):
        review = review_by_expression.get(expression)
        if mode == "release" and (
            not isinstance(review, dict)
            or review.get("status") != "approved"
            or not _has_evidence(review.get("evidence"))
        ):
            findings.append(
                Finding(
                    "LICENSE_MANUAL_REVIEW_PENDING",
                    pending_severity,
                    expression,
                    "A manual license-obligation review is required for this release.",
                )
            )

    approvals = attestation.get("asset_approvals")
    approval_by_id = (
        {
            item.get("asset_id"): item
            for item in approvals
            if isinstance(approvals, list) and isinstance(item, dict)
        }
        if isinstance(approvals, list)
        else {}
    )
    if (
        not isinstance(approvals, list)
        or len(approvals) != len(approval_by_id)
        or set(approval_by_id) != asset_ids
    ):
        findings.append(
            Finding(
                "ASSET_APPROVAL_SET_MISMATCH",
                pending_severity,
                "asset-approvals",
                "Release attestation must cover every current asset identifier exactly once.",
            )
        )
    pending_asset_ids = [
        asset_id
        for asset_id in sorted(asset_ids)
        if not isinstance(approval_by_id.get(asset_id), dict)
        or approval_by_id[asset_id].get("status") != "approved"
        or not _has_evidence(approval_by_id[asset_id].get("evidence"))
    ]
    if mode == "inventory" and pending_asset_ids:
        findings.append(
            Finding(
                "ASSET_RIGHTS_APPROVAL_PENDING",
                "review",
                f"{len(pending_asset_ids)} asset(s)",
                "Rights-owner or authorized trademark/material approval remains pending.",
            )
        )
    for asset_id in pending_asset_ids if mode == "release" else []:
        findings.append(
            Finding(
                "ASSET_RIGHTS_APPROVAL_PENDING",
                pending_severity,
                asset_id,
                "Rights-owner or authorized trademark/material approval is not evidenced.",
            )
        )

    raw_notices = attestation.get("third_party_notices")
    notices: dict[str, Any] = raw_notices if isinstance(raw_notices, dict) else {}
    notices_ok = notices.get("status") == "approved"
    if notices_ok:
        notices_path = notices.get("path")
        notices_hash = notices.get("sha256")
        if not isinstance(notices_path, str) or not isinstance(notices_hash, str):
            notices_ok = False
        else:
            try:
                path = _resolve_beneath(repo, notices_path)
            except GateConfigurationError:
                notices_ok = False
            else:
                notices_ok = (
                    path.is_file()
                    and SHA256_PATTERN.fullmatch(notices_hash) is not None
                    and _sha256_file(path) == notices_hash
                )
        notices_ok = notices_ok and _has_evidence(notices.get("evidence"))
    if not notices_ok:
        findings.append(
            Finding(
                "THIRD_PARTY_NOTICES_APPROVAL_PENDING",
                pending_severity,
                "docs/THIRD-PARTY-NOTICES.md",
                "Final third-party notices are not approved and content-hash bound.",
            )
        )

    _check_image_sbom_index(
        artifact_root=artifact_root,
        attestation=attestation,
        attested_release_id=release_id,
        mode=mode,
        findings=findings,
    )

    for role in ("rights_owner_approval", "legal_approval"):
        if not _approval_is_complete(attestation.get(role)):
            findings.append(
                Finding(
                    "MANUAL_SIGNOFF_PENDING",
                    pending_severity,
                    role,
                    "Named approval and content-hash-bound signature evidence are required.",
                )
            )


def run_gate(
    repo: Path,
    *,
    mode: Mode,
    attestation_path: Path | None = None,
    artifact_root: Path | None = None,
    expected_release_id: str | None = None,
) -> dict[str, Any]:
    repo = repo.resolve()
    artifact_root = (artifact_root or repo).resolve()
    compliance = repo / "compliance"
    snapshot = _load_json_object(compliance / "dependency-snapshot.json")
    policy = _load_json_object(compliance / "license-policy.json")
    assets = _load_json_object(compliance / "assets-manifest.json")
    if attestation_path is None:
        attestation_path = compliance / "release-rights.template.json"
    elif not attestation_path.is_absolute():
        attestation_path = repo / attestation_path
    attestation = _load_json_object(attestation_path.resolve())
    for label, value in (
        ("dependency-snapshot", snapshot),
        ("license-policy", policy),
        ("assets-manifest", assets),
        ("release-rights-attestation", attestation),
    ):
        if value.get("schema_version") != 1:
            raise GateConfigurationError(f"{label} schema_version must equal 1")
    _validate_configuration(snapshot, policy, assets)
    if (
        expected_release_id is not None
        and RELEASE_ID_PATTERN.fullmatch(expected_release_id) is None
    ):
        raise GateConfigurationError("expected_release_id must be a 40- or 64-character digest")

    findings: list[Finding] = []
    for index, entry in enumerate(_require_list(snapshot.get("inputs"), "snapshot.inputs")):
        if not isinstance(entry, dict):
            raise GateConfigurationError(f"snapshot.inputs[{index}] must be an object")
        _check_bound_file(repo, entry, findings, "LOCK_INPUT")

    license_subjects: dict[str, set[str]] = {}
    sboms = _require_list(snapshot.get("sboms"), "snapshot.sboms")
    for index, entry in enumerate(sboms):
        if not isinstance(entry, dict):
            raise GateConfigurationError(f"snapshot.sboms[{index}] must be an object")
        _check_sbom(repo, entry, policy, mode, findings, license_subjects)

    asset_ids = _check_assets(repo, assets, findings)
    python_license, web_license, _ = _check_project_license_metadata(repo, policy, mode, findings)
    for expression, subjects in sorted(license_subjects.items()):
        findings.append(
            Finding(
                "LICENSE_MANUAL_REVIEW_REQUIRED",
                "review" if mode == "inventory" else "info",
                expression,
                f"Manual release review applies to {len(subjects)} component(s).",
            )
        )
    _check_release_attestation(
        repo,
        artifact_root,
        attestation,
        asset_ids,
        set(license_subjects),
        (python_license, web_license),
        mode,
        expected_release_id,
        findings,
    )

    sorted_findings = sorted(set(findings))
    errors = sum(finding.severity == "error" for finding in sorted_findings)
    reviews = sum(finding.severity == "review" for finding in sorted_findings)
    report: dict[str, Any] = {
        "schema_version": 1,
        "mode": mode,
        "status": "PASS" if errors == 0 else "FAIL",
        "release_eligible": mode == "release" and errors == 0,
        "snapshot_digest": _canonical_digest(
            {
                "dependency_snapshot": snapshot,
                "license_policy": policy,
                "assets_manifest": assets,
            }
        ),
        "summary": {
            "errors": errors,
            "manual_reviews": reviews,
            "sboms": len(sboms),
            "declared_assets": len(asset_ids),
            "manual_license_expressions": len(license_subjects),
        },
        "findings": [asdict(finding) for finding in sorted_findings],
        "limitations": [
            "Package metadata can be incomplete or incorrect; this gate is not legal advice.",
            "Human approval references are hash-bound records, not identity verification.",
            "Release mode requires final image SBOMs; lock-file SBOMs do not cover OS packages.",
            (
                "The report digest must be signed with the immutable release; "
                "repository data can be edited."
            ),
        ],
    }
    report["report_sha256"] = _canonical_digest(report)
    return report


def _write_report(path: Path, report_text: str) -> None:
    path = path.absolute()
    existing_ancestor = path.parent
    while True:
        try:
            existing_ancestor.lstat()
        except FileNotFoundError:
            parent = existing_ancestor.parent
            if parent == existing_ancestor:
                raise GateConfigurationError(
                    "report output has no existing trusted ancestor"
                ) from None
            existing_ancestor = parent
            continue
        except OSError as exc:
            raise GateConfigurationError("cannot inspect report output ancestors") from exc
        break
    if _path_contains_symlink(existing_ancestor):
        raise GateConfigurationError("report output path cannot contain a symlink")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if _path_contains_symlink(path.parent):
        raise GateConfigurationError("report output path cannot contain a symlink")

    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    temporary_path = path.with_name(temporary_name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_descriptor: int | None = None
    descriptor: int | None = None
    temporary_created = False
    try:
        if os.name == "posix":
            directory_descriptor = _trusted_directory_descriptor(path.parent)
            try:
                destination = os.stat(path.name, dir_fd=directory_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                destination = None
            if destination is not None and not stat.S_ISREG(destination.st_mode):
                raise GateConfigurationError("report destination must be a regular file")
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
        else:
            try:
                destination = path.lstat()
            except FileNotFoundError:
                destination = None
            if destination is not None and not stat.S_ISREG(destination.st_mode):
                raise GateConfigurationError("report destination must be a regular file")
            descriptor = os.open(temporary_path, flags, 0o600)
        temporary_created = True
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(report_text.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        if directory_descriptor is not None:
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            temporary_created = False
            os.fsync(directory_descriptor)
        else:
            try:
                destination = path.lstat()
            except FileNotFoundError:
                destination = None
            if destination is not None and not stat.S_ISREG(destination.st_mode):
                raise GateConfigurationError("report destination must be a regular file")
            os.replace(temporary_path, path)
            temporary_created = False
    except (GateConfigurationError, OSError):
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if temporary_created:
            with suppress(OSError):
                if directory_descriptor is not None:
                    os.unlink(temporary_name, dir_fd=directory_descriptor)
                else:
                    temporary_path.unlink()
        raise
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _path_contains_symlink(path: Path) -> bool:
    candidate = path.absolute()
    for component in (candidate, *candidate.parents):
        try:
            if stat.S_ISLNK(component.lstat().st_mode):
                return True
        except FileNotFoundError:
            continue
        except OSError:
            return True
    return False


def _trusted_directory_descriptor(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        pinned = os.fstat(descriptor)
        current = path.stat()
        if (
            not stat.S_ISDIR(pinned.st_mode)
            or (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino)
            or (
                os.name == "posix"
                and (
                    pinned.st_uid != os.geteuid()  # type: ignore[attr-defined]
                    or pinned.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                )
            )
        ):
            raise GateConfigurationError("report output directory is not private and trusted")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify locked dependency, SBOM, asset provenance, and release-rights evidence."
    )
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--mode", choices=("inventory", "release"), default="inventory")
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--expected-release-id")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run_gate(
            args.repo,
            mode=args.mode,
            attestation_path=args.attestation,
            artifact_root=args.artifact_root,
            expected_release_id=args.expected_release_id,
        )
    except (GateConfigurationError, KeyError, OSError, TypeError) as exc:
        report = {
            "schema_version": 1,
            "mode": args.mode,
            "status": "FAIL",
            "release_eligible": False,
            "summary": {"errors": 1, "manual_reviews": 0},
            "findings": [
                asdict(Finding("GATE_CONFIGURATION_INVALID", "error", "configuration", str(exc)))
            ],
            "limitations": ["The gate could not evaluate malformed or missing committed inputs."],
        }
        report["report_sha256"] = _canonical_digest(report)
    report_text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        try:
            _write_report(args.output, report_text)
        except (GateConfigurationError, OSError) as exc:
            report = {
                "schema_version": 1,
                "mode": args.mode,
                "status": "FAIL",
                "release_eligible": False,
                "summary": {"errors": 1, "manual_reviews": 0},
                "findings": [
                    asdict(
                        Finding(
                            "REPORT_PUBLICATION_FAILED",
                            "error",
                            "output",
                            str(exc),
                        )
                    )
                ],
                "limitations": ["The report could not be durably published."],
            }
            report["report_sha256"] = _canonical_digest(report)
            report_text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    sys.stdout.write(report_text)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
