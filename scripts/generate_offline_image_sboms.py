from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REFERENCE_PATTERN = re.compile(
    r"^127\.0\.0\.1:5000/"
    r"(?P<name>[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?)"
    r"@(?P<digest>sha256:[0-9a-f]{64})$"
)
BINDING_PREFIX = "io.heyi."
INDEX_SCHEMA = "https://knowledgebases.local/schemas/image-sbom-index-v1.schema.json"
PROXY_ENVIRONMENT_KEYS = {
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
}


class ImageSbomContractError(ValueError):
    """Raised when image identity or generated evidence violates the release contract."""


@dataclass(frozen=True, order=True)
class ImageIdentity:
    reference: str
    manifest_digest: str
    config_id: str
    os: str
    architecture: str


Runner = Callable[[Sequence[str], dict[str, str], int], None]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ImageSbomContractError(f"cannot read CycloneDX JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ImageSbomContractError(f"CycloneDX document must be an object: {path}")
    return value


def _validate_relative_path(value: str, label: str) -> None:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ImageSbomContractError(f"{label} must be a safe relative POSIX path")


def _relative_to(root: Path, path: Path, label: str) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ImageSbomContractError(f"{label} must be beneath artifact_root") from exc
    value = relative.as_posix()
    _validate_relative_path(value, label)
    return value


def _validate_reference(reference: str) -> str:
    match = REFERENCE_PATTERN.fullmatch(reference)
    if match is None:
        raise ImageSbomContractError(
            "image reference must use the loopback registry and an immutable sha256 digest"
        )
    repository_and_tag = match.group("name")
    repository = repository_and_tag.rsplit(":", 1)[0]
    if any(part in {"", ".", ".."} for part in repository.split("/")):
        raise ImageSbomContractError("image reference contains an unsafe repository path")
    return match.group("digest")


def parse_image_manifest(path: Path) -> list[ImageIdentity]:
    if not path.is_file() or path.is_symlink():
        raise ImageSbomContractError("image manifest must be a regular, non-symlink file")
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ImageSbomContractError(f"cannot read image manifest: {exc}") from exc
    if content.startswith("\ufeff"):
        raise ImageSbomContractError("image manifest must not contain a byte-order mark")
    lines = content.splitlines()
    if not lines or any(not line for line in lines):
        raise ImageSbomContractError("image manifest must contain non-empty rows")

    images: list[ImageIdentity] = []
    for line_number, line in enumerate(lines, start=1):
        fields = line.split("\t")
        if len(fields) != 4 or any(not field for field in fields):
            raise ImageSbomContractError(
                f"image manifest row {line_number} must contain exactly four tab-separated fields"
            )
        reference, config_id, operating_system, architecture = fields
        manifest_digest = _validate_reference(reference)
        if DIGEST_PATTERN.fullmatch(config_id) is None:
            raise ImageSbomContractError(
                f"image manifest row {line_number} has an invalid config digest"
            )
        if operating_system != "linux" or architecture != "amd64":
            raise ImageSbomContractError(
                f"image manifest row {line_number} must target linux/amd64"
            )
        images.append(
            ImageIdentity(
                reference=reference,
                manifest_digest=manifest_digest,
                config_id=config_id,
                os=operating_system,
                architecture=architecture,
            )
        )

    references = [image.reference for image in images]
    manifest_digests = [image.manifest_digest for image in images]
    config_ids = [image.config_id for image in images]
    for label, values in (
        ("reference", references),
        ("manifest digest", manifest_digests),
        ("config digest", config_ids),
    ):
        if len(values) != len(set(values)):
            raise ImageSbomContractError(f"image manifest contains a duplicate {label}")
    if references != sorted(references):
        raise ImageSbomContractError("image manifest rows must be sorted by reference")
    return images


def parse_local_image_map(path: Path, images: Sequence[ImageIdentity]) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        raise ImageSbomContractError("local image map must be a regular, non-symlink file")
    try:
        content = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise ImageSbomContractError(f"cannot read local image map: {exc}") from exc
    lines = content.splitlines()
    if not lines or any(not line for line in lines):
        raise ImageSbomContractError("local image map must contain non-empty rows")

    signed_images = {image.reference: image for image in images}
    mapping: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        fields = line.split("\t")
        if len(fields) != 2 or any(not field for field in fields):
            raise ImageSbomContractError(
                f"local image map row {line_number} must contain exactly two tab-separated fields"
            )
        reference, local_id = fields
        _validate_reference(reference)
        if DIGEST_PATTERN.fullmatch(local_id) is None:
            raise ImageSbomContractError(
                f"local image map row {line_number} has an invalid Docker image identity"
            )
        if reference in mapping:
            raise ImageSbomContractError("local image map contains a duplicate reference")
        signed_image = signed_images.get(reference)
        if signed_image is None:
            raise ImageSbomContractError("local image map differs from the signed image manifest")
        if local_id not in {signed_image.manifest_digest, signed_image.config_id}:
            raise ImageSbomContractError(
                f"local image map row {line_number} must equal its signed manifest digest "
                "or config digest"
            )
        mapping[reference] = local_id

    references = list(mapping)
    expected_references = [image.reference for image in images]
    if references != sorted(references):
        raise ImageSbomContractError("local image map rows must be sorted by reference")
    if references != expected_references:
        raise ImageSbomContractError("local image map differs from the signed image manifest")
    if len(set(mapping.values())) != len(mapping):
        raise ImageSbomContractError("local image map contains a duplicate Docker image identity")
    return mapping


def _default_runner(command: Sequence[str], environment: dict[str, str], timeout: int) -> None:
    try:
        subprocess.run(
            list(command),
            check=True,
            capture_output=True,
            env=environment,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ImageSbomContractError(f"image SBOM scanner failed: {exc}") from exc


def _scanner_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.casefold() not in PROXY_ENVIRONMENT_KEYS
    }
    environment["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
    return environment


def _sort_object_list(value: Any, fields: tuple[str, ...]) -> None:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        return
    value.sort(key=lambda item: tuple(str(item.get(field, "")) for field in fields))


def _normalise_cyclonedx(
    document: dict[str, Any],
    *,
    image: ImageIdentity,
    scan_identity: str,
    release_id: str,
    release_git_sha: str,
    source_manifest_sha256: str,
    scanner_sha256: str,
) -> dict[str, Any]:
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        raise ImageSbomContractError("scanner output must be CycloneDX 1.6 JSON")
    document.pop("serialNumber", None)
    metadata = document.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise ImageSbomContractError("CycloneDX metadata must be an object")
    metadata.pop("timestamp", None)
    raw_properties = metadata.get("properties", [])
    if not isinstance(raw_properties, list) or not all(
        isinstance(item, dict) for item in raw_properties
    ):
        raise ImageSbomContractError("CycloneDX metadata.properties must be an object array")
    if any(str(item.get("name", "")).startswith(BINDING_PREFIX) for item in raw_properties):
        raise ImageSbomContractError("scanner output contains reserved release-binding properties")

    bindings = {
        "io.heyi.image.architecture": image.architecture,
        "io.heyi.image.config_id": image.config_id,
        "io.heyi.image.manifest_digest": image.manifest_digest,
        "io.heyi.image.os": image.os,
        "io.heyi.image.reference": image.reference,
        "io.heyi.image.scan_identity": scan_identity,
        "io.heyi.release.git_sha": release_git_sha,
        "io.heyi.release.id": release_id,
        "io.heyi.scanner.sha256": scanner_sha256,
        "io.heyi.source_manifest.sha256": source_manifest_sha256,
    }
    metadata["properties"] = sorted(
        [*raw_properties, *({"name": key, "value": value} for key, value in bindings.items())],
        key=lambda item: (str(item.get("name", "")), str(item.get("value", ""))),
    )
    _sort_object_list(document.get("components"), ("bom-ref", "name", "version", "purl"))
    _sort_object_list(document.get("services"), ("bom-ref", "name", "version"))
    _sort_object_list(document.get("dependencies"), ("ref",))
    _sort_object_list(document.get("vulnerabilities"), ("bom-ref", "id"))
    return document


def _validate_scanner(scanner: Path, expected_sha256: str) -> tuple[Path, str]:
    if not scanner.is_absolute():
        raise ImageSbomContractError("scanner path must be absolute")
    if scanner.is_symlink() or not scanner.is_file():
        raise ImageSbomContractError("scanner must be a regular, non-symlink file")
    if SHA256_PATTERN.fullmatch(expected_sha256) is None:
        raise ImageSbomContractError("scanner_sha256 must be a lowercase SHA-256 digest")
    actual_sha256 = _sha256_file(scanner)
    if actual_sha256 != expected_sha256:
        raise ImageSbomContractError("scanner binary SHA-256 does not match the approved digest")
    return scanner.resolve(), actual_sha256


def generate_image_sboms(
    *,
    artifact_root: Path,
    image_manifest: Path,
    local_image_map: Path,
    output_dir: Path,
    scanner: Path,
    scanner_sha256: str,
    release_id: str,
    release_git_sha: str,
    timeout_seconds: int = 900,
    dry_run: bool = False,
    runner: Runner = _default_runner,
) -> dict[str, Any]:
    artifact_root = artifact_root.resolve()
    image_manifest = image_manifest.resolve()
    local_image_map = local_image_map.resolve()
    output_dir = output_dir.resolve()
    if not artifact_root.is_dir():
        raise ImageSbomContractError("artifact_root must be an existing directory")
    try:
        local_image_map.relative_to(artifact_root)
    except ValueError:
        pass
    else:
        raise ImageSbomContractError("local image map must remain outside artifact_root")
    manifest_relative = _relative_to(artifact_root, image_manifest, "image_manifest")
    output_relative = _relative_to(artifact_root, output_dir, "output_dir")
    if output_dir == artifact_root or output_relative == ".":
        raise ImageSbomContractError("output_dir must be a child of artifact_root")
    if output_dir.exists():
        raise ImageSbomContractError("output_dir must not already exist")
    if not release_id or any(character.isspace() for character in release_id):
        raise ImageSbomContractError("release_id must be a non-empty token")
    if GIT_SHA_PATTERN.fullmatch(release_git_sha) is None:
        raise ImageSbomContractError("release_git_sha must be a lowercase 40-character Git SHA")
    if timeout_seconds <= 0:
        raise ImageSbomContractError("timeout_seconds must be positive")

    scanner_path, actual_scanner_sha256 = _validate_scanner(scanner, scanner_sha256)
    images = parse_image_manifest(image_manifest)
    local_images = parse_local_image_map(local_image_map, images)
    source_manifest_sha256 = _sha256_file(image_manifest)
    plan = {
        "status": "DRY_RUN" if dry_run else "PASS",
        "image_count": len(images),
        "source_manifest_sha256": source_manifest_sha256,
        "scanner_sha256": actual_scanner_sha256,
    }
    if dry_run:
        return plan

    staging = output_dir.with_name(f".{output_dir.name}.staging-{uuid.uuid4().hex}")
    if staging.exists():
        raise ImageSbomContractError("unexpected pre-existing staging directory")
    staging.mkdir(parents=False)
    try:
        records: list[dict[str, Any]] = []
        environment = _scanner_environment()
        for image in images:
            scan_identity = local_images[image.reference]
            digest_hex = image.manifest_digest.removeprefix("sha256:")
            raw_path = staging / f".raw-{digest_hex}.cdx.json"
            final_name = f"image-{digest_hex}.cdx.json"
            command = [
                str(scanner_path),
                "scan",
                # The release reference names the target host's loopback
                # Registry and is intentionally unavailable after the isolated
                # build Registry stops. Scan the already verified local Docker
                # image by the Docker backend's exact local content identity to
                # prevent network fallback. Docker 29 containerd stores expose
                # a manifest digest as .Id, while legacy stores expose the
                # config digest. The signed evidence still binds the separately
                # verified manifest, true config digest and final reference.
                f"docker:{scan_identity}",
                "-o",
                f"cyclonedx-json={raw_path}",
            ]
            runner(command, environment.copy(), timeout_seconds)
            raw_document = _load_json_object(raw_path)
            document = _normalise_cyclonedx(
                raw_document,
                image=image,
                scan_identity=scan_identity,
                release_id=release_id,
                release_git_sha=release_git_sha,
                source_manifest_sha256=source_manifest_sha256,
                scanner_sha256=actual_scanner_sha256,
            )
            final_path = staging / final_name
            _write_json(final_path, document)
            raw_path.unlink(missing_ok=True)
            relative_sbom = PurePosixPath(output_relative, final_name).as_posix()
            records.append(
                {
                    "architecture": image.architecture,
                    "component_count": len(document.get("components", [])),
                    "config_id": image.config_id,
                    "manifest_digest": image.manifest_digest,
                    "os": image.os,
                    "reference": image.reference,
                    "scan_identity": scan_identity,
                    "sbom_path": relative_sbom,
                    "sbom_sha256": _sha256_file(final_path),
                }
            )

        index = {
            "$schema": INDEX_SCHEMA,
            "images": records,
            "release_git_sha": release_git_sha,
            "release_id": release_id,
            "scanner": {
                "name": scanner_path.name,
                "sha256": actual_scanner_sha256,
            },
            "schema_version": 1,
            "source_manifest_path": manifest_relative,
            "source_manifest_sha256": source_manifest_sha256,
        }
        index_path = staging / "image-sbom-index.json"
        _write_json(index_path, index)
        index_sha256 = _sha256_file(index_path)
        staging.replace(output_dir)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return {
        **plan,
        "index_path": PurePosixPath(output_relative, "image-sbom-index.json").as_posix(),
        "index_sha256": index_sha256,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate deterministic, digest-bound SBOMs for every offline release image."
    )
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--image-manifest", type=Path, required=True)
    parser.add_argument("--local-image-map", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--scanner-sha256", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--release-git-sha", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        report = generate_image_sboms(
            artifact_root=arguments.artifact_root,
            image_manifest=arguments.image_manifest,
            local_image_map=arguments.local_image_map,
            output_dir=arguments.output_dir,
            scanner=arguments.scanner,
            scanner_sha256=arguments.scanner_sha256,
            release_id=arguments.release_id,
            release_git_sha=arguments.release_git_sha,
            timeout_seconds=arguments.timeout_seconds,
            dry_run=arguments.dry_run,
        )
    except ImageSbomContractError as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
