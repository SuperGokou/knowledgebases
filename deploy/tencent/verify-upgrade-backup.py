from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SCHEMA_HEAD = re.compile(r"^[0-9]{8}_[0-9]{4}$")
_BACKUP_ROOT = Path("/srv/heyi-knowledgebases-offline/backups")
_PROJECT = "heyi-kb-offline"
_MAX_CONTROL_STATE_FILE_BYTES = 8 * 1024 * 1024
_MAX_CONTROL_STATE_ARCHIVE_BYTES = 64 * 1024 * 1024
_ACTIVE_UPGRADE_SCOPE = "active_upgrade"
_LEGACY_ADOPTION_SCOPE = "legacy_adoption"
_OPERATION_SCOPES = frozenset({_ACTIVE_UPGRADE_SCOPE, _LEGACY_ADOPTION_SCOPE})
_CONTROL_STATE_PATHS: Final[dict[str, re.Pattern[str]]] = {
    "chat_safety_sentinel": re.compile(r"data/chat-safety/poison\.json\Z"),
    "chat_safety_clear_pending": re.compile(r"state/chat-safety-clear-pending\.json\Z"),
    "cutover_intent": re.compile(r"state/cutover-intent\.json\Z"),
    "install_in_progress": re.compile(r"state/install-in-progress\.json\Z"),
    "active_release": re.compile(r"state/active-release\.json\Z"),
    "source_installed_receipt": re.compile(r"state/installed-[0-9a-f]{64}\.json\Z"),
    "highest_release": re.compile(r"state/highest-release\.json\Z"),
    "registry_import_receipt": re.compile(r"state/registry-import-[0-9a-f]{64}\.json\Z"),
    "active_contract_manifest": re.compile(r"contracts/[0-9a-f]{64}/files\.sha256\Z"),
    "recovery_state_helper": re.compile(r"recovery/offline-recovery-state\.py\Z"),
    "recovery_dispatcher": re.compile(r"recovery/offline-recovery-dispatcher\.sh\Z"),
}
_ACTIVE_UPGRADE_RECORDS: Final[tuple[str, ...]] = (
    "chat_safety_sentinel",
    "chat_safety_clear_pending",
    "cutover_intent",
    "install_in_progress",
    "active_release",
    "source_installed_receipt",
    "highest_release",
    "registry_import_receipt",
    "active_contract_manifest",
    "recovery_state_helper",
    "recovery_dispatcher",
)
_CONTROL_STATE_OPTIONAL_ABSENCE = frozenset(
    {
        "chat_safety_sentinel",
        "chat_safety_clear_pending",
        "cutover_intent",
        "install_in_progress",
    }
)
_CONTROL_STATE_METADATA: Final[dict[str, tuple[int, int, frozenset[int]]]] = {
    "chat_safety_sentinel": (10001, 10001, frozenset({0o600})),
    "chat_safety_clear_pending": (0, 0, frozenset({0o600})),
    "cutover_intent": (0, 0, frozenset({0o400})),
    "install_in_progress": (0, 0, frozenset({0o400})),
    "active_release": (0, 0, frozenset({0o400})),
    "source_installed_receipt": (0, 0, frozenset({0o400})),
    "highest_release": (0, 0, frozenset({0o400})),
    "registry_import_receipt": (0, 0, frozenset({0o400})),
    "active_contract_manifest": (0, 0, frozenset({0o400})),
    "recovery_state_helper": (0, 0, frozenset({0o500})),
    "recovery_dispatcher": (0, 0, frozenset({0o500})),
}
_ACTIVE_RELEASE_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "project_name",
        "transaction_id",
        "contract_sha256",
        "runtime_sha256",
        "release_sha256",
        "manifest_sha256",
        "compose_profile",
        "compose_config_sha256",
        "project_inventory_sha256",
        "egress_proof_sha256",
        "active_provider_snapshot",
        "status",
    }
)
_INSTALLED_V1_KEYS = frozenset(
    {
        "schema_version",
        "contract_sha256",
        "runtime_sha256",
        "release_sha256",
        "manifest_sha256",
        "phase",
    }
)
_INSTALLED_V2_KEYS = frozenset(
    {
        *_INSTALLED_V1_KEYS,
        "migration_command_invoked",
        "operation_mode",
        "adoption_transaction_id",
        "adoption_journal_sha256",
        "adoption_plan_sha256",
        "retirement_receipt_sha256",
        "target_schema_head",
        "legacy_source_schema_head",
    }
)
_REGISTRY_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "status",
        "release_sequence",
        "release_id",
        "release_git_sha",
        "release_schema_head",
        "release_sha256",
        "manifest_sha256",
        "release_assets_sha256",
        "checksum_set_sha256",
        "signature_sha256",
        "trusted_key_sha256",
    }
)
_HIGHEST_RELEASE_KEYS = frozenset(
    {
        "schema_version",
        "release_sequence",
        "release_id",
        "release_git_sha",
        "release_schema_head",
        "manifest_sha256",
        "release_assets_sha256",
        "trusted_key_sha256",
    }
)


def _protected_regular_file(path: Path, *, max_bytes: int | None = None) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"protected path is not absolute and regular: {path}")
    canonical = path.resolve(strict=True)
    if canonical != path:
        raise ValueError(f"protected path is non-canonical or symbolic: {path}")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
        raise ValueError(f"protected file ownership or type is unsafe: {path}")
    if stat.S_IMODE(info.st_mode) not in {0o400, 0o440, 0o444}:
        raise ValueError(f"protected file permissions are unsafe: {path}")
    if max_bytes is not None and not 1 <= info.st_size <= max_bytes:
        raise ValueError(f"protected file size is outside the accepted boundary: {path}")
    checked = path.parent
    while True:
        ancestor = checked.lstat()
        if (
            checked.is_symlink()
            or not stat.S_ISDIR(ancestor.st_mode)
            or ancestor.st_uid != 0
            or ancestor.st_mode & 0o022
        ):
            raise ValueError(f"protected path ancestor is unsafe: {checked}")
        if checked == Path("/"):
            break
        checked = checked.parent
    return canonical


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must use UTC")
    return parsed.astimezone(UTC)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for name, value in pairs:
        if name in document:
            raise ValueError(f"duplicate JSON key: {name}")
        document[name] = value
    return document


def _reject_non_finite_number(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _decode_json(payload: bytes) -> Any:
    return json.loads(
        payload,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite_number,
    )


def _read_json(path: Path) -> Any:
    return _decode_json(path.read_bytes())


def _read_verified_artifact_bytes(
    path: Path,
    *,
    expected_sha256: str,
    expected_size_bytes: int,
    max_bytes: int,
) -> bytes:
    if not 0 < expected_size_bytes <= max_bytes:
        raise ValueError("protected artifact size exceeds the accepted boundary")
    flags = os.O_RDONLY
    for flag_name in ("O_NOFOLLOW", "O_CLOEXEC"):
        flags |= int(getattr(os, flag_name, 0))
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in {0o400, 0o440, 0o444}
            or before.st_size != expected_size_bytes
        ):
            raise ValueError("protected artifact metadata changed during verification")
        payload = bytearray()
        while len(payload) <= max_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_gid,
            before.st_mode,
            before.st_nlink,
            before.st_size,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_gid,
            after.st_mode,
            after.st_nlink,
            after.st_size,
        )
        if identity_after != identity_before or len(payload) != expected_size_bytes:
            raise ValueError("protected artifact changed during verification")
        materialized = bytes(payload)
        if not secrets.compare_digest(hashlib.sha256(materialized).hexdigest(), expected_sha256):
            raise ValueError("protected artifact digest changed during verification")
        return materialized
    finally:
        os.close(descriptor)


def _artifact(document: dict[str, Any], field: str) -> tuple[Path, str, int]:
    value = document.get(field)
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "size_bytes"}:
        raise ValueError(f"{field} must contain path, sha256 and size_bytes")
    raw_path = value["path"]
    digest = value["sha256"]
    size = value["size_bytes"]
    if (
        not isinstance(raw_path, str)
        or not isinstance(digest, str)
        or not _DIGEST.fullmatch(digest)
    ):
        raise ValueError(f"{field} identity is invalid")
    if type(size) is not int or size <= 0:
        raise ValueError(f"{field} size is invalid")
    path = _protected_regular_file(Path(raw_path))
    try:
        path.relative_to(_BACKUP_ROOT)
    except ValueError as exc:
        raise ValueError(f"{field} is outside the protected backup root") from exc
    if path.stat().st_size != size or _sha256(path) != digest:
        raise ValueError(f"{field} content differs from the signed evidence")
    return path, digest, size


def _validate_control_state_manifest_document(
    document: Any,
    *,
    expected_archive_sha256: str,
    expected_archive_size_bytes: int,
    issued_at: datetime,
) -> list[dict[str, Any]]:
    expected_keys = {
        "schema_version",
        "kind",
        "project",
        "source_contract_sha256",
        "captured_at",
        "archive_sha256",
        "archive_size_bytes",
        "restore_policy",
        "records",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise ValueError("control-state backup manifest schema is invalid")
    captured_at = _timestamp(document["captured_at"], "control_state.captured_at")
    source_contract_sha256 = document["source_contract_sha256"]
    restore_policy = document["restore_policy"]
    if (
        document["schema_version"] != 1
        or type(document["schema_version"]) is not int
        or document["kind"] != "offline-control-state-backup-manifest"
        or document["project"] != _PROJECT
        or not isinstance(source_contract_sha256, str)
        or _DIGEST.fullmatch(source_contract_sha256) is None
        or document["archive_sha256"] != expected_archive_sha256
        or document["archive_size_bytes"] != expected_archive_size_bytes
        or type(document["archive_size_bytes"]) is not int
        or not issued_at - timedelta(hours=1) <= captured_at <= issued_at + timedelta(minutes=5)
        or not isinstance(restore_policy, dict)
        or set(restore_policy)
        != {
            "initial_mode",
            "materialize_hold_before_runtime",
            "missing_state_policy",
            "allow_business_start_before_reconciliation",
        }
        or restore_policy["initial_mode"] != "chat_safety_maintenance_hold"
        or restore_policy["materialize_hold_before_runtime"] is not True
        or restore_policy["missing_state_policy"] != "fail_closed"
        or restore_policy["allow_business_start_before_reconciliation"] is not False
    ):
        raise ValueError("control-state backup policy is invalid")
    records = document["records"]
    if not isinstance(records, list):
        raise ValueError("control-state backup inventory is missing")
    observed: list[str] = []
    validated_records: list[dict[str, Any]] = []
    for raw_record in records:
        if not isinstance(raw_record, dict) or set(raw_record) != {
            "id",
            "path",
            "state",
            "sha256",
            "size_bytes",
        }:
            raise ValueError("control-state backup record schema is invalid")
        record_id = raw_record["id"]
        record_path = raw_record["path"]
        record_state = raw_record["state"]
        digest = raw_record["sha256"]
        size_bytes = raw_record["size_bytes"]
        if (
            not isinstance(record_id, str)
            or record_id not in _CONTROL_STATE_PATHS
            or record_id in observed
            or not isinstance(record_path, str)
            or _CONTROL_STATE_PATHS[record_id].fullmatch(record_path) is None
            or record_state not in {"present", "absent"}
        ):
            raise ValueError("control-state backup record identity is invalid")
        if record_state == "present":
            if (
                not isinstance(digest, str)
                or _DIGEST.fullmatch(digest) is None
                or type(size_bytes) is not int
                or size_bytes <= 0
            ):
                raise ValueError("control-state backup record content is invalid")
        elif (
            record_id not in _CONTROL_STATE_OPTIONAL_ABSENCE
            or digest is not None
            or size_bytes != 0
            or type(size_bytes) is not int
        ):
            raise ValueError("mandatory control state is absent from the backup")
        observed.append(record_id)
        validated_records.append(raw_record)
    if tuple(observed) != _ACTIVE_UPGRADE_RECORDS:
        raise ValueError("control-state backup inventory is incomplete")
    indexed = {str(record["id"]): record for record in validated_records}
    if (
        indexed["source_installed_receipt"]["path"]
        != f"state/installed-{source_contract_sha256}.json"
        or indexed["active_contract_manifest"]["path"]
        != f"contracts/{source_contract_sha256}/files.sha256"
    ):
        raise ValueError("control-state backup source contract path binding differs")
    return validated_records


def _contract_manifest_digests(payload: bytes, source_contract_sha256: str) -> dict[str, str]:
    if hashlib.sha256(payload).hexdigest() != source_contract_sha256:
        raise ValueError("active contract manifest digest differs from the source contract")
    observed: dict[str, str] = {}
    for raw_line in payload.splitlines():
        try:
            line = raw_line.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("active contract manifest is not ASCII") from exc
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)", line)
        if match is None:
            raise ValueError("active contract manifest record is invalid")
        relative_path = match.group(2)
        parts = Path(relative_path).parts
        if (
            relative_path in observed
            or relative_path.startswith("/")
            or "." in parts
            or ".." in parts
        ):
            raise ValueError("active contract manifest path is unsafe or duplicated")
        observed[relative_path] = match.group(1)
    required = {"runtime.env", "release.env", "release.env.images"}
    if not required.issubset(observed):
        raise ValueError("active contract manifest release bindings are incomplete")
    return observed


def _json_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        document = _decode_json(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise ValueError(f"{label} must be a JSON object")
    return document


def _validate_control_state_contract_binding(
    records: list[dict[str, Any]],
    payloads: dict[str, bytes],
    *,
    source_contract_sha256: str,
) -> None:
    indexed = {str(record["id"]): record for record in records}
    installed_path = f"state/installed-{source_contract_sha256}.json"
    contract_manifest_path = f"contracts/{source_contract_sha256}/files.sha256"
    if (
        indexed["source_installed_receipt"]["path"] != installed_path
        or indexed["active_contract_manifest"]["path"] != contract_manifest_path
    ):
        raise ValueError("control-state source contract path binding differs")

    contract_digests = _contract_manifest_digests(
        payloads["active_contract_manifest"],
        source_contract_sha256,
    )
    expected_runtime_sha256 = contract_digests["runtime.env"]
    expected_release_sha256 = contract_digests["release.env"]
    expected_manifest_sha256 = contract_digests["release.env.images"]

    active = _json_object(payloads["active_release"], "active release")
    if (
        set(active) != _ACTIVE_RELEASE_KEYS
        or active.get("schema_version") != 2
        or active.get("kind") != "offline-active-release"
        or active.get("project_name") != _PROJECT
        or active.get("status") != "committed"
        or active.get("contract_sha256") != source_contract_sha256
        or active.get("runtime_sha256") != expected_runtime_sha256
        or active.get("release_sha256") != expected_release_sha256
        or active.get("manifest_sha256") != expected_manifest_sha256
    ):
        raise ValueError("active release differs from the source contract")

    installed = _json_object(payloads["source_installed_receipt"], "installed receipt")
    schema_version = installed.get("schema_version")
    installed_keys = (
        _INSTALLED_V1_KEYS
        if type(schema_version) is int and schema_version == 1
        else _INSTALLED_V2_KEYS
    )
    if (
        set(installed) != installed_keys
        or type(schema_version) is not int
        or schema_version not in {1, 2}
        or installed.get("phase") != "completed"
        or installed.get("contract_sha256") != source_contract_sha256
        or installed.get("runtime_sha256") != expected_runtime_sha256
        or installed.get("release_sha256") != expected_release_sha256
        or installed.get("manifest_sha256") != expected_manifest_sha256
        or (schema_version == 2 and installed.get("migration_command_invoked") is not True)
    ):
        raise ValueError("installed receipt differs from the source contract")

    registry = _json_object(payloads["registry_import_receipt"], "registry import receipt")
    expected_registry_path = f"state/registry-import-{expected_manifest_sha256}.json"
    if (
        indexed["registry_import_receipt"]["path"] != expected_registry_path
        or set(registry) != _REGISTRY_RECEIPT_KEYS
        or registry.get("schema_version") != 2
        or registry.get("kind") != "offline-registry-import"
        or registry.get("status") != "verified"
        or registry.get("release_sha256") != expected_release_sha256
        or registry.get("manifest_sha256") != expected_manifest_sha256
    ):
        raise ValueError("registry import receipt differs from the source contract")

    highest = _json_object(payloads["highest_release"], "highest release receipt")
    shared_release_fields = (
        "release_sequence",
        "release_id",
        "release_git_sha",
        "release_schema_head",
        "manifest_sha256",
        "release_assets_sha256",
        "trusted_key_sha256",
    )
    if (
        set(highest) != _HIGHEST_RELEASE_KEYS
        or highest.get("schema_version") != 2
        or any(highest.get(field) != registry.get(field) for field in shared_release_fields)
    ):
        raise ValueError("highest release receipt differs from the source registry receipt")


def _validate_control_state_archive(
    archive_path: Path,
    records: list[dict[str, Any]],
    *,
    expected_archive_sha256: str,
    expected_archive_size_bytes: int,
    source_contract_sha256: str,
) -> None:
    payload = _read_verified_artifact_bytes(
        archive_path,
        expected_sha256=expected_archive_sha256,
        expected_size_bytes=expected_archive_size_bytes,
        max_bytes=_MAX_CONTROL_STATE_ARCHIVE_BYTES,
    )
    expected_records = [record for record in records if record["state"] == "present"]
    expected_paths = [str(record["path"]) for record in expected_records]
    payloads: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            members = archive.getmembers()
            observed_paths = [member.name for member in members]
            if observed_paths != expected_paths:
                raise ValueError("control-state archive inventory differs from its manifest")
            content_end = 0
            for member, record in zip(members, expected_records, strict=True):
                record_id = str(record["id"])
                expected_uid, expected_gid, accepted_modes = _CONTROL_STATE_METADATA[record_id]
                if (
                    not member.isreg()
                    or member.name.startswith("/")
                    or ".." in Path(member.name).parts
                    or member.linkname
                    or member.pax_headers
                    or member.uid != expected_uid
                    or member.gid != expected_gid
                    or member.mode not in accepted_modes
                    or member.mtime != 0
                    or member.size != record["size_bytes"]
                ):
                    raise ValueError("control-state archive member metadata is invalid")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("control-state archive member cannot be read")
                member_payload = stream.read(_MAX_CONTROL_STATE_FILE_BYTES + 1)
                if (
                    len(member_payload) != record["size_bytes"]
                    or len(member_payload) > _MAX_CONTROL_STATE_FILE_BYTES
                    or hashlib.sha256(member_payload).hexdigest() != record["sha256"]
                ):
                    raise ValueError("control-state archive member content differs")
                payloads[record_id] = member_payload
                content_end = max(
                    content_end,
                    member.offset_data + ((member.size + 511) // 512) * 512,
                )
    except (tarfile.TarError, EOFError) as exc:
        raise ValueError("control-state archive is malformed") from exc
    trailer = payload[content_end:]
    if len(trailer) < 1024 or any(trailer):
        raise ValueError("control-state archive trailer is non-canonical")
    _validate_control_state_contract_binding(
        records,
        payloads,
        source_contract_sha256=source_contract_sha256,
    )


def _validate_control_state_manifest(
    path: Path,
    *,
    archive_path: Path,
    expected_archive_sha256: str,
    expected_archive_size_bytes: int,
    issued_at: datetime,
) -> None:
    document = _read_json(path)
    records = _validate_control_state_manifest_document(
        document,
        expected_archive_sha256=expected_archive_sha256,
        expected_archive_size_bytes=expected_archive_size_bytes,
        issued_at=issued_at,
    )
    if not isinstance(document, dict):
        raise ValueError("control-state backup manifest schema is invalid")
    _validate_control_state_archive(
        archive_path,
        records,
        expected_archive_sha256=expected_archive_sha256,
        expected_archive_size_bytes=expected_archive_size_bytes,
        source_contract_sha256=str(document["source_contract_sha256"]),
    )


def _fixed_release_authorization_binding() -> tuple[str, str]:
    release_root = Path(__file__).resolve(strict=True).parents[2]
    legacy_tool = _protected_regular_file(
        release_root / "scripts" / "legacy_offline_adoption.py",
        max_bytes=1_048_576,
    )
    spec = importlib.util.spec_from_file_location(
        "heyi_upgrade_release_authorization",
        legacy_tool,
    )
    if spec is None or spec.loader is None:
        raise ValueError("trusted release authorization module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        authorization = module._current_release_authorization()
        authorization_sha256 = module._release_authorization_sha256(authorization)
    except Exception as exc:
        raise ValueError("fixed release authorization cannot be reconstructed") from exc
    finally:
        sys.modules.pop(spec.name, None)
    if not isinstance(authorization, dict) or _DIGEST.fullmatch(authorization_sha256) is None:
        raise ValueError("fixed release authorization binding is malformed")
    manifest = authorization.get("target_manifest")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"path", "sha256", "size_bytes"}
        or not isinstance(manifest.get("sha256"), str)
        or _DIGEST.fullmatch(manifest["sha256"]) is None
    ):
        raise ValueError("fixed release manifest binding is malformed")
    return authorization_sha256, manifest["sha256"]


def _verify_signature(evidence: Path, signature: Path, public_key: Path) -> None:
    completed = subprocess.run(
        [
            "/usr/bin/openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public_key),
            "-signature",
            str(signature),
            str(evidence),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        cwd="/",
        check=False,
        timeout=20,
    )
    if completed.returncode != 0:
        raise ValueError("upgrade backup evidence signature is invalid")


def _validate_document(
    document: Any,
    *,
    expected_manifest_sha256: str,
    expected_release_authorization_sha256: str,
    expected_operation_scope: str,
    require_current: bool,
) -> None:
    if expected_operation_scope not in _OPERATION_SCOPES:
        raise ValueError("expected operation scope is invalid")
    if (
        not isinstance(document, dict)
        or document.get("operation_scope") != expected_operation_scope
    ):
        raise ValueError("upgrade backup evidence operation scope differs")
    expected_keys = {
        "schema_version",
        "kind",
        "project",
        "operation_scope",
        "issued_at",
        "expires_at",
        "release_authorization_sha256",
        "target_manifest_sha256",
        "database_backup",
        "object_manifest",
        "restore_evidence",
        "restore_drill",
    }
    if expected_operation_scope == _ACTIVE_UPGRADE_SCOPE:
        expected_keys.update({"control_state_archive", "control_state_manifest"})
    if set(document) != expected_keys:
        raise ValueError("upgrade backup evidence schema is invalid")
    if (
        document["schema_version"] != 3
        or type(document["schema_version"]) is not int
        or document["kind"] != "offline-upgrade-backup"
        or document["project"] != _PROJECT
        or document["release_authorization_sha256"] != expected_release_authorization_sha256
        or document["target_manifest_sha256"] != expected_manifest_sha256
    ):
        raise ValueError("upgrade backup evidence identity differs")
    issued_at = _timestamp(document["issued_at"], "issued_at")
    expires_at = _timestamp(document["expires_at"], "expires_at")
    if not issued_at < expires_at <= issued_at + timedelta(hours=24):
        raise ValueError("upgrade backup evidence validity window is invalid")
    issued_lower_bound = issued_at - timedelta(days=30)
    issued_upper_bound = issued_at + timedelta(minutes=5)
    current_lower_bound: datetime | None = None
    current_upper_bound: datetime | None = None
    if require_current:
        now = datetime.now(UTC)
        if not now - timedelta(hours=24) <= issued_at <= now + timedelta(minutes=5):
            raise ValueError("upgrade backup evidence is stale or future-dated")
        if not now < expires_at:
            raise ValueError("upgrade backup evidence has expired")
        current_lower_bound = now - timedelta(days=30)
        current_upper_bound = now + timedelta(minutes=5)
    _artifact(document, "database_backup")
    _artifact(document, "object_manifest")
    _artifact(document, "restore_evidence")
    if expected_operation_scope == _ACTIVE_UPGRADE_SCOPE:
        control_archive_path, control_archive_sha256, control_archive_size = _artifact(
            document,
            "control_state_archive",
        )
        control_manifest_path, _control_manifest_sha256, _control_manifest_size = _artifact(
            document,
            "control_state_manifest",
        )
        _validate_control_state_manifest(
            control_manifest_path,
            archive_path=control_archive_path,
            expected_archive_sha256=control_archive_sha256,
            expected_archive_size_bytes=control_archive_size,
            issued_at=issued_at,
        )
    drill = document["restore_drill"]
    if not isinstance(drill, dict) or set(drill) != {
        "status",
        "tested_at",
        "source_schema_head",
    }:
        raise ValueError("restore drill evidence schema is invalid")
    tested_at = _timestamp(drill["tested_at"], "restore_drill.tested_at")
    if (
        drill["status"] != "passed"
        or not isinstance(drill["source_schema_head"], str)
        or _SCHEMA_HEAD.fullmatch(drill["source_schema_head"]) is None
        or not issued_lower_bound <= tested_at <= issued_upper_bound
        or (
            current_lower_bound is not None
            and current_upper_bound is not None
            and not current_lower_bound <= tested_at <= current_upper_bound
        )
    ):
        raise ValueError("restore drill did not satisfy the accepted contract")


def validate_evidence_document(
    document: Any,
    *,
    expected_manifest_sha256: str,
    expected_release_authorization_sha256: str,
    expected_operation_scope: str,
    require_current: bool,
) -> None:
    if expected_operation_scope == _ACTIVE_UPGRADE_SCOPE:
        raise ValueError(
            "active upgrade backup verification is disabled until the signed collector "
            "and source/target recovery-state bindings are complete"
        )
    _validate_document(
        document,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_release_authorization_sha256=expected_release_authorization_sha256,
        expected_operation_scope=expected_operation_scope,
        require_current=require_current,
    )


def _verify(
    *,
    evidence_path: Path,
    signature_path: Path,
    public_key_path: Path,
    expected_manifest_sha256: str,
    expected_operation_scope: str,
    require_current: bool,
) -> None:
    if expected_operation_scope == _ACTIVE_UPGRADE_SCOPE:
        raise ValueError(
            "active upgrade backup verification is disabled until the signed collector "
            "and source/target recovery-state bindings are complete"
        )
    evidence = _protected_regular_file(evidence_path, max_bytes=65_536)
    signature = _protected_regular_file(signature_path, max_bytes=16_384)
    public_key = _protected_regular_file(public_key_path, max_bytes=65_536)
    _verify_signature(evidence, signature, public_key)
    expected_authorization, fixed_manifest = _fixed_release_authorization_binding()
    if expected_manifest_sha256 != fixed_manifest:
        raise ValueError("selected manifest differs from the fixed release authorization")
    _validate_document(
        _read_json(evidence),
        expected_manifest_sha256=fixed_manifest,
        expected_release_authorization_sha256=expected_authorization,
        expected_operation_scope=expected_operation_scope,
        require_current=require_current,
    )


def verify(arguments: argparse.Namespace) -> None:
    require_current = not getattr(arguments, "durable_resume", False)
    if not require_current and arguments.expected_operation_scope != _LEGACY_ADOPTION_SCOPE:
        raise ValueError("durable resume is only valid for legacy adoption evidence")
    _verify(
        evidence_path=arguments.evidence,
        signature_path=arguments.signature,
        public_key_path=arguments.public_key,
        expected_manifest_sha256=arguments.expected_manifest_sha256,
        expected_operation_scope=arguments.expected_operation_scope,
        require_current=require_current,
    )


def verify_durable(
    *,
    evidence: Path,
    signature: Path,
    public_key: Path,
    expected_manifest_sha256: str,
    expected_operation_scope: str,
) -> None:
    if _DIGEST.fullmatch(expected_manifest_sha256) is None:
        raise ValueError("expected manifest digest is invalid")
    _verify(
        evidence_path=evidence,
        signature_path=signature,
        public_key_path=public_key,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_operation_scope=expected_operation_scope,
        require_current=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument(
        "--expected-operation-scope",
        choices=sorted(_OPERATION_SCOPES),
        required=True,
    )
    parser.add_argument("--durable-resume", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if _DIGEST.fullmatch(arguments.expected_manifest_sha256) is None:
        print("backup-evidence: expected manifest digest is invalid", file=sys.stderr)
        return 65
    try:
        verify(arguments)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"backup-evidence: {exc}", file=sys.stderr)
        return 65
    if arguments.durable_resume:
        print("backup-evidence: signed backup and restore drill verified for durable resume")
    else:
        print("backup-evidence: signed backup and restore drill are current and verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
