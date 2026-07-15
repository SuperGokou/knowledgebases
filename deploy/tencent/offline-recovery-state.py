#!/usr/bin/env python3
"""Durable, root-only state for the offline cutover reconciler.

The shell entry points deliberately delegate filesystem publication and JSON
validation to this small helper.  Every published document is fsync'd before
its parent directory, and an active receipt can only supersede an intent when
both carry the same unpredictable transaction identifier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import stat
import sys
import tempfile
from collections.abc import Callable, Iterable, Mapping
from typing import NoReturn, cast

PERSISTENT_ROOT = pathlib.Path("/srv/heyi-knowledgebases-offline")
STATE_ROOT = PERSISTENT_ROOT / "state"
CONTRACT_ROOT = PERSISTENT_ROOT / "contracts"
INTENT_PATH = STATE_ROOT / "cutover-intent.json"
ACTIVE_PATH = STATE_ROOT / "active-release.json"
PROJECT_NAME = "heyi-kb-offline"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TXID = re.compile(r"[0-9a-f]{32}\Z")
SAFE_RELATIVE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
PROFILES = {"strict-offline", "controlled-egress"}
OPERATIONS = {"install", "deploy", "maintenance"}

# This helper is installed on Linux only, but the repository is type-checked on
# Windows as well.  Resolve POSIX-only primitives without teaching the type
# checker that they are universally available, then fail closed if somebody
# attempts to run a privileged state mutation on an unsupported platform.
_GETEUID = cast(Callable[[], int] | None, getattr(os, "geteuid", None))
_FCHMOD = cast(Callable[[int, int], None] | None, getattr(os, "fchmod", None))
_O_DIRECTORY = int(getattr(os, "O_DIRECTORY", 0))
_O_NOFOLLOW = int(getattr(os, "O_NOFOLLOW", 0))


class StateError(RuntimeError):
    """A durable recovery-state invariant was violated."""


def _fail(message: str) -> NoReturn:
    raise StateError(message)


def _require_root() -> None:
    if _GETEUID is None or _FCHMOD is None or _O_DIRECTORY == 0 or _O_NOFOLLOW == 0:
        _fail("offline recovery state requires Linux POSIX safety primitives")
    if _GETEUID() != 0:
        _fail("offline recovery state must be managed as root")


def _fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_directory(
    path: pathlib.Path,
    *,
    exact_mode: int | None = None,
    forbid_non_root_write: bool = True,
) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != 0:
        _fail(f"unsafe recovery directory: {path}")
    if exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode:
        _fail(f"unexpected recovery directory mode: {path}")
    if forbid_non_root_write and info.st_mode & 0o022:
        _fail(f"recovery directory is writable by non-root: {path}")


def _validate_ancestors() -> None:
    for path in (pathlib.Path("/srv"), PERSISTENT_ROOT):
        if path.exists():
            _validate_directory(path)


def _ensure_roots() -> None:
    _validate_ancestors()
    PERSISTENT_ROOT.mkdir(mode=0o750, parents=True, exist_ok=True)
    CONTRACT_ROOT.mkdir(mode=0o700, exist_ok=True)
    STATE_ROOT.mkdir(mode=0o700, exist_ok=True)
    _validate_directory(PERSISTENT_ROOT)
    _validate_directory(CONTRACT_ROOT, exact_mode=0o700)
    _validate_directory(STATE_ROOT, exact_mode=0o700)


def _validate_hex64(value: str, field: str) -> str:
    if HEX64.fullmatch(value) is None:
        _fail(f"{field} is not a lowercase SHA-256 digest")
    return value


def _validate_profile(value: str) -> str:
    if value not in PROFILES:
        _fail("unknown offline Compose profile")
    return value


def _validate_transaction(value: str) -> str:
    if TXID.fullmatch(value) is None:
        _fail("cutover transaction identifier is invalid")
    return value


def _read_manifest(path: pathlib.Path) -> list[tuple[str, pathlib.PurePosixPath]]:
    raw = path.read_bytes()
    entries: list[tuple[str, pathlib.PurePosixPath]] = []
    observed: set[str] = set()
    for raw_line in raw.splitlines():
        try:
            line = raw_line.decode("ascii")
        except UnicodeDecodeError as error:
            raise StateError("contract manifest is not ASCII") from error
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)", line)
        if match is None:
            _fail("contract manifest contains an invalid record")
        relative_text = match.group(2)
        relative = pathlib.PurePosixPath(relative_text)
        if (
            SAFE_RELATIVE.fullmatch(relative_text) is None
            or relative.is_absolute()
            or ".." in relative.parts
            or "." in relative.parts
            or relative_text in observed
        ):
            _fail("contract manifest contains an unsafe or duplicate path")
        observed.add(relative_text)
        entries.append((match.group(1), relative))
    if not entries:
        _fail("contract manifest is empty")
    return entries


def _regular_root_file(path: pathlib.Path, expected_mode: int) -> bytes:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != expected_mode
        or info.st_nlink != 1
    ):
        _fail(f"unsafe recovery file: {path}")
    return path.read_bytes()


def _contract_metadata(
    contract_directory: pathlib.Path,
    expected_digest: str,
    *,
    persistent: bool,
) -> dict[str, str]:
    _validate_hex64(expected_digest, "contract_sha256")
    root_mode = 0o700
    _validate_directory(contract_directory, exact_mode=root_mode)
    metadata_path = contract_directory / "files.sha256"
    digest_path = contract_directory / "contract.sha256"
    expected_file_mode = 0o400
    metadata = _regular_root_file(metadata_path, expected_file_mode)
    recorded = _regular_root_file(digest_path, expected_file_mode).decode("ascii").strip()
    observed_contract = hashlib.sha256(metadata).hexdigest()
    if recorded != observed_contract or observed_contract != expected_digest:
        _fail("contract digest differs from its durable identity")
    entries = _read_manifest(metadata_path)
    for expected_file_digest, relative in entries:
        candidate = contract_directory.joinpath(*relative.parts)
        payload = _regular_root_file(candidate, expected_file_mode)
        if hashlib.sha256(payload).hexdigest() != expected_file_digest:
            _fail(f"contract content changed: {relative}")
        if persistent:
            parent = candidate.parent
            while parent != contract_directory:
                _validate_directory(parent, exact_mode=0o500)
                parent = parent.parent
    required = ("runtime.env", "release.env", "release.env.images")
    values = {
        "contract_sha256": observed_contract,
        "runtime_sha256": hashlib.sha256(
            _regular_root_file(contract_directory / required[0], expected_file_mode)
        ).hexdigest(),
        "release_sha256": hashlib.sha256(
            _regular_root_file(contract_directory / required[1], expected_file_mode)
        ).hexdigest(),
        "manifest_sha256": hashlib.sha256(
            _regular_root_file(contract_directory / required[2], expected_file_mode)
        ).hexdigest(),
    }
    return values


def _copy_contract_tree(
    source: pathlib.Path,
    destination: pathlib.Path,
    entries: Iterable[tuple[str, pathlib.PurePosixPath]],
) -> None:
    destination.mkdir(mode=0o700)
    for _digest, relative in entries:
        source_file = source.joinpath(*relative.parts)
        destination_file = destination.joinpath(*relative.parts)
        destination_file.parent.mkdir(mode=0o500, parents=True, exist_ok=True)
        descriptor = os.open(
            destination_file,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
            0o400,
        )
        try:
            with source_file.open("rb") as input_file, os.fdopen(descriptor, "wb") as output_file:
                descriptor = -1
                shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
                output_file.flush()
                os.fsync(output_file.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    for name in ("files.sha256", "contract.sha256"):
        source_file = source / name
        destination_file = destination / name
        descriptor = os.open(
            destination_file,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
            0o400,
        )
        try:
            with source_file.open("rb") as input_file, os.fdopen(descriptor, "wb") as output_file:
                descriptor = -1
                shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
                output_file.flush()
                os.fsync(output_file.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    directories = sorted(
        (path for path in destination.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for directory in directories:
        os.chmod(directory, 0o500)
        _fsync_directory(directory)
    _fsync_directory(destination)


def _same_contract(left: pathlib.Path, right: pathlib.Path) -> bool:
    left_manifest = _read_manifest(left / "files.sha256")
    right_manifest = _read_manifest(right / "files.sha256")
    if left_manifest != right_manifest:
        return False
    for name in ("files.sha256", "contract.sha256"):
        if (left / name).read_bytes() != (right / name).read_bytes():
            return False
    return all(
        left.joinpath(*relative.parts).read_bytes() == right.joinpath(*relative.parts).read_bytes()
        for _digest, relative in left_manifest
    )


def persist_contract(source_text: str, expected_digest: str) -> None:
    _require_root()
    _ensure_roots()
    source = pathlib.Path(source_text)
    source_metadata = _contract_metadata(source, expected_digest, persistent=False)
    entries = _read_manifest(source / "files.sha256")
    destination = CONTRACT_ROOT / expected_digest
    if destination.exists():
        _contract_metadata(destination, expected_digest, persistent=True)
        if not _same_contract(source, destination):
            _fail("existing persistent contract conflicts with the canonical source")
        return
    staging = pathlib.Path(
        tempfile.mkdtemp(prefix=f".contract-{expected_digest}.", dir=CONTRACT_ROOT)
    )
    try:
        os.rmdir(staging)
        _copy_contract_tree(source, staging, entries)
        _contract_metadata(staging, expected_digest, persistent=True)
        if source_metadata != _contract_metadata(staging, expected_digest, persistent=True):
            _fail("persistent contract metadata changed while copying")
        os.rename(staging, destination)
        _fsync_directory(CONTRACT_ROOT)
    except BaseException:
        if staging.exists():
            os.chmod(staging, 0o700)
            for directory in staging.rglob("*"):
                if directory.is_dir():
                    os.chmod(directory, 0o700)
            shutil.rmtree(staging)
        raise


def _atomic_json(path: pathlib.Path, document: dict[str, object]) -> None:
    _ensure_roots()
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary_text = tempfile.mkstemp(prefix=f".{path.name}.", dir=STATE_ROOT)
    temporary = pathlib.Path(temporary_text)
    try:
        if _FCHMOD is None:
            _fail("offline recovery state requires POSIX fchmod")
        _FCHMOD(descriptor, 0o400)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _fsync_directory(STATE_ROOT)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _read_json_file(path: pathlib.Path) -> dict[str, object]:
    payload = _regular_root_file(path, 0o400)
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StateError(f"invalid recovery JSON: {path.name}") from error
    if not isinstance(document, dict):
        _fail(f"invalid recovery document: {path.name}")
    return document


def _path_present(path: pathlib.Path) -> bool:
    return path.exists() or path.is_symlink()


def _contract_values(contract_sha256: str) -> dict[str, str]:
    return _contract_metadata(
        CONTRACT_ROOT / _validate_hex64(contract_sha256, "contract_sha256"),
        contract_sha256,
        persistent=True,
    )


def _base_document(contract_sha256: str, profile: str) -> dict[str, object]:
    values = _contract_values(contract_sha256)
    return {
        "schema_version": 1,
        "project_name": PROJECT_NAME,
        **values,
        "compose_profile": _validate_profile(profile),
    }


def _validate_intent(document: dict[str, object]) -> dict[str, object]:
    expected_keys = {
        "schema_version",
        "kind",
        "project_name",
        "operation",
        "transaction_id",
        "contract_sha256",
        "runtime_sha256",
        "release_sha256",
        "manifest_sha256",
        "compose_profile",
        "compose_config_sha256",
        "status",
    }
    if set(document) != expected_keys:
        _fail("cutover intent fields differ from schema version 1")
    if (
        document["schema_version"] != 1
        or document["kind"] != "offline-cutover-intent"
        or document["project_name"] != PROJECT_NAME
        or document["operation"] not in OPERATIONS
        or document["status"] != "prepared"
    ):
        _fail("cutover intent identity is invalid")
    transaction = _validate_transaction(str(document["transaction_id"]))
    profile = _validate_profile(str(document["compose_profile"]))
    compose_digest = _validate_hex64(
        str(document["compose_config_sha256"]), "compose_config_sha256"
    )
    values = _contract_values(str(document["contract_sha256"]))
    for key, value in values.items():
        if document[key] != value:
            _fail("cutover intent does not match its persistent contract")
    document["transaction_id"] = transaction
    document["compose_profile"] = profile
    document["compose_config_sha256"] = compose_digest
    return document


def _validate_active(document: dict[str, object]) -> dict[str, object]:
    expected_keys = {
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
    if set(document) != expected_keys:
        _fail("active release fields differ from schema version 2")
    if (
        document["schema_version"] != 2
        or document["kind"] != "offline-active-release"
        or document["project_name"] != PROJECT_NAME
        or document["status"] != "committed"
    ):
        _fail("active release identity is invalid")
    transaction = _validate_transaction(str(document["transaction_id"]))
    profile = _validate_profile(str(document["compose_profile"]))
    compose_digest = _validate_hex64(
        str(document["compose_config_sha256"]), "compose_config_sha256"
    )
    inventory_digest = _validate_hex64(
        str(document["project_inventory_sha256"]), "project_inventory_sha256"
    )
    egress_proof_digest = _validate_hex64(
        str(document["egress_proof_sha256"]), "egress_proof_sha256"
    )
    active_provider = str(document["active_provider_snapshot"])
    if profile == "strict-offline":
        if active_provider != "none":
            _fail("strict-offline active receipt contains a provider snapshot")
    elif active_provider not in {"deepseek", "qwen", "minimax"}:
        _fail("controlled-egress active provider snapshot is invalid")
    values = _contract_values(str(document["contract_sha256"]))
    for key, value in values.items():
        if document[key] != value:
            _fail("active release does not match its persistent contract")
    document["transaction_id"] = transaction
    document["compose_profile"] = profile
    document["compose_config_sha256"] = compose_digest
    document["project_inventory_sha256"] = inventory_digest
    document["egress_proof_sha256"] = egress_proof_digest
    document["active_provider_snapshot"] = active_provider
    return document


def _active_commits_intent(
    intent: Mapping[str, object], active: Mapping[str, object] | None
) -> bool:
    if active is None:
        return False
    return all(
        active.get(key) == intent.get(key)
        for key in (
            "transaction_id",
            "contract_sha256",
            "runtime_sha256",
            "release_sha256",
            "manifest_sha256",
            "compose_profile",
            "compose_config_sha256",
        )
    )


def write_intent(
    contract_sha256: str,
    operation: str,
    profile: str,
    compose_config_sha256: str,
) -> str:
    _require_root()
    _ensure_roots()
    if operation not in OPERATIONS:
        _fail("unknown cutover operation")
    compose_digest = _validate_hex64(compose_config_sha256, "compose_config_sha256")
    base = _base_document(contract_sha256, profile)
    if _path_present(INTENT_PATH):
        existing = _validate_intent(_read_json_file(INTENT_PATH))
        expected = {
            **base,
            "kind": "offline-cutover-intent",
            "operation": operation,
            "compose_config_sha256": compose_digest,
            "status": "prepared",
        }
        for key, value in expected.items():
            if existing.get(key) != value:
                _fail("another durable cutover intent is already active")
        return str(existing["transaction_id"])
    transaction = secrets.token_hex(16)
    document = {
        **base,
        "kind": "offline-cutover-intent",
        "operation": operation,
        "transaction_id": transaction,
        "compose_config_sha256": compose_digest,
        "status": "prepared",
    }
    _atomic_json(INTENT_PATH, document)
    _validate_intent(_read_json_file(INTENT_PATH))
    return transaction


def supersede_maintenance_intent(
    contract_sha256: str,
    profile: str,
    compose_config_sha256: str,
) -> str:
    """Replace a committed maintenance hold with a deploy transaction.

    The shell caller must first prove that no business/writer/egress container
    is running and that the exact maintenance endpoint owns the edge.  This
    helper then makes the transaction replacement atomic and durable.
    """

    _require_root()
    existing = _validate_intent(_read_json_file(INTENT_PATH))
    if existing["operation"] != "maintenance":
        _fail("only a standalone maintenance intent may be superseded")
    compose_digest = _validate_hex64(compose_config_sha256, "compose_config_sha256")
    transaction = secrets.token_hex(16)
    document = {
        **_base_document(contract_sha256, profile),
        "kind": "offline-cutover-intent",
        "operation": "deploy",
        "transaction_id": transaction,
        "compose_config_sha256": compose_digest,
        "status": "prepared",
    }
    _atomic_json(INTENT_PATH, document)
    _validate_intent(_read_json_file(INTENT_PATH))
    return transaction


def write_active(
    contract_sha256: str,
    transaction_id: str,
    profile: str,
    compose_config_sha256: str,
    project_inventory_sha256: str,
    egress_proof_sha256: str,
    active_provider_snapshot: str,
) -> None:
    _require_root()
    intent = _validate_intent(_read_json_file(INTENT_PATH))
    transaction = _validate_transaction(transaction_id)
    if intent["transaction_id"] != transaction or intent["contract_sha256"] != contract_sha256:
        _fail("active receipt does not commit the current cutover transaction")
    base = _base_document(contract_sha256, profile)
    if intent["compose_profile"] != profile:
        _fail("active receipt profile differs from the cutover intent")
    compose_digest = _validate_hex64(compose_config_sha256, "compose_config_sha256")
    if intent["compose_config_sha256"] != compose_digest:
        _fail("active receipt Compose digest differs from the cutover intent")
    inventory_digest = _validate_hex64(project_inventory_sha256, "project_inventory_sha256")
    egress_proof_digest = _validate_hex64(egress_proof_sha256, "egress_proof_sha256")
    if profile == "strict-offline":
        if active_provider_snapshot != "none":
            _fail("strict-offline cannot commit an active provider snapshot")
    elif active_provider_snapshot not in {"deepseek", "qwen", "minimax"}:
        _fail("controlled-egress active provider snapshot is invalid")
    document = {
        **base,
        "schema_version": 2,
        "kind": "offline-active-release",
        "transaction_id": transaction,
        "compose_config_sha256": compose_digest,
        "project_inventory_sha256": inventory_digest,
        "egress_proof_sha256": egress_proof_digest,
        "active_provider_snapshot": active_provider_snapshot,
        "status": "committed",
    }
    _atomic_json(ACTIVE_PATH, document)
    _validate_active(_read_json_file(ACTIVE_PATH))


def select_state() -> dict[str, object]:
    _require_root()
    _ensure_roots()
    intent = _validate_intent(_read_json_file(INTENT_PATH)) if _path_present(INTENT_PATH) else None
    active = _validate_active(_read_json_file(ACTIVE_PATH)) if _path_present(ACTIVE_PATH) else None
    if intent is not None:
        if active is not None and _active_commits_intent(intent, active):
            return {"selection": "active", **active}
        return {"selection": "intent", **intent}
    if active is not None:
        return {"selection": "active", **active}
    _fail("no valid cutover intent or active release receipt exists")


def clear_intent(contract_sha256: str, transaction_id: str) -> None:
    _require_root()
    intent = _validate_intent(_read_json_file(INTENT_PATH))
    if intent["contract_sha256"] != contract_sha256 or intent[
        "transaction_id"
    ] != _validate_transaction(transaction_id):
        _fail("refusing to clear a different cutover intent")
    active = _validate_active(_read_json_file(ACTIVE_PATH))
    if any(
        active[key] != intent[key]
        for key in (
            "transaction_id",
            "contract_sha256",
            "runtime_sha256",
            "release_sha256",
            "manifest_sha256",
            "compose_profile",
            "compose_config_sha256",
        )
    ):
        _fail("cutover intent has no matching committed active receipt")
    INTENT_PATH.unlink()
    _fsync_directory(STATE_ROOT)


def stage_contract(contract_sha256: str, destination_parent_text: str) -> pathlib.Path:
    _require_root()
    source = CONTRACT_ROOT / _validate_hex64(contract_sha256, "contract_sha256")
    _contract_metadata(source, contract_sha256, persistent=True)
    destination_parent = pathlib.Path(destination_parent_text)
    _validate_directory(destination_parent, exact_mode=0o700)
    destination = pathlib.Path(
        tempfile.mkdtemp(prefix="contract.recovery.", dir=destination_parent)
    )
    os.rmdir(destination)
    entries = _read_manifest(source / "files.sha256")
    _copy_contract_tree(source, destination, entries)
    # Runtime contracts use writable root-only directories but immutable files.
    for directory in destination.rglob("*"):
        if directory.is_dir():
            os.chmod(directory, 0o700)
    os.chmod(destination, 0o700)
    _fsync_directory(destination)
    _contract_metadata(destination, contract_sha256, persistent=False)
    return destination


def _release_manifest_paths(
    entries: Iterable[tuple[str, pathlib.PurePosixPath]],
) -> tuple[pathlib.PurePosixPath, ...]:
    release_paths: list[pathlib.PurePosixPath] = []
    for _digest, relative in entries:
        if relative.parts[0] != "release":
            continue
        if len(relative.parts) < 2:
            _fail("contract contains an invalid release root entry")
        release_paths.append(pathlib.PurePosixPath(*relative.parts[1:]))
    if not release_paths:
        _fail("contract contains no materialized release assets")
    return tuple(release_paths)


def verify_contract_path(contract_text: str, contract_sha256: str) -> None:
    """Validate an already staged, self-describing canonical contract."""

    _require_root()
    _contract_metadata(
        pathlib.Path(contract_text),
        _validate_hex64(contract_sha256, "contract_sha256"),
        persistent=False,
    )


def verify_materialized_release(
    contract_text: str,
    contract_sha256: str,
    materialized_text: str,
) -> None:
    """Verify an old release only from its immutable signed contract metadata.

    The current release's hard-coded asset list is deliberately not consulted:
    adding a verifier in version N+1 must not make a valid version N baseline
    unverifiable.  Exact path, ownership, mode, hard-link and content checks
    still fail closed.
    """

    _require_root()
    digest = _validate_hex64(contract_sha256, "contract_sha256")
    contract = pathlib.Path(contract_text)
    _contract_metadata(contract, digest, persistent=False)
    entries = _read_manifest(contract / "files.sha256")
    expected_paths = _release_manifest_paths(entries)

    releases_root = PERSISTENT_ROOT / "releases"
    materialized = pathlib.Path(materialized_text)
    expected_root = releases_root / digest
    if materialized != expected_root:
        _fail("materialized recovery release is outside its digest-bound root")
    for ancestor in (PERSISTENT_ROOT, releases_root):
        _validate_directory(ancestor)
    _validate_directory(materialized, exact_mode=0o555)

    actual_paths: set[pathlib.PurePosixPath] = set()
    for current_text, directory_names, file_names in os.walk(materialized, followlinks=False):
        current = pathlib.Path(current_text)
        _validate_directory(current, exact_mode=0o555)
        for directory_name in directory_names:
            _validate_directory(current / directory_name, exact_mode=0o555)
        for file_name in file_names:
            candidate = current / file_name
            _regular_root_file(candidate, 0o444)
            relative = candidate.relative_to(materialized)
            actual_paths.add(pathlib.PurePosixPath(*relative.parts))

    if actual_paths != set(expected_paths):
        _fail("materialized recovery release inventory differs from its contract")
    for expected_path in expected_paths:
        source = contract.joinpath("release", *expected_path.parts)
        destination = materialized.joinpath(*expected_path.parts)
        if source.read_bytes() != destination.read_bytes():
            _fail(f"materialized recovery release content changed: {expected_path}")


def simulate_faults() -> dict[str, object]:
    """Enumerate transaction cut points without touching Docker or the host."""

    old_transaction = "1" * 32
    new_transaction = "2" * 32
    old_digest = "a" * 64
    new_digest = "b" * 64
    shared_new = {
        "transaction_id": new_transaction,
        "contract_sha256": new_digest,
        "runtime_sha256": "c" * 64,
        "release_sha256": "d" * 64,
        "manifest_sha256": "e" * 64,
        "compose_profile": "strict-offline",
        "compose_config_sha256": "f" * 64,
    }
    intent = {**shared_new, "operation": "deploy"}
    old_active = {
        **shared_new,
        "transaction_id": old_transaction,
        "contract_sha256": old_digest,
    }
    new_active = {**shared_new, "project_inventory_sha256": "9" * 64}
    scenarios = [
        {
            "kill_point": "intent_fsync_before_any_mutation",
            "selection": "intent",
            "business_authorized": _active_commits_intent(intent, None),
        },
        {
            "kill_point": "writers_started_before_receipt",
            "selection": "intent",
            "business_authorized": _active_commits_intent(intent, old_active),
        },
        {
            "kill_point": "edge_switched_before_receipt",
            "selection": "intent",
            "business_authorized": _active_commits_intent(intent, old_active),
        },
        {
            "kill_point": "matching_active_receipt_fsynced",
            "selection": "active",
            "business_authorized": _active_commits_intent(intent, new_active),
        },
    ]
    valid = all(
        scenario["business_authorized"] is (scenario["selection"] == "active")
        for scenario in scenarios
    )
    # Atomic replacement means observers see the old maintenance transaction or
    # the new deploy transaction, never an absent intent between the two.
    replacement_states = ["maintenance-intent", "deploy-intent"]
    valid = valid and "no-intent" not in replacement_states
    return {
        "schema_version": 1,
        "status": "passed" if valid else "failed",
        "scenarios": scenarios,
        "maintenance_to_deploy_states": replacement_states,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    persist = subparsers.add_parser("persist-contract")
    persist.add_argument("source")
    persist.add_argument("contract_sha256")
    intent = subparsers.add_parser("write-intent")
    intent.add_argument("contract_sha256")
    intent.add_argument("operation", choices=sorted(OPERATIONS))
    intent.add_argument("profile", choices=sorted(PROFILES))
    intent.add_argument("compose_config_sha256")
    supersede = subparsers.add_parser("supersede-maintenance-intent")
    supersede.add_argument("contract_sha256")
    supersede.add_argument("profile", choices=sorted(PROFILES))
    supersede.add_argument("compose_config_sha256")
    active = subparsers.add_parser("write-active")
    active.add_argument("contract_sha256")
    active.add_argument("transaction_id")
    active.add_argument("profile", choices=sorted(PROFILES))
    active.add_argument("compose_config_sha256")
    active.add_argument("project_inventory_sha256")
    active.add_argument("egress_proof_sha256")
    active.add_argument("active_provider_snapshot")
    clear = subparsers.add_parser("clear-intent")
    clear.add_argument("contract_sha256")
    clear.add_argument("transaction_id")
    subparsers.add_parser("select")
    subparsers.add_parser("simulate-faults")
    stage = subparsers.add_parser("stage-contract")
    stage.add_argument("contract_sha256")
    stage.add_argument("destination_parent")
    verify_contract = subparsers.add_parser("verify-contract-path")
    verify_contract.add_argument("contract")
    verify_contract.add_argument("contract_sha256")
    verify_release = subparsers.add_parser("verify-materialized-release")
    verify_release.add_argument("contract")
    verify_release.add_argument("contract_sha256")
    verify_release.add_argument("materialized_release")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.command == "persist-contract":
        persist_contract(arguments.source, arguments.contract_sha256)
    elif arguments.command == "write-intent":
        print(
            write_intent(
                arguments.contract_sha256,
                arguments.operation,
                arguments.profile,
                arguments.compose_config_sha256,
            )
        )
    elif arguments.command == "write-active":
        write_active(
            arguments.contract_sha256,
            arguments.transaction_id,
            arguments.profile,
            arguments.compose_config_sha256,
            arguments.project_inventory_sha256,
            arguments.egress_proof_sha256,
            arguments.active_provider_snapshot,
        )
    elif arguments.command == "supersede-maintenance-intent":
        print(
            supersede_maintenance_intent(
                arguments.contract_sha256,
                arguments.profile,
                arguments.compose_config_sha256,
            )
        )
    elif arguments.command == "clear-intent":
        clear_intent(arguments.contract_sha256, arguments.transaction_id)
    elif arguments.command == "select":
        print(json.dumps(select_state(), sort_keys=True, separators=(",", ":")))
    elif arguments.command == "stage-contract":
        print(stage_contract(arguments.contract_sha256, arguments.destination_parent))
    elif arguments.command == "verify-contract-path":
        verify_contract_path(arguments.contract, arguments.contract_sha256)
    elif arguments.command == "verify-materialized-release":
        verify_materialized_release(
            arguments.contract,
            arguments.contract_sha256,
            arguments.materialized_release,
        )
    elif arguments.command == "simulate-faults":
        report = simulate_faults()
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        if report["status"] != "passed":
            return 1
    else:  # pragma: no cover - argparse prevents this branch.
        raise AssertionError(arguments.command)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except StateError as error:
        print(f"recovery-state: {error}", file=sys.stderr)
        raise SystemExit(65) from error
