#!/usr/bin/env python3
"""Fail-closed PRE_MIGRATION_ONLY cleanup for a legacy adoption transaction.

The command is intentionally narrow.  It can archive one uncommitted target
install and remove only target preflight artifacts that are cryptographically
bound to the adoption journal.  It never rolls a database back and it never
touches bind data, named data volumes, another Compose project, or host-wide
Docker state.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import pathlib
import re
import stat
import subprocess  # nosec B404
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, NoReturn, cast

PROJECT = "heyi-kb-offline"
OWNER = "jiangsu-heyi-knowledgebases"
STACK = "offline"
RESTORE_BOUNDARY = "PRE_MIGRATION_ONLY"
PERSISTENT_ROOT = pathlib.Path("/srv/heyi-knowledgebases-offline")
STATE_ROOT = PERSISTENT_ROOT / "state"
DATA_ROOT = PERSISTENT_ROOT / "data"
RELEASE_ROOT = PERSISTENT_ROOT / "releases"
RECOVERY_ROOT = PERSISTENT_ROOT / "recovery"
TRANSACTION_ROOT = STATE_ROOT / "legacy-adoption" / "transactions"
INSTALL_STATE = STATE_ROOT / "install-in-progress.json"
ACTIVE_RELEASE = STATE_ROOT / "active-release.json"
CUTOVER_INTENT = STATE_ROOT / "cutover-intent.json"
OWNER_MARKER = "heyi-kb-offline-owner-marker"
SYSTEMD_ROOT = pathlib.Path("/etc/systemd/system")
RECONCILE_SERVICE = "heyi-kb-offline-reconcile.service"
RECONCILE_TIMER = "heyi-kb-offline-reconcile.timer"
TRUSTED_EVIDENCE_PUBLIC_KEY = pathlib.Path("/etc/heyi-adoption/trusted-evidence-public.pem")
TRUSTED_EVIDENCE_PUBLIC_KEY_SHA256 = pathlib.Path(
    "/etc/heyi-adoption/trusted-evidence-public.sha256"
)
TRUSTED_EVIDENCE_SIGNING_KEY = pathlib.Path("/run/heyi-adoption-signing/evidence-signing.key")
ALLOWED_PREFLIGHT_SERVICES = frozenset(
    {"api-preflight", "clamav-db-preflight", "llm-egress-preflight"}
)
OPEN_PHASES = frozenset({"prepared", "preflight_passed"})
CLOSED_PHASES = frozenset(
    {
        "migration_invoked",
        "migrated",
        "bootstrapped",
        "core_ready",
        "proxy_started",
        "completed",
    }
)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TXID = re.compile(r"[0-9a-f]{32}\Z")
SCHEMA_HEAD = re.compile(r"[0-9]{8}_[0-9]{4}\Z")
IMAGE_REFERENCE = re.compile(r"127\.0\.0\.1:5000/.+@sha256:[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
CONTRACT_SNAPSHOT_CONFIG = re.compile(
    r"/run/heyi-kb-offline/contracts/contract\.[A-Za-z0-9]{10}/"
    r"release/deploy/tencent/compose\.offline\.yml\Z"
)
JOURNAL_HMAC_DOMAIN = b"heyi-adoption-transaction-v1\0"
STOP_TIMEOUT_SECONDS = 150

JOURNAL_PAYLOAD_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "status",
        "project",
        "created_at",
        "adoption_transaction_id",
        "plan_sha256",
        "target_contract_sha256",
        "target_manifest_sha256",
        "target_schema_head",
        "legacy_source_schema_head",
        "backup_evidence_sha256",
        "retirement_receipt_sha256",
        "retirement_signature_sha256",
        "legacy_receipt_archive_manifest_sha256",
        "host_isolation_baseline_sha256",
        "host_isolation_after_retire_sha256",
        "reconcile_baseline",
        "restore_boundary",
    }
)
INSTALL_STATE_KEYS = frozenset(
    {
        "schema_version",
        "contract_sha256",
        "runtime_sha256",
        "release_sha256",
        "manifest_sha256",
        "phase",
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
RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "status",
        "project",
        "issued_at",
        "adoption_transaction_id",
        "journal_sha256",
        "plan_sha256",
        "retirement_receipt_sha256",
        "target_contract_sha256",
        "target_manifest_sha256",
        "target_schema_head",
        "legacy_source_schema_head",
        "last_install_phase",
        "migration_command_invoked",
        "active_release_present",
        "installed_receipt_present",
        "removed_preflight_container_ids",
        "removed_owner_marker_volume",
        "archived_install_state",
        "archived_cutover_intent",
        "reconcile_baseline",
        "reconcile_result",
        "target_resource_counts_after",
        "host_isolation_verification",
        "preserved_bind_root",
        "bind_data_deleted",
        "named_volumes_deleted",
        "global_actions",
        "restore_boundary",
    }
)


class AbortError(RuntimeError):
    """A validation or cleanup invariant failed."""

    def __init__(self, message: str, code: int = 65) -> None:
        super().__init__(message)
        self.code = code


class BoundaryClosed(AbortError):
    """The database migration boundary may have been crossed."""

    def __init__(self, message: str) -> None:
        super().__init__(message, 70)


class CleanupFailed(AbortError):
    """A validated, exact cleanup operation did not complete."""

    def __init__(self, message: str) -> None:
        super().__init__(message, 71)


def _fail(message: str, code: int = 65) -> NoReturn:
    raise AbortError(message, code)


def _canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hex64(value: object, field: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        _fail(f"{field} must be a lowercase SHA-256 digest")
    return value


def _transaction(value: object, field: str) -> str:
    if not isinstance(value, str) or TXID.fullmatch(value) is None:
        _fail(f"{field} is invalid")
    return value


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AbortError(f"{field} is invalid") from exc
    if parsed.tzinfo is None:
        _fail(f"{field} is missing a timezone")
    return parsed.astimezone(UTC)


def _require_root_linux() -> None:
    geteuid = getattr(os, "geteuid", None)
    if sys.platform != "linux" or geteuid is None or geteuid() != 0:
        _fail("pre-migration abort requires root on Linux", 77)


def _protected_file(
    path: pathlib.Path, *, modes: frozenset[int], maximum_bytes: int = 1_048_576
) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AbortError(f"protected file is unavailable: {path}") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) not in modes
        or info.st_nlink != 1
        or info.st_size > maximum_bytes
        or path.resolve(strict=True) != path
    ):
        _fail(f"protected file is unsafe: {path}")
    return path.read_bytes()


def _protected_directory(path: pathlib.Path, *, mode: int = 0o700) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or path.is_symlink()
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != mode
        or path.resolve(strict=True) != path
    ):
        _fail(f"protected directory is unsafe: {path}")


def _protected_trust_file(
    path: pathlib.Path, *, modes: frozenset[int], maximum_bytes: int
) -> bytes:
    """Read fixed trust material only through root-owned, non-writable ancestors."""

    current = path.parent
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise AbortError(f"protected trust ancestor is unavailable: {current}") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or current.is_symlink()
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
            or current.resolve(strict=True) != current
        ):
            _fail(f"protected trust ancestor is unsafe: {current}")
        if current == current.parent:
            break
        current = current.parent
    return _protected_file(path, modes=modes, maximum_bytes=maximum_bytes)


def _fsync_directory(path: pathlib.Path) -> None:
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_json(payload: bytes, source: str) -> dict[str, Any]:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AbortError(f"{source} is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        _fail(f"{source} must be a JSON object")
    return cast(dict[str, Any], document)


def _read_binding_key(path: pathlib.Path) -> bytes:
    payload = _protected_file(path, modes=frozenset({0o400, 0o600}), maximum_bytes=4096).strip()
    if re.fullmatch(rb"[A-Za-z0-9_-]+", payload) is None:
        _fail("adoption binding key is not canonical URL-safe base64")
    try:
        decoded = base64.urlsafe_b64decode(payload + b"=" * (-len(payload) % 4))
    except (ValueError, TypeError) as exc:
        raise AbortError("adoption binding key is not URL-safe base64") from exc
    if len(decoded) < 32:
        _fail("adoption binding key must decode to at least 32 bytes")
    return decoded


def _validate_reconcile_baseline(value: object) -> dict[str, object]:
    units = (RECONCILE_SERVICE, RECONCILE_TIMER)
    if not isinstance(value, dict) or set(value) != set(units):
        _fail("reconcile baseline schema differs")
    expected = {
        "load_state": "not-found",
        "active_state": "inactive",
        "unit_file_state": "not-found",
    }
    for unit in units:
        if value.get(unit) != expected:
            _fail("adoption requires an absent reconcile watchdog baseline")
    return cast(dict[str, object], value)


@dataclass(frozen=True)
class Journal:
    path: pathlib.Path
    sha256: str
    payload: dict[str, Any]


def validate_journal(
    path: pathlib.Path,
    binding_key_path: pathlib.Path,
    *,
    expected_transaction: str,
    expected_contract: str,
    expected_plan: str | None = None,
    expected_retirement_receipt: str | None = None,
    allow_pending_journal: bool = False,
) -> Journal:
    transaction = _transaction(expected_transaction, "adoption_transaction_id")
    contract = _hex64(expected_contract, "target_contract_sha256")
    raw = _protected_file(path, modes=frozenset({0o400}), maximum_bytes=262_144)
    wrapper = _read_json(raw, "adoption journal")
    if raw != _canonical_json(wrapper):
        _fail("adoption journal is not canonical JSON")
    if set(wrapper) != {"payload", "opaque_hmac_sha256"}:
        _fail("adoption journal wrapper schema differs")
    payload = wrapper.get("payload")
    if not isinstance(payload, dict) or set(payload) != JOURNAL_PAYLOAD_KEYS:
        _fail("adoption journal payload schema differs")
    key = _read_binding_key(binding_key_path)
    observed_hmac = wrapper.get("opaque_hmac_sha256")
    if not isinstance(observed_hmac, str) or HEX64.fullmatch(observed_hmac) is None:
        _fail("adoption journal HMAC is malformed")
    expected_hmac = hmac.new(
        key, JOURNAL_HMAC_DOMAIN + _canonical_json(payload), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(observed_hmac, expected_hmac):
        _fail("adoption journal HMAC differs")
    if (
        payload.get("schema_version") != 1
        or payload.get("kind") != "heyi-offline-adoption-transaction"
        or payload.get("status") != "legacy_retired_target_not_started"
        or payload.get("project") != PROJECT
        or payload.get("restore_boundary") != RESTORE_BOUNDARY
        or payload.get("adoption_transaction_id") != transaction
        or payload.get("target_contract_sha256") != contract
    ):
        _fail("adoption journal identity differs")
    for field in (
        "plan_sha256",
        "target_contract_sha256",
        "target_manifest_sha256",
        "backup_evidence_sha256",
        "retirement_receipt_sha256",
        "retirement_signature_sha256",
        "legacy_receipt_archive_manifest_sha256",
        "host_isolation_baseline_sha256",
        "host_isolation_after_retire_sha256",
    ):
        _hex64(payload.get(field), field)
    schema_head = payload.get("target_schema_head")
    if not isinstance(schema_head, str) or SCHEMA_HEAD.fullmatch(schema_head) is None:
        _fail("target_schema_head is invalid")
    legacy_source_head = payload.get("legacy_source_schema_head")
    if not isinstance(legacy_source_head, str) or SCHEMA_HEAD.fullmatch(legacy_source_head) is None:
        _fail("legacy_source_schema_head is invalid")
    # The creator binds its local RFC 3339 timestamp into the journal HMAC.
    # Durable resume and abort must not compare it with the current wall clock:
    # an RTC rollback after retirement must never make recovery impossible.
    _timestamp(payload.get("created_at"), "journal.created_at")
    _validate_reconcile_baseline(payload.get("reconcile_baseline"))
    if expected_plan is not None and payload.get("plan_sha256") != _hex64(
        expected_plan, "confirmed plan SHA-256"
    ):
        _fail("adoption journal plan differs from confirmation")
    if expected_retirement_receipt is not None and payload.get(
        "retirement_receipt_sha256"
    ) != _hex64(expected_retirement_receipt, "confirmed retirement receipt SHA-256"):
        _fail("adoption journal retirement receipt differs from confirmation")
    transaction_directory = TRANSACTION_ROOT / transaction
    allowed_paths = {transaction_directory / "journal.json"}
    if allow_pending_journal:
        # This one fixed publication path is recoverable after a SIGKILL.  No
        # random glob or alternate pending name is accepted.
        allowed_paths.add(transaction_directory / ".journal.pending")
    if path not in allowed_paths:
        _fail("adoption journal is outside the fixed transaction path")
    _protected_directory(path.parent)
    return Journal(path=path, sha256=_sha256(raw), payload=payload)


class Runner:
    """Minimal runner for reviewed absolute binaries; no shell is enabled."""

    _environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
    }

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 180,
        accepted: frozenset[int] = frozenset({0}),
    ) -> str:
        try:
            # Each argv is a tuple for an absolute reviewed executable.
            completed = subprocess.run(  # nosec B603
                tuple(argv),
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                env=self._environment,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise CleanupFailed(f"trusted command failed: {pathlib.Path(argv[0]).name}") from exc
        if completed.returncode not in accepted:
            raise CleanupFailed(
                f"trusted command returned {completed.returncode}: {pathlib.Path(argv[0]).name}"
            )
        return completed.stdout.strip()

    def docker_json(self, argv: Sequence[str]) -> object:
        output = self.run(("/usr/bin/docker", *argv))
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            raise AbortError("Docker returned malformed JSON", 69) from exc

    def validate_evidence_key_pair(
        self,
        *,
        signing_key: bytes,
        public_key: bytes,
        challenge: bytes,
    ) -> None:
        """Perform a real OpenSSL sign/verify challenge without filesystem artifacts."""

        raw_memfd_create = getattr(os, "memfd_create", None)
        if not callable(raw_memfd_create):
            raise CleanupFailed("anonymous trust challenge storage is unavailable")
        memfd_create = cast(Callable[[str, int], int], raw_memfd_create)
        descriptors: list[int] = []

        def anonymous_file(name: str, payload: bytes) -> int:
            descriptor = memfd_create(name, int(getattr(os, "MFD_CLOEXEC", 0)))
            descriptors.append(descriptor)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise CleanupFailed("anonymous trust challenge write made no progress")
                view = view[written:]
            os.lseek(descriptor, 0, os.SEEK_SET)
            return descriptor

        try:
            signing_descriptor = anonymous_file("heyi-adoption-signing-key", signing_key)
            public_descriptor = anonymous_file("heyi-adoption-public-key", public_key)
            try:
                signed = subprocess.run(  # nosec B603
                    (
                        "/usr/bin/openssl",
                        "dgst",
                        "-sha256",
                        "-sign",
                        f"/proc/self/fd/{signing_descriptor}",
                    ),
                    check=False,
                    input=challenge,
                    capture_output=True,
                    env=self._environment,
                    timeout=30,
                    pass_fds=(signing_descriptor,),
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise CleanupFailed("trusted key-pair challenge failed") from exc
            if signed.returncode != 0 or not signed.stdout or len(signed.stdout) > 65_536:
                _fail("ephemeral adoption signer could not sign the trust challenge")
            signature_descriptor = anonymous_file(
                "heyi-adoption-challenge-signature", signed.stdout
            )
            try:
                verified = subprocess.run(  # nosec B603
                    (
                        "/usr/bin/openssl",
                        "dgst",
                        "-sha256",
                        "-verify",
                        f"/proc/self/fd/{public_descriptor}",
                        "-signature",
                        f"/proc/self/fd/{signature_descriptor}",
                    ),
                    check=False,
                    input=challenge,
                    capture_output=True,
                    env=self._environment,
                    timeout=30,
                    pass_fds=(public_descriptor, signature_descriptor),
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise CleanupFailed("trusted key-pair challenge failed") from exc
            if verified.returncode != 0:
                _fail(
                    "ephemeral adoption signer does not match the independently trusted public key"
                )
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)


def _validate_evidence_trust_root(runner: Runner, *, contract: str) -> str:
    """Validate the fixed evidence trust root before any abort-side mutation."""

    public_key = _protected_trust_file(
        TRUSTED_EVIDENCE_PUBLIC_KEY,
        modes=frozenset({0o400, 0o444}),
        maximum_bytes=65_536,
    )
    fingerprint = _protected_trust_file(
        TRUSTED_EVIDENCE_PUBLIC_KEY_SHA256,
        modes=frozenset({0o400, 0o444}),
        maximum_bytes=128,
    )
    signing_key = _protected_trust_file(
        TRUSTED_EVIDENCE_SIGNING_KEY,
        modes=frozenset({0o400}),
        maximum_bytes=65_536,
    )
    if re.fullmatch(rb"[0-9a-f]{64}\n", fingerprint) is None:
        _fail("trusted adoption evidence key fingerprint is malformed")
    expected_digest = fingerprint[:-1].decode("ascii")
    actual_digest = _sha256(public_key)
    if not hmac.compare_digest(actual_digest, expected_digest):
        _fail("trusted adoption evidence public key differs from its independent fingerprint")
    challenge = (f"heyi-adoption-evidence-key-pair-v1\n{contract}\n{expected_digest}\n").encode(
        "ascii"
    )
    runner.validate_evidence_key_pair(
        signing_key=signing_key,
        public_key=public_key,
        challenge=challenge,
    )
    if (
        not hmac.compare_digest(
            public_key,
            _protected_trust_file(
                TRUSTED_EVIDENCE_PUBLIC_KEY,
                modes=frozenset({0o400, 0o444}),
                maximum_bytes=65_536,
            ),
        )
        or not hmac.compare_digest(
            fingerprint,
            _protected_trust_file(
                TRUSTED_EVIDENCE_PUBLIC_KEY_SHA256,
                modes=frozenset({0o400, 0o444}),
                maximum_bytes=128,
            ),
        )
        or not hmac.compare_digest(
            signing_key,
            _protected_trust_file(
                TRUSTED_EVIDENCE_SIGNING_KEY,
                modes=frozenset({0o400}),
                maximum_bytes=65_536,
            ),
        )
    ):
        _fail("trusted adoption evidence trust root changed during validation")
    return actual_digest


def _lines(output: str) -> list[str]:
    return [line for line in output.splitlines() if line]


def _container_mounts_match_contract(
    service: str, mounts: object, release_root: pathlib.Path
) -> bool:
    if not isinstance(mounts, list):
        return False
    allowed: dict[str, dict[tuple[str, str], bool]] = {
        "api-preflight": {
            (str(DATA_ROOT / "capacity-probe"), "/var/lib/kb-capacity"): False,
        },
        "clamav-db-preflight": {
            (str(DATA_ROOT / "clamav-db"), "/var/lib/clamav"): False,
            (
                str(release_root / "docker/clamav/preflight-database.sh"),
                "/opt/clamav/preflight-database.sh",
            ): False,
        },
        "llm-egress-preflight": {
            (
                str(release_root / "deploy/tencent/Caddyfile.llm-egress"),
                "/etc/caddy/Caddyfile",
            ): False
        },
    }
    expected = allowed.get(service)
    if expected is None:
        return False
    observed: set[tuple[str, str]] = set()
    for raw in mounts:
        if not isinstance(raw, dict):
            return False
        if raw.get("Type") != "bind":
            return False
        source = raw.get("Source")
        destination = raw.get("Destination")
        if not isinstance(source, str) or not isinstance(destination, str):
            return False
        binding = (source, destination)
        if binding in observed or binding not in expected or raw.get("RW") is not expected[binding]:
            return False
        observed.add(binding)
    return observed == set(expected)


def _validated_preflight_containers(
    runner: Runner,
    *,
    contract_sha256: str,
    adoption_transaction: str,
    release_root: pathlib.Path,
) -> list[dict[str, Any]]:
    ids = _lines(
        runner.run(
            (
                "/usr/bin/docker",
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                f"label=com.docker.compose.project={PROJECT}",
            )
        )
    )
    if not ids:
        return []
    inspected = runner.docker_json(("inspect", *ids))
    if not isinstance(inspected, list) or len(inspected) != len(ids):
        raise BoundaryClosed("target container inventory is incomplete")
    seen_services: set[str] = set()
    validated: list[dict[str, Any]] = []
    expected_config = str(release_root / "deploy/tencent/compose.offline.yml")
    for raw in inspected:
        if not isinstance(raw, dict):
            raise BoundaryClosed("target container inspection is malformed")
        config = raw.get("Config")
        host = raw.get("HostConfig")
        state = raw.get("State")
        if (
            not isinstance(config, dict)
            or not isinstance(host, dict)
            or not isinstance(state, dict)
        ):
            raise BoundaryClosed("target container inspection is incomplete")
        labels_value = config.get("Labels")
        if not isinstance(labels_value, dict):
            raise BoundaryClosed("target preflight container labels are incomplete")
        labels = cast(dict[str, object], labels_value)
        service = labels.get("com.docker.compose.service")
        if not isinstance(service, str) or service not in ALLOWED_PREFLIGHT_SERVICES:
            raise BoundaryClosed("a data, migration, business, or unknown target container exists")
        if service in seen_services:
            raise BoundaryClosed("multiple target preflight containers are ambiguous")
        seen_services.add(service)
        config_label = labels.get("com.docker.compose.project.config_files")
        if config_label == expected_config:
            mounted_release_root = release_root
        elif (
            isinstance(config_label, str)
            and CONTRACT_SNAPSHOT_CONFIG.fullmatch(config_label) is not None
        ):
            # Install preflight executes verified helpers from the root-only
            # runtime contract snapshot.  That snapshot can be unlinked after
            # a crash while its bind mount remains.  Its strict path grammar,
            # plus the HMAC-bound contract label, is the durable identity.
            mounted_release_root = pathlib.Path(config_label).parents[2]
        else:
            raise BoundaryClosed("target preflight Compose config binding differs")
        oneoff = labels.get("com.docker.compose.oneoff")
        if (
            labels.get("com.docker.compose.project") != PROJECT
            or labels.get("io.heyi.knowledgebases.owner") != OWNER
            or labels.get("io.heyi.knowledgebases.stack") != STACK
            or labels.get("io.heyi.knowledgebases.contract-sha256") != contract_sha256
            or labels.get("io.heyi.knowledgebases.adoption-transaction") != adoption_transaction
            or oneoff not in {"True", "true"}
            or host.get("NetworkMode") != "none"
            or not isinstance(state.get("Running"), bool)
            or not isinstance(config.get("Image"), str)
            or IMAGE_REFERENCE.fullmatch(cast(str, config.get("Image"))) is None
            or not isinstance(raw.get("Image"), str)
            or IMAGE_ID.fullmatch(cast(str, raw.get("Image"))) is None
            or not _container_mounts_match_contract(
                service, raw.get("Mounts"), mounted_release_root
            )
        ):
            raise BoundaryClosed("target preflight container binding differs")
        identifier = raw.get("Id")
        if not isinstance(identifier, str) or re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
            raise BoundaryClosed("target preflight container identity is invalid")
        validated.append({"id": identifier, "service": service, "running": state["Running"]})
    return validated


def _project_resource_counts(runner: Runner) -> dict[str, int]:
    containers = _lines(
        runner.run(
            (
                "/usr/bin/docker",
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                f"label=com.docker.compose.project={PROJECT}",
            )
        )
    )
    networks = _lines(
        runner.run(
            (
                "/usr/bin/docker",
                "network",
                "ls",
                "-q",
                "--no-trunc",
                "--filter",
                f"label=com.docker.compose.project={PROJECT}",
            )
        )
    )
    volumes = _lines(
        runner.run(
            (
                "/usr/bin/docker",
                "volume",
                "ls",
                "-q",
                "--filter",
                f"label=com.docker.compose.project={PROJECT}",
            )
        )
    )
    marker_names = _lines(
        runner.run(
            (
                "/usr/bin/docker",
                "volume",
                "ls",
                "-q",
                "--filter",
                f"name=^{OWNER_MARKER}$",
            )
        )
    )
    if marker_names not in ([], [OWNER_MARKER]):
        raise BoundaryClosed("owner marker inventory is ambiguous")
    return {
        "containers": len(containers),
        "networks": len(networks),
        "project_volumes": len(volumes),
        "owner_marker": len(marker_names),
    }


def _assert_no_network_or_project_volume(runner: Runner) -> None:
    counts = _project_resource_counts(runner)
    if counts["networks"] or counts["project_volumes"]:
        raise BoundaryClosed("a target project network or volume closes the rollback boundary")


def _remove_preflight_containers(
    runner: Runner,
    containers: list[dict[str, Any]],
    *,
    execute: bool,
) -> list[str]:
    removed: list[str] = []
    for item in containers:
        identifier = cast(str, item["id"])
        if not execute:
            removed.append(identifier)
            continue
        if item["running"] is True:
            runner.run(
                (
                    "/usr/bin/docker",
                    "stop",
                    "--time",
                    str(STOP_TIMEOUT_SECONDS),
                    identifier,
                ),
                timeout=STOP_TIMEOUT_SECONDS + 30,
            )
        inspected = runner.docker_json(("inspect", identifier))
        if (
            not isinstance(inspected, list)
            or len(inspected) != 1
            or not isinstance(inspected[0], dict)
            or not isinstance(inspected[0].get("State"), dict)
            or inspected[0]["State"].get("Running") is not False
        ):
            raise CleanupFailed("exact target preflight container did not stop")
        runner.run(("/usr/bin/docker", "rm", identifier), timeout=120)
        removed.append(identifier)
    return removed


def _remove_owner_marker(
    runner: Runner,
    *,
    contract_sha256: str,
    adoption_transaction: str,
    execute: bool,
) -> bool:
    marker_names = _lines(
        runner.run(
            (
                "/usr/bin/docker",
                "volume",
                "ls",
                "-q",
                "--filter",
                f"name=^{OWNER_MARKER}$",
            )
        )
    )
    if not marker_names:
        return False
    if marker_names != [OWNER_MARKER]:
        raise BoundaryClosed("owner marker inventory is ambiguous")
    output = runner.run(("/usr/bin/docker", "volume", "inspect", OWNER_MARKER))
    try:
        inspected = json.loads(output)
    except json.JSONDecodeError as exc:
        raise BoundaryClosed("owner marker inspection is malformed") from exc
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        raise BoundaryClosed("owner marker identity is ambiguous")
    labels = inspected[0].get("Labels")
    if (
        not isinstance(labels, dict)
        or labels.get("io.heyi.knowledgebases.owner") != OWNER
        or labels.get("io.heyi.knowledgebases.compose-project") != PROJECT
        or labels.get("io.heyi.knowledgebases.contract-sha256") != contract_sha256
        or labels.get("io.heyi.knowledgebases.adoption-transaction") != adoption_transaction
    ):
        raise BoundaryClosed("owner marker binding differs")
    mounted_by = runner.run(
        (
            "/usr/bin/docker",
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            f"volume={OWNER_MARKER}",
        )
    )
    if mounted_by:
        raise BoundaryClosed("owner marker is mounted by a container")
    if execute:
        runner.run(("/usr/bin/docker", "volume", "rm", OWNER_MARKER), timeout=120)
    return True


def _read_install_state(
    journal: Journal, pending: pathlib.Path
) -> tuple[dict[str, Any] | None, pathlib.Path | None]:
    archived = pending / "archived/install-in-progress.json"
    live = INSTALL_STATE.exists() or INSTALL_STATE.is_symlink()
    saved = archived.exists() or archived.is_symlink()
    if live and saved:
        raise BoundaryClosed("live and archived install states are both present")
    if not live and not saved:
        return None, None
    path = INSTALL_STATE if live else archived
    raw = _protected_file(path, modes=frozenset({0o400}), maximum_bytes=65_536)
    document = _read_json(raw, "install state")
    if set(document) != INSTALL_STATE_KEYS or document.get("schema_version") != 2:
        raise BoundaryClosed("install state schema differs")
    phase = document.get("phase")
    if phase in CLOSED_PHASES or document.get("migration_command_invoked") is not False:
        raise BoundaryClosed("migration invocation has closed the rollback boundary")
    if phase not in OPEN_PHASES:
        raise BoundaryClosed("install phase is not a pre-migration phase")
    expected = {
        "contract_sha256": journal.payload["target_contract_sha256"],
        "manifest_sha256": journal.payload["target_manifest_sha256"],
        "operation_mode": "adoption",
        "adoption_transaction_id": journal.payload["adoption_transaction_id"],
        "adoption_journal_sha256": journal.sha256,
        "adoption_plan_sha256": journal.payload["plan_sha256"],
        "retirement_receipt_sha256": journal.payload["retirement_receipt_sha256"],
        "target_schema_head": journal.payload["target_schema_head"],
        "legacy_source_schema_head": journal.payload["legacy_source_schema_head"],
    }
    if any(document.get(key) != value for key, value in expected.items()):
        raise BoundaryClosed("install state differs from the signed adoption journal")
    for key in ("runtime_sha256", "release_sha256"):
        _hex64(document.get(key), f"install state {key}")
    return document, path


def _read_cutover_transaction(journal: Journal, pending: pathlib.Path) -> str | None:
    archived = pending / "archived/cutover-intent.json"
    live = CUTOVER_INTENT.exists() or CUTOVER_INTENT.is_symlink()
    saved = archived.exists() or archived.is_symlink()
    if live and saved:
        raise BoundaryClosed("live and archived cutover intents are both present")
    if not live and not saved:
        return None
    path = CUTOVER_INTENT if live else archived
    document = _read_json(
        _protected_file(path, modes=frozenset({0o400}), maximum_bytes=65_536),
        "cutover intent",
    )
    required = {
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
    if (
        set(document) != required
        or document.get("schema_version") != 1
        or document.get("kind") != "offline-cutover-intent"
        or document.get("project_name") != PROJECT
        or document.get("operation") != "install"
        or document.get("status") != "prepared"
        or document.get("contract_sha256") != journal.payload["target_contract_sha256"]
        or document.get("manifest_sha256") != journal.payload["target_manifest_sha256"]
    ):
        raise BoundaryClosed("cutover intent differs from the adoption journal")
    return _transaction(document.get("transaction_id"), "cutover transaction")


def _installed_receipts() -> list[pathlib.Path]:
    return sorted(STATE_ROOT.glob("installed-*.json"))


def _systemd_state(runner: Runner, unit: str) -> dict[str, str]:
    load = (
        runner.run(
            ("/usr/bin/systemctl", "show", unit, "--property=LoadState", "--value"),
            accepted=frozenset({0, 1, 4}),
        )
        or "not-found"
    )
    active = (
        runner.run(
            ("/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--value"),
            accepted=frozenset({0, 1, 4}),
        )
        or "inactive"
    )
    unit_file = runner.run(
        ("/usr/bin/systemctl", "show", unit, "--property=UnitFileState", "--value"),
        accepted=frozenset({0, 1, 4}),
    ) or ("not-found" if load == "not-found" else "disabled")
    return {
        "load_state": load,
        "active_state": active,
        "unit_file_state": unit_file,
    }


def _validate_inert_recovery_assets(release_root: pathlib.Path) -> None:
    """Validate retained recovery helpers as immutable, inactive evidence."""

    if not RECOVERY_ROOT.exists() and not RECOVERY_ROOT.is_symlink():
        return
    _protected_directory(RECOVERY_ROOT)
    expected = {
        "offline-recovery-dispatcher.sh",
        "offline-recovery-state.py",
    }
    observed = {entry.name for entry in RECOVERY_ROOT.iterdir()}
    if not observed.issubset(expected):
        raise BoundaryClosed("recovery directory contains an unknown target artifact")
    for name in observed:
        source = release_root / "deploy/tencent" / name
        destination = RECOVERY_ROOT / name
        source_payload = _protected_file(source, modes=frozenset({0o444}), maximum_bytes=2_097_152)
        retained_payload = _protected_file(
            destination, modes=frozenset({0o500}), maximum_bytes=2_097_152
        )
        if retained_payload != source_payload:
            raise BoundaryClosed("retained recovery helper differs from the target release")


def _restore_reconcile_baseline(
    runner: Runner,
    *,
    release_root: pathlib.Path,
    pending: pathlib.Path,
    execute: bool,
) -> dict[str, object]:
    archived_units = pending / "archived/systemd"
    if execute:
        archived_units.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(archived_units, 0o700)
    source_root = release_root / "deploy/tencent"
    installed: list[tuple[pathlib.Path, pathlib.Path, pathlib.Path]] = []
    target_unit_evidence = False
    for unit in (RECONCILE_SERVICE, RECONCILE_TIMER):
        source = source_root / unit
        destination = SYSTEMD_ROOT / unit
        archive = archived_units / unit
        source_payload = _protected_file(source, modes=frozenset({0o444}), maximum_bytes=65_536)
        if destination.exists() or destination.is_symlink():
            target_unit_evidence = True
            installed_payload = _protected_file(
                destination, modes=frozenset({0o444}), maximum_bytes=65_536
            )
            if installed_payload != source_payload:
                raise BoundaryClosed("reconcile unit differs from the target release")
            if archive.exists() or archive.is_symlink():
                raise BoundaryClosed("live and archived reconcile units are both present")
            installed.append((source, destination, archive))
        elif archive.exists() or archive.is_symlink():
            target_unit_evidence = True
            archived_payload = _protected_file(
                archive, modes=frozenset({0o444}), maximum_bytes=65_536
            )
            if archived_payload != source_payload:
                raise BoundaryClosed("archived reconcile unit differs from the target release")

    expected = {
        "load_state": "not-found",
        "active_state": "inactive",
        "unit_file_state": "not-found",
    }
    if not execute:
        # Exact live and exact archived unit files are both resumable under the
        # inherited fd9 operation lock.  A kill between the two atomic moves
        # can leave one of each, which is also a valid retry state.
        return {RECONCILE_SERVICE: expected, RECONCILE_TIMER: expected}

    if execute and target_unit_evidence:
        runner.run(
            ("/usr/bin/systemctl", "disable", "--now", RECONCILE_TIMER),
            accepted=frozenset({0, 1}),
        )
        runner.run(
            ("/usr/bin/systemctl", "stop", RECONCILE_SERVICE),
            accepted=frozenset({0, 1, 5}),
        )
        for _source, destination, archive in installed:
            os.replace(destination, archive)
            _fsync_directory(archive.parent)
        if installed:
            _fsync_directory(SYSTEMD_ROOT)
        runner.run(("/usr/bin/systemctl", "daemon-reload"))

    result: dict[str, object] = {
        RECONCILE_SERVICE: _systemd_state(runner, RECONCILE_SERVICE),
        RECONCILE_TIMER: _systemd_state(runner, RECONCILE_TIMER),
    }
    if result != {RECONCILE_SERVICE: expected, RECONCILE_TIMER: expected}:
        if execute:
            raise CleanupFailed("reconcile watchdog was not restored to the adoption baseline")
        raise BoundaryClosed("reconcile watchdog baseline cannot be restored exactly")
    return result


def _archive_install_state(path: pathlib.Path | None, pending: pathlib.Path) -> object:
    if path is None:
        return None
    destination = pending / "archived/install-in-progress.json"
    if path == destination:
        payload = _protected_file(destination, modes=frozenset({0o400}), maximum_bytes=65_536)
    else:
        os.replace(path, destination)
        _fsync_directory(destination.parent)
        _fsync_directory(STATE_ROOT)
        payload = _protected_file(destination, modes=frozenset({0o400}), maximum_bytes=65_536)
    return {
        "path": str(
            pending.parent / "target-pre-migration-abort" / "archived/install-in-progress.json"
        ),
        "sha256": _sha256(payload),
    }


def _archive_cutover_intent(
    runner: Runner,
    journal: Journal,
    pending: pathlib.Path,
    cutover_transaction: str | None,
    release_root: pathlib.Path,
) -> object:
    if cutover_transaction is None:
        return None
    archive = pending / "archived/cutover-intent.json"
    state_helper = release_root / "deploy/tencent/offline-recovery-state.py"
    output = runner.run(
        (
            "/usr/bin/python3",
            "-I",
            str(state_helper),
            "abort-install-intent",
            cast(str, journal.payload["target_contract_sha256"]),
            cutover_transaction,
            cast(str, journal.payload["adoption_transaction_id"]),
            journal.sha256,
            str(archive),
        )
    )
    document = _read_json(output.encode("utf-8"), "intent archive result")
    return {
        "path": str(pending.parent / "target-pre-migration-abort" / "archived/cutover-intent.json"),
        "sha256": _hex64(document.get("sha256"), "archived intent SHA-256"),
    }


def _host_isolation_verification(
    runner: Runner,
    journal: Journal,
    pending: pathlib.Path,
    *,
    release_root: pathlib.Path,
    baseline: pathlib.Path,
    hmac_key: pathlib.Path,
) -> dict[str, str]:
    if _sha256_file(baseline) != journal.payload["host_isolation_baseline_sha256"]:
        raise BoundaryClosed("host-isolation baseline differs from the adoption journal")
    report = pending / "host-isolation-after-abort.json"
    report_pending = pending / ".host-isolation-after-abort.pending"
    if report.exists() or report.is_symlink():
        _protected_file(report, modes=frozenset({0o400}), maximum_bytes=4_194_304)
    if report_pending.exists() or report_pending.is_symlink():
        _protected_file(
            report_pending,
            modes=frozenset({0o400, 0o600}),
            maximum_bytes=4_194_304,
        )
        report_pending.unlink()
        _fsync_directory(pending)
    runner.run(
        (
            "/usr/bin/python3",
            "-I",
            str(release_root / "scripts/host_isolation_guard.py"),
            "verify",
            "--baseline",
            str(baseline),
            "--hmac-key-file",
            str(hmac_key),
            "--output",
            str(report_pending),
        ),
        timeout=180,
    )
    _protected_file(report_pending, modes=frozenset({0o600}), maximum_bytes=4_194_304)
    # Flush through a write-capable descriptor before dropping write permission.
    # POSIX permits fsync(2) to reject a read-only descriptor with EBADF.
    with report_pending.open("rb+") as stream:
        os.fsync(stream.fileno())
    os.chmod(report_pending, 0o400)
    os.replace(report_pending, report)
    _fsync_directory(report.parent)
    document = _read_json(
        _protected_file(report, modes=frozenset({0o400}), maximum_bytes=4_194_304),
        "host-isolation verification",
    )
    if document.get("status") != "PASS" or document.get("change_count") != 0:
        raise BoundaryClosed("host-isolation verification detected shared-host drift")
    return {
        "path": str(pending.parent / "target-pre-migration-abort" / report.name),
        "sha256": _sha256_file(report),
        "status": "PASS",
    }


def _atomic_write(path: pathlib.Path, payload: bytes, mode: int) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _verify_signature(
    runner: Runner, receipt: pathlib.Path, signature: pathlib.Path, public_key: pathlib.Path
) -> None:
    runner.run(
        (
            "/usr/bin/openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public_key),
            "-signature",
            str(signature),
            str(receipt),
        )
    )


def _publish_receipt(
    runner: Runner,
    *,
    pending: pathlib.Path,
    final: pathlib.Path,
    receipt: Mapping[str, object],
    signing_key: pathlib.Path,
    public_key: pathlib.Path,
) -> None:
    receipt_path = pending / "receipt.json"
    signature_path = pending / "receipt.sig"
    _atomic_write(receipt_path, _canonical_json(receipt), 0o400)
    runner.run(
        (
            "/usr/bin/openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(signing_key),
            "-out",
            str(signature_path),
            str(receipt_path),
        )
    )
    with signature_path.open("rb+") as stream:
        os.fsync(stream.fileno())
    os.chmod(signature_path, 0o400)
    _protected_file(signature_path, modes=frozenset({0o400}), maximum_bytes=65_536)
    _verify_signature(runner, receipt_path, signature_path, public_key)
    _fsync_directory(pending)
    os.replace(pending, final)
    _fsync_directory(final.parent)


def _validate_published_receipt(
    runner: Runner,
    final: pathlib.Path,
    journal: Journal,
    public_key: pathlib.Path,
) -> dict[str, Any]:
    receipt_path = final / "receipt.json"
    signature_path = final / "receipt.sig"
    receipt_raw = _protected_file(receipt_path, modes=frozenset({0o400}), maximum_bytes=262_144)
    receipt = _read_json(receipt_raw, "pre-migration abort receipt")
    if receipt_raw != _canonical_json(receipt):
        _fail("published abort receipt is not canonical JSON")
    _protected_file(signature_path, modes=frozenset({0o400}), maximum_bytes=65_536)
    _verify_signature(runner, receipt_path, signature_path, public_key)
    if set(receipt) != RECEIPT_KEYS:
        _fail("published abort receipt schema differs")
    expected = {
        "schema_version": 1,
        "kind": "heyi-target-pre-migration-abort-receipt",
        "status": "aborted_pre_migration",
        "project": PROJECT,
        "adoption_transaction_id": journal.payload["adoption_transaction_id"],
        "journal_sha256": journal.sha256,
        "plan_sha256": journal.payload["plan_sha256"],
        "retirement_receipt_sha256": journal.payload["retirement_receipt_sha256"],
        "target_contract_sha256": journal.payload["target_contract_sha256"],
        "target_manifest_sha256": journal.payload["target_manifest_sha256"],
        "target_schema_head": journal.payload["target_schema_head"],
        "legacy_source_schema_head": journal.payload["legacy_source_schema_head"],
        "migration_command_invoked": False,
        "active_release_present": False,
        "installed_receipt_present": False,
        "bind_data_deleted": False,
        "named_volumes_deleted": False,
        "global_actions": [],
        "restore_boundary": RESTORE_BOUNDARY,
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        _fail("published abort receipt identity differs")
    _timestamp(receipt.get("issued_at"), "abort receipt issued_at")
    last_phase = receipt.get("last_install_phase")
    if last_phase not in {"not_started", *OPEN_PHASES}:
        _fail("published abort receipt install phase is invalid")
    removed_ids = receipt.get("removed_preflight_container_ids")
    if (
        not isinstance(removed_ids, list)
        or any(
            not isinstance(identifier, str) or re.fullmatch(r"[0-9a-f]{64}", identifier) is None
            for identifier in removed_ids
        )
        or len(set(cast(list[str], removed_ids))) != len(removed_ids)
    ):
        _fail("published abort receipt container identities are invalid")
    if not isinstance(receipt.get("removed_owner_marker_volume"), bool):
        _fail("published abort receipt owner-marker result is invalid")

    def validate_archive_descriptor(value: object, name: str) -> None:
        if value is None:
            return
        expected_path = str(final / "archived" / name)
        if (
            not isinstance(value, dict)
            or set(value) != {"path", "sha256"}
            or value.get("path") != expected_path
            or not isinstance(value.get("sha256"), str)
            or HEX64.fullmatch(cast(str, value["sha256"])) is None
        ):
            _fail(f"published abort receipt {name} archive is invalid")

    archived_state = receipt.get("archived_install_state")
    archived_intent = receipt.get("archived_cutover_intent")
    validate_archive_descriptor(archived_state, "install-in-progress.json")
    validate_archive_descriptor(archived_intent, "cutover-intent.json")
    if last_phase == "not_started" and (archived_state is not None or archived_intent is not None):
        _fail("not-started abort receipt contains archived target state")
    if last_phase in OPEN_PHASES and archived_state is None:
        _fail("started abort receipt is missing archived install state")
    if last_phase == "preflight_passed" and archived_intent is None:
        _fail("preflight abort receipt is missing archived cutover intent")
    baseline = _validate_reconcile_baseline(receipt.get("reconcile_baseline"))
    if baseline != journal.payload["reconcile_baseline"]:
        _fail("published abort receipt reconcile baseline differs")
    if receipt.get("reconcile_result") != baseline:
        _fail("published abort receipt reconcile result differs")
    if receipt.get("target_resource_counts_after") != {
        "containers": 0,
        "networks": 0,
        "project_volumes": 0,
        "owner_marker": 0,
    }:
        _fail("published abort receipt target resources remain")
    host = receipt.get("host_isolation_verification")
    if (
        not isinstance(host, dict)
        or set(host) != {"path", "sha256", "status"}
        or host.get("path") != str(final / "host-isolation-after-abort.json")
        or host.get("status") != "PASS"
        or not isinstance(host.get("sha256"), str)
        or HEX64.fullmatch(cast(str, host["sha256"])) is None
        or receipt.get("preserved_bind_root") != str(DATA_ROOT)
    ):
        _fail("published abort receipt host or data preservation evidence is invalid")
    return receipt


def _dry_run_result(
    *,
    journal: Journal,
    last_install_phase: object,
    preflight_container_ids: list[str],
    owner_marker_present: bool,
) -> dict[str, object]:
    if not isinstance(last_install_phase, str) or last_install_phase not in {
        "not_started",
        *OPEN_PHASES,
    }:
        _fail("dry-run install phase is invalid")
    return {
        "schema_version": 1,
        "status": "dry-run",
        "project": PROJECT,
        "adoption_transaction_id": journal.payload["adoption_transaction_id"],
        "contract_sha256": journal.payload["target_contract_sha256"],
        "last_install_phase": last_install_phase,
        "preflight_container_ids": preflight_container_ids,
        "owner_marker_present": owner_marker_present,
        "migration_command_invoked": False,
        "restore_boundary": RESTORE_BOUNDARY,
    }


@dataclass(frozen=True)
class AbortArguments:
    journal: pathlib.Path
    binding_key: pathlib.Path
    host_baseline: pathlib.Path
    host_hmac_key: pathlib.Path
    execute: bool
    project: str
    contract: str
    adoption_transaction: str
    plan: str
    retirement_receipt: str
    restore_boundary: str


def abort_pre_migration(arguments: AbortArguments, runner: Runner | None = None) -> dict[str, Any]:
    _require_root_linux()
    command_runner = runner or Runner()
    materialized_contract = _self_bound_contract()
    if arguments.contract != materialized_contract:
        _fail("abort confirmation differs from the sealed materialized release")
    _validate_evidence_trust_root(command_runner, contract=materialized_contract)
    if arguments.project != PROJECT or arguments.restore_boundary != RESTORE_BOUNDARY:
        _fail("exact project and PRE_MIGRATION_ONLY confirmations are required")
    journal = validate_journal(
        arguments.journal,
        arguments.binding_key,
        expected_transaction=arguments.adoption_transaction,
        expected_contract=arguments.contract,
        expected_plan=arguments.plan,
        expected_retirement_receipt=arguments.retirement_receipt,
    )
    release_root = RELEASE_ROOT / arguments.contract
    if release_root.resolve(strict=True) != release_root:
        _fail("materialized target release is unavailable")
    transaction_dir = arguments.journal.parent
    pending = transaction_dir / ".target-pre-migration-abort.pending"
    final = transaction_dir / "target-pre-migration-abort"
    if final.exists() or final.is_symlink():
        if pending.exists() or pending.is_symlink():
            _fail("published and pending abort receipts both exist")
        published = _validate_published_receipt(
            command_runner, final, journal, TRUSTED_EVIDENCE_PUBLIC_KEY
        )
        if arguments.execute:
            return published
        # Retried orchestration still performs its mandatory dry-run.  Verify
        # the signed receipt, then expose the current resource-free state using
        # the stable dry-run schema expected by that gate.
        return _dry_run_result(
            journal=journal,
            last_install_phase=published.get("last_install_phase"),
            preflight_container_ids=[],
            owner_marker_present=False,
        )
    if pending.exists() or pending.is_symlink():
        _protected_directory(pending)
    elif arguments.execute:
        pending.mkdir(mode=0o700)
        _protected_directory(pending)
    else:
        # Dry-run uses no persistent output and performs no cleanup.
        pending = transaction_dir / ".target-pre-migration-abort.dry-run"

    if ACTIVE_RELEASE.exists() or ACTIVE_RELEASE.is_symlink():
        raise BoundaryClosed("an active target release exists")
    installed = _installed_receipts()
    if installed:
        raise BoundaryClosed("a completed target installation receipt exists")
    state, state_path = _read_install_state(journal, pending)
    cutover_transaction = _read_cutover_transaction(journal, pending)
    if state is None and cutover_transaction is not None:
        raise BoundaryClosed("cutover intent exists without its bound install state")
    if state is not None and state["phase"] == "preflight_passed" and cutover_transaction is None:
        raise BoundaryClosed("preflight-passed state is missing its cutover intent")

    _assert_no_network_or_project_volume(command_runner)
    if cutover_transaction is not None:
        _validate_inert_recovery_assets(release_root)
    containers = _validated_preflight_containers(
        command_runner,
        contract_sha256=arguments.contract,
        adoption_transaction=arguments.adoption_transaction,
        release_root=release_root,
    )
    marker_present = _remove_owner_marker(
        command_runner,
        contract_sha256=arguments.contract,
        adoption_transaction=arguments.adoption_transaction,
        execute=False,
    )
    _restore_reconcile_baseline(
        command_runner,
        release_root=release_root,
        pending=pending,
        execute=False,
    )
    if not arguments.execute:
        return _dry_run_result(
            journal=journal,
            last_install_phase=state["phase"] if state is not None else "not_started",
            preflight_container_ids=[cast(str, item["id"]) for item in containers],
            owner_marker_present=marker_present,
        )

    for path in (pending / "archived",):
        path.mkdir(mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    # Close and archive the target watchdog before deleting its owner marker.
    # The caller holds the same inherited operation flock, so the timer cannot
    # observe a marker-less half-cleaned transaction between these steps.
    reconcile_result = _restore_reconcile_baseline(
        command_runner,
        release_root=release_root,
        pending=pending,
        execute=True,
    )
    removed_containers = _remove_preflight_containers(command_runner, containers, execute=True)
    removed_marker = _remove_owner_marker(
        command_runner,
        contract_sha256=arguments.contract,
        adoption_transaction=arguments.adoption_transaction,
        execute=True,
    )
    counts = _project_resource_counts(command_runner)
    if any(counts.values()):
        raise CleanupFailed("target resources remain after exact pre-migration cleanup")
    host_verification = _host_isolation_verification(
        command_runner,
        journal,
        pending,
        release_root=release_root,
        baseline=arguments.host_baseline,
        hmac_key=arguments.host_hmac_key,
    )
    archived_state = _archive_install_state(state_path, pending)
    archived_intent = _archive_cutover_intent(
        command_runner,
        journal,
        pending,
        cutover_transaction,
        release_root,
    )
    if CUTOVER_INTENT.exists() or CUTOVER_INTENT.is_symlink():
        raise CleanupFailed("live cutover intent remains after exact archival")
    if INSTALL_STATE.exists() or INSTALL_STATE.is_symlink():
        raise CleanupFailed("live install state remains after exact archival")
    receipt: dict[str, object] = {
        "schema_version": 1,
        "kind": "heyi-target-pre-migration-abort-receipt",
        "status": "aborted_pre_migration",
        "project": PROJECT,
        "issued_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "adoption_transaction_id": arguments.adoption_transaction,
        "journal_sha256": journal.sha256,
        "plan_sha256": arguments.plan,
        "retirement_receipt_sha256": arguments.retirement_receipt,
        "target_contract_sha256": arguments.contract,
        "target_manifest_sha256": journal.payload["target_manifest_sha256"],
        "target_schema_head": journal.payload["target_schema_head"],
        "legacy_source_schema_head": journal.payload["legacy_source_schema_head"],
        "last_install_phase": state["phase"] if state is not None else "not_started",
        "migration_command_invoked": False,
        "active_release_present": False,
        "installed_receipt_present": False,
        "removed_preflight_container_ids": removed_containers,
        "removed_owner_marker_volume": removed_marker,
        "archived_install_state": archived_state,
        "archived_cutover_intent": archived_intent,
        "reconcile_baseline": journal.payload["reconcile_baseline"],
        "reconcile_result": reconcile_result,
        "target_resource_counts_after": counts,
        "host_isolation_verification": host_verification,
        "preserved_bind_root": str(DATA_ROOT),
        "bind_data_deleted": False,
        "named_volumes_deleted": False,
        "global_actions": [],
        "restore_boundary": RESTORE_BOUNDARY,
    }
    _publish_receipt(
        command_runner,
        pending=pending,
        final=final,
        receipt=receipt,
        signing_key=TRUSTED_EVIDENCE_SIGNING_KEY,
        public_key=TRUSTED_EVIDENCE_PUBLIC_KEY,
    )
    return _validate_published_receipt(command_runner, final, journal, TRUSTED_EVIDENCE_PUBLIC_KEY)


def _self_bound_contract() -> str:
    """Return the contract bound to this immutable, root-owned helper."""

    helper_path = pathlib.Path(__file__).resolve(strict=True)
    contract = _hex64(helper_path.parents[2].name, "materialized release contract")
    expected_helper = RELEASE_ROOT / contract / "deploy/tencent/offline-pre-migration-abort.py"
    if helper_path != expected_helper:
        _fail("abort helper is outside the sealed materialized release")
    _protected_file(helper_path, modes=frozenset({0o444}), maximum_bytes=2_097_152)
    return contract


def _self_bound_dry_run_arguments(arguments: argparse.Namespace) -> AbortArguments:
    """Derive non-mutating confirmations from the journal and sealed release."""

    contract = _self_bound_contract()
    transaction = _transaction(
        arguments.adoption_journal.parent.name, "adoption transaction directory"
    )
    journal = validate_journal(
        arguments.adoption_journal,
        arguments.adoption_binding_key,
        expected_transaction=transaction,
        expected_contract=contract,
    )
    return AbortArguments(
        journal=arguments.adoption_journal,
        binding_key=arguments.adoption_binding_key,
        host_baseline=arguments.host_isolation_baseline,
        host_hmac_key=arguments.host_isolation_hmac_key,
        execute=False,
        project=PROJECT,
        contract=contract,
        adoption_transaction=transaction,
        plan=cast(str, journal.payload["plan_sha256"]),
        retirement_receipt=cast(str, journal.payload["retirement_receipt_sha256"]),
        restore_boundary=RESTORE_BOUNDARY,
    )


def _add_abort_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--adoption-journal", required=True, type=pathlib.Path)
    parser.add_argument("--adoption-binding-key", required=True, type=pathlib.Path)
    parser.add_argument("--host-isolation-baseline", required=True, type=pathlib.Path)
    parser.add_argument("--host-isolation-hmac-key", required=True, type=pathlib.Path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate-journal")
    validate.add_argument("--journal", required=True, type=pathlib.Path)
    validate.add_argument("--binding-key", required=True, type=pathlib.Path)
    validate.add_argument("--adoption-transaction", required=True)
    validate.add_argument("--contract-sha256", required=True)
    validate.add_argument("--allow-pending-journal", action="store_true")
    validate_trust = subparsers.add_parser("validate-evidence-trust-root")
    validate_trust.add_argument("--challenge-context-sha256", default="")
    dry_run = subparsers.add_parser("abort-dry-run")
    _add_abort_arguments(dry_run)
    abort = subparsers.add_parser("abort")
    _add_abort_arguments(abort)
    abort.add_argument("--execute", action="store_true")
    abort.add_argument("--confirm-project", default="")
    abort.add_argument("--confirm-contract-sha256", default="")
    abort.add_argument("--confirm-adoption-transaction", default="")
    abort.add_argument("--confirm-plan-sha256", default="")
    abort.add_argument("--confirm-retirement-receipt-sha256", default="")
    abort.add_argument("--confirm-restore-boundary", default="")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "validate-journal":
        _require_root_linux()
        journal = validate_journal(
            arguments.journal,
            arguments.binding_key,
            expected_transaction=arguments.adoption_transaction,
            expected_contract=arguments.contract_sha256,
            allow_pending_journal=arguments.allow_pending_journal,
        )
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "verified",
                    "journal_sha256": journal.sha256,
                    "adoption_transaction_id": journal.payload["adoption_transaction_id"],
                    "plan_sha256": journal.payload["plan_sha256"],
                    "retirement_receipt_sha256": journal.payload["retirement_receipt_sha256"],
                    "target_contract_sha256": journal.payload["target_contract_sha256"],
                    "target_manifest_sha256": journal.payload["target_manifest_sha256"],
                    "target_schema_head": journal.payload["target_schema_head"],
                    "legacy_source_schema_head": journal.payload["legacy_source_schema_head"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    if arguments.command == "validate-evidence-trust-root":
        _require_root_linux()
        explicit_context = bool(arguments.challenge_context_sha256)
        challenge_context = (
            _hex64(arguments.challenge_context_sha256, "trust challenge context")
            if explicit_context
            else _self_bound_contract()
        )
        digest = _validate_evidence_trust_root(Runner(), contract=challenge_context)
        identity = {
            (
                "challenge_context_sha256" if explicit_context else "contract_sha256"
            ): challenge_context
        }
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "verified",
                    "public_key_sha256": digest,
                    **identity,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    if arguments.command == "abort-dry-run":
        result = abort_pre_migration(_self_bound_dry_run_arguments(arguments))
    else:
        result = abort_pre_migration(
            AbortArguments(
                journal=arguments.adoption_journal,
                binding_key=arguments.adoption_binding_key,
                host_baseline=arguments.host_isolation_baseline,
                host_hmac_key=arguments.host_isolation_hmac_key,
                execute=arguments.execute,
                project=arguments.confirm_project,
                contract=arguments.confirm_contract_sha256,
                adoption_transaction=arguments.confirm_adoption_transaction,
                plan=arguments.confirm_plan_sha256,
                retirement_receipt=arguments.confirm_retirement_receipt_sha256,
                restore_boundary=arguments.confirm_restore_boundary,
            )
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AbortError as exc:
        print(f"pre-migration-abort: {exc}", file=sys.stderr)
        raise SystemExit(exc.code) from exc
