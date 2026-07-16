from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
VERIFIER_PATH = REPOSITORY / "deploy" / "tencent" / "verify-upgrade-backup.py"
ADOPTION_PATH = REPOSITORY / "deploy" / "tencent" / "adopt-offline.sh"
PREFLIGHT_PATH = REPOSITORY / "deploy" / "tencent" / "preflight-offline.sh"


def _load_verifier() -> ModuleType:
    name = "heyi_test_upgrade_backup_verifier"
    spec = importlib.util.spec_from_file_location(name, VERIFIER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _artifact_stat_view(
    observed: os.stat_result,
    *,
    uid: int,
    atime_ns: int | None = None,
    ctime_ns: int | None = None,
) -> SimpleNamespace:
    """Build the subset of descriptor metadata consumed by the verifier."""
    return SimpleNamespace(
        st_dev=observed.st_dev,
        st_ino=observed.st_ino,
        st_uid=uid,
        st_gid=observed.st_gid,
        st_mode=observed.st_mode,
        st_nlink=observed.st_nlink,
        st_size=observed.st_size,
        st_atime_ns=observed.st_atime_ns if atime_ns is None else atime_ns,
        st_ctime_ns=observed.st_ctime_ns if ctime_ns is None else ctime_ns,
    )


def _simulate_root_owned_descriptor_reads(
    verifier: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Model the root-owned production precondition for content-level tests."""
    real_fstat = verifier.os.fstat

    def root_owned_fstat(descriptor: int) -> SimpleNamespace:
        return _artifact_stat_view(real_fstat(descriptor), uid=0)

    monkeypatch.setattr(verifier.os, "fstat", root_owned_fstat)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _evidence(
    *,
    authorization_sha256: str = "a" * 64,
    manifest_sha256: str = "b" * 64,
    issued_at: datetime | None = None,
    tested_at: datetime | None = None,
    operation_scope: str = "active_upgrade",
) -> dict[str, object]:
    issued = issued_at or datetime.now(UTC) - timedelta(minutes=1)
    tested = tested_at or issued
    artifact = {
        "path": "/srv/heyi-knowledgebases-offline/backups/run/artifact",
        "sha256": "c" * 64,
        "size_bytes": 1,
    }
    document: dict[str, object] = {
        "schema_version": 3,
        "kind": "offline-upgrade-backup",
        "project": "heyi-kb-offline",
        "operation_scope": operation_scope,
        "issued_at": _timestamp(issued),
        "expires_at": _timestamp(issued + timedelta(hours=24)),
        "release_authorization_sha256": authorization_sha256,
        "target_manifest_sha256": manifest_sha256,
        "database_backup": artifact,
        "object_manifest": artifact,
        "restore_evidence": artifact,
        "restore_drill": {
            "status": "passed",
            "tested_at": _timestamp(tested),
            "source_schema_head": "20260712_0013",
        },
    }
    if operation_scope == "active_upgrade":
        document["control_state_archive"] = artifact
        document["control_state_manifest"] = artifact
    return document


def test_fixed_release_authorization_digest_is_mandatory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_verifier()
    checked: list[str] = []

    def artifact(_document: object, field: str) -> tuple[Path, str, int]:
        checked.append(field)
        return Path("/backup/artifact"), "c" * 64, 1

    monkeypatch.setattr(verifier, "_artifact", artifact)
    monkeypatch.setattr(
        verifier, "_validate_control_state_manifest", lambda *_args, **_kwargs: None
    )

    verifier._validate_document(
        _evidence(),
        expected_manifest_sha256="b" * 64,
        expected_release_authorization_sha256="a" * 64,
        expected_operation_scope="active_upgrade",
        require_current=True,
    )
    assert checked == [
        "database_backup",
        "object_manifest",
        "restore_evidence",
        "control_state_archive",
        "control_state_manifest",
    ]

    with pytest.raises(ValueError, match="identity differs"):
        verifier._validate_document(
            _evidence(authorization_sha256="d" * 64),
            expected_manifest_sha256="b" * 64,
            expected_release_authorization_sha256="a" * 64,
            expected_operation_scope="active_upgrade",
            require_current=True,
        )


def test_same_manifest_from_another_authorization_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_verifier()
    monkeypatch.setattr(
        verifier,
        "_artifact",
        lambda _document, _field: (Path("/backup/artifact"), "c" * 64, 1),
    )
    monkeypatch.setattr(
        verifier, "_validate_control_state_manifest", lambda *_args, **_kwargs: None
    )

    stale_authorization = _evidence(
        authorization_sha256="d" * 64,
        manifest_sha256="b" * 64,
    )
    with pytest.raises(ValueError, match="identity differs"):
        verifier._validate_document(
            stale_authorization,
            expected_manifest_sha256="b" * 64,
            expected_release_authorization_sha256="a" * 64,
            expected_operation_scope="active_upgrade",
            require_current=True,
        )


def test_artifact_size_rejects_json_boolean(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = _load_verifier()
    document = _evidence()
    raw_artifact = document["database_backup"]
    assert isinstance(raw_artifact, dict)
    artifact = dict(raw_artifact)
    artifact["size_bytes"] = True
    document["database_backup"] = artifact
    monkeypatch.setattr(
        verifier,
        "_protected_regular_file",
        lambda path, **_kwargs: path,
    )

    with pytest.raises(ValueError, match="size is invalid"):
        verifier._artifact(document, "database_backup")


def test_durable_resume_only_relaxes_wall_clock_freshness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_verifier()
    checked: list[str] = []

    def artifact(_document: object, field: str) -> tuple[Path, str, int]:
        checked.append(field)
        return Path("/backup/artifact"), "c" * 64, 1

    monkeypatch.setattr(verifier, "_artifact", artifact)
    monkeypatch.setattr(
        verifier, "_validate_control_state_manifest", lambda *_args, **_kwargs: None
    )
    expired = _evidence(issued_at=datetime(2024, 1, 1, tzinfo=UTC))

    with pytest.raises(ValueError, match="stale or future-dated"):
        verifier._validate_document(
            expired,
            expected_manifest_sha256="b" * 64,
            expected_release_authorization_sha256="a" * 64,
            expected_operation_scope="active_upgrade",
            require_current=True,
        )

    verifier._validate_document(
        expired,
        expected_manifest_sha256="b" * 64,
        expected_release_authorization_sha256="a" * 64,
        expected_operation_scope="active_upgrade",
        require_current=False,
    )
    assert checked == [
        "database_backup",
        "object_manifest",
        "restore_evidence",
        "control_state_archive",
        "control_state_manifest",
    ]


@pytest.mark.parametrize("require_current", (True, False))
def test_restore_drill_cannot_postdate_evidence_issuance(
    monkeypatch: pytest.MonkeyPatch,
    require_current: bool,
) -> None:
    verifier = _load_verifier()
    monkeypatch.setattr(
        verifier,
        "_artifact",
        lambda _document, _field: (Path("/backup/artifact"), "c" * 64, 1),
    )
    monkeypatch.setattr(
        verifier, "_validate_control_state_manifest", lambda *_args, **_kwargs: None
    )
    issued = datetime.now(UTC) - timedelta(hours=1)
    impossible_chronology = _evidence(
        issued_at=issued,
        tested_at=issued + timedelta(minutes=10),
    )

    with pytest.raises(ValueError, match="restore drill did not satisfy"):
        verifier._validate_document(
            impossible_chronology,
            expected_manifest_sha256="b" * 64,
            expected_release_authorization_sha256="a" * 64,
            expected_operation_scope="active_upgrade",
            require_current=require_current,
        )


@pytest.mark.parametrize(
    "payload",
    (
        '{"schema_version":2,"schema_version":2}',
        '{"schema_version":NaN}',
        '{"schema_version":Infinity}',
    ),
)
def test_evidence_json_rejects_ambiguous_numbers_and_duplicate_keys(
    tmp_path: Path,
    payload: str,
) -> None:
    verifier = _load_verifier()
    evidence = tmp_path / "evidence.json"
    evidence.write_text(payload, encoding="utf-8")

    with pytest.raises(ValueError):
        verifier._read_json(evidence)


def test_selected_manifest_must_match_fixed_release_authorization(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    verifier = _load_verifier()
    evidence = tmp_path / "evidence.json"
    signature = tmp_path / "evidence.sig"
    public_key = tmp_path / "evidence.pub"
    for path in (evidence, signature, public_key):
        path.write_bytes(b"x")
    monkeypatch.setattr(verifier, "_protected_regular_file", lambda path, **_kwargs: path)
    monkeypatch.setattr(verifier, "_verify_signature", lambda *_args: None)
    monkeypatch.setattr(
        verifier,
        "_fixed_release_authorization_binding",
        lambda: ("a" * 64, "b" * 64),
    )

    with pytest.raises(ValueError, match="selected manifest differs"):
        verifier._verify(
            evidence_path=evidence,
            signature_path=signature,
            public_key_path=public_key,
            expected_manifest_sha256="d" * 64,
            expected_operation_scope="legacy_adoption",
            require_current=True,
        )


def test_caller_bound_legacy_scope_is_accepted_and_active_upgrade_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_verifier()
    checked: list[str] = []

    def artifact(_document: object, field: str) -> tuple[Path, str, int]:
        checked.append(field)
        return Path("/backup/artifact"), "c" * 64, 1

    monkeypatch.setattr(
        verifier,
        "_artifact",
        artifact,
    )
    legacy = _evidence(operation_scope="legacy_adoption")

    verifier.validate_evidence_document(
        legacy,
        expected_manifest_sha256="b" * 64,
        expected_release_authorization_sha256="a" * 64,
        expected_operation_scope="legacy_adoption",
        require_current=True,
    )
    assert checked == ["database_backup", "object_manifest", "restore_evidence"]

    with pytest.raises(ValueError, match="active upgrade backup verification is disabled"):
        verifier.validate_evidence_document(
            legacy,
            expected_manifest_sha256="b" * 64,
            expected_release_authorization_sha256="a" * 64,
            expected_operation_scope="active_upgrade",
            require_current=True,
        )

    with pytest.raises(ValueError, match="operation scope differs"):
        verifier._validate_document(
            legacy,
            expected_manifest_sha256="b" * 64,
            expected_release_authorization_sha256="a" * 64,
            expected_operation_scope="active_upgrade",
            require_current=True,
        )


def _control_state_manifest(
    *,
    captured_at: datetime,
) -> dict[str, object]:
    runtime_sha256 = "1" * 64
    release_sha256 = "2" * 64
    release_manifest_sha256 = "3" * 64
    contract_manifest = (
        f"{runtime_sha256}  runtime.env\n"
        f"{release_sha256}  release.env\n"
        f"{release_manifest_sha256}  release.env.images\n"
    ).encode("ascii")
    source_contract_sha256 = hashlib.sha256(contract_manifest).hexdigest()
    records: list[dict[str, object]] = []
    for record_id, path in (
        ("chat_safety_sentinel", "data/chat-safety/poison.json"),
        ("chat_safety_clear_pending", "state/chat-safety-clear-pending.json"),
        ("cutover_intent", "state/cutover-intent.json"),
        ("install_in_progress", "state/install-in-progress.json"),
    ):
        records.append(
            {
                "id": record_id,
                "path": path,
                "state": "absent",
                "sha256": None,
                "size_bytes": 0,
            }
        )
    for record_id, path in (
        ("active_release", "state/active-release.json"),
        (
            "source_installed_receipt",
            f"state/installed-{source_contract_sha256}.json",
        ),
        ("highest_release", "state/highest-release.json"),
        (
            "registry_import_receipt",
            f"state/registry-import-{release_manifest_sha256}.json",
        ),
        (
            "active_contract_manifest",
            f"contracts/{source_contract_sha256}/files.sha256",
        ),
        ("recovery_state_helper", "recovery/offline-recovery-state.py"),
        ("recovery_dispatcher", "recovery/offline-recovery-dispatcher.sh"),
    ):
        records.append(
            {
                "id": record_id,
                "path": path,
                "state": "present",
                "sha256": "f" * 64,
                "size_bytes": 1,
            }
        )
    return {
        "schema_version": 1,
        "kind": "offline-control-state-backup-manifest",
        "project": "heyi-kb-offline",
        "source_contract_sha256": source_contract_sha256,
        "captured_at": _timestamp(captured_at),
        "archive_sha256": "c" * 64,
        "archive_size_bytes": 1,
        "restore_policy": {
            "initial_mode": "chat_safety_maintenance_hold",
            "materialize_hold_before_runtime": True,
            "missing_state_policy": "fail_closed",
            "allow_business_start_before_reconciliation": False,
        },
        "records": records,
    }


def _control_state_payloads(document: dict[str, object]) -> dict[str, bytes]:
    source_contract_sha256 = document["source_contract_sha256"]
    assert isinstance(source_contract_sha256, str)
    runtime_sha256 = "1" * 64
    release_sha256 = "2" * 64
    release_manifest_sha256 = "3" * 64
    release_assets_sha256 = "4" * 64
    trusted_key_sha256 = "5" * 64
    registry = {
        "schema_version": 2,
        "kind": "offline-registry-import",
        "status": "verified",
        "release_sequence": 202607160001,
        "release_id": "2026.07.16.1",
        "release_git_sha": "6" * 40,
        "release_schema_head": "20260715_0021",
        "release_sha256": release_sha256,
        "manifest_sha256": release_manifest_sha256,
        "release_assets_sha256": release_assets_sha256,
        "checksum_set_sha256": "7" * 64,
        "signature_sha256": "8" * 64,
        "trusted_key_sha256": trusted_key_sha256,
    }
    highest = {
        key: registry[key]
        for key in (
            "schema_version",
            "release_sequence",
            "release_id",
            "release_git_sha",
            "release_schema_head",
            "manifest_sha256",
            "release_assets_sha256",
            "trusted_key_sha256",
        )
    }
    active = {
        "schema_version": 2,
        "kind": "offline-active-release",
        "project_name": "heyi-kb-offline",
        "transaction_id": "9" * 32,
        "contract_sha256": source_contract_sha256,
        "runtime_sha256": runtime_sha256,
        "release_sha256": release_sha256,
        "manifest_sha256": release_manifest_sha256,
        "compose_profile": "strict-offline",
        "compose_config_sha256": "a" * 64,
        "project_inventory_sha256": "b" * 64,
        "egress_proof_sha256": "c" * 64,
        "active_provider_snapshot": "none",
        "status": "committed",
    }
    installed = {
        "schema_version": 1,
        "contract_sha256": source_contract_sha256,
        "runtime_sha256": runtime_sha256,
        "release_sha256": release_sha256,
        "manifest_sha256": release_manifest_sha256,
        "phase": "completed",
    }
    contract_manifest = (
        f"{runtime_sha256}  runtime.env\n"
        f"{release_sha256}  release.env\n"
        f"{release_manifest_sha256}  release.env.images\n"
    ).encode("ascii")
    assert hashlib.sha256(contract_manifest).hexdigest() == source_contract_sha256

    def encode(value: object) -> bytes:
        return json.dumps(value, sort_keys=True).encode("utf-8")

    return {
        "active_release": encode(active),
        "source_installed_receipt": encode(installed),
        "highest_release": encode(highest),
        "registry_import_receipt": encode(registry),
        "active_contract_manifest": contract_manifest,
        "recovery_state_helper": b"recovery-state-helper",
        "recovery_dispatcher": b"recovery-dispatcher",
    }


def test_control_state_manifest_requires_explicit_absence_and_mandatory_state() -> None:
    verifier = _load_verifier()
    issued_at = datetime.now(UTC).replace(microsecond=0)
    document = _control_state_manifest(captured_at=issued_at)

    verifier._validate_control_state_manifest_document(
        document,
        expected_archive_sha256="c" * 64,
        expected_archive_size_bytes=1,
        issued_at=issued_at,
    )

    records = document["records"]
    assert isinstance(records, list)
    document["records"] = [
        record
        for record in records
        if isinstance(record, dict) and record.get("id") != "chat_safety_clear_pending"
    ]
    with pytest.raises(ValueError, match="inventory is incomplete"):
        verifier._validate_control_state_manifest_document(
            document,
            expected_archive_sha256="c" * 64,
            expected_archive_size_bytes=1,
            issued_at=issued_at,
        )


@pytest.mark.parametrize(
    "record_id",
    ("active_release", "source_installed_receipt"),
)
def test_control_state_manifest_rejects_absent_mandatory_source_state(
    record_id: str,
) -> None:
    verifier = _load_verifier()
    issued_at = datetime.now(UTC).replace(microsecond=0)
    document = _control_state_manifest(captured_at=issued_at)
    records = document["records"]
    assert isinstance(records, list)
    mandatory = next(
        record for record in records if isinstance(record, dict) and record.get("id") == record_id
    )
    assert isinstance(mandatory, dict)
    mandatory["state"] = "absent"
    mandatory["sha256"] = None
    mandatory["size_bytes"] = 0

    with pytest.raises(ValueError, match="mandatory control state is absent"):
        verifier._validate_control_state_manifest_document(
            document,
            expected_archive_sha256="c" * 64,
            expected_archive_size_bytes=1,
            issued_at=issued_at,
        )


def test_control_state_manifest_rejects_non_contract_installed_receipt_path() -> None:
    verifier = _load_verifier()
    issued_at = datetime.now(UTC).replace(microsecond=0)
    document = _control_state_manifest(captured_at=issued_at)
    records = document["records"]
    assert isinstance(records, list)
    installed = next(
        record
        for record in records
        if isinstance(record, dict) and record.get("id") == "source_installed_receipt"
    )
    assert isinstance(installed, dict)
    installed["path"] = "state/installed-current.json"

    with pytest.raises(ValueError, match="record identity is invalid"):
        verifier._validate_control_state_manifest_document(
            document,
            expected_archive_sha256="c" * 64,
            expected_archive_size_bytes=1,
            issued_at=issued_at,
        )


@pytest.mark.parametrize(
    ("record_id", "path"),
    (
        ("source_installed_receipt", f"state/installed-{'a' * 64}.json"),
        ("active_contract_manifest", f"contracts/{'a' * 64}/files.sha256"),
    ),
)
def test_control_state_manifest_rejects_a_different_well_formed_contract_path(
    record_id: str,
    path: str,
) -> None:
    verifier = _load_verifier()
    issued_at = datetime.now(UTC).replace(microsecond=0)
    document = _control_state_manifest(captured_at=issued_at)
    records = document["records"]
    assert isinstance(records, list)
    record = next(
        record for record in records if isinstance(record, dict) and record.get("id") == record_id
    )
    assert isinstance(record, dict)
    record["path"] = path

    with pytest.raises(ValueError, match="source contract path binding differs"):
        verifier._validate_control_state_manifest_document(
            document,
            expected_archive_sha256="c" * 64,
            expected_archive_size_bytes=1,
            issued_at=issued_at,
        )


def test_control_state_archive_rejects_a_different_registry_receipt_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_verifier()
    _simulate_root_owned_descriptor_reads(verifier, monkeypatch)
    issued_at = datetime.now(UTC).replace(microsecond=0)
    document = _control_state_manifest(captured_at=issued_at)
    records = document["records"]
    assert isinstance(records, list)
    registry = next(
        record
        for record in records
        if isinstance(record, dict) and record.get("id") == "registry_import_receipt"
    )
    assert isinstance(registry, dict)
    registry["path"] = f"state/registry-import-{'f' * 64}.json"
    archive_payload = _control_state_tar(verifier, document)
    document["archive_sha256"] = hashlib.sha256(archive_payload).hexdigest()
    document["archive_size_bytes"] = len(archive_payload)
    archive_path = tmp_path / "control-state.tar"
    manifest_path = tmp_path / "control-state-manifest.json"
    archive_path.write_bytes(archive_payload)
    manifest_path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    archive_path.chmod(0o400)

    with pytest.raises(ValueError, match="registry import receipt differs"):
        verifier._validate_control_state_manifest(
            manifest_path,
            archive_path=archive_path,
            expected_archive_sha256=document["archive_sha256"],
            expected_archive_size_bytes=document["archive_size_bytes"],
            issued_at=issued_at,
        )


def test_control_state_manifest_binds_the_archive_and_fail_closed_restore_policy() -> None:
    verifier = _load_verifier()
    issued_at = datetime.now(UTC).replace(microsecond=0)
    document = _control_state_manifest(captured_at=issued_at)
    policy = document["restore_policy"]
    assert isinstance(policy, dict)
    policy["materialize_hold_before_runtime"] = False

    with pytest.raises(ValueError, match="backup policy is invalid"):
        verifier._validate_control_state_manifest_document(
            document,
            expected_archive_sha256="c" * 64,
            expected_archive_size_bytes=1,
            issued_at=issued_at,
        )

    policy["materialize_hold_before_runtime"] = True
    with pytest.raises(ValueError, match="backup policy is invalid"):
        verifier._validate_control_state_manifest_document(
            document,
            expected_archive_sha256="a" * 64,
            expected_archive_size_bytes=1,
            issued_at=issued_at,
        )


def _control_state_tar(
    verifier: ModuleType,
    document: dict[str, object],
    *,
    extra_member: bool = False,
    payload_overrides: dict[str, bytes] | None = None,
) -> bytes:
    records = document["records"]
    assert isinstance(records, list)
    payloads = _control_state_payloads(document)
    payloads.update(payload_overrides or {})
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for record in records:
            assert isinstance(record, dict)
            if record["state"] != "present":
                continue
            payload = payloads[str(record["id"])]
            record["sha256"] = hashlib.sha256(payload).hexdigest()
            record["size_bytes"] = len(payload)
            uid, gid, modes = verifier._CONTROL_STATE_METADATA[record["id"]]
            info = tarfile.TarInfo(str(record["path"]))
            info.type = tarfile.REGTYPE
            info.size = len(payload)
            info.uid = uid
            info.gid = gid
            info.mode = min(modes)
            info.mtime = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(payload))
        if extra_member:
            info = tarfile.TarInfo("state/unexpected.json")
            info.type = tarfile.REGTYPE
            info.size = 1
            info.uid = 0
            info.gid = 0
            info.mode = 0o400
            info.mtime = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(b"x"))
    return stream.getvalue()


def test_control_state_archive_and_manifest_are_verified_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_verifier()
    _simulate_root_owned_descriptor_reads(verifier, monkeypatch)
    issued_at = datetime.now(UTC).replace(microsecond=0)
    document = _control_state_manifest(captured_at=issued_at)
    archive_payload = _control_state_tar(verifier, document)
    document["archive_sha256"] = hashlib.sha256(archive_payload).hexdigest()
    document["archive_size_bytes"] = len(archive_payload)
    archive_path = tmp_path / "control-state.tar"
    manifest_path = tmp_path / "control-state-manifest.json"
    archive_path.write_bytes(archive_payload)
    manifest_path.write_text(
        json.dumps(document, sort_keys=True),
        encoding="utf-8",
    )
    archive_path.chmod(0o400)

    verifier._validate_control_state_manifest(
        manifest_path,
        archive_path=archive_path,
        expected_archive_sha256=document["archive_sha256"],
        expected_archive_size_bytes=document["archive_size_bytes"],
        issued_at=issued_at,
    )


def test_control_state_archive_rejects_an_extra_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_verifier()
    _simulate_root_owned_descriptor_reads(verifier, monkeypatch)
    issued_at = datetime.now(UTC).replace(microsecond=0)
    document = _control_state_manifest(captured_at=issued_at)
    archive_payload = _control_state_tar(verifier, document, extra_member=True)
    document["archive_sha256"] = hashlib.sha256(archive_payload).hexdigest()
    document["archive_size_bytes"] = len(archive_payload)
    archive_path = tmp_path / "control-state.tar"
    manifest_path = tmp_path / "control-state-manifest.json"
    archive_path.write_bytes(archive_payload)
    manifest_path.write_text(
        json.dumps(document, sort_keys=True),
        encoding="utf-8",
    )
    archive_path.chmod(0o400)

    with pytest.raises(ValueError, match="archive inventory differs"):
        verifier._validate_control_state_manifest(
            manifest_path,
            archive_path=archive_path,
            expected_archive_sha256=document["archive_sha256"],
            expected_archive_size_bytes=document["archive_size_bytes"],
            issued_at=issued_at,
        )


@pytest.mark.parametrize(
    ("record_id", "field", "invalid_value", "message"),
    (
        (
            "active_release",
            "contract_sha256",
            "f" * 64,
            "active release differs from the source contract",
        ),
        (
            "source_installed_receipt",
            "contract_sha256",
            "f" * 64,
            "installed receipt differs from the source contract",
        ),
        (
            "registry_import_receipt",
            "manifest_sha256",
            "f" * 64,
            "registry import receipt differs from the source contract",
        ),
    ),
)
def test_control_state_archive_rejects_cross_contract_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_id: str,
    field: str,
    invalid_value: str,
    message: str,
) -> None:
    verifier = _load_verifier()
    _simulate_root_owned_descriptor_reads(verifier, monkeypatch)
    issued_at = datetime.now(UTC).replace(microsecond=0)
    document = _control_state_manifest(captured_at=issued_at)
    payloads = _control_state_payloads(document)
    receipt = json.loads(payloads[record_id])
    receipt[field] = invalid_value
    archive_payload = _control_state_tar(
        verifier,
        document,
        payload_overrides={
            record_id: json.dumps(receipt, sort_keys=True).encode("utf-8"),
        },
    )
    document["archive_sha256"] = hashlib.sha256(archive_payload).hexdigest()
    document["archive_size_bytes"] = len(archive_payload)
    archive_path = tmp_path / "control-state.tar"
    manifest_path = tmp_path / "control-state-manifest.json"
    archive_path.write_bytes(archive_payload)
    manifest_path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    archive_path.chmod(0o400)

    with pytest.raises(ValueError, match=message):
        verifier._validate_control_state_manifest(
            manifest_path,
            archive_path=archive_path,
            expected_archive_sha256=document["archive_sha256"],
            expected_archive_size_bytes=document["archive_size_bytes"],
            issued_at=issued_at,
        )


def test_control_state_archive_rejects_contract_manifest_from_another_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_verifier()
    _simulate_root_owned_descriptor_reads(verifier, monkeypatch)
    issued_at = datetime.now(UTC).replace(microsecond=0)
    document = _control_state_manifest(captured_at=issued_at)
    archive_payload = _control_state_tar(
        verifier,
        document,
        payload_overrides={
            "active_contract_manifest": (
                f"{'1' * 64}  runtime.env\n"
                f"{'2' * 64}  release.env\n"
                f"{'f' * 64}  release.env.images\n"
            ).encode("ascii"),
        },
    )
    document["archive_sha256"] = hashlib.sha256(archive_payload).hexdigest()
    document["archive_size_bytes"] = len(archive_payload)
    archive_path = tmp_path / "control-state.tar"
    manifest_path = tmp_path / "control-state-manifest.json"
    archive_path.write_bytes(archive_payload)
    manifest_path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    archive_path.chmod(0o400)

    with pytest.raises(ValueError, match="manifest digest differs from the source contract"):
        verifier._validate_control_state_manifest(
            manifest_path,
            archive_path=archive_path,
            expected_archive_sha256=document["archive_sha256"],
            expected_archive_size_bytes=document["archive_size_bytes"],
            issued_at=issued_at,
        )


def test_verified_artifact_reader_rejects_non_root_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_verifier()
    payload = b"root ownership is mandatory"
    artifact = tmp_path / "artifact.tar"
    artifact.write_bytes(payload)
    artifact.chmod(0o400)
    real_fstat = verifier.os.fstat

    def non_root_fstat(descriptor: int) -> SimpleNamespace:
        return _artifact_stat_view(real_fstat(descriptor), uid=1000)

    monkeypatch.setattr(verifier.os, "fstat", non_root_fstat)

    with pytest.raises(
        ValueError,
        match="protected artifact metadata changed during verification",
    ):
        verifier._read_verified_artifact_bytes(
            artifact,
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            expected_size_bytes=len(payload),
            max_bytes=1024,
        )


def test_verified_artifact_reader_ignores_read_induced_timestamp_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_verifier()
    payload = b"timestamps are not security identity"
    artifact = tmp_path / "artifact.tar"
    artifact.write_bytes(payload)
    artifact.chmod(0o400)
    real_fstat = verifier.os.fstat
    observations = 0

    def timestamp_changing_fstat(descriptor: int) -> SimpleNamespace:
        nonlocal observations
        observations += 1
        observed = real_fstat(descriptor)
        return _artifact_stat_view(
            observed,
            uid=0,
            atime_ns=observed.st_atime_ns + observations,
            ctime_ns=observed.st_ctime_ns + observations,
        )

    monkeypatch.setattr(verifier.os, "fstat", timestamp_changing_fstat)

    assert (
        verifier._read_verified_artifact_bytes(
            artifact,
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            expected_size_bytes=len(payload),
            max_bytes=1024,
        )
        == payload
    )
    assert observations == 2


def test_fresh_and_durable_shell_paths_share_the_materialized_verifier() -> None:
    adoption = ADOPTION_PATH.read_text(encoding="utf-8")
    durable = adoption.split("verify_durable_backup_evidence() {", 1)[1].split("\n}", 1)[0]
    fresh = adoption.split("verify_fresh_backup_evidence() {", 1)[1].split("\n}", 1)[0]

    assert '"$trusted_backup_verifier"' in durable
    assert '"$trusted_backup_verifier"' in fresh
    assert "--durable-resume" in durable
    assert "--durable-resume" not in fresh
    for forbidden in ("expected_keys", "schema_version", "importlib", "openssl dgst"):
        assert forbidden not in durable


def test_preflight_validates_release_state_before_backup_evidence() -> None:
    preflight = PREFLIGHT_PATH.read_text(encoding="utf-8")

    release_state_gate = preflight.index("trusted release public key changed during validation")
    backup_gate = preflight.index('python3 -I "$snapshot_script_dir/verify-upgrade-backup.py"')
    assert release_state_gate < backup_gate


def test_verify_namespace_uses_durable_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = _load_verifier()
    observed: list[bool] = []
    monkeypatch.setattr(
        verifier,
        "_verify",
        lambda **kwargs: observed.append(kwargs["require_current"]),
    )
    arguments = argparse.Namespace(
        evidence=Path("/evidence"),
        signature=Path("/signature"),
        public_key=Path("/public-key"),
        expected_manifest_sha256="b" * 64,
        expected_operation_scope="legacy_adoption",
        durable_resume=True,
    )

    verifier.verify(arguments)
    assert observed == [False]


@pytest.mark.parametrize(
    ("durable_resume", "expected_message", "forbidden_message"),
    (
        (False, "are current and verified", "durable resume"),
        (True, "verified for durable resume", "are current and verified"),
    ),
)
def test_cli_success_message_distinguishes_fresh_and_durable_evidence(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    durable_resume: bool,
    expected_message: str,
    forbidden_message: str,
) -> None:
    verifier = _load_verifier()
    monkeypatch.setattr(verifier, "verify", lambda _arguments: None)
    argv = [
        "verify-upgrade-backup.py",
        "--evidence",
        "/evidence",
        "--signature",
        "/signature",
        "--public-key",
        "/public-key",
        "--expected-manifest-sha256",
        "b" * 64,
        "--expected-operation-scope",
        "legacy_adoption",
    ]
    if durable_resume:
        argv.append("--durable-resume")
    monkeypatch.setattr(sys, "argv", argv)

    assert verifier.main() == 0
    output = capsys.readouterr().out
    assert expected_message in output
    assert forbidden_message not in output
