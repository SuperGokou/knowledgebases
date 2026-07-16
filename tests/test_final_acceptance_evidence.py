from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.acceptance import build_profile, verify_signed_operational_evidence
from scripts.acceptance_gate import GateIdentity

RELEASE_ID = "2026.07.14-acceptance.1"
CONTROL_PLANE_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / "enterprise-restored-control-plane-integrity-v1.schema.json"
)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


def _artifact(root: Path, artifact_id: str, value: object) -> dict[str, object]:
    path = root / "artifacts" / f"{artifact_id}.json"
    _write_json(path, value)
    payload = path.read_bytes()
    return {
        "id": artifact_id,
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _write_signed_envelope(
    root: Path,
    *,
    identity: GateIdentity,
    kind: str,
    classification: str,
    artifacts: list[dict[str, object]],
    now: datetime,
    lifetime: timedelta,
) -> tuple[Path, Path, Path, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_path = root / "evidence-signing.pub"
    public_key_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    document = {
        "schema_version": 1,
        "kind": kind,
        "status": "complete",
        "evidence_classification": classification,
        "issued_at": _timestamp(now),
        "expires_at": _timestamp(now + lifetime),
        "target": {
            "git_head": identity.git_head,
            "content_fingerprint": identity.content_fingerprint,
            "release_id": RELEASE_ID,
        },
        "signing_key_sha256": hashlib.sha256(public_key_der).hexdigest(),
        "artifacts": artifacts,
    }
    evidence = root / f"{kind}.json"
    _write_json(evidence, document)
    signature = root / f"{kind}.sig"
    signature.write_bytes(private_key.sign(evidence.read_bytes()))
    return evidence, signature, public_key_path, private_key


def _capacity_bundle(
    root: Path,
    identity: GateIdentity,
    *,
    now: datetime,
) -> tuple[Path, Path, Path, Ed25519PrivateKey]:
    duration_seconds = 1_800
    required_tps = 5_000_000_000 / 86_400
    measured_tokens = int(required_tps * duration_seconds) + 10_000
    control_plane = {
        "schema_version": 1,
        "evidence_classification": "not_model_capacity",
        "verdict": "PASS_CONTROL_PLANE",
        "control_plane_passed": True,
        "evidence_binding": {"git_commit": identity.git_head},
        "checks": [{"name": "steady", "passed": True}],
        "capacity_claims": {
            "llm_stub_path": "MEASURED_STUB_ONLY",
            "five_billion_tokens_per_day": {"status": "UNVERIFIED_NO_GO"},
        },
    }
    benchmark = {
        "schema_version": 1,
        "kind": "enterprise-real-model-benchmark",
        "status": "passed",
        "classification": "measured_real_model_capacity",
        "collected_at": _timestamp(now),
        "traffic": {
            "mode": "real_model",
            "response_source": "private_inference_cluster",
            "provider_id": "private-inference-primary",
            "model_id": "enterprise-approved-model",
            "stub_used": False,
            "synthetic_responses": False,
            "identities": 1_000,
        },
        "measurements": {
            "steady_duration_seconds": duration_seconds,
            "measured_output_tokens": measured_tokens,
            "sustained_output_tokens_per_second": measured_tokens / duration_seconds,
            "projected_tokens_per_day": measured_tokens / duration_seconds * 86_400,
            "error_rate": 0.0001,
        },
        "quality": {
            "independent_review_passed": True,
            "output_content_logged": False,
        },
    }
    provider = {
        "schema_version": 1,
        "kind": "enterprise-provider-capacity",
        "status": "verified",
        "verified_at": _timestamp(now),
        "provider_type": "private_inference_cluster",
        "provider_id": "private-inference-primary",
        "model_id": "enterprise-approved-model",
        "quota_tokens_per_day": 5_000_000_000,
        "cost_model_verified": True,
        "data_residency_reviewed": True,
        "secret_material_included": False,
    }
    artifacts = [
        _artifact(root, "control_plane_report", control_plane),
        _artifact(root, "real_model_benchmark", benchmark),
        _artifact(root, "provider_quota", provider),
    ]
    return _write_signed_envelope(
        root,
        identity=identity,
        kind="enterprise-capacity",
        classification="combined_control_plane_and_real_model_capacity",
        artifacts=artifacts,
        now=now,
        lifetime=timedelta(hours=24),
    )


def _disaster_recovery_bundle(
    root: Path,
    identity: GateIdentity,
    *,
    now: datetime,
) -> tuple[Path, Path, Path, Ed25519PrivateKey]:
    started = now - timedelta(hours=1)
    completed = started + timedelta(minutes=30)
    source_commit = started - timedelta(minutes=5)
    restored_commit = source_commit - timedelta(seconds=60)
    restore_drill = {
        "schema_version": 1,
        "kind": "enterprise-full-restore-drill",
        "status": "passed",
        "started_at": _timestamp(started),
        "completed_at": _timestamp(completed),
        "source_latest_commit_at": _timestamp(source_commit),
        "restored_latest_commit_at": _timestamp(restored_commit),
        "rpo_seconds": 60,
        "rto_seconds": 1_800,
        "actual_restore": True,
        "simulation": False,
        "fresh_isolated_host": True,
        "source_backup_independent": True,
        "pitr_restored": True,
        "object_versioning_or_replication_verified": True,
    }
    database = {
        "schema_version": 1,
        "kind": "enterprise-restore-database-integrity",
        "status": "passed",
        "source_schema_head": "20260715_0021",
        "restored_schema_head": "20260715_0021",
        "source_table_count": 27,
        "restored_table_count": 27,
        "source_row_count": 10_000,
        "restored_row_count": 10_000,
        "checksums_match": True,
    }
    samples = [
        {
            "object_id_sha256": hashlib.sha256(f"object-id-{index}".encode()).hexdigest(),
            "source_sha256": hashlib.sha256(f"object-{index}".encode()).hexdigest(),
            "restored_sha256": hashlib.sha256(f"object-{index}".encode()).hexdigest(),
        }
        for index in range(1_000)
    ]
    objects = {
        "schema_version": 1,
        "kind": "enterprise-restore-object-integrity",
        "status": "passed",
        "source_object_count": 1_500,
        "restored_object_count": 1_500,
        "sampled_object_count": 1_000,
        "hash_match_count": 1_000,
        "hash_match_rate": 1.0,
        "manifest_sha256": hashlib.sha256(
            json.dumps(
                samples,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "samples": samples,
    }
    reconciliation_completed = completed - timedelta(minutes=10)
    hold_cleared = completed - timedelta(minutes=9)
    business_started = completed - timedelta(minutes=8)
    source_contract_sha256 = "3" * 64
    source_release_sha256 = "6" * 64
    source_release_manifest_sha256 = "4" * 64
    control_records = [
        {
            "id": "chat_safety_sentinel",
            "path": "data/chat-safety/poison.json",
            "source_state": "absent",
            "restored_state": "absent",
            "source_sha256": None,
            "restored_sha256": None,
        },
        {
            "id": "chat_safety_clear_pending",
            "path": "state/chat-safety-clear-pending.json",
            "source_state": "absent",
            "restored_state": "absent",
            "source_sha256": None,
            "restored_sha256": None,
        },
        {
            "id": "cutover_intent",
            "path": "state/cutover-intent.json",
            "source_state": "absent",
            "restored_state": "absent",
            "source_sha256": None,
            "restored_sha256": None,
        },
        {
            "id": "install_in_progress",
            "path": "state/install-in-progress.json",
            "source_state": "absent",
            "restored_state": "absent",
            "source_sha256": None,
            "restored_sha256": None,
        },
    ]
    for record_id, path in (
        ("active_release", "state/active-release.json"),
        (
            "source_installed_receipt",
            f"state/installed-{source_contract_sha256}.json",
        ),
        ("highest_release", "state/highest-release.json"),
        (
            "registry_import_receipt",
            f"state/registry-import-{source_release_manifest_sha256}.json",
        ),
        (
            "active_contract_manifest",
            f"contracts/{source_contract_sha256}/files.sha256",
        ),
        ("recovery_state_helper", "recovery/offline-recovery-state.py"),
        ("recovery_dispatcher", "recovery/offline-recovery-dispatcher.sh"),
    ):
        digest = (
            source_contract_sha256
            if record_id == "active_contract_manifest"
            else hashlib.sha256(record_id.encode()).hexdigest()
        )
        control_records.append(
            {
                "id": record_id,
                "path": path,
                "source_state": "present",
                "restored_state": "present",
                "source_sha256": digest,
                "restored_sha256": digest,
            }
        )
    control_manifest_sha256 = hashlib.sha256(
        json.dumps(
            control_records,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    control_plane = {
        "schema_version": 1,
        "kind": "enterprise-restored-control-plane-integrity",
        "status": "passed",
        "restore_started_in_maintenance_hold": True,
        "chat_safety_hold_materialized_before_runtime": True,
        "restore_hold_sentinel_sha256": hashlib.sha256(b"dr-hold").hexdigest(),
        "api_started_before_reconciliation": False,
        "edge_exposed_before_reconciliation": False,
        "missing_control_state_fail_closed": True,
        "recovery_selection": "active",
        "reconciliation_completed_at": _timestamp(reconciliation_completed),
        "hold_cleared_at": _timestamp(hold_cleared),
        "business_services_started_at": _timestamp(business_started),
        "source_contract_sha256": source_contract_sha256,
        "source_release_sha256": source_release_sha256,
        "source_release_manifest_sha256": source_release_manifest_sha256,
        "source_contract_bindings": {
            record_id: {
                "contract_sha256": source_contract_sha256,
                "release_sha256": source_release_sha256,
                "manifest_sha256": source_release_manifest_sha256,
            }
            for record_id in (
                "active_release",
                "source_installed_receipt",
                "active_contract_manifest",
                "registry_import_receipt",
            )
        },
        "source_manifest_sha256": control_manifest_sha256,
        "restored_manifest_sha256": control_manifest_sha256,
        "records": control_records,
    }
    smoke = {
        "schema_version": 1,
        "kind": "enterprise-restored-functional-smoke",
        "status": "passed",
        "login_passed": True,
        "search_passed": True,
        "download_passed": True,
        "citations_passed": True,
        "secret_material_included": False,
    }
    artifacts = [
        _artifact(root, "restore_drill_report", restore_drill),
        _artifact(root, "database_integrity", database),
        _artifact(root, "object_integrity", objects),
        _artifact(root, "control_plane_integrity", control_plane),
        _artifact(root, "functional_smoke", smoke),
    ]
    return _write_signed_envelope(
        root,
        identity=identity,
        kind="enterprise-disaster-recovery",
        classification="measured_full_restore_drill",
        artifacts=artifacts,
        now=now,
        lifetime=timedelta(days=30),
    )


def _rebind_and_resign(
    evidence: Path,
    signature: Path,
    private_key: Ed25519PrivateKey,
    *,
    artifact_id: str,
) -> None:
    document = json.loads(evidence.read_text(encoding="utf-8"))
    artifact = evidence.parent / "artifacts" / f"{artifact_id}.json"
    payload = artifact.read_bytes()
    descriptor = next(item for item in document["artifacts"] if item["id"] == artifact_id)
    descriptor["sha256"] = hashlib.sha256(payload).hexdigest()
    descriptor["bytes"] = len(payload)
    _write_json(evidence, document)
    signature.write_bytes(private_key.sign(evidence.read_bytes()))


def test_control_plane_integrity_schema_requires_exactly_eleven_records() -> None:
    schema = json.loads(CONTROL_PLANE_SCHEMA.read_text(encoding="utf-8"))
    assert {
        "source_contract_sha256",
        "source_release_sha256",
        "source_release_manifest_sha256",
        "source_contract_bindings",
    }.issubset(schema["required"])
    assert set(schema["$defs"]["sourceContractBindings"]["required"]) == {
        "active_release",
        "source_installed_receipt",
        "active_contract_manifest",
        "registry_import_receipt",
    }
    records = schema["properties"]["records"]
    assert records["minItems"] == 11
    assert records["maxItems"] == 11
    required_ids = {clause["contains"]["properties"]["id"]["const"] for clause in records["allOf"]}
    assert required_ids == {
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
    }
    control_record = schema["$defs"]["controlRecord"]
    installed_path_rule = next(
        rule
        for rule in control_record["allOf"]
        if rule.get("if", {}).get("properties", {}).get("id", {}).get("const")
        == "source_installed_receipt"
    )
    assert (
        installed_path_rule["then"]["properties"]["path"]["pattern"]
        == r"^state/installed-[0-9a-f]{64}\.json$"
    )
    mandatory_ids = next(
        rule["if"]["properties"]["id"]["enum"]
        for rule in control_record["allOf"]
        if "enum" in rule.get("if", {}).get("properties", {}).get("id", {})
    )
    assert "source_installed_receipt" in mandatory_ids


@pytest.fixture
def identity() -> GateIdentity:
    return GateIdentity("a" * 40, "b" * 64, "c" * 32)


def test_signed_capacity_evidence_requires_real_model_and_provider_capacity(
    tmp_path: Path,
    identity: GateIdentity,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, _private_key = _capacity_bundle(tmp_path, identity, now=now)

    accepted, summary = verify_signed_operational_evidence(
        "capacity",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is True
    assert "real-model" in summary


@pytest.mark.parametrize(
    ("artifact_id", "field_path", "invalid_value"),
    [
        ("real_model_benchmark", ("traffic", "stub_used"), True),
        ("real_model_benchmark", ("traffic", "synthetic_responses"), True),
        ("real_model_benchmark", ("measurements", "measured_output_tokens"), 1),
        ("provider_quota", ("quota_tokens_per_day",), 4_999_999_999),
        ("provider_quota", ("provider_type",), "approved_external_provider"),
        ("control_plane_report", ("evidence_binding", "git_commit"), "d" * 40),
    ],
)
def test_capacity_evidence_rejects_stub_or_unproven_throughput(
    tmp_path: Path,
    identity: GateIdentity,
    artifact_id: str,
    field_path: tuple[str, ...],
    invalid_value: object,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, private_key = _capacity_bundle(tmp_path, identity, now=now)
    artifact = tmp_path / "artifacts" / f"{artifact_id}.json"
    document: dict[str, Any] = json.loads(artifact.read_text(encoding="utf-8"))
    target: dict[str, Any] = document
    for field in field_path[:-1]:
        target = target[field]
    target[field_path[-1]] = invalid_value
    _write_json(artifact, document)
    _rebind_and_resign(
        evidence,
        signature,
        private_key,
        artifact_id=artifact_id,
    )

    accepted, _ = verify_signed_operational_evidence(
        "capacity",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is False


def test_signed_disaster_recovery_evidence_enforces_rpo_rto_and_integrity(
    tmp_path: Path,
    identity: GateIdentity,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, _private_key = _disaster_recovery_bundle(
        tmp_path, identity, now=now
    )

    accepted, summary = verify_signed_operational_evidence(
        "disaster-recovery",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is True
    assert "RPO/RTO" in summary


@pytest.mark.parametrize(
    ("artifact_id", "field", "invalid_value"),
    [
        ("restore_drill_report", "rpo_seconds", 901),
        ("restore_drill_report", "simulation", True),
        ("object_integrity", "sampled_object_count", 999),
        ("control_plane_integrity", "restore_started_in_maintenance_hold", False),
        ("functional_smoke", "search_passed", False),
    ],
)
def test_disaster_recovery_evidence_fails_closed_on_policy_gaps(
    tmp_path: Path,
    identity: GateIdentity,
    artifact_id: str,
    field: str,
    invalid_value: object,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, private_key = _disaster_recovery_bundle(
        tmp_path, identity, now=now
    )
    artifact = tmp_path / "artifacts" / f"{artifact_id}.json"
    document = json.loads(artifact.read_text(encoding="utf-8"))
    document[field] = invalid_value
    _write_json(artifact, document)
    _rebind_and_resign(
        evidence,
        signature,
        private_key,
        artifact_id=artifact_id,
    )

    accepted, _ = verify_signed_operational_evidence(
        "disaster-recovery",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is False


def test_disaster_recovery_evidence_rejects_missing_control_state_record(
    tmp_path: Path,
    identity: GateIdentity,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, private_key = _disaster_recovery_bundle(
        tmp_path, identity, now=now
    )
    artifact = tmp_path / "artifacts/control_plane_integrity.json"
    document = json.loads(artifact.read_text(encoding="utf-8"))
    document["records"] = [
        record for record in document["records"] if record["id"] != "chat_safety_clear_pending"
    ]
    _write_json(artifact, document)
    _rebind_and_resign(
        evidence,
        signature,
        private_key,
        artifact_id="control_plane_integrity",
    )

    accepted, _ = verify_signed_operational_evidence(
        "disaster-recovery",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is False


@pytest.mark.parametrize(
    "record_id",
    ("active_release", "source_installed_receipt"),
)
def test_disaster_recovery_evidence_rejects_absent_mandatory_control_state(
    tmp_path: Path,
    identity: GateIdentity,
    record_id: str,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, private_key = _disaster_recovery_bundle(
        tmp_path, identity, now=now
    )
    artifact = tmp_path / "artifacts/control_plane_integrity.json"
    document = json.loads(artifact.read_text(encoding="utf-8"))
    mandatory = next(record for record in document["records"] if record["id"] == record_id)
    mandatory["source_state"] = "absent"
    mandatory["restored_state"] = "absent"
    mandatory["source_sha256"] = None
    mandatory["restored_sha256"] = None
    _write_json(artifact, document)
    _rebind_and_resign(
        evidence,
        signature,
        private_key,
        artifact_id="control_plane_integrity",
    )

    accepted, _ = verify_signed_operational_evidence(
        "disaster-recovery",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is False


def test_disaster_recovery_evidence_rejects_non_contract_installed_receipt_path(
    tmp_path: Path,
    identity: GateIdentity,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, private_key = _disaster_recovery_bundle(
        tmp_path, identity, now=now
    )
    artifact = tmp_path / "artifacts/control_plane_integrity.json"
    document = json.loads(artifact.read_text(encoding="utf-8"))
    installed = next(
        record for record in document["records"] if record["id"] == "source_installed_receipt"
    )
    installed["path"] = "state/installed-current.json"
    _write_json(artifact, document)
    _rebind_and_resign(
        evidence,
        signature,
        private_key,
        artifact_id="control_plane_integrity",
    )

    accepted, _ = verify_signed_operational_evidence(
        "disaster-recovery",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is False


def test_disaster_recovery_evidence_rejects_a_different_well_formed_contract_path(
    tmp_path: Path,
    identity: GateIdentity,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, private_key = _disaster_recovery_bundle(
        tmp_path, identity, now=now
    )
    artifact = tmp_path / "artifacts/control_plane_integrity.json"
    document = json.loads(artifact.read_text(encoding="utf-8"))
    installed = next(
        record for record in document["records"] if record["id"] == "source_installed_receipt"
    )
    installed["path"] = f"state/installed-{'f' * 64}.json"
    _write_json(artifact, document)
    _rebind_and_resign(
        evidence,
        signature,
        private_key,
        artifact_id="control_plane_integrity",
    )

    accepted, _ = verify_signed_operational_evidence(
        "disaster-recovery",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is False


@pytest.mark.parametrize(
    ("binding_id", "field"),
    (
        ("active_release", "contract_sha256"),
        ("source_installed_receipt", "contract_sha256"),
        ("active_contract_manifest", "release_sha256"),
        ("registry_import_receipt", "manifest_sha256"),
    ),
)
def test_disaster_recovery_evidence_rejects_cross_contract_semantic_binding(
    tmp_path: Path,
    identity: GateIdentity,
    binding_id: str,
    field: str,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, private_key = _disaster_recovery_bundle(
        tmp_path, identity, now=now
    )
    artifact = tmp_path / "artifacts/control_plane_integrity.json"
    document = json.loads(artifact.read_text(encoding="utf-8"))
    document["source_contract_bindings"][binding_id][field] = "f" * 64
    _write_json(artifact, document)
    _rebind_and_resign(
        evidence,
        signature,
        private_key,
        artifact_id="control_plane_integrity",
    )

    accepted, _ = verify_signed_operational_evidence(
        "disaster-recovery",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is False


def test_disaster_recovery_evidence_rejects_contract_manifest_digest_not_equal_to_contract(
    tmp_path: Path,
    identity: GateIdentity,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, private_key = _disaster_recovery_bundle(
        tmp_path, identity, now=now
    )
    artifact = tmp_path / "artifacts/control_plane_integrity.json"
    document = json.loads(artifact.read_text(encoding="utf-8"))
    contract_record = next(
        record for record in document["records"] if record["id"] == "active_contract_manifest"
    )
    contract_record["source_sha256"] = "f" * 64
    contract_record["restored_sha256"] = "f" * 64
    _write_json(artifact, document)
    _rebind_and_resign(
        evidence,
        signature,
        private_key,
        artifact_id="control_plane_integrity",
    )

    accepted, _ = verify_signed_operational_evidence(
        "disaster-recovery",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is False


def test_disaster_recovery_evidence_rejects_restored_installed_receipt_digest_mismatch(
    tmp_path: Path,
    identity: GateIdentity,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, private_key = _disaster_recovery_bundle(
        tmp_path, identity, now=now
    )
    artifact = tmp_path / "artifacts/control_plane_integrity.json"
    document = json.loads(artifact.read_text(encoding="utf-8"))
    installed = next(
        record for record in document["records"] if record["id"] == "source_installed_receipt"
    )
    installed["restored_sha256"] = "f" * 64
    _write_json(artifact, document)
    _rebind_and_resign(
        evidence,
        signature,
        private_key,
        artifact_id="control_plane_integrity",
    )

    accepted, _ = verify_signed_operational_evidence(
        "disaster-recovery",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is False


def test_disaster_recovery_evidence_rejects_a_single_object_hash_mismatch(
    tmp_path: Path,
    identity: GateIdentity,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, private_key = _disaster_recovery_bundle(
        tmp_path, identity, now=now
    )
    artifact = tmp_path / "artifacts/object_integrity.json"
    document = json.loads(artifact.read_text(encoding="utf-8"))
    document["samples"][0]["restored_sha256"] = "f" * 64
    _write_json(artifact, document)
    _rebind_and_resign(
        evidence,
        signature,
        private_key,
        artifact_id="object_integrity",
    )

    accepted, _ = verify_signed_operational_evidence(
        "disaster-recovery",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is False


@pytest.mark.parametrize("failure", ["wrong-head", "wrong-release", "stale", "signature"])
def test_operational_evidence_is_signature_identity_and_freshness_bound(
    tmp_path: Path,
    identity: GateIdentity,
    failure: str,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, _private_key = _capacity_bundle(tmp_path, identity, now=now)
    verification_identity = identity
    release_id = RELEASE_ID
    verification_now = now
    if failure == "wrong-head":
        verification_identity = GateIdentity(
            "d" * 40, identity.content_fingerprint, identity.run_nonce
        )
    elif failure == "wrong-release":
        release_id = "another-release"
    elif failure == "stale":
        verification_now = now + timedelta(hours=25)
    else:
        signature.write_bytes(b"x" * 64)

    accepted, _ = verify_signed_operational_evidence(
        "capacity",
        evidence,
        signature,
        public_key,
        identity=verification_identity,
        release_id=release_id,
        require_protected_files=False,
        now=verification_now,
    )

    assert accepted is False


def test_operational_evidence_rejects_artifact_replacement_without_rebinding(
    tmp_path: Path,
    identity: GateIdentity,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, _private_key = _capacity_bundle(tmp_path, identity, now=now)
    benchmark = tmp_path / "artifacts/real_model_benchmark.json"
    benchmark.write_bytes(benchmark.read_bytes() + b" ")

    accepted, _ = verify_signed_operational_evidence(
        "capacity",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is False


@pytest.mark.parametrize("mutation", ["extra-field", "duplicate-key"])
def test_operational_evidence_rejects_noncanonical_schema_even_when_resigned(
    tmp_path: Path,
    identity: GateIdentity,
    mutation: str,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    evidence, signature, public_key, private_key = _capacity_bundle(tmp_path, identity, now=now)
    if mutation == "extra-field":
        document = json.loads(evidence.read_text(encoding="utf-8"))
        document["unexpected"] = True
        _write_json(evidence, document)
    else:
        payload = evidence.read_text(encoding="utf-8")
        evidence.write_text(
            payload.replace('"status":"complete"', '"status":"complete","status":"complete"'),
            encoding="utf-8",
        )
    signature.write_bytes(private_key.sign(evidence.read_bytes()))

    accepted, _ = verify_signed_operational_evidence(
        "capacity",
        evidence,
        signature,
        public_key,
        identity=identity,
        release_id=RELEASE_ID,
        require_protected_files=False,
        now=now,
    )

    assert accepted is False


def test_final_profile_wires_explicit_capacity_and_dr_evidence(identity: GateIdentity) -> None:
    gates = build_profile(
        "final",
        acceptance_identity=identity,
        release_id=identity.git_head,
        capacity_evidence_path="/evidence/capacity.json",
        capacity_evidence_signature_path="/evidence/capacity.sig",
        capacity_evidence_public_key_path="/secure/operational.pub",
        disaster_recovery_evidence_path="/evidence/disaster-recovery.json",
        disaster_recovery_evidence_signature_path="/evidence/disaster-recovery.sig",
        disaster_recovery_evidence_public_key_path="/secure/operational.pub",
    )
    by_id = {gate.gate_id: gate for gate in gates}

    for gate_id, kind in (
        ("CAPACITY-P0-001", "capacity"),
        ("DR-P0-001", "disaster-recovery"),
    ):
        gate = by_id[gate_id]
        assert gate.blocked_reason is None
        assert gate.command
        assert gate.command[gate.command.index("--verify-operational-evidence") + 1] == kind
        assert gate.command[gate.command.index("--release-id") + 1] == identity.git_head
        assert gate.blocked_exit_codes == (2,)
        assert len(gate.required_regular_files) == 3


def test_final_profile_keeps_missing_operational_evidence_as_no_go(
    identity: GateIdentity,
) -> None:
    by_id = {
        gate.gate_id: gate
        for gate in build_profile(
            "final",
            acceptance_identity=identity,
            release_id=identity.git_head,
        )
    }

    for gate_id in ("CAPACITY-P0-001", "DR-P0-001"):
        gate = by_id[gate_id]
        assert gate.blocked_reason is not None
        assert gate.command
        assert gate.required_regular_files == ()
