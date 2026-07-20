from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.acceptance import (
    AcceptanceGate,
    AcceptanceResult,
    CommandOutcome,
    _browser_e2e_exit_code,
    _verify_browser_e2e_document,
    build_profile,
    calculate_verdict,
    collect_worktree_evidence,
    execute_command,
    redact_output,
    resolve_command,
    run_gate,
    verify_browser_e2e_evidence,
    verify_formal_evidence,
    verify_offline_runtime_evidence,
    write_reports,
)
from scripts.functional_acceptance import ExternalTrustContext, _signature_payload


def result(gate_id: str, severity: str, status: str) -> AcceptanceResult:
    return AcceptanceResult(
        gate_id=gate_id,
        severity=severity,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        duration_seconds=0.1,
        summary="test result",
    )


def test_failed_or_blocked_p0_forces_fail() -> None:
    assert calculate_verdict([result("AUTH-P0-001", "P0", "failed")]) == "FAIL"
    assert calculate_verdict([result("AUTH-P0-001", "P0", "blocked")]) == "FAIL"


def test_unverified_p1_is_conditional_but_p2_does_not_block() -> None:
    assert (
        calculate_verdict(
            [
                result("AUTH-P0-001", "P0", "passed"),
                result("OPS-P1-001", "P1", "blocked"),
            ]
        )
        == "CONDITIONAL"
    )
    assert (
        calculate_verdict(
            [
                result("AUTH-P0-001", "P0", "passed"),
                result("UX-P2-001", "P2", "failed"),
            ]
        )
        == "PASS"
    )


def test_redaction_removes_credentials_tokens_and_presigned_queries() -> None:
    raw = "\n".join(
        [
            "Authorization: Bearer secret-token-value",
            "postgresql://admin:db-password@db.internal/knowledge",
            "KB_JWT_SECRET=super-secret-value",
            "https://objects.internal/file?X-Amz-Credential=user&X-Amz-Signature=abc123",
        ]
    )

    redacted = redact_output(raw)

    for secret in ("secret-token-value", "db-password", "super-secret-value", "abc123"):
        assert secret not in redacted
    assert "[REDACTED]" in redacted
    assert "https://objects.internal/file?[REDACTED]" in redacted


def test_nonzero_exit_is_failed_and_summary_is_bounded() -> None:
    gate = AcceptanceGate(
        gate_id="CODE-P0-001",
        severity="P0",
        command=("tool", "check"),
        cwd=".",
        timeout_seconds=30,
    )

    def executor(_gate: AcceptanceGate) -> CommandOutcome:
        return CommandOutcome(returncode=2, stdout="x" * 20_000, stderr="failed")

    outcome = run_gate(gate, executor=executor)

    assert outcome.status == "failed"
    assert len(outcome.summary) <= 4_096


def test_declared_preflight_exit_code_is_reported_as_blocked() -> None:
    gate = AcceptanceGate(
        gate_id="HOST-P0-001",
        severity="P0",
        command=("python", "host_preflight.py"),
        cwd=".",
        timeout_seconds=30,
        blocked_exit_codes=(2,),
    )

    outcome = run_gate(
        gate,
        executor=lambda _gate: CommandOutcome(
            returncode=2,
            stdout='{"status":"blocked"}',
            stderr="",
        ),
    )

    assert outcome.status == "blocked"
    assert '"status":"blocked"' in outcome.summary


def test_target_gate_rejects_missing_or_symlinked_required_evidence(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    gate = AcceptanceGate(
        gate_id="HOST-P0-001",
        severity="P0",
        command=("tool",),
        cwd=".",
        timeout_seconds=30,
        required_regular_files=(str(missing),),
    )
    called = False

    def executor(_gate: AcceptanceGate) -> CommandOutcome:
        nonlocal called
        called = True
        return CommandOutcome(returncode=0, stdout="ok", stderr="")

    assert run_gate(gate, executor=executor).status == "blocked"
    assert called is False

    actual = tmp_path / "actual.json"
    actual.write_text("{}", encoding="utf-8")
    linked = tmp_path / "linked.json"
    try:
        linked.symlink_to(actual)
    except OSError:
        pytest.skip("creating symlinks is unavailable on this test host")
    linked_gate = replace(gate, required_regular_files=(str(linked),))
    assert run_gate(linked_gate, executor=executor).status == "blocked"
    assert called is False


def test_e2e_block_marker_is_blocked_but_real_failure_is_failed() -> None:
    gate = AcceptanceGate(
        gate_id="E2E-P0-001",
        severity="P0",
        command=("npm", "run", "test:e2e"),
        cwd="web",
        timeout_seconds=30,
        blocked_output_markers=("E2E_BLOCKED",),
    )

    blocked = run_gate(
        gate,
        executor=lambda _gate: CommandOutcome(
            returncode=1,
            stdout="E2E_BLOCKED: enterprise topology is incomplete",
            stderr="",
        ),
    )
    failed = run_gate(
        gate,
        executor=lambda _gate: CommandOutcome(
            returncode=1,
            stdout="assertion failed",
            stderr="",
        ),
    )

    assert blocked.status == "blocked"
    assert failed.status == "failed"


def test_successful_browser_process_cannot_pass_without_verified_evidence() -> None:
    successful_process = CommandOutcome(returncode=0, stdout="18 passed", stderr="")

    assert _browser_e2e_exit_code(successful_process, evidence_verified=False) == 2
    assert _browser_e2e_exit_code(successful_process, evidence_verified=True) == 0
    assert (
        _browser_e2e_exit_code(
            CommandOutcome(returncode=1, stdout="assertion failed", stderr=""),
            evidence_verified=True,
        )
        == 1
    )


def test_sha_only_browser_evidence_is_never_accepted(tmp_path: Path) -> None:
    evidence = tmp_path / "browser-e2e.json"
    evidence.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "evidence_id": "EXT-BROWSER-E2E-001",
                "status": "complete",
                "attestation": {"type": "sha256-chain-v1", "digest": "a" * 64},
            }
        ),
        encoding="utf-8",
    )

    accepted, _summary = verify_browser_e2e_evidence(
        evidence,
        tmp_path / "trust.json",
        tmp_path / "challenges",
        tmp_path,
        expected_key_id="browser-e2e-ed25519",
    )

    assert accepted is False


def test_signed_browser_evidence_passes_once_and_replay_blocks(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[1]
    evidence = tmp_path / "browser-e2e.json"
    raw = tmp_path / "raw/browser-result.json"
    raw.parent.mkdir()
    raw_content = b'{"browser":"passed"}\n'
    raw.write_bytes(raw_content)
    identity = collect_worktree_evidence(repository)
    checks = {
        check: {"status": "passed", "artifact_ids": ["browser-result"]}
        for check in (
            "login_role_routing",
            "account_lifecycle",
            "knowledge_acl",
            "file_upload_scan_okf_approval_download",
            "chat_citations_audit_table",
            "model_switch",
            "api_key_lifecycle",
            "error_loading_states",
        )
    }
    document: dict[str, object] = {
        "schema_version": 2,
        "evidence_id": "EXT-BROWSER-E2E-001",
        "status": "complete",
        "collector": {"id": "heyi-browser-e2e", "version": "1.0.0"},
        "target": {
            "git_head": identity.git_head,
            "content_fingerprint": identity.content_fingerprint,
        },
        "collected_at": datetime.now(UTC).isoformat(),
        "artifacts": [
            {
                "id": "browser-result",
                "path": "raw/browser-result.json",
                "sha256": hashlib.sha256(raw_content).hexdigest(),
                "bytes": len(raw_content),
            }
        ],
        "checks": checks,
    }
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = "browser-e2e-ed25519"
    challenge_id = "challenge-browser-final-001"
    nonce = base64.b64encode(b"unpredictable-browser-challenge-001").decode()
    document["attestation"] = {
        "type": "ed25519-challenge-v1",
        "key_id": key_id,
        "challenge_id": challenge_id,
        "challenge_nonce": nonce,
        "signature": base64.b64encode(
            private_key.sign(
                _signature_payload(
                    document,
                    key_id=key_id,
                    challenge_id=challenge_id,
                    challenge_nonce=nonce,
                )
            )
        ).decode(),
    }
    evidence.write_text(json.dumps(document), encoding="utf-8")
    context = ExternalTrustContext(
        public_keys={("heyi-browser-e2e", key_id): public_key},
        challenges={
            challenge_id: {
                "status": "issued",
                "evidence_id": "EXT-BROWSER-E2E-001",
                "nonce": nonce,
                "issued_at": datetime.now(UTC).isoformat(),
                "expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
            }
        },
        consumed_challenges=set(),
    )

    accepted = _verify_browser_e2e_document(
        evidence,
        repository,
        expected_key_id=key_id,
        trust_context=context,
    )
    replayed = _verify_browser_e2e_document(
        evidence,
        repository,
        expected_key_id=key_id,
        trust_context=context,
    )

    assert accepted is True
    assert replayed is False


def test_long_command_summary_preserves_the_trailing_verdict() -> None:
    gate = AcceptanceGate("BACKEND-P0-001", "P0", ("pytest",), ".", 30)

    def executor(_gate: AcceptanceGate) -> CommandOutcome:
        return CommandOutcome(
            returncode=0,
            stdout=("test output\n" * 1_000) + "TOTAL 84.40%\n146 passed",
            stderr="",
        )

    outcome = run_gate(gate, executor=executor)

    assert len(outcome.summary) <= 4_096
    assert "TOTAL 84.40%" in outcome.summary
    assert outcome.summary.endswith("146 passed")


def test_timeout_is_failed_without_leaking_command_output() -> None:
    gate = AcceptanceGate(
        gate_id="BUILD-P0-001",
        severity="P0",
        command=("build-tool",),
        cwd="web",
        timeout_seconds=1,
    )

    def executor(_gate: AcceptanceGate) -> CommandOutcome:
        raise subprocess.TimeoutExpired(cmd=["build-tool"], timeout=1, output="secret")

    outcome = run_gate(gate, executor=executor)

    assert outcome.status == "failed"
    assert outcome.summary == "command timed out after 1 seconds"


def test_missing_executable_is_a_controlled_gate_failure() -> None:
    gate = AcceptanceGate(
        gate_id="TOOL-P0-001",
        severity="P0",
        command=("missing-tool",),
        cwd=".",
        timeout_seconds=1,
    )

    def executor(_gate: AcceptanceGate) -> CommandOutcome:
        raise FileNotFoundError("sensitive local path")

    outcome = run_gate(gate, executor=executor)

    assert outcome.status == "failed"
    assert outcome.summary == "command executable was not found"


def test_platform_command_shim_is_resolved_before_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _value: "C:/tools/npm.CMD")

    assert resolve_command(("npm", "test")) == ("C:/tools/npm.CMD", "test")


def test_command_capture_uses_explicit_fault_tolerant_utf8(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(args=["tool"], returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    gate = AcceptanceGate("CODE-P0-001", "P0", ("tool",), ".", 10)

    assert execute_command(gate).returncode == 0
    assert captured["encoding"] == "utf-8"
    assert captured["errors"] == "replace"


def test_local_profile_contains_required_deterministic_gates() -> None:
    ids = {gate.gate_id for gate in build_profile("local")}

    assert {
        "CODE-P0-001",
        "BACKEND-P0-001",
        "FRONTEND-P0-001",
        "BUILD-P0-001",
        "OFFLINE-P0-001",
        "SERVER-P1-001",
    } <= ids


def test_final_profile_adds_executable_target_evidence_gates() -> None:
    gates = build_profile(
        "final",
        host_disk_path="/data/knowledge",
        host_io_evidence_path="/evidence/host-io.json",
        storage_chain_evidence_path="/evidence/watermark-chain.json",
        offline_env_file="/etc/heyi/offline.env",
        offline_image_manifest_path="/evidence/offline-images.txt",
        offline_runtime_evidence_path="/evidence/offline-runtime-evidence.json",
        e2e_evidence_path="/evidence/browser-e2e.json",
        functional_trust_store_path="/secure/functional-trust.json",
        functional_challenge_store_path="/secure/challenges",
        e2e_signing_key_path="/secure/browser-e2e.key",
        e2e_signing_key_id="browser-e2e-ed25519",
        malware_evidence_path="/evidence/malware.json",
        security_scan_evidence_path="/evidence/security.json",
    )
    by_id = {gate.gate_id: gate for gate in gates}

    format_gate = by_id["FORMAT-P0-001"]
    assert format_gate.severity == "P0"
    assert format_gate.blocked_reason is None
    assert format_gate.blocked_exit_codes == (2,)
    assert format_gate.command[-3:] == (
        "-m",
        "app.document_parser_preflight",
        "--require-all",
    )

    backend_gate = by_id["BACKEND-P0-001"]
    assert backend_gate.blocked_exit_codes == (2,)
    assert Path(backend_gate.command[1]).name == "backend_acceptance.py"
    assert backend_gate.command[-2:] == (
        "--postgres-evidence",
        "artifacts/acceptance/evidence/postgres.json",
    )
    ordered_ids = [gate.gate_id for gate in gates]
    assert ordered_ids.index("TOKEN-GOV-P0-001") < ordered_ids.index("BACKEND-P0-001")
    e2e_gate = by_id["E2E-P0-001"]
    assert Path(e2e_gate.command[1]).name == "acceptance.py"
    assert "--run-browser-e2e" in e2e_gate.command
    assert e2e_gate.command[-8:] == (
        "--functional-trust-store",
        "/secure/functional-trust.json",
        "--functional-challenge-store",
        "/secure/challenges",
        "--e2e-signing-key-path",
        "/secure/browser-e2e.key",
        "--e2e-signing-key-id",
        "browser-e2e-ed25519",
    )
    assert e2e_gate.environment == ()
    assert e2e_gate.blocked_exit_codes == (2,)
    assert e2e_gate.required_regular_files == (
        "/secure/functional-trust.json",
        "/secure/browser-e2e.key",
    )
    host_gate = by_id["HOST-P0-001"]
    assert host_gate.severity == "P0"
    assert host_gate.blocked_reason is None
    assert host_gate.blocked_exit_codes == (2,)
    assert host_gate.command[-4:] == (
        "--disk-path",
        "/data/knowledge",
        "--io-evidence",
        "/evidence/host-io.json",
    )
    assert host_gate.command[1:3] == ("-m", "scripts.host_preflight")
    assert host_gate.required_regular_files == ("/evidence/host-io.json",)
    storage_gate = by_id["STORAGE-WATERMARK-P0-001"]
    assert storage_gate.severity == "P0"
    assert storage_gate.blocked_reason is None
    assert storage_gate.blocked_exit_codes == (2,)
    assert storage_gate.command[1:3] == ("-m", "scripts.storage_watermark_preflight")
    assert "--object-root" in storage_gate.command
    assert storage_gate.command[-2:] == (
        "--chain-evidence",
        "/evidence/watermark-chain.json",
    )
    assert storage_gate.required_regular_files == ("/evidence/watermark-chain.json",)
    token_gate = by_id["TOKEN-GOV-P0-001"]
    assert token_gate.severity == "P0"
    assert token_gate.blocked_reason is None
    assert token_gate.blocked_exit_codes == (2,)
    assert Path(token_gate.command[1]).name == "postgres_acceptance.py"
    assert token_gate.command[-2:] == (
        "--image",
        "postgres:17.5-bookworm",
    )
    blockers = {
        "CAPACITY-P0-001": "5 billion tokens per day",
        "DR-P0-001": "disaster-recovery restore drill",
    }
    for gate_id, evidence_phrase in blockers.items():
        gate = by_id[gate_id]
        assert gate.severity == "P0"
        assert gate.command == ()
        assert gate.blocked_reason is not None
        assert evidence_phrase in gate.blocked_reason

    malware_gate = by_id["MALWARE-P0-001"]
    assert malware_gate.blocked_reason is None
    assert malware_gate.blocked_exit_codes == (2,)
    assert malware_gate.command[-4:] == (
        "--verify-evidence",
        "malware",
        "--evidence-file",
        "/evidence/malware.json",
    )

    security_gate = by_id["SECURITY-SCAN-P0-001"]
    assert security_gate.blocked_reason is None
    assert security_gate.blocked_exit_codes == (2,)
    assert security_gate.command[-4:] == (
        "--verify-evidence",
        "security-scan",
        "--evidence-file",
        "/evidence/security.json",
    )

    worktree_gate = by_id["WORKTREE-P0-001"]
    assert worktree_gate.blocked_reason is None
    assert worktree_gate.blocked_exit_codes == (2,)
    assert worktree_gate.command[-1] == "--verify-clean-worktree"

    offline_gate = by_id["OFFLINE-P0-001"]
    assert Path(offline_gate.command[1]).name == "preflight-offline.sh"
    assert offline_gate.command[2:] == ("/etc/heyi/offline.env",)
    assert {66, 77} <= set(offline_gate.blocked_exit_codes)
    assert offline_gate.required_regular_files == ("/etc/heyi/offline.env",)
    image_gate = by_id["OFFLINE-IMAGES-P0-001"]
    assert Path(image_gate.command[1]).name == "verify-offline-images.sh"
    assert image_gate.command[2:] == (
        "verify",
        "/etc/heyi/offline.env",
        "/evidence/offline-images.txt",
    )
    assert image_gate.required_regular_files == (
        "/etc/heyi/offline.env",
        "/evidence/offline-images.txt",
    )
    runtime_gate = by_id["OFFLINE-RUNTIME-P0-001"]
    assert runtime_gate.command[-3:] == (
        "--verify-offline-runtime-evidence",
        "--evidence-file",
        "/evidence/offline-runtime-evidence.json",
    )
    assert runtime_gate.blocked_exit_codes == (2,)
    assert runtime_gate.required_regular_files == (
        "/evidence/offline-runtime-evidence.json",
    )
    assert "STORAGE-P0-001" not in by_id


def _init_git_repository(path: Path) -> None:
    path.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "acceptance@example.invalid"], cwd=path, check=True
    )
    subprocess.run(["git", "config", "user.name", "Acceptance Test"], cwd=path, check=True)
    (path / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=path, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "baseline"], cwd=path, check=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_malware_evidence_requires_all_target_linux_chain_artifacts(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _init_git_repository(repository)
    identity = collect_worktree_evidence(repository)
    evidence_dir = tmp_path / "malware-evidence"
    evidence_dir.mkdir()
    checks: dict[str, dict[str, str]] = {}
    for name in (
        "clamav_database_preflight",
        "eicar_quarantined",
        "clean_file_released",
        "minio_scan_approval_download",
    ):
        artifact = evidence_dir / f"{name}.json"
        artifact.write_text('{"status":"passed"}\n', encoding="utf-8")
        checks[name] = {
            "status": "passed",
            "artifact": artifact.name,
            "sha256": _sha256(artifact),
        }
    evidence = evidence_dir / "malware.json"
    evidence.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "malware",
                "status": "complete",
                "target": {
                    "os": "linux",
                    "git_head": identity.git_head,
                    "content_fingerprint": identity.content_fingerprint,
                },
                "checks": checks,
            }
        ),
        encoding="utf-8",
    )

    accepted, summary = verify_formal_evidence("malware", evidence, repository)

    assert accepted is True
    assert summary == "malware target-host evidence verified (4/4 checks)"

    checks["eicar_quarantined"]["status"] = "blocked"
    evidence.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "malware",
                "status": "complete",
                "target": {
                    "os": "linux",
                    "git_head": identity.git_head,
                    "content_fingerprint": identity.content_fingerprint,
                },
                "checks": checks,
            }
        ),
        encoding="utf-8",
    )
    accepted, summary = verify_formal_evidence("malware", evidence, repository)
    assert accepted is False
    assert summary == "malware evidence is incomplete or does not match this worktree"


def test_security_scan_evidence_requires_complete_matching_report(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _init_git_repository(repository)
    identity = collect_worktree_evidence(repository)
    evidence_dir = tmp_path / "security-evidence"
    evidence_dir.mkdir()
    report = evidence_dir / "security-report.json"
    report.write_text('{"status":"complete"}\n', encoding="utf-8")
    evidence = evidence_dir / "security.json"
    document = {
        "schema_version": 1,
        "kind": "security-scan",
        "status": "complete",
        "policy_status": "passed",
        "target": {
            "git_head": identity.git_head,
            "content_fingerprint": identity.content_fingerprint,
        },
        "report": {"artifact": report.name, "sha256": _sha256(report)},
        "summary": {"open_critical": 0, "open_high": 0, "open_medium": 2, "open_low": 1},
    }
    evidence.write_text(json.dumps(document), encoding="utf-8")

    accepted, summary = verify_formal_evidence("security-scan", evidence, repository)

    assert accepted is True
    assert summary == "complete security scan report verified for this worktree"

    document["target"]["content_fingerprint"] = "0" * 64
    evidence.write_text(json.dumps(document), encoding="utf-8")
    accepted, summary = verify_formal_evidence("security-scan", evidence, repository)
    assert accepted is False
    assert summary == "security scan evidence is incomplete or does not match this worktree"


def test_formal_evidence_rejects_symlinked_artifact(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _init_git_repository(repository)
    identity = collect_worktree_evidence(repository)
    evidence_dir = tmp_path / "security-evidence"
    evidence_dir.mkdir()
    actual_report = evidence_dir / "actual-report.json"
    actual_report.write_text('{"status":"complete"}\n', encoding="utf-8")
    linked_report = evidence_dir / "linked-report.json"
    try:
        linked_report.symlink_to(actual_report)
    except OSError:
        pytest.skip("creating symlinks is unavailable on this test host")
    evidence = evidence_dir / "security.json"
    evidence.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "security-scan",
                "status": "complete",
                "policy_status": "passed",
                "target": {
                    "git_head": identity.git_head,
                    "content_fingerprint": identity.content_fingerprint,
                },
                "report": {"artifact": linked_report.name, "sha256": _sha256(actual_report)},
                "summary": {
                    "open_critical": 0,
                    "open_high": 0,
                    "open_medium": 0,
                    "open_low": 0,
                },
            }
        ),
        encoding="utf-8",
    )

    accepted, _summary = verify_formal_evidence("security-scan", evidence, repository)

    assert accepted is False


def _offline_runtime_document(
    repository: Path,
    evidence_dir: Path,
    *,
    result: str = "passed",
    runner: str = "subprocess-v1",
) -> dict[str, object]:
    identity = collect_worktree_evidence(repository)
    raw_dir = evidence_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    artifact = raw_dir / "000-runtime.json"
    artifact.write_text('{"status":"passed"}\n', encoding="utf-8")
    descriptor = {
        "id": "runtime",
        "path": "raw/000-runtime.json",
        "sha256": _sha256(artifact),
        "bytes": artifact.stat().st_size,
    }
    checks = {
        check: {"status": "passed", "artifact_ids": ["runtime"]}
        for check in (
            "offline_network_isolation",
            "cold_start",
            "login",
            "rbac",
            "acl",
            "upload",
            "approval",
            "download",
            "question_answer",
            "restart_persistence",
            "network_recovery",
        )
    }
    document: dict[str, object] = {
        "schema_version": 1,
        "evidence_id": "EXT-OFFLINE-RUNTIME-001",
        "status": "complete",
        "result": result,
        "runner": runner,
        "collector": {"id": "heyi-offline-runtime", "version": "1.0.0"},
        "collected_at": datetime.now(UTC).isoformat(),
        "challenge": "A" * 24,
        "test_tenant": "kb-acceptance-final",
        "target": {
            "git_head": identity.git_head,
            "content_fingerprint": identity.content_fingerprint,
            "host_fingerprint": "a" * 64,
            "project_name": "heyi-kb-offline",
        },
        "checks": checks,
        "artifacts": [descriptor],
    }
    canonical = lambda value: hashlib.sha256(  # noqa: E731
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    document["result_sha256"] = canonical(
        {"target": document["target"], "checks": checks, "artifacts": [descriptor]}
    )
    document["attestation"] = {"type": "sha256-chain-v1", "digest": canonical(document)}
    return document


def _test_protected_regular_file(path: Path, *, maximum_bytes: int) -> bool:
    """Model the regular-file boundary without requiring root-owned CI fixtures."""

    return (
        path.is_file()
        and not path.is_symlink()
        and 0 < path.stat().st_size <= maximum_bytes
    )


def test_offline_runtime_evidence_requires_real_target_bound_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    _init_git_repository(repository)
    evidence_dir = tmp_path / "offline-runtime"
    evidence_dir.mkdir()
    evidence = evidence_dir / "offline-runtime-evidence.json"
    document = _offline_runtime_document(repository, evidence_dir)
    evidence.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr("scripts.acceptance.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        "scripts.acceptance._offline_runtime_host_fingerprint", lambda: "a" * 64
    )
    monkeypatch.setattr(
        "scripts.acceptance._protected_regular_file", _test_protected_regular_file
    )

    accepted, summary = verify_offline_runtime_evidence(evidence, repository)

    assert accepted is True
    assert summary == "offline runtime target evidence verified"

    document["runner"] = "test-double"
    evidence.write_text(json.dumps(document), encoding="utf-8")
    accepted, _summary = verify_offline_runtime_evidence(evidence, repository)
    assert accepted is False

    document = _offline_runtime_document(repository, evidence_dir)
    document["result"] = "blocked"
    evidence.write_text(json.dumps(document), encoding="utf-8")
    assert verify_offline_runtime_evidence(evidence, repository)[0] is False

    document = _offline_runtime_document(repository, evidence_dir)
    target = document["target"]
    assert isinstance(target, dict)
    target["content_fingerprint"] = "0" * 64
    evidence.write_text(json.dumps(document), encoding="utf-8")
    assert verify_offline_runtime_evidence(evidence, repository)[0] is False


def test_offline_runtime_evidence_blocks_windows_and_tampered_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    _init_git_repository(repository)
    evidence_dir = tmp_path / "offline-runtime"
    evidence_dir.mkdir()
    evidence = evidence_dir / "offline-runtime-evidence.json"
    document = _offline_runtime_document(repository, evidence_dir)
    evidence.write_text(json.dumps(document), encoding="utf-8")

    monkeypatch.setattr("scripts.acceptance.platform.system", lambda: "Windows")
    assert verify_offline_runtime_evidence(evidence, repository)[0] is False

    monkeypatch.setattr("scripts.acceptance.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        "scripts.acceptance._offline_runtime_host_fingerprint", lambda: "a" * 64
    )
    monkeypatch.setattr(
        "scripts.acceptance._protected_regular_file", _test_protected_regular_file
    )
    (evidence_dir / "raw/000-runtime.json").write_text("tampered\n", encoding="utf-8")
    assert verify_offline_runtime_evidence(evidence, repository)[0] is False


def test_final_profile_is_guaranteed_to_fail_while_local_and_ci_semantics_are_unchanged() -> None:
    local_ids = {gate.gate_id for gate in build_profile("local")}
    ci_ids = {gate.gate_id for gate in build_profile("ci")}
    final_gates = build_profile("final")
    final_results = [
        run_gate(
            gate,
            executor=lambda _gate: CommandOutcome(returncode=0, stdout="ok", stderr=""),
        )
        for gate in final_gates
    ]

    assert "E2E-P0-001" not in local_ids | ci_ids
    assert "FORMAT-P0-001" not in local_ids
    assert "FORMAT-P0-001" in ci_ids
    assert "CAPACITY-P0-001" not in local_ids | ci_ids
    assert "SERVER-P1-001" in local_ids
    assert "SERVER-P1-001" not in ci_ids
    assert "SERVER-P1-001" not in {gate.gate_id for gate in final_gates}
    assert "HOST-P0-001" in {gate.gate_id for gate in final_gates}
    assert calculate_verdict(final_results) == "FAIL"


def test_final_profile_without_explicit_target_evidence_is_blocked_before_execution() -> None:
    by_id = {gate.gate_id: gate for gate in build_profile("final")}

    for gate_id in (
        "HOST-P0-001",
        "STORAGE-WATERMARK-P0-001",
        "OFFLINE-P0-001",
        "OFFLINE-IMAGES-P0-001",
        "OFFLINE-RUNTIME-P0-001",
        "E2E-P0-001",
    ):
        gate = by_id[gate_id]
        assert gate.blocked_reason is not None
        assert run_gate(gate).status == "blocked"


def test_executor_signature_is_injectable() -> None:
    gate = AcceptanceGate(
        gate_id="CODE-P0-001",
        severity="P0",
        command=("tool",),
        cwd=".",
        timeout_seconds=30,
    )
    calls: list[str] = []

    def executor(item: AcceptanceGate) -> CommandOutcome:
        calls.append(item.gate_id)
        return CommandOutcome(returncode=0, stdout="ok", stderr="")

    assert run_gate(gate, executor=executor).status == "passed"
    assert calls == ["CODE-P0-001"]


def test_reports_are_redacted_and_preserve_blocked_status(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _init_git_repository(repository)
    results = [
        AcceptanceResult(
            gate_id="AUTH-P0-001",
            severity="P0",
            status="passed",
            duration_seconds=0.25,
            summary="Authorization: Bearer secret-token-value",
        ),
        AcceptanceResult(
            gate_id="SERVER-P1-001",
            severity="P1",
            status="blocked",
            duration_seconds=0.0,
            summary="real server unavailable",
        ),
    ]

    json_path, markdown_path = write_reports(
        results,
        report_dir=tmp_path,
        profile="local",
        revision="abc123",
        repository=repository,
    )

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")
    assert payload["verdict"] == "CONDITIONAL"
    assert payload["revision"] == payload["worktree"]["git_head"]
    assert payload["results"][1]["status"] == "blocked"
    assert payload["evidence_class"] == "development_smoke_not_for_signoff"
    assert len(payload["worktree"]["content_fingerprint"]) == 64
    assert payload["worktree"]["dirty"] is False
    assert payload["worktree"]["status_counts"]["total"] == 0
    assert len(payload["worktree"]["tracked_diff_sha256"]) == 64
    assert len(payload["worktree"]["untracked_manifest_sha256"]) == 64
    assert "secret-token-value" not in json_path.read_text(encoding="utf-8")
    assert "secret-token-value" not in markdown
    assert "SERVER-P1-001" in markdown
    assert "blocked" in markdown
    assert "NON-SIGNING DEVELOPMENT SMOKE" in markdown


def test_dirty_final_report_cannot_claim_pass_and_does_not_expose_paths(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _init_git_repository(repository)
    (repository / "tracked.txt").write_text("changed\n", encoding="utf-8")
    secret_named_file = repository / "PRIVATE_TOKEN_do_not_report.txt"
    secret_named_file.write_text("not-a-real-secret-value", encoding="utf-8")

    json_path, markdown_path = write_reports(
        [result("ALL-P0-001", "P0", "passed")],
        report_dir=tmp_path / "reports",
        profile="final",
        revision="stale-revision-argument",
        repository=repository,
    )

    raw_json = json_path.read_text(encoding="utf-8")
    raw_markdown = markdown_path.read_text(encoding="utf-8")
    payload = json.loads(raw_json)
    assert payload["verdict"] == "FAIL"
    assert payload["evidence_class"] == "final_signoff_candidate"
    assert payload["worktree"]["dirty"] is True
    assert payload["worktree"]["status_counts"] == {
        "total": 2,
        "staged": 0,
        "unstaged": 1,
        "untracked": 1,
        "conflicts": 0,
    }
    assert payload["revision"] == payload["worktree"]["git_head"]
    assert "PRIVATE_TOKEN_do_not_report.txt" not in raw_json + raw_markdown
    assert "not-a-real-secret-value" not in raw_json + raw_markdown
    assert "DIRTY WORKTREE: NOT SIGNABLE" in raw_markdown
