from __future__ import annotations

import base64
import hashlib
import json
import platform
import shutil
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import scripts.acceptance as acceptance_module
from scripts.acceptance import (
    AcceptanceGate,
    AcceptanceResult,
    BrowserCollectionContract,
    CommandOutcome,
    _browser_e2e_exit_code,
    _formal_signature_payload,
    _verify_browser_e2e_document,
    build_profile,
    calculate_verdict,
    collect_worktree_evidence,
    execute_command,
    initialize_acceptance_identity,
    redact_output,
    resolve_browser_e2e_suite_timeout_seconds,
    resolve_command,
    run_browser_e2e,
    run_gate,
    run_gates_bound_to_identity,
    verify_bound_child_evidence,
    verify_browser_e2e_collection,
    verify_browser_e2e_evidence,
    verify_formal_evidence,
    verify_offline_runtime_evidence,
    write_reports,
)
from scripts.acceptance_gate import GateIdentity
from scripts.functional_acceptance import ExternalTrustContext, _signature_payload


def result(gate_id: str, severity: str, status: str) -> AcceptanceResult:
    return AcceptanceResult(
        gate_id=gate_id,
        severity=severity,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        duration_seconds=0.1,
        summary="test result",
    )


def final_browser_e2e_gate() -> AcceptanceGate:
    return next(
        gate
        for gate in build_profile(
            "final",
            e2e_evidence_path="/evidence/browser-e2e.json",
            functional_trust_store_path="/secure/trust.json",
            functional_challenge_store_path="/secure/challenges",
            e2e_signing_key_path="/secure/browser-e2e.key",
            e2e_signing_key_id="browser-e2e-ed25519",
        )
        if gate.gate_id == "E2E-P0-001"
    )


_REQUIRED_BROWSER_TITLES = (
    "@enterprise preflight 真实前端、API 与故障控制面必须可达",
    "@enterprise TLS validates trusted identity and short-lived certificate renewal architecture",
    "@enterprise unified login routes accounts by effective role",
    "@enterprise account lifecycle rejects duplicates and revokes active access",
    "@enterprise password reset enforces scope and revokes old credentials and sessions",
    "@enterprise role administration edits and deletes safely under references and concurrency",
    "@enterprise knowledge grants are visible then fail closed immediately after revocation",
    "@enterprise all nine document formats complete scan, OKF, approval, retrieval and cited chat",
    "@enterprise chat renders citations, no-answer, audited rejection and sourced table",
    "@enterprise configured model switches and provider failure degrades safely",
    "@enterprise API key enforces knowledge scope, rate limit and revocation",
    "@enterprise audit query, pagination, CSV export and permission revocation fail closed",
    "@enterprise loading and 401/403/409/429/5xx/timeout states fail visibly",
)

_REQUIRED_BROWSER_CHECKS = (
    "login_role_routing",
    "account_lifecycle",
    "knowledge_acl",
    "file_upload_scan_okf_approval_download",
    "chat_citations_audit_table",
    "model_switch",
    "model_deepseek_success",
    "model_qwen_success",
    "model_minimax_success",
    "api_key_lifecycle",
    "audit_log_query_export",
    "error_loading_states",
    "tls_ca_trust",
    "tls_san_identity",
    "tls_validity_and_renewal",
    "tls_strict_client",
)


def _browser_collection_output() -> str:
    lines = ["Listing tests:"]
    for project in ("enterprise-desktop", "enterprise-mobile"):
        lines.extend(
            f"  [{project}] › enterprise-business.spec.ts:1:1 › {title}"
            for title in _REQUIRED_BROWSER_TITLES
        )
    lines.append("Total: 26 tests in 3 files")
    return "\n".join(lines)


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


def test_gate_subprocess_inherits_the_single_parent_deployment_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(acceptance_module, "_active_offline_lock_fd", 9)
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(acceptance_module, "_root_protected_executable", lambda command: command)

    outcome = execute_command(AcceptanceGate("LOCK", "P0", ("tool",), ".", 10))

    assert outcome.returncode == 0
    assert captured["pass_fds"] == (9,)
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert environment["KB_OFFLINE_LOCK_HELD"] == "heyi-kb-offline-operation-v2"


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


def test_browser_e2e_suite_timeout_defaults_to_two_hours() -> None:
    assert resolve_browser_e2e_suite_timeout_seconds({}) == 7_200


def test_browser_collection_requires_exact_count_projects_and_critical_titles() -> None:
    repository = Path(__file__).parents[1]
    contract = acceptance_module._browser_collection_contract(repository)

    accepted, _ = verify_browser_e2e_collection(_browser_collection_output(), contract)
    missing, _ = verify_browser_e2e_collection(
        _browser_collection_output().replace(_REQUIRED_BROWSER_TITLES[0], "renamed", 1),
        contract,
    )
    filtered, _ = verify_browser_e2e_collection(
        _browser_collection_output().replace("Total: 26 tests", "Total: 25 tests"),
        contract,
    )

    assert accepted is True
    assert contract.required_projects == ("enterprise-desktop", "enterprise-mobile")
    assert missing is False
    assert filtered is False


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        ({"KB_E2E_SUITE_TIMEOUT_MS": "not-an-integer"}, "integer"),
        ({"KB_E2E_SUITE_TIMEOUT_MS": "1799999"}, "between"),
        ({"KB_E2E_SUITE_TIMEOUT_MS": "43200001"}, "between"),
        (
            {
                "KB_E2E_SUITE_TIMEOUT_MS": "1800000",
                "KB_E2E_TEST_TIMEOUT_MS": "1800001",
            },
            "shorter",
        ),
        ({"KB_E2E_TEST_TIMEOUT_MS": "invalid"}, "integer"),
    ],
)
def test_browser_e2e_suite_timeout_rejects_unsafe_values(
    environment: dict[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        resolve_browser_e2e_suite_timeout_seconds(environment)


def test_browser_e2e_runner_and_outer_gate_use_configured_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    signing_key = tmp_path / "browser-e2e.key"
    signing_key.write_text("synthetic", encoding="utf-8")
    challenge = tmp_path / "challenge.json"
    challenge.write_text("{}", encoding="utf-8")
    evidence = tmp_path / "browser-e2e.json"
    trust_store = tmp_path / "trust.json"
    challenge_store = tmp_path / "challenges"
    captured: dict[str, object] = {}
    calls: list[list[str]] = []
    identity = GateIdentity("a" * 40, "b" * 64, "c" * 32)

    monkeypatch.setenv("KB_E2E_TEST_TIMEOUT_MS", "1800000")
    monkeypatch.setenv("KB_E2E_SUITE_TIMEOUT_MS", "3600000")
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        acceptance_module,
        "_protected_regular_file",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        acceptance_module,
        "_browser_collection_contract",
        lambda _repository: BrowserCollectionContract(
            26,
            ("enterprise-desktop", "enterprise-mobile"),
            _REQUIRED_BROWSER_TITLES,
        ),
    )
    monkeypatch.setattr(acceptance_module, "_root_protected_executable", lambda command: command)
    monkeypatch.setattr(
        acceptance_module,
        "_browser_challenge_path",
        lambda *_args, **_kwargs: challenge,
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        captured["timeout"] = kwargs["timeout"]
        captured["environment"] = kwargs["env"]
        if command[-2:] == ["--", "--list"]:
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout=_browser_collection_output(),
                stderr="",
            )
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="26 passed",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(
        acceptance_module,
        "verify_browser_e2e_evidence",
        lambda *_args, **_kwargs: (True, "verified"),
    )

    exit_code, _summary = run_browser_e2e(
        repository=repository,
        evidence_file=evidence,
        trust_store=trust_store,
        challenge_store=challenge_store,
        signing_key=signing_key,
        signing_key_id="browser-e2e-ed25519",
        identity=identity,
        identity_collector=lambda _repository: identity,
    )
    e2e_gate = final_browser_e2e_gate()

    assert exit_code == 0
    assert len(calls) == 2
    assert calls[0][-2:] == ["--", "--list"]
    assert captured["timeout"] == 3_600
    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert environment["KB_E2E_PROFILE"] == "enterprise"
    assert environment["KB_E2E_RUN_ID"] == f"acceptance-{identity.run_nonce}"
    assert e2e_gate.timeout_seconds == 3_660
    assert e2e_gate.blocked_reason is None


def test_invalid_browser_e2e_timeout_blocks_outer_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KB_E2E_SUITE_TIMEOUT_MS", "1")

    e2e_gate = final_browser_e2e_gate()

    assert e2e_gate.blocked_reason == "browser E2E timeout configuration is invalid"


def test_invalid_browser_e2e_timeout_blocks_before_starting_npm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("KB_E2E_SUITE_TIMEOUT_MS", "1")

    def unexpected_run(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("npm must not start with an unsafe timeout")

    monkeypatch.setattr(subprocess, "run", unexpected_run)

    exit_code, summary = run_browser_e2e(
        repository=tmp_path / "repository",
        evidence_file=tmp_path / "browser-e2e.json",
        trust_store=tmp_path / "trust.json",
        challenge_store=tmp_path / "challenges",
        signing_key=tmp_path / "browser-e2e.key",
        signing_key_id="browser-e2e-ed25519",
    )

    assert exit_code == 2
    assert summary == "browser E2E timeout configuration is invalid"


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
        expected_run_id="acceptance-" + "c" * 32,
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
    run_id = "acceptance-browser-final-001"
    checks = {
        check: {"status": "passed", "artifact_ids": ["browser-result"]}
        for check in _REQUIRED_BROWSER_CHECKS
    }
    document: dict[str, object] = {
        "schema_version": 2,
        "evidence_id": "EXT-BROWSER-E2E-001",
        "status": "complete",
        "collector": {"id": "heyi-browser-e2e", "version": "1.0.0"},
        "target": {
            "git_head": identity.git_head,
            "content_fingerprint": identity.content_fingerprint,
            "run_id": run_id,
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
                "target": {
                    "git_head": identity.git_head,
                    "content_fingerprint": identity.content_fingerprint,
                    "run_id": run_id,
                },
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
        expected_run_id=run_id,
        trust_context=context,
    )
    replayed = _verify_browser_e2e_document(
        evidence,
        repository,
        expected_key_id=key_id,
        expected_run_id=run_id,
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
    gates = build_profile("local")
    ids = {gate.gate_id for gate in gates}

    assert {
        "CODE-P0-001",
        "BACKEND-P0-001",
        "FRONTEND-P0-001",
        "BUILD-P0-001",
        "OFFLINE-P0-001",
        "SERVER-P1-001",
    } <= ids
    offline_gate = next(gate for gate in gates if gate.gate_id == "OFFLINE-P0-001")
    repository = Path(acceptance_module.__file__).resolve().parents[1]
    runtime_index = offline_gate.command.index(
        str(repository / "deploy/tencent/offline.env.example")
    )
    release_index = offline_gate.command.index(
        str(repository / "deploy/tencent/release.env.example")
    )
    assert runtime_index < release_index
    assert offline_gate.command.count("--env-file") == 2
    assert "maintenance" in offline_gate.command


def test_final_profile_rejects_the_deprecated_single_environment_file() -> None:
    gates = build_profile(
        "final",
        offline_env_file="/etc/heyi/offline.env",
        offline_image_manifest_path="/evidence/offline-images.txt",
    )
    by_id = {gate.gate_id: gate for gate in gates}

    for gate_id in ("OFFLINE-P0-001", "OFFLINE-IMAGES-P0-001"):
        blocker = by_id[gate_id].blocked_reason
        assert blocker is not None
        assert "deprecated" in blocker
        assert "forbidden for the final profile" in blocker


@pytest.mark.parametrize(
    ("runtime_env", "release_env", "missing_option"),
    [
        (None, "/srv/heyi/releases/approved/release.env", "--offline-runtime-env-file"),
        ("/etc/heyi/runtime.env", None, "--offline-release-env-file"),
    ],
)
def test_final_profile_requires_both_offline_environment_files(
    runtime_env: str | None,
    release_env: str | None,
    missing_option: str,
) -> None:
    gates = build_profile(
        "final",
        offline_runtime_env_file=runtime_env,
        offline_release_env_file=release_env,
        offline_image_manifest_path="/evidence/offline-images.txt",
    )
    offline_gate = next(gate for gate in gates if gate.gate_id == "OFFLINE-P0-001")

    assert offline_gate.blocked_reason is not None
    assert missing_option in offline_gate.blocked_reason


def test_final_profile_adds_executable_target_evidence_gates() -> None:
    contract_dir = "/run/heyi-kb-offline/contracts/contract.acceptance"
    contract_sha256 = "d" * 64
    gates = build_profile(
        "final",
        host_disk_path="/data/knowledge",
        host_io_evidence_path="/evidence/host-io.json",
        storage_chain_evidence_path="/evidence/watermark-chain.json",
        offline_runtime_env_file="/etc/heyi/runtime.env",
        offline_release_env_file="/srv/heyi/releases/approved/release.env",
        offline_image_manifest_path="/srv/heyi/releases/approved/release.env.images",
        offline_contract_dir=contract_dir,
        offline_contract_sha256=contract_sha256,
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
    for gate_id in ("CAPACITY-P0-001", "DR-P0-001"):
        gate = by_id[gate_id]
        assert gate.severity == "P0"
        assert gate.command
        assert "--verify-operational-evidence" in gate.command
        assert gate.blocked_reason is not None
        assert "--release-id" in gate.blocked_reason

    malware_gate = by_id["MALWARE-P0-001"]
    assert malware_gate.blocked_reason is None
    assert malware_gate.blocked_exit_codes == (2,)
    assert malware_gate.command[2:] == (
        "--verify-evidence",
        "malware",
        "--evidence-file",
        "/evidence/malware.json",
        "--functional-trust-store",
        "/secure/functional-trust.json",
        "--functional-challenge-store",
        "/secure/challenges",
    )
    assert malware_gate.required_regular_files == (
        "/evidence/malware.json",
        "/secure/functional-trust.json",
    )

    security_gate = by_id["SECURITY-SCAN-P0-001"]
    assert security_gate.blocked_reason is None
    assert security_gate.blocked_exit_codes == (2,)
    assert security_gate.command[2:] == (
        "--verify-evidence",
        "security-scan",
        "--evidence-file",
        "/evidence/security.json",
        "--functional-trust-store",
        "/secure/functional-trust.json",
        "--functional-challenge-store",
        "/secure/challenges",
    )
    assert security_gate.required_regular_files == (
        "/evidence/security.json",
        "/secure/functional-trust.json",
    )

    worktree_gate = by_id["WORKTREE-P0-001"]
    assert worktree_gate.blocked_reason is None
    assert worktree_gate.blocked_exit_codes == (2,)
    assert worktree_gate.command[-1] == "--verify-clean-worktree"

    offline_gate = by_id["OFFLINE-P0-001"]
    assert Path(offline_gate.command[1]).name == "preflight-offline.sh"
    assert offline_gate.command[2:] == (
        "--upgrade",
        "--contract-dir",
        contract_dir,
        "--contract-sha256",
        contract_sha256,
    )
    assert {66, 77} <= set(offline_gate.blocked_exit_codes)
    assert offline_gate.required_regular_files == (
        f"{contract_dir}/runtime.env",
        f"{contract_dir}/release.env",
        f"{contract_dir}/release.env.images",
        f"{contract_dir}/contract.sha256",
    )
    image_gate = by_id["OFFLINE-IMAGES-P0-001"]
    assert Path(image_gate.command[1]).name == "verify-offline-images.sh"
    assert image_gate.command[2:] == (
        "verify",
        "--contract-dir",
        contract_dir,
        "--contract-sha256",
        contract_sha256,
    )
    assert image_gate.required_regular_files == (
        f"{contract_dir}/runtime.env",
        f"{contract_dir}/release.env",
        f"{contract_dir}/release.env.images",
        f"{contract_dir}/contract.sha256",
    )
    runtime_gate = by_id["OFFLINE-RUNTIME-P0-001"]
    assert runtime_gate.command[-3:] == (
        "--verify-offline-runtime-evidence",
        "--evidence-file",
        "/evidence/offline-runtime-evidence.json",
    )
    assert runtime_gate.blocked_exit_codes == (2,)
    assert runtime_gate.required_regular_files == ("/evidence/offline-runtime-evidence.json",)
    assert "STORAGE-P0-001" not in by_id


def test_final_supply_chain_gate_is_release_only_and_identity_bound() -> None:
    identity = GateIdentity("a" * 40, "b" * 64, "c" * 32)
    gates = build_profile(
        "final",
        supply_chain_attestation_path="/secure/release-rights-attestation.json",
        supply_chain_artifact_root="/srv/heyi/releases/approved/supply-chain",
        acceptance_identity=identity,
    )
    by_id = {gate.gate_id: gate for gate in gates}
    gate = by_id["SUPPLY-CHAIN-P0-001"]

    assert gate.severity == "P0"
    assert gate.blocked_reason is None
    assert Path(gate.command[1]).name == "supply_chain_gate.py"
    assert gate.command[gate.command.index("--mode") + 1] == "release"
    assert "inventory" not in gate.command
    assert gate.command[gate.command.index("--attestation") + 1] == (
        "/secure/release-rights-attestation.json"
    )
    assert gate.command[gate.command.index("--artifact-root") + 1] == (
        "/srv/heyi/releases/approved/supply-chain"
    )
    assert gate.command[gate.command.index("--expected-release-id") + 1] == identity.git_head
    assert gate.required_regular_files == ("/secure/release-rights-attestation.json",)

    ordered_ids = [item.gate_id for item in gates]
    assert ordered_ids.index("CODE-P0-001") < ordered_ids.index("SUPPLY-CHAIN-P0-001")
    assert ordered_ids.index("SUPPLY-CHAIN-P0-001") < ordered_ids.index("FUNCTIONAL-P0-001")


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

    assert accepted is False
    assert summary == (
        "malware evidence is unsigned, replayed, incomplete, or does not match this acceptance run"
    )

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
    assert summary == (
        "malware evidence is unsigned, replayed, incomplete, or does not match this acceptance run"
    )


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

    assert accepted is False
    assert summary == (
        "security scan evidence is unsigned, replayed, incomplete, or does not match this "
        "acceptance run"
    )

    document["target"]["content_fingerprint"] = "0" * 64
    evidence.write_text(json.dumps(document), encoding="utf-8")
    accepted, summary = verify_formal_evidence("security-scan", evidence, repository)
    assert accepted is False
    assert summary == (
        "security scan evidence is unsigned, replayed, incomplete, or does not match this "
        "acceptance run"
    )


def _signed_formal_evidence(
    tmp_path: Path,
    kind: str,
) -> tuple[
    Path,
    Path,
    GateIdentity,
    ExternalTrustContext,
    dict[str, object],
    Ed25519PrivateKey,
    str,
    str,
    str,
]:
    repository = tmp_path / f"{kind}-repository"
    _init_git_repository(repository)
    worktree = collect_worktree_evidence(repository)
    identity = GateIdentity(worktree.git_head, worktree.content_fingerprint, "c" * 32)
    run_id = f"acceptance-{identity.run_nonce}"
    evidence_dir = tmp_path / f"{kind}-signed-evidence"
    evidence_dir.mkdir()
    if kind == "malware":
        evidence_id = "EXT-MALWARE-001"
        collector_id = "heyi-malware-acceptance"
        check_names = (
            "clamav_database_preflight",
            "eicar_quarantined",
            "clean_file_released",
            "minio_scan_approval_download",
        )
    else:
        evidence_id = "EXT-SECURITY-SCAN-001"
        collector_id = "heyi-security-acceptance"
        check_names = ("security_scan_complete", "no_open_critical", "no_open_high")

    artifacts: list[dict[str, object]] = []
    checks: dict[str, dict[str, object]] = {}
    for index, check_name in enumerate(check_names):
        artifact = evidence_dir / f"{index:02d}-{check_name}.json"
        artifact.write_text(json.dumps({"check": check_name, "status": "passed"}), encoding="utf-8")
        artifact_id = f"artifact-{index:02d}"
        artifacts.append(
            {
                "id": artifact_id,
                "path": artifact.name,
                "sha256": _sha256(artifact),
                "bytes": artifact.stat().st_size,
            }
        )
        checks[check_name] = {"status": "passed", "artifact_ids": [artifact_id]}

    now = datetime.now(UTC)
    document: dict[str, object] = {
        "schema_version": 2,
        "evidence_id": evidence_id,
        "kind": kind,
        "status": "complete",
        "collector": {"id": collector_id, "version": "1.0.0"},
        "target": {
            "git_head": identity.git_head,
            "content_fingerprint": identity.content_fingerprint,
            "run_id": run_id,
        },
        "collected_at": now.isoformat(),
        "artifacts": artifacts,
        "checks": checks,
    }
    if kind == "security-scan":
        document["policy_status"] = "passed"
        document["summary"] = {
            "open_critical": 0,
            "open_high": 0,
            "open_medium": 2,
            "open_low": 1,
        }

    private_key = Ed25519PrivateKey.generate()
    key_id = f"{kind}-ed25519"
    challenge_id = f"{kind}-challenge"
    challenge_nonce = f"{kind}-one-time-challenge-nonce"
    signature = private_key.sign(
        _formal_signature_payload(
            document,
            key_id=key_id,
            challenge_id=challenge_id,
            challenge_nonce=challenge_nonce,
        )
    )
    document["attestation"] = {
        "type": "ed25519-challenge-v1",
        "key_id": key_id,
        "challenge_id": challenge_id,
        "challenge_nonce": challenge_nonce,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    evidence = evidence_dir / f"{kind}.json"
    evidence.write_text(json.dumps(document), encoding="utf-8")
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    trust_context = ExternalTrustContext(
        public_keys={(collector_id, key_id): public_key},
        challenges={
            challenge_id: {
                "schema_version": 1,
                "challenge_id": challenge_id,
                "evidence_id": evidence_id,
                "nonce": challenge_nonce,
                "status": "issued",
                "target": {
                    "git_head": identity.git_head,
                    "content_fingerprint": identity.content_fingerprint,
                    "run_id": run_id,
                },
                "issued_at": (now - timedelta(minutes=1)).isoformat(),
                "expires_at": (now + timedelta(minutes=10)).isoformat(),
            }
        },
        consumed_challenges=set(),
    )
    return (
        repository,
        evidence,
        identity,
        trust_context,
        document,
        private_key,
        key_id,
        challenge_id,
        challenge_nonce,
    )


@pytest.mark.parametrize(
    ("kind", "success_summary"),
    (
        ("malware", "malware target-host evidence verified (4/4 checks)"),
        (
            "security-scan",
            "signed complete security scan report verified for this acceptance run",
        ),
    ),
)
def test_formal_evidence_requires_full_signature_identity_and_one_time_challenge(
    tmp_path: Path,
    kind: str,
    success_summary: str,
) -> None:
    (
        repository,
        evidence,
        identity,
        trust_context,
        _document,
        _private_key,
        _key_id,
        _challenge_id,
        _challenge_nonce,
    ) = _signed_formal_evidence(tmp_path, kind)

    accepted, summary = verify_formal_evidence(
        kind,  # type: ignore[arg-type]
        evidence,
        repository,
        identity=identity,
        trust_context=trust_context,
        require_protected_evidence=False,
    )
    assert accepted is True
    assert summary == success_summary

    replayed, _ = verify_formal_evidence(
        kind,  # type: ignore[arg-type]
        evidence,
        repository,
        identity=identity,
        trust_context=trust_context,
        require_protected_evidence=False,
    )
    assert replayed is False


@pytest.mark.parametrize("kind", ("malware", "security-scan"))
@pytest.mark.parametrize(
    "mutation",
    (
        "extra_run_nonce",
        "extra_os",
        "missing_run_id",
        "mismatched_run_id",
        "mismatched_challenge_target",
    ),
)
def test_formal_evidence_rejects_noncanonical_or_unbound_run_target(
    tmp_path: Path,
    kind: str,
    mutation: str,
) -> None:
    (
        repository,
        evidence,
        identity,
        trust_context,
        document,
        private_key,
        key_id,
        challenge_id,
        challenge_nonce,
    ) = _signed_formal_evidence(tmp_path, kind)
    target = document["target"]
    assert isinstance(target, dict)
    if mutation == "extra_run_nonce":
        target["run_nonce"] = identity.run_nonce
    elif mutation == "extra_os":
        target["os"] = "linux"
    elif mutation == "missing_run_id":
        target.pop("run_id")
    elif mutation == "mismatched_run_id":
        target["run_id"] = "acceptance-" + "d" * 32

    challenge = trust_context.challenges[challenge_id]
    challenge["target"] = dict(target)
    if mutation == "mismatched_challenge_target":
        challenge_target = challenge["target"]
        assert isinstance(challenge_target, dict)
        challenge_target["run_id"] = "acceptance-" + "d" * 32

    document["attestation"] = {
        "type": "ed25519-challenge-v1",
        "key_id": key_id,
        "challenge_id": challenge_id,
        "challenge_nonce": challenge_nonce,
        "signature": base64.b64encode(
            private_key.sign(
                _formal_signature_payload(
                    document,
                    key_id=key_id,
                    challenge_id=challenge_id,
                    challenge_nonce=challenge_nonce,
                )
            )
        ).decode("ascii"),
    }
    evidence.write_text(json.dumps(document), encoding="utf-8")

    accepted, _summary = verify_formal_evidence(
        kind,  # type: ignore[arg-type]
        evidence,
        repository,
        identity=identity,
        trust_context=trust_context,
        require_protected_evidence=False,
    )

    assert accepted is False


def test_formal_malware_evidence_keeps_protected_linux_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        repository,
        evidence,
        identity,
        trust_context,
        _document,
        _private_key,
        _key_id,
        _challenge_id,
        _challenge_nonce,
    ) = _signed_formal_evidence(tmp_path, "malware")
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(acceptance_module, "_protected_regular_file", lambda *_a, **_k: True)
    assert not verify_formal_evidence(
        "malware",
        evidence,
        repository,
        identity=identity,
        trust_context=trust_context,
    )[0]

    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(acceptance_module, "_protected_regular_file", lambda *_a, **_k: False)
    assert not verify_formal_evidence(
        "malware",
        evidence,
        repository,
        identity=identity,
        trust_context=trust_context,
    )[0]


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
    egress_mode: str = "strict_offline",
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
            "egress_mode": egress_mode,
        },
        "checks": checks,
        "artifacts": [descriptor],
    }
    canonical = lambda value: hashlib.sha256(  # noqa: E731
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    document["result_sha256"] = canonical(
        {"target": document["target"], "checks": checks, "artifacts": [descriptor]}
    )
    document["attestation"] = {"type": "sha256-chain-v1", "digest": canonical(document)}
    return document


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
    monkeypatch.setattr("scripts.acceptance._offline_runtime_host_fingerprint", lambda: "a" * 64)

    accepted, summary = verify_offline_runtime_evidence(evidence, repository)

    assert accepted is True
    assert summary == "offline runtime target evidence verified"

    controlled = _offline_runtime_document(
        repository,
        evidence_dir,
        egress_mode="controlled_gateway",
    )
    evidence.write_text(json.dumps(controlled), encoding="utf-8")
    assert verify_offline_runtime_evidence(evidence, repository)[0] is True

    invalid_mode = _offline_runtime_document(repository, evidence_dir)
    invalid_target = invalid_mode["target"]
    assert isinstance(invalid_target, dict)
    invalid_target["egress_mode"] = "direct"
    evidence.write_text(json.dumps(invalid_mode), encoding="utf-8")
    assert verify_offline_runtime_evidence(evidence, repository)[0] is False

    wrong_project = _offline_runtime_document(repository, evidence_dir)
    wrong_target = wrong_project["target"]
    assert isinstance(wrong_target, dict)
    wrong_target["project_name"] = "another-project"
    evidence.write_text(json.dumps(wrong_project), encoding="utf-8")
    assert verify_offline_runtime_evidence(evidence, repository)[0] is False

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
    monkeypatch.setattr("scripts.acceptance._offline_runtime_host_fingerprint", lambda: "a" * 64)
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
        "SUPPLY-CHAIN-P0-001",
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


def _identity_arguments(command: tuple[str, ...]) -> dict[str, str]:
    options = (
        "--expected-git-head",
        "--expected-content-fingerprint",
        "--acceptance-run-nonce",
    )
    return {option: command[command.index(option) + 1] for option in options}


def test_machine_child_gates_share_one_top_level_acceptance_identity() -> None:
    identity = GateIdentity("a" * 40, "b" * 64, "c" * 32)
    expected = {
        "--expected-git-head": identity.git_head,
        "--expected-content-fingerprint": identity.content_fingerprint,
        "--acceptance-run-nonce": identity.run_nonce,
    }

    local = {gate.gate_id: gate for gate in build_profile("local", acceptance_identity=identity)}
    final = {gate.gate_id: gate for gate in build_profile("final", acceptance_identity=identity)}

    evidence_contracts = {
        "FUNCTIONAL-P0-001": (
            "artifacts/acceptance/evidence/functional.json",
            "functional-acceptance",
        ),
        "TOKEN-GOV-P0-001": (
            "artifacts/acceptance/evidence/postgres.json",
            "postgres-acceptance",
        ),
        "BACKEND-P0-001": (
            "artifacts/acceptance/evidence/backend.json",
            "backend-acceptance",
        ),
    }
    local_functional = local["FUNCTIONAL-P0-001"]
    assert _identity_arguments(local_functional.command) == expected
    assert local_functional.child_evidence_path == evidence_contracts["FUNCTIONAL-P0-001"][0]
    assert local_functional.child_evidence_kind == evidence_contracts["FUNCTIONAL-P0-001"][1]
    e2e = final["E2E-P0-001"]
    assert _identity_arguments(e2e.command) == expected
    assert dict(e2e.environment)["KB_E2E_RUN_ID"] == f"acceptance-{identity.run_nonce}"
    for gate_id, (evidence_path, evidence_kind) in evidence_contracts.items():
        gate = final[gate_id]
        command = gate.command
        assert _identity_arguments(command) == expected
        assert all(command.count(option) == 1 for option in expected)
        assert command.count("--evidence-file") == 1
        assert command[command.index("--evidence-file") + 1] == evidence_path
        assert gate.child_evidence_path == evidence_path
        assert gate.child_evidence_kind == evidence_kind


def test_gate_orchestrator_checks_identity_before_after_each_gate_and_at_end() -> None:
    identity = GateIdentity("a" * 40, "b" * 64, "c" * 32)
    current = acceptance_module.WorktreeEvidence(
        git_head=identity.git_head,
        dirty=False,
        status_counts={"total": 0},
        tracked_diff_sha256="d" * 64,
        untracked_manifest_sha256="e" * 64,
        content_fingerprint=identity.content_fingerprint,
    )
    identity_checks: list[Path] = []
    executed: list[str] = []

    def collector(repository: Path) -> acceptance_module.WorktreeEvidence:
        identity_checks.append(repository)
        return current

    def executor(gate: AcceptanceGate) -> CommandOutcome:
        executed.append(gate.gate_id)
        return CommandOutcome(0, "ok", "")

    gates = (
        AcceptanceGate("ONE", "P0", ("one",), ".", 1),
        AcceptanceGate("TWO", "P1", ("two",), ".", 1),
    )
    results = run_gates_bound_to_identity(
        gates,
        repository=Path.cwd(),
        identity=identity,
        executor=executor,
        identity_collector=collector,
    )

    assert [item.status for item in results] == ["passed", "passed"]
    assert executed == ["ONE", "TWO"]
    assert len(identity_checks) == 5


def test_gate_orchestrator_stops_when_a_gate_changes_repository_identity() -> None:
    identity = GateIdentity("a" * 40, "b" * 64, "c" * 32)
    matching = acceptance_module.WorktreeEvidence(
        git_head=identity.git_head,
        dirty=False,
        status_counts={"total": 0},
        tracked_diff_sha256="d" * 64,
        untracked_manifest_sha256="e" * 64,
        content_fingerprint=identity.content_fingerprint,
    )
    changed = replace(matching, content_fingerprint="f" * 64)
    observations = iter((matching, changed))
    executed: list[str] = []

    def executor(gate: AcceptanceGate) -> CommandOutcome:
        executed.append(gate.gate_id)
        return CommandOutcome(0, "ok", "")

    results = run_gates_bound_to_identity(
        (
            AcceptanceGate("MUTATING", "P1", ("mutate",), ".", 1),
            AcceptanceGate("MUST-NOT-RUN", "P0", ("later",), ".", 1),
        ),
        repository=Path.cwd(),
        identity=identity,
        executor=executor,
        identity_collector=lambda _repository: next(observations),
    )

    assert executed == ["MUTATING"]
    assert len(results) == 1
    assert results[0].gate_id == "ACCEPTANCE-IDENTITY-P0-001"
    assert results[0].severity == "P0"
    assert results[0].status == "failed"
    assert "after MUTATING" in results[0].summary


_CHILD_EVIDENCE_CASES = (
    (
        "functional-acceptance",
        "artifacts/acceptance/evidence/functional.json",
    ),
    (
        "postgres-acceptance",
        "artifacts/acceptance/evidence/postgres.json",
    ),
    (
        "backend-acceptance",
        "artifacts/acceptance/evidence/backend.json",
    ),
)


def _child_document(kind: str, identity: GateIdentity) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": 2,
        "kind": kind,
        "status": "complete",
        "policy_status": "passed",
        "target": identity.target(),
    }
    if kind == "functional-acceptance":
        document.update({"verdict": "PASS", "source_verdict": "PASS"})
    return document


@pytest.mark.parametrize(("kind", "relative_path"), _CHILD_EVIDENCE_CASES)
def test_machine_child_evidence_requires_exact_nonce_bound_contract(
    tmp_path: Path,
    kind: str,
    relative_path: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    identity = GateIdentity("a" * 40, "b" * 64, "c" * 32)
    evidence_path = repository / relative_path
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_text(
        json.dumps(_child_document(kind, identity)),
        encoding="utf-8",
    )
    gate = AcceptanceGate(
        "CHILD-P0-001",
        "P0",
        ("child",),
        str(repository),
        1,
        child_evidence_path=relative_path,
        child_evidence_kind=kind,  # type: ignore[arg-type]
    )

    accepted, summary = verify_bound_child_evidence(
        gate,
        repository=repository,
        identity=identity,
    )

    assert accepted is True
    assert "exact acceptance target" in summary


@pytest.mark.parametrize(
    "mutation",
    (
        "schema",
        "kind",
        "status",
        "policy",
        "missing_target_key",
        "extra_target_key",
        "old_nonce",
        "wrong_git_head",
        "wrong_fingerprint",
        "functional_verdict",
    ),
)
def test_machine_child_evidence_rejects_self_reported_or_stale_success(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    identity = GateIdentity("a" * 40, "b" * 64, "c" * 32)
    relative_path = "artifacts/acceptance/evidence/functional.json"
    evidence_path = repository / relative_path
    evidence_path.parent.mkdir(parents=True)
    document = _child_document("functional-acceptance", identity)
    if mutation == "schema":
        document["schema_version"] = 1
    elif mutation == "kind":
        document["kind"] = "postgres-acceptance"
    elif mutation == "status":
        document["status"] = "failed"
    elif mutation == "policy":
        document["policy_status"] = "failed"
    elif mutation == "functional_verdict":
        document["verdict"] = "FAIL"
    else:
        target = dict(identity.target())
        if mutation == "missing_target_key":
            target.pop("run_nonce")
        elif mutation == "extra_target_key":
            target["unexpected"] = "value"
        elif mutation == "old_nonce":
            target["run_nonce"] = "d" * 32
        elif mutation == "wrong_git_head":
            target["git_head"] = "d" * 40
        else:
            target["content_fingerprint"] = "d" * 64
        document["target"] = target
    evidence_path.write_text(json.dumps(document), encoding="utf-8")
    gate = AcceptanceGate(
        "FUNCTIONAL-P0-001",
        "P0",
        ("child",),
        str(repository),
        1,
        child_evidence_path=relative_path,
        child_evidence_kind="functional-acceptance",
    )

    accepted, _ = verify_bound_child_evidence(
        gate,
        repository=repository,
        identity=identity,
    )

    assert accepted is False


def test_machine_child_evidence_rejects_missing_invalid_and_symlink_files(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    identity = GateIdentity("a" * 40, "b" * 64, "c" * 32)
    relative_path = "artifacts/acceptance/evidence/backend.json"
    evidence_path = repository / relative_path
    evidence_path.parent.mkdir(parents=True)
    gate = AcceptanceGate(
        "BACKEND-P0-001",
        "P0",
        ("child",),
        str(repository),
        1,
        child_evidence_path=relative_path,
        child_evidence_kind="backend-acceptance",
    )

    assert not verify_bound_child_evidence(gate, repository=repository, identity=identity)[0]
    evidence_path.write_text("[]", encoding="utf-8")
    assert not verify_bound_child_evidence(gate, repository=repository, identity=identity)[0]
    evidence_path.write_bytes(b"x" * (1024 * 1024 + 1))
    assert not verify_bound_child_evidence(gate, repository=repository, identity=identity)[0]

    actual = tmp_path / "actual.json"
    actual.write_text(
        json.dumps(_child_document("backend-acceptance", identity)),
        encoding="utf-8",
    )
    evidence_path.unlink()
    try:
        evidence_path.symlink_to(actual)
    except OSError:
        return
    assert not verify_bound_child_evidence(gate, repository=repository, identity=identity)[0]


def test_invalid_child_evidence_stops_dependent_gates(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    relative_path = "artifacts/acceptance/evidence/postgres.json"
    evidence_path = repository / relative_path
    evidence_path.parent.mkdir(parents=True)
    identity = GateIdentity("a" * 40, "b" * 64, "c" * 32)
    current = acceptance_module.WorktreeEvidence(
        git_head=identity.git_head,
        dirty=False,
        status_counts={"total": 0},
        tracked_diff_sha256="d" * 64,
        untracked_manifest_sha256="e" * 64,
        content_fingerprint=identity.content_fingerprint,
    )
    executed: list[str] = []

    def executor(gate: AcceptanceGate) -> CommandOutcome:
        executed.append(gate.gate_id)
        if gate.gate_id == "TOKEN-GOV-P0-001":
            stale_identity = GateIdentity(identity.git_head, identity.content_fingerprint, "d" * 32)
            evidence_path.write_text(
                json.dumps(_child_document("postgres-acceptance", stale_identity)),
                encoding="utf-8",
            )
        return CommandOutcome(0, "ok", "")

    results = run_gates_bound_to_identity(
        (
            AcceptanceGate(
                "TOKEN-GOV-P0-001",
                "P0",
                ("postgres",),
                str(repository),
                1,
                child_evidence_path=relative_path,
                child_evidence_kind="postgres-acceptance",
            ),
            AcceptanceGate("BACKEND-P0-001", "P0", ("backend",), str(repository), 1),
        ),
        repository=repository,
        identity=identity,
        executor=executor,
        identity_collector=lambda _repository: current,
    )

    assert executed == ["TOKEN-GOV-P0-001"]
    assert len(results) == 1
    assert results[0].gate_id == "TOKEN-GOV-P0-001"
    assert results[0].status == "failed"


def test_acceptance_identity_initialization_binds_clean_and_dirty_snapshots(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    _init_git_repository(repository)

    clean_snapshot, clean_identity = initialize_acceptance_identity(repository)
    assert clean_snapshot.dirty is False
    assert clean_identity.git_head == clean_snapshot.git_head
    assert clean_identity.content_fingerprint == clean_snapshot.content_fingerprint

    (repository / "tracked.txt").write_text("dirty\n", encoding="utf-8")
    dirty_snapshot, dirty_identity = initialize_acceptance_identity(repository)
    assert dirty_snapshot.dirty is True
    assert dirty_identity.content_fingerprint == dirty_snapshot.content_fingerprint
    assert dirty_identity.content_fingerprint != clean_identity.content_fingerprint


def test_final_profile_fails_before_contract_creation_or_gate_build_on_dirty_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = GateIdentity("a" * 40, "b" * 64, "c" * 32)
    dirty = acceptance_module.WorktreeEvidence(
        git_head=identity.git_head,
        dirty=True,
        status_counts={"total": 1},
        tracked_diff_sha256="d" * 64,
        untracked_manifest_sha256="e" * 64,
        content_fingerprint=identity.content_fingerprint,
    )
    forbidden_calls: list[str] = []

    monkeypatch.setattr(
        acceptance_module,
        "initialize_acceptance_identity",
        lambda _repository: (dirty, identity),
    )
    monkeypatch.setattr(
        acceptance_module,
        "write_reports",
        lambda *_args, **_kwargs: (tmp_path / "acceptance.json", tmp_path / "acceptance.md"),
    )

    def forbidden(*_args: object, **_kwargs: object) -> None:
        forbidden_calls.append("called")
        raise AssertionError("dirty final acceptance must fail before external setup")

    monkeypatch.setattr(acceptance_module, "_create_offline_contract", forbidden)
    monkeypatch.setattr(acceptance_module, "build_profile", forbidden)

    exit_code = acceptance_module.main(
        ["--profile", "final", "--report-dir", str(tmp_path / "reports")]
    )

    assert exit_code == 1
    assert forbidden_calls == []


def test_final_report_is_nonce_bound_and_fails_closed_without_matching_identity(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    _init_git_repository(repository)
    worktree = collect_worktree_evidence(repository)
    identity = GateIdentity(worktree.git_head, worktree.content_fingerprint, "c" * 32)

    json_path, _ = write_reports(
        [result("ALL-P0-001", "P0", "passed")],
        report_dir=tmp_path / "valid",
        profile="final",
        revision=worktree.git_head,
        repository=repository,
        acceptance_identity=identity,
    )
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["verdict"] == "PASS"
    assert payload["identity_verified"] is True
    assert payload["target"] == identity.target()

    (repository / "tracked.txt").write_text("changed during acceptance\n", encoding="utf-8")
    changed_path, _ = write_reports(
        [result("ALL-P0-001", "P0", "passed")],
        report_dir=tmp_path / "changed",
        profile="final",
        revision=worktree.git_head,
        repository=repository,
        acceptance_identity=identity,
    )
    changed_payload = json.loads(changed_path.read_text(encoding="utf-8"))
    assert changed_payload["verdict"] == "FAIL"
    assert changed_payload["identity_verified"] is False

    unsigned_repository = tmp_path / "unsigned"
    _init_git_repository(unsigned_repository)
    unsigned_path, _ = write_reports(
        [result("ALL-P0-001", "P0", "passed")],
        report_dir=tmp_path / "unsigned-report",
        profile="final",
        revision="ignored",
        repository=unsigned_repository,
    )
    unsigned_payload = json.loads(unsigned_path.read_text(encoding="utf-8"))
    assert unsigned_payload["verdict"] == "FAIL"
    assert unsigned_payload["identity_verified"] is False
