from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.acceptance import (
    AcceptanceGate,
    AcceptanceResult,
    CommandOutcome,
    build_profile,
    calculate_verdict,
    execute_command,
    redact_output,
    resolve_command,
    run_gate,
    write_reports,
)


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


def test_final_profile_adds_real_e2e_and_every_declared_hard_blocker() -> None:
    gates = build_profile("final")
    by_id = {gate.gate_id: gate for gate in gates}

    assert by_id["E2E-P0-001"].command == ("npm", "run", "test:e2e")
    assert Path(by_id["E2E-P0-001"].cwd).name == "web"
    blockers = {
        "CAPACITY-P0-001": "5 billion tokens per day",
        "STORAGE-P0-001": "10 TB",
        "MALWARE-P0-001": "malware scanning",
        "TOKEN-GOV-P0-001": "token cost governance",
        "DR-P0-001": "disaster-recovery restore drill",
        "SECURITY-SCAN-P0-001": "thread limit",
    }
    for gate_id, evidence_phrase in blockers.items():
        gate = by_id[gate_id]
        assert gate.severity == "P0"
        assert gate.command == ()
        assert gate.blocked_reason is not None
        assert evidence_phrase in gate.blocked_reason


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
    assert "CAPACITY-P0-001" not in local_ids | ci_ids
    assert "SERVER-P1-001" in local_ids
    assert "SERVER-P1-001" not in ci_ids
    assert calculate_verdict(final_results) == "FAIL"


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
    )

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")
    assert payload["verdict"] == "CONDITIONAL"
    assert payload["revision"] == "abc123"
    assert payload["results"][1]["status"] == "blocked"
    assert "secret-token-value" not in json_path.read_text(encoding="utf-8")
    assert "secret-token-value" not in markdown
    assert "SERVER-P1-001" in markdown
    assert "blocked" in markdown
