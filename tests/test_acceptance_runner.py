from __future__ import annotations

import json
import subprocess
from pathlib import Path

from scripts.acceptance import (
    AcceptanceGate,
    AcceptanceResult,
    CommandOutcome,
    build_profile,
    calculate_verdict,
    redact_output,
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
