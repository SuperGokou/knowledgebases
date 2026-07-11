from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

Severity = Literal["P0", "P1", "P2"]
GateStatus = Literal["passed", "failed", "blocked"]
Verdict = Literal["PASS", "CONDITIONAL", "FAIL"]

_SUMMARY_LIMIT = 4_096
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?im)^([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)=.*$"
)
_BEARER = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+")
_URL_PASSWORD = re.compile(r"(?P<prefix>\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@]+@", re.I)
_PRESIGNED_QUERY = re.compile(
    r"(?P<origin>https?://[^\s?]+)\?[^\s]*(?:X-Amz-(?:Signature|Credential)|Signature=)[^\s]*",
    re.I,
)


@dataclass(frozen=True, slots=True)
class AcceptanceGate:
    gate_id: str
    severity: Severity
    command: tuple[str, ...]
    cwd: str
    timeout_seconds: int
    blocked_reason: str | None = None


@dataclass(frozen=True, slots=True)
class AcceptanceResult:
    gate_id: str
    severity: Severity
    status: GateStatus
    duration_seconds: float
    summary: str


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    returncode: int
    stdout: str
    stderr: str


GateExecutor = Callable[[AcceptanceGate], CommandOutcome]


def calculate_verdict(results: Sequence[AcceptanceResult]) -> Verdict:
    if any(item.severity == "P0" and item.status != "passed" for item in results):
        return "FAIL"
    if any(item.severity == "P1" and item.status != "passed" for item in results):
        return "CONDITIONAL"
    return "PASS"


def redact_output(value: str) -> str:
    redacted = _BEARER.sub(r"\1[REDACTED]", value)
    redacted = _URL_PASSWORD.sub(r"\g<prefix>[REDACTED]@", redacted)
    redacted = _SENSITIVE_ASSIGNMENT.sub(r"\1=[REDACTED]", redacted)
    return _PRESIGNED_QUERY.sub(r"\g<origin>?[REDACTED]", redacted)


def resolve_command(command: tuple[str, ...]) -> tuple[str, ...]:
    if not command:
        return command
    executable = shutil.which(command[0]) or command[0]
    return (executable, *command[1:])


def _bounded_summary(value: str) -> str:
    if len(value) <= _SUMMARY_LIMIT:
        return value
    marker = "[...earlier output truncated...]\n"
    return marker + value[-(_SUMMARY_LIMIT - len(marker)) :]


def execute_command(gate: AcceptanceGate) -> CommandOutcome:
    completed = subprocess.run(  # noqa: S603
        list(resolve_command(gate.command)),
        cwd=gate.cwd,
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        shell=False,
        timeout=gate.timeout_seconds,
    )
    return CommandOutcome(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def run_gate(
    gate: AcceptanceGate,
    *,
    executor: GateExecutor = execute_command,
) -> AcceptanceResult:
    started = time.monotonic()
    if gate.blocked_reason is not None:
        return AcceptanceResult(
            gate_id=gate.gate_id,
            severity=gate.severity,
            status="blocked",
            duration_seconds=0.0,
            summary=redact_output(gate.blocked_reason)[:_SUMMARY_LIMIT],
        )
    try:
        outcome = executor(gate)
    except FileNotFoundError:
        return AcceptanceResult(
            gate_id=gate.gate_id,
            severity=gate.severity,
            status="failed",
            duration_seconds=time.monotonic() - started,
            summary="command executable was not found",
        )
    except subprocess.TimeoutExpired:
        return AcceptanceResult(
            gate_id=gate.gate_id,
            severity=gate.severity,
            status="failed",
            duration_seconds=time.monotonic() - started,
            summary=f"command timed out after {gate.timeout_seconds} seconds",
        )
    combined = "\n".join(part for part in (outcome.stdout, outcome.stderr) if part).strip()
    summary = _bounded_summary(
        redact_output(combined or f"command exited {outcome.returncode}")
    )
    return AcceptanceResult(
        gate_id=gate.gate_id,
        severity=gate.severity,
        status="passed" if outcome.returncode == 0 else "failed",
        duration_seconds=time.monotonic() - started,
        summary=summary,
    )


def build_profile(profile: Literal["local", "ci"]) -> tuple[AcceptanceGate, ...]:
    repository = Path(__file__).resolve().parents[1]
    web = repository / "web"
    base = (
        AcceptanceGate(
            "CODE-P0-001",
            "P0",
            ("uv", "run", "ruff", "check", "."),
            str(repository),
            120,
        ),
        AcceptanceGate(
            "TYPE-P1-001",
            "P1",
            ("uv", "run", "mypy", "app", "scripts"),
            str(repository),
            180,
        ),
        AcceptanceGate(
            "BACKEND-P0-001",
            "P0",
            (
                "uv",
                "run",
                "pytest",
                "--cov=app",
                "--cov-report=term-missing",
                "--cov-fail-under=80",
            ),
            str(repository),
            600,
        ),
        AcceptanceGate(
            "FRONTEND-P0-001",
            "P0",
            ("npm", "test"),
            str(web),
            300,
        ),
        AcceptanceGate(
            "FRONTEND-P1-001",
            "P1",
            ("npm", "run", "lint"),
            str(web),
            300,
        ),
        AcceptanceGate(
            "BUILD-P0-001",
            "P0",
            ("npm", "run", "build"),
            str(web),
            600,
        ),
        AcceptanceGate(
            "OFFLINE-P0-001",
            "P0",
            (
                "docker",
                "compose",
                "--project-name",
                "heyi-kb-offline",
                "--env-file",
                str(repository / "deploy/tencent/offline.env.example"),
                "--file",
                str(repository / "deploy/tencent/compose.offline.yml"),
                "--profile",
                "ops",
                "config",
                "--quiet",
            ),
            str(repository),
            120,
        ),
        AcceptanceGate(
            "SERVER-P1-001",
            "P1",
            (),
            str(repository),
            1,
            blocked_reason=(
                "real 8 vCPU, 16 GB RAM, 300 GB SSD Tencent host is not available; "
                "the discovered host is below the required profile"
            ),
        ),
    )
    return base if profile == "local" else tuple(
        gate for gate in base if gate.gate_id != "SERVER-P1-001"
    )


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def write_reports(
    results: Sequence[AcceptanceResult],
    *,
    report_dir: Path,
    profile: str,
    revision: str,
) -> tuple[Path, Path]:
    safe_results = [replace(item, summary=redact_output(item.summary)) for item in results]
    verdict = calculate_verdict(safe_results)
    generated_at = datetime.now(UTC).isoformat()
    payload = {
        "schema_version": 1,
        "generated_at": generated_at,
        "profile": profile,
        "revision": revision,
        "verdict": verdict,
        "results": [asdict(item) for item in safe_results],
    }
    json_path = report_dir / "acceptance.json"
    markdown_path = report_dir / "acceptance.md"
    _atomic_write(json_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    rows = [
        "# Enterprise Acceptance Evidence",
        "",
        f"- Generated: `{generated_at}`",
        f"- Revision: `{revision}`",
        f"- Profile: `{profile}`",
        f"- Verdict: **{verdict}**",
        "",
        "| Gate | Severity | Status | Duration | Summary |",
        "|---|---|---|---:|---|",
    ]
    for item in safe_results:
        summary = item.summary.replace("|", "\\|").replace("\r", " ").replace("\n", " ")
        rows.append(
            f"| `{item.gate_id}` | {item.severity} | {item.status} | "
            f"{item.duration_seconds:.2f}s | {summary} |"
        )
    _atomic_write(markdown_path, "\n".join(rows) + "\n")
    return json_path, markdown_path


def _revision(repository: Path) -> str:
    completed = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run redacted enterprise acceptance gates")
    parser.add_argument("--profile", choices=("local", "ci"), default="local")
    parser.add_argument("--report-dir", type=Path, default=Path("artifacts/acceptance"))
    arguments = parser.parse_args(argv)

    gates = build_profile(arguments.profile)
    results: list[AcceptanceResult] = []
    for gate in gates:
        result = run_gate(gate)
        results.append(result)
        print(f"{result.gate_id}: {result.status} ({result.duration_seconds:.2f}s)")

    repository = Path(__file__).resolve().parents[1]
    json_path, markdown_path = write_reports(
        results,
        report_dir=arguments.report_dir,
        profile=arguments.profile,
        revision=_revision(repository),
    )
    verdict = calculate_verdict(results)
    print(f"verdict={verdict}")
    print(f"json_report={json_path}")
    print(f"markdown_report={markdown_path}")
    return {"PASS": 0, "CONDITIONAL": 2, "FAIL": 1}[verdict]


if __name__ == "__main__":
    sys.exit(main())
