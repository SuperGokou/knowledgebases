from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from scripts.collect_offline_runtime_evidence import (
    EXECUTION_CONFIRMATION,
    REQUIRED_COMMAND_STEPS,
    CollectionBlocked,
    CommandResult,
    ExecutionContext,
    build_plan,
    canonical_digest,
    execute_collection,
    main,
    public_remote_endpoints,
)


@dataclass
class FakeRunner:
    challenge: str
    tenant: str
    fail_step: str | None = None
    calls: list[str] = field(default_factory=list)

    def run(self, step_id: str, argv: tuple[str, ...], timeout_seconds: int) -> CommandResult:
        del argv, timeout_seconds
        self.calls.append(step_id)
        if step_id == self.fail_step:
            return CommandResult(1, "", "deliberate failure")
        if step_id.endswith("dns_external"):
            return CommandResult(2, "", "resolution blocked")
        if step_id.endswith("containers"):
            return CommandResult(0, "container-1\n", "")
        if "container_pid" in step_id:
            return CommandResult(0, "4242\n", "")
        if "container_netns" in step_id:
            return CommandResult(0, "net:[123456]\n", "")
        if step_id.endswith("networks"):
            return CommandResult(0, "network-1\n", "")
        if step_id.endswith("network_inspect"):
            return CommandResult(0, '[{"Name":"internal","Internal":true}]\n', "")
        if step_id.startswith("probe_"):
            return CommandResult(0, "", "")
        return CommandResult(
            0,
            json.dumps(
                {
                    "status": "passed",
                    "check": step_id,
                    "challenge": self.challenge,
                    "test_tenant": self.tenant,
                    "observations": {"verified": True},
                }
            ),
            "",
        )


def _context(tmp_path: Path) -> ExecutionContext:
    challenge = "round2-offline-challenge-0123456789"
    tenant = "kb-acceptance-round2"
    commands = {
        step: {
            "argv": [f"/opt/heyi-acceptance/{step}", challenge, tenant],
            "timeout_seconds": 30,
        }
        for step in REQUIRED_COMMAND_STEPS
    }
    return ExecutionContext(
        challenge=challenge,
        test_tenant=tenant,
        project_name="heyi-kb-acceptance",
        git_head="a" * 40,
        content_fingerprint="b" * 64,
        host_fingerprint="c" * 64,
        commands=commands,
        output_dir=tmp_path / "evidence",
    )


def test_default_mode_only_prints_plan_and_never_runs_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "planned"
    assert payload["mutating"] is False
    assert payload["required_command_steps"] == list(REQUIRED_COMMAND_STEPS)
    assert payload["execute_confirmation"] == EXECUTION_CONFIRMATION


def test_plan_covers_every_required_network_and_business_check() -> None:
    plan = build_plan()

    assert set(plan["network_evidence"]) == {
        "host_and_container_public_sockets",
        "dns_resolution_path",
        "default_and_all_routes",
        "host_and_container_network_namespaces",
        "firewall_ruleset",
        "compose_internal_networks",
    }
    assert set(plan["business_checks"]) >= {
        "login",
        "rbac",
        "acl",
        "upload",
        "approval",
        "download",
        "question_answer",
        "persistence_verify",
    }


def test_public_socket_parser_only_returns_globally_routable_peers() -> None:
    output = "\n".join(
        (
            "tcp ESTAB 0 0 10.0.0.2:443 8.8.8.8:53000 users:((x))",
            "tcp ESTAB 0 0 127.0.0.1:5432 127.0.0.1:41100 users:((x))",
            "udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:((x))",
            "tcp ESTAB 0 0 [fd00::2]:443 [fd00::3]:50000 users:((x))",
        )
    )

    assert public_remote_endpoints(output) == ["8.8.8.8:53000"]


def test_successful_fake_orchestration_writes_hashed_attested_evidence(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    runner = FakeRunner(context.challenge, context.test_tenant)

    document = execute_collection(context, runner=runner)

    assert document["status"] == "complete"
    assert document["result"] == "test-only"
    assert document["runner"] == "test-double"
    assert runner.calls.index("rollback_arm") < runner.calls.index("network_disconnect")
    assert runner.calls.index("network_restore") < runner.calls.index("rollback_cancel")
    assert set(document["checks"]) >= {
        "offline_network_isolation",
        "login",
        "rbac",
        "acl",
        "upload",
        "approval",
        "download",
        "question_answer",
        "restart_persistence",
    }
    for artifact in document["artifacts"]:
        path = context.output_dir / artifact["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == artifact["sha256"]
        assert path.stat().st_size == artifact["bytes"]
    assert document["attestation"]["digest"] == canonical_digest(
        {key: value for key, value in document.items() if key != "attestation"}
    )


def test_business_failure_always_restores_network_and_is_blocked(tmp_path: Path) -> None:
    context = _context(tmp_path)
    runner = FakeRunner(context.challenge, context.test_tenant, fail_step="approval")

    with pytest.raises(CollectionBlocked, match="approval"):
        execute_collection(context, runner=runner)

    assert "network_restore" in runner.calls
    assert "rollback_cancel" in runner.calls
    assert "recovery_verify" in runner.calls


def test_restore_failure_can_never_create_pass_evidence(tmp_path: Path) -> None:
    context = _context(tmp_path)
    runner = FakeRunner(context.challenge, context.test_tenant, fail_step="network_restore")

    with pytest.raises(CollectionBlocked, match="restore"):
        execute_collection(context, runner=runner)

    assert not (context.output_dir / "offline-runtime-evidence.json").exists()


def test_fake_runner_output_is_explicitly_rejected_by_formal_schema(tmp_path: Path) -> None:
    context = _context(tmp_path)
    document = execute_collection(
        context, runner=FakeRunner(context.challenge, context.test_tenant)
    )
    schema_path = (
        Path(__file__).parents[1]
        / "docs"
        / "schemas"
        / "offline-runtime-evidence-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert document["result"] == "test-only"
    assert document["result"] != schema["properties"]["result"]["const"]
    assert document["runner"] != schema["properties"]["runner"]["const"]


def test_execute_mode_is_fail_closed_before_any_command_without_full_guard(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "scripts.collect_offline_runtime_evidence.platform.system", lambda: "Windows"
    )

    result = main(["--execute", "--confirmation", EXECUTION_CONFIRMATION])

    assert result == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "collector": "heyi-offline-runtime",
        "result": "blocked",
        "schema_version": 1,
        "status": "complete",
    }
