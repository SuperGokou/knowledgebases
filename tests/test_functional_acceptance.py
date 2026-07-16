from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import scripts.functional_acceptance as functional_acceptance
from scripts.acceptance import build_profile, collect_worktree_evidence
from scripts.functional_acceptance import (
    AcceptanceGateError,
    ContractError,
    ExternalEvidenceReport,
    ExternalTrustContext,
    _consume_challenge_once,
    _payload,
    _signature_payload,
    _vitest_collected_nodes,
    evaluate_contract,
    evaluate_external_evidence,
    load_manifest,
    main,
    policy_digest,
    run_test_commands,
)

REPOSITORY = Path(__file__).resolve().parents[1]
MANIFEST = REPOSITORY / "docs/functional_acceptance_manifest.json"


def test_vitest_collection_rejects_duplicate_machine_nodes(tmp_path: Path) -> None:
    test_file = tmp_path / "duplicate-title.test.ts"
    report = tmp_path / "vitest-collection.json"
    report.write_text(
        json.dumps(
            [
                {"file": str(test_file), "name": "suite > duplicate case"},
                {"file": str(test_file), "name": "suite > duplicate case"},
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(AcceptanceGateError, match="duplicate tests"):
        _vitest_collected_nodes(report, tmp_path)


def _canonical_evidence_digest(document: dict[str, object]) -> str:
    bound = {
        key: document.get(key)
        for key in (
            "schema_version",
            "evidence_id",
            "status",
            "collector",
            "target",
            "collected_at",
            "artifacts",
            "checks",
        )
    }
    return hashlib.sha256(
        json.dumps(
            bound,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _minimal_manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "requirements": [
            {
                "id": "FUNC-AUTH-001",
                "title": "统一登录与角色路由",
                "severity": "P0",
                "blocking": True,
                "preconditions": ["存在可登录账户"],
                "steps": ["登录"],
                "expected_results": ["按权限进入工作区"],
                "evidence": [
                    {
                        "kind": "route",
                        "path": "app/api/v1/routes/auth.py",
                        "contains": ['@router.post("/token"'],
                    },
                    {
                        "kind": "automated_test",
                        "path": "tests/test_integration_api.py",
                        "contains": ["test_admin_role_user_and_refresh_workflow"],
                        "runner": "backend-functional",
                        "status": "active",
                    },
                ],
            }
        ],
        "test_commands": [
            {
                "id": "backend-functional",
                "cwd": ".",
                "command": ["python", "-m", "pytest", "-q", "tests/test_integration_api.py"],
                "framework": "pytest",
                "required_test_nodes": ["tests/test_integration_api.py"],
                "minimum_passed_tests": 2,
                "covers": ["FUNC-AUTH-001"],
                "forbid_skips": True,
            }
        ],
        "external_evidence": [
            {
                "id": "EXT-BROWSER-E2E-001",
                "title": "完整浏览器业务链",
                "severity": "P0",
                "required_for": "runtime-functional",
                "path": "artifacts/functional-acceptance/browser-e2e.json",
                "required_checks": ["login_role_routing"],
                "evidence_schema_version": 2,
                "collector": {
                    "id": "heyi-browser-e2e",
                    "version": "1.0.0",
                },
                "max_age_seconds": 3600,
            }
        ],
    }


def test_repository_manifest_is_complete_and_source_contract_passes() -> None:
    manifest = load_manifest(MANIFEST)

    report = evaluate_contract(REPOSITORY, manifest)

    assert report.verdict == "PASS"
    assert report.failed == 0
    assert report.requirement_count >= 14
    assert {
        "FUNC-AUTH-001",
        "FUNC-ACCOUNT-001",
        "FUNC-RBAC-001",
        "FUNC-LIMIT-001",
        "FUNC-KB-ACL-001",
        "FUNC-FILE-001",
        "FUNC-CHAT-001",
        "FUNC-MODEL-001",
        "FUNC-APIKEY-001",
        "FUNC-AUDIT-001",
        "FUNC-UXSTATE-001",
        "FUNC-HEALTH-001",
        "FUNC-OFFLINE-001",
        "FUNC-FORMAT-001",
    } <= {item.requirement_id for item in report.requirements}


def test_repository_backend_runner_uses_the_bound_python_environment() -> None:
    manifest = load_manifest(MANIFEST)
    backend = next(
        item
        for item in manifest["test_commands"]
        if item["id"] == "backend-functional"  # type: ignore[index]
    )

    assert backend["command"][:3] == ["python", "-m", "pytest"]


def test_python_runner_resolves_to_the_acceptance_interpreter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["args"] = args[0]
        captured.update(kwargs)
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    functional_acceptance._execute(("python", "-m", "pytest"), REPOSITORY, 30)

    assert captured["args"] == [functional_acceptance.sys.executable, "-m", "pytest"]


def test_repository_policy_digest_is_stable_and_manifest_cannot_drop_required_id() -> None:
    manifest = load_manifest(MANIFEST)
    manifest["requirements"] = [
        item
        for item in manifest["requirements"]
        if item["id"] != "FUNC-OFFLINE-001"  # type: ignore[index]
    ]

    report = evaluate_contract(REPOSITORY, manifest)

    assert len(policy_digest(REPOSITORY)) == 64
    assert report.policy_sha256 == policy_digest(REPOSITORY)
    assert report.verdict == "FAIL"
    assert any("required requirement ids" in item.summary for item in report.requirements)


def test_repository_manifest_cannot_remove_standard_to_bypass_policy() -> None:
    manifest = load_manifest(MANIFEST)
    manifest.pop("standard")
    manifest["requirements"] = manifest["requirements"][:1]  # type: ignore[index]

    report = evaluate_contract(REPOSITORY, manifest)

    assert report.verdict == "FAIL"
    assert report.requirements[0].requirement_id == "TRUSTED-POLICY"
    assert "trusted acceptance standard" in report.requirements[0].summary


def test_repository_policy_rejects_rebinding_all_requirements_to_one_test() -> None:
    manifest = load_manifest(MANIFEST)
    backend = next(
        item
        for item in manifest["test_commands"]
        if item["id"] == "backend-functional"  # type: ignore[index]
    )
    single_node = "tests/test_functional_acceptance.py::test_empty_requirements_fail_closed"
    backend["required_test_nodes"] = [single_node]
    backend["command"] = ["uv", "run", "pytest", "-rA", single_node]
    backend["minimum_passed_tests"] = 1
    backend["covers"] = [item["id"] for item in manifest["requirements"]]  # type: ignore[index]
    for requirement in manifest["requirements"]:  # type: ignore[index]
        for evidence in requirement["evidence"]:
            if evidence["kind"] == "automated_test":
                evidence["path"] = "tests/test_functional_acceptance.py"
                evidence["contains"] = ["test_empty_requirements_fail_closed"]
                evidence["runner"] = "backend-functional"

    report = evaluate_contract(REPOSITORY, manifest)

    assert report.verdict == "FAIL"
    assert any("trusted runner policy" in item.summary for item in report.requirements)


def test_repository_manifest_binds_all_document_formats_to_active_parser_tests() -> None:
    manifest = load_manifest(MANIFEST)
    requirements = {
        item["id"]: item
        for item in manifest["requirements"]  # type: ignore[index]
    }
    format_requirement = requirements["FUNC-FORMAT-001"]
    expected_extensions = {
        ".txt",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".csv",
        ".pdf",
        ".ppt",
        ".pptx",
    }
    declared_results = " ".join(format_requirement["expected_results"])
    assert all(extension in declared_results for extension in expected_extensions)

    backend = next(
        item
        for item in manifest["test_commands"]
        if item["id"] == "backend-functional"  # type: ignore[index]
    )
    assert "FUNC-FORMAT-001" in backend["covers"]
    assert {
        "tests/test_document_parser.py",
        "tests/test_document_parser_preflight.py",
        "tests/test_okf_document_pipeline.py",
    } <= set(backend["required_test_nodes"])


def test_repository_manifest_binds_new_enterprise_lifecycle_and_recovery_checks() -> None:
    manifest = load_manifest(MANIFEST)
    runners = {
        item["id"]: item
        for item in manifest["test_commands"]  # type: ignore[index]
    }

    backend = runners["backend-functional"]
    assert backend["minimum_passed_tests"] == 434
    assert {
        "tests/test_user_retirement.py",
        "tests/test_user_retirement_migration.py",
        "tests/test_user_activity_locking.py",
        "tests/test_legacy_offline_adoption.py",
        "tests/test_offline_adoption_transaction.py",
        "tests/test_offline_crash_recovery.py",
        "tests/test_offline_pre_migration_abort.py",
        "tests/test_legacy_adoption_document_contract.py",
        "tests/test_linux_host_evidence_collector.py",
    } <= set(backend["required_test_nodes"])

    frontend = runners["frontend-functional"]
    assert frontend["minimum_passed_tests"] == 182
    assert "FUNC-AUDIT-001" in frontend["covers"]
    assert {
        "tests/user-retirement.test.ts",
        "tests/audit-log-console.test.ts",
        "tests/file-approval.test.ts",
    } <= set(frontend["required_test_nodes"])

    postgres = manifest["internal_gate_bindings"][0]  # type: ignore[index]
    assert {
        "user_retirement_linearization",
        "last_superuser_linearization",
        "api_key_retirement_linearization",
    } <= set(postgres["required_checks"])

    external = {
        item["id"]: item
        for item in manifest["external_evidence"]  # type: ignore[index]
    }
    browser = external["EXT-BROWSER-E2E-001"]
    assert browser["collection"]["expected_collected_tests"] == 26
    assert {
        "audit_log_query_export",
        "tls_validity_and_renewal",
    } <= set(browser["required_checks"])
    assert "tls_expiry_30d" not in browser["required_checks"]
    assert {
        "caddy_ca_persistent_storage",
        "caddy_automatic_certificate_management",
        "caddy_renewal_health",
    } <= set(external["EXT-LINUX-HOST-001"]["required_checks"])


def test_blocking_requirement_fails_closed_on_skipped_test(tmp_path: Path) -> None:
    manifest = _minimal_manifest()
    test_evidence = manifest["requirements"][0]["evidence"][1]  # type: ignore[index]
    test_evidence["status"] = "skipped"  # type: ignore[index]

    report = evaluate_contract(REPOSITORY, manifest, enforce_policy=False)

    assert report.verdict == "FAIL"
    assert report.failed == 1
    assert "active automated test" in report.requirements[0].summary


@pytest.mark.parametrize(
    "unsafe_path",
    ["../outside.py", ".env", "deploy/tencent/offline.env"],
)
def test_evidence_paths_cannot_escape_or_read_environment_files(unsafe_path: str) -> None:
    manifest = _minimal_manifest()
    evidence = manifest["requirements"][0]["evidence"][0]  # type: ignore[index]
    evidence["path"] = unsafe_path  # type: ignore[index]

    report = evaluate_contract(REPOSITORY, manifest, enforce_policy=False)

    assert report.verdict == "FAIL"
    assert "unsafe evidence path" in report.requirements[0].summary


def test_missing_literal_evidence_fails_closed() -> None:
    manifest = _minimal_manifest()
    evidence = manifest["requirements"][0]["evidence"][0]  # type: ignore[index]
    evidence["contains"] = ["definitely-not-present"]  # type: ignore[index]

    report = evaluate_contract(REPOSITORY, manifest, enforce_policy=False)

    assert report.verdict == "FAIL"
    assert "missing literal evidence" in report.requirements[0].summary


def test_empty_requirements_fail_closed() -> None:
    manifest = _minimal_manifest()
    manifest["requirements"] = []

    report = evaluate_contract(REPOSITORY, manifest, enforce_policy=False)

    assert report.verdict == "FAIL"
    assert report.failed == 1
    assert "non-empty requirements" in report.requirements[0].summary


def test_empty_test_commands_fail_closed() -> None:
    manifest = _minimal_manifest()
    manifest["test_commands"] = []

    report = evaluate_contract(REPOSITORY, manifest, enforce_policy=False)
    runtime = run_test_commands(REPOSITORY, manifest, enforce_policy=False)

    assert report.verdict == "FAIL"
    assert "non-empty" in report.requirements[0].summary
    assert runtime[0].status == "failed"


def test_empty_external_evidence_fails_closed() -> None:
    manifest = _minimal_manifest()
    manifest["external_evidence"] = []

    report = evaluate_external_evidence(REPOSITORY, manifest, enforce_policy=False)

    assert report.verdict == "BLOCKED"
    assert report.results[0].status == "blocked"
    assert "non-empty" in report.results[0].summary


def test_repository_policy_rejects_deleting_one_required_external_evidence() -> None:
    manifest = load_manifest(MANIFEST)
    manifest["external_evidence"] = manifest["external_evidence"][:-1]  # type: ignore[index]

    report = evaluate_external_evidence(REPOSITORY, manifest)

    assert report.verdict == "BLOCKED"
    assert "exact required external evidence ids" in report.results[0].summary


def test_repository_policy_rejects_browser_collection_contract_tampering() -> None:
    manifest = load_manifest(MANIFEST)
    browser = next(
        item
        for item in manifest["external_evidence"]
        if item["id"] == "EXT-BROWSER-E2E-001"  # type: ignore[index]
    )
    browser["collection"]["expected_collected_tests"] = 2  # type: ignore[index]

    report = evaluate_contract(REPOSITORY, manifest)

    assert report.verdict == "FAIL"
    assert any("external test collections" in item.summary for item in report.requirements)


def test_runner_is_bound_to_declared_test_nodes() -> None:
    manifest = _minimal_manifest()
    command = manifest["test_commands"][0]  # type: ignore[index]
    command["command"] = [  # type: ignore[index]
        "python",
        "-m",
        "pytest",
        "-q",
        "tests/test_functional_acceptance.py",
    ]

    report = evaluate_contract(REPOSITORY, manifest, enforce_policy=False)

    assert report.verdict == "FAIL"
    assert "required test nodes" in report.requirements[0].summary


def test_runner_rejects_selection_filters_in_the_manifest() -> None:
    manifest = _minimal_manifest()
    command = manifest["test_commands"][0]  # type: ignore[index]
    command["command"] = [  # type: ignore[index]
        "python",
        "-m",
        "pytest",
        "-k",
        "only_one_test",
        "tests/test_integration_api.py",
    ]

    result = run_test_commands(REPOSITORY, manifest, enforce_policy=False)[0]

    assert result.status == "failed"
    assert "forbidden selection controls" in result.summary


def test_runner_rejects_a_junit_report_missing_one_collected_case() -> None:
    manifest = _minimal_manifest()

    def incomplete_executor(
        command: list[str] | tuple[str, ...], _cwd: Path, _timeout: int
    ) -> subprocess.CompletedProcess[str]:
        if "--collect-only" in command:
            output = "\n".join(
                (
                    "tests/test_integration_api.py::test_first",
                    "tests/test_integration_api.py::test_second",
                    "2 tests collected in 0.01s",
                )
            )
            return subprocess.CompletedProcess(command, 0, output, "")
        junit_argument = next(item for item in command if item.startswith("--junitxml="))
        Path(junit_argument.split("=", 1)[1]).write_text(
            "<testsuites><testsuite><testcase "
            'classname="tests.test_integration_api" name="test_first" />'
            "</testsuite></testsuites>",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "1 passed", "")

    result = run_test_commands(
        REPOSITORY,
        manifest,
        enforce_policy=False,
        executor=incomplete_executor,
    )[0]

    assert result.status == "failed"
    assert "exact collected test set" in result.summary


def test_unrelated_one_pass_output_cannot_satisfy_runner_minimum() -> None:
    manifest = _minimal_manifest()

    results = run_test_commands(
        REPOSITORY,
        manifest,
        enforce_policy=False,
        executor=lambda command, _cwd, _timeout: subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="1 passed",
            stderr="",
        ),
    )

    assert results[0].status == "failed"
    assert results[0].passed_tests == 0
    assert "machine-readable per-node report" in results[0].summary


def test_real_runner_emits_hashed_per_node_machine_artifact() -> None:
    manifest = _minimal_manifest()
    command = manifest["test_commands"][0]  # type: ignore[index]
    node = "tests/test_functional_acceptance.py::test_empty_requirements_fail_closed"
    command["command"] = ["python", "-m", "pytest", "-q", node]
    command["required_test_nodes"] = [node]
    command["minimum_passed_tests"] = 1

    result = run_test_commands(REPOSITORY, manifest, enforce_policy=False)[0]

    assert result.status == "passed"
    assert result.verified_nodes == 1
    assert result.machine_artifact is not None
    artifact = Path(result.machine_artifact)
    assert artifact.is_file()
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == result.machine_artifact_sha256
    document = json.loads(artifact.read_text(encoding="utf-8"))
    assert document["target"]["git_head"]
    assert document["target"]["content_fingerprint"]
    assert len(document["target"]["run_nonce"]) >= 32
    assert document["environment"]["dependency_lock_sha256"]
    assert document["machine_execution"]["collected"] == 1
    assert document["machine_execution"]["node_ids"] == [node]
    assert document["required_nodes"] == [
        {
            "node": node,
            "status": "passed",
            "cases": 1,
            "failed": 0,
            "skipped": 0,
        }
    ]
    assert document["result_hash"] == result.result_hash
    claimed_result_hash = document.pop("result_hash")
    assert (
        claimed_result_hash
        == hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def test_final_profile_marks_missing_external_evidence_as_blocked(tmp_path: Path) -> None:
    manifest = _minimal_manifest()

    report = evaluate_external_evidence(tmp_path, manifest, enforce_policy=False)

    assert report.verdict == "BLOCKED"
    assert report.results[0].status == "blocked"
    assert "not available" in report.results[0].summary


def test_external_evidence_requires_every_named_check(tmp_path: Path) -> None:
    manifest = _minimal_manifest()
    evidence_path = tmp_path / "artifacts/functional-acceptance/browser-e2e.json"
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_text(
        json.dumps({"schema_version": 2, "status": "complete", "checks": {}}),
        encoding="utf-8",
    )

    report = evaluate_external_evidence(tmp_path, manifest, enforce_policy=False)

    assert report.verdict == "BLOCKED"
    assert report.results[0].status == "blocked"


def test_handwritten_passed_checks_are_not_trusted_external_evidence(tmp_path: Path) -> None:
    manifest = _minimal_manifest()
    evidence_path = tmp_path / "artifacts/functional-acceptance/browser-e2e.json"
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "evidence_id": "EXT-BROWSER-E2E-001",
                "status": "complete",
                "checks": {"login_role_routing": {"status": "passed"}},
            }
        ),
        encoding="utf-8",
    )

    report = evaluate_external_evidence(tmp_path, manifest, enforce_policy=False)

    assert report.verdict == "BLOCKED"
    assert report.results[0].status == "blocked"
    assert "provenance" in report.results[0].summary


def test_fresh_signed_challenged_external_evidence_passes_and_replay_blocks(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir(parents=True)
    (repository / ".gitignore").write_text("artifacts/acceptance/\n", encoding="utf-8")
    (repository / "application.txt").write_text("release candidate\n", encoding="utf-8")
    for arguments in (
        ("init", "-q"),
        ("config", "user.email", "acceptance@example.invalid"),
        ("config", "user.name", "Acceptance Test"),
        ("add", ".gitignore", "application.txt"),
        ("commit", "-q", "-m", "test fixture"),
    ):
        subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
        )

    manifest = _minimal_manifest()
    contract = manifest["external_evidence"][0]  # type: ignore[index]
    contract["path"] = "artifacts/acceptance/functional/browser-e2e.json"  # type: ignore[index]
    evidence_path = repository / str(contract["path"])  # type: ignore[index]
    raw_path = evidence_path.parent / "raw/browser-result.json"
    raw_path.parent.mkdir(parents=True)
    raw_content = b'{"browser":"passed"}\n'
    raw_path.write_bytes(raw_content)
    identity = collect_worktree_evidence(repository)
    run_id = "acceptance-functional-test-001"
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
        "checks": {
            "login_role_routing": {
                "status": "passed",
                "artifact_ids": ["browser-result"],
            }
        },
    }
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    challenge_id = "challenge-browser-001"
    challenge_nonce = base64.b64encode(b"unpredictable-test-challenge-0001").decode()
    key_id = "test-browser-key"
    document["attestation"] = {
        "type": "sha256-chain-v1",
        "digest": _canonical_evidence_digest(document),
    }
    evidence_path.write_text(json.dumps(document), encoding="utf-8")
    unsigned_context = ExternalTrustContext(
        public_keys={("heyi-browser-e2e", key_id): public_key},
        challenges={
            challenge_id: {
                "status": "issued",
                "evidence_id": "EXT-BROWSER-E2E-001",
                "nonce": challenge_nonce,
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
    unsigned = evaluate_external_evidence(
        repository,
        manifest,
        trust_context=unsigned_context,
        enforce_policy=False,
    )

    document["attestation"] = {
        "type": "ed25519-challenge-v1",
        "key_id": key_id,
        "challenge_id": challenge_id,
        "challenge_nonce": challenge_nonce,
        "signature": base64.b64encode(
            private_key.sign(
                _signature_payload(
                    document,
                    key_id=key_id,
                    challenge_id=challenge_id,
                    challenge_nonce=challenge_nonce,
                )
            )
        ).decode(),
    }
    evidence_path.write_text(json.dumps(document), encoding="utf-8")

    context = ExternalTrustContext(
        public_keys={("heyi-browser-e2e", key_id): public_key},
        challenges={
            challenge_id: {
                "status": "issued",
                "evidence_id": "EXT-BROWSER-E2E-001",
                "nonce": challenge_nonce,
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

    accepted = evaluate_external_evidence(
        repository, manifest, trust_context=context, enforce_policy=False
    )
    replayed = evaluate_external_evidence(
        repository, manifest, trust_context=context, enforce_policy=False
    )

    assert unsigned.verdict == "BLOCKED"
    assert accepted.verdict == "PASS"
    assert accepted.results[0].status == "passed"
    assert replayed.verdict == "BLOCKED"
    assert replayed.results[0].status == "blocked"


def _generic_external_report(
    tmp_path: Path,
    *,
    challenge_run_id: str,
    extra_target_field: bool = False,
) -> ExternalEvidenceReport:
    repository = tmp_path / "generic-repository"
    repository.mkdir(parents=True)
    (repository / ".gitignore").write_text("artifacts/acceptance/\n", encoding="utf-8")
    (repository / "application.txt").write_text("release candidate\n", encoding="utf-8")
    for arguments in (
        ("init", "-q"),
        ("config", "user.email", "acceptance@example.invalid"),
        ("config", "user.name", "Acceptance Test"),
        ("add", ".gitignore", "application.txt"),
        ("commit", "-q", "-m", "test fixture"),
    ):
        subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
        )
    evidence_path = repository / "artifacts/acceptance/functional/linux-host.json"
    raw_path = evidence_path.parent / "raw/host.json"
    raw_path.parent.mkdir(parents=True)
    raw = b'{"host":"passed"}\n'
    raw_path.write_bytes(raw)
    identity = collect_worktree_evidence(repository)
    run_id = "linux-host-target-001"
    target: dict[str, object] = {
        "git_head": identity.git_head,
        "content_fingerprint": identity.content_fingerprint,
        "run_id": run_id,
    }
    if extra_target_field:
        target["operator"] = "untrusted"
    document: dict[str, object] = {
        "schema_version": 2,
        "evidence_id": "EXT-LINUX-HOST-001",
        "status": "complete",
        "collector": {"id": "heyi-linux-host", "version": "1.0.0"},
        "target": target,
        "collected_at": datetime.now(UTC).isoformat(),
        "artifacts": [
            {
                "id": "host",
                "path": "raw/host.json",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
            }
        ],
        "checks": {"linux_amd64": {"status": "passed", "artifact_ids": ["host"]}},
    }
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    challenge_id = "challenge-linux-host-001"
    nonce = "n" * 40
    key_id = "linux-host-ed25519"
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
    evidence_path.write_text(json.dumps(document), encoding="utf-8")
    manifest = {
        "external_evidence": [
            {
                "id": "EXT-LINUX-HOST-001",
                "path": "artifacts/acceptance/functional/linux-host.json",
                "required_checks": ["linux_amd64"],
                "evidence_schema_version": 2,
                "collector": {"id": "heyi-linux-host", "version": "1.0.0"},
                "max_age_seconds": 3600,
            }
        ]
    }
    context = ExternalTrustContext(
        public_keys={("heyi-linux-host", key_id): public_key},
        challenges={
            challenge_id: {
                "status": "issued",
                "evidence_id": "EXT-LINUX-HOST-001",
                "nonce": nonce,
                "target": {
                    "git_head": identity.git_head,
                    "content_fingerprint": identity.content_fingerprint,
                    "run_id": challenge_run_id,
                },
                "issued_at": datetime.now(UTC).isoformat(),
                "expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
            }
        },
        consumed_challenges=set(),
    )
    return evaluate_external_evidence(
        repository,
        manifest,
        trust_context=context,
        enforce_policy=False,
    )


def test_all_external_evidence_requires_exact_run_bound_challenge_target(
    tmp_path: Path,
) -> None:
    matching = _generic_external_report(
        tmp_path / "matching",
        challenge_run_id="linux-host-target-001",
    )
    mismatched = _generic_external_report(
        tmp_path / "mismatched",
        challenge_run_id="different-linux-run-001",
    )
    extra_target = _generic_external_report(
        tmp_path / "extra",
        challenge_run_id="linux-host-target-001",
        extra_target_field=True,
    )

    assert matching.verdict == "PASS"
    assert mismatched.verdict == "BLOCKED"
    assert extra_target.verdict == "BLOCKED"


def test_challenge_consume_is_noreplace_and_fsyncs_directory() -> None:
    events: list[object] = []
    with (
        patch.object(functional_acceptance.os, "open", return_value=91),
        patch.object(
            functional_acceptance.os,
            "link",
            side_effect=lambda *args, **kwargs: events.append(("link", args, kwargs)),
        ),
        patch.object(
            functional_acceptance.os,
            "fsync",
            side_effect=lambda descriptor: events.append(("fsync", descriptor)),
        ),
        patch.object(
            functional_acceptance.os,
            "unlink",
            side_effect=lambda *args, **kwargs: events.append(("unlink", args, kwargs)),
        ),
        patch.object(functional_acceptance.os, "close", return_value=None),
    ):
        assert _consume_challenge_once(Path("/trust/challenge-linux-host-001.json"))

    assert [event[0] for event in events] == ["link", "fsync", "unlink", "fsync"]
    link_event = events[0]
    assert isinstance(link_event, tuple)
    assert link_event[2]["follow_symlinks"] is False


def test_challenge_consume_crash_marker_blocks_overwrite_and_preserves_source() -> None:
    unlinks: list[object] = []
    with (
        patch.object(functional_acceptance.os, "open", return_value=92),
        patch.object(functional_acceptance.os, "link", return_value=None),
        patch.object(functional_acceptance.os, "fsync", side_effect=OSError("crash")),
        patch.object(functional_acceptance.os, "unlink", side_effect=unlinks.append),
        patch.object(functional_acceptance.os, "close", return_value=None),
    ):
        assert not _consume_challenge_once(Path("/trust/challenge-linux-host-001.json"))
    assert unlinks == []

    with (
        patch.object(functional_acceptance.os, "open", return_value=93),
        patch.object(functional_acceptance.os, "link", side_effect=FileExistsError),
        patch.object(functional_acceptance.os, "unlink") as unlink,
        patch.object(functional_acceptance.os, "close", return_value=None),
    ):
        assert not _consume_challenge_once(Path("/trust/challenge-linux-host-001.json"))
        unlink.assert_not_called()


def test_current_sha_chain_without_trusted_signature_is_blocked(tmp_path: Path) -> None:
    manifest = _minimal_manifest()
    evidence_path = tmp_path / "artifacts/functional-acceptance/browser-e2e.json"
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "evidence_id": "EXT-BROWSER-E2E-001",
                "status": "complete",
                "collector": {"id": "heyi-browser-e2e", "version": "1.0.0"},
                "attestation": {"type": "sha256-chain-v1", "digest": "0" * 64},
            }
        ),
        encoding="utf-8",
    )

    report = evaluate_external_evidence(tmp_path, manifest, enforce_policy=False)

    assert report.verdict == "BLOCKED"


def test_manifest_loader_rejects_non_object_json(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("[]", encoding="utf-8")

    with pytest.raises(ContractError, match="JSON object"):
        load_manifest(manifest_path)


def test_enterprise_acceptance_profile_runs_functional_source_gate() -> None:
    by_id = {gate.gate_id: gate for gate in build_profile("local")}

    gate = by_id["FUNCTIONAL-P0-001"]
    assert Path(gate.command[1]).name == "functional_acceptance.py"
    assert gate.command[-2:] == ("--run-tests", "--json")


def test_source_without_runtime_tests_is_unverified() -> None:
    manifest = _minimal_manifest()
    contract = evaluate_contract(REPOSITORY, manifest, enforce_policy=False)

    payload = _payload(
        contract,
        ExternalEvidenceReport("PASS", ()),
        (),
        "source",
    )

    assert payload["source_verdict"] == "UNVERIFIED"
    assert payload["runtime_functional_verdict"] == "BLOCKED"
    assert payload["verdict"] == "UNVERIFIED"
    assert "final_verdict" not in payload


def test_failed_source_contract_propagates_fail_to_runtime_verdict() -> None:
    manifest = _minimal_manifest()
    manifest["requirements"] = []
    contract = evaluate_contract(REPOSITORY, manifest, enforce_policy=False)

    payload = _payload(
        contract,
        ExternalEvidenceReport("PASS", ()),
        (),
        "runtime-functional",
    )

    assert payload["source_verdict"] == "FAIL"
    assert payload["runtime_functional_verdict"] == "FAIL"
    assert payload["verdict"] == "FAIL"


def test_runtime_functional_cli_never_outputs_an_enterprise_final_verdict(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["--profile", "runtime-functional", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert payload["profile"] == "runtime-functional"
    assert payload["source_verdict"] == "UNVERIFIED"
    assert payload["runtime_functional_verdict"] == "BLOCKED"
    assert payload["verdict"] == "BLOCKED"
    assert "final_verdict" not in payload


def test_functional_cli_writes_nonce_bound_machine_evidence(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence_path = tmp_path / "functional.json"

    exit_code = main(
        [
            "--profile",
            "runtime-functional",
            "--json",
            "--evidence-file",
            str(evidence_path),
        ]
    )
    printed = json.loads(capsys.readouterr().out)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

    assert exit_code == 2
    assert evidence == printed
    assert evidence["schema_version"] == 2
    assert evidence["kind"] == "functional-acceptance"
    assert evidence["status"] == "failed"
    assert evidence["policy_status"] == "failed"
    assert evidence["target"]["git_head"]
    assert len(evidence["target"]["content_fingerprint"]) == 64
    assert len(evidence["target"]["run_nonce"]) >= 32


def test_legacy_functional_final_profile_is_rejected() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--profile", "final", "--json"])

    assert exc_info.value.code == 2


def test_runtime_skip_in_critical_command_fails_closed() -> None:
    manifest = _minimal_manifest()

    results = run_test_commands(
        REPOSITORY,
        manifest,
        enforce_policy=False,
        executor=lambda _command, _cwd, _timeout: subprocess.CompletedProcess(
            args=["pytest"],
            returncode=0,
            stdout="1 passed, 1 skipped",
            stderr="",
        ),
    )

    assert results[0].status == "failed"
    assert results[0].passed_tests == 0
    assert "machine-readable per-node report" in results[0].summary
