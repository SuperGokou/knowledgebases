from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from scripts.acceptance_gate import (
    AcceptanceGateError,
    GateIdentity,
    add_identity_arguments,
    assert_gate_identity,
    atomic_write_bytes,
    build_pytest_collection_command,
    build_pytest_execution_command,
    discover_postgres_test_files,
    parse_pytest_collection,
    parse_pytest_junit,
    private_artifact_directory,
    read_regular_file_nofollow,
    reserve_machine_report,
    sanitized_test_environment,
    start_gate_identity,
    verify_file_artifact,
    write_json_evidence,
)
from scripts.postgres_acceptance import (
    POSTGRES_REQUIRED_CHECKS,
    postgres_business_checks_from_nodes,
)
from scripts.postgres_acceptance import (
    build_pytest_command as build_postgres_pytest_command,
)

_REPOSITORY = Path(__file__).resolve().parents[1]
POSTGRES_MAPPED_TESTS = discover_postgres_test_files(_REPOSITORY)


def build_backend_command(
    repository: Path = _REPOSITORY, *, coverage: bool = True
) -> tuple[str, ...]:
    mapped = discover_postgres_test_files(repository)
    ignored = tuple(f"--ignore={path}" for path in mapped)
    coverage_arguments = (
        ("--cov=app", "--cov-report=term-missing", "--cov-fail-under=80") if coverage else ()
    )
    return (
        "uv",
        "run",
        "pytest",
        "-rA",
        "--maxfail=1",
        "tests",
        *ignored,
        *coverage_arguments,
    )


def backend_result_passed(*, returncode: int, output: str) -> bool:
    forbidden = r"\b\d+\s+(?:skipped|deselected|xfailed|xpassed|failed|errors?)\b"
    return returncode == 0 and re.search(forbidden, output, re.I) is None


def postgres_evidence_closes_mapping(
    document: object,
    *,
    repository: Path,
    evidence_path: Path,
    identity: GateIdentity,
    expected_nodes: tuple[str, ...],
) -> bool:
    if not isinstance(document, dict):
        return False
    target = document.get("target")
    checks = document.get("checks")
    pytest_evidence = document.get("pytest")
    if (
        not isinstance(target, dict)
        or not isinstance(checks, dict)
        or not isinstance(pytest_evidence, dict)
    ):
        return False
    node_ids = pytest_evidence.get("node_ids")
    covered = pytest_evidence.get("test_files")
    if (
        document.get("schema_version") != 2
        or document.get("kind") != "postgres-acceptance"
        or document.get("status") != "complete"
        or document.get("policy_status") != "passed"
        or target != identity.target()
        or set(checks) != set(POSTGRES_REQUIRED_CHECKS)
        or not isinstance(node_ids, list)
        or not node_ids
        or not all(isinstance(node, str) and node for node in node_ids)
        or len(node_ids) != len(set(node_ids))
        or tuple(node_ids) != expected_nodes
        or not isinstance(covered, list)
        or covered != list(discover_postgres_test_files(repository))
    ):
        return False
    count = len(node_ids)
    if not (
        pytest_evidence.get("collected") == count
        and pytest_evidence.get("executed") == count
        and pytest_evidence.get("passed") == count
        and all(
            pytest_evidence.get(field) == 0
            for field in (
                "failed",
                "errors",
                "skipped",
                "xfailed",
                "xpassed",
                "deselected",
                "unexpected",
            )
        )
        and pytest_evidence.get("missing_node_ids") == []
        and pytest_evidence.get("unexpected_node_ids") == []
    ):
        return False
    node_set = set(node_ids)
    try:
        expected_checks = postgres_business_checks_from_nodes(tuple(node_ids))
    except AcceptanceGateError:
        return False
    for check_name in POSTGRES_REQUIRED_CHECKS:
        check = checks.get(check_name)
        if not isinstance(check, dict):
            return False
        check_nodes = check.get("node_ids")
        if (
            check.get("status") != "passed"
            or not isinstance(check_nodes, list)
            or not check_nodes
            or not all(isinstance(node, str) and node in node_set for node in check_nodes)
            or check != expected_checks[check_name]
        ):
            return False

    raw_path = pytest_evidence.get("path")
    expected_hash = pytest_evidence.get("sha256")
    expected_size = pytest_evidence.get("bytes")
    if (
        not isinstance(raw_path, str)
        or not raw_path
        or not isinstance(expected_hash, str)
        or not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
    ):
        return False
    relative = Path(raw_path)
    if relative.is_absolute() or any(part == ".." for part in relative.parts):
        return False
    root = evidence_path.resolve().parent
    artifact = (root / relative).resolve()
    try:
        artifact.relative_to(root)
        verify_file_artifact(artifact, sha256=expected_hash, size=expected_size)
        reparsed = parse_pytest_junit(artifact, tuple(node_ids))
    except (AcceptanceGateError, OSError, ValueError):
        return False
    return bool(
        reparsed.is_success
        and reparsed.sha256 == expected_hash
        and reparsed.size == expected_size
        and list(reparsed.test_files) == covered
    )


def _load_json_document(path: Path) -> object:
    try:
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def collect_postgres_nodes(repository: Path) -> tuple[str, ...]:
    command = build_pytest_collection_command(build_postgres_pytest_command(repository))
    completed = subprocess.run(  # noqa: S603
        list(command),
        cwd=repository,
        env=sanitized_test_environment(),
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        shell=False,
        timeout=180,
    )
    output = "\n".join((completed.stdout, completed.stderr))
    if completed.returncode != 0:
        raise AcceptanceGateError("PostgreSQL pytest collection failed")
    return parse_pytest_collection(output)


def _write_evidence(path: Path, payload: dict[str, object]) -> None:
    write_json_evidence(path, payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the non-PostgreSQL backend suite with fail-closed skip handling"
    )
    parser.add_argument("--postgres-evidence", type=Path, required=True)
    parser.add_argument(
        "--evidence-file",
        type=Path,
        default=Path("artifacts/acceptance/evidence/backend.json"),
    )
    add_identity_arguments(parser)
    args = parser.parse_args(argv)
    repository = Path(__file__).resolve().parents[1]
    postgres_evidence_path = (
        args.postgres_evidence
        if args.postgres_evidence.is_absolute()
        else repository / args.postgres_evidence
    ).resolve()
    evidence_path = (
        args.evidence_file if args.evidence_file.is_absolute() else repository / args.evidence_file
    ).resolve()
    started_at = datetime.now(UTC).isoformat()
    try:
        identity = start_gate_identity(
            repository,
            expected_git_head=args.expected_git_head,
            expected_content_fingerprint=args.expected_content_fingerprint,
            run_nonce=args.acceptance_run_nonce,
        )
    except AcceptanceGateError:
        print(json.dumps({"status": "blocked", "reason": "acceptance_identity_invalid"}))
        return 2

    try:
        expected_postgres_nodes = collect_postgres_nodes(repository)
    except (AcceptanceGateError, OSError, subprocess.TimeoutExpired):
        print(json.dumps({"status": "blocked", "reason": "postgres_collection_unverified"}))
        return 2
    postgres_document = _load_json_document(postgres_evidence_path)
    if not postgres_evidence_closes_mapping(
        postgres_document,
        repository=repository,
        evidence_path=postgres_evidence_path,
        identity=identity,
        expected_nodes=expected_postgres_nodes,
    ):
        print(json.dumps({"status": "blocked", "reason": "postgres_mapping_unverified"}))
        return 2
    postgres_raw = postgres_evidence_path.read_bytes()
    postgres_sha256 = hashlib.sha256(postgres_raw).hexdigest()
    junit = None
    published_junit_path: Path | None = None
    try:
        raw_directory = evidence_path.parent / "raw"
        if raw_directory.is_symlink():
            raise AcceptanceGateError("backend evidence directory cannot be a symlink")
        raw_directory.mkdir(parents=True, exist_ok=True)
        published_junit_path = raw_directory / f"backend-{identity.run_nonce}.junit.xml"
        with private_artifact_directory(
            evidence_path.parent,
            prefix=".backend-acceptance-",
        ) as staging:
            staged_junit_path = staging / "backend.junit.xml"
            reserve_machine_report(staged_junit_path)
            environment = sanitized_test_environment(
                overrides={"COVERAGE_FILE": str(staging / "coverage")}
            )
            collection_command = build_pytest_collection_command(
                build_backend_command(repository, coverage=False)
            )
            collected = subprocess.run(  # noqa: S603
                list(collection_command),
                cwd=repository,
                env=environment,
                capture_output=True,
                check=False,
                encoding="utf-8",
                errors="replace",
                shell=False,
                timeout=180,
            )
            collection_output = "\n".join((collected.stdout, collected.stderr))
            if collected.returncode != 0:
                print(collection_output, file=sys.stderr)
                raise AcceptanceGateError("backend pytest collection failed")
            expected_nodes = parse_pytest_collection(collection_output)
            execution_command = build_pytest_execution_command(
                build_backend_command(repository), staged_junit_path
            )
            completed = subprocess.run(  # noqa: S603
                list(execution_command),
                cwd=repository,
                env=environment,
                capture_output=True,
                check=False,
                encoding="utf-8",
                errors="replace",
                shell=False,
                timeout=600,
            )
            output = "\n".join((completed.stdout, completed.stderr))
            junit = parse_pytest_junit(staged_junit_path, expected_nodes)
            junit_raw = read_regular_file_nofollow(
                staged_junit_path,
                maximum_bytes=100 * 1024 * 1024,
            )
            atomic_write_bytes(published_junit_path, junit_raw)
        if completed.returncode != 0 or not junit.is_success:
            print(output, file=sys.stderr)
            raise AcceptanceGateError("backend tests did not execute the exact collected node set")
        if hashlib.sha256(postgres_evidence_path.read_bytes()).hexdigest() != postgres_sha256:
            raise AcceptanceGateError("PostgreSQL evidence changed during backend acceptance")
        assert_gate_identity(repository, identity)
        evidence: dict[str, object] = {
            "schema_version": 2,
            "kind": "backend-acceptance",
            "status": "complete",
            "policy_status": "passed",
            "started_at": started_at,
            "finished_at": datetime.now(UTC).isoformat(),
            "target": identity.target(),
            "checks": {"coverage_minimum_percent": 80},
            "pytest": junit.as_dict(
                path=published_junit_path.relative_to(evidence_path.parent).as_posix()
            ),
            "postgres_skip_closure": {
                "gate_id": "TOKEN-GOV-P0-001",
                "evidence_kind": "postgres-acceptance",
                "evidence_file_name": postgres_evidence_path.name,
                "evidence_sha256": postgres_sha256,
                "mapped_test_files": list(discover_postgres_test_files(repository)),
            },
        }
        _write_evidence(evidence_path, evidence)
        assert_gate_identity(repository, identity)
    except (
        AcceptanceGateError,
        OSError,
        subprocess.TimeoutExpired,
    ) as exc:
        failed: dict[str, object] = {
            "schema_version": 2,
            "kind": "backend-acceptance",
            "status": "failed",
            "policy_status": "failed",
            "started_at": started_at,
            "finished_at": datetime.now(UTC).isoformat(),
            "target": identity.target(),
            "error_type": type(exc).__name__,
        }
        if junit is not None:
            failed["pytest"] = junit.as_dict(
                path=(
                    published_junit_path.relative_to(evidence_path.parent).as_posix()
                    if published_junit_path is not None
                    else "raw/backend-unavailable.junit.xml"
                )
            )
        _write_evidence(evidence_path, failed)
        print(json.dumps({"status": "failed", "reason": "backend_acceptance_failed"}))
        return 1

    print(
        json.dumps(
            {
                "status": "passed",
                "pytest_collected": junit.collected,
                "pytest_passed": junit.passed,
                "postgres_mapped_test_files": len(discover_postgres_test_files(repository)),
                "worktree_fingerprint": identity.content_fingerprint,
                "run_nonce": identity.run_nonce,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
