from __future__ import annotations

import argparse
import importlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

POSTGRES_MAPPED_TESTS: tuple[str, ...] = (
    "tests/test_llm_usage_postgres.py",
    "tests/test_scan_audit_postgres.py",
    "tests/test_rbac_acl_revocation_postgres.py",
    "tests/test_migration_0011_postgres.py",
    "tests/test_auth_refresh_postgres.py",
)
POSTGRES_MINIMUM_PASSED_TESTS = 21
POSTGRES_REQUIRED_CHECKS: tuple[str, ...] = (
    "real_migrations",
    "budget_concurrency",
    "idempotency_single_winner",
    "malware_scan_lease",
    "rbac_acl_revocation_concurrency",
    "refresh_token_rotation",
    "audit_append_only_runtime_role",
    "isolated_migration_0011",
)


class _WorktreeIdentity(Protocol):
    git_head: str
    content_fingerprint: str


def _collect_worktree_evidence(repository: Path) -> _WorktreeIdentity:
    module = importlib.import_module("scripts.acceptance")
    collector = cast("object", module.collect_worktree_evidence)
    if not callable(collector):
        raise RuntimeError("worktree evidence collector is unavailable")
    return cast("_WorktreeIdentity", collector(repository))


def build_backend_command() -> tuple[str, ...]:
    ignored = tuple(f"--ignore={path}" for path in POSTGRES_MAPPED_TESTS)
    return (
        "uv",
        "run",
        "pytest",
        "--runxfail",
        "-rs",
        "--maxfail=1",
        *ignored,
        "--cov=app",
        "--cov-report=term-missing",
        "--cov-fail-under=80",
    )


def backend_result_passed(*, returncode: int, output: str) -> bool:
    return returncode == 0 and re.search(r"\b\d+\s+skipped\b", output, re.I) is None


def postgres_evidence_closes_mapping(
    document: object,
    content_fingerprint: str,
) -> bool:
    if not isinstance(document, dict):
        return False
    target = document.get("target")
    checks = document.get("checks")
    if not isinstance(target, dict) or not isinstance(checks, dict):
        return False
    covered = checks.get("covered_test_files")
    return bool(
        document.get("schema_version") == 1
        and document.get("kind") == "postgres-acceptance"
        and document.get("status") == "complete"
        and document.get("policy_status") == "passed"
        and target.get("content_fingerprint") == content_fingerprint
        and isinstance(checks.get("pytest_passed"), int)
        and checks["pytest_passed"] >= POSTGRES_MINIMUM_PASSED_TESTS
        and checks.get("pytest_skipped") == 0
        and all(checks.get(check_name) == "passed" for check_name in POSTGRES_REQUIRED_CHECKS)
        and isinstance(covered, list)
        and len(covered) == len(POSTGRES_MAPPED_TESTS)
        and set(covered) == set(POSTGRES_MAPPED_TESTS)
    )


def _load_json_document(path: Path) -> object:
    try:
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def _write_evidence(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


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
    args = parser.parse_args(argv)
    repository = Path(__file__).resolve().parents[1]
    started_at = datetime.now(UTC).isoformat()
    identity = _collect_worktree_evidence(repository)
    postgres_document = _load_json_document(args.postgres_evidence)
    if not postgres_evidence_closes_mapping(
        postgres_document,
        identity.content_fingerprint,
    ):
        print(json.dumps({"status": "blocked", "reason": "postgres_mapping_unverified"}))
        return 2
    completed = subprocess.run(  # noqa: S603
        list(build_backend_command()),
        cwd=repository,
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        shell=False,
        timeout=600,
    )
    output = "\n".join((completed.stdout, completed.stderr))
    passed = backend_result_passed(returncode=completed.returncode, output=output)
    passed_match = re.search(r"\b(\d+) passed\b", output)
    evidence: dict[str, object] = {
        "schema_version": 1,
        "kind": "backend-acceptance",
        "status": "complete" if passed else "failed",
        "policy_status": "passed" if passed else "failed",
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat(),
        "target": {
            "git_head": identity.git_head,
            "content_fingerprint": identity.content_fingerprint,
        },
        "checks": {
            "pytest_passed": int(passed_match.group(1)) if passed_match else None,
            "pytest_skipped": 0 if passed else None,
            "coverage_minimum_percent": 80,
        },
        "postgres_skip_closure": {
            "gate_id": "TOKEN-GOV-P0-001",
            "evidence_kind": "postgres-acceptance",
            "evidence_file_name": args.postgres_evidence.name,
            "mapped_test_files": list(POSTGRES_MAPPED_TESTS),
        },
    }
    _write_evidence(args.evidence_file, evidence)
    print(
        json.dumps(
            {
                "status": "passed" if passed else "failed",
                "pytest_passed": int(passed_match.group(1)) if passed_match else None,
                "pytest_skipped": 0 if passed else None,
                "postgres_mapped_test_files": len(POSTGRES_MAPPED_TESTS),
                "worktree_fingerprint": identity.content_fingerprint,
            }
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
