from pathlib import Path

from scripts.backend_acceptance import (
    POSTGRES_MAPPED_TESTS,
    POSTGRES_MINIMUM_PASSED_TESTS,
    backend_result_passed,
    build_backend_command,
    postgres_evidence_closes_mapping,
)

REPOSITORY = Path(__file__).resolve().parents[1]


def test_backend_acceptance_runner_exists() -> None:
    assert (REPOSITORY / "scripts/backend_acceptance.py").is_file()


def test_backend_command_excludes_only_tests_closed_by_postgres_p0() -> None:
    command = build_backend_command()

    assert command[:3] == ("uv", "run", "pytest")
    assert set(POSTGRES_MAPPED_TESTS) == {
        "tests/test_llm_usage_postgres.py",
        "tests/test_scan_audit_postgres.py",
        "tests/test_rbac_acl_revocation_postgres.py",
        "tests/test_migration_0011_postgres.py",
    }
    ignored = {
        item.removeprefix("--ignore=") for item in command if item.startswith("--ignore=")
    }
    assert ignored == set(POSTGRES_MAPPED_TESTS)
    assert "--cov=app" in command
    assert "--cov-fail-under=80" in command
    assert "-rs" in command


def test_backend_gate_rejects_every_unmapped_skip() -> None:
    assert backend_result_passed(returncode=0, output="279 passed") is True
    assert backend_result_passed(returncode=0, output="278 passed, 1 skipped") is False
    assert backend_result_passed(returncode=1, output="1 failed") is False


def test_backend_mapping_requires_matching_complete_postgres_evidence() -> None:
    fingerprint = "a" * 64
    document = {
        "schema_version": 1,
        "kind": "postgres-acceptance",
        "status": "complete",
        "policy_status": "passed",
        "target": {"content_fingerprint": fingerprint},
        "checks": {
            "pytest_passed": POSTGRES_MINIMUM_PASSED_TESTS,
            "pytest_skipped": 0,
            "real_migrations": "passed",
            "budget_concurrency": "passed",
            "idempotency_single_winner": "passed",
            "malware_scan_lease": "passed",
            "rbac_acl_revocation_concurrency": "passed",
            "audit_append_only_runtime_role": "passed",
            "isolated_migration_0011": "passed",
            "covered_test_files": list(POSTGRES_MAPPED_TESTS),
        },
    }

    assert postgres_evidence_closes_mapping(document, fingerprint) is True
    document["checks"]["pytest_skipped"] = 1  # type: ignore[index]
    assert postgres_evidence_closes_mapping(document, fingerprint) is False
    document["checks"]["pytest_skipped"] = 0  # type: ignore[index]
    assert postgres_evidence_closes_mapping(document, "b" * 64) is False
    document["target"]["content_fingerprint"] = fingerprint  # type: ignore[index]
    document["checks"]["rbac_acl_revocation_concurrency"] = "failed"  # type: ignore[index]
    assert postgres_evidence_closes_mapping(document, fingerprint) is False
