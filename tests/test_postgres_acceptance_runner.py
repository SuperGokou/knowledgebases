import os
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

from scripts.postgres_acceptance import (
    POSTGRES_MAPPED_TESTS,
    UnsafePostgresTarget,
    build_pytest_command,
    ensure_container_identity,
    pytest_result_passed,
    validate_database_identity,
)

REPOSITORY = Path(__file__).resolve().parents[1]


def test_postgres_acceptance_runner_exists() -> None:
    assert (REPOSITORY / "scripts/postgres_acceptance.py").is_file()


def test_direct_script_can_collect_worktree_evidence_outside_repository_cwd(
    tmp_path: Path,
) -> None:
    script = REPOSITORY / "scripts/postgres_acceptance.py"
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    probe = """
from pathlib import Path
import runpy
import sys

script = Path(sys.argv[1]).resolve()
sys.path.append(sys.argv[2])
namespace = runpy.run_path(str(script), run_name="postgres_acceptance_direct_entry_test")
identity = namespace["_collect_worktree_evidence"](script.parents[1])
assert len(identity.content_fingerprint) == 64
"""

    completed = subprocess.run(
        (sys.executable, "-S", "-c", probe, str(script), sysconfig.get_path("purelib")),
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr


def test_module_entry_exposes_postgres_acceptance_cli() -> None:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)

    completed = subprocess.run(
        (sys.executable, "-m", "scripts.postgres_acceptance", "--help"),
        cwd=REPOSITORY,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert "--image" in completed.stdout
    assert "--expected-git-head" in completed.stdout
    assert "--expected-content-fingerprint" in completed.stdout
    assert "--acceptance-run-nonce" in completed.stdout


def test_database_identity_requires_random_acceptance_database_and_marker() -> None:
    marker = "a" * 32

    validate_database_identity(
        database_name=f"kb_acceptance_{'b' * 24}",
        host="127.0.0.1",
        actual_marker=marker,
        expected_marker=marker,
    )

    unsafe_cases = (
        ("knowledge", "127.0.0.1", marker, marker),
        (f"kb_acceptance_{'b' * 24}", "db.internal", marker, marker),
        (f"kb_acceptance_{'b' * 24}", "127.0.0.1", "wrong", marker),
        (f"kb_acceptance_{'b' * 24}", "127.0.0.1", marker, ""),
    )
    for database_name, host, actual_marker, expected_marker in unsafe_cases:
        with pytest.raises(UnsafePostgresTarget):
            validate_database_identity(
                database_name=database_name,
                host=host,
                actual_marker=actual_marker,
                expected_marker=expected_marker,
            )


def test_postgres_gate_runs_only_real_postgres_tests_without_skip_escape_hatch() -> None:
    command = build_pytest_command(REPOSITORY)

    assert command[:3] == ("uv", "run", "pytest")
    selected = tuple(item for item in command if item.startswith("tests/"))
    assert selected == POSTGRES_MAPPED_TESTS
    assert len(selected) == len(set(selected))
    assert "--runxfail" not in command
    assert "-rA" in command
    assert not any("sqlite" in item.lower() for item in command)


def test_postgres_tests_never_recreate_an_arbitrary_database() -> None:
    for relative in POSTGRES_MAPPED_TESTS:
        source = (REPOSITORY / relative).read_text(encoding="utf-8")
        assert "Base.metadata.drop_all" not in source
        assert "Base.metadata.create_all" not in source
        assert "assert_acceptance_database" in source


def test_container_cleanup_requires_exact_id_name_and_marker() -> None:
    container_id = "a" * 64
    marker = "b" * 32
    name = f"kb-acceptance-pg-{marker[:16]}"

    ensure_container_identity(
        expected_id=container_id,
        actual_id=container_id,
        expected_name=name,
        actual_name=f"/{name}",
        expected_marker=marker,
        actual_marker=marker,
    )

    with pytest.raises(UnsafePostgresTarget):
        ensure_container_identity(
            expected_id=container_id,
            actual_id="c" * 64,
            expected_name=name,
            actual_name=f"/{name}",
            expected_marker=marker,
            actual_marker=marker,
        )


def test_postgres_test_gate_fails_on_any_skip_or_nonzero_exit() -> None:
    assert pytest_result_passed(returncode=0, output="5 passed") is True
    assert pytest_result_passed(returncode=0, output="4 passed, 1 skipped") is False
    assert pytest_result_passed(returncode=0, output="4 passed, 1 deselected") is False
    assert pytest_result_passed(returncode=0, output="4 passed, 1 xfailed") is False
    assert pytest_result_passed(returncode=0, output="4 passed, 1 xpassed") is False
    assert pytest_result_passed(returncode=0, output="4 passed, 1 error") is False
    assert pytest_result_passed(returncode=1, output="1 failed") is False
