from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import quote

import psycopg
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection


def _bootstrap_repository_import_path() -> None:
    if __package__ not in {None, ""}:
        return
    repository_root = str(Path(__file__).resolve().parents[1])
    sys.path.insert(0, repository_root)


_bootstrap_repository_import_path()

_DATABASE_PATTERN = re.compile(r"kb_acceptance_[0-9a-f]{24}(?:_migration_test)?\Z")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_CONTAINER_LABEL = "com.heyi.knowledgebase.acceptance-marker"
_DEFAULT_EVIDENCE = Path("artifacts/acceptance/evidence/postgres.json")


class UnsafePostgresTarget(RuntimeError):
    pass


class _WorktreeIdentity(Protocol):
    git_head: str
    content_fingerprint: str


def _collect_worktree_evidence(repository: Path) -> _WorktreeIdentity:
    module = importlib.import_module("scripts.acceptance")
    collector = cast("object", module.collect_worktree_evidence)
    if not callable(collector):
        raise RuntimeError("worktree evidence collector is unavailable")
    return cast("_WorktreeIdentity", collector(repository))


def ensure_container_identity(
    *,
    expected_id: str,
    actual_id: str,
    expected_name: str,
    actual_name: str,
    expected_marker: str,
    actual_marker: str,
) -> None:
    valid_id = re.fullmatch(r"[0-9a-f]{64}", expected_id) is not None
    valid_name = re.fullmatch(r"kb-acceptance-pg-[0-9a-f]{16}", expected_name) is not None
    if not (
        valid_id
        and valid_name
        and actual_id == expected_id
        and actual_name == f"/{expected_name}"
        and len(expected_marker) >= 32
        and actual_marker == expected_marker
    ):
        raise UnsafePostgresTarget("refusing to operate on an unverified container")


def pytest_result_passed(*, returncode: int, output: str) -> bool:
    return returncode == 0 and re.search(r"\b\d+\s+skipped\b", output, re.I) is None


def validate_database_identity(
    *,
    database_name: str,
    host: str,
    actual_marker: str,
    expected_marker: str,
) -> None:
    if _DATABASE_PATTERN.fullmatch(database_name) is None:
        raise UnsafePostgresTarget("database name is not an isolated acceptance resource")
    if host.lower() not in _LOOPBACK_HOSTS:
        raise UnsafePostgresTarget("PostgreSQL acceptance target is not loopback-only")
    if len(expected_marker) < 32 or actual_marker != expected_marker:
        raise UnsafePostgresTarget("PostgreSQL acceptance marker mismatch")


def build_pytest_command(repository: Path) -> tuple[str, ...]:
    del repository
    return (
        "uv",
        "run",
        "pytest",
        "--runxfail",
        "-rs",
        "--maxfail=1",
        "tests/test_llm_usage_postgres.py",
        "tests/test_scan_audit_postgres.py",
        "tests/test_rbac_acl_revocation_postgres.py",
        "tests/test_migration_0011_postgres.py",
        "tests/test_auth_refresh_postgres.py",
    )


async def assert_acceptance_database(connection: AsyncConnection) -> None:
    """Fail closed unless this is the runner's marked, loopback-only PostgreSQL."""

    expected_marker = os.environ.get("KB_POSTGRES_ACCEPTANCE_MARKER", "")
    host = connection.engine.url.host or ""
    if connection.dialect.name != "postgresql":
        raise UnsafePostgresTarget("PostgreSQL acceptance cannot run on another dialect")
    try:
        database_name = str(await connection.scalar(text("SELECT current_database()")) or "")
        actual_marker = str(
            await connection.scalar(text("SELECT marker FROM public.kb_acceptance_marker LIMIT 1"))
            or ""
        )
    except SQLAlchemyError as exc:
        raise UnsafePostgresTarget("PostgreSQL acceptance marker is unavailable") from exc
    validate_database_identity(
        database_name=database_name,
        host=host,
        actual_marker=actual_marker,
        expected_marker=expected_marker,
    )


def assert_acceptance_database_sync(engine: Engine) -> None:
    """Protect the independently destructive migration-test database."""

    expected_marker = os.environ.get("KB_POSTGRES_ACCEPTANCE_MARKER", "")
    host = engine.url.host or ""
    if engine.dialect.name != "postgresql":
        raise UnsafePostgresTarget("PostgreSQL migration acceptance requires PostgreSQL")
    try:
        with engine.connect() as connection:
            database_name = str(connection.scalar(text("SELECT current_database()")) or "")
            actual_marker = str(
                connection.scalar(text("SELECT marker FROM kb_acceptance_guard.marker LIMIT 1"))
                or ""
            )
    except SQLAlchemyError as exc:
        raise UnsafePostgresTarget("migration acceptance marker is unavailable") from exc
    if not database_name.endswith("_migration_test"):
        raise UnsafePostgresTarget("migration test requires its independent database")
    validate_database_identity(
        database_name=database_name,
        host=host,
        actual_marker=actual_marker,
        expected_marker=expected_marker,
    )


def _run(
    command: tuple[str, ...],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        list(command),
        cwd=cwd,
        env=env,
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        shell=False,
        timeout=timeout,
    )


def _docker(
    docker: str,
    repository: Path,
    *arguments: str,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return _run((docker, *arguments), cwd=repository, timeout=timeout)


def _write_evidence(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _inspect_container(
    docker: str,
    repository: Path,
    container_id: str,
) -> tuple[str, str, str, str]:
    inspected = _docker(
        docker,
        repository,
        "inspect",
        "--format",
        f'{{{{.Id}}}}|{{{{.Name}}}}|{{{{index .Config.Labels "{_CONTAINER_LABEL}"}}}}|'
        "{{.State.Health.Status}}",
        container_id,
        timeout=30,
    )
    if inspected.returncode != 0:
        raise UnsafePostgresTarget("acceptance container identity is unavailable")
    values = inspected.stdout.strip().split("|", 3)
    if len(values) != 4:
        raise UnsafePostgresTarget("acceptance container identity is malformed")
    return values[0], values[1], values[2], values[3]


def _cleanup_container(
    docker: str,
    repository: Path,
    *,
    container_id: str,
    container_name: str,
    marker: str,
) -> bool:
    try:
        actual_id, actual_name, actual_marker, _health = _inspect_container(
            docker, repository, container_id
        )
        ensure_container_identity(
            expected_id=container_id,
            actual_id=actual_id,
            expected_name=container_name,
            actual_name=actual_name,
            expected_marker=marker,
            actual_marker=actual_marker,
        )
    except UnsafePostgresTarget:
        return False
    removed = _docker(docker, repository, "rm", "--force", container_id, timeout=30)
    return removed.returncode == 0


def _wait_healthy(
    docker: str,
    repository: Path,
    *,
    container_id: str,
    container_name: str,
    marker: str,
    timeout_seconds: int = 60,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        actual_id, actual_name, actual_marker, health = _inspect_container(
            docker, repository, container_id
        )
        ensure_container_identity(
            expected_id=container_id,
            actual_id=actual_id,
            expected_name=container_name,
            actual_name=actual_name,
            expected_marker=marker,
            actual_marker=actual_marker,
        )
        if health == "healthy":
            return
        if health == "unhealthy":
            raise RuntimeError("isolated PostgreSQL container failed its health check")
        time.sleep(1)
    raise RuntimeError("isolated PostgreSQL container did not become healthy in time")


def _published_port(docker: str, repository: Path, container_id: str) -> int:
    result = _docker(docker, repository, "port", container_id, "5432/tcp", timeout=30)
    match = re.fullmatch(r"127\.0\.0\.1:(\d+)", result.stdout.strip())
    if result.returncode != 0 or match is None:
        raise UnsafePostgresTarget("isolated PostgreSQL is not loopback-only")
    return int(match.group(1))


def _base_evidence(repository: Path, *, image_id: str, started_at: str) -> dict[str, object]:
    identity = _collect_worktree_evidence(repository)
    return {
        "schema_version": 1,
        "kind": "postgres-acceptance",
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat(),
        "image_id": image_id,
        "target": {
            "git_head": identity.git_head,
            "content_fingerprint": identity.content_fingerprint,
        },
    }


def run_acceptance(*, image: str, evidence_path: Path) -> int:
    repository = Path(__file__).resolve().parents[1]
    started_at = datetime.now(UTC).isoformat()
    docker = shutil.which("docker")
    if docker is None:
        print(json.dumps({"status": "blocked", "reason": "docker_unavailable"}))
        return 2

    image_check = _docker(docker, repository, "image", "inspect", "--format", "{{.Id}}", image)
    image_id = image_check.stdout.strip()
    if image_check.returncode != 0 or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        print(json.dumps({"status": "blocked", "reason": "offline_postgres_image_unavailable"}))
        return 2

    marker = secrets.token_hex(16)
    database_name = f"kb_acceptance_{secrets.token_hex(12)}"
    container_name = f"kb-acceptance-pg-{marker[:16]}"
    database_user = "acceptance_admin"
    database_password = secrets.token_urlsafe(32)
    container_id = ""
    phase = "container_start"
    cleanup_succeeded = False
    exit_code = 1
    evidence: dict[str, object] | None = None
    output: dict[str, object] = {"status": "failed", "failed_phase": phase}
    try:
        with tempfile.TemporaryDirectory(prefix="kb-pg-acceptance-") as temporary_dir:
            env_file = Path(temporary_dir) / "postgres.env"
            env_file.write_text(
                "\n".join(
                    (
                        f"POSTGRES_DB={database_name}",
                        f"POSTGRES_USER={database_user}",
                        f"POSTGRES_PASSWORD={database_password}",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            os.chmod(env_file, 0o600)
            started = _docker(
                docker,
                repository,
                "run",
                "--detach",
                "--rm",
                "--name",
                container_name,
                "--label",
                f"{_CONTAINER_LABEL}={marker}",
                "--publish",
                "127.0.0.1::5432",
                "--env-file",
                str(env_file),
                "--tmpfs",
                "/var/lib/postgresql/data:rw,noexec,nosuid,size=1073741824",
                "--health-cmd",
                f"pg_isready -U {database_user} -d {database_name}",
                "--health-interval",
                "1s",
                "--health-timeout",
                "2s",
                "--health-retries",
                "60",
                image,
            )
            container_id = started.stdout.strip()
            if started.returncode != 0 or re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
                raise RuntimeError("isolated PostgreSQL container could not start")

            phase = "container_health"
            _wait_healthy(
                docker,
                repository,
                container_id=container_id,
                container_name=container_name,
                marker=marker,
            )
            port = _published_port(docker, repository, container_id)
            password = quote(database_password, safe="")
            sync_dsn = f"postgresql://{database_user}:{password}@127.0.0.1:{port}/{database_name}"
            async_dsn = (
                f"postgresql+asyncpg://{database_user}:{password}@127.0.0.1:{port}/{database_name}"
            )
            child_env = os.environ.copy()
            child_env["KB_DATABASE_URL"] = async_dsn
            child_env["KB_TEST_POSTGRES_URL"] = async_dsn
            child_env["KB_POSTGRES_ACCEPTANCE_MARKER"] = marker

            phase = "alembic_upgrade"
            migration = _run(
                ("uv", "run", "alembic", "upgrade", "head"),
                cwd=repository,
                env=child_env,
                timeout=180,
            )
            if migration.returncode != 0:
                raise RuntimeError("real PostgreSQL migration failed")

            phase = "database_marker"
            with (
                psycopg.connect(sync_dsn, connect_timeout=10) as connection,
                connection.cursor() as cursor,
            ):
                cursor.execute(
                    "CREATE TABLE public.kb_acceptance_marker "
                    "(marker text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now())"
                )
                cursor.execute(
                    "INSERT INTO public.kb_acceptance_marker (marker) VALUES (%s)",
                    (marker,),
                )

            phase = "migration_database"
            migration_database = f"{database_name}_migration_test"
            with psycopg.connect(sync_dsn, connect_timeout=10, autocommit=True) as admin_connection:
                admin_connection.execute(
                    sql.SQL("CREATE DATABASE {}").format(sql.Identifier(migration_database))
                )
            migration_sync_dsn = (
                f"postgresql://{database_user}:{password}@127.0.0.1:{port}/{migration_database}"
            )
            migration_async_dsn = (
                f"postgresql+asyncpg://{database_user}:{password}@127.0.0.1:{port}/"
                f"{migration_database}"
            )
            with psycopg.connect(migration_sync_dsn, connect_timeout=10) as migration_connection:
                migration_connection.execute("CREATE SCHEMA kb_acceptance_guard")
                migration_connection.execute(
                    "CREATE TABLE kb_acceptance_guard.marker (marker text PRIMARY KEY)"
                )
                migration_connection.execute(
                    "INSERT INTO kb_acceptance_guard.marker (marker) VALUES (%s)",
                    (marker,),
                )
            child_env["KB_TEST_MIGRATION_POSTGRES_URL"] = migration_async_dsn

            phase = "postgres_tests"
            tests = _run(
                build_pytest_command(repository),
                cwd=repository,
                env=child_env,
                timeout=300,
            )
            test_output = "\n".join((tests.stdout, tests.stderr))
            if not pytest_result_passed(returncode=tests.returncode, output=test_output):
                print(test_output, file=sys.stderr)
                raise RuntimeError("real PostgreSQL tests failed or were skipped")

            passed_match = re.search(r"\b(\d+) passed\b", test_output)
            evidence = _base_evidence(repository, image_id=image_id, started_at=started_at)
            evidence.update(
                {
                    "status": "complete",
                    "policy_status": "passed",
                    "checks": {
                        "real_migrations": "passed",
                        "budget_concurrency": "passed",
                        "idempotency_single_winner": "passed",
                        "malware_scan_lease": "passed",
                        "rbac_acl_revocation_concurrency": "passed",
                        "refresh_token_rotation": "passed",
                        "audit_append_only_runtime_role": "passed",
                        "isolated_migration_0011": "passed",
                        "pytest_passed": int(passed_match.group(1)) if passed_match else None,
                        "pytest_skipped": 0,
                        "covered_test_files": [
                            "tests/test_llm_usage_postgres.py",
                            "tests/test_scan_audit_postgres.py",
                            "tests/test_rbac_acl_revocation_postgres.py",
                            "tests/test_migration_0011_postgres.py",
                            "tests/test_auth_refresh_postgres.py",
                        ],
                    },
                }
            )
            target = evidence["target"]
            assert isinstance(target, dict)
            output = {
                "status": "passed",
                "checks": 8,
                "pytest_skipped": 0,
                "worktree_fingerprint": target["content_fingerprint"],
            }
            exit_code = 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, psycopg.Error) as exc:
        evidence = _base_evidence(repository, image_id=image_id, started_at=started_at)
        evidence.update(
            {
                "status": "failed",
                "policy_status": "failed",
                "failed_phase": phase,
                "error_type": type(exc).__name__,
            }
        )
        output = {"status": "failed", "failed_phase": phase}
        exit_code = 1
    finally:
        if container_id:
            cleanup_succeeded = _cleanup_container(
                docker,
                repository,
                container_id=container_id,
                container_name=container_name,
                marker=marker,
            )
            if not cleanup_succeeded:
                evidence = _base_evidence(repository, image_id=image_id, started_at=started_at)
                evidence.update(
                    {
                        "status": "failed",
                        "policy_status": "failed",
                        "failed_phase": "safe_cleanup",
                    }
                )
                output = {"status": "failed", "failed_phase": "safe_cleanup"}
                exit_code = 1
    assert evidence is not None
    _write_evidence(evidence_path, evidence)
    print(json.dumps(output))
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run isolated, destructive-safe PostgreSQL P0 acceptance"
    )
    parser.add_argument("--image", required=True)
    parser.add_argument("--evidence-file", type=Path, default=_DEFAULT_EVIDENCE)
    args = parser.parse_args(argv)
    return run_acceptance(image=args.image, evidence_path=args.evidence_file)


if __name__ == "__main__":
    raise SystemExit(main())
