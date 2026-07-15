from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url

from scripts.postgres_acceptance import assert_acceptance_database_sync

REPOSITORY = Path(__file__).resolve().parents[1]
_POSTGRES_URL = os.getenv("KB_TEST_MIGRATION_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not _POSTGRES_URL,
    reason="KB_TEST_MIGRATION_POSTGRES_URL is required for destructive migration verification",
)


def _urls() -> tuple[URL, str]:
    assert _POSTGRES_URL is not None
    parsed = make_url(_POSTGRES_URL)
    if not (parsed.database or "").endswith("_migration_test"):
        pytest.fail(
            "KB_TEST_MIGRATION_POSTGRES_URL must use a disposable *_migration_test database"
        )
    sync_url = parsed.set(drivername="postgresql+psycopg")
    async_url = parsed.set(drivername="postgresql+asyncpg")
    return sync_url, async_url.render_as_string(hide_password=False)


def _alembic(revision: str, *, downgrade: bool = False) -> subprocess.CompletedProcess[str]:
    _, async_url = _urls()
    environment = os.environ.copy()
    environment["KB_DATABASE_URL"] = async_url
    command = "downgrade" if downgrade else "upgrade"
    return subprocess.run(
        [sys.executable, "-m", "alembic", command, revision],
        cwd=REPOSITORY,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )


def test_0011_backfills_security_outcomes_and_refuses_destructive_downgrade() -> None:
    sync_url, _ = _urls()
    engine = create_engine(sync_url)
    try:
        assert_acceptance_database_sync(engine)
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))

        upgrade_0010 = _alembic("20260712_0010")
        assert upgrade_0010.returncode == 0, upgrade_0010.stderr

        expected = {
            "upload.rejected_size_mismatch": "FAILURE",
            "upload.rejected_checksum_mismatch": "FAILURE",
            "auth.token.reuse_detected": "DENIED",
            "auth.login.denied": "DENIED",
            "auth.login.succeeded": "SUCCESS",
            "custom.security.event": "FAILURE",
        }
        with engine.begin() as connection:
            for action in expected:
                connection.execute(
                    text(
                        "INSERT INTO audit_logs (action, resource_type, details) "
                        "VALUES (:action, 'migration-test', '{}'::json)"
                    ),
                    {"action": action},
                )

        upgrade_0011 = _alembic("20260712_0011")
        assert upgrade_0011.returncode == 0, upgrade_0011.stderr

        with engine.connect() as connection:
            actual: dict[str, str] = {
                str(row[0]): str(row[1])
                for row in connection.execute(
                    text("SELECT action, result::text FROM audit_logs ORDER BY action")
                )
            }
        assert actual == expected

        downgrade = _alembic("20260712_0010", downgrade=True)
        assert downgrade.returncode != 0
        assert "irreversible" in downgrade.stderr

        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "20260712_0011"
            )
            persisted: dict[str, str] = {
                str(row[0]): str(row[1])
                for row in connection.execute(
                    text("SELECT action, result::text FROM audit_logs ORDER BY action")
                )
            }
        assert persisted == expected
    finally:
        engine.dispose()


def test_0019_restricts_role_references_and_refuses_version_lying_downgrade() -> None:
    sync_url, _ = _urls()
    engine = create_engine(sync_url)
    try:
        assert_acceptance_database_sync(engine)
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))

        upgrade = _alembic("20260714_0019")
        assert upgrade.returncode == 0, upgrade.stderr

        user_id = uuid4()
        role_id = uuid4()
        knowledge_base_id = uuid4()
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO users "
                    "(id, email, password_hash, status, is_superuser, token_version) "
                    "VALUES (:id, :email, 'unused', 'ACTIVE', false, 0)"
                ),
                {"id": user_id, "email": f"restrict-{user_id}@example.com"},
            )
            connection.execute(
                text(
                    "INSERT INTO roles (id, code, name, priority, is_system) "
                    "VALUES (:id, :code, 'Restricted role', 0, false)"
                ),
                {"id": role_id, "code": f"restrict_{role_id.hex}"},
            )
            connection.execute(
                text(
                    "INSERT INTO user_roles (id, user_id, role_id, assigned_by) "
                    "VALUES (:id, :user_id, :role_id, :user_id)"
                ),
                {"id": uuid4(), "user_id": user_id, "role_id": role_id},
            )
            connection.execute(
                text(
                    "INSERT INTO knowledge_bases (id, owner_id, name, custom_metadata) "
                    "VALUES (:id, :owner_id, 'Restricted KB', '{}'::json)"
                ),
                {"id": knowledge_base_id, "owner_id": user_id},
            )
            connection.execute(
                text(
                    "INSERT INTO knowledge_base_role_grants "
                    "(id, knowledge_base_id, role_id, access_level, granted_by) "
                    "VALUES (:id, :kb_id, :role_id, 'READER', :user_id)"
                ),
                {
                    "id": uuid4(),
                    "kb_id": knowledge_base_id,
                    "role_id": role_id,
                    "user_id": user_id,
                },
            )

        expected_constraints = {
            "fk_user_roles_role_id_roles",
            "fk_knowledge_base_role_grants_role_id_roles",
        }
        with engine.connect() as connection:
            constraints_before = {
                str(name): str(delete_action)
                for name, delete_action in connection.execute(
                    text(
                        "SELECT conname, confdeltype FROM pg_constraint "
                        "WHERE conname IN (:first_name, :second_name)"
                    ),
                    {
                        "first_name": "fk_user_roles_role_id_roles",
                        "second_name": "fk_knowledge_base_role_grants_role_id_roles",
                    },
                )
            }
            assert constraints_before == {name: "r" for name in expected_constraints}

        downgrade = _alembic("20260714_0018", downgrade=True)
        assert downgrade.returncode != 0
        assert "intentionally irreversible" in downgrade.stderr

        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "20260714_0019"
            )
            constraints_after = {
                str(name): str(delete_action)
                for name, delete_action in connection.execute(
                    text(
                        "SELECT conname, confdeltype FROM pg_constraint "
                        "WHERE conname IN (:first_name, :second_name)"
                    ),
                    {
                        "first_name": "fk_user_roles_role_id_roles",
                        "second_name": "fk_knowledge_base_role_grants_role_id_roles",
                    },
                )
            }
            assert constraints_after == constraints_before
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM user_roles WHERE role_id = :role_id"),
                    {"role_id": role_id},
                )
                == 1
            )
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM knowledge_base_role_grants WHERE role_id = :role_id"
                    ),
                    {"role_id": role_id},
                )
                == 1
            )
    finally:
        engine.dispose()
