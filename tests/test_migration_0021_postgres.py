from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import IntegrityError

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
    return (
        parsed.set(drivername="postgresql+psycopg"),
        parsed.set(drivername="postgresql+asyncpg").render_as_string(hide_password=False),
    )


def _alembic(revision: str, *, downgrade: bool = False) -> subprocess.CompletedProcess[str]:
    _, async_url = _urls()
    environment = os.environ.copy()
    environment["KB_DATABASE_URL"] = async_url
    environment["KB_ENVIRONMENT"] = "test"
    return subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade" if downgrade else "upgrade", revision],
        cwd=REPOSITORY,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )


def test_0021_adds_durable_user_retirement_evidence_and_refuses_downgrade() -> None:
    sync_url, _ = _urls()
    engine = create_engine(sync_url)
    existing_user_id = uuid4()
    operator_id = uuid4()
    try:
        assert_acceptance_database_sync(engine)
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))

        upgrade_0020 = _alembic("20260714_0020")
        assert upgrade_0020.returncode == 0, upgrade_0020.stderr
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO users "
                    "(id, email, password_hash, status, is_superuser, token_version) "
                    "VALUES (:id, :email, 'existing-hash', 'ACTIVE', false, 7), "
                    "(:operator_id, :operator_email, 'operator-hash', 'ACTIVE', true, 3)"
                ),
                {
                    "id": existing_user_id,
                    "email": f"retirement-existing-{existing_user_id}@example.com",
                    "operator_id": operator_id,
                    "operator_email": f"retirement-operator-{operator_id}@example.com",
                },
            )

        upgrade_0021 = _alembic("20260715_0021")
        assert upgrade_0021.returncode == 0, upgrade_0021.stderr

        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "20260715_0021"
            )
            existing = connection.execute(
                text(
                    "SELECT email, password_hash, status::text, token_version, "
                    "retired_at, retired_by_id, retirement_reason "
                    "FROM users WHERE id = :id"
                ),
                {"id": existing_user_id},
            ).one()
            assert existing[1:] == ("existing-hash", "ACTIVE", 7, None, None, None)
            columns = {
                row[0]: (row[1], row[2])
                for row in connection.execute(
                    text(
                        "SELECT column_name, is_nullable, data_type "
                        "FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = 'users' "
                        "AND column_name IN "
                        "('retired_at', 'retired_by_id', 'retirement_reason')"
                    )
                )
            }
            assert columns == {
                "retired_at": ("YES", "timestamp with time zone"),
                "retired_by_id": ("YES", "uuid"),
                "retirement_reason": ("YES", "text"),
            }
            constraints = {
                row[0]: (row[1], row[2], row[3])
                for row in connection.execute(
                    text(
                        "SELECT con.conname, con.contype, con.confdeltype, "
                        "pg_get_constraintdef(con.oid) "
                        "FROM pg_constraint con "
                        "JOIN pg_class rel ON rel.oid = con.conrelid "
                        "JOIN pg_namespace ns ON ns.oid = rel.relnamespace "
                        "WHERE ns.nspname = 'public' AND rel.relname = 'users' "
                        "AND con.conname IN ("
                        "'fk_users_retired_by_id_users', "
                        "'ck_users_retirement_metadata_requires_timestamp', "
                        "'ck_users_retirement_requires_disabled_status', "
                        "'ck_users_retirement_actor_not_self')"
                    )
                )
            }
            assert constraints["fk_users_retired_by_id_users"][0] == "f"
            assert constraints["fk_users_retired_by_id_users"][1] == "r"
            assert {
                name for name, (kind, _, _) in constraints.items() if kind == "c"
            } == {
                "ck_users_retirement_metadata_requires_timestamp",
                "ck_users_retirement_requires_disabled_status",
                "ck_users_retirement_actor_not_self",
            }

        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text("UPDATE users SET retired_at = now() WHERE id = :id"),
                {"id": existing_user_id},
            )
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE users SET retired_at = now(), retired_by_id = :operator_id "
                    "WHERE id = :id"
                ),
                {"id": existing_user_id, "operator_id": operator_id},
            )
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE users SET status = 'DISABLED', retired_at = now(), "
                    "retired_by_id = id WHERE id = :id"
                ),
                {"id": existing_user_id},
            )

        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE users SET status = 'DISABLED', retired_at = now(), "
                    "retired_by_id = :operator_id, retirement_reason = 'accepted' "
                    "WHERE id = :id"
                ),
                {"id": existing_user_id, "operator_id": operator_id},
            )
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": operator_id})

        downgrade = _alembic("20260714_0020", downgrade=True)
        assert downgrade.returncode != 0
        assert "intentionally irreversible" in downgrade.stderr
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "20260715_0021"
            )
            assert connection.scalar(
                text(
                    "SELECT count(*) FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = 'users' "
                    "AND column_name IN "
                    "('retired_at', 'retired_by_id', 'retirement_reason')"
                )
            ) == 3
    finally:
        engine.dispose()
