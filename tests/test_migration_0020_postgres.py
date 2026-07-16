from __future__ import annotations

import json
import os
import subprocess
import sys
import zlib
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
    sync_url = parsed.set(drivername="postgresql+psycopg")
    async_url = parsed.set(drivername="postgresql+asyncpg")
    return sync_url, async_url.render_as_string(hide_password=False)


def _alembic(revision: str, *, downgrade: bool = False) -> subprocess.CompletedProcess[str]:
    _, async_url = _urls()
    environment = os.environ.copy()
    environment["KB_DATABASE_URL"] = async_url
    environment["KB_ENVIRONMENT"] = "test"
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


def test_0020_destroys_legacy_plaintext_and_requires_aead_metadata() -> None:
    sync_url, _ = _urls()
    engine = create_engine(sync_url)
    user_id = uuid4()
    knowledge_base_id = uuid4()
    record_id = uuid4()
    raw_response = json.dumps(
        {
            "knowledge_base_id": str(knowledge_base_id),
            "answer": "legacy confidential plaintext",
            "citations": [],
            "source_status": {
                "status": "no_results",
                "strategy": "retrieval",
                "reason": "no_matching_content",
                "citation_count": 0,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    legacy_payload = zlib.compress(raw_response)
    try:
        assert_acceptance_database_sync(engine)
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))

        upgrade_0019 = _alembic("20260714_0019")
        assert upgrade_0019.returncode == 0, upgrade_0019.stderr

        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO users "
                    "(id, email, password_hash, status, is_superuser, token_version) "
                    "VALUES (:id, :email, 'unused', 'ACTIVE', false, 0)"
                ),
                {"id": user_id, "email": f"aead-migration-{user_id}@example.com"},
            )
            connection.execute(
                text(
                    "INSERT INTO knowledge_bases (id, owner_id, name, custom_metadata) "
                    "VALUES (:id, :owner_id, 'AEAD migration', '{}'::json)"
                ),
                {"id": knowledge_base_id, "owner_id": user_id},
            )
            connection.execute(
                text(
                    "INSERT INTO chat_idempotency_records "
                    "(id, principal_hash, idempotency_key_hash, request_hash, "
                    "knowledge_base_id, knowledge_base_content_version, status, response_body, "
                    "response_encoding, response_size_bytes, completed_at, expires_at) "
                    "VALUES (:id, :principal, :key_hash, :request_hash, :kb_id, 1, "
                    "'COMPLETED', :payload, 'zlib-json-v1', :raw_size, now(), "
                    "now() + interval '24 hours')"
                ),
                {
                    "id": record_id,
                    "principal": "a" * 64,
                    "key_hash": "b" * 64,
                    "request_hash": "c" * 64,
                    "kb_id": knowledge_base_id,
                    "payload": legacy_payload,
                    "raw_size": len(raw_response),
                },
            )

        upgrade_0020 = _alembic("20260714_0020")
        assert upgrade_0020.returncode == 0, upgrade_0020.stderr

        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "20260714_0020"
            )
            migrated = connection.execute(
                text(
                    "SELECT status::text, response_body, response_encoding, "
                    "response_size_bytes, response_key_version, response_nonce "
                    "FROM chat_idempotency_records WHERE id = :id"
                ),
                {"id": record_id},
            ).one()
            assert migrated[0] == "OUTCOME_UNKNOWN"
            assert all(value is None for value in migrated[1:])
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM chat_idempotency_records "
                        "WHERE response_body IS NOT NULL"
                    )
                )
                == 0
            )

        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO chat_idempotency_records "
                    "(id, principal_hash, idempotency_key_hash, request_hash, "
                    "knowledge_base_id, knowledge_base_content_version, status, "
                    "response_body, response_encoding, response_size_bytes, completed_at, "
                    "expires_at) VALUES (:id, :principal, :key_hash, :request_hash, :kb_id, "
                    "1, 'COMPLETED', decode('00', 'hex'), 'aesgcm-zlib-json-v1', 1, now(), "
                    "now() + interval '24 hours')"
                ),
                {
                    "id": uuid4(),
                    "principal": "d" * 64,
                    "key_hash": "e" * 64,
                    "request_hash": "f" * 64,
                    "kb_id": knowledge_base_id,
                },
            )

        downgrade = _alembic("20260714_0019", downgrade=True)
        assert downgrade.returncode != 0
        assert "intentionally irreversible" in downgrade.stderr
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "20260714_0020"
            )
    finally:
        engine.dispose()
