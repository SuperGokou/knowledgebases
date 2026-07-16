from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.errors import ApiError
from app.core.config import Settings
from app.db.models import (
    KnowledgeBase,
    LlmUsageRecord,
    LlmUsageStatus,
)
from app.schemas.chat import ChatQueryRequest, ChatQueryResponse, ChatSourceStatus
from app.services.chat_idempotency import (
    ChatIdempotencyPrincipal,
    execute_chat_query_idempotently,
)
from app.services.chat_replay_authorization import ChatAuthorizationSnapshot
from app.services.llm_usage import (
    LlmUsageDimensions,
    LlmUsageDuplicate,
    LlmUsageGovernance,
)
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


def _sha256(value: str | bytes) -> str:
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(payload).hexdigest()


def _historical_chat_hashes(
    request: ChatQueryRequest,
    *,
    api_key_id: UUID,
    client_key: str,
) -> tuple[str, str, str]:
    canonical = json.dumps(
        request.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return (
        _sha256(f"chat-principal-v1\0api_key\0{api_key_id}"),
        _sha256(f"chat-idempotency-key-v1\0{client_key}"),
        _sha256(b"chat-query-request-v1\0" + canonical),
    )


def _historical_llm_hash(
    *,
    tenant_key: str,
    user_id: UUID,
    api_key_id: UUID,
    knowledge_base_id: UUID,
    provider: str,
    model: str,
    operation: str,
    client_key: str,
) -> str:
    context = json.dumps(
        {
            "tenant": tenant_key,
            "user": str(user_id),
            "api_key": str(api_key_id),
            "knowledge_base": str(knowledge_base_id),
            "provider": provider,
            "model": model,
            "operation": operation,
            "client_key": client_key,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256(context)


def _response(request: ChatQueryRequest) -> ChatQueryResponse:
    return ChatQueryResponse(
        knowledge_base_id=request.knowledge_base_id,
        answer="must never execute",
        citations=[],
        source_status=ChatSourceStatus(
            status="no_results",
            strategy="retrieval",
            reason="no_matching_content",
            citation_count=0,
        ),
    )


async def _exercise_historical_namespaces(
    *,
    async_url: str,
    user_id: UUID,
    api_key_id: UUID,
    knowledge_base_id: UUID,
    requests: tuple[tuple[str, ChatQueryRequest], ...],
    tenant_key: str,
    provider: str,
    model: str,
    usage_client_key: str,
) -> None:
    engine = create_async_engine(async_url, pool_size=2, max_overflow=0)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    operation_calls = 0

    async def authorize(session: AsyncSession) -> ChatAuthorizationSnapshot:
        knowledge_base = await session.scalar(
            select(KnowledgeBase)
            .where(KnowledgeBase.id == knowledge_base_id)
            .with_for_update(read=True)
        )
        assert knowledge_base is not None
        return ChatAuthorizationSnapshot(
            knowledge_base_id=knowledge_base.id,
            content_version=knowledge_base.content_version,
        )

    async def operation() -> ChatQueryResponse:
        nonlocal operation_calls
        operation_calls += 1
        return _response(requests[0][1])

    settings = Settings(
        environment="test",
        database_url=async_url,
        chat_replay_encryption_keys={1: base64.urlsafe_b64encode(b"m" * 32).decode("ascii")},
        chat_replay_active_key_version=1,
        deepseek_timeout_seconds=5,
        chat_idempotency_processing_timeout_seconds=60,
    )
    try:
        for client_key, request in requests:
            async with factory() as session:
                with pytest.raises(ApiError) as captured:
                    await execute_chat_query_idempotently(
                        session,
                        settings,
                        principal=ChatIdempotencyPrincipal.for_api_key(api_key_id),
                        idempotency_key=client_key,
                        request=request,
                        authorize=authorize,
                        operation=operation,
                    )
            assert captured.value.code == "idempotency_outcome_unknown"
        assert operation_calls == 0

        dimensions = LlmUsageDimensions(
            tenant_key=tenant_key,
            user_id=user_id,
            api_key_id=api_key_id,
            api_key_credential_family_id=api_key_id,
            knowledge_base_id=knowledge_base_id,
            provider=provider,
            model=model,
            operation="chat.answer",
        )
        async with factory() as session:
            with pytest.raises(LlmUsageDuplicate) as duplicate:
                await LlmUsageGovernance().reserve(
                    session,
                    dimensions=dimensions,
                    idempotency_key=usage_client_key,
                    estimated_input_tokens=10,
                    maximum_output_tokens=10,
                )
            assert duplicate.value.status is LlmUsageStatus.SETTLED
            assert await session.scalar(select(func.count(LlmUsageRecord.id))) == 1
    finally:
        await engine.dispose()


def test_0018_preserves_historical_claims_and_binds_replay_to_content_version() -> None:
    sync_url, async_url = _urls()
    engine = create_engine(sync_url)
    user_id = uuid4()
    knowledge_base_id = uuid4()
    api_key_id = uuid4()
    cas_user_id = uuid4()
    cas_role_id = uuid4()
    cas_knowledge_base_id = uuid4()
    unknown_request = ChatQueryRequest(
        knowledge_base_id=knowledge_base_id,
        message="historical unknown outcome",
    )
    completed_request = ChatQueryRequest(
        knowledge_base_id=knowledge_base_id,
        message="historical completed response",
    )
    unknown_key = "historical-unknown"
    completed_key = "historical-completed"
    tenant_key = "historical-tenant"
    provider = "historical-provider"
    model = "historical-model"
    usage_client_key = "historical-usage"
    usage_hash = _historical_llm_hash(
        tenant_key=tenant_key,
        user_id=user_id,
        api_key_id=api_key_id,
        knowledge_base_id=knowledge_base_id,
        provider=provider,
        model=model,
        operation="chat.answer",
        client_key=usage_client_key,
    )
    try:
        assert_acceptance_database_sync(engine)
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))

        upgrade_0013 = _alembic("20260712_0013")
        assert upgrade_0013.returncode == 0, upgrade_0013.stderr

        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO users "
                    "(id, email, password_hash, status, is_superuser, token_version) "
                    "VALUES (:id, :email, 'unused', 'ACTIVE', false, 0)"
                ),
                {"id": cas_user_id, "email": f"cas-upgrade-{cas_user_id}@example.com"},
            )
            connection.execute(
                text(
                    "INSERT INTO roles (id, code, name, priority, is_system) "
                    "VALUES (:id, :code, 'CAS upgrade role', 0, false)"
                ),
                {"id": cas_role_id, "code": f"cas_upgrade_{cas_role_id.hex}"},
            )
            connection.execute(
                text(
                    "INSERT INTO knowledge_bases (id, owner_id, name, custom_metadata) "
                    "VALUES (:id, :owner_id, 'CAS upgrade KB', '{}'::json)"
                ),
                {"id": cas_knowledge_base_id, "owner_id": cas_user_id},
            )

        upgrade_0017 = _alembic("20260714_0017")
        assert upgrade_0017.returncode == 0, upgrade_0017.stderr

        with engine.connect() as connection:
            assert (
                connection.scalar(
                    text("SELECT role_assignment_version FROM users WHERE id = :id"),
                    {"id": cas_user_id},
                )
                == 1
            )
            assert (
                connection.scalar(
                    text("SELECT policy_version FROM roles WHERE id = :id"),
                    {"id": cas_role_id},
                )
                == 1
            )
            assert (
                connection.scalar(
                    text("SELECT role_grant_version FROM knowledge_bases WHERE id = :id"),
                    {"id": cas_knowledge_base_id},
                )
                == 1
            )

        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO users "
                    "(id, email, password_hash, status, is_superuser, token_version) "
                    "VALUES (:id, :email, 'unused', 'ACTIVE', false, 0)"
                ),
                {"id": user_id, "email": f"historical-{user_id}@example.com"},
            )
            connection.execute(
                text(
                    "INSERT INTO knowledge_bases "
                    "(id, owner_id, name, custom_metadata) "
                    "VALUES (:id, :owner_id, 'Historical KB', '{}'::json)"
                ),
                {"id": knowledge_base_id, "owner_id": user_id},
            )
            connection.execute(
                text(
                    "INSERT INTO api_keys "
                    "(id, user_id, created_by, name, key_hash, key_prefix, permission_codes, "
                    "knowledge_base_ids, requests_per_minute) VALUES "
                    "(:id, :user_id, :user_id, 'Historical key', :key_hash, 'kb_hist', "
                    "'[\"chat:query\"]'::json, CAST(:kb_ids AS json), 60)"
                ),
                {
                    "id": api_key_id,
                    "user_id": user_id,
                    "key_hash": uuid4().hex + uuid4().hex,
                    "kb_ids": json.dumps([str(knowledge_base_id)]),
                },
            )
            for status, client_key, request in (
                ("OUTCOME_UNKNOWN", unknown_key, unknown_request),
                ("COMPLETED", completed_key, completed_request),
            ):
                principal_hash, key_hash, request_hash = _historical_chat_hashes(
                    request,
                    api_key_id=api_key_id,
                    client_key=client_key,
                )
                connection.execute(
                    text(
                        "INSERT INTO chat_idempotency_records "
                        "(id, principal_hash, idempotency_key_hash, request_hash, status, "
                        "response_body, response_encoding, response_size_bytes, completed_at, "
                        "expires_at) VALUES "
                        "(:id, :principal_hash, :key_hash, :request_hash, "
                        "CAST(:status AS chat_idempotency_status), "
                        "CASE WHEN :completed THEN decode('78', 'hex') ELSE NULL END, "
                        "CASE WHEN :completed THEN 'zlib-json-v1' ELSE NULL END, "
                        "CASE WHEN :completed THEN 1 ELSE NULL END, now(), "
                        "now() + interval '24 hours')"
                    ),
                    {
                        "id": uuid4(),
                        "principal_hash": principal_hash,
                        "key_hash": key_hash,
                        "request_hash": request_hash,
                        "status": status,
                        "completed": status == "COMPLETED",
                    },
                )
            connection.execute(
                text(
                    "INSERT INTO llm_usage_records "
                    "(id, tenant_key, idempotency_hash, user_id, api_key_id, knowledge_base_id, "
                    "provider, model, operation, status, reserved_input_tokens, "
                    "reserved_output_tokens, reserved_token_count, reserved_cost_micro_usd, "
                    "input_price_micro_usd_per_million_tokens, "
                    "output_price_micro_usd_per_million_tokens, actual_input_tokens, "
                    "actual_output_tokens, actual_token_count, actual_cost_micro_usd, settled_at) "
                    "VALUES (:id, :tenant, :hash, :user_id, :api_key_id, :kb_id, :provider, "
                    ":model, 'chat.answer', 'SETTLED', 10, 10, 20, 20, 1000000, 1000000, "
                    "10, 10, 20, 20, now())"
                ),
                {
                    "id": uuid4(),
                    "tenant": tenant_key,
                    "hash": usage_hash,
                    "user_id": user_id,
                    "api_key_id": api_key_id,
                    "kb_id": knowledge_base_id,
                    "provider": provider,
                    "model": model,
                },
            )

        upgrade_0018 = _alembic("20260714_0018")
        assert upgrade_0018.returncode == 0, upgrade_0018.stderr

        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "20260714_0018"
            )
            assert connection.scalar(
                text("SELECT credential_family_id = id FROM api_keys WHERE id = :id"),
                {"id": api_key_id},
            )
            assert connection.scalar(
                text(
                    "SELECT api_key_credential_family_id = api_key_id "
                    "FROM llm_usage_records WHERE api_key_id = :id"
                ),
                {"id": api_key_id},
            )
            migrated_chat = connection.execute(
                text(
                    "SELECT status::text, response_body, knowledge_base_id "
                    "FROM chat_idempotency_records ORDER BY request_hash"
                )
            ).all()
            assert len(migrated_chat) == 2
            assert all(row[0] == "OUTCOME_UNKNOWN" for row in migrated_chat)
            assert all(row[1] is None and row[2] is None for row in migrated_chat)
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM pg_enum enum_value "
                        "JOIN pg_type enum_type ON enum_type.oid = enum_value.enumtypid "
                        "WHERE enum_type.typname = 'chat_idempotency_status' "
                        "AND enum_value.enumlabel = 'INVALIDATED'"
                    )
                )
                == 1
            )
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM pg_trigger "
                        "WHERE tgrelid = 'knowledge_entries'::regclass "
                        "AND tgname LIKE 'trg_knowledge_entries_content_version_%' "
                        "AND NOT tgisinternal"
                    )
                )
                == 4
            )

        entry_ids = (uuid4(), uuid4())
        with engine.begin() as connection:
            assert (
                connection.scalar(
                    text("SELECT content_version FROM knowledge_bases WHERE id = :id"),
                    {"id": knowledge_base_id},
                )
                == 1
            )
            connection.execute(
                text(
                    "INSERT INTO knowledge_entries "
                    "(id, knowledge_base_id, entry_type, title, content, custom_metadata, "
                    "publication_status) VALUES "
                    "(:first, :kb, 'policy', 'First', 'v1', '{}'::json, 'PUBLISHED'), "
                    "(:second, :kb, 'policy', 'Second', 'v1', '{}'::json, 'PUBLISHED')"
                ),
                {"first": entry_ids[0], "second": entry_ids[1], "kb": knowledge_base_id},
            )
            assert (
                connection.scalar(
                    text("SELECT content_version FROM knowledge_bases WHERE id = :id"),
                    {"id": knowledge_base_id},
                )
                == 2
            )
            connection.execute(
                text(
                    "UPDATE knowledge_entries SET content = content || '-v2' WHERE id = ANY(:ids)"
                ),
                {"ids": list(entry_ids)},
            )
            assert (
                connection.scalar(
                    text("SELECT content_version FROM knowledge_bases WHERE id = :id"),
                    {"id": knowledge_base_id},
                )
                == 3
            )
            connection.execute(
                text("DELETE FROM knowledge_entries WHERE id = ANY(:ids)"),
                {"ids": list(entry_ids)},
            )
            assert (
                connection.scalar(
                    text("SELECT content_version FROM knowledge_bases WHERE id = :id"),
                    {"id": knowledge_base_id},
                )
                == 4
            )
            connection.execute(text("TRUNCATE knowledge_entries, okf_conversion_jobs"))
            assert (
                connection.scalar(
                    text("SELECT content_version FROM knowledge_bases WHERE id = :id"),
                    {"id": knowledge_base_id},
                )
                == 5
            )

        downgrade = _alembic("20260714_0017", downgrade=True)
        assert downgrade.returncode != 0
        assert "intentionally irreversible" in downgrade.stderr
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "20260714_0018"
            )

        # Current application code intentionally requires the later 0020 AEAD
        # columns plus 0021 retirement evidence. Exercise the historical
        # namespace only after proving 0018's own forward-only boundary and
        # then restoring the disposable database to the current head.
        upgrade_head = _alembic("head")
        assert upgrade_head.returncode == 0, upgrade_head.stderr
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "20260715_0021"
            )

        asyncio.run(
            _exercise_historical_namespaces(
                async_url=async_url,
                user_id=user_id,
                api_key_id=api_key_id,
                knowledge_base_id=knowledge_base_id,
                requests=(
                    (unknown_key, unknown_request),
                    (completed_key, completed_request),
                ),
                tenant_key=tenant_key,
                provider=provider,
                model=model,
                usage_client_key=usage_client_key,
            )
        )
    finally:
        engine.dispose()


def test_0018_rolls_back_after_late_failure_and_is_safely_resumable() -> None:
    """Only the documented enum commit may survive a failed 0018 attempt."""

    sync_url, _ = _urls()
    engine = create_engine(sync_url)
    record_id = uuid4()
    try:
        assert_acceptance_database_sync(engine)
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))

        upgrade_0017 = _alembic("20260714_0017")
        assert upgrade_0017.returncode == 0, upgrade_0017.stderr

        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO chat_idempotency_records "
                    "(id, principal_hash, idempotency_key_hash, request_hash, status, "
                    "response_body, response_encoding, response_size_bytes, completed_at, "
                    "expires_at) VALUES (:id, :principal, :key_hash, :request_hash, "
                    "'COMPLETED', :payload, 'zlib-json-v1', 6, now(), "
                    "now() + interval '24 hours')"
                ),
                {
                    "id": record_id,
                    "principal": "1" * 64,
                    "key_hash": "2" * 64,
                    "request_hash": "3" * 64,
                    "payload": b"legacy",
                },
            )
            # Force a failure after 0018 has already added/backfilled columns,
            # rebuilt constraints, and created indexes. The enum label is the
            # migration's sole intentional autocommit boundary.
            connection.execute(
                text(
                    "CREATE FUNCTION public.bump_kb_content_version_after_entry_insert() "
                    "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$"
                )
            )

        failed = _alembic("20260714_0018")
        assert failed.returncode != 0

        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "20260714_0017"
            )
            labels = set(
                connection.scalars(
                    text(
                        "SELECT enumlabel FROM pg_enum "
                        "WHERE enumtypid = 'chat_idempotency_status'::regtype"
                    )
                )
            )
            assert "INVALIDATED" in labels
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND "
                        "((table_name = 'knowledge_bases' AND column_name = 'content_version') "
                        "OR (table_name = 'api_keys' AND column_name = 'credential_family_id') "
                        "OR (table_name = 'chat_idempotency_records' "
                        "AND column_name = 'knowledge_base_id'))"
                    )
                )
                == 0
            )
            historical = connection.execute(
                text(
                    "SELECT status::text, response_body "
                    "FROM chat_idempotency_records WHERE id = :id"
                ),
                {"id": record_id},
            ).one()
            assert historical == ("COMPLETED", b"legacy")

        with engine.begin() as connection:
            connection.execute(
                text("DROP FUNCTION public.bump_kb_content_version_after_entry_insert()")
            )

        resumed = _alembic("head")
        assert resumed.returncode == 0, resumed.stderr
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "20260715_0021"
            )
            migrated = connection.execute(
                text(
                    "SELECT status::text, response_body "
                    "FROM chat_idempotency_records WHERE id = :id"
                ),
                {"id": record_id},
            ).one()
            assert migrated == ("OUTCOME_UNKNOWN", None)
    finally:
        engine.dispose()
