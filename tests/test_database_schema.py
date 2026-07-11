from __future__ import annotations

from typing import Any

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.db import models  # noqa: F401
from app.db.base import Base
from app.db.schema_version import (
    EXPECTED_ALEMBIC_HEADS,
    DatabaseSchemaDriftError,
    assert_database_schema_current,
)


def test_enterprise_metadata_tables_are_registered() -> None:
    expected = {
        "users",
        "roles",
        "permissions",
        "user_roles",
        "role_permissions",
        "limit_definitions",
        "role_limits",
        "user_limit_overrides",
        "files",
        "upload_sessions",
        "quota_counters",
        "quota_reservations",
        "refresh_tokens",
        "audit_logs",
        "knowledge_bases",
        "knowledge_base_role_grants",
        "knowledge_entries",
        "api_keys",
        "llm_provider_configs",
    }

    assert expected <= set(Base.metadata.tables)


def test_assignment_and_limit_tables_prevent_duplicates() -> None:
    for table_name, columns in {
        "user_roles": {"user_id", "role_id"},
        "role_permissions": {"role_id", "permission_id"},
        "role_limits": {"role_id", "limit_definition_id"},
        "user_limit_overrides": {"user_id", "limit_definition_id"},
        "knowledge_base_role_grants": {"knowledge_base_id", "role_id"},
    }.items():
        table = Base.metadata.tables[table_name]
        unique_column_sets = {
            frozenset(constraint.columns.keys())
            for constraint in table.constraints
            if constraint.__class__.__name__ == "UniqueConstraint"
        }
        assert frozenset(columns) in unique_column_sets


def test_object_keys_are_unique_and_file_owner_is_indexed() -> None:
    table = Base.metadata.tables["files"]

    assert table.c.object_key.unique
    assert table.c.owner_id.index


def test_upload_expiry_cleanup_has_a_matching_index() -> None:
    table = Base.metadata.tables["upload_sessions"]
    indexes = {tuple(index.columns.keys()) for index in table.indexes}

    assert ("status", "expires_at") in indexes


def test_knowledge_files_and_entries_keep_source_and_derived_data_separate() -> None:
    files = Base.metadata.tables["files"]
    entries = Base.metadata.tables["knowledge_entries"]

    assert files.c.knowledge_base_id.index
    assert entries.c.knowledge_base_id.index
    assert entries.c.source_file_id.index
    assert {"format_version", "custom_metadata", "content"} <= set(entries.c.keys())


def test_api_keys_are_hashed_scoped_and_llm_default_is_unique() -> None:
    api_keys = Base.metadata.tables["api_keys"]
    assert "key_hash" in api_keys.c
    assert "key_prefix" in api_keys.c
    assert "knowledge_base_ids" in api_keys.c
    assert "permission_codes" in api_keys.c
    assert "key" not in api_keys.c

    providers = Base.metadata.tables["llm_provider_configs"]
    default_indexes = [
        index
        for index in providers.indexes
        if index.name == "uq_llm_provider_configs_default"
    ]
    assert len(default_indexes) == 1
    assert default_indexes[0].unique
    assert default_indexes[0].dialect_options["postgresql"]["where"] is not None
    assert default_indexes[0].dialect_options["sqlite"]["where"] is not None


def test_expected_database_heads_match_the_alembic_graph() -> None:
    script = ScriptDirectory.from_config(Config("alembic.ini"))

    assert frozenset(script.get_heads()) == EXPECTED_ALEMBIC_HEADS


class FakeRevisionResult:
    def __init__(self, revisions: set[str]) -> None:
        self._revisions = revisions

    def scalars(self) -> FakeRevisionResult:
        return self

    def all(self) -> list[str]:
        return sorted(self._revisions)


class FakeRevisionSession:
    def __init__(self, revisions: set[str]) -> None:
        self.revisions = revisions

    async def execute(self, _statement: Any) -> FakeRevisionResult:
        return FakeRevisionResult(self.revisions)


@pytest.mark.asyncio
async def test_database_schema_drift_is_rejected() -> None:
    session = FakeRevisionSession({"20260709_0001"})

    with pytest.raises(DatabaseSchemaDriftError):
        await assert_database_schema_current(session)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_current_database_schema_is_accepted() -> None:
    session = FakeRevisionSession(set(EXPECTED_ALEMBIC_HEADS))

    await assert_database_schema_current(session)  # type: ignore[arg-type]
