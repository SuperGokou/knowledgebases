from app.db import models  # noqa: F401
from app.db.base import Base


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
