from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, call

import pytest
import sqlalchemy as sa

from app.db.models import User


def _migration() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "alembic/versions/20260715_0021_user_retirement.py"
    spec = importlib.util.spec_from_file_location("migration_20260715_0021", path)
    if spec is None or spec.loader is None:
        raise AssertionError("unable to load the user retirement migration")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_0021_adds_nullable_auditable_retirement_columns_and_self_reference(
    monkeypatch,
) -> None:
    migration = _migration()
    assert migration.revision == "20260715_0021"
    assert migration.down_revision == "20260714_0020"
    operations = Mock()
    operations.f.side_effect = lambda name: name
    monkeypatch.setattr(migration, "op", operations)

    migration.upgrade()

    added_columns = [invocation.args for invocation in operations.add_column.call_args_list]
    assert [table_name for table_name, _ in added_columns] == ["users", "users", "users"]
    assert [column.name for _, column in added_columns] == [
        "retired_at",
        "retired_by_id",
        "retirement_reason",
    ]
    assert all(column.nullable for _, column in added_columns)
    assert isinstance(added_columns[0][1].type, sa.DateTime)
    assert added_columns[0][1].type.timezone is True
    assert isinstance(added_columns[1][1].type, sa.Uuid)
    assert isinstance(added_columns[2][1].type, sa.Text)
    operations.create_foreign_key.assert_called_once_with(
        "fk_users_retired_by_id_users",
        "users",
        "users",
        ["retired_by_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    assert operations.create_check_constraint.call_args_list == [
        call(
            "ck_users_retirement_metadata_requires_timestamp",
            "users",
            "(retired_at IS NULL AND retired_by_id IS NULL AND retirement_reason IS NULL) "
            "OR (retired_at IS NOT NULL AND retired_by_id IS NOT NULL)",
        ),
        call(
            "ck_users_retirement_requires_disabled_status",
            "users",
            "retired_at IS NULL OR status = 'DISABLED'",
        ),
        call(
            "ck_users_retirement_actor_not_self",
            "users",
            "retired_by_id IS NULL OR retired_by_id <> id",
        ),
    ]


def test_user_model_declares_the_same_retirement_invariants() -> None:
    constraints = {
        constraint.name: str(constraint.sqltext)
        for constraint in User.__table__.constraints
        if isinstance(constraint, sa.CheckConstraint)
    }

    assert constraints["ck_users_retirement_metadata_requires_timestamp"] == (
        "(retired_at IS NULL AND retired_by_id IS NULL AND retirement_reason IS NULL) "
        "OR (retired_at IS NOT NULL AND retired_by_id IS NOT NULL)"
    )
    assert constraints["ck_users_retirement_requires_disabled_status"] == (
        "retired_at IS NULL OR status = 'DISABLED'"
    )
    assert constraints["ck_users_retirement_actor_not_self"] == (
        "retired_by_id IS NULL OR retired_by_id <> id"
    )


def test_0021_refuses_destructive_downgrade_of_retirement_evidence(monkeypatch) -> None:
    migration = _migration()
    operations = Mock()
    monkeypatch.setattr(migration, "op", operations)

    with pytest.raises(RuntimeError, match="intentionally irreversible.*audit evidence"):
        migration.downgrade()
    assert operations.mock_calls == []
