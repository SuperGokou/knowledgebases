from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from app.db.schema_version import EXPECTED_ALEMBIC_HEADS


def _migration() -> ModuleType:
    path = (
        Path(__file__).resolve().parents[1]
        / "alembic/versions/20260714_0019_role_reference_restrict.py"
    )
    spec = importlib.util.spec_from_file_location("migration_20260714_0019", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_role_reference_restrict_precedes_the_current_schema_head() -> None:
    migration = _migration()

    assert migration.revision == "20260714_0019"
    assert migration.down_revision == "20260714_0018"
    assert frozenset({"20260714_0020"}) == EXPECTED_ALEMBIC_HEADS


def test_role_reference_restrict_downgrade_fails_before_any_schema_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = _migration()
    calls: list[str] = []
    for operation in ("execute", "drop_constraint", "create_foreign_key"):
        monkeypatch.setattr(
            migration.op,
            operation,
            lambda *args, _operation=operation, **kwargs: calls.append(_operation),
        )

    with pytest.raises(RuntimeError, match="intentionally irreversible"):
        migration.downgrade()

    assert calls == []
