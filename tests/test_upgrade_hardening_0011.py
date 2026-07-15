from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from app.db.schema_version import EXPECTED_ALEMBIC_HEADS

REPOSITORY = Path(__file__).resolve().parents[1]


def _load_migration(revision: str) -> Any:
    path = next((REPOSITORY / "alembic/versions").glob(f"{revision}_*.py"))
    spec = importlib.util.spec_from_file_location(f"migration_{revision}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _offline_compose() -> dict[str, Any]:
    parsed = yaml.safe_load(
        (REPOSITORY / "deploy/tencent/compose.offline.yml").read_text(encoding="utf-8")
    )
    assert isinstance(parsed, dict)
    return parsed


def test_hardening_migrations_form_the_current_schema_head_chain() -> None:
    migration = REPOSITORY / "alembic/versions/20260712_0011_scan_audit_hardening.py"

    assert migration.is_file()
    content = migration.read_text(encoding="utf-8")
    assert 'revision: str = "20260712_0011"' in content
    assert 'down_revision: str | None = "20260712_0010"' in content
    retry_migration = REPOSITORY / "alembic/versions/20260712_0012_okf_retry_generation.py"
    assert retry_migration.is_file()
    retry_content = retry_migration.read_text(encoding="utf-8")
    assert 'revision: str = "20260712_0012"' in retry_content
    assert 'down_revision: str | None = "20260712_0011"' in retry_content
    data_api_migration = REPOSITORY / "alembic/versions/20260712_0013_deny_direct_data_api.py"
    assert data_api_migration.is_file()
    data_api_content = data_api_migration.read_text(encoding="utf-8")
    assert 'revision: str = "20260712_0013"' in data_api_content
    assert 'down_revision: str | None = "20260712_0012"' in data_api_content
    role_cas_migration = REPOSITORY / "alembic/versions/20260714_0014_user_role_assignment_cas.py"
    assert role_cas_migration.is_file()
    role_cas_content = role_cas_migration.read_text(encoding="utf-8")
    assert 'revision: str = "20260714_0014"' in role_cas_content
    assert 'down_revision: str | None = "20260712_0013"' in role_cas_content
    grant_cas_migration = REPOSITORY / "alembic/versions/20260714_0015_knowledge_grant_cas.py"
    assert grant_cas_migration.is_file()
    grant_cas_content = grant_cas_migration.read_text(encoding="utf-8")
    assert 'revision: str = "20260714_0015"' in grant_cas_content
    assert 'down_revision: str | None = "20260714_0014"' in grant_cas_content
    chat_idempotency_migration = REPOSITORY / "alembic/versions/20260714_0016_chat_idempotency.py"
    assert chat_idempotency_migration.is_file()
    chat_idempotency_content = chat_idempotency_migration.read_text(encoding="utf-8")
    assert 'revision: str = "20260714_0016"' in chat_idempotency_content
    assert 'down_revision: str | None = "20260714_0015"' in chat_idempotency_content
    role_policy_cas_migration = REPOSITORY / "alembic/versions/20260714_0017_role_policy_cas.py"
    assert role_policy_cas_migration.is_file()
    role_policy_cas_content = role_policy_cas_migration.read_text(encoding="utf-8")
    assert 'revision: str = "20260714_0017"' in role_policy_cas_content
    assert 'down_revision: str | None = "20260714_0016"' in role_policy_cas_content
    chat_replay_lineage_migration = (
        REPOSITORY / "alembic/versions/20260714_0018_chat_replay_lineage.py"
    )
    assert chat_replay_lineage_migration.is_file()
    chat_replay_lineage_content = chat_replay_lineage_migration.read_text(encoding="utf-8")
    assert 'revision: str = "20260714_0018"' in chat_replay_lineage_content
    assert 'down_revision: str | None = "20260714_0017"' in chat_replay_lineage_content
    role_reference_migration = (
        REPOSITORY / "alembic/versions/20260714_0019_role_reference_restrict.py"
    )
    assert role_reference_migration.is_file()
    role_reference_content = role_reference_migration.read_text(encoding="utf-8")
    assert 'revision: str = "20260714_0019"' in role_reference_content
    assert 'down_revision: str | None = "20260714_0018"' in role_reference_content
    replay_aead_migration = REPOSITORY / "alembic/versions/20260714_0020_chat_replay_aead.py"
    assert replay_aead_migration.is_file()
    replay_aead_content = replay_aead_migration.read_text(encoding="utf-8")
    assert 'revision: str = "20260714_0020"' in replay_aead_content
    assert 'down_revision: str | None = "20260714_0019"' in replay_aead_content
    assert "aesgcm-zlib-json-v1" in replay_aead_content
    assert frozenset({"20260714_0020"}) == EXPECTED_ALEMBIC_HEADS


def test_offline_migrate_reconciles_runtime_role_on_every_upgrade() -> None:
    migrate = _offline_compose()["services"]["migrate"]
    command = " ".join(migrate["command"])
    migration_gate = (REPOSITORY / "deploy/tencent/run-migration-with-lock.py").read_text(
        encoding="utf-8"
    )

    assert command == ("python /opt/heyi/run-migration-with-lock.py --migrate-and-bootstrap")
    assert migrate["volumes"] == [
        "./run-migration-with-lock.py:/opt/heyi/run-migration-with-lock.py:ro"
    ]
    alembic_upgrade = '("alembic", "upgrade", "head")'
    runtime_role_reconcile = '(sys.executable, "-m", "app.db.runtime_role")'
    bootstrap = '(sys.executable, "-m", "app.bootstrap")'
    assert alembic_upgrade in migration_gate
    assert runtime_role_reconcile in migration_gate
    assert bootstrap in migration_gate
    assert migration_gate.index(alembic_upgrade) < migration_gate.index(runtime_role_reconcile)
    assert migration_gate.index(runtime_role_reconcile) < migration_gate.index(bootstrap)
    assert 'if operation == "--bootstrap-only":' in migration_gate
    assert "commands = commands[-1:]" in migration_gate
    assert migrate["environment"]["KB_DATABASE_RUNTIME_ROLE"] == "${POSTGRES_APP_USER:?required}"


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("upload.rejected_size_mismatch", "FAILURE"),
        ("upload.rejected_checksum_mismatch", "FAILURE"),
        ("file.malware_scan.infected", "FAILURE"),
        ("file.malware_scan.failed_closed", "FAILURE"),
        ("okf.conversion_failed", "FAILURE"),
        ("auth.login.denied", "DENIED"),
        ("auth.token.reuse_detected", "DENIED"),
    ],
)
def test_legacy_security_actions_have_explicit_non_success_results(
    action: str,
    expected: str,
) -> None:
    migration = _load_migration("20260712_0011")

    assert migration.legacy_audit_result(action) == expected


@pytest.mark.parametrize(
    "revision",
    ["20260712_0009", "20260712_0010", "20260712_0011"],
)
def test_security_and_billing_evidence_migrations_are_explicitly_irreversible(
    revision: str,
) -> None:
    migration = _load_migration(revision)

    with pytest.raises(RuntimeError, match="irreversible|archive"):
        migration.downgrade()


@pytest.mark.parametrize("revision", ["20260712_0009", "20260712_0011"])
def test_large_backfill_migrations_override_the_global_statement_timeout(
    revision: str,
) -> None:
    migration_path = next((REPOSITORY / "alembic/versions").glob(f"{revision}_*.py"))
    content = migration_path.read_text(encoding="utf-8")

    assert "SET LOCAL statement_timeout" in content
    assert "SET LOCAL lock_timeout" in content
    assert "15min" in content
