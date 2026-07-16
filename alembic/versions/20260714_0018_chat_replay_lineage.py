"""Bind chat replay to content revisions and stable API credential families.

Revision ID: 20260714_0018
Revises: 20260714_0017
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "20260714_0018"
down_revision: str | None = "20260714_0017"
branch_labels: str | None = None
depends_on: str | None = None


_STATUS_PAYLOAD_V2 = (
    "(status = 'PROCESSING' AND response_body IS NULL "
    "AND response_encoding IS NULL AND response_size_bytes IS NULL "
    "AND completed_at IS NULL AND expires_at IS NULL) OR "
    "(status = 'COMPLETED' AND response_body IS NOT NULL "
    "AND response_encoding IS NOT NULL AND response_encoding = 'zlib-json-v1' "
    "AND response_size_bytes IS NOT NULL "
    "AND completed_at IS NOT NULL AND expires_at IS NOT NULL) OR "
    "(status IN ('OUTCOME_UNKNOWN', 'INVALIDATED') AND response_body IS NULL "
    "AND response_encoding IS NULL AND response_size_bytes IS NULL "
    "AND completed_at IS NOT NULL AND expires_at IS NOT NULL)"
)


def upgrade() -> None:
    # PostgreSQL cannot safely reference a newly-added enum label until the
    # ALTER TYPE transaction commits. Alembic's autocommit block is the
    # documented boundary for additive enum evolution.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE chat_idempotency_status ADD VALUE IF NOT EXISTS 'INVALIDATED'")

    op.add_column(
        "knowledge_bases",
        sa.Column(
            "content_version",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.create_check_constraint(
        op.f("ck_knowledge_bases_content_version_positive"),
        "knowledge_bases",
        "content_version >= 1",
    )

    op.add_column(
        "api_keys",
        sa.Column("credential_family_id", sa.Uuid(), nullable=True),
    )
    op.execute("UPDATE api_keys SET credential_family_id = id")
    op.alter_column("api_keys", "credential_family_id", nullable=False)
    op.create_index(
        "ix_api_keys_credential_family",
        "api_keys",
        ["credential_family_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "uq_api_keys_active_credential_family",
        "api_keys",
        ["credential_family_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )

    op.add_column(
        "llm_usage_records",
        sa.Column("api_key_credential_family_id", sa.Uuid(), nullable=True),
    )
    op.execute(
        """
        UPDATE llm_usage_records AS usage
        SET api_key_credential_family_id = api_key.credential_family_id
        FROM api_keys AS api_key
        WHERE usage.api_key_id = api_key.id
        """
    )
    op.create_index(
        "ix_llm_usage_api_key_family_created",
        "llm_usage_records",
        ["api_key_credential_family_id", "created_at"],
        unique=False,
    )
    op.create_check_constraint(
        op.f("ck_llm_usage_records_llm_usage_api_key_family_required"),
        "llm_usage_records",
        "api_key_id IS NULL OR api_key_credential_family_id IS NOT NULL",
    )

    op.add_column(
        "chat_idempotency_records",
        sa.Column("knowledge_base_id", sa.Uuid(), nullable=True),
    )
    op.add_column(
        "chat_idempotency_records",
        sa.Column("knowledge_base_content_version", sa.BigInteger(), nullable=True),
    )
    op.create_foreign_key(
        op.f("fk_chat_idempotency_records_knowledge_base_id_knowledge_bases"),
        "chat_idempotency_records",
        "knowledge_bases",
        ["knowledge_base_id"],
        ["id"],
        ondelete="CASCADE",
    )
    # Pre-0018 rows cannot be tied back to a KB because 0016 deliberately kept
    # only a request hash. Preserve the key claim but remove every replayable
    # payload so an upgrade cannot disclose or double-execute an unknown result.
    op.execute(
        """
        UPDATE chat_idempotency_records
        SET status = 'OUTCOME_UNKNOWN',
            response_body = NULL,
            response_encoding = NULL,
            response_size_bytes = NULL,
            completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP),
            expires_at = GREATEST(
                COALESCE(expires_at, CURRENT_TIMESTAMP),
                CURRENT_TIMESTAMP + INTERVAL '24 hours'
            )
        """
    )

    op.drop_constraint(
        op.f("ck_chat_idempotency_records_chat_idempotency_status_payload"),
        "chat_idempotency_records",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_chat_idempotency_records_chat_idempotency_status_payload"),
        "chat_idempotency_records",
        _STATUS_PAYLOAD_V2,
    )
    op.create_check_constraint(
        op.f("ck_chat_idempotency_records_chat_idempotency_resource_snapshot"),
        "chat_idempotency_records",
        "((knowledge_base_id IS NULL AND knowledge_base_content_version IS NULL "
        "AND status = 'OUTCOME_UNKNOWN') OR "
        "(knowledge_base_id IS NOT NULL "
        "AND knowledge_base_content_version IS NOT NULL "
        "AND knowledge_base_content_version >= 1))",
    )
    op.drop_constraint(
        op.f("ck_chat_idempotency_records_chat_idempotency_hash_lengths"),
        "chat_idempotency_records",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_chat_idempotency_records_chat_idempotency_hash_lengths"),
        "chat_idempotency_records",
        "octet_length(principal_hash) = 64 "
        "AND octet_length(idempotency_key_hash) = 64 "
        "AND octet_length(request_hash) = 64",
    )
    op.create_check_constraint(
        op.f("ck_chat_idempotency_records_chat_idempotency_response_octets"),
        "chat_idempotency_records",
        "response_body IS NULL OR octet_length(response_body) <= 524288",
    )
    op.create_index(
        "ix_chat_idempotency_kb_status",
        "chat_idempotency_records",
        ["knowledge_base_id", "status"],
        unique=False,
    )

    # Transition-table statement triggers update each affected KB once, even
    # for a bulk import. This avoids one parent-row UPDATE/WAL record per entry.
    op.execute(
        """
        CREATE FUNCTION bump_kb_content_version_after_entry_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            UPDATE knowledge_bases AS kb
            SET content_version = kb.content_version + 1
            FROM (
                SELECT DISTINCT knowledge_base_id
                FROM new_entries
                WHERE deleted_at IS NULL AND publication_status::text = 'PUBLISHED'
            ) AS affected
            WHERE kb.id = affected.knowledge_base_id;
            RETURN NULL;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION bump_kb_content_version_after_entry_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            UPDATE knowledge_bases AS kb
            SET content_version = kb.content_version + 1
            FROM (
                SELECT knowledge_base_id FROM old_entries
                WHERE deleted_at IS NULL AND publication_status::text = 'PUBLISHED'
                UNION
                SELECT knowledge_base_id FROM new_entries
                WHERE deleted_at IS NULL AND publication_status::text = 'PUBLISHED'
            ) AS affected
            WHERE kb.id = affected.knowledge_base_id;
            RETURN NULL;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION bump_kb_content_version_after_entry_delete()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            UPDATE knowledge_bases AS kb
            SET content_version = kb.content_version + 1
            FROM (
                SELECT DISTINCT knowledge_base_id
                FROM old_entries
                WHERE deleted_at IS NULL AND publication_status::text = 'PUBLISHED'
            ) AS affected
            WHERE kb.id = affected.knowledge_base_id;
            RETURN NULL;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION bump_all_kb_content_versions_after_entry_truncate()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            UPDATE knowledge_bases SET content_version = content_version + 1;
            RETURN NULL;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_knowledge_entries_content_version_insert
        AFTER INSERT ON knowledge_entries
        REFERENCING NEW TABLE AS new_entries
        FOR EACH STATEMENT
        EXECUTE FUNCTION bump_kb_content_version_after_entry_insert()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_knowledge_entries_content_version_update
        AFTER UPDATE ON knowledge_entries
        REFERENCING OLD TABLE AS old_entries NEW TABLE AS new_entries
        FOR EACH STATEMENT
        EXECUTE FUNCTION bump_kb_content_version_after_entry_update()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_knowledge_entries_content_version_delete
        AFTER DELETE ON knowledge_entries
        REFERENCING OLD TABLE AS old_entries
        FOR EACH STATEMENT
        EXECUTE FUNCTION bump_kb_content_version_after_entry_delete()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_knowledge_entries_content_version_truncate
        AFTER TRUNCATE ON knowledge_entries
        FOR EACH STATEMENT
        EXECUTE FUNCTION bump_all_kb_content_versions_after_entry_truncate()
        """
    )


def downgrade() -> None:
    raise RuntimeError(
        "20260714_0018 is intentionally irreversible: removing content snapshots "
        "or credential-family namespaces could replay stale data or execute a "
        "previously claimed provider request twice. Restore the pre-upgrade database "
        "backup during a maintenance window instead."
    )
