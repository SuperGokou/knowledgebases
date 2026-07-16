"""Add a durable, content-minimized chat idempotency result ledger.

Revision ID: 20260714_0016
Revises: 20260714_0015
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "20260714_0016"
down_revision: str | None = "20260714_0015"
branch_labels: str | None = None
depends_on: str | None = None

chat_idempotency_status = sa.Enum(
    "PROCESSING",
    "COMPLETED",
    "OUTCOME_UNKNOWN",
    name="chat_idempotency_status",
)


def upgrade() -> None:
    op.create_table(
        "chat_idempotency_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("principal_hash", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "status",
            chat_idempotency_status,
            nullable=False,
            server_default=sa.text("'PROCESSING'"),
        ),
        sa.Column("response_body", sa.LargeBinary(), nullable=True),
        sa.Column("response_encoding", sa.String(length=20), nullable=True),
        sa.Column("response_size_bytes", sa.Integer(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(principal_hash) = 64 AND length(idempotency_key_hash) = 64 "
            "AND length(request_hash) = 64",
            name=op.f("ck_chat_idempotency_records_chat_idempotency_hash_lengths"),
        ),
        sa.CheckConstraint(
            "response_size_bytes IS NULL OR "
            "(response_size_bytes > 0 AND response_size_bytes <= 524288)",
            name=op.f("ck_chat_idempotency_records_chat_idempotency_response_size"),
        ),
        sa.CheckConstraint(
            "(status = 'PROCESSING' AND response_body IS NULL "
            "AND response_encoding IS NULL AND response_size_bytes IS NULL "
            "AND completed_at IS NULL AND expires_at IS NULL) OR "
            "(status = 'COMPLETED' AND response_body IS NOT NULL "
            "AND response_encoding = 'zlib-json-v1' AND response_size_bytes IS NOT NULL "
            "AND completed_at IS NOT NULL AND expires_at IS NOT NULL) OR "
            "(status = 'OUTCOME_UNKNOWN' AND response_body IS NULL "
            "AND response_encoding IS NULL AND response_size_bytes IS NULL "
            "AND completed_at IS NOT NULL AND expires_at IS NOT NULL)",
            name=op.f("ck_chat_idempotency_records_chat_idempotency_status_payload"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_chat_idempotency_records")),
        sa.UniqueConstraint(
            "principal_hash",
            "idempotency_key_hash",
            name="uq_chat_idempotency_principal_key",
        ),
    )
    op.create_index(
        "ix_chat_idempotency_status_expires",
        "chat_idempotency_records",
        ["status", "expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_chat_idempotency_status_updated",
        "chat_idempotency_records",
        ["status", "updated_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_chat_idempotency_status_updated",
        table_name="chat_idempotency_records",
    )
    op.drop_index(
        "ix_chat_idempotency_status_expires",
        table_name="chat_idempotency_records",
    )
    op.drop_table("chat_idempotency_records")
    chat_idempotency_status.drop(op.get_bind(), checkfirst=True)
