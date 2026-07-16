"""Encrypt durable chat replay payloads with externally managed AEAD keys.

Revision ID: 20260714_0020
Revises: 20260714_0019
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "20260714_0020"
down_revision: str | None = "20260714_0019"
branch_labels: str | None = None
depends_on: str | None = None

_STATUS_PAYLOAD_AEAD = """
(status = 'PROCESSING'
 AND response_body IS NULL
 AND response_encoding IS NULL
 AND response_size_bytes IS NULL
 AND response_key_version IS NULL
 AND response_nonce IS NULL
 AND completed_at IS NULL
 AND expires_at IS NULL)
OR
(status = 'COMPLETED'
 AND response_body IS NOT NULL
 AND response_encoding = 'aesgcm-zlib-json-v1'
 AND response_size_bytes IS NOT NULL
 AND response_key_version IS NOT NULL
 AND response_key_version > 0
 AND response_nonce IS NOT NULL
 AND octet_length(response_nonce) = 12
 AND completed_at IS NOT NULL
 AND expires_at IS NOT NULL)
OR
(status IN ('OUTCOME_UNKNOWN', 'INVALIDATED')
 AND response_body IS NULL
 AND response_encoding IS NULL
 AND response_size_bytes IS NULL
 AND response_key_version IS NULL
 AND response_nonce IS NULL
 AND completed_at IS NOT NULL
 AND expires_at IS NOT NULL)
"""


def upgrade() -> None:
    op.add_column(
        "chat_idempotency_records",
        sa.Column("response_key_version", sa.Integer(), nullable=True),
    )
    op.add_column(
        "chat_idempotency_records",
        sa.Column("response_nonce", sa.LargeBinary(), nullable=True),
    )

    # No replay payload created by 0016-0019 was authenticated or encrypted.
    # Its outcome remains terminal, but retaining the reversible zlib bytes
    # would preserve the original database/backup disclosure. Destructive
    # invalidation is the only safe forward migration without access to the
    # external keyring inside Alembic.
    op.execute(
        """
        UPDATE chat_idempotency_records
        SET status = 'OUTCOME_UNKNOWN',
            response_body = NULL,
            response_encoding = NULL,
            response_size_bytes = NULL,
            response_key_version = NULL,
            response_nonce = NULL,
            completed_at = COALESCE(completed_at, now()),
            expires_at = COALESCE(expires_at, now() + interval '24 hours')
        WHERE status = 'COMPLETED'
           OR response_body IS NOT NULL
           OR response_encoding IS NOT NULL
           OR response_size_bytes IS NOT NULL
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
        _STATUS_PAYLOAD_AEAD,
    )


def downgrade() -> None:
    raise RuntimeError(
        "20260714_0020 is intentionally irreversible: legacy plaintext replay "
        "payloads were destroyed and must never be restored"
    )
