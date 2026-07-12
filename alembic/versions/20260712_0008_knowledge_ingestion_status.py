"""Expose file knowledge-ingestion state separately from download availability.

Revision ID: 20260712_0008
Revises: 20260712_0007
Create Date: 2026-07-12 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260712_0008"
down_revision: str | None = "20260712_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

knowledge_status = sa.Enum(
    "NOT_REQUESTED",
    "PENDING",
    "DRAFT_READY",
    "INDEXED",
    "FAILED",
    "UNSUPPORTED",
    name="knowledge_ingestion_status",
)


def upgrade() -> None:
    knowledge_status.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "files",
        sa.Column(
            "knowledge_status",
            knowledge_status,
            server_default="NOT_REQUESTED",
            nullable=False,
        ),
    )
    op.add_column(
        "files",
        sa.Column("knowledge_error_code", sa.String(length=100), nullable=True),
    )
    op.execute(
        """
        UPDATE files AS file
        SET knowledge_status = CASE latest.status::text
            WHEN 'PENDING' THEN 'PENDING'::knowledge_ingestion_status
            WHEN 'PROCESSING' THEN 'PENDING'::knowledge_ingestion_status
            WHEN 'RETRY_WAIT' THEN 'PENDING'::knowledge_ingestion_status
            WHEN 'SUCCEEDED' THEN 'DRAFT_READY'::knowledge_ingestion_status
            WHEN 'FAILED' THEN 'FAILED'::knowledge_ingestion_status
            WHEN 'UNSUPPORTED' THEN 'UNSUPPORTED'::knowledge_ingestion_status
            ELSE 'NOT_REQUESTED'::knowledge_ingestion_status
        END,
        knowledge_error_code = latest.error_code
        FROM (
            SELECT DISTINCT ON (file_id) file_id, status, error_code
            FROM okf_conversion_jobs
            ORDER BY file_id, file_version DESC
        ) AS latest
        WHERE latest.file_id = file.id
        """
    )
    op.execute(
        """
        UPDATE files AS file
        SET knowledge_status = 'INDEXED'::knowledge_ingestion_status,
            knowledge_error_code = NULL
        WHERE EXISTS (
            SELECT 1
            FROM knowledge_entries AS entry
            WHERE entry.source_file_id = file.id
              AND entry.publication_status = 'PUBLISHED'
              AND entry.deleted_at IS NULL
        )
        """
    )


def downgrade() -> None:
    op.drop_column("files", "knowledge_error_code")
    op.drop_column("files", "knowledge_status")
    knowledge_status.drop(op.get_bind(), checkfirst=True)
