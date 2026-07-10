"""Add durable OKF conversion jobs.

Revision ID: 20260710_0003
Revises: 20260710_0002
Create Date: 2026-07-10 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260710_0003"
down_revision: str | None = "20260710_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "knowledge_bases",
        sa.Column(
            "external_llm_processing_enabled",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )
    publication_status = sa.Enum(
        "DRAFT",
        "PUBLISHED",
        name="knowledge_entry_publication_status",
    )
    op.add_column(
        "knowledge_entries",
        sa.Column(
            "publication_status",
            publication_status,
            server_default="PUBLISHED",
            nullable=False,
        ),
    )
    conversion_status = sa.Enum(
        "PENDING",
        "PROCESSING",
        "RETRY_WAIT",
        "SUCCEEDED",
        "FAILED",
        "UNSUPPORTED",
        name="okf_conversion_status",
    )
    op.create_table(
        "okf_conversion_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("knowledge_base_id", sa.Uuid(), nullable=False),
        sa.Column("file_version", sa.Integer(), nullable=False),
        sa.Column("status", conversion_status, nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=True),
        sa.Column("prompt_version", sa.String(length=50), nullable=False),
        sa.Column("output_entry_id", sa.Uuid(), nullable=True),
        sa.Column("error_code", sa.String(length=100), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_id", sa.Uuid(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["file_id"],
            ["files.id"],
            name="fk_okf_conversion_jobs_file_id_files",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["knowledge_base_id"],
            ["knowledge_bases.id"],
            name="fk_okf_conversion_jobs_knowledge_base_id_knowledge_bases",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["output_entry_id"],
            ["knowledge_entries.id"],
            name="fk_okf_conversion_jobs_output_entry_id_knowledge_entries",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_okf_conversion_jobs"),
        sa.UniqueConstraint("file_id", "file_version", name="uq_okf_conversion_file_version"),
        sa.UniqueConstraint("output_entry_id", name="uq_okf_conversion_jobs_output_entry_id"),
    )
    op.create_index("ix_okf_conversion_jobs_file_id", "okf_conversion_jobs", ["file_id"])
    op.create_index(
        "ix_okf_conversion_jobs_knowledge_base_id",
        "okf_conversion_jobs",
        ["knowledge_base_id"],
    )
    op.create_index(
        "ix_okf_conversion_jobs_next_attempt_at",
        "okf_conversion_jobs",
        ["next_attempt_at"],
    )
    op.create_index("ix_okf_conversion_jobs_locked_at", "okf_conversion_jobs", ["locked_at"])
    op.create_index("ix_okf_conversion_jobs_lease_id", "okf_conversion_jobs", ["lease_id"])
    op.create_index(
        "ix_okf_conversion_claim",
        "okf_conversion_jobs",
        ["status", "next_attempt_at", "created_at"],
    )


def downgrade() -> None:
    op.drop_table("okf_conversion_jobs")
    sa.Enum(name="okf_conversion_status").drop(op.get_bind(), checkfirst=True)
    op.drop_column("knowledge_entries", "publication_status")
    sa.Enum(name="knowledge_entry_publication_status").drop(
        op.get_bind(), checkfirst=True
    )
    op.drop_column("knowledge_bases", "external_llm_processing_enabled")
