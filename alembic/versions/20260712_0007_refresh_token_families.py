"""Track refresh-token families and detect credential reuse.

Revision ID: 20260712_0007
Revises: 20260710_0006
Create Date: 2026-07-12 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260712_0007"
down_revision: str | None = "20260710_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("refresh_tokens", sa.Column("family_id", sa.Uuid(), nullable=True))
    op.add_column("refresh_tokens", sa.Column("parent_id", sa.Uuid(), nullable=True))
    op.add_column("refresh_tokens", sa.Column("replaced_by_id", sa.Uuid(), nullable=True))
    op.add_column(
        "refresh_tokens",
        sa.Column("reuse_detected_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute("UPDATE refresh_tokens SET family_id = id WHERE family_id IS NULL")
    op.alter_column("refresh_tokens", "family_id", nullable=False)
    op.create_index(
        "ix_refresh_tokens_family_id",
        "refresh_tokens",
        ["family_id"],
        unique=False,
    )
    op.create_index(
        "ix_refresh_tokens_parent_id",
        "refresh_tokens",
        ["parent_id"],
        unique=False,
    )
    op.create_unique_constraint(
        "uq_refresh_tokens_replaced_by_id",
        "refresh_tokens",
        ["replaced_by_id"],
    )
    op.create_foreign_key(
        "fk_refresh_tokens_parent_id",
        "refresh_tokens",
        "refresh_tokens",
        ["parent_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_refresh_tokens_replaced_by_id",
        "refresh_tokens",
        "refresh_tokens",
        ["replaced_by_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_refresh_tokens_replaced_by_id",
        "refresh_tokens",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_refresh_tokens_parent_id",
        "refresh_tokens",
        type_="foreignkey",
    )
    op.drop_constraint(
        "uq_refresh_tokens_replaced_by_id",
        "refresh_tokens",
        type_="unique",
    )
    op.drop_index("ix_refresh_tokens_parent_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_family_id", table_name="refresh_tokens")
    op.drop_column("refresh_tokens", "reuse_detected_at")
    op.drop_column("refresh_tokens", "replaced_by_id")
    op.drop_column("refresh_tokens", "parent_id")
    op.drop_column("refresh_tokens", "family_id")
