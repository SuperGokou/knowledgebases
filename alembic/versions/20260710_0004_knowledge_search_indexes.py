"""Add multilingual trigram indexes for bounded knowledge search.

Revision ID: 20260710_0004
Revises: 20260710_0003
Create Date: 2026-07-10 00:00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260710_0004"
down_revision: str | None = "20260710_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Trigram search preserves substring matching for Chinese and mixed-language
    # documents while avoiding a sequential scan for every chat query.
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute(
        "CREATE INDEX ix_knowledge_entries_title_trgm "
        "ON knowledge_entries USING gin (title gin_trgm_ops)"
    )
    op.execute(
        "CREATE INDEX ix_knowledge_entries_content_trgm "
        "ON knowledge_entries USING gin (content gin_trgm_ops)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_knowledge_entries_content_trgm")
    op.execute("DROP INDEX IF EXISTS ix_knowledge_entries_title_trgm")
