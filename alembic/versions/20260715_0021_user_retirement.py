"""Add auditable, non-destructive user retirement metadata.

Revision ID: 20260715_0021
Revises: 20260714_0020
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "20260715_0021"
down_revision: str | None = "20260714_0020"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # All columns are nullable, so upgrading does not rewrite existing users.
    op.add_column("users", sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("retired_by_id", sa.Uuid(), nullable=True))
    op.add_column("users", sa.Column("retirement_reason", sa.Text(), nullable=True))
    op.create_foreign_key(
        "fk_users_retired_by_id_users",
        "users",
        "users",
        ["retired_by_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        op.f("ck_users_retirement_metadata_requires_timestamp"),
        "users",
        "(retired_at IS NULL AND retired_by_id IS NULL AND retirement_reason IS NULL) "
        "OR (retired_at IS NOT NULL AND retired_by_id IS NOT NULL)",
    )
    # SQLAlchemy persists enum member names in PostgreSQL; user_status is
    # therefore ACTIVE/DISABLED/LOCKED, not the Python-facing lowercase value.
    op.create_check_constraint(
        op.f("ck_users_retirement_requires_disabled_status"),
        "users",
        "retired_at IS NULL OR status = 'DISABLED'",
    )
    op.create_check_constraint(
        op.f("ck_users_retirement_actor_not_self"),
        "users",
        "retired_by_id IS NULL OR retired_by_id <> id",
    )


def downgrade() -> None:
    # These columns are the durable explanation for an account that can no
    # longer authenticate. Dropping them would leave disabled users and audit
    # entries without the actor/reason linkage required by the retirement
    # contract. Production rollback is therefore application rollback against
    # the expanded schema, never destructive schema downgrade.
    raise RuntimeError(
        "20260715_0021 is intentionally irreversible: dropping user retirement "
        "metadata would destroy account-lifecycle audit evidence"
    )
