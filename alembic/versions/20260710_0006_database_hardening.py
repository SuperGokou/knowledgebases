"""Harden extension placement and foreign-key lookups.

Revision ID: 20260710_0006
Revises: 20260710_0005
Create Date: 2026-07-10 00:00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260710_0006"
down_revision: str | None = "20260710_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS extensions")
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM pg_extension AS extension
                JOIN pg_namespace AS namespace
                  ON namespace.oid = extension.extnamespace
                WHERE extension.extname = 'pg_trgm'
                  AND namespace.nspname <> 'extensions'
            ) THEN
                ALTER EXTENSION pg_trgm SET SCHEMA extensions;
            END IF;
        END
        $$
        """
    )

    op.create_index(
        "ix_role_limits_limit_definition_id",
        "role_limits",
        ["limit_definition_id"],
    )
    op.create_index(
        "ix_user_limit_overrides_limit_definition_id",
        "user_limit_overrides",
        ["limit_definition_id"],
    )
    op.create_index(
        "ix_user_roles_assigned_by",
        "user_roles",
        ["assigned_by"],
    )


def downgrade() -> None:
    op.drop_index("ix_user_roles_assigned_by", table_name="user_roles")
    op.drop_index(
        "ix_user_limit_overrides_limit_definition_id",
        table_name="user_limit_overrides",
    )
    op.drop_index("ix_role_limits_limit_definition_id", table_name="role_limits")
    # Keep the extension outside public: reverting that security boundary would
    # reintroduce the Supabase advisor finding this migration resolves.
