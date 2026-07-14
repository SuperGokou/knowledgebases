"""Deny direct Data API access to application-owned tables.

Revision ID: 20260712_0013
Revises: 20260712_0012
"""

from __future__ import annotations

from alembic import op

revision: str = "20260712_0013"
down_revision: str | None = "20260712_0012"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # PostgreSQL grants PUBLIC no table privileges by default, but explicitly
    # revoking them makes the intended boundary auditable and repairs projects
    # whose owner/default ACLs were changed before this migration.
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC")
    op.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC")
    op.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC"
    )

    # Supabase's Data API connects as anon/authenticated. These roles are not
    # present in the isolated PostgreSQL profile, so the block is portable.
    # When present, deny both existing objects and future objects owned by the
    # migration identity. Application access continues through the private
    # runtime role and FastAPI authorization boundary.
    op.execute(
        """
        DO $deny_data_api$
        DECLARE
          data_api_role text;
        BEGIN
          FOREACH data_api_role IN ARRAY ARRAY['anon', 'authenticated']
          LOOP
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = data_api_role) THEN
              EXECUTE format(
                'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I',
                data_api_role
              );
              EXECUTE format(
                'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %I',
                data_api_role
              );
              EXECUTE format(
                'ALTER DEFAULT PRIVILEGES IN SCHEMA public '
                'REVOKE ALL ON TABLES FROM %I',
                data_api_role
              );
              EXECUTE format(
                'ALTER DEFAULT PRIVILEGES IN SCHEMA public '
                'REVOKE ALL ON SEQUENCES FROM %I',
                data_api_role
              );
            END IF;
          END LOOP;
        END
        $deny_data_api$;
        """
    )


def downgrade() -> None:
    # Restoring broad Data API grants would re-open the authorization bypass.
    # Operators who intentionally expose a table must create a reviewed,
    # table-specific policy in a separate forward migration.
    pass
