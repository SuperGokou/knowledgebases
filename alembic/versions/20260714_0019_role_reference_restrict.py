"""Prevent role deletion from cascading into business assignments.

Revision ID: 20260714_0019
Revises: 20260714_0018
"""

from __future__ import annotations

from alembic import op

revision: str = "20260714_0019"
down_revision: str | None = "20260714_0018"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # Fail before changing constraints if a manually modified database already
    # contains orphaned business references. Silently normalizing this state
    # would hide authorization loss.
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1
            FROM user_roles AS ur
            LEFT JOIN roles AS r ON r.id = ur.role_id
            WHERE r.id IS NULL
          ) THEN
            RAISE EXCEPTION 'orphaned user_roles.role_id blocks role reference hardening';
          END IF;
          IF EXISTS (
            SELECT 1
            FROM knowledge_base_role_grants AS kbrg
            LEFT JOIN roles AS r ON r.id = kbrg.role_id
            WHERE r.id IS NULL
          ) THEN
            RAISE EXCEPTION
              'orphaned knowledge_base_role_grants.role_id blocks role reference hardening';
          END IF;
        END
        $$;
        """
    )
    op.drop_constraint(
        "fk_user_roles_role_id_roles",
        "user_roles",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_user_roles_role_id_roles",
        "user_roles",
        "roles",
        ["role_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.drop_constraint(
        "fk_knowledge_base_role_grants_role_id_roles",
        "knowledge_base_role_grants",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_knowledge_base_role_grants_role_id_roles",
        "knowledge_base_role_grants",
        "roles",
        ["role_id"],
        ["id"],
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    raise RuntimeError(
        "20260714_0019 is intentionally irreversible: restoring cascading role "
        "references could silently erase user assignments or knowledge-base grants"
    )
