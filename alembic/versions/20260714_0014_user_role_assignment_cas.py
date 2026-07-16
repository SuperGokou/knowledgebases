"""Add a monotonic CAS version to user role assignments.

Revision ID: 20260714_0014
Revises: 20260712_0013
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "20260714_0014"
down_revision: str | None = "20260712_0013"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "role_assignment_version",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.create_check_constraint(
        op.f("ck_users_role_assignment_version_positive"),
        "users",
        "role_assignment_version >= 1",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_users_role_assignment_version_positive"),
        "users",
        type_="check",
    )
    op.drop_column("users", "role_assignment_version")
