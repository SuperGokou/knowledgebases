"""Add a monotonic CAS version to role policy mutations.

Revision ID: 20260714_0017
Revises: 20260714_0016
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "20260714_0017"
down_revision: str | None = "20260714_0016"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "roles",
        sa.Column(
            "policy_version",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.create_check_constraint(
        op.f("ck_roles_policy_version_positive"),
        "roles",
        "policy_version >= 1",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_roles_policy_version_positive"),
        "roles",
        type_="check",
    )
    op.drop_column("roles", "policy_version")
