"""Add a monotonic CAS version to knowledge-base role grants.

Revision ID: 20260714_0015
Revises: 20260714_0014
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "20260714_0015"
down_revision: str | None = "20260714_0014"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "knowledge_bases",
        sa.Column(
            "role_grant_version",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.create_check_constraint(
        op.f("ck_knowledge_bases_role_grant_version_positive"),
        "knowledge_bases",
        "role_grant_version >= 1",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_knowledge_bases_role_grant_version_positive"),
        "knowledge_bases",
        type_="check",
    )
    op.drop_column("knowledge_bases", "role_grant_version")
