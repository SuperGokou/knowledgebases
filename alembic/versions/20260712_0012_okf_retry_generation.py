"""Add a monotonic generation to OKF provider-call idempotency keys.

Revision ID: 20260712_0012
Revises: 20260712_0011
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "20260712_0012"
down_revision: str | None = "20260712_0011"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "okf_conversion_jobs",
        sa.Column(
            "retry_generation",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.alter_column("okf_conversion_jobs", "retry_generation", server_default=None)
    op.create_check_constraint(
        op.f("ck_okf_conversion_jobs_okf_conversion_retry_generation_non_negative"),
        "okf_conversion_jobs",
        "retry_generation >= 0",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_okf_conversion_jobs_okf_conversion_retry_generation_non_negative"),
        "okf_conversion_jobs",
        type_="check",
    )
    op.drop_column("okf_conversion_jobs", "retry_generation")
