"""Add fail-closed LLM pricing, budgets, reservations, and usage ledger.

Revision ID: 20260712_0010
Revises: 20260712_0009
Create Date: 2026-07-12 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260712_0010"
down_revision: str | None = "20260712_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

llm_usage_status = sa.Enum(
    "HELD",
    "SETTLED",
    "RELEASED",
    "INDETERMINATE",
    name="llm_usage_status",
)


def upgrade() -> None:
    op.create_table(
        "llm_model_prices",
        sa.Column("provider", sa.String(length=30), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("input_micro_usd_per_million_tokens", sa.BigInteger(), nullable=False),
        sa.Column("output_micro_usd_per_million_tokens", sa.BigInteger(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "input_micro_usd_per_million_tokens >= 0",
            name="llm_model_price_non_negative_input",
        ),
        sa.CheckConstraint(
            "output_micro_usd_per_million_tokens >= 0",
            name="llm_model_price_non_negative_output",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by"],
            ["users.id"],
            name="fk_llm_model_prices_updated_by_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("provider", "model", name="pk_llm_model_prices"),
    )
    op.create_index(
        "ix_llm_model_prices_updated_by",
        "llm_model_prices",
        ["updated_by"],
        unique=False,
    )

    op.create_table(
        "llm_budget_policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("tenant_key", sa.String(length=100), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("api_key_id", sa.Uuid(), nullable=True),
        sa.Column("provider", sa.String(length=30), nullable=True),
        sa.Column("model", sa.String(length=100), nullable=True),
        sa.Column("daily_token_limit", sa.BigInteger(), nullable=True),
        sa.Column("monthly_token_limit", sa.BigInteger(), nullable=True),
        sa.Column("daily_cost_limit_micro_usd", sa.BigInteger(), nullable=True),
        sa.Column("monthly_cost_limit_micro_usd", sa.BigInteger(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "daily_token_limit IS NOT NULL OR monthly_token_limit IS NOT NULL OR "
            "daily_cost_limit_micro_usd IS NOT NULL OR "
            "monthly_cost_limit_micro_usd IS NOT NULL",
            name="llm_budget_policy_has_limit",
        ),
        sa.CheckConstraint(
            "(daily_token_limit IS NULL OR daily_token_limit >= 0) AND "
            "(monthly_token_limit IS NULL OR monthly_token_limit >= 0) AND "
            "(daily_cost_limit_micro_usd IS NULL OR daily_cost_limit_micro_usd >= 0) AND "
            "(monthly_cost_limit_micro_usd IS NULL OR monthly_cost_limit_micro_usd >= 0)",
            name="llm_budget_policy_non_negative_limits",
        ),
        sa.ForeignKeyConstraint(
            ["api_key_id"],
            ["api_keys.id"],
            name="fk_llm_budget_policies_api_key_id_api_keys",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by"],
            ["users.id"],
            name="fk_llm_budget_policies_updated_by_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_llm_budget_policies_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_llm_budget_policies"),
    )
    op.create_index(
        "ix_llm_budget_policies_api_key_id",
        "llm_budget_policies",
        ["api_key_id"],
        unique=False,
    )
    op.create_index(
        "ix_llm_budget_policies_updated_by",
        "llm_budget_policies",
        ["updated_by"],
        unique=False,
    )
    op.create_index(
        "ix_llm_budget_policies_user_id",
        "llm_budget_policies",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_llm_budget_policy_match",
        "llm_budget_policies",
        ["tenant_key", "user_id", "api_key_id", "provider", "model", "enabled"],
        unique=False,
    )

    op.create_table(
        "llm_budget_counters",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("window_kind", sa.String(length=10), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_token_count", sa.BigInteger(), nullable=False),
        sa.Column("reserved_token_count", sa.BigInteger(), nullable=False),
        sa.Column("used_cost_micro_usd", sa.BigInteger(), nullable=False),
        sa.Column("reserved_cost_micro_usd", sa.BigInteger(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "used_token_count >= 0 AND reserved_token_count >= 0 AND "
            "used_cost_micro_usd >= 0 AND reserved_cost_micro_usd >= 0",
            name="llm_budget_counter_non_negative",
        ),
        sa.CheckConstraint(
            "window_kind IN ('day', 'month')",
            name="llm_budget_window_kind",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["llm_budget_policies.id"],
            name="fk_llm_budget_counters_policy_id_llm_budget_policies",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_llm_budget_counters"),
        sa.UniqueConstraint(
            "policy_id",
            "window_kind",
            "window_start",
            name="uq_llm_budget_counter_window",
        ),
    )
    op.create_index(
        "ix_llm_budget_counters_policy_id",
        "llm_budget_counters",
        ["policy_id"],
        unique=False,
    )

    op.create_table(
        "llm_usage_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_key", sa.String(length=100), nullable=False),
        sa.Column("idempotency_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("api_key_id", sa.Uuid(), nullable=True),
        sa.Column("knowledge_base_id", sa.Uuid(), nullable=True),
        sa.Column("provider", sa.String(length=30), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("operation", sa.String(length=100), nullable=False),
        sa.Column("status", llm_usage_status, nullable=False),
        sa.Column("reserved_input_tokens", sa.BigInteger(), nullable=False),
        sa.Column("reserved_output_tokens", sa.BigInteger(), nullable=False),
        sa.Column("reserved_token_count", sa.BigInteger(), nullable=False),
        sa.Column("reserved_cost_micro_usd", sa.BigInteger(), nullable=False),
        sa.Column(
            "input_price_micro_usd_per_million_tokens", sa.BigInteger(), nullable=False
        ),
        sa.Column(
            "output_price_micro_usd_per_million_tokens", sa.BigInteger(), nullable=False
        ),
        sa.Column("actual_input_tokens", sa.BigInteger(), nullable=True),
        sa.Column("actual_output_tokens", sa.BigInteger(), nullable=True),
        sa.Column("actual_token_count", sa.BigInteger(), nullable=True),
        sa.Column("actual_cost_micro_usd", sa.BigInteger(), nullable=True),
        sa.Column("error_code", sa.String(length=100), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("settled_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(actual_input_tokens IS NULL OR actual_input_tokens >= 0) AND "
            "(actual_output_tokens IS NULL OR actual_output_tokens >= 0) AND "
            "(actual_token_count IS NULL OR actual_token_count >= 0) AND "
            "(actual_cost_micro_usd IS NULL OR actual_cost_micro_usd >= 0)",
            name="llm_usage_non_negative_actual",
        ),
        sa.CheckConstraint(
            "reserved_input_tokens >= 0 AND reserved_output_tokens >= 0 AND "
            "reserved_token_count >= 0 AND reserved_cost_micro_usd >= 0",
            name="llm_usage_non_negative_reservation",
        ),
        sa.ForeignKeyConstraint(
            ["api_key_id"],
            ["api_keys.id"],
            name="fk_llm_usage_records_api_key_id_api_keys",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["knowledge_base_id"],
            ["knowledge_bases.id"],
            name="fk_llm_usage_records_knowledge_base_id_knowledge_bases",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_llm_usage_records_user_id_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_llm_usage_records"),
        sa.UniqueConstraint(
            "tenant_key",
            "idempotency_hash",
            name="uq_llm_usage_tenant_idempotency",
        ),
    )
    for column in ("api_key_id", "created_at", "knowledge_base_id", "user_id"):
        op.create_index(
            f"ix_llm_usage_records_{column}",
            "llm_usage_records",
            [column],
            unique=False,
        )
    op.create_index(
        "ix_llm_usage_dimensions",
        "llm_usage_records",
        ["provider", "model", "user_id", "api_key_id"],
        unique=False,
    )
    op.create_index(
        "ix_llm_usage_tenant_created",
        "llm_usage_records",
        ["tenant_key", "created_at", "id"],
        unique=False,
    )
    op.create_index(
        "ix_llm_usage_knowledge_base_status",
        "llm_usage_records",
        ["knowledge_base_id", "status"],
        unique=False,
    )

    op.create_table(
        "llm_usage_budget_holds",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("usage_id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("window_kind", sa.String(length=10), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reserved_token_count", sa.BigInteger(), nullable=False),
        sa.Column("reserved_cost_micro_usd", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "window_kind IN ('day', 'month')",
            name="llm_hold_window_kind",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["llm_budget_policies.id"],
            name="fk_llm_usage_budget_holds_policy_id_llm_budget_policies",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["usage_id"],
            ["llm_usage_records.id"],
            name="fk_llm_usage_budget_holds_usage_id_llm_usage_records",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_llm_usage_budget_holds"),
        sa.UniqueConstraint(
            "usage_id",
            "policy_id",
            "window_kind",
            name="uq_llm_usage_budget_hold",
        ),
    )
    op.create_index(
        "ix_llm_usage_budget_holds_policy_id",
        "llm_usage_budget_holds",
        ["policy_id"],
        unique=False,
    )
    op.create_index(
        "ix_llm_usage_budget_holds_usage_id",
        "llm_usage_budget_holds",
        ["usage_id"],
        unique=False,
    )


def downgrade() -> None:
    raise RuntimeError(
        "20260712_0010 is irreversible: downgrade would delete billing, token-usage, "
        "budget, and reservation evidence; restore a verified pre-upgrade archive "
        "instead"
    )
