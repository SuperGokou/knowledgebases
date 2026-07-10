"""Add scoped API keys and runtime LLM provider settings.

Revision ID: 20260710_0005
Revises: 20260710_0004
Create Date: 2026-07-10 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260710_0005"
down_revision: str | None = "20260710_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("key_prefix", sa.String(length=24), nullable=False),
        sa.Column("permission_codes", sa.JSON(), nullable=False),
        sa.Column("knowledge_base_ids", sa.JSON(), nullable=False),
        sa.Column("requests_per_minute", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "requests_per_minute >= 1 AND requests_per_minute <= 10000",
            name="api_key_rpm_range",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name="fk_api_keys_created_by_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_api_keys_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_api_keys"),
        sa.UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),
    )
    op.create_index("ix_api_keys_created_by", "api_keys", ["created_by"], unique=False)
    op.create_index("ix_api_keys_expires_at", "api_keys", ["expires_at"], unique=False)
    op.create_index("ix_api_keys_key_prefix", "api_keys", ["key_prefix"], unique=False)
    op.create_index("ix_api_keys_revoked_at", "api_keys", ["revoked_at"], unique=False)
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"], unique=False)
    op.create_index(
        "ix_api_keys_user_created", "api_keys", ["user_id", "created_at"], unique=False
    )

    op.create_table(
        "llm_provider_configs",
        sa.Column("provider", sa.String(length=30), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("base_url", sa.String(length=500), nullable=False),
        sa.Column("api_key_ciphertext", sa.Text(), nullable=True),
        sa.Column("is_default", sa.Boolean(), nullable=False),
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
            "provider IN ('deepseek', 'qwen', 'minimax')",
            name="supported_llm_provider",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by"],
            ["users.id"],
            name="fk_llm_provider_configs_updated_by_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("provider", name="pk_llm_provider_configs"),
    )
    op.create_index(
        "ix_llm_provider_configs_updated_by",
        "llm_provider_configs",
        ["updated_by"],
        unique=False,
    )
    op.create_index(
        "uq_llm_provider_configs_default",
        "llm_provider_configs",
        ["is_default"],
        unique=True,
        postgresql_where=sa.text("is_default"),
        sqlite_where=sa.text("is_default = 1"),
    )
    provider_table = sa.table(
        "llm_provider_configs",
        sa.column("provider", sa.String()),
        sa.column("model", sa.String()),
        sa.column("base_url", sa.String()),
        sa.column("is_default", sa.Boolean()),
    )
    op.bulk_insert(
        provider_table,
        [
            {
                "provider": "deepseek",
                "model": "deepseek-v4-flash",
                "base_url": "https://api.deepseek.com",
                "is_default": True,
            },
            {
                "provider": "qwen",
                "model": "qwen-plus",
                "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
                "is_default": False,
            },
            {
                "provider": "minimax",
                "model": "MiniMax-M2.7",
                "base_url": "https://api.minimax.io/v1",
                "is_default": False,
            },
        ],
    )


def downgrade() -> None:
    op.drop_index("uq_llm_provider_configs_default", table_name="llm_provider_configs")
    op.drop_index("ix_llm_provider_configs_updated_by", table_name="llm_provider_configs")
    op.drop_table("llm_provider_configs")
    op.drop_index("ix_api_keys_user_created", table_name="api_keys")
    op.drop_index("ix_api_keys_user_id", table_name="api_keys")
    op.drop_index("ix_api_keys_revoked_at", table_name="api_keys")
    op.drop_index("ix_api_keys_key_prefix", table_name="api_keys")
    op.drop_index("ix_api_keys_expires_at", table_name="api_keys")
    op.drop_index("ix_api_keys_created_by", table_name="api_keys")
    op.drop_table("api_keys")
