"""Create the initial enterprise knowledge-base schema.

Revision ID: 20260709_0001
Revises:
Create Date: 2026-07-09 00:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260709_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=True),
        sa.Column(
            "status",
            sa.Enum("ACTIVE", "DISABLED", "LOCKED", name="user_status"),
            nullable=False,
        ),
        sa.Column("is_superuser", sa.Boolean(), nullable=False),
        sa.Column("token_version", sa.Integer(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_users"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("code", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("is_system", sa.Boolean(), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name="pk_roles"),
        sa.UniqueConstraint("code", name="uq_roles_code"),
    )

    op.create_table(
        "permissions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("code", sa.String(length=150), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_permissions"),
        sa.UniqueConstraint("code", name="uq_permissions_code"),
    )

    op.create_table(
        "limit_definitions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("key", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("unit", sa.String(length=50), nullable=False),
        sa.Column("window", sa.String(length=30), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_limit_definitions"),
        sa.UniqueConstraint("key", name="uq_limit_definitions_key"),
    )

    op.create_table(
        "user_roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("assigned_by", sa.Uuid(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["assigned_by"],
            ["users.id"],
            name="fk_user_roles_assigned_by_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_user_roles_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_roles_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_roles"),
        sa.UniqueConstraint("user_id", "role_id", name="uq_user_roles_pair"),
    )
    op.create_index("ix_user_roles_role_id", "user_roles", ["role_id"], unique=False)
    op.create_index("ix_user_roles_user_id", "user_roles", ["user_id"], unique=False)

    op.create_table(
        "role_permissions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("permission_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name="fk_role_permissions_permission_id_permissions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_role_permissions_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_role_permissions"),
        sa.UniqueConstraint("role_id", "permission_id", name="uq_role_permissions_pair"),
    )
    op.create_index(
        "ix_role_permissions_permission_id",
        "role_permissions",
        ["permission_id"],
        unique=False,
    )
    op.create_index("ix_role_permissions_role_id", "role_permissions", ["role_id"], unique=False)

    op.create_table(
        "role_limits",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("limit_definition_id", sa.Uuid(), nullable=False),
        sa.Column("value", sa.BigInteger(), nullable=True),
        sa.CheckConstraint("value IS NULL OR value >= 0", name="non_negative_value"),
        sa.ForeignKeyConstraint(
            ["limit_definition_id"],
            ["limit_definitions.id"],
            name="fk_role_limits_limit_definition_id_limit_definitions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_role_limits_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_role_limits"),
        sa.UniqueConstraint("role_id", "limit_definition_id", name="uq_role_limits_pair"),
    )
    op.create_index("ix_role_limits_role_id", "role_limits", ["role_id"], unique=False)

    op.create_table(
        "user_limit_overrides",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("limit_definition_id", sa.Uuid(), nullable=False),
        sa.Column("value", sa.BigInteger(), nullable=True),
        sa.CheckConstraint(
            "value IS NULL OR value >= 0",
            name="non_negative_value",
        ),
        sa.ForeignKeyConstraint(
            ["limit_definition_id"],
            ["limit_definitions.id"],
            name="fk_user_limit_overrides_limit_definition_id_limit_definitions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_limit_overrides_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_limit_overrides"),
        sa.UniqueConstraint(
            "user_id",
            "limit_definition_id",
            name="uq_user_limit_overrides_pair",
        ),
    )
    op.create_index(
        "ix_user_limit_overrides_user_id",
        "user_limit_overrides",
        ["user_id"],
        unique=False,
    )

    op.create_table(
        "files",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("bucket", sa.String(length=255), nullable=False),
        sa.Column("object_key", sa.String(length=1024), nullable=False),
        sa.Column("original_name", sa.String(length=500), nullable=False),
        sa.Column("extension", sa.String(length=20), nullable=False),
        sa.Column("content_type", sa.String(length=255), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("checksum_algorithm", sa.String(length=50), nullable=True),
        sa.Column("checksum_value", sa.String(length=255), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING",
                "UPLOADING",
                "PROCESSING",
                "AVAILABLE",
                "QUARANTINED",
                "FAILED",
                "DELETED",
                name="file_status",
            ),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("custom_metadata", sa.JSON(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["owner_id"],
            ["users.id"],
            name="fk_files_owner_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_files"),
        sa.UniqueConstraint("object_key", name="uq_files_object_key"),
    )
    op.create_index("ix_files_owner_id", "files", ["owner_id"], unique=False)

    op.create_table(
        "upload_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("mode", sa.String(length=20), nullable=False),
        sa.Column("storage_upload_id", sa.Text(), nullable=True),
        sa.Column("part_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("part_count", sa.Integer(), nullable=False),
        sa.Column("expected_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "INITIATED",
                "FINALIZING",
                "COMPLETED",
                "FAILED",
                "ABORTED",
                "EXPIRED",
                name="upload_session_status",
            ),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["file_id"],
            ["files.id"],
            name="fk_upload_sessions_file_id_files",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_upload_sessions_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_upload_sessions"),
        sa.UniqueConstraint("file_id", name="uq_upload_sessions_file_id"),
        sa.UniqueConstraint("user_id", "idempotency_key", name="uq_upload_sessions_idempotency"),
    )
    op.create_index("ix_upload_sessions_user_id", "upload_sessions", ["user_id"], unique=False)
    op.create_index(
        "ix_upload_sessions_status_expires_at",
        "upload_sessions",
        ["status", "expires_at"],
        unique=False,
    )

    op.create_table(
        "quota_counters",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("limit_key", sa.String(length=100), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_value", sa.BigInteger(), nullable=False),
        sa.Column("reserved_value", sa.BigInteger(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("reserved_value >= 0", name="non_negative_reserved"),
        sa.CheckConstraint("used_value >= 0", name="non_negative_used"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_quota_counters_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_quota_counters"),
        sa.UniqueConstraint("user_id", "limit_key", "window_start", name="uq_quota_counter_window"),
    )
    op.create_index(
        "ix_quota_counters_lookup",
        "quota_counters",
        ["user_id", "limit_key", "window_start"],
        unique=False,
    )

    op.create_table(
        "quota_reservations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("upload_session_id", sa.Uuid(), nullable=False),
        sa.Column("limit_key", sa.String(length=100), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("amount", sa.BigInteger(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "HELD",
                "CONSUMED",
                "RELEASED",
                "EXPIRED",
                name="reservation_status",
            ),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("amount >= 0", name="non_negative_amount"),
        sa.ForeignKeyConstraint(
            ["upload_session_id"],
            ["upload_sessions.id"],
            name="fk_quota_reservations_upload_session_id_upload_sessions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_quota_reservations_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_quota_reservations"),
        sa.UniqueConstraint("upload_session_id", "limit_key", name="uq_quota_reservation_metric"),
    )
    op.create_index(
        "ix_quota_reservations_upload_session_id",
        "quota_reservations",
        ["upload_session_id"],
        unique=False,
    )
    op.create_index(
        "ix_quota_reservations_user_id",
        "quota_reservations",
        ["user_id"],
        unique=False,
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_refresh_tokens_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_refresh_tokens"),
        sa.UniqueConstraint("token_hash", name="uq_refresh_tokens_token_hash"),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"], unique=False)

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=150), nullable=False),
        sa.Column("resource_type", sa.String(length=100), nullable=False),
        sa.Column("resource_id", sa.String(length=255), nullable=True),
        sa.Column("request_id", sa.String(length=100), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["users.id"],
            name="fk_audit_logs_actor_id_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_logs"),
    )
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"], unique=False)
    op.create_index("ix_audit_logs_actor_id", "audit_logs", ["actor_id"], unique=False)
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"], unique=False)
    op.create_index("ix_audit_logs_request_id", "audit_logs", ["request_id"], unique=False)
    op.create_index(
        "ix_audit_logs_resource",
        "audit_logs",
        ["resource_type", "resource_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("refresh_tokens")
    op.drop_table("quota_reservations")
    op.drop_table("quota_counters")
    op.drop_table("upload_sessions")
    op.drop_table("files")
    op.drop_table("user_limit_overrides")
    op.drop_table("role_limits")
    op.drop_table("role_permissions")
    op.drop_table("user_roles")
    op.drop_table("limit_definitions")
    op.drop_table("permissions")
    op.drop_table("roles")
    op.drop_table("users")

    op.execute("DROP TYPE reservation_status")
    op.execute("DROP TYPE upload_session_status")
    op.execute("DROP TYPE file_status")
    op.execute("DROP TYPE user_status")
