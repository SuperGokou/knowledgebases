"""Add knowledge bases, role grants, and derived knowledge entries.

Revision ID: 20260710_0002
Revises: 20260709_0001
Create Date: 2026-07-10 00:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260710_0002"
down_revision: str | None = "20260709_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "knowledge_bases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("custom_metadata", sa.JSON(), nullable=False),
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
            name="fk_knowledge_bases_owner_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_knowledge_bases"),
    )
    op.create_index("ix_knowledge_bases_owner_id", "knowledge_bases", ["owner_id"], unique=False)
    op.create_index(
        "ix_knowledge_bases_owner_updated",
        "knowledge_bases",
        ["owner_id", "updated_at"],
        unique=False,
    )

    access_level = sa.Enum(
        "READER",
        "EDITOR",
        "MANAGER",
        name="knowledge_base_access_level",
    )
    op.create_table(
        "knowledge_base_role_grants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("knowledge_base_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("access_level", access_level, nullable=False),
        sa.Column("granted_by", sa.Uuid(), nullable=True),
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
            ["granted_by"],
            ["users.id"],
            name="fk_knowledge_base_role_grants_granted_by_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["knowledge_base_id"],
            ["knowledge_bases.id"],
            name="fk_knowledge_base_role_grants_knowledge_base_id_knowledge_bases",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_knowledge_base_role_grants_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_knowledge_base_role_grants"),
        sa.UniqueConstraint(
            "knowledge_base_id",
            "role_id",
            name="uq_knowledge_base_role_grants_pair",
        ),
    )
    op.create_index(
        "ix_knowledge_base_role_grants_granted_by",
        "knowledge_base_role_grants",
        ["granted_by"],
        unique=False,
    )
    op.create_index(
        "ix_knowledge_base_role_grants_knowledge_base_id",
        "knowledge_base_role_grants",
        ["knowledge_base_id"],
        unique=False,
    )
    op.create_index(
        "ix_knowledge_base_role_grants_role_id",
        "knowledge_base_role_grants",
        ["role_id"],
        unique=False,
    )

    op.add_column("files", sa.Column("knowledge_base_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_files_knowledge_base_id_knowledge_bases",
        "files",
        "knowledge_bases",
        ["knowledge_base_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_files_knowledge_base_id", "files", ["knowledge_base_id"], unique=False)

    op.create_table(
        "knowledge_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("knowledge_base_id", sa.Uuid(), nullable=False),
        sa.Column("source_file_id", sa.Uuid(), nullable=True),
        sa.Column("entry_type", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("source_path", sa.String(length=1000), nullable=True),
        sa.Column("format_version", sa.String(length=50), nullable=True),
        sa.Column("custom_metadata", sa.JSON(), nullable=False),
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
            ["knowledge_base_id"],
            ["knowledge_bases.id"],
            name="fk_knowledge_entries_knowledge_base_id_knowledge_bases",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_file_id"],
            ["files.id"],
            name="fk_knowledge_entries_source_file_id_files",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_knowledge_entries"),
    )
    op.create_index(
        "ix_knowledge_entries_knowledge_base_id",
        "knowledge_entries",
        ["knowledge_base_id"],
        unique=False,
    )
    op.create_index(
        "ix_knowledge_entries_source_file_id",
        "knowledge_entries",
        ["source_file_id"],
        unique=False,
    )
    op.create_index(
        "ix_knowledge_entries_kb_updated",
        "knowledge_entries",
        ["knowledge_base_id", "updated_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("knowledge_entries")
    op.drop_index("ix_files_knowledge_base_id", table_name="files")
    op.drop_constraint(
        "fk_files_knowledge_base_id_knowledge_bases",
        "files",
        type_="foreignkey",
    )
    op.drop_column("files", "knowledge_base_id")
    op.drop_table("knowledge_base_role_grants")
    op.drop_table("knowledge_bases")
    sa.Enum(name="knowledge_base_access_level").drop(op.get_bind(), checkfirst=True)
