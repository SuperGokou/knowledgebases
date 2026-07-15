"""Add malware scan leases and indexed, explicit audit outcomes.

Revision ID: 20260712_0011
Revises: 20260712_0010
Create Date: 2026-07-12 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260712_0011"
down_revision: str | None = "20260712_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

audit_result = sa.Enum("SUCCESS", "FAILURE", "DENIED", name="audit_result")

_DENIED_LEGACY_ACTIONS = frozenset(
    {
        "auth.login.denied",
        "auth.token.reuse_detected",
    }
)
_FAILURE_LEGACY_ACTIONS = frozenset(
    {
        "file.malware_scan.failed_closed",
        "file.malware_scan.infected",
        "okf.conversion_failed",
        "upload.expired",
        "upload.rejected_checksum_mismatch",
        "upload.rejected_size_mismatch",
    }
)
_SUCCESS_LEGACY_ACTIONS = frozenset(
    {
        "api_key.created",
        "api_key.revoked",
        "auth.login.succeeded",
        "auth.logout.succeeded",
        "auth.token.refreshed",
        "file.approved",
        "file.download_grant.issued",
        "file.malware_scan.clean",
        "file.malware_scan.started",
        "knowledge_base.created",
        "knowledge_base.role_grants_replaced",
        "knowledge_base.updated",
        "knowledge_entry.created",
        "knowledge_entry.updated",
        "llm.budget_policy_created",
        "llm.budget_policy_updated",
        "llm.provider_updated",
        "okf.conversion_queued",
        "okf.conversion_retried",
        "okf.conversion_skipped",
        "okf.conversion_succeeded",
        "role.created",
        "role.limits.replaced",
        "role.permissions.replaced",
        "role.policy.replaced",
        "role.updated",
        "upload.aborted",
        "upload.completed",
        "upload.finalization_reconciled",
        "upload.initiated",
        "user.created",
        "user.roles.replaced",
        "user.updated",
    }
)


def legacy_audit_result(action: str) -> str:
    """Classify a pre-0011 action conservatively for the one-time backfill."""
    normalized = action.strip().lower()
    if normalized in _DENIED_LEGACY_ACTIONS:
        return "DENIED"
    if normalized in _FAILURE_LEGACY_ACTIONS:
        return "FAILURE"
    if normalized in _SUCCESS_LEGACY_ACTIONS:
        return "SUCCESS"
    # Known failures and unknown legacy/custom actions must never be upgraded to
    # a successful security event merely because their name lacks a suffix.
    return "FAILURE"


def upgrade() -> None:
    # Backfilling audit_logs may exceed the application's 15-second timeout on
    # mature installations. Run this revision only in a declared maintenance
    # window: lock contention still fails quickly and transaction rollback keeps
    # the old schema/data intact, while the bounded rewrite gets up to 15 minutes.
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute("SET LOCAL statement_timeout = '15min'")
    op.drop_index("ix_files_malware_scan_claim", table_name="files")
    op.add_column("files", sa.Column("malware_scan_lease_id", sa.Uuid()))
    op.add_column(
        "files",
        sa.Column(
            "malware_scan_attempts",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.create_check_constraint(
        op.f("ck_files_malware_scan_attempts_non_negative"),
        "files",
        "malware_scan_attempts >= 0",
    )
    op.alter_column(
        "files",
        "malware_scan_attempts",
        existing_type=sa.Integer(),
        server_default=None,
    )
    op.add_column(
        "files",
        sa.Column("malware_scan_next_attempt_at", sa.DateTime(timezone=True)),
    )
    op.execute(
        """
        UPDATE files
        SET malware_scan_next_attempt_at = COALESCE(malware_scan_started_at, now())
        WHERE malware_scan_status = 'PROCESSING'::malware_scan_status
        """
    )
    op.create_index(
        "ix_files_malware_scan_lease_id",
        "files",
        ["malware_scan_lease_id"],
    )
    op.create_index(
        "ix_files_malware_scan_next_attempt_at",
        "files",
        ["malware_scan_next_attempt_at"],
    )
    op.create_index(
        "ix_files_malware_scan_claim",
        "files",
        [
            "status",
            "malware_scan_status",
            "malware_scan_next_attempt_at",
            "created_at",
        ],
    )

    audit_result.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "audit_logs",
        sa.Column(
            "result",
            audit_result,
            server_default="SUCCESS",
            nullable=True,
        ),
    )
    # This one-time compatibility mapping is deliberately not used by runtime
    # queries. New writers must always persist an explicit controlled result.
    legacy_outcome_backfill = sa.text(
        """
        UPDATE audit_logs
        SET result = CASE
            WHEN lower(btrim(action)) IN :denied_actions
              THEN 'DENIED'::audit_result
            WHEN lower(btrim(action)) IN :failure_actions
              THEN 'FAILURE'::audit_result
            WHEN lower(btrim(action)) IN :success_actions
              THEN 'SUCCESS'::audit_result
            ELSE 'FAILURE'::audit_result
        END
        """
    ).bindparams(
        sa.bindparam("denied_actions", expanding=True),
        sa.bindparam("failure_actions", expanding=True),
        sa.bindparam("success_actions", expanding=True),
    )
    op.get_bind().execute(
        legacy_outcome_backfill,
        {
            "denied_actions": tuple(sorted(_DENIED_LEGACY_ACTIONS)),
            "failure_actions": tuple(sorted(_FAILURE_LEGACY_ACTIONS)),
            "success_actions": tuple(sorted(_SUCCESS_LEGACY_ACTIONS)),
        },
    )
    op.alter_column(
        "audit_logs",
        "result",
        existing_type=audit_result,
        nullable=False,
        server_default=None,
    )
    op.create_index(
        "ix_audit_logs_result_id",
        "audit_logs",
        ["result", "id"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "20260712_0011 is irreversible: downgrade would delete explicit audit "
        "outcomes and malware-scan lease evidence; restore a verified pre-upgrade "
        "archive instead"
    )
