from __future__ import annotations

import asyncio
import os
import re

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from app.core.config import get_settings

_ROLE_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,62}\Z")


class RuntimeRoleReconciliationError(RuntimeError):
    pass


async def reconcile_runtime_role_privileges(
    connection: AsyncConnection,
    role_name: str,
) -> None:
    """Idempotently converge the runtime role to append-only audit access."""

    if _ROLE_PATTERN.fullmatch(role_name) is None:
        raise RuntimeRoleReconciliationError("invalid runtime database role name")
    role_exists = await connection.scalar(
        text("SELECT 1 FROM pg_roles WHERE rolname = :role_name"),
        {"role_name": role_name},
    )
    if role_exists != 1:
        raise RuntimeRoleReconciliationError("runtime database role does not exist")
    audit_table = await connection.scalar(text("SELECT to_regclass('public.audit_logs')"))
    if audit_table is None:
        raise RuntimeRoleReconciliationError("audit log table does not exist after migration")

    quoted_role = connection.dialect.identifier_preparer.quote(role_name)
    await connection.execute(
        text(
            "REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER "
            f"ON TABLE public.audit_logs FROM {quoted_role}"
        )
    )
    await connection.execute(
        text(f"GRANT SELECT, INSERT ON TABLE public.audit_logs TO {quoted_role}")
    )
    await connection.execute(
        text(f"GRANT USAGE, SELECT ON SEQUENCE public.audit_logs_id_seq TO {quoted_role}")
    )
    await connection.execute(
        text(
            f"""
            CREATE OR REPLACE FUNCTION public.enforce_audit_log_runtime_privileges()
            RETURNS event_trigger
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            BEGIN
              IF to_regclass('public.audit_logs') IS NOT NULL THEN
                EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER '
                        'ON TABLE public.audit_logs FROM {quoted_role}';
                EXECUTE 'GRANT SELECT, INSERT ON TABLE public.audit_logs TO {quoted_role}';
              END IF;
            END
            $function$
            """
        )
    )
    await connection.execute(
        text("REVOKE ALL ON FUNCTION public.enforce_audit_log_runtime_privileges() FROM PUBLIC")
    )
    await connection.execute(
        text("DROP EVENT TRIGGER IF EXISTS enforce_audit_log_runtime_privileges")
    )
    await connection.execute(
        text(
            "CREATE EVENT TRIGGER enforce_audit_log_runtime_privileges "
            "ON ddl_command_end "
            "WHEN TAG IN ('CREATE TABLE', 'ALTER TABLE') "
            "EXECUTE FUNCTION public.enforce_audit_log_runtime_privileges()"
        )
    )

    privileges = await connection.execute(
        text(
            "SELECT "
            "has_table_privilege(:role_name, 'public.audit_logs', 'SELECT'), "
            "has_table_privilege(:role_name, 'public.audit_logs', 'INSERT'), "
            "has_table_privilege(:role_name, 'public.audit_logs', 'UPDATE'), "
            "has_table_privilege(:role_name, 'public.audit_logs', 'DELETE'), "
            "has_table_privilege(:role_name, 'public.audit_logs', 'TRUNCATE')"
        ),
        {"role_name": role_name},
    )
    actual = privileges.one()
    if tuple(actual) != (True, True, False, False, False):
        raise RuntimeRoleReconciliationError("runtime database role privileges did not converge")
    sequence_privileges = await connection.execute(
        text(
            "SELECT "
            "has_sequence_privilege(:role_name, 'public.audit_logs_id_seq', 'USAGE'), "
            "has_sequence_privilege(:role_name, 'public.audit_logs_id_seq', 'SELECT')"
        ),
        {"role_name": role_name},
    )
    if tuple(sequence_privileges.one()) != (True, True):
        raise RuntimeRoleReconciliationError(
            "runtime database sequence privileges did not converge"
        )


async def _run() -> None:
    role_name = os.environ.get("KB_DATABASE_RUNTIME_ROLE", "")
    settings = get_settings()
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            await reconcile_runtime_role_privileges(connection, role_name)
    finally:
        await engine.dispose()


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
