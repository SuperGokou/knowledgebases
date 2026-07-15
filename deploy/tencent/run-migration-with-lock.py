from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys
from collections.abc import Sequence

import asyncpg

_MIGRATION_LOCK_ID = 4_848_959_473_284_661_318


async def _run_command(
    command: Sequence[str], interrupted: asyncio.Event, *, env: dict[str, str] | None = None
) -> int:
    process = await asyncio.create_subprocess_exec(
        *command, env=env, start_new_session=True
    )
    completed = asyncio.create_task(process.wait())
    stopped = asyncio.create_task(interrupted.wait())
    done, _pending = await asyncio.wait(
        {completed, stopped}, return_when=asyncio.FIRST_COMPLETED
    )
    if completed in done:
        stopped.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await stopped
        return completed.result()
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        await asyncio.wait_for(completed, timeout=20)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await completed
    return 130


async def _main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {
        "--bootstrap-only",
        "--migrate-and-bootstrap",
    }:
        print("migration-gate: an explicit reviewed operation is required", file=sys.stderr)
        return 64
    operation = sys.argv[1]
    sqlalchemy_url = os.environ.get("KB_DATABASE_URL", "")
    prefix = "postgresql+asyncpg://"
    if not sqlalchemy_url.startswith(prefix):
        print("migration-gate: database URL is not the reviewed asyncpg URL", file=sys.stderr)
        return 65
    dsn = "postgresql://" + sqlalchemy_url.removeprefix(prefix)
    connection = await asyncpg.connect(dsn, timeout=10)
    interrupted = asyncio.Event()
    loop = asyncio.get_running_loop()
    for handled_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(handled_signal, interrupted.set)
    acquired = False
    try:
        acquired = bool(
            await connection.fetchval("SELECT pg_try_advisory_lock($1)", _MIGRATION_LOCK_ID)
        )
        if not acquired:
            print("migration-gate: another migration owns the database lock", file=sys.stderr)
            return 75
        bootstrap_environment = dict(os.environ)
        bootstrap_database_url = bootstrap_environment.pop(
            "KB_BOOTSTRAP_DATABASE_URL", ""
        )
        if bootstrap_database_url:
            bootstrap_environment["KB_DATABASE_URL"] = bootstrap_database_url
        commands: tuple[tuple[Sequence[str], dict[str, str] | None], ...] = (
            (
                ("alembic", "upgrade", "head"),
                None,
            ),
            (
                (sys.executable, "-m", "app.db.runtime_role"),
                None,
            ),
            (
                (sys.executable, "-m", "app.bootstrap"),
                bootstrap_environment,
            ),
        )
        if operation == "--bootstrap-only":
            commands = commands[-1:]
        for command, command_environment in commands:
            if interrupted.is_set():
                return 130
            return_code = await _run_command(
                command, interrupted, env=command_environment
            )
            if return_code != 0:
                print(
                    f"migration-gate: command failed with status {return_code}",
                    file=sys.stderr,
                )
                return return_code
        return 0
    finally:
        for handled_signal in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(handled_signal)
        if acquired:
            await connection.execute("SELECT pg_advisory_unlock($1)", _MIGRATION_LOCK_ID)
        await connection.close(timeout=10)


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(_main()))
    except (OSError, asyncpg.PostgresError, TimeoutError) as exc:
        print(f"migration-gate: {exc.__class__.__name__}", file=sys.stderr)
        raise SystemExit(69) from exc
