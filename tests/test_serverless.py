import json
import tomllib
from pathlib import Path

from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.db.session import engine_options


def test_serverless_asyncpg_uses_null_pool_and_disables_statement_caches() -> None:
    options = engine_options(
        Settings(
            serverless=True,
            database_url="postgresql+asyncpg://user:password@db.example.com/postgres",
        )
    )

    assert options["poolclass"] is NullPool
    assert options["connect_args"] == {
        "prepared_statement_cache_size": 0,
        "statement_cache_size": 0,
    }
    assert "pool_size" not in options
    assert "max_overflow" not in options


def test_serverless_psycopg_disables_automatic_prepared_statements() -> None:
    options = engine_options(
        Settings(
            serverless=True,
            database_url="postgresql+psycopg://user:password@db.example.com/postgres",
        )
    )

    assert options["poolclass"] is NullPool
    assert options["connect_args"] == {"prepare_threshold": None}


def test_persistent_runtime_keeps_bounded_application_pool() -> None:
    options = engine_options(Settings(serverless=False))

    assert options["pool_size"] == 10
    assert options["max_overflow"] == 20
    assert "poolclass" not in options


def test_vercel_configuration_and_ignore_file_are_safe() -> None:
    root = Path(__file__).resolve().parents[1]
    config = json.loads((root / "vercel.json").read_text(encoding="utf-8"))
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    ignored = set((root / ".vercelignore").read_text(encoding="utf-8").splitlines())

    assert pyproject["tool"]["vercel"]["entrypoint"] == "app.main:app"
    assert config["crons"] == [
        {"path": "/api/v1/internal/maintenance", "schedule": "17 3 * * *"}
    ]
    assert ".env" in ignored
    assert ".env.*" in ignored
