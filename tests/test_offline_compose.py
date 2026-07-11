from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

REPOSITORY = Path(__file__).resolve().parents[1]


def offline_compose_config() -> dict[str, Any]:
    completed = subprocess.run(  # noqa: S603
        [
            "docker",
            "compose",
            "--project-name",
            "heyi-kb-offline",
            "--env-file",
            str(REPOSITORY / "deploy/tencent/offline.env.example"),
            "--file",
            str(REPOSITORY / "deploy/tencent/compose.offline.yml"),
            "--profile",
            "ops",
            "config",
        ],
        cwd=REPOSITORY,
        capture_output=True,
        check=True,
        shell=False,
        text=True,
        timeout=30,
    )
    parsed = yaml.safe_load(completed.stdout)
    assert isinstance(parsed, dict)
    return parsed


def test_offline_redis_has_only_entrypoint_initialization_capabilities() -> None:
    config = offline_compose_config()
    redis = config["services"]["redis"]

    assert set(redis["cap_drop"]) == {"ALL"}
    assert set(redis["cap_add"]) == {"CHOWN", "SETGID", "SETUID"}


def test_offline_data_services_do_not_publish_host_ports() -> None:
    config = offline_compose_config()

    for service in ("postgres", "redis", "minio", "api", "web"):
        assert not config["services"][service].get("ports"), service
    assert config["networks"]["backend"]["internal"] is True
    assert config["networks"]["frontend"]["internal"] is True


def test_offline_api_uses_a_distinct_non_admin_database_identity() -> None:
    config = offline_compose_config()
    api_database = urlparse(config["services"]["api"]["environment"]["KB_DATABASE_URL"])
    migration_database = urlparse(
        config["services"]["migrate"]["environment"]["KB_DATABASE_URL"]
    )

    assert api_database.username == "knowledge-runtime"
    assert migration_database.username == "knowledge"
    assert api_database.username != migration_database.username


def test_runtime_database_role_is_initialized_without_cluster_privileges() -> None:
    script = (REPOSITORY / "docker/postgres/init-runtime-role.sh").read_text(
        encoding="utf-8"
    )

    for restriction in (
        "NOSUPERUSER",
        "NOCREATEDB",
        "NOCREATEROLE",
        "NOREPLICATION",
        "NOBYPASSRLS",
    ):
        assert restriction in script
    assert "ALTER DEFAULT PRIVILEGES" in script
    assert "GRANT SELECT, INSERT, UPDATE, DELETE" in script


def test_offline_preflight_rejects_shared_database_identity() -> None:
    script = (REPOSITORY / "deploy/tencent/preflight-offline.sh").read_text(
        encoding="utf-8"
    )

    assert '[ "$POSTGRES_USER" != "$POSTGRES_APP_USER" ]' in script
    assert "database owner and runtime role must be different" in script


def test_offline_object_proxy_does_not_log_presigned_request_uris() -> None:
    caddyfile = (REPOSITORY / "deploy/tencent/Caddyfile.offline").read_text(
        encoding="utf-8"
    )
    object_server = caddyfile.split("https://{$KB_PUBLIC_HOST}:9443", maxsplit=1)[1]

    assert "\n\tlog {" not in object_server
