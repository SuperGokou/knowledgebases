from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

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
