from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[1]
BASE_ENV = REPOSITORY / "deploy/tencent/offline.env.example"
LLM_ENV = REPOSITORY / "deploy/tencent/llm-egress.env.example"
BASE_COMPOSE = REPOSITORY / "deploy/tencent/compose.offline.yml"
EGRESS_COMPOSE = REPOSITORY / "deploy/tencent/compose.llm-egress.yml"
GENERIC_PROXY_KEYS = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
}


def _config(
    *compose_files: Path,
    include_llm_env: bool = False,
    llm_env: Path = LLM_ENV,
) -> dict[str, Any]:
    command = [
        "docker",
        "compose",
        "--project-name",
        "heyi-kb-offline",
        "--env-file",
        str(BASE_ENV),
    ]
    if include_llm_env:
        command.extend(["--env-file", str(llm_env)])
    for compose_file in compose_files:
        command.extend(["--file", str(compose_file)])
    command.extend(["--profile", "ops", "config", "--format", "json", "--no-path-resolution"])
    completed = subprocess.run(  # noqa: S603
        command,
        cwd=REPOSITORY,
        capture_output=True,
        check=True,
        shell=False,
        text=True,
        timeout=30,
    )
    payload = json.loads(completed.stdout)
    assert isinstance(payload, dict)
    return payload


def _verify(llm_env: Path = LLM_ENV) -> subprocess.CompletedProcess[str]:
    verifier = REPOSITORY / "deploy/tencent/verify-llm-egress-compose.py"
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(verifier),
            "heyi-kb-offline",
            str(BASE_ENV),
            str(llm_env),
            str(BASE_COMPOSE),
            str(EGRESS_COMPOSE),
        ],
        cwd=REPOSITORY,
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        timeout=30,
    )


def test_llm_egress_override_preserves_private_data_networks() -> None:
    config = _config(BASE_COMPOSE, EGRESS_COMPOSE, include_llm_env=True)

    assert config["networks"]["backend"]["internal"] is True
    assert config["networks"]["frontend"]["internal"] is True
    client = config["networks"]["llm-client"]
    assert client["internal"] is True
    assert client["driver"] == "bridge"
    assert client.get("attachable", False) is False
    assert client["driver_opts"] == {"com.docker.network.bridge.name": "br-kb-llmc"}
    assert client["ipam"]["config"] == [{"subnet": "172.30.243.0/28"}]

    egress = config["networks"]["llm-egress"]
    assert egress.get("internal", False) is False
    assert egress["driver"] == "bridge"
    assert egress.get("attachable", False) is False
    assert egress["driver_opts"] == {"com.docker.network.bridge.name": "br-kb-llme"}
    assert egress["ipam"]["config"] == [{"subnet": "172.30.244.0/28"}]

    client_consumers = {
        name
        for name, service in config["services"].items()
        if "llm-client" in service.get("networks", {})
    }
    egress_consumers = {
        name
        for name, service in config["services"].items()
        if "llm-egress" in service.get("networks", {})
    }
    assert client_consumers == {"api", "maintenance", "llm-egress-proxy"}
    assert egress_consumers == {"llm-egress-proxy"}
    assert set(config["services"]["api"]["networks"]) == {
        "backend",
        "frontend",
        "llm-client",
    }
    assert set(config["services"]["maintenance"]["networks"]) == {
        "backend",
        "llm-client",
    }
    proxy = config["services"]["llm-egress-proxy"]
    assert set(proxy["networks"]) == {
        "llm-client",
        "llm-egress",
    }
    assert proxy["command"] == ["python", "-m", "app.llm_egress_proxy"]
    assert proxy["pull_policy"] == "never"
    assert proxy["read_only"] is True
    assert set(proxy["cap_drop"]) == {"ALL"}
    assert not proxy.get("ports")
    assert proxy["environment"] == {
        "KB_LLM_EGRESS_PROXY_BIND_HOST": "0.0.0.0",
        "KB_LLM_EGRESS_PROXY_BIND_PORT": "8080",
        "LLM_EGRESS_PROXY_EXTRA_HOSTS": "[]",
    }
    assert GENERIC_PROXY_KEYS.isdisjoint(proxy["environment"])


def test_llm_egress_override_changes_only_the_two_runtime_services() -> None:
    base = _config(BASE_COMPOSE)
    merged = _config(BASE_COMPOSE, EGRESS_COMPOSE, include_llm_env=True)
    expected_changes = {
        "KB_DEPLOYMENT_PROFILE",
        "KB_EXTERNAL_LLM_ENABLED",
        "KB_LLM_DEFAULT_PROVIDER",
        "KB_DEEPSEEK_API_KEY",
        "KB_DEEPSEEK_BASE_URL",
        "KB_DEEPSEEK_MODEL",
        "KB_QWEN_API_KEY",
        "KB_QWEN_BASE_URL",
        "KB_QWEN_MODEL",
        "KB_QWEN_ALLOWED_WORKSPACE_HOSTS",
        "KB_MINIMAX_API_KEY",
        "KB_MINIMAX_BASE_URL",
        "KB_MINIMAX_MODEL",
        "KB_LLM_HTTPS_PROXY",
    }

    for service_name, merged_service in merged["services"].items():
        if service_name == "llm-egress-proxy":
            assert service_name not in base["services"]
            assert not {
                "KB_DEEPSEEK_API_KEY",
                "KB_QWEN_API_KEY",
                "KB_MINIMAX_API_KEY",
            }.intersection(merged_service.get("environment", {}))
            continue
        base_service = base["services"][service_name]
        base_environment = base_service.get("environment", {})
        merged_environment = merged_service.get("environment", {})
        changed = {
            key
            for key in set(base_environment) | set(merged_environment)
            if base_environment.get(key) != merged_environment.get(key)
        }
        if service_name in {"api", "maintenance"}:
            assert changed == expected_changes
            assert merged_environment["KB_DEPLOYMENT_PROFILE"] == "private_connected"
            assert merged_environment["KB_EXTERNAL_LLM_ENABLED"] == "true"
            assert merged_environment["KB_LLM_HTTPS_PROXY"] == ("http://llm-egress-proxy:8080")
            assert GENERIC_PROXY_KEYS.isdisjoint(merged_environment)
            assert not merged_service.get("ports")
        else:
            assert changed == set(), service_name
            assert "llm-egress" not in merged_service.get("networks", {})
            assert "llm-client" not in merged_service.get("networks", {})


def test_qwen_workspace_host_policy_is_shared_with_the_proxy(tmp_path: Path) -> None:
    workspace_policy = '["tenant.maas.aliyuncs.com"]'
    custom_env = tmp_path / "llm-egress.env"
    custom_env.write_text(
        LLM_ENV.read_text(encoding="utf-8")
        .replace(
            "KB_QWEN_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1",
            "KB_QWEN_BASE_URL=https://tenant.maas.aliyuncs.com/compatible-mode/v1",
        )
        .replace(
            "KB_QWEN_ALLOWED_WORKSPACE_HOSTS=[]",
            f"KB_QWEN_ALLOWED_WORKSPACE_HOSTS={workspace_policy}",
        ),
        encoding="utf-8",
    )

    merged = _config(
        BASE_COMPOSE,
        EGRESS_COMPOSE,
        include_llm_env=True,
        llm_env=custom_env,
    )

    assert merged["services"]["api"]["environment"][
        "KB_QWEN_ALLOWED_WORKSPACE_HOSTS"
    ] == workspace_policy
    assert merged["services"]["llm-egress-proxy"]["environment"][
        "LLM_EGRESS_PROXY_EXTRA_HOSTS"
    ] == workspace_policy
    assert _verify(custom_env).returncode == 0


def test_qwen_workspace_base_url_requires_matching_proxy_policy(tmp_path: Path) -> None:
    custom_env = tmp_path / "llm-egress.env"
    custom_env.write_text(
        LLM_ENV.read_text(encoding="utf-8").replace(
            "KB_QWEN_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1",
            "KB_QWEN_BASE_URL=https://tenant.maas.aliyuncs.com/compatible-mode/v1",
        ),
        encoding="utf-8",
    )

    completed = _verify(custom_env)

    assert completed.returncode != 0
    assert "Qwen base URL must use an approved HTTPS host" in completed.stderr


def test_qwen_workspace_base_url_rejects_trailing_dot(tmp_path: Path) -> None:
    custom_env = tmp_path / "llm-egress.env"
    custom_env.write_text(
        LLM_ENV.read_text(encoding="utf-8")
        .replace(
            "KB_QWEN_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1",
            "KB_QWEN_BASE_URL=https://tenant.maas.aliyuncs.com./compatible-mode/v1",
        )
        .replace(
            "KB_QWEN_ALLOWED_WORKSPACE_HOSTS=[]",
            'KB_QWEN_ALLOWED_WORKSPACE_HOSTS=["tenant.maas.aliyuncs.com"]',
        ),
        encoding="utf-8",
    )

    completed = _verify(custom_env)

    assert completed.returncode != 0
    assert "Qwen base URL must use an approved HTTPS host" in completed.stderr


def test_llm_egress_static_verifier_accepts_the_approved_boundary() -> None:
    completed = _verify()

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "llm-egress-compose: rendered boundary is valid"
