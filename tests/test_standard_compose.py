from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_standard_compose_passes_security_and_llm_runtime_contract() -> None:
    document = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    environment = document["x-app-environment"]

    required = {
        "KB_DEPLOYMENT_PROFILE",
        "KB_LLM_EGRESS_MODE",
        "KB_LLM_EGRESS_GATEWAY_URL",
        "KB_CHAT_REPLAY_ENCRYPTION_KEYS",
        "KB_CHAT_REPLAY_ACTIVE_KEY_VERSION",
        "KB_LLM_DEFAULT_PROVIDER",
        "KB_LLM_CREDENTIAL_ENCRYPTION_KEY",
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
    }
    assert required <= environment.keys()

    assert ":?" in environment["KB_CHAT_REPLAY_ENCRYPTION_KEYS"]
    assert ":?" in environment["KB_CHAT_REPLAY_ACTIVE_KEY_VERSION"]
    assert environment["KB_DEPLOYMENT_PROFILE"] == "${KB_DEPLOYMENT_PROFILE:-standard}"
    assert environment["KB_LLM_EGRESS_MODE"] == "${KB_LLM_EGRESS_MODE:-strict_offline}"

    for service_name in ("migrate", "bootstrap", "app", "maintenance"):
        service_environment = document["services"][service_name]["environment"]
        assert isinstance(service_environment, dict)
        # YAML aliases and merges are resolved by safe_load; every application
        # process must receive the complete contract rather than an incomplete copy.
        assert required <= service_environment.keys()
