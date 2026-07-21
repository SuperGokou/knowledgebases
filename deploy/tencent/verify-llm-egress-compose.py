#!/usr/bin/env python3
"""Validate the rendered private-connected Compose boundary without exposing secrets."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlparse

CLIENT_NETWORK = "llm-client"
CLIENT_SUBNET = "172.30.243.0/28"
CLIENT_BRIDGE = "br-kb-llmc"
EGRESS_NETWORK = "llm-egress"
EGRESS_SUBNET = "172.30.244.0/28"
EGRESS_BRIDGE = "br-kb-llme"
RUNTIME_SERVICES = frozenset({"api", "maintenance"})
PROXY_SERVICE = "llm-egress-proxy"
PROVIDER_KEYS = frozenset(
    {
        "KB_DEEPSEEK_API_KEY",
        "KB_QWEN_API_KEY",
        "KB_MINIMAX_API_KEY",
    }
)
PROVIDER_CONFIG_KEYS = frozenset(
    {
        "KB_DEEPSEEK_BASE_URL",
        "KB_DEEPSEEK_MODEL",
        "KB_QWEN_BASE_URL",
        "KB_QWEN_MODEL",
        "KB_QWEN_ALLOWED_WORKSPACE_HOSTS",
        "KB_MINIMAX_BASE_URL",
        "KB_MINIMAX_MODEL",
    }
)
MODEL_ENVIRONMENT_KEYS = PROVIDER_KEYS | PROVIDER_CONFIG_KEYS | {"KB_LLM_DEFAULT_PROVIDER"}
GENERIC_PROXY_KEYS = frozenset(
    {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    }
)
PROVIDER_TO_KEY = {
    "deepseek": "KB_DEEPSEEK_API_KEY",
    "qwen": "KB_QWEN_API_KEY",
    "minimax": "KB_MINIMAX_API_KEY",
}
MAAS_HOST_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+maas\.aliyuncs\.com"
)


def fail(message: str) -> NoReturn:
    raise ValueError(f"llm-egress-compose: {message}")


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a mapping")
    return {str(key): item for key, item in value.items()}


def _render_compose(arguments: list[str]) -> dict[str, Any]:
    if len(arguments) != 6:
        print(
            "usage: verify-llm-egress-compose.py PROJECT BASE_ENV LLM_ENV "
            "BASE_COMPOSE EGRESS_OVERRIDE",
            file=sys.stderr,
        )
        raise SystemExit(64)
    _, project, base_env, llm_env, base_compose, override = arguments
    for candidate in (base_env, llm_env, base_compose, override):
        if not Path(candidate).is_file():
            fail("a required input file is missing")
    command = [
        "docker",
        "compose",
        "--project-name",
        project,
        "--env-file",
        base_env,
        "--env-file",
        llm_env,
        "--file",
        base_compose,
        "--file",
        override,
        "--profile",
        "ops",
        "config",
        "--format",
        "json",
        "--no-path-resolution",
    ]
    try:
        completed = subprocess.run(  # noqa: S603
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError(
            "llm-egress-compose: Docker Compose rendering failed; output suppressed"
        ) from error
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, ValueError) as error:
        raise ValueError("llm-egress-compose: Compose returned invalid JSON") from error
    return _mapping(payload, "Compose document")


def validate(config: dict[str, Any]) -> None:
    services = _mapping(config.get("services"), "services")
    networks = _mapping(config.get("networks"), "networks")

    for internal_name in ("backend", "frontend"):
        network = _mapping(networks.get(internal_name), f"network {internal_name}")
        if network.get("internal") is not True:
            fail(f"base network {internal_name} must remain internal")

    client = _mapping(networks.get(CLIENT_NETWORK), "LLM client network")
    if client.get("internal") is not True:
        fail("LLM client network must be internal")
    if client.get("driver") != "bridge":
        fail("LLM client network must use the bridge driver")
    if client.get("attachable") not in {False, None}:
        fail("LLM client network must not be attachable")
    client_driver_options = _mapping(client.get("driver_opts"), "LLM client driver options")
    if client_driver_options.get("com.docker.network.bridge.name") != CLIENT_BRIDGE:
        fail("LLM client network must use its dedicated host bridge")
    client_ipam = _mapping(client.get("ipam"), "LLM client IPAM")
    client_ipam_config = client_ipam.get("config")
    if not isinstance(client_ipam_config, list) or client_ipam_config != [
        {"subnet": CLIENT_SUBNET}
    ]:
        fail("LLM client network must use the reserved non-overlapping subnet")

    egress = _mapping(networks.get(EGRESS_NETWORK), "LLM egress network")
    if egress.get("internal") not in {False, None}:
        fail("LLM egress network must be non-internal")
    if egress.get("driver") != "bridge":
        fail("LLM egress network must use the bridge driver")
    if egress.get("attachable") not in {False, None}:
        fail("LLM egress network must not be attachable")
    driver_options = _mapping(egress.get("driver_opts"), "LLM egress driver options")
    if driver_options.get("com.docker.network.bridge.name") != EGRESS_BRIDGE:
        fail("LLM egress network must use its dedicated host bridge")
    ipam = _mapping(egress.get("ipam"), "LLM egress IPAM")
    ipam_config = ipam.get("config")
    if not isinstance(ipam_config, list) or ipam_config != [{"subnet": EGRESS_SUBNET}]:
        fail("LLM egress network must use the reserved non-overlapping subnet")

    client_consumers: set[str] = set()
    egress_consumers: set[str] = set()
    for service_name, raw_service in services.items():
        service = _mapping(raw_service, f"service {service_name}")
        service_networks = _mapping(service.get("networks", {}), f"service {service_name} networks")
        if CLIENT_NETWORK in service_networks:
            client_consumers.add(service_name)
        if EGRESS_NETWORK in service_networks:
            egress_consumers.add(service_name)
    if client_consumers != RUNTIME_SERVICES | {PROXY_SERVICE}:
        fail("only api, maintenance and the proxy may join the LLM client network")
    if egress_consumers != {PROXY_SERVICE}:
        fail("only the dedicated proxy may join the non-internal egress network")

    expected_networks = {
        "api": {"backend", "frontend", CLIENT_NETWORK},
        "maintenance": {"backend", CLIENT_NETWORK},
    }
    for service_name in sorted(RUNTIME_SERVICES):
        service = _mapping(services.get(service_name), f"service {service_name}")
        environment = _mapping(service.get("environment"), f"service {service_name} environment")
        service_networks = _mapping(service.get("networks"), f"service {service_name} networks")
        if set(service_networks) != expected_networks[service_name]:
            fail(f"service {service_name} has an unexpected network attachment")
        if service.get("ports"):
            fail(f"service {service_name} must not publish host ports")
        if environment.get("KB_DEPLOYMENT_PROFILE") != "private_connected":
            fail(f"service {service_name} must use private_connected")
        if environment.get("KB_EXTERNAL_LLM_ENABLED") != "true":
            fail(f"service {service_name} must explicitly enable external LLM access")
        if environment.get("KB_LLM_HTTPS_PROXY") != "http://llm-egress-proxy:8080":
            fail(f"service {service_name} must use the dedicated HTTPS proxy")
        if GENERIC_PROXY_KEYS.intersection(environment):
            fail(f"service {service_name} must not receive generic proxy variables")
        if "llm-egress-proxy" not in str(environment.get("KB_LLM_HTTPS_PROXY")):
            fail(f"service {service_name} proxy boundary is invalid")
        depends_on = _mapping(service.get("depends_on", {}), f"service {service_name} dependencies")
        proxy_dependency = _mapping(
            depends_on.get(PROXY_SERVICE), f"service {service_name} proxy dependency"
        )
        if proxy_dependency.get("condition") != "service_healthy":
            fail(f"service {service_name} must wait for the egress proxy healthcheck")
        present_model_keys = {key for key in environment if key in MODEL_ENVIRONMENT_KEYS}
        if present_model_keys != MODEL_ENVIRONMENT_KEYS:
            fail(f"service {service_name} model environment contract is incomplete")

        configured = {
            provider
            for provider, key in PROVIDER_TO_KEY.items()
            if isinstance(environment.get(key), str) and environment[key].strip()
        }
        if len(configured) < 2:
            fail("at least two independent model providers must be configured")
        default_provider = environment.get("KB_LLM_DEFAULT_PROVIDER")
        if default_provider not in configured:
            fail("the default provider must have a configured credential")

    proxy = _mapping(services.get(PROXY_SERVICE), "LLM egress proxy service")
    proxy_networks = _mapping(proxy.get("networks"), "LLM egress proxy networks")
    if set(proxy_networks) != {CLIENT_NETWORK, EGRESS_NETWORK}:
        fail("the LLM egress proxy must bridge only client and egress networks")
    if proxy.get("command") != ["python", "-m", "app.llm_egress_proxy"]:
        fail("the LLM egress proxy must run the approved proxy module")
    if proxy.get("pull_policy") != "never":
        fail("the LLM egress proxy image must be preloaded")
    if proxy.get("read_only") is not True:
        fail("the LLM egress proxy root filesystem must be read-only")
    if set(proxy.get("cap_drop", [])) != {"ALL"}:
        fail("the LLM egress proxy must drop every Linux capability")
    if proxy.get("ports"):
        fail("the LLM egress proxy must not publish host ports")
    proxy_environment = _mapping(proxy.get("environment", {}), "LLM egress proxy environment")
    api_runtime_environment = _mapping(
        _mapping(services["api"], "service api").get("environment"),
        "service api environment",
    )
    workspace_host_policy = api_runtime_environment.get("KB_QWEN_ALLOWED_WORKSPACE_HOSTS")
    if proxy_environment != {
        "KB_LLM_EGRESS_PROXY_BIND_HOST": "0.0.0.0",
        "KB_LLM_EGRESS_PROXY_BIND_PORT": "8080",
        "LLM_EGRESS_PROXY_EXTRA_HOSTS": workspace_host_policy,
    }:
        fail("the LLM egress proxy listener environment is invalid")
    try:
        workspace_hosts = json.loads(str(workspace_host_policy))
    except (TypeError, ValueError) as error:
        raise ValueError("llm-egress-compose: invalid Qwen workspace host JSON") from error
    if (
        not isinstance(workspace_hosts, list)
        or len(workspace_hosts) > 32
        or any(
            not isinstance(host, str) or MAAS_HOST_PATTERN.fullmatch(host) is None
            for host in workspace_hosts
        )
    ):
        fail("Qwen workspace hosts must be exact canonical MaaS hostnames")
    qwen_base_url = api_runtime_environment.get("KB_QWEN_BASE_URL")
    try:
        parsed_qwen_url = urlparse(str(qwen_base_url))
        qwen_port = parsed_qwen_url.port
    except ValueError as error:
        raise ValueError("llm-egress-compose: invalid Qwen base URL") from error
    qwen_hostname = (parsed_qwen_url.hostname or "").lower()
    built_in_qwen_hosts = {
        "dashscope.aliyuncs.com",
        "dashscope-us.aliyuncs.com",
        "dashscope-intl.aliyuncs.com",
    }
    if (
        parsed_qwen_url.scheme.lower() != "https"
        or not qwen_hostname
        or qwen_hostname.endswith(".")
        or parsed_qwen_url.username is not None
        or parsed_qwen_url.password is not None
        or qwen_port not in {None, 443}
        or parsed_qwen_url.query
        or parsed_qwen_url.fragment
        or qwen_hostname not in built_in_qwen_hosts | set(workspace_hosts)
    ):
        fail("Qwen base URL must use an approved HTTPS host")
    if MODEL_ENVIRONMENT_KEYS.intersection(proxy_environment):
        fail("model credentials must never enter the egress proxy")
    if GENERIC_PROXY_KEYS.intersection(proxy_environment):
        fail("generic proxy variables must never enter the egress proxy")

    for service_name, raw_service in services.items():
        if service_name in RUNTIME_SERVICES:
            continue
        environment = _mapping(
            _mapping(raw_service, f"service {service_name}").get("environment", {}),
            f"service {service_name} environment",
        )
        leaked = MODEL_ENVIRONMENT_KEYS.intersection(environment)
        if leaked:
            fail("model credentials or selection leaked to a non-egress service")

    api_environment = _mapping(
        _mapping(services["api"], "service api").get("environment"),
        "service api environment",
    )
    maintenance_environment = _mapping(
        _mapping(services["maintenance"], "service maintenance").get("environment"),
        "service maintenance environment",
    )
    for key in MODEL_ENVIRONMENT_KEYS:
        if api_environment.get(key) != maintenance_environment.get(key):
            fail("api and maintenance must receive identical model configuration")


def main(arguments: list[str]) -> int:
    try:
        validate(_render_compose(arguments))
    except (RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 69
    print("llm-egress-compose: rendered boundary is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
