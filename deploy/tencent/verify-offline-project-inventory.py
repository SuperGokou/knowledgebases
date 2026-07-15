#!/usr/bin/env python3
"""Fail-closed verifier for the final offline Docker Compose inventory.

The caller captures the rendered Compose model, Compose service hashes, Docker
container inspection, and Docker network inspection into root-only regular files.
This program treats those captures as data and never invokes Docker itself.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Never

EXPECTED_PROJECT = "heyi-kb-offline"
EXPECTED_OWNER = "jiangsu-heyi-knowledgebases"
EXPECTED_STACK = "offline"
MAX_INPUT_BYTES = 32 * 1024 * 1024

PROJECT_LABEL = "com.docker.compose.project"
SERVICE_LABEL = "com.docker.compose.service"
NETWORK_LABEL = "com.docker.compose.network"
CONFIG_FILE_LABEL = "com.docker.compose.project.config_files"
CONFIG_HASH_LABEL = "com.docker.compose.config-hash"
ONEOFF_LABEL = "com.docker.compose.oneoff"
OWNER_LABEL = "io.heyi.knowledgebases.owner"
STACK_LABEL = "io.heyi.knowledgebases.stack"

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_PINNED_LOOPBACK_IMAGE = re.compile(
    r"^127\.0\.0\.1:5000/.+@sha256:[0-9a-f]{64}$"
)
_MATERIALIZED_COMPOSE = re.compile(
    r"^/srv/heyi-knowledgebases-offline/releases/[0-9a-f]{64}/"
    r"deploy/tencent/compose\.offline\.yml$"
)
_MAC_ADDRESS = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
_CANONICAL_POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")

BASE_SERVICES = frozenset(
    {
        "api",
        "clamd",
        "maintenance",
        "minio",
        "minio-init",
        "minio-multipart-gc",
        "postgres",
        "proxy",
        "redis",
        "web",
    }
)
SERVICE_NETWORKS: dict[str, frozenset[str]] = {
    "postgres": frozenset({"backend"}),
    "redis": frozenset({"backend"}),
    "minio": frozenset({"backend", "frontend"}),
    "minio-init": frozenset({"backend"}),
    "minio-multipart-gc": frozenset({"backend"}),
    "clamd": frozenset({"backend"}),
    "api": frozenset({"backend", "frontend", "llm-control"}),
    "maintenance": frozenset({"backend", "llm-control"}),
    "llm-egress": frozenset({"llm-control", "llm-uplink"}),
    "web": frozenset({"frontend"}),
    "proxy": frozenset({"edge", "frontend"}),
    "maintenance-page": frozenset({"edge"}),
}
BASE_NETWORKS = frozenset({"backend", "edge", "frontend", "llm-control"})
NETWORK_SUBNETS = {
    "backend": ipaddress.IPv4Network("172.30.241.0/24"),
    "edge": ipaddress.IPv4Network("172.30.242.0/24"),
    "frontend": ipaddress.IPv4Network("172.30.240.0/24"),
    "llm-control": ipaddress.IPv4Network("172.30.243.0/24"),
    "llm-uplink": ipaddress.IPv4Network("172.30.244.0/24"),
}
SERVICE_RESTART_POLICIES = {
    service: (
        "unless-stopped"
        if service
        in {"clamd", "maintenance-page", "minio", "postgres", "redis"}
        else "no"
    )
    for service in SERVICE_NETWORKS
}
COMPOSE_HEALTHCHECKED_SERVICES = frozenset(
    {"api", "clamd", "llm-egress", "maintenance-page", "minio", "postgres", "redis"}
)
RUNTIME_HEALTHCHECKED_SERVICES = COMPOSE_HEALTHCHECKED_SERVICES | {"web"}
SERVICE_RESOURCE_LIMITS = {
    "api": (1_610_612_736, 1_250_000_000, 256),
    "clamd": (1_879_048_192, 500_000_000, 128),
    "maintenance": (536_870_912, 250_000_000, 128),
    "maintenance-page": (134_217_728, 150_000_000, 64),
    "minio": (1_342_177_280, 750_000_000, 256),
    "minio-init": (134_217_728, 100_000_000, 64),
    "minio-multipart-gc": (134_217_728, 50_000_000, 64),
    "postgres": (2_147_483_648, 1_000_000_000, 256),
    "proxy": (134_217_728, 150_000_000, 64),
    "redis": (805_306_368, 250_000_000, 128),
    "web": (805_306_368, 600_000_000, 256),
    "llm-egress": (134_217_728, 150_000_000, 64),
}


class InputError(ValueError):
    """The protected evidence could not be read or decoded."""


class UsageError(ValueError):
    """The command-line contract is invalid."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise UsageError(message)


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object with string keys")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def _string(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ValueError(f"{label} must be a string")
    return value


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{label} must be a boolean")
    return value


def _integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{label} must be an integer")
    return value


def _decimal_bytes(value: object, label: str) -> int:
    if type(value) is int and value > 0:
        return value
    if isinstance(value, str) and _CANONICAL_POSITIVE_DECIMAL.fullmatch(value):
        return int(value)
    raise ValueError(f"{label} must be a positive canonical byte count")


def _expected_services(profile: str, phase: str) -> frozenset[str]:
    if profile not in {"strict", "controlled-egress"}:
        raise ValueError("profile must be strict or controlled-egress")
    if phase not in {"install", "deploy", "recovery"}:
        raise ValueError("phase must be install, deploy, or recovery")
    services = set(BASE_SERVICES)
    if profile == "controlled-egress":
        services.add("llm-egress")
    if phase == "deploy":
        services.add("maintenance-page")
    return frozenset(services)


def _expected_networks(profile: str) -> frozenset[str]:
    networks = set(BASE_NETWORKS)
    if profile == "controlled-egress":
        networks.add("llm-uplink")
    return frozenset(networks)


def _expected_internal(logical_network: str) -> bool:
    return logical_network != "llm-uplink"


def _validate_compose_network(
    definition: dict[str, Any],
    *,
    logical_network: str,
    expected_runtime_name: str,
) -> None:
    if definition.get("name") != expected_runtime_name:
        raise ValueError(f"Compose network {logical_network} has an unsafe runtime name")
    if definition.get("driver") != "bridge":
        raise ValueError(f"Compose network {logical_network} must use the bridge driver")
    if definition.get("internal", False) is not _expected_internal(logical_network):
        raise ValueError(f"Compose network {logical_network} has an unsafe Internal setting")
    if definition.get("enable_ipv6", False) is not False:
        raise ValueError(f"Compose network {logical_network} must disable IPv6")
    labels = _object(
        definition.get("labels"), f"Compose labels for network {logical_network}"
    )
    if (
        labels.get(OWNER_LABEL) != EXPECTED_OWNER
        or labels.get(STACK_LABEL) != EXPECTED_STACK
    ):
        raise ValueError(f"Compose network {logical_network} lacks ownership labels")
    ipam = _object(definition.get("ipam"), f"Compose IPAM for {logical_network}")
    if ipam.get("driver", "default") != "default":
        raise ValueError(f"Compose network {logical_network} has an unsafe IPAM driver")
    configs = _list(ipam.get("config"), f"Compose IPAM config for {logical_network}")
    if len(configs) != 1:
        raise ValueError(f"Compose network {logical_network} must have one fixed subnet")
    config = _object(configs[0], f"Compose IPAM subnet for {logical_network}")
    if config.get("subnet") != str(NETWORK_SUBNETS[logical_network]):
        raise ValueError(f"Compose network {logical_network} has an unsafe subnet")


def _validate_runtime_network(
    network: dict[str, Any],
    *,
    logical_network: str,
) -> None:
    if network.get("Driver") != "bridge":
        raise ValueError(f"network {logical_network} must use the bridge driver")
    if network.get("Internal") is not _expected_internal(logical_network):
        raise ValueError(f"network {logical_network} has an unsafe Internal setting")
    if network.get("EnableIPv6") is not False:
        raise ValueError(f"network {logical_network} must disable IPv6")
    ipam = _object(network.get("IPAM"), f"runtime IPAM for {logical_network}")
    if ipam.get("Driver") != "default":
        raise ValueError(f"network {logical_network} has an unsafe IPAM driver")
    configs = _list(ipam.get("Config"), f"runtime IPAM config for {logical_network}")
    if len(configs) != 1:
        raise ValueError(f"network {logical_network} must have one fixed subnet")
    config = _object(configs[0], f"runtime IPAM subnet for {logical_network}")
    try:
        observed_subnet = ipaddress.ip_network(
            _string(config.get("Subnet"), f"runtime subnet for {logical_network}"),
            strict=True,
        )
    except ValueError as exc:
        raise ValueError(f"network {logical_network} has an invalid subnet") from exc
    if observed_subnet != NETWORK_SUBNETS[logical_network]:
        raise ValueError(f"network {logical_network} has an unsafe subnet")


def _compose_networks(service_config: dict[str, Any], service: str) -> frozenset[str]:
    raw = _object(service_config.get("networks"), f"Compose networks for {service}")
    observed = frozenset(raw)
    if observed != SERVICE_NETWORKS[service]:
        raise ValueError(f"{service} differs from the fixed network policy")
    for logical_network, raw_membership in raw.items():
        if raw_membership is None:
            continue
        membership = _object(
            raw_membership, f"Compose network membership for {service}/{logical_network}"
        )
        if membership.get("aliases", []) not in (None, []):
            raise ValueError(f"{service} must not define custom network aliases")
    return observed


def _compose_port_bindings(
    service_config: dict[str, Any], service: str
) -> dict[str, tuple[str, str]]:
    raw_ports = _list(service_config.get("ports", []), f"Compose ports for {service}")
    bindings: dict[str, tuple[str, str]] = {}
    for raw_port in raw_ports:
        port = _object(raw_port, f"Compose port for {service}")
        target = _integer(port.get("target"), f"Compose target port for {service}")
        published = _string(
            port.get("published"), f"Compose published port for {service}"
        )
        host_ip = _string(port.get("host_ip"), f"Compose host IP for {service}")
        if (
            not 1 <= target <= 65_535
            or not published.isdigit()
            or published.startswith("0")
            or not 1 <= int(published) <= 65_535
            or port.get("protocol", "tcp") != "tcp"
            or port.get("mode", "ingress") != "ingress"
        ):
            raise ValueError(f"{service} has an unsafe Compose port binding")
        key = f"{target}/tcp"
        if key in bindings:
            raise ValueError(f"{service} has duplicate Compose port bindings")
        bindings[key] = (host_ip, published)
    if service in {"proxy", "maintenance-page"}:
        if set(bindings) != {"8443/tcp", "9443/tcp"}:
            raise ValueError(f"{service} differs from the fixed edge port policy")
    elif bindings:
        raise ValueError(f"{service} must not publish host ports")
    return bindings


def _compose_mounts(
    service_config: dict[str, Any], service: str
) -> frozenset[tuple[str, str, bool]]:
    raw_mounts = service_config.get("volumes", [])
    mounts = _list(raw_mounts, f"Compose volumes for {service}")
    normalized: list[tuple[str, str, bool]] = []
    destinations: set[str] = set()
    for raw_mount in mounts:
        mount = _object(raw_mount, f"Compose mount for {service}")
        if mount.get("type") != "bind":
            raise ValueError(f"{service} Compose volumes must contain only bind mounts")
        source = _string(mount.get("source"), f"Compose bind source for {service}")
        destination = _string(mount.get("target"), f"Compose bind target for {service}")
        if not source.startswith("/") or not destination.startswith("/"):
            raise ValueError(f"{service} Compose bind mounts must use absolute paths")
        read_only_raw = mount.get("read_only", False)
        read_only = _bool(read_only_raw, f"Compose bind read_only for {service}")
        if destination in destinations:
            raise ValueError(f"{service} Compose bind destinations must be unique")
        destinations.add(destination)
        normalized.append((source, destination, not read_only))
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{service} Compose bind mounts must be unique")
    return frozenset(normalized)


def _runtime_mounts(container: dict[str, Any], service: str) -> frozenset[tuple[str, str, bool]]:
    raw_mounts = _list(container.get("Mounts"), f"runtime mounts for {service}")
    normalized: list[tuple[str, str, bool]] = []
    destinations: set[str] = set()
    for raw_mount in raw_mounts:
        mount = _object(raw_mount, f"runtime mount for {service}")
        if mount.get("Type") != "bind":
            raise ValueError(f"{service} runtime must contain only bind mounts")
        source = _string(mount.get("Source"), f"runtime bind source for {service}")
        destination = _string(
            mount.get("Destination"), f"runtime bind destination for {service}"
        )
        read_write = _bool(mount.get("RW"), f"runtime bind RW for {service}")
        if mount.get("Propagation") != "rprivate":
            raise ValueError(f"{service} runtime bind mounts must use rprivate propagation")
        if destination in destinations:
            raise ValueError(f"{service} runtime bind destinations must be unique")
        destinations.add(destination)
        normalized.append((source, destination, read_write))
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{service} runtime bind mounts must be unique")
    return frozenset(normalized)


def _parse_nonzero_timestamp(value: object, label: str) -> datetime:
    timestamp = _string(value, label)
    if not timestamp.endswith("Z"):
        raise ValueError(f"{label} must be a Docker UTC timestamp")
    try:
        parsed = datetime.fromisoformat(timestamp[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} must be a Docker UTC timestamp") from exc
    if parsed.year <= 1:
        raise ValueError(f"{label} must be non-zero")
    return parsed


def _validate_state(
    service: str,
    raw_state: object,
    *,
    expects_healthcheck: bool,
    require_healthy: bool,
) -> bool:
    state = _object(raw_state, f"state for {service}")
    status = _string(state.get("Status"), f"status for {service}")
    running = _bool(state.get("Running"), f"running state for {service}")
    oom_killed = _bool(state.get("OOMKilled"), f"OOM state for {service}")
    error = _string(state.get("Error"), f"runtime error for {service}", allow_empty=True)

    if service == "minio-init":
        exit_code = _integer(state.get("ExitCode"), "minio-init exit code")
        started = _parse_nonzero_timestamp(state.get("StartedAt"), "minio-init StartedAt")
        finished = _parse_nonzero_timestamp(
            state.get("FinishedAt"), "minio-init FinishedAt"
        )
        if (
            status != "exited"
            or running
            or exit_code != 0
            or oom_killed
            or error != ""
            or finished < started
        ):
            raise ValueError("minio-init did not complete cleanly")
        return False

    if service == "maintenance-page":
        if status != "exited" or running or oom_killed or error != "":
            raise ValueError("maintenance-page must be stopped in the final deploy inventory")
        return False

    if status != "running" or not running or oom_killed or error != "":
        raise ValueError(f"{service} is not a cleanly running final service")
    health = state.get("Health")
    if expects_healthcheck:
        health_state = _object(health, f"health state for {service}")
        health_status = health_state.get("Status")
        if health_status not in {"starting", "healthy", "unhealthy"}:
            raise ValueError(f"{service} has an invalid health state")
        if require_healthy and health_status != "healthy":
            raise ValueError(f"{service} is not healthy")
    elif health is not None:
        raise ValueError(f"{service} has an unexpected runtime healthcheck")
    return True


def _validate_restart_policy(
    service: str,
    service_config: dict[str, Any],
    container: dict[str, Any],
) -> None:
    expected_restart = SERVICE_RESTART_POLICIES[service]
    if service_config.get("restart", "no") != expected_restart:
        raise ValueError(f"{service} differs from the fixed restart policy")
    host_config = _object(container.get("HostConfig"), f"host config for {service}")
    restart_policy = _object(
        host_config.get("RestartPolicy"), f"restart policy for {service}"
    )
    if (
        restart_policy.get("Name") != expected_restart
        or restart_policy.get("MaximumRetryCount") != 0
    ):
        raise ValueError(f"{service} runtime restart policy differs from Compose")


def _validate_resource_limits(
    service: str,
    service_config: dict[str, Any],
    container: dict[str, Any],
) -> None:
    expected_memory, expected_nano_cpus, expected_pids = SERVICE_RESOURCE_LIMITS[service]
    compose_memory = _decimal_bytes(
        service_config.get("mem_limit"), f"memory limit for {service}"
    )
    compose_pids = _integer(service_config.get("pids_limit"), f"PID limit for {service}")
    compose_cpus = service_config.get("cpus")
    if (
        isinstance(compose_cpus, bool)
        or not isinstance(compose_cpus, (int, float))
        or not math.isfinite(compose_cpus)
    ):
        raise ValueError(f"CPU limit for {service} must be finite")
    compose_nano_cpus = round(compose_cpus * 1_000_000_000)
    if (
        compose_memory != expected_memory
        or compose_nano_cpus != expected_nano_cpus
        or compose_pids != expected_pids
    ):
        raise ValueError(f"{service} differs from the fixed resource limits")

    host_config = _object(container.get("HostConfig"), f"host config for {service}")
    observed_memory = _integer(host_config.get("Memory"), f"runtime memory for {service}")
    observed_memory_swap = _integer(
        host_config.get("MemorySwap"), f"runtime memory+swap policy for {service}"
    )
    observed_nano_cpus = _integer(
        host_config.get("NanoCpus"), f"runtime CPU limit for {service}"
    )
    observed_pids = _integer(
        host_config.get("PidsLimit"), f"runtime PID limit for {service}"
    )
    if (
        observed_memory != expected_memory
        or observed_memory_swap != 0
        or observed_nano_cpus != expected_nano_cpus
        or observed_pids != expected_pids
    ):
        raise ValueError(f"{service} runtime resource limits differ from Compose")


def _validate_port_bindings(
    service: str,
    expected_bindings: dict[str, tuple[str, str]],
    container: dict[str, Any],
) -> None:
    host_config = _object(container.get("HostConfig"), f"host config for {service}")
    if host_config.get("PublishAllPorts") is not False:
        raise ValueError(f"{service} must disable automatic port publication")
    raw_bindings = _object(
        host_config.get("PortBindings"), f"runtime port bindings for {service}"
    )
    if set(raw_bindings) != set(expected_bindings):
        raise ValueError(f"{service} runtime port bindings differ from Compose")
    for key, expected in expected_bindings.items():
        candidates = _list(raw_bindings.get(key), f"runtime binding for {service}/{key}")
        if len(candidates) != 1:
            raise ValueError(f"{service} runtime port bindings differ from Compose")
        candidate = _object(candidates[0], f"runtime binding for {service}/{key}")
        if (candidate.get("HostIp"), candidate.get("HostPort")) != expected:
            raise ValueError(f"{service} runtime port bindings differ from Compose")


def _validate_labels(
    labels: dict[str, Any],
    *,
    service: str,
    project_name: str,
    expected_config_file: str,
    expected_config_hash: str,
) -> None:
    expected = {
        PROJECT_LABEL: project_name,
        SERVICE_LABEL: service,
        CONFIG_FILE_LABEL: expected_config_file,
        CONFIG_HASH_LABEL: expected_config_hash,
        OWNER_LABEL: EXPECTED_OWNER,
        STACK_LABEL: EXPECTED_STACK,
    }
    for key, value in expected.items():
        observed = labels.get(key)
        if observed != value:
            if key == CONFIG_HASH_LABEL:
                raise ValueError(f"{service} runtime config hash differs from Compose")
            raise ValueError(f"{service} has invalid Compose provenance")
    oneoff = labels.get(ONEOFF_LABEL)
    if not isinstance(oneoff, str) or oneoff.lower() != "false":
        raise ValueError(f"{service} must not be a Compose one-off container")


def _validate_runtime_endpoint(
    endpoint: dict[str, Any],
    *,
    service: str,
    logical_network: str,
    expected_network_id: str,
    running: bool,
    normalized_name: str,
    container_id: str,
) -> tuple[str, str, str] | None:
    network_id = _string(
        endpoint.get("NetworkID"), f"network id for {service}/{logical_network}"
    )
    if network_id != expected_network_id:
        raise ValueError(f"{service} network membership differs from inspected network")
    endpoint_id = _string(
        endpoint.get("EndpointID"),
        f"endpoint id for {service}/{logical_network}",
        allow_empty=True,
    )
    address = _string(
        endpoint.get("IPAddress"),
        f"IP address for {service}/{logical_network}",
        allow_empty=True,
    )
    prefix_length = _integer(
        endpoint.get("IPPrefixLen"), f"IP prefix for {service}/{logical_network}"
    )
    mac_address = _string(
        endpoint.get("MacAddress"),
        f"MAC address for {service}/{logical_network}",
        allow_empty=True,
    )
    allowed_dns_names = {service, normalized_name, container_id[:12]}
    aliases = [
        _string(value, f"network alias for {service}/{logical_network}")
        for value in _list(
            endpoint.get("Aliases"),
            f"network aliases for {service}/{logical_network}",
        )
    ]
    if (
        service not in aliases
        or len(set(aliases)) != len(aliases)
        or not set(aliases) <= allowed_dns_names
    ):
        raise ValueError(f"{service} has unsafe runtime network aliases")
    raw_dns_names = endpoint.get("DNSNames")
    if raw_dns_names is not None:
        dns_names = [
            _string(value, f"DNS name for {service}/{logical_network}")
            for value in _list(
                raw_dns_names, f"DNS names for {service}/{logical_network}"
            )
        ]
        if (
            service not in dns_names
            or len(set(dns_names)) != len(dns_names)
            or not set(dns_names) <= allowed_dns_names
        ):
            raise ValueError(f"{service} has unsafe runtime DNS names")
    if not running:
        if endpoint_id or address or prefix_length != 0 or mac_address:
            raise ValueError(f"stopped {service} retains an active network endpoint")
        return None
    if _HEX_64.fullmatch(endpoint_id) is None:
        raise ValueError(f"{service} has an invalid active endpoint identity")
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError(f"{service} has an invalid active network address") from exc
    if (
        not isinstance(parsed_address, ipaddress.IPv4Address)
        or prefix_length != 24
        or parsed_address not in NETWORK_SUBNETS[logical_network]
    ):
        raise ValueError(f"{service} has an address outside the fixed network policy")
    if _MAC_ADDRESS.fullmatch(mac_address) is None:
        raise ValueError(f"{service} has an invalid active MAC address")
    return endpoint_id, f"{address}/{prefix_length}", mac_address


def validate_inventory(
    compose: object,
    compose_hashes: dict[str, str],
    containers: object,
    networks: object,
    *,
    project_name: str,
    profile: str,
    phase: str,
    expected_config_file: str,
) -> None:
    """Validate exact final service, mount, state, and network provenance."""

    if project_name != EXPECTED_PROJECT:
        raise ValueError("unexpected offline Compose project name")
    if _MATERIALIZED_COMPOSE.fullmatch(expected_config_file) is None:
        raise ValueError("expected Compose file is outside the materialized release")
    expected_services = _expected_services(profile, phase)
    expected_networks = _expected_networks(profile)

    compose_model = _object(compose, "Compose model")
    if compose_model.get("name") != project_name:
        raise ValueError("rendered Compose project name differs from the fixed project")
    compose_services = _object(compose_model.get("services"), "Compose services")
    compose_networks = _object(compose_model.get("networks"), "Compose networks")
    if set(compose_services) != set(expected_services):
        raise ValueError("Compose service inventory differs from the selected profile")
    if set(compose_networks) != set(expected_networks):
        raise ValueError("Compose network inventory differs from the selected profile")
    if set(compose_hashes) != set(expected_services):
        raise ValueError("Compose service hash inventory differs from the selected profile")
    if any(_HEX_64.fullmatch(value) is None for value in compose_hashes.values()):
        raise ValueError("Compose service hashes must be lowercase sha256 values")

    runtime_network_names: dict[str, str] = {}
    for logical_network in expected_networks:
        definition = _object(
            compose_networks.get(logical_network),
            f"Compose network definition for {logical_network}",
        )
        expected_runtime_name = f"{project_name}_{logical_network}"
        _validate_compose_network(
            definition,
            logical_network=logical_network,
            expected_runtime_name=expected_runtime_name,
        )
        runtime_network_names[logical_network] = expected_runtime_name
    if len(set(runtime_network_names.values())) != len(runtime_network_names):
        raise ValueError("Compose runtime network names must be unique")

    expected_images: dict[str, str] = {}
    expected_mounts: dict[str, frozenset[tuple[str, str, bool]]] = {}
    expected_service_configs: dict[str, dict[str, Any]] = {}
    expected_port_bindings: dict[str, dict[str, tuple[str, str]]] = {}
    for service in expected_services:
        service_config = _object(
            compose_services.get(service), f"Compose service definition for {service}"
        )
        image = _string(service_config.get("image"), f"Compose image for {service}")
        if _PINNED_LOOPBACK_IMAGE.fullmatch(image) is None:
            raise ValueError(f"{service} image must be loopback and digest-pinned")
        expected_images[service] = image
        expected_service_configs[service] = service_config
        has_healthcheck = "healthcheck" in service_config
        if has_healthcheck is not (service in COMPOSE_HEALTHCHECKED_SERVICES):
            raise ValueError(f"{service} differs from the fixed healthcheck policy")
        if has_healthcheck:
            healthcheck = _object(
                service_config.get("healthcheck"), f"Compose healthcheck for {service}"
            )
            if healthcheck.get("disable", False) is not False:
                raise ValueError(f"{service} must not disable its healthcheck")
        _compose_networks(service_config, service)
        expected_mounts[service] = _compose_mounts(service_config, service)
        expected_port_bindings[service] = _compose_port_bindings(service_config, service)

    raw_containers = _list(containers, "container inspection")
    by_service: dict[str, dict[str, Any]] = {}
    by_id: dict[str, dict[str, Any]] = {}
    endpoint_expectations: dict[str, dict[str, tuple[str, str, str, str, str]]] = {
        runtime_name: {} for runtime_name in runtime_network_names.values()
    }
    network_ids_by_runtime_name: dict[str, str] = {}

    raw_networks = _list(networks, "network inspection")
    inspected_networks: dict[str, dict[str, Any]] = {}
    for raw_network in raw_networks:
        network = _object(raw_network, "inspected network")
        labels = _object(network.get("Labels"), "inspected network labels")
        observed_logical = labels.get(NETWORK_LABEL)
        if not isinstance(observed_logical, str) or observed_logical not in expected_networks:
            raise ValueError("network inventory differs from the selected profile")
        logical_network = observed_logical
        if logical_network in inspected_networks:
            raise ValueError("network inventory contains a duplicate logical network")
        if (
            labels.get(PROJECT_LABEL) != project_name
            or labels.get(OWNER_LABEL) != EXPECTED_OWNER
            or labels.get(STACK_LABEL) != EXPECTED_STACK
        ):
            raise ValueError(f"network {logical_network} has invalid Compose provenance")
        runtime_name = runtime_network_names[logical_network]
        if network.get("Name") != runtime_name:
            raise ValueError(f"network {logical_network} has an unsafe runtime name")
        _validate_runtime_network(network, logical_network=logical_network)
        network_id = _string(network.get("Id"), f"network id for {logical_network}")
        if _HEX_64.fullmatch(network_id) is None:
            raise ValueError(f"network {logical_network} has an invalid identity")
        if network_id in network_ids_by_runtime_name.values():
            raise ValueError("network inventory contains a duplicate Docker identity")
        inspected_networks[logical_network] = network
        network_ids_by_runtime_name[runtime_name] = network_id
    if set(inspected_networks) != set(expected_networks):
        raise ValueError("network inventory differs from the selected profile")

    for raw_container in raw_containers:
        container = _object(raw_container, "inspected container")
        config = _object(container.get("Config"), "container configuration")
        labels = _object(config.get("Labels"), "container labels")
        observed_service = labels.get(SERVICE_LABEL)
        if not isinstance(observed_service, str) or observed_service not in expected_services:
            raise ValueError("service inventory contains a non-whitelisted service")
        service = observed_service
        if service in by_service:
            raise ValueError("service inventory contains duplicate service containers")
        container_id = _string(container.get("Id"), f"container id for {service}")
        if _HEX_64.fullmatch(container_id) is None or container_id in by_id:
            raise ValueError("service inventory contains an invalid container identity")
        _validate_labels(
            labels,
            service=service,
            project_name=project_name,
            expected_config_file=expected_config_file,
            expected_config_hash=compose_hashes[service],
        )
        if config.get("Image") != expected_images[service]:
            raise ValueError(f"{service} runtime image differs from rendered Compose")
        if _runtime_mounts(container, service) != expected_mounts[service]:
            raise ValueError(f"{service} runtime bind mounts differ from rendered Compose")
        service_config = expected_service_configs[service]
        _validate_restart_policy(service, service_config, container)
        _validate_resource_limits(service, service_config, container)
        _validate_port_bindings(service, expected_port_bindings[service], container)

        running = _validate_state(
            service,
            container.get("State"),
            expects_healthcheck=service in RUNTIME_HEALTHCHECKED_SERVICES,
            require_healthy=phase != "recovery",
        )
        network_settings = _object(
            container.get("NetworkSettings"), f"network settings for {service}"
        )
        runtime_endpoints = _object(
            network_settings.get("Networks"), f"network memberships for {service}"
        )
        expected_runtime_networks = {
            runtime_network_names[logical] for logical in SERVICE_NETWORKS[service]
        }
        if set(runtime_endpoints) != expected_runtime_networks:
            raise ValueError(f"{service} network membership differs from rendered Compose")
        container_name = _string(container.get("Name"), f"container name for {service}")
        normalized_name = container_name.removeprefix("/")
        if not normalized_name or "\n" in normalized_name or "\r" in normalized_name:
            raise ValueError(f"{service} has an invalid container name")
        for logical_network in SERVICE_NETWORKS[service]:
            runtime_name = runtime_network_names[logical_network]
            endpoint = _object(
                runtime_endpoints.get(runtime_name),
                f"runtime endpoint for {service}/{logical_network}",
            )
            identity = _validate_runtime_endpoint(
                endpoint,
                service=service,
                logical_network=logical_network,
                expected_network_id=network_ids_by_runtime_name[runtime_name],
                running=running,
                normalized_name=normalized_name,
                container_id=container_id,
            )
            if identity is not None:
                endpoint_expectations[runtime_name][container_id] = (
                    normalized_name,
                    *identity,
                    service,
                )
        by_service[service] = container
        by_id[container_id] = container

    if set(by_service) != set(expected_services):
        raise ValueError("service inventory differs from the selected profile")

    for logical_network, network in inspected_networks.items():
        runtime_name = runtime_network_names[logical_network]
        raw_reverse = network.get("Containers")
        if raw_reverse is None:
            reverse = {}
        else:
            reverse = _object(raw_reverse, f"reverse endpoints for {logical_network}")
        expected_reverse = endpoint_expectations[runtime_name]
        if set(reverse) != set(expected_reverse):
            raise ValueError(
                f"{logical_network} reverse endpoint inventory differs from running containers"
            )
        for container_id, expected_identity in expected_reverse.items():
            endpoint = _object(
                reverse.get(container_id),
                f"reverse endpoint for {logical_network}",
            )
            expected_name, expected_endpoint, expected_ipv4, expected_mac, service = (
                expected_identity
            )
            observed_identity = (
                endpoint.get("Name"),
                endpoint.get("EndpointID"),
                endpoint.get("IPv4Address"),
                endpoint.get("MacAddress"),
            )
            if observed_identity != (
                expected_name,
                expected_endpoint,
                expected_ipv4,
                expected_mac,
            ):
                raise ValueError(
                    f"{service}/{logical_network} reverse endpoint identity differs"
                )


def parse_compose_hashes(text: str) -> dict[str, str]:
    """Parse the stable ``docker compose config --hash '*'`` line format."""

    hashes: dict[str, str] = {}
    lines = text.splitlines()
    if not lines:
        raise InputError("Compose service hash input is empty")
    for line_number, line in enumerate(lines, 1):
        parts = line.split()
        if len(parts) != 2:
            raise InputError(f"invalid Compose service hash line {line_number}")
        service, digest = parts
        if service in hashes:
            raise InputError("Compose service hash input contains duplicates")
        if _HEX_64.fullmatch(digest) is None:
            raise InputError(f"invalid Compose service hash line {line_number}")
        hashes[service] = digest
    return hashes


def _read_protected(path: Path) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise InputError("inventory input must be a protected regular file")
        descriptor = os.open(path, flags)
    except (OSError, ValueError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("inventory input must be a protected regular file") from exc
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or (observed.st_dev, observed.st_ino) != (before.st_dev, before.st_ino)
            or observed.st_nlink != 1
            or not 0 < observed.st_size <= MAX_INPUT_BYTES
        ):
            raise InputError("inventory input must be a protected regular file")
        current_uid = getattr(os, "geteuid", lambda: observed.st_uid)()
        if os.name == "posix" and (
            observed.st_uid != current_uid or observed.st_mode & 0o077
        ):
            raise InputError("inventory input must be a protected regular file")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            return handle.read()
    except (OSError, UnicodeError) as exc:
        raise InputError("inventory input could not be read") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_json(path: Path) -> object:
    try:
        return json.loads(_read_protected(path))
    except json.JSONDecodeError as exc:
        raise InputError("inventory input contains invalid JSON") from exc


def _arguments(argv: list[str]) -> argparse.Namespace:
    parser = _Parser(add_help=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--profile", choices=("strict", "controlled-egress"), required=True)
    parser.add_argument(
        "--phase", choices=("install", "deploy", "recovery"), required=True
    )
    parser.add_argument("--expected-config-file", required=True)
    parser.add_argument("--compose-config-json", type=Path, required=True)
    parser.add_argument("--compose-hashes", type=Path, required=True)
    parser.add_argument("--container-inspect-json", type=Path, required=True)
    parser.add_argument("--network-inspect-json", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _arguments(sys.argv[1:] if argv is None else argv)
    except UsageError as exc:
        print(f"offline-project-inventory: {exc}", file=sys.stderr)
        return 64
    try:
        compose = _read_json(arguments.compose_config_json)
        hashes = parse_compose_hashes(_read_protected(arguments.compose_hashes))
        containers = _read_json(arguments.container_inspect_json)
        networks = _read_json(arguments.network_inspect_json)
    except InputError as exc:
        print(f"offline-project-inventory: {exc}", file=sys.stderr)
        return 66
    try:
        validate_inventory(
            compose,
            hashes,
            containers,
            networks,
            project_name=arguments.project_name,
            profile=arguments.profile,
            phase=arguments.phase,
            expected_config_file=arguments.expected_config_file,
        )
    except ValueError as exc:
        print(f"offline-project-inventory: {exc}", file=sys.stderr)
        return 70
    print("offline-project-inventory: verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
