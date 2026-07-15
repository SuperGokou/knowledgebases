from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY / "deploy/tencent/verify-offline-project-inventory.py"
PROJECT = "heyi-kb-offline"
CONFIG_FILE = (
    "/srv/heyi-knowledgebases-offline/releases/" + "a" * 64 + "/deploy/tencent/compose.offline.yml"
)

SERVICE_NETWORKS = {
    "postgres": {"backend"},
    "redis": {"backend"},
    "minio": {"backend", "frontend"},
    "minio-init": {"backend"},
    "minio-multipart-gc": {"backend"},
    "clamd": {"backend"},
    "api": {"backend", "frontend", "llm-control"},
    "maintenance": {"backend", "llm-control"},
    "llm-egress": {"llm-control", "llm-uplink"},
    "web": {"frontend"},
    "proxy": {"edge", "frontend"},
    "maintenance-page": {"edge"},
}
NETWORK_IDS = {
    name: hashlib.sha256(f"network:{name}".encode()).hexdigest()
    for name in ("backend", "edge", "frontend", "llm-control", "llm-uplink")
}
NETWORK_OCTETS = {
    "frontend": 240,
    "backend": 241,
    "edge": 242,
    "llm-control": 243,
    "llm-uplink": 244,
}
RESTART_POLICIES = {
    service: (
        "unless-stopped"
        if service in {"clamd", "maintenance-page", "minio", "postgres", "redis"}
        else "no"
    )
    for service in SERVICE_NETWORKS
}
COMPOSE_HEALTHCHECKED_SERVICES = {
    "api",
    "clamd",
    "llm-egress",
    "maintenance-page",
    "minio",
    "postgres",
    "redis",
}
RUNTIME_HEALTHCHECKED_SERVICES = COMPOSE_HEALTHCHECKED_SERVICES | {"web"}
RESOURCE_LIMITS = {
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


def _verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location("offline_project_inventory", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _image(service: str) -> str:
    digest = hashlib.sha256(f"image:{service}".encode()).hexdigest()
    return f"127.0.0.1:5000/heyi-release/{service}@sha256:{digest}"


def _container_id(service: str) -> str:
    return hashlib.sha256(f"container:{service}".encode()).hexdigest()


def _endpoint_id(service: str, network: str) -> str:
    return hashlib.sha256(f"endpoint:{service}:{network}".encode()).hexdigest()


def _config_hash(service: str) -> str:
    return hashlib.sha256(f"config:{service}".encode()).hexdigest()


def _active_services(profile: str, phase: str) -> set[str]:
    services = {
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
    if profile == "controlled-egress":
        services.add("llm-egress")
    if phase == "deploy":
        services.add("maintenance-page")
    return services


def _inventory(
    *, profile: str = "strict", phase: str = "install"
) -> tuple[
    dict[str, Any],
    dict[str, str],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    services = _active_services(profile, phase)
    expected_networks = {"backend", "edge", "frontend", "llm-control"}
    if profile == "controlled-egress":
        expected_networks.add("llm-uplink")

    compose_services: dict[str, Any] = {}
    containers: list[dict[str, Any]] = []
    for index, service in enumerate(sorted(services), 10):
        memory_limit, nano_cpus, pids_limit = RESOURCE_LIMITS[service]
        source = f"/srv/heyi-knowledgebases-offline/test/{service}"
        target = f"/opt/heyi/{service}"
        container_name = f"{PROJECT}-{service}-1"
        read_only = service not in {"postgres", "redis", "minio"}
        compose_services[service] = {
            "image": _image(service),
            "restart": RESTART_POLICIES[service],
            # compose-go UnitBytes.MarshalJSON emits a quoted decimal string.
            "mem_limit": str(memory_limit),
            "cpus": nano_cpus / 1_000_000_000,
            "pids_limit": pids_limit,
            "networks": {name: None for name in sorted(SERVICE_NETWORKS[service])},
            "volumes": [
                {
                    "type": "bind",
                    "source": source,
                    "target": target,
                    "read_only": read_only,
                }
            ],
        }
        if service in COMPOSE_HEALTHCHECKED_SERVICES:
            compose_services[service]["healthcheck"] = {"test": ["CMD", "true"]}
        port_bindings: dict[str, list[dict[str, str]]] = {}
        if service in {"proxy", "maintenance-page"}:
            compose_services[service]["ports"] = [
                {
                    "target": target_port,
                    "published": published_port,
                    "host_ip": "10.0.0.10",
                    "protocol": "tcp",
                    "mode": "ingress",
                }
                for target_port, published_port in ((8443, "19443"), (9443, "19444"))
            ]
            port_bindings = {
                f"{target_port}/tcp": [{"HostIp": "10.0.0.10", "HostPort": published_port}]
                for target_port, published_port in ((8443, "19443"), (9443, "19444"))
            }
        running = service not in {"minio-init", "maintenance-page"}
        state: dict[str, Any] = {
            "Status": "running" if running else "exited",
            "Running": running,
            "ExitCode": 0,
            "OOMKilled": False,
            "Error": "",
            "StartedAt": "2026-07-14T10:00:00.000000001Z",
            "FinishedAt": ("0001-01-01T00:00:00Z" if running else "2026-07-14T10:00:01.000000001Z"),
        }
        if running and service in RUNTIME_HEALTHCHECKED_SERVICES:
            state["Health"] = {"Status": "healthy"}
        runtime_networks: dict[str, Any] = {}
        for network in sorted(SERVICE_NETWORKS[service]):
            active_endpoint = running
            runtime_networks[f"{PROJECT}_{network}"] = {
                "NetworkID": NETWORK_IDS[network],
                "EndpointID": _endpoint_id(service, network) if active_endpoint else "",
                "IPAddress": (
                    f"172.30.{NETWORK_OCTETS[network]}.{index}" if active_endpoint else ""
                ),
                "IPPrefixLen": 24 if active_endpoint else 0,
                "MacAddress": f"02:42:ac:1e:{index:02x}:{index:02x}" if active_endpoint else "",
                "Aliases": [service, container_name],
                "DNSNames": [service, container_name, _container_id(service)[:12]],
            }
        containers.append(
            {
                "Id": _container_id(service),
                "Name": f"/{container_name}",
                "Config": {
                    "Image": _image(service),
                    "Labels": {
                        "com.docker.compose.project": PROJECT,
                        "com.docker.compose.service": service,
                        "com.docker.compose.project.config_files": CONFIG_FILE,
                        "com.docker.compose.config-hash": _config_hash(service),
                        "com.docker.compose.oneoff": "False",
                        "io.heyi.knowledgebases.owner": "jiangsu-heyi-knowledgebases",
                        "io.heyi.knowledgebases.stack": "offline",
                    },
                },
                "State": state,
                "HostConfig": {
                    "RestartPolicy": {
                        "Name": RESTART_POLICIES[service],
                        "MaximumRetryCount": 0,
                    },
                    "Memory": memory_limit,
                    "MemorySwap": 0,
                    "NanoCpus": nano_cpus,
                    "PidsLimit": pids_limit,
                    "PublishAllPorts": False,
                    "PortBindings": port_bindings,
                },
                "Mounts": [
                    {
                        "Type": "bind",
                        "Source": source,
                        "Destination": target,
                        "RW": not read_only,
                        "Propagation": "rprivate",
                    }
                ],
                "NetworkSettings": {"Networks": runtime_networks},
            }
        )

    compose = {
        "name": PROJECT,
        "services": compose_services,
        "networks": {
            name: {
                "name": f"{PROJECT}_{name}",
                "driver": "bridge",
                "internal": name != "llm-uplink",
                "labels": {
                    "io.heyi.knowledgebases.owner": "jiangsu-heyi-knowledgebases",
                    "io.heyi.knowledgebases.stack": "offline",
                },
                "ipam": {"config": [{"subnet": f"172.30.{NETWORK_OCTETS[name]}.0/24"}]},
            }
            for name in sorted(expected_networks)
        },
    }
    networks: list[dict[str, Any]] = []
    containers_by_service = {
        container["Config"]["Labels"]["com.docker.compose.service"]: container
        for container in containers
    }
    for network in sorted(expected_networks):
        reverse: dict[str, Any] = {}
        for service, container in containers_by_service.items():
            if not container["State"]["Running"] or network not in SERVICE_NETWORKS[service]:
                continue
            runtime = container["NetworkSettings"]["Networks"][f"{PROJECT}_{network}"]
            reverse[container["Id"]] = {
                "Name": container["Name"].removeprefix("/"),
                "EndpointID": runtime["EndpointID"],
                "MacAddress": runtime["MacAddress"],
                "IPv4Address": runtime["IPAddress"] + "/24",
            }
        networks.append(
            {
                "Id": NETWORK_IDS[network],
                "Name": f"{PROJECT}_{network}",
                "Driver": "bridge",
                "Internal": network != "llm-uplink",
                "EnableIPv6": False,
                "IPAM": {
                    "Driver": "default",
                    "Config": [{"Subnet": f"172.30.{NETWORK_OCTETS[network]}.0/24"}],
                },
                "Labels": {
                    "com.docker.compose.project": PROJECT,
                    "com.docker.compose.network": network,
                    "io.heyi.knowledgebases.owner": "jiangsu-heyi-knowledgebases",
                    "io.heyi.knowledgebases.stack": "offline",
                },
                "Containers": reverse,
            }
        )
    compose_hashes = {service: _config_hash(service) for service in services}
    return compose, compose_hashes, containers, networks


def _validate(
    compose: dict[str, Any],
    compose_hashes: dict[str, str],
    containers: list[dict[str, Any]],
    networks: list[dict[str, Any]],
    *,
    profile: str = "strict",
    phase: str = "install",
) -> None:
    verifier = _verifier()
    verifier.validate_inventory(
        compose,
        compose_hashes,
        containers,
        networks,
        project_name=PROJECT,
        profile=profile,
        phase=phase,
        expected_config_file=CONFIG_FILE,
    )


@pytest.mark.parametrize(
    ("profile", "phase"),
    [
        ("strict", "install"),
        ("controlled-egress", "install"),
        ("strict", "deploy"),
        ("controlled-egress", "deploy"),
        ("strict", "recovery"),
        ("controlled-egress", "recovery"),
    ],
)
def test_accepts_exact_fixed_inventory(profile: str, phase: str) -> None:
    compose, compose_hashes, containers, networks = _inventory(profile=profile, phase=phase)
    _validate(
        compose,
        compose_hashes,
        containers,
        networks,
        profile=profile,
        phase=phase,
    )


@pytest.mark.parametrize("collection", ["services", "networks"])
def test_rejects_extra_compose_inventory(collection: str) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    compose[collection]["foreign"] = {}

    with pytest.raises(ValueError, match="Compose .* inventory"):
        _validate(compose, compose_hashes, containers, networks)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("Driver", "host", "bridge driver"),
        ("Internal", False, "Internal"),
        (
            "IPAM",
            {"Driver": "default", "Config": [{"Subnet": "172.30.0.0/16"}]},
            "subnet",
        ),
    ],
)
def test_rejects_unsafe_runtime_network_contract(field: str, value: object, message: str) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    backend = next(item for item in networks if item["Name"].endswith("_backend"))
    backend[field] = value

    with pytest.raises(ValueError, match=message):
        _validate(compose, compose_hashes, containers, networks)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("EnableIPv6", True, "disable IPv6"),
        (
            "IPAM",
            {"Driver": "custom", "Config": [{"Subnet": "172.30.241.0/24"}]},
            "IPAM driver",
        ),
    ],
)
def test_rejects_runtime_network_egress_bypass_fields(
    field: str, value: object, message: str
) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    backend = next(item for item in networks if item["Name"].endswith("_backend"))
    backend[field] = value

    with pytest.raises(ValueError, match=message):
        _validate(compose, compose_hashes, containers, networks)


@pytest.mark.parametrize(
    "unsafe_service",
    ["api\nforeign", "foreign", "migrate", "api ", ""],
)
def test_rejects_non_scalar_or_non_whitelisted_service_labels(unsafe_service: str) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    containers[0]["Config"]["Labels"]["com.docker.compose.service"] = unsafe_service

    with pytest.raises(ValueError, match="service inventory"):
        _validate(compose, compose_hashes, containers, networks)


def test_rejects_duplicate_service_containers() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    duplicate = copy.deepcopy(containers[0])
    duplicate["Id"] = "f" * 64
    containers.append(duplicate)

    with pytest.raises(ValueError, match="service inventory"):
        _validate(compose, compose_hashes, containers, networks)


def test_rejects_image_that_differs_from_rendered_compose() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    containers[0]["Config"]["Image"] = _image("foreign")

    with pytest.raises(ValueError, match="image differs"):
        _validate(compose, compose_hashes, containers, networks)


def test_rejects_runtime_config_hash_that_differs_from_compose() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    containers[0]["Config"]["Labels"]["com.docker.compose.config-hash"] = "f" * 64

    with pytest.raises(ValueError, match="config hash differs"):
        _validate(compose, compose_hashes, containers, networks)


def test_rejects_runtime_restart_policy_drift() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    api = next(
        item
        for item in containers
        if item["Config"]["Labels"]["com.docker.compose.service"] == "api"
    )
    api["HostConfig"]["RestartPolicy"]["Name"] = "unless-stopped"

    with pytest.raises(ValueError, match="restart policy differs"):
        _validate(compose, compose_hashes, containers, networks)


def test_rejects_internal_service_host_port_publication() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    api = next(
        item
        for item in containers
        if item["Config"]["Labels"]["com.docker.compose.service"] == "api"
    )
    api["HostConfig"]["PortBindings"] = {"8000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8000"}]}

    with pytest.raises(ValueError, match="port bindings differ"):
        _validate(compose, compose_hashes, containers, networks)


def test_rejects_publish_all_ports() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    api = next(
        item
        for item in containers
        if item["Config"]["Labels"]["com.docker.compose.service"] == "api"
    )
    api["HostConfig"]["PublishAllPorts"] = True

    with pytest.raises(ValueError, match="disable automatic port publication"):
        _validate(compose, compose_hashes, containers, networks)


@pytest.mark.parametrize("field", ["Memory", "MemorySwap", "NanoCpus", "PidsLimit"])
def test_rejects_runtime_resource_limit_drift(field: str) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    api = next(
        item
        for item in containers
        if item["Config"]["Labels"]["com.docker.compose.service"] == "api"
    )
    api["HostConfig"][field] = -1 if field == "MemorySwap" else 0

    with pytest.raises(ValueError, match="runtime resource limits differ"):
        _validate(compose, compose_hashes, containers, networks)


def test_rejects_compose_resource_policy_drift_even_if_runtime_matches() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    compose["services"]["api"]["cpus"] = 8.0
    api = next(
        item
        for item in containers
        if item["Config"]["Labels"]["com.docker.compose.service"] == "api"
    )
    api["HostConfig"]["NanoCpus"] = 8_000_000_000

    with pytest.raises(ValueError, match="fixed resource limits"):
        _validate(compose, compose_hashes, containers, networks)


@pytest.mark.parametrize("unsafe_memory", [None, True, 1.5, "", "-1", "01", "1g", " 1024"])
def test_rejects_noncanonical_compose_memory_limit(unsafe_memory: object) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    compose["services"]["api"]["mem_limit"] = unsafe_memory

    with pytest.raises(ValueError, match="canonical byte count"):
        _validate(compose, compose_hashes, containers, networks)


def test_accepts_integer_compose_memory_limit_for_compatible_compose_versions() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    compose["services"]["api"]["mem_limit"] = RESOURCE_LIMITS["api"][0]

    _validate(compose, compose_hashes, containers, networks)


@pytest.mark.parametrize("service", ["api", "web"])
def test_rejects_unhealthy_required_service(service: str) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    target = next(
        item
        for item in containers
        if item["Config"]["Labels"]["com.docker.compose.service"] == service
    )
    target["State"]["Health"]["Status"] = "unhealthy"

    with pytest.raises(ValueError, match="not healthy"):
        _validate(compose, compose_hashes, containers, networks)


def test_recovery_structural_audit_defers_transient_health_to_readiness_sampler() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    api = next(
        item
        for item in containers
        if item["Config"]["Labels"]["com.docker.compose.service"] == "api"
    )
    api["State"]["Health"]["Status"] = "unhealthy"

    _validate(
        compose,
        compose_hashes,
        containers,
        networks,
        phase="recovery",
    )


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "api\n",
        "api not-a-hash\n",
        f"api {'a' * 64} extra\n",
        f"api {'a' * 64}\napi {'b' * 64}\n",
    ],
)
def test_rejects_malformed_or_duplicate_compose_hash_output(payload: str) -> None:
    verifier = _verifier()

    with pytest.raises(ValueError):
        verifier.parse_compose_hashes(payload)


def test_rejects_unpinned_image_even_when_compose_and_container_agree() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    service = containers[0]["Config"]["Labels"]["com.docker.compose.service"]
    compose["services"][service]["image"] = "127.0.0.1:5000/heyi-release/api:latest"
    containers[0]["Config"]["Image"] = compose["services"][service]["image"]

    with pytest.raises(ValueError, match="digest-pinned"):
        _validate(compose, compose_hashes, containers, networks)


def test_rejects_container_networks_that_differ_from_compose() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    api = next(
        item
        for item in containers
        if item["Config"]["Labels"]["com.docker.compose.service"] == "api"
    )
    api["NetworkSettings"]["Networks"].pop(f"{PROJECT}_frontend")

    with pytest.raises(ValueError, match="network membership differs"):
        _validate(compose, compose_hashes, containers, networks)


def test_rejects_compose_custom_network_alias() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    compose["services"]["maintenance"]["networks"]["backend"] = {"aliases": ["postgres"]}

    with pytest.raises(ValueError, match="custom network aliases"):
        _validate(compose, compose_hashes, containers, networks)


@pytest.mark.parametrize("field", ["Aliases", "DNSNames"])
def test_rejects_runtime_dns_alias_drift(field: str) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    maintenance = next(
        item
        for item in containers
        if item["Config"]["Labels"]["com.docker.compose.service"] == "maintenance"
    )
    maintenance["NetworkSettings"]["Networks"][f"{PROJECT}_backend"][field].append("postgres")

    with pytest.raises(ValueError, match="unsafe runtime"):
        _validate(compose, compose_hashes, containers, networks)


def test_rejects_compose_network_policy_that_exposes_non_gateway_to_uplink() -> None:
    compose, compose_hashes, containers, networks = _inventory(profile="controlled-egress")
    compose["services"]["api"]["networks"]["llm-uplink"] = None
    api = next(
        item
        for item in containers
        if item["Config"]["Labels"]["com.docker.compose.service"] == "api"
    )
    api["NetworkSettings"]["Networks"][f"{PROJECT}_llm-uplink"] = {
        "NetworkID": NETWORK_IDS["llm-uplink"],
        "EndpointID": _endpoint_id("api", "llm-uplink"),
        "IPAddress": "172.30.244.100",
        "IPPrefixLen": 24,
        "MacAddress": "02:42:ac:1e:64:64",
    }

    with pytest.raises(ValueError, match="fixed network policy"):
        _validate(
            compose,
            compose_hashes,
            containers,
            networks,
            profile="controlled-egress",
        )


def test_rejects_foreign_reverse_network_endpoint() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    backend = next(
        item for item in networks if item["Labels"]["com.docker.compose.network"] == "backend"
    )
    backend["Containers"]["f" * 64] = {
        "Name": "foreign",
        "EndpointID": "e" * 64,
        "MacAddress": "02:42:ac:1e:ff:ff",
        "IPv4Address": "172.30.241.254/24",
    }

    with pytest.raises(ValueError, match="reverse endpoint inventory"):
        _validate(compose, compose_hashes, containers, networks)


def test_rejects_reverse_endpoint_identity_mismatch() -> None:
    compose, compose_hashes, containers, networks = _inventory()
    backend = next(
        item for item in networks if item["Labels"]["com.docker.compose.network"] == "backend"
    )
    first_endpoint = next(iter(backend["Containers"].values()))
    first_endpoint["EndpointID"] = "e" * 64

    with pytest.raises(ValueError, match="reverse endpoint identity"):
        _validate(compose, compose_hashes, containers, networks)


@pytest.mark.parametrize("mount_type", ["volume", "tmpfs", "npipe", "cluster"])
def test_rejects_non_bind_or_anonymous_runtime_mounts(mount_type: str) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    containers[0]["Mounts"][0]["Type"] = mount_type

    with pytest.raises(ValueError, match="bind mounts"):
        _validate(compose, compose_hashes, containers, networks)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Source", "/srv/foreign"),
        ("Destination", "/opt/foreign"),
        ("RW", True),
    ],
)
def test_rejects_bind_mount_that_differs_from_compose(field: str, value: object) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    containers[0]["Mounts"][0][field] = value

    with pytest.raises(ValueError, match="bind mounts differ"):
        _validate(compose, compose_hashes, containers, networks)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Status", "dead"),
        ("Running", True),
        ("ExitCode", 1),
        ("StartedAt", "0001-01-01T00:00:00Z"),
        ("FinishedAt", "0001-01-01T00:00:00Z"),
        ("OOMKilled", True),
        ("Error", "runtime failure"),
    ],
)
def test_rejects_unclean_minio_initializer_state(field: str, value: object) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    initializer = next(
        item
        for item in containers
        if item["Config"]["Labels"]["com.docker.compose.service"] == "minio-init"
    )
    initializer["State"][field] = value

    with pytest.raises(ValueError, match="minio-init"):
        _validate(compose, compose_hashes, containers, networks)


def test_deploy_requires_a_stopped_maintenance_page() -> None:
    compose, compose_hashes, containers, networks = _inventory(phase="deploy")
    maintenance_page = next(
        item
        for item in containers
        if item["Config"]["Labels"]["com.docker.compose.service"] == "maintenance-page"
    )
    maintenance_page["State"]["Status"] = "running"
    maintenance_page["State"]["Running"] = True

    with pytest.raises(ValueError, match="maintenance-page"):
        _validate(
            compose,
            compose_hashes,
            containers,
            networks,
            phase="deploy",
        )


def _write_protected_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, 0o600)


def test_cli_reads_protected_files_without_echoing_sensitive_compose_data(
    tmp_path: Path,
) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    compose["services"]["api"]["environment"] = {"SECRET": "must-not-be-printed"}
    paths = [
        tmp_path / name
        for name in ("compose.json", "hashes.txt", "containers.json", "networks.json")
    ]
    for path, payload in zip(
        (paths[0], paths[2], paths[3]), (compose, containers, networks), strict=True
    ):
        _write_protected_json(path, payload)
    paths[1].write_text(
        "".join(f"{service} {digest}\n" for service, digest in sorted(compose_hashes.items())),
        encoding="utf-8",
    )
    os.chmod(paths[1], 0o600)

    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-I",
            str(SCRIPT),
            "--project-name",
            PROJECT,
            "--profile",
            "strict",
            "--phase",
            "install",
            "--expected-config-file",
            CONFIG_FILE,
            "--compose-config-json",
            str(paths[0]),
            "--compose-hashes",
            str(paths[1]),
            "--container-inspect-json",
            str(paths[2]),
            "--network-inspect-json",
            str(paths[3]),
        ],
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "offline-project-inventory: verified\n"
    assert "must-not-be-printed" not in completed.stdout + completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics are required")
def test_cli_rejects_group_readable_sensitive_input(tmp_path: Path) -> None:
    compose, compose_hashes, containers, networks = _inventory()
    paths = [
        tmp_path / name
        for name in ("compose.json", "hashes.txt", "containers.json", "networks.json")
    ]
    for path, payload in zip(
        (paths[0], paths[2], paths[3]), (compose, containers, networks), strict=True
    ):
        _write_protected_json(path, payload)
    paths[1].write_text(
        "".join(f"{service} {digest}\n" for service, digest in sorted(compose_hashes.items())),
        encoding="utf-8",
    )
    os.chmod(paths[1], 0o600)
    os.chmod(paths[0], 0o640)

    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-I",
            str(SCRIPT),
            "--project-name",
            PROJECT,
            "--profile",
            "strict",
            "--phase",
            "install",
            "--expected-config-file",
            CONFIG_FILE,
            "--compose-config-json",
            str(paths[0]),
            "--compose-hashes",
            str(paths[1]),
            "--container-inspect-json",
            str(paths[2]),
            "--network-inspect-json",
            str(paths[3]),
        ],
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 66
    assert "protected regular file" in completed.stderr
