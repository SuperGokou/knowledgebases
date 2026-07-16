from __future__ import annotations

import importlib.util
import ipaddress
from pathlib import Path
from types import ModuleType

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY / "deploy/tencent/verify-offline-network-cidrs.py"


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("offline_network_cidrs", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _requested() -> list[ipaddress.IPv4Network]:
    return [
        ipaddress.ip_network("172.30.240.0/24"),
        ipaddress.ip_network("172.30.241.0/24"),
    ]


def test_network_validator_accepts_unrelated_routes_and_networks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "_docker_networks", lambda: [])
    monkeypatch.setattr(
        module,
        "_run_json",
        lambda _command: [{"dst": "10.0.0.0/8", "dev": "eth0"}],
    )

    module.validate("heyi-kb-offline", _requested())


def test_network_validator_rejects_overlapping_host_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    monkeypatch.setattr(module, "_docker_networks", lambda: [])
    monkeypatch.setattr(
        module,
        "_run_json",
        lambda _command: [{"dst": "172.30.240.0/20", "dev": "tun0"}],
    )

    with pytest.raises(RuntimeError, match="host route"):
        module.validate("heyi-kb-offline", _requested())


def test_network_validator_rejects_unrelated_overlapping_docker_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "_docker_networks",
        lambda: [
            {
                "Id": "a" * 64,
                "Labels": {module.PROJECT_LABEL: "another-project"},
                "IPAM": {"Config": [{"Subnet": "172.30.241.0/24"}]},
            }
        ],
    )
    monkeypatch.setattr(module, "_run_json", lambda _command: [])

    with pytest.raises(RuntimeError, match="unrelated Docker network"):
        module.validate("heyi-kb-offline", _requested())


def test_network_validator_allows_existing_owned_project_bridge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    network_id = "b" * 64
    bridge = f"br-{network_id[:12]}"
    monkeypatch.setattr(
        module,
        "_docker_networks",
        lambda: [
            {
                "Id": network_id,
                "Name": "heyi-kb-offline_frontend",
                "Driver": "bridge",
                "Internal": True,
                "Labels": {
                    module.PROJECT_LABEL: "heyi-kb-offline",
                    module.NETWORK_LABEL: "frontend",
                    module.OWNER_LABEL: module.EXPECTED_OWNER,
                    module.STACK_LABEL: module.EXPECTED_STACK,
                },
                "IPAM": {"Config": [{"Subnet": "172.30.240.0/24"}]},
            }
        ],
    )
    monkeypatch.setattr(
        module,
        "_run_json",
        lambda _command: [
            {"dst": "172.30.240.0/24", "dev": bridge},
            {"dst": "172.30.240.1/32", "dev": bridge},
        ],
    )

    module.validate("heyi-kb-offline", _requested())
