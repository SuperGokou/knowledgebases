#!/usr/bin/env python3
"""Reject Docker bridge CIDRs that overlap host routes or unrelated networks."""

from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
from collections.abc import Iterable
from typing import Any

PROJECT_LABEL = "com.docker.compose.project"


def _run_json(command: list[str]) -> Any:
    completed = subprocess.run(  # noqa: S603
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return json.loads(completed.stdout or "[]")


def _network_ids() -> list[str]:
    completed = subprocess.run(  # noqa: S603
        ["docker", "network", "ls", "-q"],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def _docker_networks() -> list[dict[str, Any]]:
    identifiers = _network_ids()
    if not identifiers:
        return []
    payload = _run_json(["docker", "network", "inspect", *identifiers])
    if not isinstance(payload, list):
        raise ValueError("unexpected docker network inspect response")
    return [item for item in payload if isinstance(item, dict)]


def _subnets(network: dict[str, Any]) -> Iterable[ipaddress.IPv4Network]:
    ipam = network.get("IPAM")
    if not isinstance(ipam, dict):
        return
    config = ipam.get("Config")
    if not isinstance(config, list):
        return
    for item in config:
        if not isinstance(item, dict):
            continue
        subnet = item.get("Subnet")
        if not isinstance(subnet, str):
            continue
        parsed = ipaddress.ip_network(subnet, strict=False)
        if isinstance(parsed, ipaddress.IPv4Network):
            yield parsed


def _bridge_device(network: dict[str, Any]) -> str | None:
    options = network.get("Options")
    if isinstance(options, dict):
        explicit = options.get("com.docker.network.bridge.name")
        if isinstance(explicit, str) and explicit:
            return explicit
    identifier = network.get("Id")
    if isinstance(identifier, str) and len(identifier) >= 12:
        return f"br-{identifier[:12]}"
    return None


def _labels(network: dict[str, Any]) -> dict[str, str]:
    labels = network.get("Labels")
    if not isinstance(labels, dict):
        return {}
    return {str(key): str(value) for key, value in labels.items()}


def validate(project: str, requested: list[ipaddress.IPv4Network]) -> None:
    allowed_existing: set[ipaddress.IPv4Network] = set()
    allowed_devices: set[str] = set()

    for network in _docker_networks():
        owned = _labels(network).get(PROJECT_LABEL) == project
        device = _bridge_device(network)
        for existing in _subnets(network):
            overlaps = [candidate for candidate in requested if candidate.overlaps(existing)]
            if not overlaps:
                continue
            if owned and existing in requested:
                allowed_existing.add(existing)
                if device:
                    allowed_devices.add(device)
                continue
            raise RuntimeError(
                f"requested Docker CIDR overlaps an unrelated Docker network: {existing}"
            )

    routes = _run_json(["ip", "-j", "route", "show", "table", "all"])
    if not isinstance(routes, list):
        raise ValueError("unexpected ip route response")
    for route in routes:
        if not isinstance(route, dict):
            continue
        destination = route.get("dst")
        if not isinstance(destination, str) or destination == "default":
            continue
        try:
            routed = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if not isinstance(routed, ipaddress.IPv4Network):
            continue
        for candidate in requested:
            if not candidate.overlaps(routed):
                continue
            device = route.get("dev")
            if (
                candidate in allowed_existing
                and isinstance(device, str)
                and device in allowed_devices
            ):
                continue
            raise RuntimeError(
                f"requested Docker CIDR overlaps a host route: {routed}"
            )


def main(arguments: list[str]) -> int:
    if len(arguments) < 3:
        print(
            "usage: verify-offline-network-cidrs.py COMPOSE_PROJECT CIDR CIDR...",
            file=sys.stderr,
        )
        return 64
    project = arguments[1]
    try:
        requested: list[ipaddress.IPv4Network] = []
        for value in arguments[2:]:
            parsed = ipaddress.ip_network(value, strict=True)
            if not isinstance(parsed, ipaddress.IPv4Network):
                raise ValueError("only IPv4 networks are supported")
            requested.append(parsed)
        if len(set(requested)) != len(requested):
            raise ValueError("requested Docker CIDRs must be unique")
        for index, left in enumerate(requested):
            for right in requested[index + 1 :]:
                if left.overlaps(right):
                    raise ValueError("requested Docker CIDRs overlap each other")
        validate(project, requested)
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as exc:
        print(f"offline-network: {exc}", file=sys.stderr)
        return 69
    print("offline-network: requested Docker CIDRs do not overlap host routes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
