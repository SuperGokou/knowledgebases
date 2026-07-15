from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from scripts.acceptance import collect_worktree_evidence
from scripts.host_preflight import (
    MINIMUM_FILESYSTEM_AVAILABLE_BYTES,
    MINIMUM_FILESYSTEM_TOTAL_BYTES,
    MINIMUM_LOGICAL_CPUS,
    MINIMUM_VISIBLE_MEMORY_BYTES,
    SUPPORTED_ARCHITECTURES,
    collect_host_facts,
)

SCHEMA_VERSION = 1
COLLECTOR_ID = "heyi-offline-runtime"
COLLECTOR_VERSION = "1.0.0"
EXECUTION_CONFIRMATION = "EXECUTE-OFFLINE-RUNTIME-ACCEPTANCE"
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_ARTIFACTS = 256
CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{24,128}$")
TENANT_PATTERN = re.compile(r"^kb-acceptance-[a-z0-9-]{1,48}$")
PROJECT_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GIT_HASH_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
FORBIDDEN_EXECUTABLES = frozenset(
    {
        "ash",
        "bash",
        "busybox",
        "cmd",
        "dash",
        "env",
        "fish",
        "ksh",
        "powershell",
        "pwsh",
        "sh",
        "sudo",
        "su",
        "zsh",
    }
)
SECRET_KEY_PATTERN = re.compile(
    r"(?:authorization|credential|password|private[_-]?key|secret|token)", re.I
)
SECRET_VALUE_PATTERN = re.compile(
    r"(?i)(?:\bbearer\s+\S+|(?:password|secret|token)\s*[:=]|"
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b)"
)

REQUIRED_COMMAND_STEPS = (
    "recovery_preflight",
    "rollback_arm",
    "network_disconnect",
    "cold_start",
    "login",
    "rbac",
    "acl",
    "upload",
    "approval",
    "download",
    "question_answer",
    "persistence_write",
    "restart",
    "persistence_verify",
    "network_restore",
    "rollback_cancel",
    "recovery_verify",
)
BUSINESS_STEPS = (
    "login",
    "rbac",
    "acl",
    "upload",
    "approval",
    "download",
    "question_answer",
    "persistence_write",
    "restart",
    "persistence_verify",
)
SYSTEM_TOOL_NAMES = ("docker", "getent", "ip", "nft", "nsenter", "readlink", "ss")
EGRESS_MODES = ("strict_offline", "controlled_gateway")
STRICT_OFFLINE_NETWORKS = frozenset({"backend", "edge", "frontend", "llm-control"})
CONTROLLED_GATEWAY_NETWORKS = frozenset({*STRICT_OFFLINE_NETWORKS, "llm-uplink"})
CONTROLLED_EGRESS_POLICY_STEP = "controlled_egress_policy"
CONTROLLED_NFT_TABLE = "heyi_kb_egress"
CONTROLLED_NFT_CHAIN = "heyi_llm_egress_forward"
CONTROLLED_NFT_PRIORITY = -5
CONTROLLED_NFT_COMMENT = "heyi-controlled-egress"
PROVIDER_HOSTS = {
    "deepseek": "api.deepseek.com",
    "qwen": "dashscope.aliyuncs.com",
    "minimax": "api.minimax.io",
}
PROVIDER_ORDER = tuple(PROVIDER_HOSTS)
STRICT_CONTAINER_SERVICES = ("api", "maintenance")
STRICT_CONTAINER_EGRESS_SCRIPT = r"""
import ipaddress, os, pathlib, socket, sys

service = sys.argv[1]
failed = any(os.environ.get(name) for name in (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
))
try:
    hosts = pathlib.Path("/etc/hosts").read_text(encoding="utf-8", errors="replace")
except OSError:
    failed = True
else:
    failed = failed or "host.docker.internal" in hosts.casefold()
try:
    socket.setdefaulttimeout(1.0)
    socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)
except OSError:
    pass
else:
    failed = True
for host, port in (("1.1.1.1", 443), ("169.254.169.254", 80)):
    try:
        connection = socket.create_connection((host, port), timeout=1.0)
    except OSError:
        continue
    else:
        connection.close()
        failed = True
try:
    lines = pathlib.Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]
except OSError:
    failed = True
else:
    for line in lines:
        columns = line.split()
        if len(columns) < 4 or columns[3] != "01":
            continue
        address_hex, port_hex = columns[2].split(":", 1)
        address = ipaddress.ip_address(bytes.fromhex(address_hex)[::-1])
        if int(port_hex, 16) and address.is_global:
            failed = True
if failed:
    raise SystemExit(1)
print(f"heyi-strict-container-egress-v1:{service}")
"""


class CollectionBlocked(RuntimeError):
    """The collector could not prove the acceptance condition safely."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def run(self, step_id: str, argv: tuple[str, ...], timeout_seconds: int) -> CommandResult: ...


@dataclass(frozen=True, slots=True)
class SubprocessCommandRunner:
    def run(self, step_id: str, argv: tuple[str, ...], timeout_seconds: int) -> CommandResult:
        del step_id
        try:
            completed = subprocess.run(  # noqa: S603 - validated argv, never a shell
                argv,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                timeout=timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CollectionBlocked("a bounded collector command could not complete") from error
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    challenge: str
    test_tenant: str
    project_name: str
    git_head: str
    content_fingerprint: str
    host_fingerprint: str
    egress_mode: str
    commands: dict[str, dict[str, object]]
    output_dir: Path
    tools: dict[str, str] = field(
        default_factory=lambda: {name: f"/usr/bin/{name}" for name in SYSTEM_TOOL_NAMES}
    )
    resolver_config: str = ""


@dataclass(frozen=True, slots=True)
class PublicConnection:
    protocol: str
    endpoint: str


@dataclass(frozen=True, slots=True)
class NetworkSnapshot:
    public_connections: dict[str, tuple[PublicConnection, ...]]
    nftables_ruleset_sha256: str
    nftables_ruleset: dict[str, object]
    uplink_bridge_interface: str | None


@dataclass(slots=True)
class ArtifactStore:
    root: Path
    artifacts: list[dict[str, object]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)

    def write_json(self, artifact_id: str, value: object) -> str:
        if len(self.artifacts) >= MAX_ARTIFACTS:
            raise CollectionBlocked("artifact count exceeded its safety bound")
        if SAFE_IDENTIFIER_PATTERN.fullmatch(artifact_id) is None:
            raise CollectionBlocked("artifact identifier is invalid")
        if any(item.get("id") == artifact_id for item in self.artifacts):
            raise CollectionBlocked("artifact identifier was reused")
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        raw = (payload + "\n").encode("utf-8")
        if len(raw) > MAX_OUTPUT_BYTES:
            raise CollectionBlocked("artifact exceeded its safety bound")
        relative = Path("raw") / f"{len(self.artifacts):03d}-{artifact_id}.json"
        target = self.root / relative
        target.parent.mkdir(mode=0o700, exist_ok=True)
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        self.artifacts.append(
            {
                "id": artifact_id,
                "path": relative.as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
            }
        )
        return artifact_id


def canonical_digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()


def _required_command_steps(egress_mode: str) -> tuple[str, ...]:
    if egress_mode == "strict_offline":
        return REQUIRED_COMMAND_STEPS
    if egress_mode == "controlled_gateway":
        return (*REQUIRED_COMMAND_STEPS, CONTROLLED_EGRESS_POLICY_STEP)
    raise CollectionBlocked("egress mode is invalid")


def build_plan(egress_mode: str = "strict_offline") -> dict[str, object]:
    required_steps = _required_command_steps(egress_mode)
    return {
        "schema_version": SCHEMA_VERSION,
        "collector": COLLECTOR_ID,
        "collector_version": COLLECTOR_VERSION,
        "status": "planned",
        "mutating": False,
        "egress_mode": egress_mode,
        "target": {
            "platform": "Linux amd64/x86_64",
            "logical_cpus_minimum": MINIMUM_LOGICAL_CPUS,
            "visible_memory_bytes_minimum": MINIMUM_VISIBLE_MEMORY_BYTES,
            "filesystem_total_bytes_minimum": MINIMUM_FILESYSTEM_TOTAL_BYTES,
            "filesystem_available_bytes_minimum": MINIMUM_FILESYSTEM_AVAILABLE_BYTES,
        },
        "network_evidence": [
            "host_and_container_public_sockets",
            "dns_resolution_path",
            "default_and_all_routes",
            "host_and_container_network_namespaces",
            "firewall_ruleset",
            "mode_bound_compose_network_topology",
            "controlled_gateway_l3_l4_allowlist_attestation",
        ],
        "business_checks": list(BUSINESS_STEPS),
        "required_command_steps": list(required_steps),
        "network_topology": {
            "strict_offline": {
                "networks": sorted(STRICT_OFFLINE_NETWORKS),
                "all_internal": True,
                "forbidden_service": "llm-egress",
            },
            "controlled_gateway": {
                "networks": sorted(CONTROLLED_GATEWAY_NETWORKS),
                "only_noninternal_network": "llm-uplink",
                "only_uplink_service": "llm-egress",
                "requires_command_step": CONTROLLED_EGRESS_POLICY_STEP,
            },
        },
        "execute_confirmation": EXECUTION_CONFIRMATION,
        "execution_requires": [
            "explicit --execute and exact confirmation",
            "root on the target Linux host",
            "matching host, Git and content fingerprints",
            "one-time challenge and dedicated test tenant",
            "root-owned non-writable control plan and executable harnesses",
            "armed rollback and verified recovery",
        ],
    }


def _endpoint_host(endpoint: str) -> str | None:
    endpoint = endpoint.strip()
    if not endpoint or endpoint in {"*", "*:*", "0.0.0.0:*", "[::]:*"}:
        return None
    if endpoint.startswith("["):
        closing = endpoint.find("]")
        return endpoint[1:closing] if closing > 1 else None
    host, separator, _port = endpoint.rpartition(":")
    if not separator:
        return None
    return host.rsplit("%", 1)[0]


def public_remote_endpoints(ss_output: str) -> list[str]:
    return sorted({item.endpoint for item in _public_remote_connections(ss_output)})


def _public_remote_connections(ss_output: str) -> tuple[PublicConnection, ...]:
    connections: set[tuple[str, str]] = set()
    for line in ss_output.splitlines():
        columns = line.split()
        if len(columns) < 6:
            continue
        protocol = columns[0].casefold()
        if protocol not in {"tcp", "udp"}:
            continue
        endpoint = columns[5]
        host = _endpoint_host(endpoint)
        if host is None:
            continue
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            continue
        if address.is_global:
            connections.add((protocol, endpoint))
    return tuple(
        PublicConnection(protocol=protocol, endpoint=endpoint)
        for protocol, endpoint in sorted(connections)
    )


def _bounded_result(step_id: str, result: CommandResult) -> dict[str, object]:
    stdout_raw = result.stdout.encode("utf-8")
    stderr_raw = result.stderr.encode("utf-8")
    if len(stdout_raw) > MAX_OUTPUT_BYTES or len(stderr_raw) > MAX_OUTPUT_BYTES:
        raise CollectionBlocked(f"{step_id} output exceeded its safety bound")
    return {
        "step": step_id,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _contains_secret(value: object, *, parent_key: str = "") -> bool:
    if SECRET_KEY_PATTERN.search(parent_key):
        return True
    if isinstance(value, dict):
        return any(
            not isinstance(key, str) or _contains_secret(item, parent_key=key)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret(item, parent_key=parent_key) for item in value)
    return isinstance(value, str) and (
        len(value) > 4096 or SECRET_VALUE_PATTERN.search(value) is not None
    )


def _validated_step_payload(
    context: ExecutionContext, step_id: str, result: CommandResult
) -> dict[str, object]:
    if result.returncode != 0 or result.stderr.strip():
        raise CollectionBlocked(f"{step_id} did not complete successfully")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CollectionBlocked(f"{step_id} did not return bounded JSON evidence") from error
    if not isinstance(payload, dict) or set(payload) != {
        "status",
        "check",
        "challenge",
        "test_tenant",
        "observations",
    }:
        raise CollectionBlocked(f"{step_id} returned an invalid evidence envelope")
    if (
        payload["status"] != "passed"
        or payload["check"] != step_id
        or payload["challenge"] != context.challenge
        or payload["test_tenant"] != context.test_tenant
        or _contains_secret(payload["observations"])
    ):
        raise CollectionBlocked(f"{step_id} evidence did not match the active challenge")
    return cast(dict[str, object], payload)


def _command_spec(context: ExecutionContext, step_id: str) -> tuple[tuple[str, ...], int]:
    raw = context.commands.get(step_id)
    if not isinstance(raw, dict):
        raise CollectionBlocked(f"{step_id} is missing from the control plan")
    argv = raw.get("argv")
    timeout = raw.get("timeout_seconds")
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(item, str) for item in argv)
        or not isinstance(timeout, int)
    ):
        raise CollectionBlocked(f"{step_id} control command is malformed")
    return tuple(argv), timeout


def _run_control_step(
    context: ExecutionContext,
    runner: CommandRunner,
    store: ArtifactStore,
    step_id: str,
) -> str:
    artifact_id, _payload = _run_control_step_with_payload(context, runner, store, step_id)
    return artifact_id


def _run_control_step_with_payload(
    context: ExecutionContext,
    runner: CommandRunner,
    store: ArtifactStore,
    step_id: str,
    *,
    artifact_id: str | None = None,
) -> tuple[str, dict[str, object]]:
    argv, timeout = _command_spec(context, step_id)
    payload = _validated_step_payload(context, step_id, runner.run(step_id, argv, timeout))
    stored_id = artifact_id or step_id
    return store.write_json(stored_id, payload), payload


def _run_probe(
    runner: CommandRunner,
    store: ArtifactStore,
    step_id: str,
    argv: tuple[str, ...],
    *,
    expected_returncode: int = 0,
) -> CommandResult:
    result = runner.run(step_id, argv, 30)
    store.write_json(step_id, _bounded_result(step_id, result))
    if result.returncode != expected_returncode:
        raise CollectionBlocked(f"{step_id} could not prove the required state")
    return result


def _lines(value: str) -> list[str]:
    return [item.strip() for item in value.splitlines() if item.strip()]


def _strict_container_egress_probes(
    context: ExecutionContext,
    runner: CommandRunner,
    store: ArtifactStore,
    label: str,
    container_inventory: dict[str, tuple[str, bool, frozenset[str]]],
) -> None:
    by_service: dict[str, list[str]] = {}
    for container_id, (service, running, _networks) in container_inventory.items():
        if running:
            by_service.setdefault(service, []).append(container_id)
    for service in STRICT_CONTAINER_SERVICES:
        container_ids = by_service.get(service, [])
        if len(container_ids) != 1:
            raise CollectionBlocked(
                "strict_offline requires one exact application container namespace"
            )
        step_id = f"probe_{label}_strict_egress_{service}"
        result = _run_probe(
            runner,
            store,
            step_id,
            (
                context.tools["docker"],
                "exec",
                container_ids[0],
                "python",
                "-I",
                "-c",
                STRICT_CONTAINER_EGRESS_SCRIPT,
                service,
            ),
        )
        if result.stderr or result.stdout != f"heyi-strict-container-egress-v1:{service}\n":
            raise CollectionBlocked("strict_offline container namespace proof was not exact")


def _json_list(result: CommandResult, message: str) -> list[object]:
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CollectionBlocked(message) from error
    if not isinstance(payload, list):
        raise CollectionBlocked(message)
    return payload


def _container_inventory(
    context: ExecutionContext,
    payload: list[object],
    expected_ids: set[str],
) -> dict[str, tuple[str, bool, frozenset[str]]]:
    inventory: dict[str, tuple[str, bool, frozenset[str]]] = {}
    for raw in payload:
        if not isinstance(raw, dict):
            raise CollectionBlocked("project container inventory was invalid")
        container_id = raw.get("Id")
        config = raw.get("Config")
        state = raw.get("State")
        network_settings = raw.get("NetworkSettings")
        if not (
            isinstance(container_id, str)
            and container_id in expected_ids
            and SAFE_IDENTIFIER_PATTERN.fullmatch(container_id) is not None
            and isinstance(config, dict)
            and isinstance(state, dict)
            and isinstance(network_settings, dict)
        ):
            raise CollectionBlocked("project container inventory was invalid")
        labels = config.get("Labels")
        networks = network_settings.get("Networks")
        if not isinstance(labels, dict) or not isinstance(networks, dict):
            raise CollectionBlocked("project container inventory was invalid")
        service = labels.get("com.docker.compose.service")
        if (
            labels.get("com.docker.compose.project") != context.project_name
            or not isinstance(service, str)
            or SAFE_IDENTIFIER_PATTERN.fullmatch(service) is None
            or not isinstance(state.get("Running"), bool)
        ):
            raise CollectionBlocked("project container identity was not Compose-bound")
        network_ids: set[str] = set()
        for attachment in networks.values():
            if not isinstance(attachment, dict):
                raise CollectionBlocked("project container network attachment was invalid")
            network_id = attachment.get("NetworkID")
            if (
                not isinstance(network_id, str)
                or SAFE_IDENTIFIER_PATTERN.fullmatch(network_id) is None
            ):
                raise CollectionBlocked("project container network attachment was invalid")
            network_ids.add(network_id)
        if container_id in inventory:
            raise CollectionBlocked("project container inventory contained duplicate identities")
        inventory[container_id] = (
            service,
            cast(bool, state["Running"]),
            frozenset(network_ids),
        )
    if set(inventory) != expected_ids:
        raise CollectionBlocked("the exact project container set could not be proven")
    return inventory


def _validate_mode_topology(
    context: ExecutionContext,
    network_payload: list[object],
    expected_network_ids: set[str],
    containers: dict[str, tuple[str, bool, frozenset[str]]],
) -> str | None:
    by_logical_name: dict[str, tuple[str, bool, set[str]]] = {}
    bridge_by_logical_name: dict[str, str] = {}
    observed_ids: set[str] = set()
    for raw in network_payload:
        if not isinstance(raw, dict):
            raise CollectionBlocked("project network inventory was invalid")
        network_id = raw.get("Id")
        labels = raw.get("Labels")
        attached = raw.get("Containers")
        options = raw.get("Options")
        if not (
            isinstance(network_id, str)
            and network_id in expected_network_ids
            and SAFE_IDENTIFIER_PATTERN.fullmatch(network_id) is not None
            and isinstance(raw.get("Internal"), bool)
            and isinstance(labels, dict)
            and isinstance(attached, dict)
            and isinstance(options, dict)
            and labels.get("com.docker.compose.project") == context.project_name
        ):
            raise CollectionBlocked("project network inventory was invalid")
        logical_name = labels.get("com.docker.compose.network")
        if (
            not isinstance(logical_name, str)
            or SAFE_IDENTIFIER_PATTERN.fullmatch(logical_name) is None
            or logical_name in by_logical_name
        ):
            raise CollectionBlocked("project network logical identity was invalid")
        attached_ids = set(attached)
        if not attached_ids <= set(containers):
            raise CollectionBlocked("project network contained an unbound container endpoint")
        by_logical_name[logical_name] = (
            network_id,
            cast(bool, raw["Internal"]),
            attached_ids,
        )
        configured_bridge = options.get("com.docker.network.bridge.name")
        bridge_name = (
            configured_bridge
            if isinstance(configured_bridge, str) and configured_bridge
            else f"br-{network_id[:12]}"
        )
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", bridge_name) is None:
            raise CollectionBlocked("project network bridge identity was invalid")
        bridge_by_logical_name[logical_name] = bridge_name
        observed_ids.add(network_id)
    if observed_ids != expected_network_ids:
        raise CollectionBlocked("the exact project network set could not be proven")
    for container_id, (_service, _running, network_ids) in containers.items():
        if not network_ids <= observed_ids:
            raise CollectionBlocked(
                f"project container {container_id} was attached to an unreviewed network"
            )
    for network_id, _internal, attached_ids in by_logical_name.values():
        declared_attached_ids = {
            container_id
            for container_id, (_service, _running, network_ids) in containers.items()
            if network_id in network_ids
        }
        if attached_ids != declared_attached_ids:
            raise CollectionBlocked("project network endpoint inventory changed during collection")

    expected_names = (
        STRICT_OFFLINE_NETWORKS
        if context.egress_mode == "strict_offline"
        else CONTROLLED_GATEWAY_NETWORKS
    )
    if set(by_logical_name) != expected_names:
        raise CollectionBlocked(
            f"{context.egress_mode} requires the exact reviewed Compose network set"
        )
    noninternal = {
        name for name, (_network_id, internal, _attached) in by_logical_name.items() if not internal
    }
    if context.egress_mode == "strict_offline":
        if noninternal:
            raise CollectionBlocked("strict_offline requires every project network to be internal")
        if any(service == "llm-egress" for service, _running, _networks in containers.values()):
            raise CollectionBlocked("strict_offline forbids a materialized llm-egress service")
        return None

    if noninternal != {"llm-uplink"}:
        raise CollectionBlocked(
            "controlled_gateway requires llm-uplink as the only noninternal network"
        )
    gateway_ids = {
        container_id
        for container_id, (service, running, _networks) in containers.items()
        if service == "llm-egress" and running
    }
    all_gateway_ids = {
        container_id
        for container_id, (service, _running, _networks) in containers.items()
        if service == "llm-egress"
    }
    if len(gateway_ids) != 1 or all_gateway_ids != gateway_ids:
        raise CollectionBlocked(
            "controlled_gateway requires exactly one running llm-egress service"
        )
    gateway_id = next(iter(gateway_ids))
    logical_by_id = {
        network_id: logical_name
        for logical_name, (network_id, _internal, _attached) in by_logical_name.items()
    }
    gateway_attachments = {
        logical_by_id[network_id]
        for network_id in containers[gateway_id][2]
        if network_id in logical_by_id
    }
    if gateway_attachments != {"llm-control", "llm-uplink"}:
        raise CollectionBlocked("llm-egress must attach only to llm-control and llm-uplink")
    uplink_attached = by_logical_name["llm-uplink"][2]
    if uplink_attached != {gateway_id}:
        raise CollectionBlocked("llm-egress must be the only llm-uplink endpoint")
    uplink_id = by_logical_name["llm-uplink"][0]
    if any(
        container_id != gateway_id and uplink_id in network_ids
        for container_id, (_service, _running, network_ids) in containers.items()
    ):
        raise CollectionBlocked("a non-gateway container was attached to llm-uplink")
    return bridge_by_logical_name["llm-uplink"]


def _recheck_project_inventory(
    context: ExecutionContext,
    runner: CommandRunner,
    store: ArtifactStore,
    label: str,
    *,
    running_ids: set[str],
    all_container_ids: set[str],
    network_ids: set[str],
    container_inventory: dict[str, tuple[str, bool, frozenset[str]]],
    network_payload: list[object],
) -> None:
    tool = context.tools
    rechecked_running = set(
        _lines(
            _run_probe(
                runner,
                store,
                f"probe_{label}_containers_recheck",
                (
                    tool["docker"],
                    "ps",
                    "--no-trunc",
                    "--filter",
                    f"label=com.docker.compose.project={context.project_name}",
                    "--format",
                    "{{.ID}}",
                ),
            ).stdout
        )
    )
    rechecked_all = set(
        _lines(
            _run_probe(
                runner,
                store,
                f"probe_{label}_all_containers_recheck",
                (
                    tool["docker"],
                    "ps",
                    "--all",
                    "--no-trunc",
                    "--filter",
                    f"label=com.docker.compose.project={context.project_name}",
                    "--format",
                    "{{.ID}}",
                ),
            ).stdout
        )
    )
    rechecked_networks = set(
        _lines(
            _run_probe(
                runner,
                store,
                f"probe_{label}_networks_recheck",
                (
                    tool["docker"],
                    "network",
                    "ls",
                    "--no-trunc",
                    "--filter",
                    f"label=com.docker.compose.project={context.project_name}",
                    "--format",
                    "{{.ID}}",
                ),
            ).stdout
        )
    )
    if (
        rechecked_running != running_ids
        or rechecked_all != all_container_ids
        or rechecked_networks != network_ids
    ):
        raise CollectionBlocked("project container or network identity changed during snapshot")
    container_result = _run_probe(
        runner,
        store,
        f"probe_{label}_container_inspect_recheck",
        (tool["docker"], "inspect", *sorted(rechecked_all)),
    )
    rechecked_inventory = _container_inventory(
        context,
        _json_list(container_result, "project container recheck inventory was invalid"),
        rechecked_all,
    )
    network_result = _run_probe(
        runner,
        store,
        f"probe_{label}_network_inspect_recheck",
        (tool["docker"], "network", "inspect", *sorted(rechecked_networks)),
    )
    rechecked_network_payload = _json_list(
        network_result, "project network recheck inventory was invalid"
    )
    _validate_mode_topology(
        context,
        rechecked_network_payload,
        rechecked_networks,
        rechecked_inventory,
    )
    if rechecked_inventory != container_inventory or canonical_digest(
        sorted(
            rechecked_network_payload,
            key=lambda item: str(cast(dict[str, object], item)["Id"]),
        )
    ) != canonical_digest(
        sorted(
            network_payload,
            key=lambda item: str(cast(dict[str, object], item)["Id"]),
        )
    ):
        raise CollectionBlocked("project container or network topology changed during snapshot")


def _network_snapshot(
    context: ExecutionContext,
    runner: CommandRunner,
    store: ArtifactStore,
    label: str,
    *,
    require_offline: bool,
) -> NetworkSnapshot:
    tool = context.tools
    public_connections: dict[str, list[PublicConnection]] = {"host": []}
    host_sockets = _run_probe(
        runner,
        store,
        f"probe_{label}_host_sockets",
        (tool["ss"], "-H", "-tunap"),
    )
    public_connections["host"].extend(_public_remote_connections(host_sockets.stdout))
    _run_probe(
        runner,
        store,
        f"probe_{label}_routes",
        (tool["ip"], "-json", "route", "show", "table", "all"),
    )
    _run_probe(
        runner,
        store,
        f"probe_{label}_netns",
        (tool["ip"], "netns", "list"),
    )
    firewall = _run_probe(
        runner,
        store,
        f"probe_{label}_firewall",
        (tool["nft"], "-j", "list", "ruleset"),
    )
    try:
        nftables_ruleset = json.loads(firewall.stdout)
    except json.JSONDecodeError as error:
        raise CollectionBlocked("nftables ruleset evidence was invalid") from error
    if (
        not isinstance(nftables_ruleset, dict)
        or set(nftables_ruleset) != {"nftables"}
        or not isinstance(nftables_ruleset.get("nftables"), list)
    ):
        raise CollectionBlocked("nftables ruleset evidence was invalid")
    containers = _lines(
        _run_probe(
            runner,
            store,
            f"probe_{label}_containers",
            (
                tool["docker"],
                "ps",
                "--no-trunc",
                "--filter",
                f"label=com.docker.compose.project={context.project_name}",
                "--format",
                "{{.ID}}",
            ),
        ).stdout
    )
    if not containers or any(
        SAFE_IDENTIFIER_PATTERN.fullmatch(item) is None for item in containers
    ):
        raise CollectionBlocked("the complete project container set could not be identified")

    all_container_ids = _lines(
        _run_probe(
            runner,
            store,
            f"probe_{label}_all_containers",
            (
                tool["docker"],
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                f"label=com.docker.compose.project={context.project_name}",
                "--format",
                "{{.ID}}",
            ),
        ).stdout
    )
    if not all_container_ids or any(
        SAFE_IDENTIFIER_PATTERN.fullmatch(item) is None for item in all_container_ids
    ):
        raise CollectionBlocked("the complete materialized project service set was unavailable")
    if len(set(all_container_ids)) != len(all_container_ids) or not set(containers) <= set(
        all_container_ids
    ):
        raise CollectionBlocked("the exact running project container set was unavailable")
    container_result = _run_probe(
        runner,
        store,
        f"probe_{label}_container_inspect",
        (tool["docker"], "inspect", *all_container_ids),
    )
    container_inventory = _container_inventory(
        context,
        _json_list(container_result, "project container inventory was invalid"),
        set(all_container_ids),
    )
    expected_running_ids = {
        container_id
        for container_id, (_service, running, _networks) in container_inventory.items()
        if running
    }
    if set(containers) != expected_running_ids:
        raise CollectionBlocked("running project container inventory changed during collection")
    for index, container in enumerate(containers):
        pid_result = _run_probe(
            runner,
            store,
            f"probe_{label}_container_pid_{index}",
            (tool["docker"], "inspect", "--format", "{{.State.Pid}}", container),
        )
        pid = pid_result.stdout.strip()
        if not pid.isdigit() or int(pid) <= 1:
            raise CollectionBlocked("a project container network namespace was unavailable")
        namespace = _run_probe(
            runner,
            store,
            f"probe_{label}_container_netns_{index}",
            (tool["readlink"], f"/proc/{pid}/ns/net"),
        )
        if not re.fullmatch(r"net:\[[0-9]+\]\s*", namespace.stdout):
            raise CollectionBlocked("a project container network namespace identity was invalid")
        sockets = _run_probe(
            runner,
            store,
            f"probe_{label}_container_sockets_{index}",
            (tool["nsenter"], "-t", pid, "-n", tool["ss"], "-H", "-tunap"),
        )
        service = container_inventory[container][0]
        public_connections.setdefault(service, []).extend(
            _public_remote_connections(sockets.stdout)
        )
    networks = _lines(
        _run_probe(
            runner,
            store,
            f"probe_{label}_networks",
            (
                tool["docker"],
                "network",
                "ls",
                "--no-trunc",
                "--filter",
                f"label=com.docker.compose.project={context.project_name}",
                "--format",
                "{{.ID}}",
            ),
        ).stdout
    )
    if not networks or any(SAFE_IDENTIFIER_PATTERN.fullmatch(item) is None for item in networks):
        raise CollectionBlocked("the project network set could not be identified")
    network_result = _run_probe(
        runner,
        store,
        f"probe_{label}_network_inspect",
        (tool["docker"], "network", "inspect", *networks),
    )
    network_payload = _json_list(network_result, "project network inventory was invalid")
    if len(network_payload) != len(networks) or len(set(networks)) != len(networks):
        raise CollectionBlocked("the exact project network set could not be proven")
    uplink_bridge_interface = _validate_mode_topology(
        context,
        network_payload,
        set(networks),
        container_inventory,
    )
    store.write_json(
        f"probe_{label}_resolver_config",
        {"path": "/etc/resolv.conf", "content": context.resolver_config},
    )
    if require_offline:
        dns_result = runner.run(
            f"probe_{label}_dns_external",
            (tool["getent"], "ahosts", "example.com"),
            15,
        )
        store.write_json(
            f"probe_{label}_dns_external",
            _bounded_result(f"probe_{label}_dns_external", dns_result),
        )
        if context.egress_mode == "strict_offline":
            if dns_result.returncode == 0:
                raise CollectionBlocked(
                    "external DNS resolution remained available after isolation"
                )
            if any(public_connections.values()):
                raise CollectionBlocked("public sockets remained after strict_offline isolation")
            _strict_container_egress_probes(
                context,
                runner,
                store,
                label,
                container_inventory,
            )
        elif any(
            connections
            for source, connections in public_connections.items()
            if source != "llm-egress"
        ):
            raise CollectionBlocked("controlled_gateway observed public sockets outside llm-egress")
    _recheck_project_inventory(
        context,
        runner,
        store,
        label,
        running_ids=set(containers),
        all_container_ids=set(all_container_ids),
        network_ids=set(networks),
        container_inventory=container_inventory,
        network_payload=network_payload,
    )
    return NetworkSnapshot(
        public_connections={
            source: tuple(sorted(connections, key=lambda item: (item.protocol, item.endpoint)))
            for source, connections in sorted(public_connections.items())
        },
        nftables_ruleset_sha256=hashlib.sha256(firewall.stdout.encode("utf-8")).hexdigest(),
        nftables_ruleset=cast(dict[str, object], nftables_ruleset),
        uplink_bridge_interface=uplink_bridge_interface,
    )


def _connection_target(
    connection: PublicConnection,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    host = _endpoint_host(connection.endpoint)
    if host is None:
        raise CollectionBlocked("a controlled egress public endpoint was invalid")
    if connection.endpoint.startswith("["):
        closing = connection.endpoint.find("]")
        port_text = connection.endpoint[closing + 1 :].removeprefix(":")
    else:
        _host, separator, port_text = connection.endpoint.rpartition(":")
        if not separator:
            raise CollectionBlocked("a controlled egress public endpoint was invalid")
    try:
        address = ipaddress.ip_address(host)
        port = int(port_text)
    except ValueError as error:
        raise CollectionBlocked("a controlled egress public endpoint was invalid") from error
    if not 1 <= port <= 65535:
        raise CollectionBlocked("a controlled egress public endpoint was invalid")
    return address, port


def _nft_match(left: object, right: object) -> dict[str, object]:
    return {"match": {"op": "==", "left": left, "right": right}}


def _nft_destination_value(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> object:
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return {
        "prefix": {
            "addr": str(network.network_address),
            "len": network.prefixlen,
        }
    }


def _counter_free_nft_expressions(value: object) -> list[object]:
    if not isinstance(value, list):
        raise CollectionBlocked("controlled egress nftables rule expression was invalid")
    expressions: list[object] = []
    for expression in value:
        if isinstance(expression, dict) and set(expression) == {"counter"}:
            counter = expression["counter"]
            if not (
                isinstance(counter, dict)
                and set(counter) == {"bytes", "packets"}
                and all(
                    isinstance(counter[key], int) and counter[key] >= 0
                    for key in ("bytes", "packets")
                )
            ):
                raise CollectionBlocked("controlled egress nftables counter was invalid")
            continue
        expressions.append(expression)
    return expressions


def _expected_nft_accept_expressions(
    interface: str,
    protocol: str,
    port: int,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> list[object]:
    address_protocol = "ip" if network.version == 4 else "ip6"
    return [
        _nft_match({"meta": {"key": "iifname"}}, interface),
        _nft_match({"meta": {"key": "l4proto"}}, protocol),
        _nft_match(
            {"payload": {"protocol": address_protocol, "field": "daddr"}},
            _nft_destination_value(network),
        ),
        _nft_match(
            {"payload": {"protocol": protocol, "field": "dport"}},
            port,
        ),
        {"accept": None},
    ]


def _validate_nft_rule_envelope(rule: object) -> dict[str, object]:
    if (
        not isinstance(rule, dict)
        or not {
            "chain",
            "comment",
            "expr",
            "family",
            "handle",
            "table",
        }
        <= set(rule)
        or not set(rule)
        <= {
            "chain",
            "comment",
            "expr",
            "family",
            "handle",
            "table",
        }
    ):
        raise CollectionBlocked("controlled egress nftables rule envelope was invalid")
    if (
        rule.get("family") != "inet"
        or rule.get("table") != CONTROLLED_NFT_TABLE
        or rule.get("chain") != CONTROLLED_NFT_CHAIN
        or rule.get("comment") != CONTROLLED_NFT_COMMENT
        or not isinstance(rule.get("handle"), int)
        or cast(int, rule["handle"]) <= 0
    ):
        raise CollectionBlocked("controlled egress nftables rule identity was invalid")
    return cast(dict[str, object], rule)


def _verify_nftables_controlled_policy(
    snapshot: NetworkSnapshot,
    destinations: tuple[
        tuple[
            str,
            int,
            ipaddress.IPv4Network | ipaddress.IPv6Network,
        ],
        ...,
    ],
) -> None:
    interface = snapshot.uplink_bridge_interface
    entries = snapshot.nftables_ruleset.get("nftables")
    if interface is None or not isinstance(entries, list):
        raise CollectionBlocked("controlled egress nftables policy scope was unavailable")
    matching_tables = [
        entry["table"]
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("table"), dict)
        and entry["table"].get("family") == "inet"
        and entry["table"].get("name") == CONTROLLED_NFT_TABLE
    ]
    matching_chains = [
        entry["chain"]
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("chain"), dict)
        and entry["chain"].get("family") == "inet"
        and entry["chain"].get("table") == CONTROLLED_NFT_TABLE
        and entry["chain"].get("name") == CONTROLLED_NFT_CHAIN
    ]
    if len(matching_tables) != 1 or len(matching_chains) != 1:
        raise CollectionBlocked("controlled egress nftables table or chain was unavailable")
    chain = matching_chains[0]
    if (
        not isinstance(chain, dict)
        or not {
            "family",
            "handle",
            "hook",
            "name",
            "policy",
            "prio",
            "table",
            "type",
        }
        <= set(chain)
        or (
            chain.get("type") != "filter"
            or chain.get("hook") != "forward"
            or chain.get("prio") != CONTROLLED_NFT_PRIORITY
            or chain.get("policy") != "accept"
            or not isinstance(chain.get("handle"), int)
            or cast(int, chain["handle"]) <= 0
        )
    ):
        raise CollectionBlocked("controlled egress nftables base chain was invalid")
    rules = [
        _validate_nft_rule_envelope(entry["rule"])
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("rule"), dict)
        and entry["rule"].get("family") == "inet"
        and entry["rule"].get("table") == CONTROLLED_NFT_TABLE
        and entry["rule"].get("chain") == CONTROLLED_NFT_CHAIN
    ]
    if len(rules) != len(destinations) + 1:
        raise CollectionBlocked("controlled egress nftables chain was not exact")
    actual_accepts = {
        canonical_digest(_counter_free_nft_expressions(rule["expr"])) for rule in rules[:-1]
    }
    expected_accepts = {
        canonical_digest(_expected_nft_accept_expressions(interface, protocol, port, network))
        for protocol, port, network in destinations
    }
    expected_drop = [
        _nft_match({"meta": {"key": "iifname"}}, interface),
        {"drop": None},
    ]
    if (
        len(actual_accepts) != len(rules) - 1
        or actual_accepts != expected_accepts
        or _counter_free_nft_expressions(rules[-1]["expr"]) != expected_drop
    ):
        raise CollectionBlocked(
            "controlled egress nftables rules did not enforce the exact scoped allowlist"
        )


def _validated_controlled_allowlist(
    observations: object,
    snapshot: NetworkSnapshot,
    context: ExecutionContext,
    runner: CommandRunner,
    store: ArtifactStore,
    artifact_id: str,
) -> tuple[
    tuple[
        tuple[
            str,
            int,
            ipaddress.IPv4Network | ipaddress.IPv6Network,
        ],
        ...,
    ],
    tuple[str, ...],
    str,
]:
    if not isinstance(observations, dict) or set(observations) != {
        "active_provider",
        "allowed_destinations",
        "approved_providers",
        "default_action",
        "endpoint_service",
        "enforcement_scope",
        "nftables_ruleset_sha256",
        "policy_engine",
    }:
        raise CollectionBlocked(
            "controlled_gateway requires explicit L3/L4 host allowlist evidence"
        )
    if (
        observations.get("policy_engine") != "nftables"
        or observations.get("default_action") != "drop"
        or observations.get("endpoint_service") != "llm-egress"
        or observations.get("enforcement_scope") != "llm-uplink-forward"
        or observations.get("nftables_ruleset_sha256") != snapshot.nftables_ruleset_sha256
    ):
        raise CollectionBlocked(
            "controlled_gateway L3/L4 policy did not bind the observed nftables ruleset"
        )
    raw_providers = observations.get("approved_providers")
    active_provider = observations.get("active_provider")
    if (
        not isinstance(raw_providers, list)
        or not raw_providers
        or not all(isinstance(item, str) for item in raw_providers)
    ):
        raise CollectionBlocked("controlled_gateway approved provider set is invalid")
    providers = tuple(cast(list[str], raw_providers))
    if (
        len(set(providers)) != len(providers)
        or any(item not in PROVIDER_HOSTS for item in providers)
        or providers != tuple(item for item in PROVIDER_ORDER if item in providers)
        or active_provider not in providers
    ):
        raise CollectionBlocked(
            "controlled_gateway active provider is outside the canonical approval set"
        )

    resolved_networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for provider in providers:
        step_id = f"{artifact_id}_dns_{provider}"
        result = _run_probe(
            runner,
            store,
            step_id,
            (context.tools["getent"], "ahosts", PROVIDER_HOSTS[provider]),
        )
        if result.stderr:
            raise CollectionBlocked("approved provider DNS proof emitted unexpected output")
        provider_networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        for line in _lines(result.stdout):
            first = line.split(maxsplit=1)[0]
            try:
                address = ipaddress.ip_address(first)
            except ValueError as error:
                raise CollectionBlocked("approved provider DNS result was invalid") from error
            if (
                not address.is_global
                or address.is_private
                or address.is_link_local
                or address.is_loopback
                or address.is_multicast
                or address.is_reserved
                or address.is_unspecified
            ):
                raise CollectionBlocked("approved provider DNS returned an unsafe address")
            provider_networks.add(
                ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=True)
            )
        if not provider_networks:
            raise CollectionBlocked("approved provider DNS returned no global address")
        resolved_networks.update(provider_networks)
    raw_destinations = observations.get("allowed_destinations")
    if (
        not isinstance(raw_destinations, list)
        or len(raw_destinations) != len(resolved_networks)
        or not 1 <= len(raw_destinations) <= 64
    ):
        raise CollectionBlocked("controlled_gateway L3/L4 allowlist is empty or unbounded")
    destinations: list[tuple[str, int, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    seen: set[tuple[str, int, str]] = set()
    for raw in raw_destinations:
        if not isinstance(raw, dict) or set(raw) != {"cidr", "port", "protocol"}:
            raise CollectionBlocked("controlled_gateway L3/L4 allowlist entry is invalid")
        protocol = raw.get("protocol")
        port = raw.get("port")
        cidr = raw.get("cidr")
        if (
            protocol != "tcp"
            or not isinstance(port, int)
            or port != 443
            or not isinstance(cidr, str)
        ):
            raise CollectionBlocked("controlled_gateway L3/L4 allowlist entry is invalid")
        try:
            network = ipaddress.ip_network(cidr, strict=True)
        except ValueError as error:
            raise CollectionBlocked(
                "controlled_gateway L3/L4 allowlist entry is invalid"
            ) from error
        if (
            network.prefixlen != network.max_prefixlen
            or not network.network_address.is_global
            or network.is_private
            or network.is_loopback
            or network.is_link_local
            or network.is_multicast
            or network.is_reserved
            or network.is_unspecified
        ):
            raise CollectionBlocked(
                "controlled_gateway L3/L4 allowlist entry is excessively broad or unsafe"
            )
        identity = (cast(str, protocol), port, network.with_prefixlen)
        if identity in seen:
            raise CollectionBlocked("controlled_gateway L3/L4 allowlist contains duplicates")
        seen.add(identity)
        destinations.append((cast(str, protocol), port, network))
    normalized_destinations = tuple(
        sorted(
            destinations,
            key=lambda item: (item[0], item[1], item[2].version, item[2].with_prefixlen),
        )
    )
    if {item[2] for item in normalized_destinations} != resolved_networks:
        raise CollectionBlocked("controlled_gateway allowlist differs from approved provider DNS")
    _verify_nftables_controlled_policy(snapshot, normalized_destinations)
    return normalized_destinations, providers, cast(str, active_provider)


def _verify_controlled_egress_policy(
    context: ExecutionContext,
    runner: CommandRunner,
    store: ArtifactStore,
    snapshot: NetworkSnapshot,
    *,
    artifact_id: str,
) -> tuple[
    str,
    tuple[
        tuple[
            str,
            int,
            ipaddress.IPv4Network | ipaddress.IPv6Network,
        ],
        ...,
    ],
    tuple[str, ...],
    str,
]:
    argv, timeout = _command_spec(context, CONTROLLED_EGRESS_POLICY_STEP)
    payload = _validated_step_payload(
        context,
        CONTROLLED_EGRESS_POLICY_STEP,
        runner.run(CONTROLLED_EGRESS_POLICY_STEP, argv, timeout),
    )
    destinations, providers, active_provider = _validated_controlled_allowlist(
        payload.get("observations"),
        snapshot,
        context,
        runner,
        store,
        artifact_id,
    )
    _assert_controlled_connections_allowed(snapshot, destinations)
    # Persist only after the exact observation schema, DNS set and nftables
    # semantics have passed.  A rejected harness can never write headers or a
    # provider response body into the formal evidence directory.
    stored_id = store.write_json(artifact_id, payload)
    return stored_id, destinations, providers, active_provider


def _assert_controlled_connections_allowed(
    snapshot: NetworkSnapshot,
    destinations: tuple[
        tuple[
            str,
            int,
            ipaddress.IPv4Network | ipaddress.IPv6Network,
        ],
        ...,
    ],
) -> None:
    for connection in snapshot.public_connections.get("llm-egress", ()):
        address, port = _connection_target(connection)
        if not any(
            connection.protocol == protocol and port == allowed_port and address in network
            for protocol, allowed_port, network in destinations
        ):
            raise CollectionBlocked(
                "llm-egress used a public endpoint outside the attested L3/L4 allowlist"
            )


def execute_collection(
    context: ExecutionContext,
    *,
    runner: CommandRunner | None = None,
) -> dict[str, object]:
    formal_evidence = runner is None
    active_runner = runner or SubprocessCommandRunner()
    required_steps = set(_required_command_steps(context.egress_mode))
    if set(context.commands) != required_steps:
        raise CollectionBlocked(
            f"{context.egress_mode} control plan does not define its exact command set"
        )
    store = ArtifactStore(context.output_dir)
    checks: dict[str, dict[str, object]] = {}
    disconnect_attempted = False
    restored = False
    recovery_completed = False
    cleanup_error: CollectionBlocked | None = None
    try:
        recovery_id = _run_control_step(context, active_runner, store, "recovery_preflight")
        _network_snapshot(context, active_runner, store, "before", require_offline=False)
        rollback_id = _run_control_step(context, active_runner, store, "rollback_arm")
        disconnect_attempted = True
        disconnect_id = _run_control_step(context, active_runner, store, "network_disconnect")
        offline_ids_before = len(store.artifacts)
        _network_snapshot(context, active_runner, store, "offline", require_offline=True)
        cold_start_id = _run_control_step(context, active_runner, store, "cold_start")
        checks["cold_start"] = {"status": "passed", "artifact_ids": [cold_start_id]}
        post_cold_snapshot = _network_snapshot(
            context,
            active_runner,
            store,
            "offline_post_cold_start",
            require_offline=True,
        )
        policy_id: str | None = None
        controlled_destinations: (
            tuple[
                tuple[
                    str,
                    int,
                    ipaddress.IPv4Network | ipaddress.IPv6Network,
                ],
                ...,
            ]
            | None
        ) = None
        controlled_provider_identity: tuple[tuple[str, ...], str] | None = None
        if context.egress_mode == "controlled_gateway":
            (
                policy_id,
                controlled_destinations,
                approved_providers,
                active_provider,
            ) = _verify_controlled_egress_policy(
                context,
                active_runner,
                store,
                post_cold_snapshot,
                artifact_id="controlled_egress_policy_post_cold_start",
            )
            controlled_provider_identity = (approved_providers, active_provider)
        offline_ids = [cast(str, item["id"]) for item in store.artifacts[offline_ids_before:]]
        if policy_id is not None and policy_id not in offline_ids:
            raise CollectionBlocked("controlled egress policy artifact was not captured")
        business_artifacts: dict[str, str] = {}
        for step_id in BUSINESS_STEPS:
            business_artifacts[step_id] = _run_control_step(context, active_runner, store, step_id)
        evidenced_business_steps = (
            "login",
            "rbac",
            "acl",
            "upload",
            "approval",
            "download",
            "question_answer",
        )
        for step_id in evidenced_business_steps:
            checks[step_id] = {
                "status": "passed",
                "artifact_ids": [business_artifacts[step_id]],
            }
        checks["restart_persistence"] = {
            "status": "passed",
            "artifact_ids": [
                business_artifacts["persistence_write"],
                business_artifacts["restart"],
                business_artifacts["persistence_verify"],
            ],
        }
        post_business_ids_before = len(store.artifacts)
        post_business_snapshot = _network_snapshot(
            context,
            active_runner,
            store,
            "offline_post_business",
            require_offline=True,
        )
        if context.egress_mode == "controlled_gateway":
            if controlled_destinations is None:
                raise CollectionBlocked("controlled egress policy evidence was unavailable")
            (
                _post_policy_id,
                post_business_destinations,
                post_business_providers,
                post_business_active_provider,
            ) = _verify_controlled_egress_policy(
                context,
                active_runner,
                store,
                post_business_snapshot,
                artifact_id="controlled_egress_policy_post_business",
            )
            if (
                post_business_destinations != controlled_destinations
                or controlled_provider_identity
                != (post_business_providers, post_business_active_provider)
            ):
                raise CollectionBlocked(
                    "controlled egress policy identity changed during business acceptance"
                )
        offline_ids.extend(
            cast(str, item["id"]) for item in store.artifacts[post_business_ids_before:]
        )
        checks["offline_network_isolation"] = {
            "status": "passed",
            "artifact_ids": [recovery_id, rollback_id, disconnect_id, *offline_ids],
        }
        restore_id = _run_control_step(context, active_runner, store, "network_restore")
        restored = True
        cancel_id = _run_control_step(context, active_runner, store, "rollback_cancel")
        verify_id = _run_control_step(context, active_runner, store, "recovery_verify")
        recovery_completed = True
        _network_snapshot(context, active_runner, store, "restored", require_offline=False)
        checks["network_recovery"] = {
            "status": "passed",
            "artifact_ids": [restore_id, cancel_id, verify_id],
        }
    finally:
        if disconnect_attempted and not recovery_completed:
            try:
                if not restored:
                    _run_control_step(context, active_runner, store, "network_restore")
                    restored = True
                _run_control_step(context, active_runner, store, "rollback_cancel")
                _run_control_step(context, active_runner, store, "recovery_verify")
                recovery_completed = True
            except CollectionBlocked:
                cleanup_error = CollectionBlocked("network restore or rollback verification failed")
        if cleanup_error is not None:
            raise cleanup_error
    document: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "evidence_id": "EXT-OFFLINE-RUNTIME-001",
        "status": "complete",
        "result": "passed" if formal_evidence else "test-only",
        "runner": "subprocess-v1" if formal_evidence else "test-double",
        "collector": {"id": COLLECTOR_ID, "version": COLLECTOR_VERSION},
        "collected_at": datetime.now(UTC).isoformat(),
        "challenge": context.challenge,
        "test_tenant": context.test_tenant,
        "target": {
            "git_head": context.git_head,
            "content_fingerprint": context.content_fingerprint,
            "host_fingerprint": context.host_fingerprint,
            "project_name": context.project_name,
            "egress_mode": context.egress_mode,
        },
        "checks": checks,
        "artifacts": store.artifacts,
    }
    document["result_sha256"] = canonical_digest(
        {"target": document["target"], "checks": checks, "artifacts": store.artifacts}
    )
    document["attestation"] = {
        "type": "sha256-chain-v1",
        "digest": canonical_digest(document),
    }
    output = context.output_dir / "offline-runtime-evidence.json"
    raw = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return document


def host_fingerprint() -> str:
    try:
        machine_id = Path("/etc/machine-id").read_text(encoding="ascii").strip()
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        root_device = str(os.stat("/").st_dev)
    except (OSError, UnicodeError) as error:
        raise CollectionBlocked("target host identity could not be collected") from error
    material = "\0".join(
        (
            machine_id,
            boot_id,
            platform.node(),
            platform.release(),
            platform.machine(),
            root_device,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _secure_root_file(path: Path, *, executable: bool = False) -> Path:
    if path.is_symlink() or not path.is_file():
        raise CollectionBlocked("a required control artifact is not a regular file")
    metadata = path.stat()
    if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise CollectionBlocked("control artifacts must be root-owned and non-writable")
    if executable and not metadata.st_mode & stat.S_IXUSR:
        raise CollectionBlocked("control harnesses must be directly executable")
    return path.resolve(strict=True)


def _load_control_plan(path: Path) -> dict[str, object]:
    resolved = _secure_root_file(path)
    if resolved.stat().st_size > 256 * 1024:
        raise CollectionBlocked("control plan exceeded its size bound")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CollectionBlocked("control plan is invalid") from error
    if not isinstance(payload, dict):
        raise CollectionBlocked("control plan is invalid")
    return cast(dict[str, object], payload)


def _validate_control_commands(
    value: object, *, challenge: str, test_tenant: str, egress_mode: str
) -> dict[str, dict[str, object]]:
    if not isinstance(value, dict) or set(value) != set(_required_command_steps(egress_mode)):
        raise CollectionBlocked("control plan must define the exact required command set")
    commands: dict[str, dict[str, object]] = {}
    for step_id, raw in value.items():
        if (
            not isinstance(step_id, str)
            or not isinstance(raw, dict)
            or set(raw)
            != {
                "argv",
                "timeout_seconds",
            }
        ):
            raise CollectionBlocked("control command is malformed")
        argv = raw.get("argv")
        timeout = raw.get("timeout_seconds")
        if (
            not isinstance(argv, list)
            or not (1 <= len(argv) <= 64)
            or not all(
                isinstance(item, str)
                and 0 < len(item) <= 512
                and not any(character in item for character in ("\0", "\r", "\n"))
                for item in argv
            )
            or not isinstance(timeout, int)
            or not 1 <= timeout <= 900
        ):
            raise CollectionBlocked("control command exceeded its safety bounds")
        executable = Path(cast(str, argv[0]))
        if not executable.is_absolute() or executable.name.casefold() in FORBIDDEN_EXECUTABLES:
            raise CollectionBlocked("shells and indirect command launchers are forbidden")
        if challenge not in argv or test_tenant not in argv:
            raise CollectionBlocked("every control command must bind the challenge and test tenant")
        _secure_root_file(executable, executable=True)
        commands[step_id] = {"argv": list(argv), "timeout_seconds": timeout}
    return commands


def _resolve_system_tools() -> dict[str, str]:
    tools: dict[str, str] = {}
    for name in SYSTEM_TOOL_NAMES:
        resolved = shutil.which(name)
        if resolved is None:
            raise CollectionBlocked("a required offline network evidence tool is missing")
        tools[name] = str(_secure_root_file(Path(resolved), executable=True))
    return tools


def _reserve_challenge(state_dir: Path, challenge: str) -> None:
    if state_dir.is_symlink() or not state_dir.is_dir():
        raise CollectionBlocked("challenge state directory is unavailable")
    metadata = state_dir.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise CollectionBlocked("challenge state directory must be root-owned mode 0700")
    marker = state_dir / hashlib.sha256(challenge.encode("ascii")).hexdigest()
    try:
        descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise CollectionBlocked("the one-time challenge has already been consumed") from error
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(datetime.now(UTC).isoformat())
        handle.flush()
        os.fsync(handle.fileno())


def _required_text(value: str | None, label: str) -> str:
    if not value:
        raise CollectionBlocked(f"{label} is required for execution")
    return value


def _execution_context(arguments: argparse.Namespace) -> ExecutionContext:
    if platform.system().casefold() != "linux":
        raise CollectionBlocked("execution is only permitted on the target Linux host")
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise CollectionBlocked("execution requires root")
    if arguments.confirmation != EXECUTION_CONFIRMATION:
        raise CollectionBlocked("explicit execution confirmation did not match")
    challenge = _required_text(arguments.challenge, "challenge")
    tenant = _required_text(arguments.test_tenant, "test tenant")
    project = _required_text(arguments.project_name, "project name")
    egress_mode = _required_text(arguments.egress_mode, "egress mode")
    expected_host = _required_text(arguments.expected_host_fingerprint, "host fingerprint")
    if CHALLENGE_PATTERN.fullmatch(challenge) is None:
        raise CollectionBlocked("challenge format is invalid")
    if TENANT_PATTERN.fullmatch(tenant) is None:
        raise CollectionBlocked("a dedicated acceptance tenant is required")
    if PROJECT_PATTERN.fullmatch(project) is None or HASH_PATTERN.fullmatch(expected_host) is None:
        raise CollectionBlocked("target identity format is invalid")
    if egress_mode not in EGRESS_MODES:
        raise CollectionBlocked("egress mode is invalid")
    if host_fingerprint() != expected_host:
        raise CollectionBlocked("target host fingerprint did not match")
    repository = Path(_required_text(arguments.repository, "repository")).resolve(strict=True)
    output_dir = Path(_required_text(arguments.output_dir, "output directory"))
    disk_path = Path(_required_text(arguments.disk_path, "disk path")).resolve(strict=True)
    state_dir = Path(_required_text(arguments.challenge_state_dir, "challenge state directory"))
    plan_path = Path(_required_text(arguments.control_plan, "control plan"))
    if output_dir.exists() or output_dir.is_symlink():
        raise CollectionBlocked("evidence output directory must not already exist")
    output_parent = output_dir.parent.resolve(strict=True)
    parent_metadata = output_parent.stat()
    if parent_metadata.st_uid != 0 or parent_metadata.st_mode & stat.S_IWOTH:
        raise CollectionBlocked("evidence parent must be root-owned and not world-writable")
    facts = collect_host_facts(disk_path)
    if (
        facts.platform.casefold() != "linux"
        or facts.architecture.casefold() not in SUPPORTED_ARCHITECTURES
        or facts.logical_cpus < MINIMUM_LOGICAL_CPUS
        or facts.memory_bytes < MINIMUM_VISIBLE_MEMORY_BYTES
        or facts.filesystem_total_bytes < MINIMUM_FILESYSTEM_TOTAL_BYTES
        or facts.filesystem_available_bytes < MINIMUM_FILESYSTEM_AVAILABLE_BYTES
    ):
        raise CollectionBlocked("target host does not meet the 8C/16G/300G acceptance floor")
    identity = collect_worktree_evidence(repository)
    plan = _load_control_plan(plan_path)
    if (
        plan.get("schema_version") != SCHEMA_VERSION
        or plan.get("challenge") != challenge
        or plan.get("test_tenant") != tenant
        or plan.get("project_name") != project
        or plan.get("egress_mode") != egress_mode
        or plan.get("host_fingerprint") != expected_host
        or plan.get("git_head") != identity.git_head
        or plan.get("content_fingerprint") != identity.content_fingerprint
    ):
        raise CollectionBlocked("control plan is not bound to the active target and source")
    commands = _validate_control_commands(
        plan.get("commands"),
        challenge=challenge,
        test_tenant=tenant,
        egress_mode=egress_mode,
    )
    resolver_path = Path("/etc/resolv.conf").resolve(strict=True)
    resolver_metadata = resolver_path.stat()
    if (
        not resolver_path.is_file()
        or resolver_metadata.st_uid != 0
        or resolver_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise CollectionBlocked("resolver configuration is not a protected regular file")
    if resolver_path.stat().st_size > 64 * 1024:
        raise CollectionBlocked("resolver configuration exceeded its safety bound")
    tools = _resolve_system_tools()
    _reserve_challenge(state_dir, challenge)
    return ExecutionContext(
        challenge=challenge,
        test_tenant=tenant,
        project_name=project,
        git_head=identity.git_head,
        content_fingerprint=identity.content_fingerprint,
        host_fingerprint=expected_host,
        egress_mode=egress_mode,
        commands=commands,
        output_dir=output_dir,
        tools=tools,
        resolver_config=resolver_path.read_text(encoding="utf-8", errors="replace"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan or collect fail-closed offline runtime acceptance evidence"
    )
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirmation")
    parser.add_argument("--challenge")
    parser.add_argument("--test-tenant")
    parser.add_argument("--project-name")
    parser.add_argument("--egress-mode", choices=EGRESS_MODES)
    parser.add_argument("--expected-host-fingerprint")
    parser.add_argument("--repository")
    parser.add_argument("--disk-path")
    parser.add_argument("--control-plan")
    parser.add_argument("--output-dir")
    parser.add_argument("--challenge-state-dir", default="/var/lib/heyi-acceptance/challenges")
    arguments = parser.parse_args(argv)
    if not arguments.execute:
        plan = build_plan(arguments.egress_mode or "strict_offline")
        if platform.system().casefold() == "linux":
            try:
                plan["observed_host_fingerprint"] = host_fingerprint()
            except CollectionBlocked:
                plan["observed_host_fingerprint"] = None
        print(json.dumps(plan, ensure_ascii=False, sort_keys=True))
        return 0
    try:
        document = execute_collection(_execution_context(arguments))
    except (CollectionBlocked, OSError, ValueError, TypeError):
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "collector": COLLECTOR_ID,
                    "status": "complete",
                    "result": "blocked",
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(document, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
