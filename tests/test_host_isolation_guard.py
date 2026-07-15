from __future__ import annotations

import copy
import json
import os
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from scripts import host_isolation_guard as isolation_guard
from scripts.host_isolation_guard import (
    CONTAINER_INSPECT_TEMPLATE,
    EXCLUDED_COMPOSE_PROJECT_PREFIXES,
    EXCLUDED_COMPOSE_PROJECTS,
    GuardError,
    attach_integrity,
    collect_snapshot,
    load_hmac_key,
    load_json_evidence,
    safe_write_json,
    verify_against_baseline,
    verify_integrity,
)

PROTECTED_ID = "1" * 64
TARGET_ID = "2" * 64
ADDED_ID = "3" * 64
PROTECTED_IMAGE = f"sha256:{'a' * 64}"
TARGET_IMAGE = f"sha256:{'b' * 64}"
ADDED_IMAGE = f"sha256:{'c' * 64}"


def raw_container(
    *,
    identifier: str,
    name: str,
    image_id: str,
    project: str | None,
    host_port: str,
) -> dict[str, object]:
    return {
        "id": identifier,
        "name": f"/{name}",
        "image_id": image_id,
        "image_ref": f"registry.internal/{name}@{image_id}",
        "created_at": "2026-07-14T01:00:00.000000000Z",
        "state_status": "running",
        "state_running": True,
        "state_paused": False,
        "state_restarting": False,
        "state_oom_killed": False,
        "state_dead": False,
        "started_at": "2026-07-14T01:00:01.000000000Z",
        "finished_at": "0001-01-01T00:00:00Z",
        "exit_code": 0,
        "restart_count": 0,
        "health": "healthy",
        "restart_policy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
        "network_mode": "shared_default",
        "configured_ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": host_port}]},
        "runtime_ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": host_port}]},
        "mounts": [
            {
                "Type": "volume",
                "Name": f"{name}_data",
                "Source": f"/var/lib/docker/volumes/{name}_data/_data",
                "Destination": "/data",
                "Driver": "local",
                "Mode": "rw",
                "RW": True,
                "Propagation": "",
                "SecretValue": "mount-secret-must-not-appear",
            }
        ],
        "networks": {
            "shared_default": {
                "NetworkID": "d" * 64,
                "EndpointID": "e" * 64,
                "Gateway": "172.25.0.1",
                "IPAddress": "172.25.0.8",
                "IPPrefixLen": 16,
                "IPv6Gateway": "",
                "GlobalIPv6Address": "",
                "GlobalIPv6PrefixLen": 0,
                "MacAddress": "02:42:ac:19:00:08",
                "Aliases": [name, identifier[:12]],
                "DNSNames": [identifier[:12], name],
                "Links": None,
                "IPAMConfig": None,
                "DriverOpts": {"password": "network-secret-must-not-appear"},
            }
        },
        "compose_project": project,
        "Config": {
            "Env": ["PASSWORD=env-secret-must-not-appear"],
            "Labels": {"private.token": "label-secret-must-not-appear"},
        },
    }


class FakeDocker:
    def __init__(self, containers: list[dict[str, object]]) -> None:
        self.containers = copy.deepcopy(containers)

    def __call__(self, arguments: Sequence[str]) -> str:
        if arguments[0] == "info":
            return json.dumps(
                {
                    "daemon_id": "DAEMON-ENTERPRISE-01",
                    "daemon_name": "shared-app-host",
                    "server_version": "29.6.0",
                    "operating_system": "Ubuntu 24.04 LTS",
                    "architecture": "x86_64",
                }
            )
        if arguments[:2] == ("container", "ls"):
            return "\n".join(str(item["id"]) for item in self.containers) + "\n"
        if arguments[:2] == ("container", "inspect"):
            requested = set(arguments[4:])
            selected = [item for item in self.containers if item["id"] in requested]
            return "\n".join(json.dumps(item) for item in selected) + "\n"
        if arguments[:2] == ("image", "inspect"):
            return "\n".join(json.dumps(image_id) for image_id in arguments[4:]) + "\n"
        raise AssertionError(f"unexpected Docker command category: {arguments[:2]}")


def protected_container() -> dict[str, object]:
    return raw_container(
        identifier=PROTECTED_ID,
        name="existing-business-app",
        image_id=PROTECTED_IMAGE,
        project="existing-business",
        host_port="10051",
    )


def target_container(project: str = "heyi-kb-offline") -> dict[str, object]:
    return raw_container(
        identifier=TARGET_ID,
        name="heyi-kb-api",
        image_id=TARGET_IMAGE,
        project=project,
        host_port="19443",
    )


def protected_file_identity(path: str, *, inode: int) -> dict[str, object]:
    return {
        "declared_path": path,
        "resolved_path": path,
        "device": 2049,
        "inode": inode,
        "size": 8192,
        "mtime_ns": 1_750_000_000_000_000_000,
        "ctime_ns": 1_750_000_000_000_000_001,
        "uid": 0,
        "gid": 0,
        "mode": "0755",
        "sha256": f"{inode:064x}",
    }


def host_resources(
    *,
    main_pid: int = 702,
    socket_inode: int = 81234,
    listener: bool = True,
    requirements_satisfied: bool = True,
) -> dict[str, object]:
    process = {
        "pid": main_pid,
        "start_ticks": 900001,
        "executable": protected_file_identity("/usr/sbin/zabbix_agentd", inode=42001),
    }
    listeners = (
        [
            {
                "family": "ipv4",
                "local_address": "0.0.0.0",
                "local_port": 10050,
                "state": "LISTEN",
                "uid": 112,
                "socket_inode": socket_inode,
                "owner_unit": "zabbix-agent.service",
                "owner_pids": [main_pid],
            }
        ]
        if listener
        else []
    )
    return {
        "systemd_services": [
            {
                "unit": "zabbix-agent.service",
                "load_state": "loaded",
                "active_state": "active",
                "sub_state": "running",
                "unit_file_state": "enabled",
                "fragment": protected_file_identity(
                    "/usr/lib/systemd/system/zabbix-agent.service", inode=42002
                ),
                "main_pid": main_pid,
                "exec_main_pid": main_pid,
                "restart_count": 0,
                "invocation_id": "a" * 32,
                "control_group": "/system.slice/zabbix-agent.service",
                "user": "zabbix",
                "group": "zabbix",
                "dynamic_user": False,
                "active_enter_timestamp_monotonic": 800001,
                "exec_main_start_timestamp_monotonic": 800000,
                "processes": [process],
            }
        ],
        "tcp_listeners": listeners,
        "requirements_satisfied": requirements_satisfied,
    }


def systemctl_properties() -> dict[str, str]:
    return {
        "Id": "zabbix-agent.service",
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "UnitFileState": "enabled",
        "FragmentPath": "/usr/lib/systemd/system/zabbix-agent.service",
        "MainPID": "702",
        "ExecMainPID": "702",
        "NRestarts": "0",
        "InvocationID": "a" * 32,
        "ControlGroup": "/system.slice/zabbix-agent.service",
        "User": "zabbix",
        "Group": "zabbix",
        "DynamicUser": "no",
        "ActiveEnterTimestampMonotonic": "800001",
        "ExecMainStartTimestampMonotonic": "800000",
    }


class FakeHostProbe:
    def __init__(self, resources: dict[str, object] | None = None) -> None:
        self.resources = resources or host_resources()

    def __call__(self, enforce_required: bool) -> dict[str, object]:
        result = copy.deepcopy(self.resources)
        if enforce_required and result["requirements_satisfied"] is not True:
            raise GuardError(
                "required_port_unprotected",
                "required TCP port 10050 is not owned by zabbix-agent.service",
            )
        return result


def make_baseline(
    *, key: bytes | None = None, resources: dict[str, object] | None = None
) -> dict[str, object]:
    return collect_snapshot(
        FakeDocker([protected_container(), target_container()]),
        FakeHostProbe(resources),
        captured_at="2026-07-14T02:00:00Z",
        integrity_key=key,
    )


def test_snapshot_excludes_only_target_projects_and_keeps_exact_safe_fields() -> None:
    snapshot = make_baseline()

    assert snapshot["policy"] == {
        "excluded_compose_projects": list(EXCLUDED_COMPOSE_PROJECTS),
        "excluded_compose_project_prefixes": list(EXCLUDED_COMPOSE_PROJECT_PREFIXES),
        "required_protected_host_ports": [10050],
        "required_systemd_units": ["zabbix-agent.service"],
        "required_tcp_listeners": [
            {
                "protocol": "tcp",
                "port": 10050,
                "owner_unit": "zabbix-agent.service",
            }
        ],
        "process_identity_comparison": "exact",
        "service_restart_tolerance": "none",
        "comparison": "exact",
    }
    containers = snapshot["protected_containers"]
    assert isinstance(containers, list)
    assert len(containers) == 1
    assert containers[0]["name"] == "existing-business-app"
    assert containers[0]["image_id"] == PROTECTED_IMAGE
    assert containers[0]["state"]["started_at"] == "2026-07-14T01:00:01.000000000Z"
    assert containers[0]["state"]["restart_count"] == 0
    assert containers[0]["state"]["health"] == "healthy"
    assert containers[0]["restart_policy"] == {
        "name": "unless-stopped",
        "maximum_retry_count": 0,
    }
    assert snapshot["required_port_owners"] == {
        "10050": {
            "docker_containers": [],
            "systemd_units": ["zabbix-agent.service"],
        }
    }
    host_snapshot = snapshot["protected_host_resources"]
    assert isinstance(host_snapshot, dict)
    assert host_snapshot["systemd_services"][0]["main_pid"] == 702
    assert host_snapshot["tcp_listeners"][0]["local_port"] == 10050

    serialized = json.dumps(snapshot, ensure_ascii=False)
    for secret in (
        "env-secret-must-not-appear",
        "label-secret-must-not-appear",
        "mount-secret-must-not-appear",
        "network-secret-must-not-appear",
        "PASSWORD=",
        "private.token",
        "DriverOpts",
    ):
        assert secret not in serialized


def test_docker_template_never_requests_environment_commands_or_generic_labels() -> None:
    assert ".Config.Env" not in CONTAINER_INSPECT_TEMPLATE
    assert ".Config.Cmd" not in CONTAINER_INSPECT_TEMPLATE
    assert ".Args" not in CONTAINER_INSPECT_TEMPLATE
    assert "{{json .Config.Labels}}" not in CONTAINER_INSPECT_TEMPLATE
    assert "com.docker.compose.project" in CONTAINER_INSPECT_TEMPLATE


def test_host_probe_rejects_unknown_nested_fields_instead_of_serializing_secrets() -> None:
    unsafe = host_resources()
    unsafe["systemd_services"][0]["Environment"] = "PASSWORD=must-not-appear"

    with pytest.raises(GuardError) as raised:
        collect_snapshot(
            FakeDocker([protected_container(), target_container()]),
            FakeHostProbe(unsafe),
        )

    assert raised.value.code == "invalid_host_state"
    assert "must-not-appear" not in str(raised.value)


def test_system_runner_binds_an_absolute_docker_binary_and_redacts_daemon_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []
    observed_environment: dict[str, str] = {}
    trusted_docker = Path(os.path.abspath("trusted-docker"))

    monkeypatch.setattr(isolation_guard, "_resolve_docker_executable", lambda: trusted_docker)
    monkeypatch.setattr(
        isolation_guard,
        "_resolve_local_docker_endpoint",
        lambda: "unix:///run/docker.sock",
    )
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.invalid:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "remote-attacker")

    def failed_run(command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
        observed.extend(command)
        environment = options.get("env")
        assert isinstance(environment, dict)
        observed_environment.update(environment)
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="PASSWORD=daemon-error-secret-must-not-appear",
        )

    monkeypatch.setattr(isolation_guard.subprocess, "run", failed_run)
    with pytest.raises(GuardError) as raised:
        isolation_guard._system_docker_runner(("info",))

    assert raised.value.code == "docker_failed"
    assert str(raised.value) == "Docker inventory command failed"
    assert trusted_docker.is_absolute()
    assert observed[0] == os.fspath(trusted_docker)
    assert observed[1:3] == ["--host", "unix:///run/docker.sock"]
    assert observed_environment == {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": isolation_guard.TRUSTED_DOCKER_PATH,
    }


def test_systemctl_probe_uses_only_whitelisted_properties_and_sanitized_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_systemctl = Path(os.path.abspath("trusted-systemctl"))
    observed_command: list[str] = []
    observed_environment: dict[str, str] = {}
    properties = systemctl_properties()
    monkeypatch.setattr(
        isolation_guard,
        "_resolve_systemctl_executable",
        lambda: trusted_systemctl,
    )
    monkeypatch.setenv("SYSTEMD_PAGER", "credential-exfiltrator")
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.invalid:2375")

    def successful_run(command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
        observed_command.extend(command)
        environment = options.get("env")
        assert isinstance(environment, dict)
        observed_environment.update(environment)
        stdout = "\n".join(f"{key}={value}" for key, value in properties.items())
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(isolation_guard.subprocess, "run", successful_run)

    assert isolation_guard._systemctl_show("zabbix-agent.service") == properties
    assert observed_command[0] == os.fspath(trusted_systemctl)
    assert observed_command[1:4] == ["--system", "show", "zabbix-agent.service"]
    property_argument = next(item for item in observed_command if item.startswith("--property="))
    assert "Environment" not in property_argument
    assert "ExecStart" not in property_argument
    assert "CommandLine" not in property_argument
    assert observed_environment == {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": isolation_guard.TRUSTED_DOCKER_PATH,
    }


def test_systemctl_failure_never_relays_stderr_or_service_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        isolation_guard,
        "_resolve_systemctl_executable",
        lambda: Path(os.path.abspath("trusted-systemctl")),
    )

    def failed_run(command: list[str], **_options: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="Environment=PASSWORD=must-not-appear",
            stderr="ExecStart=/secret/path --api-key must-not-appear",
        )

    monkeypatch.setattr(isolation_guard.subprocess, "run", failed_run)
    with pytest.raises(GuardError) as raised:
        isolation_guard._systemctl_show("zabbix-agent.service")

    assert raised.value.code == "systemctl_failed"
    assert str(raised.value) == "Systemd unit state command failed"
    assert "must-not-appear" not in str(raised.value)


def test_proc_tcp_parser_collects_only_port_10050_listeners_without_process_text() -> None:
    header = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm retrnsmt   uid  "
        "timeout inode\n"
    )
    tcp = (
        header + "   0: 00000000:2742 00000000:0000 0A 00000000:00000000 "
        "00:00000000 00000000 112 0 81234 1\n"
        + "   1: 0100007F:01BB 00000000:0000 0A 00000000:00000000 "
        "00:00000000 00000000 0 0 90001 1\n"
    )
    tcp6 = (
        header + "   0: 00000000000000000000000000000000:2742 "
        "00000000000000000000000000000000:0000 0A "
        "00000000:00000000 00:00000000 00000000 112 0 81235 1\n"
    )

    ipv4 = isolation_guard._parse_proc_tcp(tcp, family="ipv4", required_port=10050)
    ipv6 = isolation_guard._parse_proc_tcp(tcp6, family="ipv6", required_port=10050)

    assert ipv4 == [
        {
            "family": "ipv4",
            "local_address": "0.0.0.0",
            "local_port": 10050,
            "state": "LISTEN",
            "uid": 112,
            "socket_inode": 81234,
        }
    ]
    assert ipv6[0]["local_address"] == "::"
    serialized = json.dumps([*ipv4, *ipv6])
    assert "command" not in serialized.lower()
    assert "environment" not in serialized.lower()


def test_systemd_snapshot_uses_mocked_linux_probes_and_detects_stable_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    properties = systemctl_properties()
    process = host_resources()["systemd_services"][0]["processes"][0]
    monkeypatch.setattr(isolation_guard, "_systemctl_show", lambda _unit: copy.deepcopy(properties))
    monkeypatch.setattr(isolation_guard, "_unit_cgroup_pids", lambda _group: [702])
    monkeypatch.setattr(
        isolation_guard,
        "_regular_file_identity",
        lambda path: protected_file_identity(path, inode=42002),
    )
    monkeypatch.setattr(isolation_guard, "_process_identity", lambda _pid: copy.deepcopy(process))
    monkeypatch.setattr(isolation_guard, "_process_start_ticks", lambda _pid: 900001)

    snapshot = isolation_guard._systemd_service_snapshot("zabbix-agent.service")

    assert snapshot["main_pid"] == 702
    assert snapshot["unit_file_state"] == "enabled"
    assert snapshot["processes"] == [process]
    serialized = json.dumps(snapshot).lower()
    for forbidden in ("password", "credential", "environment", "commandline", "execstart"):
        assert forbidden not in serialized


def test_required_host_resource_probe_maps_listener_to_systemd_cgroup_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = copy.deepcopy(host_resources()["systemd_services"][0])
    monkeypatch.setattr(
        isolation_guard,
        "_systemd_service_snapshot",
        lambda _unit: copy.deepcopy(service),
    )
    monkeypatch.setattr(isolation_guard, "_socket_inodes_for_pid", lambda _pid: {81234})
    monkeypatch.setattr(isolation_guard, "_assert_service_still_matches", lambda _service: None)
    monkeypatch.setattr(
        isolation_guard,
        "_tcp_listeners",
        lambda _port: [
            {
                "family": "ipv4",
                "local_address": "0.0.0.0",
                "local_port": 10050,
                "state": "LISTEN",
                "uid": 112,
                "socket_inode": 81234,
            }
        ],
    )

    resources = isolation_guard._collect_required_host_resources(True)

    assert resources["requirements_satisfied"] is True
    listener = resources["tcp_listeners"][0]
    assert listener["owner_unit"] == "zabbix-agent.service"
    assert listener["owner_pids"] == [702]


def test_required_host_resource_probe_fails_closed_on_listener_capture_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = copy.deepcopy(host_resources()["systemd_services"][0])
    calls = 0

    monkeypatch.setattr(
        isolation_guard,
        "_systemd_service_snapshot",
        lambda _unit: copy.deepcopy(service),
    )
    monkeypatch.setattr(isolation_guard, "_assert_service_still_matches", lambda _service: None)
    monkeypatch.setattr(isolation_guard, "_socket_inodes_for_pid", lambda _pid: {81234, 81235})

    def changing_listeners(_port: int) -> list[dict[str, object]]:
        nonlocal calls
        calls += 1
        return [
            {
                "family": "ipv4",
                "local_address": "0.0.0.0",
                "local_port": 10050,
                "state": "LISTEN",
                "uid": 112,
                "socket_inode": 81234 if calls == 1 else 81235,
            }
        ]

    monkeypatch.setattr(isolation_guard, "_tcp_listeners", changing_listeners)

    with pytest.raises(GuardError) as raised:
        isolation_guard._collect_required_host_resources(True)

    assert raised.value.code == "unstable_host_snapshot"


@pytest.mark.parametrize(
    "mutator",
    [
        lambda item: item.update(image_id=ADDED_IMAGE),
        lambda item: item.update(started_at="2026-07-14T03:00:00.000000000Z"),
        lambda item: item.update(restart_count=1),
        lambda item: item.update(health="unhealthy"),
        lambda item: item["restart_policy"].update(Name="always"),
        lambda item: item["mounts"][0].update(Destination="/changed"),
        lambda item: item["networks"]["shared_default"].update(IPAddress="172.25.0.9"),
        lambda item: item["runtime_ports"]["8080/tcp"][0].update(HostIp="127.0.0.1"),
    ],
)
def test_any_protected_resource_change_fails_with_hash_only_diagnostics(mutator: object) -> None:
    baseline = make_baseline()
    changed = protected_container()
    assert callable(mutator)
    mutator(changed)
    report = verify_against_baseline(
        baseline,
        FakeDocker([changed, target_container()]),
        FakeHostProbe(),
        verified_at="2026-07-14T03:00:00Z",
    )

    assert report["status"] == "FAIL"
    assert report["change_count"] >= 1
    changes = report["changes"]
    assert isinstance(changes, list)
    assert all(
        set(change) == {"path", "change", "before_sha256", "after_sha256"} for change in changes
    )
    serialized_changes = json.dumps(changes)
    assert "172.25.0.9" not in serialized_changes
    assert "unhealthy" not in serialized_changes


def test_added_non_project_container_fails_but_acceptance_project_changes_are_ignored() -> None:
    baseline = make_baseline()
    added = raw_container(
        identifier=ADDED_ID,
        name="unapproved-sidecar",
        image_id=ADDED_IMAGE,
        project=None,
        host_port="19000",
    )
    failed = verify_against_baseline(
        baseline,
        FakeDocker([protected_container(), target_container(), added]),
        FakeHostProbe(),
        verified_at="2026-07-14T03:00:00Z",
    )
    assert failed["status"] == "FAIL"

    changed_target = target_container("heyi-kb-acceptance-run-20260714")
    changed_target["restart_count"] = 999
    changed_target["image_id"] = ADDED_IMAGE
    passed = verify_against_baseline(
        baseline,
        FakeDocker([protected_container(), changed_target]),
        FakeHostProbe(),
        verified_at="2026-07-14T03:00:00Z",
    )
    assert passed["status"] == "PASS"
    assert passed["change_count"] == 0

    misleading_project = copy.deepcopy(added)
    misleading_project["compose_project"] = "heyi-kb-offline-shadow"
    exact_only = verify_against_baseline(
        baseline,
        FakeDocker([protected_container(), target_container(), misleading_project]),
        FakeHostProbe(),
        verified_at="2026-07-14T03:00:00Z",
    )
    assert exact_only["status"] == "FAIL"


def test_systemd_owned_port_10050_passes_without_docker_owner_and_missing_listener_fails() -> None:
    app = protected_container()
    snapshot = collect_snapshot(
        FakeDocker([app, target_container()]),
        FakeHostProbe(),
        captured_at="2026-07-14T02:00:00Z",
    )
    assert snapshot["required_port_owners"] == {
        "10050": {
            "docker_containers": [],
            "systemd_units": ["zabbix-agent.service"],
        }
    }

    missing_listener = host_resources(listener=False, requirements_satisfied=False)

    with pytest.raises(GuardError, match="10050") as raised:
        collect_snapshot(FakeDocker([app, target_container()]), FakeHostProbe(missing_listener))

    assert raised.value.code == "required_port_unprotected"

    report = verify_against_baseline(
        make_baseline(),
        FakeDocker([app, target_container()]),
        FakeHostProbe(missing_listener),
        verified_at="2026-07-14T03:00:00Z",
    )
    assert report["status"] == "FAIL"
    current = report["current_snapshot"]
    assert isinstance(current, dict)
    assert current["required_port_owners"] == {
        "10050": {"docker_containers": [], "systemd_units": []}
    }


def test_systemd_pid_restart_and_listener_inode_drift_fail_exact_comparison() -> None:
    baseline = make_baseline()
    restarted = host_resources(main_pid=1702, socket_inode=99123)

    report = verify_against_baseline(
        baseline,
        FakeDocker([protected_container(), target_container()]),
        FakeHostProbe(restarted),
        verified_at="2026-07-14T03:00:00Z",
    )

    assert report["status"] == "FAIL"
    change_paths = {item["path"] for item in report["changes"]}
    assert any("main_pid" in path for path in change_paths)
    assert any("socket_inode" in path for path in change_paths)


def test_sha256_and_hmac_integrity_detect_tampering_and_wrong_keys() -> None:
    sha_baseline = make_baseline()
    verify_integrity(sha_baseline)
    tampered = copy.deepcopy(sha_baseline)
    tampered["protected_image_ids"] = [ADDED_IMAGE]
    with pytest.raises(GuardError) as sha_error:
        verify_integrity(tampered)
    assert sha_error.value.code == "integrity_mismatch"

    key = b"formal-host-isolation-hmac-key-32-bytes-minimum"
    signed = make_baseline(key=key)
    verify_integrity(signed, key)
    with pytest.raises(GuardError) as missing_key:
        verify_integrity(signed)
    assert missing_key.value.code == "hmac_key_required"
    with pytest.raises(GuardError) as wrong_key:
        verify_integrity(signed, b"another-formal-host-isolation-key-32-bytes")
    assert wrong_key.value.code == "hmac_key_mismatch"


def test_safe_json_writer_is_atomic_and_evidence_is_machine_readable(tmp_path: Path) -> None:
    evidence = tmp_path / "host-isolation.json"
    snapshot = make_baseline()

    safe_write_json(evidence, snapshot)

    assert load_json_evidence(evidence) == snapshot
    assert list(tmp_path.glob(".host-isolation.json.*.tmp")) == []
    if os.name == "posix":
        assert stat.S_IMODE(evidence.stat().st_mode) == 0o600


def test_safe_writer_and_reader_reject_symlinks_when_supported(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("filesystem does not permit symlink creation")

    with pytest.raises(GuardError) as write_error:
        safe_write_json(link, attach_integrity({"safe": True}))
    assert write_error.value.code == "unsafe_output"
    with pytest.raises(GuardError) as read_error:
        load_json_evidence(link)
    assert read_error.value.code == "unsafe_file"

    real_directory = tmp_path / "real"
    real_directory.mkdir()
    linked_directory = tmp_path / "linked-directory"
    linked_directory.symlink_to(real_directory, target_is_directory=True)
    with pytest.raises(GuardError) as ancestor_error:
        safe_write_json(linked_directory / "evidence.json", attach_integrity({"safe": True}))
    assert ancestor_error.value.code == "unsafe_path"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission semantics required")
def test_hmac_key_must_be_private_on_posix(tmp_path: Path) -> None:
    key_path = tmp_path / "isolation.hmac"
    key_path.write_bytes(b"x" * 32)
    key_path.chmod(0o644)
    with pytest.raises(GuardError) as raised:
        load_hmac_key(key_path)
    assert raised.value.code == "unsafe_permissions"

    key_path.chmod(0o600)
    assert load_hmac_key(key_path) == b"x" * 32


def test_duplicate_json_keys_are_rejected_even_if_integrity_field_looks_valid(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "duplicate.json"
    evidence.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    if os.name == "posix":
        evidence.chmod(0o600)

    with pytest.raises(GuardError) as raised:
        load_json_evidence(evidence)

    assert raised.value.code == "invalid_json"
