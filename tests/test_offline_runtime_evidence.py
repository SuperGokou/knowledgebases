from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest

from scripts.collect_offline_runtime_evidence import (
    CONTROLLED_EGRESS_POLICY_STEP,
    EXECUTION_CONFIRMATION,
    REQUIRED_COMMAND_STEPS,
    CollectionBlocked,
    CommandResult,
    ExecutionContext,
    build_plan,
    canonical_digest,
    execute_collection,
    main,
    public_remote_endpoints,
)


def _fake_nft_ruleset(cidr: str, *, counter_packets: int | None = None) -> str:
    network = ipaddress.ip_network(cidr, strict=True)
    address_protocol = "ip" if network.version == 4 else "ip6"
    destination: object = str(network.network_address)
    if network.prefixlen != network.max_prefixlen:
        destination = {
            "prefix": {
                "addr": str(network.network_address),
                "len": network.prefixlen,
            }
        }
    counter = (
        []
        if counter_packets is None
        else [{"counter": {"packets": counter_packets, "bytes": counter_packets * 64}}]
    )
    common_rule = {
        "family": "inet",
        "table": "heyi_kb_egress",
        "chain": "heyi_llm_egress_forward",
        "comment": "heyi-controlled-egress",
    }
    return (
        json.dumps(
            {
                "nftables": [
                    {"metainfo": {"json_schema_version": 1}},
                    {"table": {"family": "inet", "name": "heyi_kb_egress", "handle": 1}},
                    {
                        "chain": {
                            "family": "inet",
                            "table": "heyi_kb_egress",
                            "name": "heyi_llm_egress_forward",
                            "handle": 2,
                            "type": "filter",
                            "hook": "forward",
                            "prio": -5,
                            "policy": "accept",
                        }
                    },
                    {
                        "rule": {
                            **common_rule,
                            "handle": 10,
                            "expr": [
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {"meta": {"key": "iifname"}},
                                        "right": "br-network-llm-",
                                    }
                                },
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {"meta": {"key": "l4proto"}},
                                        "right": "tcp",
                                    }
                                },
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {
                                            "payload": {
                                                "protocol": address_protocol,
                                                "field": "daddr",
                                            }
                                        },
                                        "right": destination,
                                    }
                                },
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                        "right": 443,
                                    }
                                },
                                *counter,
                                {"accept": None},
                            ],
                        }
                    },
                    {
                        "rule": {
                            **common_rule,
                            "handle": 11,
                            "expr": [
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {"meta": {"key": "iifname"}},
                                        "right": "br-network-llm-",
                                    }
                                },
                                *counter,
                                {"drop": None},
                            ],
                        }
                    },
                ]
            },
            separators=(",", ":"),
        )
        + "\n"
    )


@dataclass
class FakeRunner:
    challenge: str
    tenant: str
    egress_mode: str = "strict_offline"
    project_name: str = "heyi-kb-acceptance"
    fail_step: str | None = None
    materialize_gateway: bool | None = None
    include_uplink: bool | None = None
    uplink_internal: bool = False
    attach_api_to_uplink: bool = False
    attach_api_to_external: bool = False
    api_public_socket: str = ""
    gateway_public_socket: str = ""
    firewall_output: str | None = None
    post_business_firewall_output: str | None = None
    post_business_counter_packets: int | None = None
    policy_ruleset_sha256: str | None = None
    policy_enforcement_scope: str = "llm-uplink-forward"
    policy_cidr: str = "8.8.8.8/32"
    policy_protocol: str = "tcp"
    policy_port: int = 443
    approved_providers: tuple[str, ...] = ("deepseek",)
    active_provider: str = "deepseek"
    extra_policy_destination: dict[str, object] | None = None
    strict_probe_failure_service: str | None = None
    post_business_policy_cidr: str | None = None
    recheck_extra_container: bool = False
    calls: list[str] = field(default_factory=list)

    def _effective_policy_cidr(self, *, post_business: bool) -> str:
        if post_business and self.post_business_policy_cidr is not None:
            return self.post_business_policy_cidr
        return self.policy_cidr

    def _effective_firewall_output(self, *, post_business: bool) -> str:
        override = (
            self.post_business_firewall_output
            if post_business and self.post_business_firewall_output is not None
            else self.firewall_output
        )
        if override is not None:
            return override
        return _fake_nft_ruleset(
            self._effective_policy_cidr(post_business=post_business),
            counter_packets=(self.post_business_counter_packets if post_business else None),
        )

    def _gateway_materialized(self) -> bool:
        if self.materialize_gateway is not None:
            return self.materialize_gateway
        return self.egress_mode == "controlled_gateway"

    def _uplink_materialized(self) -> bool:
        if self.include_uplink is not None:
            return self.include_uplink
        return self.egress_mode == "controlled_gateway"

    def _network_names(self) -> list[str]:
        names = ["backend", "edge", "frontend", "llm-control"]
        if self._uplink_materialized():
            names.append("llm-uplink")
        return names

    def _container_ids(self) -> list[str]:
        ids = ["container-api", "container-maintenance"]
        if self._gateway_materialized():
            ids.append("container-egress")
        return ids

    def _container_payload(self) -> list[dict[str, object]]:
        api_networks = {"backend": "network-backend", "llm-control": "network-llm-control"}
        if self.attach_api_to_uplink:
            api_networks["llm-uplink"] = "network-llm-uplink"
        if self.attach_api_to_external:
            api_networks["foreign"] = "network-foreign"
        payload: list[dict[str, object]] = [
            {
                "Id": "container-api",
                "Config": {
                    "Labels": {
                        "com.docker.compose.project": self.project_name,
                        "com.docker.compose.service": "api",
                    }
                },
                "State": {"Running": True},
                "NetworkSettings": {
                    "Networks": {
                        name: {"NetworkID": network_id} for name, network_id in api_networks.items()
                    }
                },
            }
        ]
        payload.append(
            {
                "Id": "container-maintenance",
                "Config": {
                    "Labels": {
                        "com.docker.compose.project": self.project_name,
                        "com.docker.compose.service": "maintenance",
                    }
                },
                "State": {"Running": True},
                "NetworkSettings": {
                    "Networks": {
                        "backend": {"NetworkID": "network-backend"},
                        "llm-control": {"NetworkID": "network-llm-control"},
                    }
                },
            }
        )
        if self._gateway_materialized():
            gateway_networks = {"llm-control": "network-llm-control"}
            if self._uplink_materialized():
                gateway_networks["llm-uplink"] = "network-llm-uplink"
            payload.append(
                {
                    "Id": "container-egress",
                    "Config": {
                        "Labels": {
                            "com.docker.compose.project": self.project_name,
                            "com.docker.compose.service": "llm-egress",
                        }
                    },
                    "State": {"Running": self.egress_mode == "controlled_gateway"},
                    "NetworkSettings": {
                        "Networks": {
                            name: {"NetworkID": network_id}
                            for name, network_id in gateway_networks.items()
                        }
                    },
                }
            )
        return payload

    def _network_payload(self) -> list[dict[str, object]]:
        payload: list[dict[str, object]] = []
        for name in self._network_names():
            attached: dict[str, object] = {}
            if name in {"backend", "llm-control"}:
                attached["container-api"] = {"Name": "api"}
                attached["container-maintenance"] = {"Name": "maintenance"}
            if self._gateway_materialized() and name == "llm-control":
                attached["container-egress"] = {"Name": "llm-egress"}
            if name == "llm-uplink":
                if self._gateway_materialized():
                    attached["container-egress"] = {"Name": "llm-egress"}
                if self.attach_api_to_uplink:
                    attached["container-api"] = {"Name": "api"}
            payload.append(
                {
                    "Id": f"network-{name}",
                    "Name": f"{self.project_name}_{name}",
                    "Internal": not (name == "llm-uplink" and not self.uplink_internal),
                    "Labels": {
                        "com.docker.compose.project": self.project_name,
                        "com.docker.compose.network": name,
                    },
                    "Options": {},
                    "Containers": attached,
                }
            )
        return payload

    def run(self, step_id: str, argv: tuple[str, ...], timeout_seconds: int) -> CommandResult:
        del argv, timeout_seconds
        self.calls.append(step_id)
        if step_id == self.fail_step:
            return CommandResult(1, "", "deliberate failure")
        if step_id == CONTROLLED_EGRESS_POLICY_STEP:
            post_business_policy = self.calls.count(CONTROLLED_EGRESS_POLICY_STEP) > 1
            current_firewall = self._effective_firewall_output(post_business=post_business_policy)
            ruleset_hash = (
                self.policy_ruleset_sha256
                or hashlib.sha256(current_firewall.encode("utf-8")).hexdigest()
            )
            policy_cidr = self._effective_policy_cidr(post_business=post_business_policy)
            return CommandResult(
                0,
                json.dumps(
                    {
                        "status": "passed",
                        "check": step_id,
                        "challenge": self.challenge,
                        "test_tenant": self.tenant,
                        "observations": {
                            "policy_engine": "nftables",
                            "default_action": "drop",
                            "endpoint_service": "llm-egress",
                            "enforcement_scope": self.policy_enforcement_scope,
                            "nftables_ruleset_sha256": ruleset_hash,
                            "approved_providers": list(self.approved_providers),
                            "active_provider": self.active_provider,
                            "allowed_destinations": [
                                {
                                    "protocol": self.policy_protocol,
                                    "cidr": policy_cidr,
                                    "port": self.policy_port,
                                },
                                *(
                                    [self.extra_policy_destination]
                                    if self.extra_policy_destination is not None
                                    else []
                                ),
                            ],
                        },
                    }
                ),
                "",
            )
        if step_id.endswith("dns_external"):
            return CommandResult(2, "", "resolution blocked")
        if any(step_id.endswith(f"_dns_{provider}") for provider in self.approved_providers):
            address = str(ipaddress.ip_network(self.policy_cidr, strict=True).network_address)
            return CommandResult(0, f"{address} STREAM provider\n", "")
        if "strict_egress_" in step_id:
            service = step_id.rsplit("strict_egress_", 1)[1]
            if service == self.strict_probe_failure_service:
                return CommandResult(1, "", "")
            return CommandResult(
                0,
                f"heyi-strict-container-egress-v1:{service}\n",
                "",
            )
        if step_id.endswith("firewall"):
            return CommandResult(
                0,
                self._effective_firewall_output(post_business="offline_post_business" in step_id),
                "",
            )
        if step_id.endswith(("all_containers", "all_containers_recheck")):
            container_ids = self._container_ids()
            if step_id.endswith("all_containers_recheck") and self.recheck_extra_container:
                container_ids.append("container-rogue")
            return CommandResult(0, "\n".join(container_ids) + "\n", "")
        if step_id.endswith(("containers", "containers_recheck")):
            running_ids = [
                str(item["Id"])
                for item in self._container_payload()
                if item["State"] == {"Running": True}
            ]
            return CommandResult(0, "\n".join(running_ids) + "\n", "")
        if step_id.endswith(("container_inspect", "container_inspect_recheck")):
            return CommandResult(0, json.dumps(self._container_payload()), "")
        if "container_pid" in step_id:
            return CommandResult(0, "4242\n", "")
        if "container_netns" in step_id:
            return CommandResult(0, "net:[123456]\n", "")
        if "container_sockets_0" in step_id:
            return CommandResult(0, self.api_public_socket, "")
        if "container_sockets_1" in step_id:
            return CommandResult(0, "", "")
        if "container_sockets_2" in step_id:
            return CommandResult(0, self.gateway_public_socket, "")
        if step_id.endswith(("network_inspect", "network_inspect_recheck")):
            return CommandResult(0, json.dumps(self._network_payload()), "")
        if step_id.endswith(("networks", "networks_recheck")):
            names = (f"network-{name}" for name in self._network_names())
            return CommandResult(0, "\n".join(names) + "\n", "")
        if step_id.startswith("probe_"):
            return CommandResult(0, "", "")
        return CommandResult(
            0,
            json.dumps(
                {
                    "status": "passed",
                    "check": step_id,
                    "challenge": self.challenge,
                    "test_tenant": self.tenant,
                    "observations": {"verified": True},
                }
            ),
            "",
        )


def _context(tmp_path: Path, *, egress_mode: str = "strict_offline") -> ExecutionContext:
    challenge = "round2-offline-challenge-0123456789"
    tenant = "kb-acceptance-round2"
    command_steps = list(REQUIRED_COMMAND_STEPS)
    if egress_mode == "controlled_gateway":
        command_steps.append(CONTROLLED_EGRESS_POLICY_STEP)
    commands = {
        step: {
            "argv": [f"/opt/heyi-acceptance/{step}", challenge, tenant],
            "timeout_seconds": 30,
        }
        for step in command_steps
    }
    return ExecutionContext(
        challenge=challenge,
        test_tenant=tenant,
        project_name="heyi-kb-acceptance",
        git_head="a" * 40,
        content_fingerprint="b" * 64,
        host_fingerprint="c" * 64,
        egress_mode=egress_mode,
        commands=commands,
        output_dir=tmp_path / "evidence",
    )


def test_default_mode_only_prints_plan_and_never_runs_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "planned"
    assert payload["mutating"] is False
    assert payload["egress_mode"] == "strict_offline"
    assert payload["required_command_steps"] == list(REQUIRED_COMMAND_STEPS)
    assert payload["execute_confirmation"] == EXECUTION_CONFIRMATION


def test_plan_covers_every_required_network_and_business_check() -> None:
    plan = cast(dict[str, Any], build_plan())

    assert set(plan["network_evidence"]) == {
        "host_and_container_public_sockets",
        "dns_resolution_path",
        "default_and_all_routes",
        "host_and_container_network_namespaces",
        "firewall_ruleset",
        "mode_bound_compose_network_topology",
        "controlled_gateway_l3_l4_allowlist_attestation",
    }
    assert set(plan["business_checks"]) >= {
        "login",
        "rbac",
        "acl",
        "upload",
        "approval",
        "download",
        "question_answer",
        "persistence_verify",
    }


def test_controlled_gateway_plan_requires_policy_step_and_exact_topology() -> None:
    plan = cast(dict[str, Any], build_plan("controlled_gateway"))

    assert plan["egress_mode"] == "controlled_gateway"
    assert CONTROLLED_EGRESS_POLICY_STEP in plan["required_command_steps"]
    assert plan["network_topology"]["controlled_gateway"] == {
        "networks": ["backend", "edge", "frontend", "llm-control", "llm-uplink"],
        "only_noninternal_network": "llm-uplink",
        "only_uplink_service": "llm-egress",
        "requires_command_step": CONTROLLED_EGRESS_POLICY_STEP,
    }


def test_public_socket_parser_only_returns_globally_routable_peers() -> None:
    output = "\n".join(
        (
            "tcp ESTAB 0 0 10.0.0.2:443 8.8.8.8:53000 users:((x))",
            "tcp ESTAB 0 0 127.0.0.1:5432 127.0.0.1:41100 users:((x))",
            "udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:((x))",
            "tcp ESTAB 0 0 [fd00::2]:443 [fd00::3]:50000 users:((x))",
        )
    )

    assert public_remote_endpoints(output) == ["8.8.8.8:53000"]


def test_successful_fake_orchestration_writes_hashed_attested_evidence(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    runner = FakeRunner(context.challenge, context.test_tenant)

    document = cast(dict[str, Any], execute_collection(context, runner=runner))

    assert document["status"] == "complete"
    assert document["result"] == "test-only"
    assert document["runner"] == "test-double"
    assert document["target"]["egress_mode"] == "strict_offline"
    assert runner.calls.index("rollback_arm") < runner.calls.index("network_disconnect")
    assert runner.calls.index("network_restore") < runner.calls.index("rollback_cancel")
    assert set(document["checks"]) >= {
        "offline_network_isolation",
        "login",
        "rbac",
        "acl",
        "upload",
        "approval",
        "download",
        "question_answer",
        "restart_persistence",
    }
    for artifact in document["artifacts"]:
        path = context.output_dir / artifact["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == artifact["sha256"]
        assert path.stat().st_size == artifact["bytes"]
    assert document["attestation"]["digest"] == canonical_digest(
        {key: value for key, value in document.items() if key != "attestation"}
    )


def test_controlled_gateway_writes_mode_bound_policy_evidence(tmp_path: Path) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
        gateway_public_socket=("tcp ESTAB 0 0 172.30.244.2:44000 8.8.8.8:443 users:((caddy))\n"),
    )

    document = cast(dict[str, Any], execute_collection(context, runner=runner))

    assert document["target"]["egress_mode"] == "controlled_gateway"
    isolation_artifacts = document["checks"]["offline_network_isolation"]["artifact_ids"]
    assert "controlled_egress_policy_post_cold_start" in isolation_artifacts
    assert "controlled_egress_policy_post_business" in isolation_artifacts
    assert runner.calls.count(CONTROLLED_EGRESS_POLICY_STEP) == 2


@pytest.mark.parametrize(
    ("field_name", "field_value", "message"),
    [
        ("include_uplink", True, "exact reviewed Compose network set"),
        ("materialize_gateway", True, "forbids a materialized llm-egress"),
        ("attach_api_to_external", True, "attached to an unreviewed network"),
    ],
)
def test_strict_offline_rejects_uplink_or_gateway_materialization(
    tmp_path: Path,
    field_name: str,
    field_value: bool,
    message: str,
) -> None:
    context = _context(tmp_path)
    runner = FakeRunner(context.challenge, context.test_tenant)
    setattr(runner, field_name, field_value)

    with pytest.raises(CollectionBlocked, match=message):
        execute_collection(context, runner=runner)


@pytest.mark.parametrize(
    ("field_name", "field_value", "message"),
    [
        ("include_uplink", False, "exact reviewed Compose network set"),
        ("uplink_internal", True, "only noninternal network"),
        ("attach_api_to_uplink", True, "only llm-uplink endpoint"),
        ("materialize_gateway", False, "exactly one running llm-egress"),
    ],
)
def test_controlled_gateway_rejects_topology_drift(
    tmp_path: Path,
    field_name: str,
    field_value: bool,
    message: str,
) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
    )
    setattr(runner, field_name, field_value)

    with pytest.raises(CollectionBlocked, match=message):
        execute_collection(context, runner=runner)


def test_controlled_gateway_blocks_missing_or_unbound_l3_l4_policy(tmp_path: Path) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    missing_policy = ExecutionContext(
        challenge=context.challenge,
        test_tenant=context.test_tenant,
        project_name=context.project_name,
        git_head=context.git_head,
        content_fingerprint=context.content_fingerprint,
        host_fingerprint=context.host_fingerprint,
        egress_mode=context.egress_mode,
        commands={
            key: value
            for key, value in context.commands.items()
            if key != CONTROLLED_EGRESS_POLICY_STEP
        },
        output_dir=context.output_dir,
    )
    with pytest.raises(CollectionBlocked, match="exact command set"):
        execute_collection(
            missing_policy,
            runner=FakeRunner(
                context.challenge,
                context.test_tenant,
                egress_mode=context.egress_mode,
            ),
        )

    mismatch_root = tmp_path / "mismatch"
    mismatch_root.mkdir()
    mismatched_context = _context(mismatch_root, egress_mode="controlled_gateway")
    mismatched_runner = FakeRunner(
        mismatched_context.challenge,
        mismatched_context.test_tenant,
        egress_mode=mismatched_context.egress_mode,
        policy_ruleset_sha256="f" * 64,
    )
    with pytest.raises(CollectionBlocked, match="did not bind the observed nftables"):
        execute_collection(mismatched_context, runner=mismatched_runner)


def test_controlled_gateway_rejects_overstated_host_output_scope(tmp_path: Path) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
        policy_enforcement_scope="host-output-and-forward",
    )

    with pytest.raises(CollectionBlocked, match="did not bind the observed nftables"):
        execute_collection(context, runner=runner)


def test_controlled_gateway_rejects_non_gateway_or_unapproved_public_socket(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
        gateway_public_socket=("tcp ESTAB 0 0 172.30.244.2:44000 1.1.1.1:443 users:((caddy))\n"),
    )

    with pytest.raises(CollectionBlocked, match="outside the attested L3/L4 allowlist"):
        execute_collection(context, runner=runner)

    non_gateway_root = tmp_path / "non-gateway"
    non_gateway_root.mkdir()
    non_gateway_context = _context(non_gateway_root, egress_mode="controlled_gateway")
    non_gateway_runner = FakeRunner(
        non_gateway_context.challenge,
        non_gateway_context.test_tenant,
        egress_mode=non_gateway_context.egress_mode,
        api_public_socket=("tcp ESTAB 0 0 172.30.241.2:44000 8.8.8.8:443 users:((api))\n"),
    )
    with pytest.raises(CollectionBlocked, match="outside llm-egress"):
        execute_collection(non_gateway_context, runner=non_gateway_runner)


def test_controlled_gateway_accepts_dynamic_nft_counter_changes_when_reverified(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
        post_business_counter_packets=7,
    )

    document = execute_collection(context, runner=runner)

    assert document["result"] == "test-only"
    assert runner.calls.count(CONTROLLED_EGRESS_POLICY_STEP) == 2


def test_controlled_gateway_rejects_allowlist_mutation_during_business_checks(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
        post_business_policy_cidr="1.1.1.1/32",
    )

    with pytest.raises(
        CollectionBlocked,
        match="allowlist differs from approved provider DNS",
    ):
        execute_collection(context, runner=runner)


def test_controlled_gateway_rejects_excessively_broad_allowlist(tmp_path: Path) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
        policy_cidr="8.0.0.0/8",
    )

    with pytest.raises(CollectionBlocked, match="excessively broad"):
        execute_collection(context, runner=runner)


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    (("policy_protocol", "udp"), ("policy_port", 8443)),
)
def test_controlled_gateway_accepts_only_tcp_443_allowlist_entries(
    tmp_path: Path,
    field_name: str,
    field_value: object,
) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
    )
    setattr(runner, field_name, field_value)

    with pytest.raises(CollectionBlocked, match="allowlist entry is invalid"):
        execute_collection(context, runner=runner)


def test_controlled_gateway_rejects_private_provider_dns_and_allowlist(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
        policy_cidr="169.254.169.254/32",
    )

    with pytest.raises(CollectionBlocked, match="DNS returned an unsafe address"):
        execute_collection(context, runner=runner)


def test_controlled_gateway_rejects_any_extra_allowlist_destination(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
        extra_policy_destination={
            "protocol": "tcp",
            "cidr": "1.1.1.1/32",
            "port": 443,
        },
    )

    with pytest.raises(CollectionBlocked, match="allowlist is empty or unbounded"):
        execute_collection(context, runner=runner)


@pytest.mark.parametrize(
    ("approved_providers", "active_provider"),
    (
        (("qwen", "deepseek"), "qwen"),
        (("deepseek", "deepseek"), "deepseek"),
        (("deepseek",), "qwen"),
    ),
)
def test_controlled_gateway_rejects_noncanonical_or_unapproved_provider_identity(
    tmp_path: Path,
    approved_providers: tuple[str, ...],
    active_provider: str,
) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
        approved_providers=approved_providers,
        active_provider=active_provider,
    )

    with pytest.raises(CollectionBlocked, match="canonical approval set"):
        execute_collection(context, runner=runner)


def test_strict_offline_requires_exact_zero_egress_proof_from_each_app_namespace(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        strict_probe_failure_service="maintenance",
    )

    with pytest.raises(CollectionBlocked, match="strict_egress_maintenance"):
        execute_collection(context, runner=runner)


def test_controlled_gateway_rejects_harness_claim_without_matching_nft_policy(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
        firewall_output='{"nftables":[]}\n',
    )

    with pytest.raises(CollectionBlocked, match="table or chain was unavailable"):
        execute_collection(context, runner=runner)


def test_controlled_gateway_rejects_nft_rule_scoped_to_wrong_bridge(tmp_path: Path) -> None:
    payload = json.loads(_fake_nft_ruleset("8.8.8.8/32"))
    accept_rule = payload["nftables"][3]["rule"]
    accept_rule["expr"][0]["match"]["right"] = "br-unreviewed"
    firewall_output = json.dumps(payload, separators=(",", ":")) + "\n"
    context = _context(tmp_path, egress_mode="controlled_gateway")
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        egress_mode=context.egress_mode,
        firewall_output=firewall_output,
    )

    with pytest.raises(CollectionBlocked, match="exact scoped allowlist"):
        execute_collection(context, runner=runner)


def test_snapshot_rejects_container_created_during_inventory_window(tmp_path: Path) -> None:
    context = _context(tmp_path)
    runner = FakeRunner(
        context.challenge,
        context.test_tenant,
        recheck_extra_container=True,
    )

    with pytest.raises(CollectionBlocked, match="identity changed during snapshot"):
        execute_collection(context, runner=runner)


def test_business_failure_always_restores_network_and_is_blocked(tmp_path: Path) -> None:
    context = _context(tmp_path)
    runner = FakeRunner(context.challenge, context.test_tenant, fail_step="approval")

    with pytest.raises(CollectionBlocked, match="approval"):
        execute_collection(context, runner=runner)

    assert "network_restore" in runner.calls
    assert "rollback_cancel" in runner.calls
    assert "recovery_verify" in runner.calls


def test_restore_failure_can_never_create_pass_evidence(tmp_path: Path) -> None:
    context = _context(tmp_path)
    runner = FakeRunner(context.challenge, context.test_tenant, fail_step="network_restore")

    with pytest.raises(CollectionBlocked, match="restore"):
        execute_collection(context, runner=runner)

    assert not (context.output_dir / "offline-runtime-evidence.json").exists()


def test_fake_runner_output_is_explicitly_rejected_by_formal_schema(tmp_path: Path) -> None:
    context = _context(tmp_path)
    document = execute_collection(
        context, runner=FakeRunner(context.challenge, context.test_tenant)
    )
    schema_path = (
        Path(__file__).parents[1] / "docs" / "schemas" / "offline-runtime-evidence-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert document["result"] == "test-only"
    assert document["result"] != schema["properties"]["result"]["const"]
    assert document["runner"] != schema["properties"]["runner"]["const"]
    assert "egress_mode" in schema["properties"]["target"]["required"]
    assert schema["properties"]["target"]["properties"]["egress_mode"]["enum"] == [
        "strict_offline",
        "controlled_gateway",
    ]
    assert schema["properties"]["artifacts"]["maxItems"] == 256


def test_execute_mode_is_fail_closed_before_any_command_without_full_guard(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "scripts.collect_offline_runtime_evidence.platform.system", lambda: "Windows"
    )

    result = main(["--execute", "--confirmation", EXECUTION_CONFIRMATION])

    assert result == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "collector": "heyi-offline-runtime",
        "result": "blocked",
        "schema_version": 1,
        "status": "complete",
    }
