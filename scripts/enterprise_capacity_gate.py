#!/usr/bin/env python3
"""Fail-closed evaluator for the enterprise load and capacity acceptance run.

This tool deliberately separates measured control-plane capacity from model-provider
capacity. A deterministic LLM stub can prove queueing, timeout, metering and fallback
behaviour, but it can never certify five billion real model tokens per day.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import secrets
import stat
import statistics
import sys
from collections.abc import Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TARGET_IDENTITIES = 1_000
TARGET_TOKENS_PER_DAY = 5_000_000_000
SECONDS_PER_DAY = 86_400
BUSINESS_WINDOW_SECONDS = 8 * 60 * 60
PEAK_MULTIPLIER = 5
MIN_STEADY_SECONDS = 30 * 60
MIN_LOGICAL_CPUS = 8
MIN_MEMORY_BYTES = 15 * 1024**3
MIN_DISK_BYTES = 300_000_000_000
MAX_HOST_CPU_MEAN_PERCENT = 75.0
MAX_HOST_MEMORY_PERCENT = 85.0
MIN_DISK_FREE_PERCENT = 20.0
MAX_POSTGRES_CONNECTIONS = 79
MAX_ERROR_RATE = 0.001


class GateInputError(ValueError):
    """The supplied evidence is absent, malformed, or not acceptance-grade."""


class GateOutputError(RuntimeError):
    """The capacity report cannot be published through a trusted filesystem path."""


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    passed: bool
    actual: Any
    expected: str
    evidence: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "actual": self.actual,
            "expected": self.expected,
            "evidence": self.evidence,
        }


def token_capacity_model() -> dict[str, Any]:
    conversations: dict[str, Any] = {}
    for tokens_per_conversation in (4_000, 8_000, 16_000):
        conversations[str(tokens_per_conversation)] = {
            "conversations_per_day": TARGET_TOKENS_PER_DAY / tokens_per_conversation,
            "chat_rps_24h_average": (
                TARGET_TOKENS_PER_DAY / tokens_per_conversation / SECONDS_PER_DAY
            ),
            "chat_rps_8h_average": (
                TARGET_TOKENS_PER_DAY / tokens_per_conversation / BUSINESS_WINDOW_SECONDS
            ),
            "chat_rps_5x_peak": (
                TARGET_TOKENS_PER_DAY
                / tokens_per_conversation
                / BUSINESS_WINDOW_SECONDS
                * PEAK_MULTIPLIER
            ),
            "upstream_calls_rps_5x_peak": (
                TARGET_TOKENS_PER_DAY
                / tokens_per_conversation
                / BUSINESS_WINDOW_SECONDS
                * PEAK_MULTIPLIER
                * 2
            ),
        }
    return {
        "classification": "MODELLED_NOT_MEASURED",
        "target_tokens_per_day": TARGET_TOKENS_PER_DAY,
        "tokens_per_second_24h_average": TARGET_TOKENS_PER_DAY / SECONDS_PER_DAY,
        "tokens_per_second_8h_average": (TARGET_TOKENS_PER_DAY / BUSINESS_WINDOW_SECONDS),
        "tokens_per_second_5x_peak": (
            TARGET_TOKENS_PER_DAY / BUSINESS_WINDOW_SECONDS * PEAK_MULTIPLIER
        ),
        "tokens_per_user_per_day": TARGET_TOKENS_PER_DAY / TARGET_IDENTITIES,
        "conversation_models": conversations,
        "certification_warning": (
            "These values are demand calculations only. Stub traffic, request counts, "
            "or a short benchmark cannot certify real provider token throughput, quota, "
            "quality, residency, or cost."
        ),
    }


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GateInputError(f"cannot read valid JSON evidence: {path}") from error
    if not isinstance(value, Mapping):
        raise GateInputError(f"JSON evidence must be an object: {path}")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise GateInputError(f"cannot hash evidence: {path}") from error
    return digest.hexdigest()


def _text(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise GateInputError(f"{name} must be a non-empty string")
    return value


def _manifest_binding(
    manifest: Mapping[str, Any], *, manifest_sha256: str
) -> tuple[dict[str, str], Mapping[str, Any]]:
    if manifest.get("schema_version") != 1:
        raise GateInputError("capacity manifest schema_version must equal 1")
    if manifest.get("classification") != "isolated_capacity_acceptance":
        raise GateInputError("capacity manifest is not an isolated acceptance run")
    if manifest.get("evidence_classification") != "not_model_capacity":
        raise GateInputError("capacity manifest must be classified not_model_capacity")
    if manifest.get("secret_material_included") is not False:
        raise GateInputError("manifest must explicitly exclude secret material")
    if manifest.get("identity_material_included") is not False:
        raise GateInputError("manifest must explicitly exclude identity material")
    run_id = _text(manifest.get("run_id"), name="manifest.run_id")
    project = _text(manifest.get("project"), name="manifest.project")
    git_commit = _text(manifest.get("git_commit"), name="manifest.git_commit")
    if not project.startswith("heyi-kb-acceptance-") or project == "heyi-kb-offline":
        raise GateInputError("manifest project is not a safe acceptance project")
    if project != f"heyi-kb-acceptance-{run_id}":
        raise GateInputError("manifest project and run id do not match")
    if len(git_commit) != 40 or any(
        character not in "0123456789abcdef" for character in git_commit
    ):
        raise GateInputError("manifest git commit must be lowercase 40-hex")
    acceptance = _mapping(manifest.get("acceptance"), name="manifest.acceptance")
    if acceptance.get("isolated") is not True or acceptance.get("cleanup_required") is not True:
        raise GateInputError("manifest must require isolated cleanup")
    fingerprints = _mapping(manifest.get("fingerprints"), name="manifest.fingerprints")
    binding = {
        "manifest_sha256": manifest_sha256,
        "run_id": run_id,
        "project": project,
        "git_commit": git_commit,
    }
    for key in (
        "compose_sha256",
        "non_secret_config_sha256",
        "host_sha256",
        "image_inventory_sha256",
    ):
        digest = _text(fingerprints.get(key), name=f"manifest.fingerprints.{key}")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise GateInputError(f"manifest fingerprint {key} must be lowercase SHA-256")
        binding[key] = digest
    return binding, _mapping(manifest.get("resource_sampling"), name="manifest.resource_sampling")


def _require_binding(value: Any, *, expected: Mapping[str, str], name: str) -> None:
    actual = _mapping(value, name=name)
    for key, expected_value in expected.items():
        if actual.get(key) != expected_value:
            raise GateInputError(f"{name}.{key} differs from the capacity manifest")


def _load_json_lines(path: Path) -> list[Mapping[str, Any]]:
    samples: list[Mapping[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise GateInputError(f"cannot read resource evidence: {path}") from error
    for line_number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise GateInputError(
                f"resource evidence line {line_number} is not valid JSON"
            ) from error
        if not isinstance(value, Mapping):
            raise GateInputError(f"resource evidence line {line_number} must be an object")
        samples.append(value)
    if len(samples) < 2:
        raise GateInputError("resource evidence requires at least two samples")
    return samples


def _mapping(value: Any, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GateInputError(f"{name} must be an object")
    return value


def _sequence(value: Any, *, name: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise GateInputError(f"{name} must be an array")
    return value


def _number(value: Any, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GateInputError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise GateInputError(f"{name} must be finite")
    return result


def _metric(summary: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    metrics = _mapping(summary.get("metrics"), name="summary.metrics")
    return _mapping(metrics.get(name), name=f"summary.metrics.{name}")


def _metric_number(summary: Mapping[str, Any], metric: str, value: str) -> float:
    return _number(_metric(summary, metric).get(value), name=f"{metric}.{value}")


def _sample_host(sample: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping(sample.get("host"), name="resource.host")


def _optional_metric_samples(
    samples: Iterable[Mapping[str, Any]], group: str, name: str
) -> list[float]:
    values: list[float] = []
    for sample in samples:
        group_value = sample.get(group)
        if isinstance(group_value, Mapping) and group_value.get(name) is not None:
            values.append(_number(group_value[name], name=f"resource.{group}.{name}"))
    return values


def _resource_checks(
    samples: list[Mapping[str, Any]],
    *,
    binding: Mapping[str, str],
    sampling_contract: Mapping[str, Any],
) -> list[Check]:
    expected_duration = _number(
        sampling_contract.get("duration_seconds"),
        name="manifest.resource_sampling.duration_seconds",
    )
    expected_interval = _number(
        sampling_contract.get("interval_seconds"),
        name="manifest.resource_sampling.interval_seconds",
    )
    expected_samples = int(
        _number(
            sampling_contract.get("expected_samples"),
            name="manifest.resource_sampling.expected_samples",
        )
    )
    maximum_gap = _number(
        sampling_contract.get("maximum_gap_seconds"),
        name="manifest.resource_sampling.maximum_gap_seconds",
    )
    if expected_samples != int(expected_duration // expected_interval):
        raise GateInputError("manifest expected sample count is inconsistent")
    if len(samples) != expected_samples:
        raise GateInputError(
            f"resource evidence has {len(samples)} samples; exactly {expected_samples} required"
        )
    sample_indexes: list[int] = []
    for sample in samples:
        if sample.get("schema_version") != 2:
            raise GateInputError("resource sample schema_version must equal 2")
        _require_binding(
            sample.get("evidence_binding"), expected=binding, name="resource.evidence_binding"
        )
        sample_indexes.append(
            int(_number(sample.get("sample_index"), name="resource.sample_index"))
        )
    if sample_indexes != list(range(1, expected_samples + 1)):
        raise GateInputError("resource sample indexes must be complete and contiguous")
    timestamps = [
        _number(sample.get("monotonic_seconds"), name="resource.monotonic_seconds")
        for sample in samples
    ]
    if timestamps != sorted(timestamps) or len(set(timestamps)) != len(timestamps):
        raise GateInputError("resource sample timestamps must be strictly increasing")
    gaps = [later - earlier for earlier, later in zip(timestamps, timestamps[1:], strict=False)]
    if timestamps[0] > maximum_gap:
        raise GateInputError("first resource sample was delayed beyond the allowed gap")
    if timestamps[-1] < expected_duration:
        raise GateInputError("last resource sample does not cover the full steady duration")
    if gaps and max(gaps) > maximum_gap:
        raise GateInputError("resource evidence contains a fail-closed monotonic sample gap")
    duration = timestamps[-1] - timestamps[0]
    hosts = [_sample_host(sample) for sample in samples]
    logical_cpus = _number(hosts[0].get("logical_cpus"), name="host.logical_cpus")
    memory_total = _number(hosts[0].get("memory_total_bytes"), name="host.memory_total_bytes")
    disk_total = _number(hosts[0].get("disk_total_bytes"), name="host.disk_total_bytes")
    cpu_values = [_number(host.get("cpu_percent"), name="host.cpu_percent") for host in hosts]
    memory_values = [
        _number(host.get("memory_percent"), name="host.memory_percent") for host in hosts
    ]
    disk_free_values = [
        _number(host.get("disk_free_percent"), name="host.disk_free_percent") for host in hosts
    ]

    errors: list[str] = []
    restart_deltas: list[int] = []
    oom_killed = False
    expected_container_names: set[str] | None = None
    for sample in samples:
        sample_errors = _sequence(sample.get("errors", []), name="resource.errors")
        errors.extend(str(item) for item in sample_errors)
        containers = _sequence(sample.get("containers"), name="resource.containers")
        names: set[str] = set()
        for raw_container in containers:
            container = _mapping(raw_container, name="resource.container")
            name = container.get("name")
            if not isinstance(name, str) or not name:
                raise GateInputError("resource container name must be non-empty")
            names.add(name)
            restart_deltas.append(
                int(_number(container.get("restart_delta"), name="container.restart_delta"))
            )
            oom_killed = oom_killed or bool(container.get("oom_killed"))
        if expected_container_names is None:
            expected_container_names = names
        elif names != expected_container_names:
            errors.append("container inventory changed during the load run")

    pg_active = _optional_metric_samples(samples, "postgres", "active_connections")
    pg_deadlocks = _optional_metric_samples(samples, "postgres", "deadlocks")
    pg_long_transactions = _optional_metric_samples(samples, "postgres", "long_transactions")
    redis_evicted = _optional_metric_samples(samples, "redis", "evicted_keys")
    redis_rejected = _optional_metric_samples(samples, "redis", "rejected_connections")

    required_observation_count = len(samples)
    database_observability_complete = all(
        len(values) >= required_observation_count
        for values in (
            pg_active,
            pg_deadlocks,
            pg_long_transactions,
            redis_evicted,
            redis_rejected,
        )
    )
    deadlock_delta = int(pg_deadlocks[-1] - pg_deadlocks[0]) if pg_deadlocks else -1
    evicted_delta = int(redis_evicted[-1] - redis_evicted[0]) if redis_evicted else -1
    rejected_delta = int(redis_rejected[-1] - redis_rejected[0]) if redis_rejected else -1

    return [
        Check(
            "resource_sample_coverage",
            len(samples) == expected_samples
            and timestamps[0] <= maximum_gap
            and timestamps[-1] >= expected_duration
            and (not gaps or max(gaps) <= maximum_gap),
            {
                "samples": len(samples),
                "first_seconds": round(timestamps[0], 3),
                "last_seconds": round(timestamps[-1], 3),
                "maximum_gap_seconds": round(max(gaps), 3) if gaps else 0,
                "monotonic_span_seconds": round(duration, 3),
            },
            (
                f"exactly {expected_samples} contiguous samples, final >= {expected_duration}s, "
                f"and every gap <= {maximum_gap}s"
            ),
            "manifest-bound resource JSONL monotonic clock",
        ),
        Check(
            "target_logical_cpus",
            logical_cpus >= MIN_LOGICAL_CPUS,
            int(logical_cpus),
            f">= {MIN_LOGICAL_CPUS}",
            "first host sample",
        ),
        Check(
            "target_memory",
            memory_total >= MIN_MEMORY_BYTES,
            int(memory_total),
            f">= {MIN_MEMORY_BYTES} bytes (15 GiB visible)",
            "first host sample",
        ),
        Check(
            "target_disk",
            disk_total >= MIN_DISK_BYTES,
            int(disk_total),
            f">= {MIN_DISK_BYTES} bytes",
            "first host sample for the configured data filesystem",
        ),
        Check(
            "host_cpu_mean",
            statistics.fmean(cpu_values) <= MAX_HOST_CPU_MEAN_PERCENT,
            round(statistics.fmean(cpu_values), 3),
            f"<= {MAX_HOST_CPU_MEAN_PERCENT}%",
            "all resource samples",
        ),
        Check(
            "host_memory_peak",
            max(memory_values) <= MAX_HOST_MEMORY_PERCENT,
            round(max(memory_values), 3),
            f"<= {MAX_HOST_MEMORY_PERCENT}%",
            "all resource samples",
        ),
        Check(
            "disk_free_floor",
            min(disk_free_values) >= MIN_DISK_FREE_PERCENT,
            round(min(disk_free_values), 3),
            f">= {MIN_DISK_FREE_PERCENT}%",
            "all resource samples",
        ),
        Check(
            "container_inventory_and_sampler_health",
            not errors,
            errors,
            "no sampler errors and a stable Compose inventory",
            "resource samples",
        ),
        Check(
            "container_restart_and_oom",
            bool(restart_deltas) and all(delta == 0 for delta in restart_deltas) and not oom_killed,
            {"restart_deltas": sorted(set(restart_deltas)), "oom_killed": oom_killed},
            "zero restarts and zero OOM kills",
            "Docker inspect samples",
        ),
        Check(
            "database_observability_coverage",
            database_observability_complete,
            {
                "required": required_observation_count,
                "postgres": len(pg_active),
                "redis": len(redis_evicted),
            },
            "every resource sample includes PostgreSQL and Redis counters",
            "resource samples",
        ),
        Check(
            "postgres_connections",
            bool(pg_active) and max(pg_active) <= MAX_POSTGRES_CONNECTIONS,
            max(pg_active) if pg_active else None,
            f"<= {MAX_POSTGRES_CONNECTIONS} active connections",
            "pg_stat_activity",
        ),
        Check(
            "postgres_deadlocks",
            deadlock_delta == 0,
            deadlock_delta,
            "delta = 0",
            "pg_stat_database",
        ),
        Check(
            "postgres_long_transactions",
            bool(pg_long_transactions) and max(pg_long_transactions) == 0,
            max(pg_long_transactions) if pg_long_transactions else None,
            "maximum = 0 transactions older than 30 seconds",
            "pg_stat_activity",
        ),
        Check(
            "redis_evictions",
            evicted_delta == 0,
            evicted_delta,
            "delta = 0",
            "Redis INFO stats",
        ),
        Check(
            "redis_rejected_connections",
            rejected_delta == 0,
            rejected_delta,
            "delta = 0",
            "Redis INFO stats",
        ),
    ]


def evaluate(
    summary: Mapping[str, Any],
    resource_samples: list[Mapping[str, Any]],
    manifest: Mapping[str, Any],
    cleanup: Mapping[str, Any],
    *,
    manifest_sha256: str,
    require_llm_stub: bool,
    require_quota_contracts: bool,
    require_multipart: bool,
) -> dict[str, Any]:
    binding, sampling_contract = _manifest_binding(manifest, manifest_sha256=manifest_sha256)
    if summary.get("schema_version") != 1:
        raise GateInputError("load summary schema_version must equal 1")
    if summary.get("profile") != "formal":
        raise GateInputError("only a formal load profile can produce acceptance evidence")
    if summary.get("classification") != "not_model_capacity":
        raise GateInputError("load summary must be explicitly classified not_model_capacity")
    if summary.get("isolated_acceptance") is not True:
        raise GateInputError("load summary must attest isolated acceptance execution")
    if summary.get("credential_material_included") is not False:
        raise GateInputError("load summary must explicitly exclude credential material")
    _require_binding(
        summary.get("evidence_binding"), expected=binding, name="summary.evidence_binding"
    )
    if (
        cleanup.get("schema_version") != 1
        or cleanup.get("classification") != "isolated_capacity_cleanup"
    ):
        raise GateInputError("cleanup evidence schema or classification is invalid")
    if cleanup.get("evidence_classification") != "not_model_capacity":
        raise GateInputError("cleanup evidence must be classified not_model_capacity")
    if cleanup.get("run_id") != binding["run_id"] or cleanup.get("project") != binding["project"]:
        raise GateInputError("cleanup evidence is bound to a different acceptance run")
    if cleanup.get("manifest_sha256") != manifest_sha256:
        raise GateInputError("cleanup evidence manifest digest differs")
    if cleanup.get("passed") is not True:
        raise GateInputError("isolated acceptance cleanup did not pass")
    if cleanup.get("containers_absent") is not True or cleanup.get("data_root_absent") is not True:
        raise GateInputError("cleanup did not remove all acceptance containers and data")
    configuration = _mapping(summary.get("configuration"), name="summary.configuration")
    identities = int(
        _number(configuration.get("identity_count"), name="configuration.identity_count")
    )
    steady_seconds = _number(
        configuration.get("steady_duration_seconds"),
        name="configuration.steady_duration_seconds",
    )
    if steady_seconds != _number(
        sampling_contract.get("duration_seconds"),
        name="manifest.resource_sampling.duration_seconds",
    ):
        raise GateInputError("k6 steady duration differs from resource-sampling manifest")
    chat_mode = configuration.get("chat_mode")
    if chat_mode not in {"retrieval_only", "stub"}:
        raise GateInputError("configuration.chat_mode must be retrieval_only or stub")
    if require_llm_stub and chat_mode != "stub":
        raise GateInputError("this run requires the deterministic LLM stub path")
    if require_multipart and configuration.get("multipart_enabled") is not True:
        raise GateInputError("this run requires the isolated multipart scenario")
    if summary.get("k6_thresholds_passed") is not True:
        raise GateInputError("k6 reported one or more failed thresholds")

    identity_attempts = _metric_number(summary, "identity_attempts", "count")
    identity_successes = _metric_number(summary, "identity_successes", "count")
    checks = [
        Check(
            "formal_duration",
            steady_seconds >= MIN_STEADY_SECONDS,
            steady_seconds,
            f">= {MIN_STEADY_SECONDS} seconds",
            "k6 formal configuration",
        ),
        Check(
            "unique_identity_input",
            identities >= TARGET_IDENTITIES,
            identities,
            f">= {TARGET_IDENTITIES} unique synthetic identities",
            "validated credential fixture count; credentials are not copied into evidence",
        ),
        Check(
            "identity_login_coverage",
            identity_attempts >= TARGET_IDENTITIES
            and identity_successes == identity_attempts
            and identity_successes >= identities,
            {"attempts": identity_attempts, "successes": identity_successes},
            "every supplied identity logs in and resolves /auth/me exactly successfully",
            "k6 custom counters",
        ),
        Check(
            "control_plane_latency",
            _metric_number(summary, "control_plane_latency", "p95") <= 500
            and _metric_number(summary, "control_plane_latency", "p99") <= 1_500,
            {
                "p95_ms": _metric_number(summary, "control_plane_latency", "p95"),
                "p99_ms": _metric_number(summary, "control_plane_latency", "p99"),
            },
            "p95 <= 500 ms and p99 <= 1500 ms",
            "k6 Trend",
        ),
        Check(
            "control_plane_success",
            _metric_number(summary, "control_plane_success", "rate") >= 0.999,
            _metric_number(summary, "control_plane_success", "rate"),
            ">= 0.999",
            "k6 Rate",
        ),
        Check(
            "retrieval_latency",
            _metric_number(summary, "retrieval_latency", "p95") <= 2_000
            and _metric_number(summary, "retrieval_latency", "p99") <= 5_000,
            {
                "p95_ms": _metric_number(summary, "retrieval_latency", "p95"),
                "p99_ms": _metric_number(summary, "retrieval_latency", "p99"),
            },
            "p95 <= 2000 ms and p99 <= 5000 ms",
            "k6 Trend",
        ),
        Check(
            "retrieval_success",
            _metric_number(summary, "retrieval_success", "rate") >= 0.999,
            _metric_number(summary, "retrieval_success", "rate"),
            ">= 0.999",
            "k6 Rate",
        ),
        Check(
            "unexpected_5xx",
            _metric_number(summary, "unexpected_5xx", "rate") <= MAX_ERROR_RATE,
            _metric_number(summary, "unexpected_5xx", "rate"),
            f"<= {MAX_ERROR_RATE}",
            "k6 Rate; expected quota/backpressure responses are tracked separately",
        ),
    ]

    if require_llm_stub:
        checks.extend(
            [
                Check(
                    "stub_rag_success",
                    _metric_number(summary, "stub_rag_success", "rate") >= 0.999,
                    _metric_number(summary, "stub_rag_success", "rate"),
                    ">= 0.999 responses are grounded RAG with passed answer review",
                    "deterministic OpenAI-compatible stub only",
                ),
                Check(
                    "stub_rag_latency",
                    _metric_number(summary, "stub_rag_latency", "p95") <= 5_000
                    and _metric_number(summary, "stub_rag_latency", "p99") <= 10_000,
                    {
                        "p95_ms": _metric_number(summary, "stub_rag_latency", "p95"),
                        "p99_ms": _metric_number(summary, "stub_rag_latency", "p99"),
                    },
                    "p95 <= 5000 ms and p99 <= 10000 ms",
                    "stub request path, not real model latency",
                ),
                Check(
                    "backpressure_safe_degradation",
                    _metric_number(summary, "backpressure_safe", "rate") >= 0.999,
                    _metric_number(summary, "backpressure_safe", "rate"),
                    ">= 0.999 bounded fallback/429/503 responses and no unhandled 5xx",
                    "stub-injected upstream 429 path",
                ),
            ]
        )

    if require_quota_contracts:
        for metric_name in (
            "request_rate_limit_contract",
            "upload_limit_contract",
            "download_limit_contract",
        ):
            checks.append(
                Check(
                    metric_name,
                    _metric_number(summary, metric_name, "rate") == 1.0,
                    _metric_number(summary, metric_name, "rate"),
                    "= 1.0",
                    "dedicated disposable quota identity",
                )
            )

    if require_multipart:
        checks.extend(
            [
                Check(
                    "multipart_success",
                    _metric_number(summary, "multipart_success", "rate") == 1.0,
                    _metric_number(summary, "multipart_success", "rate"),
                    "= 1.0 on the disposable isolated object store",
                    "k6 multipart initiate/part upload/complete flow",
                ),
                Check(
                    "multipart_concurrency",
                    _metric_number(summary, "multipart_attempts", "count") >= 8,
                    _metric_number(summary, "multipart_attempts", "count"),
                    ">= 8 concurrent multipart attempts",
                    "k6 multipart custom counter",
                ),
                Check(
                    "multipart_latency",
                    _metric_number(summary, "multipart_latency", "p95") <= 120_000,
                    _metric_number(summary, "multipart_latency", "p95"),
                    "p95 <= 120000 ms",
                    "end-to-end multipart completion Trend",
                ),
            ]
        )

    checks.extend(
        _resource_checks(
            resource_samples,
            binding=binding,
            sampling_contract=sampling_contract,
        )
    )
    checks.append(
        Check(
            "isolated_acceptance_cleanup",
            True,
            {
                "containers_absent": cleanup.get("containers_absent"),
                "data_root_absent": cleanup.get("data_root_absent"),
            },
            "temporary Compose project, database, and object-store data removed",
            "manifest-bound cleanup evidence",
        )
    )
    control_plane_passed = all(check.passed for check in checks)
    result = {
        "schema_version": 1,
        "evidence_classification": "not_model_capacity",
        "verdict": "PASS_CONTROL_PLANE" if control_plane_passed else "FAIL_CONTROL_PLANE",
        "control_plane_passed": control_plane_passed,
        "evidence_binding": binding,
        "checks": [check.as_dict() for check in checks],
        "capacity_claims": {
            "linux_8c_16g_300gb_control_plane": (
                "MEASURED_PASS" if control_plane_passed else "MEASURED_FAIL"
            ),
            "llm_stub_path": ("MEASURED_STUB_ONLY" if require_llm_stub else "NOT_RUN"),
            "five_billion_tokens_per_day": {
                "status": "UNVERIFIED_NO_GO",
                "reason": (
                    "This gate never promotes stub throughput to real provider capacity. "
                    "Independent provider/GPU-cluster quota, sustained real-token, cost, "
                    "residency and quality evidence is still required."
                ),
                "model": token_capacity_model(),
            },
            "ten_tb_storage": {
                "status": "UNVERIFIED_NO_GO",
                "reason": (
                    "A 300 GB single host cannot certify the separate 10 TB storage target."
                ),
            },
        },
    }
    return result


def _path_contains_symlink(path: Path) -> bool:
    candidate = path.absolute()
    for component in (candidate, *candidate.parents):
        try:
            if stat.S_ISLNK(component.lstat().st_mode):
                return True
        except FileNotFoundError:
            continue
        except OSError:
            return True
    return False


def _trusted_directory_descriptor(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        pinned = os.fstat(descriptor)
        current = path.stat()
        if (
            not stat.S_ISDIR(pinned.st_mode)
            or (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino)
            or (
                os.name == "posix"
                and (
                    pinned.st_uid != os.geteuid()  # type: ignore[attr-defined, unused-ignore]
                    or pinned.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                )
            )
        ):
            raise GateOutputError("capacity report directory is not private")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _prepare_private_output_parent(path: Path) -> None:
    existing_ancestor = path.parent
    while True:
        try:
            existing_ancestor.lstat()
        except FileNotFoundError:
            parent = existing_ancestor.parent
            if parent == existing_ancestor:
                raise GateOutputError("capacity report has no existing trusted ancestor") from None
            existing_ancestor = parent
            continue
        except OSError as error:
            raise GateOutputError("cannot inspect capacity report ancestors") from error
        break
    if _path_contains_symlink(existing_ancestor):
        raise GateOutputError("capacity report path cannot contain a symlink")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        raise GateOutputError("cannot create capacity report directory") from error
    if _path_contains_symlink(path.parent):
        raise GateOutputError("capacity report path cannot contain a symlink")


def _atomic_write(path: Path, raw: bytes) -> None:
    """Durably publish one private report without following filesystem links."""

    path = path.absolute()
    _prepare_private_output_parent(path)
    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    temporary_path = path.with_name(temporary_name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_descriptor: int | None = None
    descriptor: int | None = None
    temporary_created = False
    try:
        if os.name == "posix":
            directory_descriptor = _trusted_directory_descriptor(path.parent)
            try:
                destination = os.stat(path.name, dir_fd=directory_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                destination = None
            if destination is not None and not stat.S_ISREG(destination.st_mode):
                raise GateOutputError("capacity report destination must be a regular file")
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
        else:
            try:
                destination = path.lstat()
            except FileNotFoundError:
                destination = None
            if destination is not None and not stat.S_ISREG(destination.st_mode):
                raise GateOutputError("capacity report destination must be a regular file")
            descriptor = os.open(temporary_path, flags, 0o600)
        temporary_created = True
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if directory_descriptor is not None:
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            temporary_created = False
            os.fsync(directory_descriptor)
        else:
            try:
                destination = path.lstat()
            except FileNotFoundError:
                destination = None
            if destination is not None and not stat.S_ISREG(destination.st_mode):
                raise GateOutputError("capacity report destination must be a regular file")
            os.replace(temporary_path, path)
            temporary_created = False
    except GateOutputError:
        raise
    except OSError as error:
        raise GateOutputError("capacity report could not be published atomically") from error
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if temporary_created:
            with suppress(OSError):
                if directory_descriptor is not None:
                    os.unlink(temporary_name, dir_fd=directory_descriptor)
                else:
                    temporary_path.unlink()
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _write_json(path: Path | None, value: Mapping[str, Any]) -> None:
    rendered = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path is None:
        sys.stdout.write(rendered)
        return
    _atomic_write(path, rendered.encode())


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate the 8C/16G/300GB enterprise capacity evidence without overclaiming."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    model = subparsers.add_parser("model", help="print the five-billion-token demand model")
    model.add_argument("--output", type=Path)

    evaluate_parser = subparsers.add_parser(
        "evaluate", help="evaluate k6 and host resource evidence"
    )
    evaluate_parser.add_argument("--summary", type=Path, required=True)
    evaluate_parser.add_argument("--resources", type=Path, required=True)
    evaluate_parser.add_argument("--manifest", type=Path, required=True)
    evaluate_parser.add_argument("--cleanup", type=Path, required=True)
    evaluate_parser.add_argument("--output", type=Path)
    evaluate_parser.add_argument("--require-llm-stub", action="store_true")
    evaluate_parser.add_argument("--require-quota-contracts", action="store_true")
    evaluate_parser.add_argument("--require-multipart", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "model":
        try:
            _write_json(arguments.output, token_capacity_model())
        except GateOutputError as error:
            sys.stderr.write(f"capacity gate output rejected: {error}\n")
            return 2
        return 0
    try:
        result = evaluate(
            _load_json(arguments.summary),
            _load_json_lines(arguments.resources),
            _load_json(arguments.manifest),
            _load_json(arguments.cleanup),
            manifest_sha256=_sha256_file(arguments.manifest),
            require_llm_stub=arguments.require_llm_stub,
            require_quota_contracts=arguments.require_quota_contracts,
            require_multipart=arguments.require_multipart,
        )
    except GateInputError as error:
        sys.stderr.write(f"capacity gate input rejected: {error}\n")
        return 2
    try:
        _write_json(arguments.output, result)
    except GateOutputError as error:
        sys.stderr.write(f"capacity gate output rejected: {error}\n")
        return 2
    return 0 if result["control_plane_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
