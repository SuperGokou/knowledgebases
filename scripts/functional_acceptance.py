from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import asdict, dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from scripts.acceptance import collect_worktree_evidence
from scripts.acceptance_gate import (
    AcceptanceGateError,
    GateIdentity,
    PytestJUnitEvidence,
    TrustedExecutableBinding,
    add_identity_arguments,
    assert_gate_identity,
    atomic_write_text,
    bind_trusted_executable,
    build_pytest_collection_command,
    build_pytest_execution_command,
    parse_pytest_collection,
    parse_pytest_junit,
    read_regular_file_nofollow,
    reserve_machine_report,
    sanitized_test_environment,
    start_gate_identity,
    verify_trusted_executable_binding,
    write_json_evidence,
)

ContractVerdict = Literal["PASS", "FAIL"]
ExternalVerdict = Literal["PASS", "BLOCKED"]
CheckStatus = Literal["passed", "failed", "blocked"]
SourceVerdict = Literal["PASS", "FAIL", "UNVERIFIED"]
RuntimeFunctionalVerdict = Literal["PASS", "FAIL", "BLOCKED"]
FunctionalProfile = Literal["source", "runtime-functional"]

_MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
_ALLOWED_EVIDENCE_KINDS = {"route", "source", "config", "documentation", "automated_test"}
_SKIP_PATTERN = re.compile(r"(?im)(?:\b\d+\s+skipped\b|\btests?\s+\d+\s+skipped\b)")
_PASS_PATTERN = re.compile(r"(?im)(?:\b(\d+)\s+passed\b|\btests?\s+(\d+)\s+passed\b)")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_SEMVER_PATTERN = re.compile(r"\d+\.\d+\.\d+")
_EXTERNAL_RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{8,80}\Z")
_CHALLENGE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_MAX_RAW_ARTIFACT_BYTES = 100 * 1024 * 1024
_MAX_CLOCK_SKEW = timedelta(minutes=5)
_SUPPORTED_FRAMEWORK_PREFIXES: dict[str, tuple[tuple[str, ...], ...]] = {
    "pytest": (
        ("uv", "run", "pytest"),
        ("python", "-m", "pytest"),
        ("python3", "-m", "pytest"),
    ),
    "vitest": (("node", "node_modules/vitest/vitest.mjs", "run"),),
}
_POLICY_RELATIVE_PATH = Path("docs/functional_acceptance_policy.json")
_POLICY_SHA256 = "1b83360e3eadc66e86fb422a43f2151103840db8a84168dc91867df41d93228e"


class ContractError(ValueError):
    """Raised when the manifest itself cannot be loaded safely."""


@dataclass(frozen=True, slots=True)
class RequirementResult:
    requirement_id: str
    status: CheckStatus
    summary: str


@dataclass(frozen=True, slots=True)
class ContractReport:
    verdict: ContractVerdict
    requirement_count: int
    passed: int
    failed: int
    requirements: tuple[RequirementResult, ...]
    policy_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class ExternalEvidenceResult:
    evidence_id: str
    status: Literal["passed", "blocked"]
    summary: str


@dataclass(frozen=True, slots=True)
class ExternalEvidenceReport:
    verdict: ExternalVerdict
    results: tuple[ExternalEvidenceResult, ...]


@dataclass(frozen=True, slots=True)
class TestCommandResult:
    command_id: str
    status: CheckStatus
    passed_tests: int
    summary: str
    machine_artifact: str | None = None
    machine_artifact_sha256: str | None = None
    result_hash: str | None = None
    verified_nodes: int = 0


@dataclass(frozen=True, slots=True)
class VitestMachineEvidence:
    collected: int
    executed: int
    passed: int
    failed: int
    skipped: int
    deselected: int
    unexpected: int
    node_ids: tuple[str, ...]
    missing_node_ids: tuple[str, ...]
    unexpected_node_ids: tuple[str, ...]
    test_files: tuple[str, ...]

    @property
    def is_success(self) -> bool:
        return bool(
            self.collected > 0
            and self.executed == self.collected
            and self.passed == self.collected
            and not any((self.failed, self.skipped, self.deselected, self.unexpected))
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "collected": self.collected,
            "executed": self.executed,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "deselected": self.deselected,
            "unexpected": self.unexpected,
            "node_ids": list(self.node_ids),
            "missing_node_ids": list(self.missing_node_ids),
            "unexpected_node_ids": list(self.unexpected_node_ids),
            "test_files": list(self.test_files),
        }


@dataclass(slots=True)
class ExternalTrustContext:
    """Verifier-owned trust material; private collector keys never enter this process."""

    public_keys: Mapping[tuple[str, str], bytes]
    challenges: Mapping[str, Mapping[str, object]]
    consumed_challenges: set[str]
    challenge_paths: Mapping[str, Path] = dataclass_field(default_factory=dict)


TestExecutor = Callable[[Sequence[str], Path, int], subprocess.CompletedProcess[str]]


def _secure_root_file(path: Path) -> bool:
    if os.name != "posix" or path.is_symlink() or not path.is_file():
        return False
    stat = path.stat()
    return stat.st_uid == 0 and (stat.st_mode & 0o777) in {0o400, 0o600}


def load_external_trust_context(
    repository: Path,
    trust_store: Path,
    challenge_store: Path,
) -> ExternalTrustContext:
    repository = repository.resolve()
    trust_store = trust_store.resolve()
    challenge_store = challenge_store.resolve()
    for candidate in (trust_store, challenge_store):
        try:
            candidate.relative_to(repository)
        except ValueError:
            pass
        else:
            raise ContractError("external trust material must be outside the repository")
    if not _secure_root_file(trust_store):
        raise ContractError("trusted collector public-key store is not root-owned 0400/0600")
    if (
        os.name != "posix"
        or challenge_store.is_symlink()
        or not challenge_store.is_dir()
        or challenge_store.stat().st_uid != 0
        or (challenge_store.stat().st_mode & 0o777) != 0o700
    ):
        raise ContractError("challenge store is not a root-owned 0700 directory")
    try:
        trust_document = json.loads(trust_store.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError("trusted collector public-key store is unreadable") from exc
    keys = _object_list(trust_document.get("keys")) if isinstance(trust_document, dict) else None
    if (
        not isinstance(trust_document, dict)
        or trust_document.get("schema_version") != 1
        or not keys
    ):
        raise ContractError("trusted collector public-key store is invalid")
    public_keys: dict[tuple[str, str], bytes] = {}
    for item in keys:
        collector_id = item.get("collector_id")
        key_id = item.get("key_id")
        encoded = item.get("public_key_base64")
        if not all(isinstance(value, str) and value for value in (collector_id, key_id, encoded)):
            raise ContractError("trusted collector public-key entry is invalid")
        collector_id = cast(str, collector_id)
        key_id = cast(str, key_id)
        encoded = cast(str, encoded)
        try:
            public_key = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ContractError("trusted collector public key is not valid base64") from exc
        if len(public_key) != 32 or (collector_id, key_id) in public_keys:
            raise ContractError("trusted collector public key is invalid or duplicated")
        public_keys[(collector_id, key_id)] = public_key
    challenges: dict[str, Mapping[str, object]] = {}
    challenge_paths: dict[str, Path] = {}
    consumed_challenges: set[str] = set()
    for path in challenge_store.glob("*.consumed"):
        consumed_id = path.name.removesuffix(".consumed")
        if (
            not consumed_id
            or _CHALLENGE_ID_PATTERN.fullmatch(consumed_id) is None
            or not _secure_root_file(path)
            or consumed_id in consumed_challenges
        ):
            raise ContractError("consumed challenge marker is invalid or duplicated")
        consumed_challenges.add(consumed_id)
    for path in challenge_store.glob("*.json"):
        if not _secure_root_file(path):
            raise ContractError("challenge file is not root-owned 0400/0600")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ContractError("challenge file is unreadable") from exc
        challenge = _mapping(document)
        challenge_id = challenge.get("challenge_id") if challenge else None
        if (
            challenge is None
            or challenge.get("schema_version") != 1
            or not isinstance(challenge_id, str)
            or not challenge_id
            or challenge_id in challenges
            or path.stem != challenge_id
        ):
            raise ContractError("challenge file is invalid or duplicated")
        challenges[challenge_id] = challenge
        challenge_paths[challenge_id] = path
    if not challenges:
        raise ContractError("challenge store has no issued challenge")
    return ExternalTrustContext(public_keys, challenges, consumed_challenges, challenge_paths)


def policy_digest(repository: Path) -> str:
    path = repository.resolve() / _POLICY_RELATIVE_PATH
    try:
        digest = _sha256_file(path)
    except OSError as exc:
        raise ContractError("trusted functional acceptance policy is unavailable") from exc
    if digest != _POLICY_SHA256:
        raise ContractError("trusted functional acceptance policy digest mismatch")
    return digest


def _trusted_policy(
    repository: Path,
    manifest: Mapping[str, object],
    *,
    required: bool,
) -> Mapping[str, object] | None:
    policy_path = repository.resolve() / _POLICY_RELATIVE_PATH
    if not policy_path.is_file():
        if required:
            raise ContractError("trusted functional acceptance policy is unavailable")
        return None
    try:
        raw = policy_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != _POLICY_SHA256:
            raise ContractError("trusted functional acceptance policy digest mismatch")
        policy = json.loads(raw)
    except ContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError("trusted functional acceptance policy is unreadable") from exc
    if not isinstance(policy, dict):
        raise ContractError("trusted functional acceptance policy must be an object")
    if manifest.get("standard") != policy.get("manifest_standard"):
        if required:
            raise ContractError("manifest is not bound to the trusted acceptance standard")
        return None
    return policy


def _policy_errors(manifest: Mapping[str, object], policy: Mapping[str, object]) -> list[str]:
    errors: list[str] = []
    requirements = _object_list(manifest.get("requirements")) or []
    actual_ids = [item.get("id") for item in requirements]
    expected_ids = _string_list(policy.get("required_requirement_ids")) or []
    if actual_ids != expected_ids:
        errors.append("manifest does not contain the exact required requirement ids")

    commands = _object_list(manifest.get("test_commands")) or []
    actual_commands = {
        str(item.get("id")): item for item in commands if isinstance(item.get("id"), str)
    }
    runners = _mapping(policy.get("runners")) or {}
    if set(actual_commands) != set(runners):
        errors.append("manifest runner ids do not match trusted runner policy")
    for runner_id, raw_expected in runners.items():
        expected = _mapping(raw_expected)
        actual = actual_commands.get(runner_id)
        if expected is None or actual is None:
            continue
        for field in (
            "framework",
            "minimum_passed_tests",
            "covers",
            "required_test_nodes",
        ):
            if actual.get(field) != expected.get(field):
                errors.append(f"{runner_id} does not match trusted runner policy for {field}")
    if manifest.get("internal_gate_bindings") != policy.get("internal_gate_bindings"):
        errors.append("manifest internal gate bindings do not match trusted policy")
    expected_collections = _mapping(policy.get("external_test_collections")) or {}
    external_entries = _object_list(manifest.get("external_evidence")) or []
    actual_collections = {
        str(item.get("id")): item.get("collection")
        for item in external_entries
        if isinstance(item.get("id"), str) and item.get("collection") is not None
    }
    if actual_collections != expected_collections:
        errors.append("manifest external test collections do not match trusted policy")
    bindings = _object_list(manifest.get("internal_gate_bindings"))
    if bindings is None or not bindings:
        errors.append("manifest must bind the PostgreSQL acceptance gate")
    else:
        binding = bindings[0]
        required_checks = _string_list(binding.get("required_checks"))
        if (
            len(bindings) != 1
            or binding.get("gate_id") != "TOKEN-GOV-P0-001"
            or binding.get("evidence_kind") != "postgres-acceptance"
            or binding.get("test_discovery")
            != "KB_TEST_POSTGRES_URL|KB_TEST_MIGRATION_POSTGRES_URL"
            or required_checks is None
            or len(required_checks) != len(set(required_checks))
        ):
            errors.append("manifest PostgreSQL gate binding is invalid")
    return errors


def load_manifest(path: Path) -> dict[str, object]:
    try:
        if path.stat().st_size > _MAX_EVIDENCE_BYTES:
            raise ContractError("functional acceptance manifest is too large")
        value = json.loads(path.read_text(encoding="utf-8"))
    except ContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError("functional acceptance manifest is unreadable") from exc
    if not isinstance(value, dict):
        raise ContractError("functional acceptance manifest must be a JSON object")
    return value


def _mapping(value: object) -> Mapping[str, object] | None:
    return value if isinstance(value, Mapping) else None


def _object_list(value: object) -> list[Mapping[str, object]] | None:
    if not isinstance(value, list):
        return None
    values: list[Mapping[str, object]] = []
    for item in value:
        mapped = _mapping(item)
        if mapped is None:
            return None
        values.append(mapped)
    return values


def _string_list(value: object) -> list[str] | None:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        return None
    return list(value)


def _safe_path(repository: Path, raw_path: object, *, must_exist: bool) -> Path | None:
    if not isinstance(raw_path, str) or not raw_path:
        return None
    relative = Path(raw_path)
    if relative.is_absolute() or any(part == ".." for part in relative.parts):
        return None
    if any(".env" in part.lower() for part in relative.parts):
        return None
    root = repository.resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if must_exist and not candidate.exists():
        return None
    return candidate


def _has_selection_pollution(command: Sequence[str], framework: object) -> bool:
    pytest_forbidden = {
        "-k",
        "-m",
        "--deselect",
        "--ignore",
        "--ignore-glob",
        "--lf",
        "--last-failed",
        "--ff",
        "--failed-first",
        "--sw",
        "--stepwise",
        "--collect-only",
        "--runxfail",
    }
    vitest_forbidden = {
        "-t",
        "--testNamePattern",
        "--changed",
        "--shard",
        "--related",
        "--passWithNoTests",
    }
    forbidden = pytest_forbidden if framework == "pytest" else vitest_forbidden
    prefixes = _SUPPORTED_FRAMEWORK_PREFIXES.get(str(framework), ())
    prefix = next(
        (item for item in prefixes if tuple(command[: len(item)]) == item),
        (),
    )
    arguments = command[len(prefix) :]
    return any(
        token in forbidden or any(token.startswith(f"{item}=") for item in forbidden)
        for token in arguments
    )


def _test_command_catalog(
    repository: Path,
    manifest: Mapping[str, object],
) -> tuple[dict[str, Mapping[str, object]], list[str]]:
    entries = _object_list(manifest.get("test_commands"))
    if entries is None or not entries:
        return {}, ["test_commands must be a non-empty list of objects"]
    catalog: dict[str, Mapping[str, object]] = {}
    errors: list[str] = []
    for entry in entries:
        command_id = entry.get("id")
        command = _string_list(entry.get("command"))
        covers = _string_list(entry.get("covers"))
        required_nodes = _string_list(entry.get("required_test_nodes"))
        framework = entry.get("framework")
        minimum_passed_tests = entry.get("minimum_passed_tests")
        cwd = _safe_path(repository, entry.get("cwd"), must_exist=True)
        if not isinstance(command_id, str) or not command_id:
            errors.append("test command is missing an id")
            continue
        if command_id in catalog:
            errors.append(f"duplicate test command: {command_id}")
            continue
        if (
            command is None
            or cwd is None
            or not cwd.is_dir()
            or covers is None
            or required_nodes is None
            or not isinstance(minimum_passed_tests, int)
            or isinstance(minimum_passed_tests, bool)
            or minimum_passed_tests <= 0
        ):
            errors.append(f"invalid test command: {command_id}")
            continue
        prefixes = (
            _SUPPORTED_FRAMEWORK_PREFIXES.get(framework) if isinstance(framework, str) else None
        )
        if prefixes is None or not any(
            tuple(command[: len(prefix)]) == prefix for prefix in prefixes
        ):
            errors.append(f"unsupported test framework command: {command_id}")
            continue
        if _has_selection_pollution(command, framework):
            errors.append(f"test command contains forbidden selection controls: {command_id}")
            continue
        if len(set(required_nodes)) != len(required_nodes) or not all(
            node in command for node in required_nodes
        ):
            errors.append(f"test command is missing required test nodes: {command_id}")
            continue
        selected_nodes = [token for token in command if token.startswith("tests/")]
        if selected_nodes != required_nodes:
            errors.append(f"test command does not exactly bind required test nodes: {command_id}")
            continue
        if entry.get("forbid_skips") is not True:
            errors.append(f"test command does not forbid skips: {command_id}")
            continue
        catalog[command_id] = entry
    return catalog, errors


def _runner_selects_evidence_file(
    repository: Path,
    evidence_path: Path,
    runner: Mapping[str, object],
) -> bool:
    cwd = _safe_path(repository, runner.get("cwd"), must_exist=True)
    nodes = _string_list(runner.get("required_test_nodes"))
    if cwd is None or nodes is None:
        return False
    for node in nodes:
        raw_path = node.split("::", 1)[0]
        candidate = (cwd / raw_path).resolve()
        if candidate == evidence_path.resolve():
            return True
    return False


def _validate_evidence(
    repository: Path,
    requirement_id: str,
    evidence: Mapping[str, object],
    commands: Mapping[str, Mapping[str, object]],
) -> list[str]:
    errors: list[str] = []
    kind = evidence.get("kind")
    if kind not in _ALLOWED_EVIDENCE_KINDS:
        return ["unsupported evidence kind"]
    path = _safe_path(repository, evidence.get("path"), must_exist=True)
    if path is None or not path.is_file():
        return ["unsafe evidence path or file is missing"]
    literals = _string_list(evidence.get("contains"))
    if literals is None:
        return ["evidence must declare non-empty literal checks"]
    try:
        if path.stat().st_size > _MAX_EVIDENCE_BYTES:
            return ["evidence file is too large"]
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ["evidence file is unreadable"]
    missing = [literal for literal in literals if literal not in content]
    if missing:
        errors.append("missing literal evidence")
    if kind == "automated_test":
        runner = evidence.get("runner")
        if evidence.get("status") != "active":
            errors.append("blocking requirement requires active automated test evidence")
        if not isinstance(runner, str) or runner not in commands:
            errors.append("automated test references an unknown runner")
        else:
            covers = _string_list(commands[runner].get("covers")) or []
            if requirement_id not in covers:
                errors.append("automated test runner does not cover requirement")
            if not _runner_selects_evidence_file(repository, path, commands[runner]):
                errors.append("automated test file is not bound to runner test nodes")
    return errors


def evaluate_contract(
    repository: Path,
    manifest: Mapping[str, object],
    *,
    enforce_policy: bool = True,
) -> ContractReport:
    repository = repository.resolve()
    policy: Mapping[str, object] | None = None
    try:
        policy = _trusted_policy(repository, manifest, required=enforce_policy)
        policy_errors = _policy_errors(manifest, policy) if policy is not None else []
    except ContractError as exc:
        policy_errors = [str(exc)]
    requirements = _object_list(manifest.get("requirements"))
    commands, command_errors = _test_command_catalog(repository, manifest)
    if manifest.get("schema_version") != 1 or requirements is None or not requirements:
        result = RequirementResult(
            "MANIFEST",
            "failed",
            "schema_version=1 and a non-empty requirements list are mandatory",
        )
        return ContractReport("FAIL", 0, 0, 1, (result,))

    results: list[RequirementResult] = []
    if policy_errors:
        results.append(RequirementResult("TRUSTED-POLICY", "failed", "; ".join(policy_errors)))
    seen_ids: set[str] = set()
    for requirement in requirements:
        errors = list(command_errors)
        requirement_id = requirement.get("id")
        if not isinstance(requirement_id, str) or not requirement_id:
            requirement_id = "INVALID-REQUIREMENT"
            errors.append("requirement id is missing")
        elif requirement_id in seen_ids:
            errors.append("requirement id is duplicated")
        seen_ids.add(requirement_id)

        if requirement.get("severity") not in {"P0", "P1", "P2"}:
            errors.append("severity must be P0, P1, or P2")
        blocking = requirement.get("blocking") is True
        for field in ("preconditions", "steps", "expected_results"):
            if _string_list(requirement.get(field)) is None:
                errors.append(f"{field} must be a non-empty string list")

        evidence_entries = _object_list(requirement.get("evidence"))
        if evidence_entries is None:
            errors.append("evidence must be a list of objects")
            evidence_entries = []
        kinds = {entry.get("kind") for entry in evidence_entries}
        if blocking and not kinds.intersection({"route", "source", "config", "documentation"}):
            errors.append("blocking requirement requires source evidence")
        if blocking and "automated_test" not in kinds:
            errors.append("blocking requirement requires active automated test evidence")
        for evidence in evidence_entries:
            errors.extend(_validate_evidence(repository, requirement_id, evidence, commands))

        unique_errors = list(dict.fromkeys(errors))
        results.append(
            RequirementResult(
                requirement_id=requirement_id,
                status="failed" if unique_errors else "passed",
                summary=(
                    "; ".join(unique_errors)
                    if unique_errors
                    else "all declared evidence is present"
                ),
            )
        )

    failed = sum(item.status == "failed" for item in results)
    return ContractReport(
        verdict="FAIL" if failed else "PASS",
        requirement_count=len(requirements),
        passed=len(results) - failed,
        failed=failed,
        requirements=tuple(results),
        policy_sha256=_POLICY_SHA256 if policy is not None else None,
    )


def _execute(
    command: Sequence[str],
    cwd: Path,
    timeout_seconds: int,
    *,
    node_binding: TrustedExecutableBinding | None = None,
) -> subprocess.CompletedProcess[str]:
    if tuple(command[:2]) in {("python", "-m"), ("python3", "-m")}:
        executable = sys.executable
    elif command and command[0] == "node":
        if node_binding is None:
            raise AcceptanceGateError("trusted Node executable binding is required")
        executable = verify_trusted_executable_binding(
            Path(__file__).resolve().parents[1],
            node_binding,
        )
    else:
        executable = shutil.which(command[0]) or command[0]
    return subprocess.run(  # noqa: S603
        [executable, *command[1:]],
        cwd=cwd,
        env=sanitized_test_environment(),
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        shell=False,
        timeout=timeout_seconds,
    )


def _node_statuses_from_pytest(
    report_path: Path, required_nodes: Sequence[str]
) -> tuple[list[dict[str, object]], int, int]:
    raw = read_regular_file_nofollow(report_path, maximum_bytes=_MAX_RAW_ARTIFACT_BYTES)
    root = ET.fromstring(raw)
    if root is None:
        raise ContractError("pytest JUnit report has no document element")
    cases = list(root.iter("testcase"))
    nodes: list[dict[str, object]] = []
    passed_total = 0
    skipped_total = 0
    for case in cases:
        case_failed = any(case.find(tag) is not None for tag in ("failure", "error"))
        case_skipped = case.find("skipped") is not None
        passed_total += not case_failed and not case_skipped
        skipped_total += case_skipped
    for node in required_nodes:
        raw_file, separator, raw_function = node.partition("::")
        module = raw_file.removesuffix(".py").replace("/", ".").replace("\\", ".")
        matched = []
        for case in cases:
            classname = case.get("classname", "")
            name = case.get("name", "").split("[", 1)[0]
            file_matches = classname == module or classname.startswith(f"{module}.")
            function_matches = not separator or name == raw_function
            if file_matches and function_matches:
                matched.append(case)
        skipped = sum(case.find("skipped") is not None for case in matched)
        failed = sum(
            any(case.find(tag) is not None for tag in ("failure", "error")) for case in matched
        )
        nodes.append(
            {
                "node": node,
                "status": "passed" if matched and not skipped and not failed else "failed",
                "cases": len(matched),
                "failed": failed,
                "skipped": skipped,
            }
        )
    return nodes, passed_total, skipped_total


def _node_statuses_from_vitest(
    report_path: Path, required_nodes: Sequence[str]
) -> tuple[list[dict[str, object]], int, int]:
    document = json.loads(report_path.read_text(encoding="utf-8"))
    suites = document.get("testResults") if isinstance(document, dict) else None
    if not isinstance(suites, list):
        raise ValueError("vitest report has no testResults")
    nodes: list[dict[str, object]] = []
    passed_total = 0
    skipped_total = 0
    normalized_suites: list[tuple[str, list[Mapping[str, object]]]] = []
    for suite in suites:
        if not isinstance(suite, Mapping):
            continue
        name = str(suite.get("name", "")).replace("\\", "/")
        assertions = suite.get("assertionResults")
        mapped = (
            [item for item in assertions if isinstance(item, Mapping)]
            if isinstance(assertions, list)
            else []
        )
        normalized_suites.append((name, mapped))
        for assertion in mapped:
            status = assertion.get("status")
            passed_total += status == "passed"
            skipped_total += status in {"pending", "skipped", "todo"}
    for node in required_nodes:
        normalized = node.replace("\\", "/")
        assertions = [
            assertion
            for name, suite_assertions in normalized_suites
            if name.endswith(normalized)
            for assertion in suite_assertions
        ]
        failed = sum(item.get("status") != "passed" for item in assertions)
        skipped = sum(item.get("status") in {"pending", "skipped", "todo"} for item in assertions)
        nodes.append(
            {
                "node": node,
                "status": "passed" if assertions and not failed else "failed",
                "cases": len(assertions),
                "failed": failed,
                "skipped": skipped,
            }
        )
    return nodes, passed_total, skipped_total


def _build_vitest_collection_command(command: Sequence[str], report_path: Path) -> tuple[str, ...]:
    selected_files = tuple(token for token in command if token.startswith("tests/"))
    if (
        tuple(command[:3]) != ("node", "node_modules/vitest/vitest.mjs", "run")
        or not selected_files
    ):
        raise AcceptanceGateError("vitest collection command is not safely bound")
    return (
        "node",
        "node_modules/vitest/vitest.mjs",
        "list",
        *selected_files,
        f"--json={report_path}",
        "--allowOnly=false",
    )


def _relative_machine_test_path(cwd: Path, raw_path: object) -> str:
    if not isinstance(raw_path, str) or not raw_path:
        raise AcceptanceGateError("machine test result has no file path")
    candidate = Path(raw_path).resolve()
    try:
        return candidate.relative_to(cwd.resolve()).as_posix()
    except ValueError as exc:
        raise AcceptanceGateError("machine test result escapes its runner directory") from exc


def _vitest_collected_nodes(report_path: Path, cwd: Path) -> tuple[str, ...]:
    try:
        document = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AcceptanceGateError("vitest collection report is invalid") from exc
    if not isinstance(document, list) or not document:
        raise AcceptanceGateError("vitest collection did not report tests")
    nodes: list[str] = []
    for item in document:
        if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
            raise AcceptanceGateError("vitest collection report has an invalid test")
        relative = _relative_machine_test_path(cwd, item.get("file"))
        nodes.append(f"{relative}::{item['name']}")
    if len(nodes) != len(set(nodes)):
        raise AcceptanceGateError("vitest collection contains duplicate tests")
    return tuple(nodes)


def _vitest_machine_evidence(
    report_path: Path, cwd: Path, expected_nodes: Sequence[str]
) -> VitestMachineEvidence:
    try:
        document = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AcceptanceGateError("vitest result report is invalid") from exc
    suites = document.get("testResults") if isinstance(document, Mapping) else None
    if not isinstance(suites, list):
        raise AcceptanceGateError("vitest result report has no testResults")
    actual_nodes: list[str] = []
    passed = failed = skipped = 0
    for suite in suites:
        if not isinstance(suite, Mapping):
            raise AcceptanceGateError("vitest result suite is invalid")
        relative = _relative_machine_test_path(cwd, suite.get("name"))
        assertions = suite.get("assertionResults")
        if not isinstance(assertions, list):
            raise AcceptanceGateError("vitest result suite has no assertions")
        for assertion in assertions:
            if not isinstance(assertion, Mapping):
                raise AcceptanceGateError("vitest assertion is invalid")
            ancestors = assertion.get("ancestorTitles")
            title = assertion.get("title")
            status = assertion.get("status")
            if (
                not isinstance(ancestors, list)
                or not all(isinstance(item, str) and item for item in ancestors)
                or not isinstance(title, str)
                or not title
            ):
                raise AcceptanceGateError("vitest assertion identity is invalid")
            name = " > ".join((*ancestors, title))
            actual_nodes.append(f"{relative}::{name}")
            passed += status == "passed"
            skipped += status in {"pending", "skipped", "todo"}
            failed += status not in {"passed", "pending", "skipped", "todo"}

    expected = tuple(expected_nodes)
    expected_set = set(expected)
    actual_set = set(actual_nodes)
    if len(expected) != len(expected_set):
        raise AcceptanceGateError("expected vitest collection contains duplicate tests")
    missing = tuple(sorted(expected_set - actual_set))
    unexpected_nodes = tuple(sorted(actual_set - expected_set))
    duplicates = len(actual_nodes) - len(actual_set)
    return VitestMachineEvidence(
        collected=len(expected),
        executed=len(actual_nodes),
        passed=passed,
        failed=failed,
        skipped=skipped,
        deselected=len(missing),
        unexpected=len(unexpected_nodes) + duplicates,
        node_ids=tuple(actual_nodes),
        missing_node_ids=missing,
        unexpected_node_ids=unexpected_nodes,
        test_files=tuple(sorted({node.split("::", 1)[0] for node in actual_nodes})),
    )


def _runner_artifact_directory(repository: Path, identity: GateIdentity) -> Path:
    root = Path(tempfile.gettempdir()) / "heyi-functional-acceptance"
    directory: Path = Path(
        root
        / identity.content_fingerprint
        / str(identity.run_nonce)
        / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    )
    directory.mkdir(parents=True, exist_ok=False)
    directory.chmod(0o700)
    metadata = directory.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (os.name == "posix" and (metadata.st_mode & 0o777) != 0o700)
    ):
        raise AcceptanceGateError("functional acceptance artifact directory is not private")
    return directory


def _dependency_fingerprint(repository: Path, framework: str) -> str:
    candidates = (
        (repository / "uv.lock", repository / "pyproject.toml")
        if framework == "pytest"
        else (repository / "web/package-lock.json", repository / "web/package.json")
    )
    digest = hashlib.sha256()
    for path in candidates:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def run_test_commands(
    repository: Path,
    manifest: Mapping[str, object],
    *,
    executor: TestExecutor = _execute,
    node_binding: TrustedExecutableBinding | None = None,
    enforce_policy: bool = True,
    identity: GateIdentity | None = None,
    expected_git_head: str | None = None,
    expected_content_fingerprint: str | None = None,
    run_nonce: str | None = None,
) -> tuple[TestCommandResult, ...]:
    repository = repository.resolve()
    try:
        policy = _trusted_policy(repository, manifest, required=enforce_policy)
        policy_errors = _policy_errors(manifest, policy) if policy is not None else []
    except ContractError as exc:
        policy_errors = [str(exc)]
    catalog, errors = _test_command_catalog(repository, manifest)
    errors.extend(policy_errors)
    if errors:
        return (TestCommandResult("MANIFEST", "failed", 0, "; ".join(errors)),)
    try:
        if identity is None:
            identity = start_gate_identity(
                repository,
                expected_git_head=expected_git_head,
                expected_content_fingerprint=expected_content_fingerprint,
                run_nonce=run_nonce,
            )
        else:
            assert_gate_identity(repository, identity, stage="start")
        artifact_directory = _runner_artifact_directory(repository, identity)
    except (AcceptanceGateError, OSError, RuntimeError, UnicodeError) as exc:
        return (TestCommandResult("MANIFEST", "failed", 0, f"cannot bind run identity: {exc}"),)
    effective_executor = executor
    if executor is _execute:

        def effective_executor(
            command: Sequence[str], cwd: Path, timeout_seconds: int
        ) -> subprocess.CompletedProcess[str]:
            return _execute(
                command,
                cwd,
                timeout_seconds,
                node_binding=node_binding,
            )

    results: list[TestCommandResult] = []
    for command_id, entry in catalog.items():
        command = _string_list(entry.get("command")) or []
        cwd = _safe_path(repository, entry.get("cwd"), must_exist=True)
        timeout = entry.get("timeout_seconds", 600)
        minimum_passed_tests = entry.get("minimum_passed_tests")
        framework = entry.get("framework")
        required_nodes = _string_list(entry.get("required_test_nodes")) or []
        if cwd is None or not isinstance(timeout, int) or timeout <= 0:
            results.append(TestCommandResult(command_id, "failed", 0, "invalid command contract"))
            continue
        raw_report = artifact_directory / (
            f"{command_id}.xml" if framework == "pytest" else f"{command_id}.json"
        )
        collection_report = artifact_directory / f"{command_id}.collection.json"
        started_at = datetime.now(UTC)
        started_monotonic = time.monotonic()
        try:
            if framework == "pytest":
                reserve_machine_report(raw_report)
                collection_command = build_pytest_collection_command(command)
            elif framework == "vitest":
                reserve_machine_report(collection_report)
                reserve_machine_report(raw_report)
                collection_command = _build_vitest_collection_command(command, collection_report)
            else:
                raise AcceptanceGateError("unsupported machine report framework")
            collection = effective_executor(collection_command, cwd, timeout)
            if collection.returncode != 0:
                raise AcceptanceGateError(f"test collection exited {collection.returncode}")
            if framework == "pytest":
                expected_cases = parse_pytest_collection(
                    "\n".join((collection.stdout, collection.stderr))
                )
                machine_command = build_pytest_execution_command(command, raw_report)
            else:
                expected_cases = _vitest_collected_nodes(collection_report, cwd)
                machine_command = (
                    *command,
                    "--reporter=json",
                    f"--outputFile={raw_report}",
                    "--allowOnly=false",
                )
            assert_gate_identity(repository, identity)
            completed = effective_executor(machine_command, cwd, timeout)
        except AcceptanceGateError as exc:
            results.append(
                TestCommandResult(
                    command_id,
                    "failed",
                    0,
                    f"machine-readable per-node report is invalid: {exc}",
                )
            )
            continue
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            results.append(
                TestCommandResult(command_id, "failed", 0, f"test command unavailable: {exc}")
            )
            continue
        finished_at = datetime.now(UTC)
        duration_ms = round((time.monotonic() - started_monotonic) * 1000)
        machine_evidence: PytestJUnitEvidence | VitestMachineEvidence
        try:
            if not raw_report.is_file() or raw_report.stat().st_size <= 0:
                raise ValueError("machine report missing")
            if raw_report.stat().st_size > _MAX_RAW_ARTIFACT_BYTES:
                raise ValueError("machine report is too large")
            if framework == "pytest":
                machine_evidence = parse_pytest_junit(raw_report, expected_cases)
                node_results, passed_tests, skipped_tests = _node_statuses_from_pytest(
                    raw_report, required_nodes
                )
            elif framework == "vitest":
                machine_evidence = _vitest_machine_evidence(raw_report, cwd, expected_cases)
                node_results, passed_tests, skipped_tests = _node_statuses_from_vitest(
                    raw_report, required_nodes
                )
            else:
                raise ValueError("unsupported machine report framework")
            if passed_tests != machine_evidence.passed:
                raise ValueError("machine report pass totals disagree")
            assert_gate_identity(repository, identity)
        except (
            AcceptanceGateError,
            OSError,
            UnicodeError,
            ValueError,
            SyntaxError,
            DefusedXmlException,
            json.JSONDecodeError,
        ) as exc:
            results.append(
                TestCommandResult(
                    command_id,
                    "failed",
                    0,
                    f"machine-readable per-node report is invalid: {exc}",
                )
            )
            continue
        raw_hash = _sha256_file(raw_report)
        if (
            isinstance(machine_evidence, PytestJUnitEvidence)
            and raw_hash != machine_evidence.sha256
        ):
            results.append(
                TestCommandResult(
                    command_id,
                    "failed",
                    0,
                    "machine-readable report changed after verification",
                )
            )
            continue
        ledger: dict[str, object] = {
            "schema_version": 2,
            "policy_sha256": _POLICY_SHA256 if policy is not None else None,
            "command_id": command_id,
            "framework": framework,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_ms": duration_ms,
            "exit_code": completed.returncode,
            "environment": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
                "dependency_lock_sha256": _dependency_fingerprint(repository, str(framework)),
            },
            "target": identity.target(),
            "raw_result": {
                "path": str(raw_report),
                "sha256": raw_hash,
                "bytes": raw_report.stat().st_size,
            },
            "passed_tests": passed_tests,
            "skipped_tests": skipped_tests,
            "machine_execution": (
                machine_evidence.as_dict(path=str(raw_report))
                if isinstance(machine_evidence, PytestJUnitEvidence)
                else machine_evidence.as_dict()
            ),
            "required_nodes": node_results,
        }
        result_hash = hashlib.sha256(
            json.dumps(ledger, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        ledger["result_hash"] = result_hash
        ledger_path = artifact_directory / f"{command_id}.acceptance.json"
        atomic_write_text(
            ledger_path,
            json.dumps(ledger, ensure_ascii=False, indent=2) + "\n",
        )
        if _sha256_file(raw_report) != raw_hash:
            results.append(
                TestCommandResult(
                    command_id,
                    "failed",
                    passed_tests,
                    "machine-readable report changed while writing its ledger",
                )
            )
            continue
        ledger_hash = _sha256_file(ledger_path)
        all_nodes_passed = all(item["status"] == "passed" for item in node_results)
        if completed.returncode != 0:
            results.append(
                TestCommandResult(
                    command_id,
                    "failed",
                    passed_tests,
                    f"test command exited {completed.returncode}",
                )
            )
        elif not machine_evidence.is_success:
            results.append(
                TestCommandResult(
                    command_id,
                    "failed",
                    passed_tests,
                    "critical test command did not execute its exact collected test set",
                    str(ledger_path),
                    ledger_hash,
                    result_hash,
                    len(machine_evidence.node_ids),
                )
            )
        elif not all_nodes_passed:
            results.append(
                TestCommandResult(
                    command_id,
                    "failed",
                    passed_tests,
                    "one or more required test nodes did not execute and pass",
                    str(ledger_path),
                    ledger_hash,
                    result_hash,
                    sum(item["status"] == "passed" for item in node_results),
                )
            )
        elif (
            not isinstance(minimum_passed_tests, int)
            or isinstance(minimum_passed_tests, bool)
            or passed_tests < minimum_passed_tests
        ):
            expected = minimum_passed_tests if isinstance(minimum_passed_tests, int) else 1
            results.append(
                TestCommandResult(
                    command_id,
                    "failed",
                    passed_tests,
                    f"test command reported fewer than minimum {expected} passed tests",
                    str(ledger_path),
                    ledger_hash,
                    result_hash,
                    len(node_results),
                )
            )
        else:
            results.append(
                TestCommandResult(
                    command_id,
                    "passed",
                    passed_tests,
                    f"{passed_tests} tests passed",
                    str(ledger_path),
                    ledger_hash,
                    result_hash,
                    len(node_results),
                )
            )
    try:
        assert_gate_identity(repository, identity)
    except AcceptanceGateError as exc:
        results.append(TestCommandResult("IDENTITY", "failed", 0, str(exc)))
    return tuple(results)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_evidence(path: Path, payload: Mapping[str, object]) -> None:
    write_json_evidence(path, payload)


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _raw_artifact_path(evidence_path: Path, raw_path: object) -> Path | None:
    if not isinstance(raw_path, str) or not raw_path:
        return None
    relative = Path(raw_path)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        return None
    if any(".env" in part.lower() for part in relative.parts):
        return None
    root = evidence_path.parent.resolve()
    unresolved = root
    for part in relative.parts:
        unresolved /= part
        if unresolved.is_symlink():
            return None
    try:
        candidate = unresolved.resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, ValueError):
        return None
    return candidate if candidate.is_file() else None


def _chain_digest(document: Mapping[str, object]) -> str:
    bound = {
        key: document.get(key)
        for key in (
            "schema_version",
            "evidence_id",
            "status",
            "collector",
            "target",
            "collected_at",
            "artifacts",
            "checks",
        )
    }
    encoded = json.dumps(
        bound,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _signature_payload(
    document: Mapping[str, object],
    *,
    key_id: str,
    challenge_id: str,
    challenge_nonce: str,
) -> bytes:
    payload = {
        "evidence_sha256": _chain_digest(document),
        "key_id": key_id,
        "challenge_id": challenge_id,
        "challenge_nonce": challenge_nonce,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _consume_challenge_once(challenge_path: Path) -> bool:
    """Durably consume a challenge without replacing an existing replay marker.

    The hard-link + directory-fsync sequence is intentionally recoverable.  If
    the process dies after the link is durable but before the issued name is
    removed, the ``.consumed`` marker still makes the challenge unusable on the
    next verifier process.
    """

    challenge_name = challenge_path.name
    if not challenge_name.endswith(".json"):
        return False
    consumed_name = f"{challenge_name[:-5]}.consumed"
    directory_flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    nofollow = int(getattr(os, "O_NOFOLLOW", 0))
    try:
        directory_fd = os.open(challenge_path.parent, directory_flags | nofollow)
    except OSError:
        return False
    linked = False
    try:
        try:
            os.link(
                challenge_name,
                consumed_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            linked = True
            os.fsync(directory_fd)
            os.unlink(challenge_name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except OSError:
            # Never remove a durable marker on failure: it is the fail-closed
            # crash-recovery record preventing cross-process replay.
            return False
    finally:
        os.close(directory_fd)
    return linked


def _validate_external_provenance(
    repository: Path,
    evidence_path: Path,
    contract: Mapping[str, object],
    document: Mapping[str, object],
    *,
    policy: Mapping[str, object] | None,
    trust_context: ExternalTrustContext | None,
    signature_payload_builder: Callable[..., bytes] = _signature_payload,
) -> bool:
    expected_collector = _mapping(contract.get("collector"))
    collector = _mapping(document.get("collector"))
    collector_id = expected_collector.get("id") if expected_collector else None
    collector_version = expected_collector.get("version") if expected_collector else None
    max_age_seconds = contract.get("max_age_seconds")
    if (
        contract.get("evidence_schema_version") != 2
        or expected_collector is None
        or collector != expected_collector
        or not isinstance(collector_id, str)
        or not collector_id
        or not isinstance(collector_version, str)
        or _SEMVER_PATTERN.fullmatch(collector_version) is None
        or not isinstance(max_age_seconds, int)
        or isinstance(max_age_seconds, bool)
        or max_age_seconds <= 0
        or max_age_seconds > 7 * 24 * 60 * 60
        or document.get("schema_version") != 2
        or document.get("evidence_id") != contract.get("id")
        or document.get("status") != "complete"
    ):
        return False

    collected_at = _parse_timestamp(document.get("collected_at"))
    now = datetime.now(UTC)
    if (
        collected_at is None
        or collected_at > now + _MAX_CLOCK_SKEW
        or now - collected_at > timedelta(seconds=max_age_seconds)
    ):
        return False

    try:
        identity = collect_worktree_evidence(repository)
    except (OSError, RuntimeError, UnicodeError):
        return False
    target = _mapping(document.get("target"))
    if (
        target is None
        or target.get("git_head") != identity.git_head
        or target.get("content_fingerprint") != identity.content_fingerprint
        or not isinstance(target.get("run_id"), str)
        or _EXTERNAL_RUN_ID_PATTERN.fullmatch(str(target.get("run_id"))) is None
        or set(target) != {"git_head", "content_fingerprint", "run_id"}
    ):
        return False

    artifacts = _object_list(document.get("artifacts"))
    if artifacts is None or not artifacts:
        return False
    artifact_ids: set[str] = set()
    for artifact in artifacts:
        artifact_id = artifact.get("id")
        expected_hash = artifact.get("sha256")
        expected_size = artifact.get("bytes")
        artifact_path = _raw_artifact_path(evidence_path, artifact.get("path"))
        if (
            not isinstance(artifact_id, str)
            or not artifact_id
            or artifact_id in artifact_ids
            or not isinstance(expected_hash, str)
            or _SHA256_PATTERN.fullmatch(expected_hash) is None
            or not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
            or expected_size > _MAX_RAW_ARTIFACT_BYTES
            or artifact_path is None
            or artifact_path.stat().st_size != expected_size
            or _sha256_file(artifact_path) != expected_hash
        ):
            return False
        artifact_ids.add(artifact_id)

    required_checks = _string_list(contract.get("required_checks"))
    checks = _mapping(document.get("checks"))
    if required_checks is None or checks is None:
        return False
    for check_name in required_checks:
        check = _mapping(checks.get(check_name))
        references = _string_list(check.get("artifact_ids")) if check else None
        if (
            check is None
            or check.get("status") != "passed"
            or references is None
            or not set(references).issubset(artifact_ids)
        ):
            return False

    if trust_context is None:
        return False
    attestation = _mapping(document.get("attestation"))
    if attestation is None or attestation.get("type") != "ed25519-challenge-v1":
        return False
    key_id = attestation.get("key_id")
    challenge_id = attestation.get("challenge_id")
    challenge_nonce = attestation.get("challenge_nonce")
    encoded_signature = attestation.get("signature")
    if not all(
        isinstance(value, str) and value
        for value in (key_id, challenge_id, challenge_nonce, encoded_signature)
    ):
        return False
    key_id = cast(str, key_id)
    challenge_id = cast(str, challenge_id)
    challenge_nonce = cast(str, challenge_nonce)
    encoded_signature = cast(str, encoded_signature)

    if policy is not None:
        collectors = _mapping(policy.get("external_collectors"))
        evidence_id = document.get("evidence_id")
        expected = (
            _mapping(collectors.get(evidence_id))
            if collectors is not None and isinstance(evidence_id, str)
            else None
        )
        if (
            expected is None
            or expected.get("collector_id") != collector_id
            or expected.get("key_id") != key_id
        ):
            return False

    challenge = trust_context.challenges.get(challenge_id)
    if challenge is None or challenge_id in trust_context.consumed_challenges:
        return False
    target_run_id = target.get("run_id") if target is not None else None
    challenge_target = _mapping(challenge.get("target"))
    issued_at = _parse_timestamp(challenge.get("issued_at"))
    expires_at = _parse_timestamp(challenge.get("expires_at"))
    if (
        challenge.get("status") != "issued"
        or challenge.get("evidence_id") != document.get("evidence_id")
        or challenge.get("nonce") != challenge_nonce
        or not isinstance(target_run_id, str)
        or _EXTERNAL_RUN_ID_PATTERN.fullmatch(target_run_id) is None
        or challenge_target != target
        or issued_at is None
        or expires_at is None
        or issued_at > now + _MAX_CLOCK_SKEW
        or expires_at <= now
        or expires_at - issued_at > timedelta(hours=24)
    ):
        return False
    public_key = trust_context.public_keys.get((collector_id, key_id))
    if public_key is None or len(public_key) != 32:
        return False
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
        if len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            signature_payload_builder(
                document,
                key_id=key_id,
                challenge_id=challenge_id,
                challenge_nonce=challenge_nonce,
            ),
        )
    except (ValueError, binascii.Error, InvalidSignature):
        return False
    challenge_path = trust_context.challenge_paths.get(challenge_id)
    if challenge_path is not None and not _consume_challenge_once(challenge_path):
        return False
    trust_context.consumed_challenges.add(challenge_id)
    return True


def evaluate_external_evidence(
    repository: Path,
    manifest: Mapping[str, object],
    *,
    trust_context: ExternalTrustContext | None = None,
    enforce_policy: bool = True,
) -> ExternalEvidenceReport:
    try:
        policy = _trusted_policy(repository.resolve(), manifest, required=enforce_policy)
    except ContractError as exc:
        result = ExternalEvidenceResult("TRUSTED-POLICY", "blocked", str(exc))
        return ExternalEvidenceReport("BLOCKED", (result,))
    entries = _object_list(manifest.get("external_evidence"))
    if entries is None or not entries:
        result = ExternalEvidenceResult(
            "EXTERNAL-MANIFEST",
            "blocked",
            "external_evidence must be a non-empty list of objects",
        )
        return ExternalEvidenceReport("BLOCKED", (result,))
    if policy is not None:
        expected_ids = _string_list(policy.get("required_external_evidence_ids")) or []
        actual_ids = [entry.get("id") for entry in entries]
        if actual_ids != expected_ids:
            result = ExternalEvidenceResult(
                "TRUSTED-POLICY",
                "blocked",
                "manifest does not contain the exact required external evidence ids",
            )
            return ExternalEvidenceReport("BLOCKED", (result,))
    results: list[ExternalEvidenceResult] = []
    for entry in entries:
        evidence_id = entry.get("id")
        if not isinstance(evidence_id, str) or not evidence_id:
            evidence_id = "INVALID-EXTERNAL-EVIDENCE"
        path = _safe_path(repository, entry.get("path"), must_exist=True)
        if path is None or not path.is_file():
            results.append(
                ExternalEvidenceResult(
                    evidence_id,
                    "blocked",
                    "required external evidence is not available",
                )
            )
            continue
        try:
            if path.stat().st_size > _MAX_EVIDENCE_BYTES:
                raise ValueError
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            results.append(
                ExternalEvidenceResult(evidence_id, "blocked", "external evidence is invalid")
            )
            continue
        if not isinstance(document, dict):
            results.append(
                ExternalEvidenceResult(
                    evidence_id,
                    "blocked",
                    "external evidence contract is invalid",
                )
            )
            continue
        if not _validate_external_provenance(
            repository.resolve(),
            path,
            entry,
            document,
            policy=policy,
            trust_context=trust_context,
        ):
            results.append(
                ExternalEvidenceResult(
                    evidence_id,
                    "blocked",
                    "external evidence provenance is incomplete or invalid",
                )
            )
            continue
        results.append(
            ExternalEvidenceResult(
                evidence_id,
                "passed",
                "all external checks and provenance passed",
            )
        )
    blocked = any(item.status == "blocked" for item in results)
    return ExternalEvidenceReport("BLOCKED" if blocked else "PASS", tuple(results))


def _payload(
    contract: ContractReport,
    external: ExternalEvidenceReport,
    tests: Sequence[TestCommandResult],
    profile: FunctionalProfile,
) -> dict[str, object]:
    tests_executed = bool(tests)
    tests_pass = all(item.status == "passed" for item in tests)
    source_verdict: SourceVerdict
    if contract.verdict == "FAIL" or (tests_executed and not tests_pass):
        source_verdict = "FAIL"
    elif not tests_executed:
        source_verdict = "UNVERIFIED"
    else:
        source_verdict = "PASS"

    runtime_verdict: RuntimeFunctionalVerdict
    if source_verdict == "FAIL":
        runtime_verdict = "FAIL"
    elif source_verdict != "PASS" or external.verdict != "PASS":
        runtime_verdict = "BLOCKED"
    else:
        runtime_verdict = "PASS"
    selected_verdict = source_verdict if profile == "source" else runtime_verdict
    return {
        "schema_version": 1,
        "profile": profile,
        "source_verdict": source_verdict,
        "runtime_functional_verdict": runtime_verdict,
        "verdict": selected_verdict,
        "contract": asdict(contract),
        "test_commands": [asdict(item) for item in tests],
        "external_evidence": asdict(external),
    }


def main(argv: Sequence[str] | None = None) -> int:
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Run fail-closed functional acceptance checks")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=repository / "docs/functional_acceptance_manifest.json",
    )
    parser.add_argument(
        "--profile",
        choices=("source", "runtime-functional"),
        default="source",
    )
    parser.add_argument("--run-tests", action="store_true")
    parser.add_argument("--node-executable", type=Path)
    parser.add_argument("--node-executable-sha256")
    parser.add_argument("--node-executable-require-root-owner", action="store_true")
    parser.add_argument(
        "--trust-store",
        type=Path,
        help="root-owned collector public-key JSON outside the repository",
    )
    parser.add_argument(
        "--challenge-store",
        type=Path,
        help="root-owned 0700 directory containing one-time challenge JSON files",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--evidence-file",
        type=Path,
        help="write nonce-bound functional acceptance evidence to this JSON path",
    )
    add_identity_arguments(parser)
    arguments = parser.parse_args(argv)
    try:
        identity = start_gate_identity(
            repository,
            expected_git_head=arguments.expected_git_head,
            expected_content_fingerprint=arguments.expected_content_fingerprint,
            run_nonce=arguments.acceptance_run_nonce,
        )
    except AcceptanceGateError as exc:
        print(
            json.dumps(
                {
                    "schema_version": 2,
                    "profile": arguments.profile,
                    "source_verdict": "FAIL",
                    "runtime_functional_verdict": "FAIL",
                    "verdict": "FAIL",
                    "error": str(exc),
                },
                ensure_ascii=True,
            )
        )
        return 1
    try:
        manifest = load_manifest(arguments.manifest)
    except ContractError as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "profile": arguments.profile,
                    "source_verdict": "FAIL",
                    "runtime_functional_verdict": "FAIL",
                    "verdict": "FAIL",
                    "error": str(exc),
                },
                ensure_ascii=True,
            )
        )
        return 1
    node_binding: TrustedExecutableBinding | None = None
    node_binding_error: str | None = None
    if arguments.run_tests:
        supplied_binding = (
            arguments.node_executable is not None,
            arguments.node_executable_sha256 is not None,
        )
        try:
            if (any(supplied_binding) or arguments.node_executable_require_root_owner) and not all(
                supplied_binding
            ):
                raise AcceptanceGateError("trusted Node executable binding is incomplete")
            if all(supplied_binding):
                node_binding = TrustedExecutableBinding(
                    path=str(arguments.node_executable),
                    sha256=arguments.node_executable_sha256,
                    require_root_owner=arguments.node_executable_require_root_owner,
                )
                verify_trusted_executable_binding(repository, node_binding)
            else:
                node_binding = bind_trusted_executable(
                    repository,
                    "node",
                    search_path=os.environ.get("PATH"),
                )
        except AcceptanceGateError as exc:
            node_binding_error = str(exc)
    contract = evaluate_contract(repository, manifest)
    trust_context: ExternalTrustContext | None = None
    trust_error: str | None = None
    if arguments.trust_store is not None or arguments.challenge_store is not None:
        if arguments.trust_store is None or arguments.challenge_store is None:
            trust_error = "both --trust-store and --challenge-store are required"
        else:
            try:
                trust_context = load_external_trust_context(
                    repository, arguments.trust_store, arguments.challenge_store
                )
            except ContractError as exc:
                trust_error = str(exc)
    external = (
        ExternalEvidenceReport(
            "BLOCKED", (ExternalEvidenceResult("TRUST-STORE", "blocked", trust_error),)
        )
        if trust_error is not None
        else evaluate_external_evidence(repository, manifest, trust_context=trust_context)
    )
    tests: tuple[TestCommandResult, ...]
    if node_binding_error is not None:
        tests = (
            TestCommandResult(
                "frontend-functional",
                "failed",
                0,
                f"trusted Node executable unavailable: {node_binding_error}",
            ),
        )
    else:
        tests = (
            run_test_commands(
                repository,
                manifest,
                identity=identity,
                node_binding=node_binding,
            )
            if arguments.run_tests
            else ()
        )
    payload = _payload(contract, external, tests, arguments.profile)
    try:
        assert_gate_identity(repository, identity)
    except AcceptanceGateError as exc:
        payload["source_verdict"] = "FAIL"
        payload["runtime_functional_verdict"] = "FAIL"
        payload["verdict"] = "FAIL"
        payload["identity_error"] = str(exc)
    payload["schema_version"] = 2
    payload["kind"] = "functional-acceptance"
    payload["target"] = identity.target()
    payload["status"] = "complete" if payload["verdict"] == "PASS" else "failed"
    payload["policy_status"] = "passed" if payload["verdict"] == "PASS" else "failed"
    if arguments.evidence_file is not None:
        try:
            _write_json_evidence(arguments.evidence_file, payload)
            assert_gate_identity(repository, identity)
        except (AcceptanceGateError, OSError, UnicodeError) as exc:
            payload["source_verdict"] = "FAIL"
            payload["runtime_functional_verdict"] = "FAIL"
            payload["verdict"] = "FAIL"
            payload["status"] = "failed"
            payload["policy_status"] = "failed"
            payload["evidence_error"] = str(exc)
            with suppress(AcceptanceGateError, OSError, UnicodeError):
                _write_json_evidence(arguments.evidence_file, payload)
    if arguments.json:
        print(json.dumps(payload, ensure_ascii=True, indent=2))
    else:
        print(
            f"source_verdict={payload['source_verdict']} "
            f"requirements={contract.passed}/{contract.requirement_count}"
        )
        for test_result in tests:
            print(f"{test_result.command_id}: {test_result.status} ({test_result.summary})")
        print(f"external_evidence={external.verdict}")
        for external_result in external.results:
            print(
                f"{external_result.evidence_id}: {external_result.status} "
                f"({external_result.summary})"
            )
        print(f"runtime_functional_verdict={payload['runtime_functional_verdict']}")
        print(f"verdict={payload['verdict']}")
    if payload["verdict"] == "PASS":
        return 0
    if payload["verdict"] == "FAIL":
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
