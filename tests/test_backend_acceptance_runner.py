from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path

from scripts.acceptance_gate import GateIdentity, discover_postgres_test_files
from scripts.backend_acceptance import (
    POSTGRES_MAPPED_TESTS,
    backend_result_passed,
    build_backend_command,
    postgres_evidence_closes_mapping,
)
from scripts.postgres_acceptance import (
    POSTGRES_BUSINESS_CHECK_NODES,
    postgres_business_checks_from_nodes,
)

REPOSITORY = Path(__file__).resolve().parents[1]


def _representative_postgres_nodes() -> tuple[str, ...]:
    nodes = list(
        dict.fromkeys(
            selector
            for selectors in POSTGRES_BUSINESS_CHECK_NODES.values()
            for selector in selectors
        )
    )
    for test_file in discover_postgres_test_files(REPOSITORY):
        if not any(node.startswith(f"{test_file}::") for node in nodes):
            nodes.append(f"{test_file}::test_acceptance_mapping_placeholder")
    return tuple(nodes)


def _write_junit(path: Path, nodes: tuple[str, ...]) -> tuple[str, int]:
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite", tests=str(len(nodes)))
    for node in nodes:
        raw_file, *parts = node.split("::")
        module = raw_file.removesuffix(".py").replace("/", ".")
        classname = ".".join((module, *parts[:-1]))
        ET.SubElement(suite, "testcase", classname=classname, name=parts[-1])
    path.parent.mkdir(parents=True)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _postgres_evidence(tmp_path: Path) -> tuple[dict[str, object], Path, GateIdentity]:
    evidence_path = tmp_path / "postgres.json"
    junit_path = tmp_path / "raw/postgres.junit.xml"
    nodes = _representative_postgres_nodes()
    digest, size = _write_junit(junit_path, nodes)
    identity = GateIdentity("a" * 40, "b" * 64, "c" * 32)
    document: dict[str, object] = {
        "schema_version": 2,
        "kind": "postgres-acceptance",
        "status": "complete",
        "policy_status": "passed",
        "target": identity.target(),
        "checks": postgres_business_checks_from_nodes(nodes),
        "pytest": {
            "path": "raw/postgres.junit.xml",
            "sha256": digest,
            "bytes": size,
            "collected": len(nodes),
            "executed": len(nodes),
            "passed": len(nodes),
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
            "deselected": 0,
            "unexpected": 0,
            "node_ids": list(nodes),
            "missing_node_ids": [],
            "unexpected_node_ids": [],
            "test_files": list(discover_postgres_test_files(REPOSITORY)),
        },
    }
    evidence_path.write_text("{}", encoding="utf-8")
    return document, evidence_path, identity


def test_backend_acceptance_runner_exists() -> None:
    assert (REPOSITORY / "scripts/backend_acceptance.py").is_file()


def test_backend_command_excludes_exactly_the_dynamically_discovered_postgres_tests() -> None:
    command = build_backend_command()

    assert command[:3] == ("uv", "run", "pytest")
    assert discover_postgres_test_files(REPOSITORY) == POSTGRES_MAPPED_TESTS
    ignored = tuple(
        item.removeprefix("--ignore=") for item in command if item.startswith("--ignore=")
    )
    assert ignored == POSTGRES_MAPPED_TESTS
    assert "--cov=app" in command
    assert "--cov-fail-under=80" in command
    assert "--runxfail" not in command
    assert "-rA" in command


def test_backend_gate_rejects_every_non_pass_summary() -> None:
    assert backend_result_passed(returncode=0, output="279 passed") is True
    for output in (
        "278 passed, 1 skipped",
        "278 passed, 1 deselected",
        "278 passed, 1 xfailed",
        "278 passed, 1 xpassed",
        "278 passed, 1 error",
    ):
        assert backend_result_passed(returncode=0, output=output) is False
    assert backend_result_passed(returncode=1, output="1 failed") is False


def test_backend_mapping_requires_exact_nodes_artifact_and_identity(tmp_path: Path) -> None:
    document, evidence_path, identity = _postgres_evidence(tmp_path)
    expected_nodes = _representative_postgres_nodes()

    assert postgres_evidence_closes_mapping(
        document,
        repository=REPOSITORY,
        evidence_path=evidence_path,
        identity=identity,
        expected_nodes=expected_nodes,
    )
    assert not postgres_evidence_closes_mapping(
        document,
        repository=REPOSITORY,
        evidence_path=evidence_path,
        identity=identity,
        expected_nodes=expected_nodes[:-1],
    )

    wrong_nonce = GateIdentity(identity.git_head, identity.content_fingerprint, "d" * 32)
    assert not postgres_evidence_closes_mapping(
        document,
        repository=REPOSITORY,
        evidence_path=evidence_path,
        identity=wrong_nonce,
        expected_nodes=expected_nodes,
    )

    pytest_evidence = document["pytest"]
    assert isinstance(pytest_evidence, dict)
    pytest_evidence["deselected"] = 1
    assert not postgres_evidence_closes_mapping(
        document,
        repository=REPOSITORY,
        evidence_path=evidence_path,
        identity=identity,
        expected_nodes=expected_nodes,
    )
    pytest_evidence["deselected"] = 0

    (tmp_path / "raw/postgres.junit.xml").write_text("tampered", encoding="utf-8")
    assert not postgres_evidence_closes_mapping(
        document,
        repository=REPOSITORY,
        evidence_path=evidence_path,
        identity=identity,
        expected_nodes=expected_nodes,
    )


def test_backend_mapping_rejects_a_self_reported_check_not_bound_to_nodes(
    tmp_path: Path,
) -> None:
    document, evidence_path, identity = _postgres_evidence(tmp_path)
    expected_nodes = _representative_postgres_nodes()
    checks = document["checks"]
    assert isinstance(checks, dict)
    check = checks["chat_idempotency_concurrency"]
    assert isinstance(check, dict)
    check["node_ids"] = ["tests/test_scan_audit_postgres.py::fabricated"]

    assert not postgres_evidence_closes_mapping(
        document,
        repository=REPOSITORY,
        evidence_path=evidence_path,
        identity=identity,
        expected_nodes=expected_nodes,
    )
