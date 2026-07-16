from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from scripts.acceptance_gate import (
    AcceptanceGateError,
    GateIdentity,
    TrustedExecutableBinding,
    assert_gate_identity,
    atomic_write_bytes,
    bind_trusted_executable,
    build_pytest_collection_command,
    build_pytest_execution_command,
    discover_postgres_test_files,
    parse_pytest_collection,
    parse_pytest_junit,
    private_artifact_directory,
    read_regular_file_nofollow,
    reserve_machine_report,
    sanitized_test_environment,
    start_gate_identity,
    validate_postgres_test_mapping,
    verify_file_artifact,
    verify_trusted_executable_binding,
    write_json_evidence,
)


@dataclass(frozen=True)
class _Identity:
    git_head: str
    content_fingerprint: str


@pytest.fixture
def private_external_executable() -> Path:
    """Copy an executable below a private, repository-external directory."""

    with tempfile.TemporaryDirectory(prefix="kb-node-binding-", dir=Path.home()) as raw_directory:
        directory = Path(raw_directory)
        if os.name == "posix":
            directory.chmod(0o700)
        executable = directory / ("trusted-node.exe" if os.name == "nt" else "trusted-node")
        shutil.copy2(Path(sys.executable).resolve(), executable)
        if os.name == "posix":
            executable.chmod(0o700)
        yield executable


def test_trusted_executable_binding_round_trip_uses_external_canonical_file(
    private_external_executable: Path,
) -> None:
    repository = Path(__file__).resolve().parents[1]

    binding = bind_trusted_executable(
        repository,
        private_external_executable.name,
        search_path=str(private_external_executable.parent),
    )

    assert binding.path == str(private_external_executable.resolve())
    assert len(binding.sha256) == 64
    assert verify_trusted_executable_binding(repository, binding) == binding.path


def test_trusted_executable_binding_rejects_digest_tampering(
    private_external_executable: Path,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    binding = bind_trusted_executable(
        repository,
        private_external_executable.name,
        search_path=str(private_external_executable.parent),
    )

    with pytest.raises(AcceptanceGateError, match="digest"):
        verify_trusted_executable_binding(
            repository,
            TrustedExecutableBinding(binding.path, "0" * 64),
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership contract")
def test_trusted_executable_binding_can_require_root_ownership(
    private_external_executable: Path,
) -> None:
    if private_external_executable.stat().st_uid == 0:
        pytest.skip("fixture is already root-owned")

    with pytest.raises(AcceptanceGateError, match="root-owned"):
        bind_trusted_executable(
            Path(__file__).resolve().parents[1],
            private_external_executable.name,
            search_path=str(private_external_executable.parent),
            require_root_owner=True,
        )


def test_trusted_executable_binding_rejects_repository_file(
    private_external_executable: Path,
) -> None:
    with pytest.raises(AcceptanceGateError, match="outside the repository"):
        bind_trusted_executable(
            private_external_executable.parent,
            private_external_executable.name,
            search_path=str(private_external_executable.parent),
        )


def test_trusted_executable_binding_rejects_symbolic_link(
    private_external_executable: Path,
) -> None:
    link = private_external_executable.with_name(f"{private_external_executable.name}-link")
    try:
        link.symlink_to(private_external_executable)
    except (NotImplementedError, OSError):
        pytest.skip("symbolic links are unavailable on this host")

    with pytest.raises(AcceptanceGateError, match="symbolic link"):
        verify_trusted_executable_binding(
            Path(__file__).resolve().parents[1],
            TrustedExecutableBinding(str(link), "0" * 64),
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission contract")
def test_trusted_executable_binding_rejects_world_writable_ancestor(
    private_external_executable: Path,
) -> None:
    private_external_executable.parent.chmod(0o777)

    with pytest.raises(AcceptanceGateError, match="writable ancestor"):
        bind_trusted_executable(
            Path(__file__).resolve().parents[1],
            private_external_executable.name,
            search_path=str(private_external_executable.parent),
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX inode replacement contract")
def test_trusted_executable_binding_rejects_replacement_between_lstat_and_open(
    private_external_executable: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_open = os.open
    replacement = private_external_executable.with_name("replacement-node")
    shutil.copy2(Path(sys.executable).resolve(), replacement)
    replacement.chmod(0o700)
    swapped = False

    def replacing_open(path: os.PathLike[str] | str, flags: int, mode: int = 0o777) -> int:
        nonlocal swapped
        if Path(path) == private_external_executable and not swapped:
            os.replace(replacement, private_external_executable)
            swapped = True
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", replacing_open)

    with pytest.raises(AcceptanceGateError, match="changed before hashing"):
        bind_trusted_executable(
            Path(__file__).resolve().parents[1],
            private_external_executable.name,
            search_path=str(private_external_executable.parent),
        )


def test_postgres_discovery_and_declared_mapping_must_be_identical(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_primary_postgres.py").write_text(
        'import os\nURL = os.getenv("KB_TEST_POSTGRES_URL")\n', encoding="utf-8"
    )
    (tests / "test_migration_postgres.py").write_text(
        'import os\nURL = os.getenv("KB_TEST_MIGRATION_POSTGRES_URL")\n',
        encoding="utf-8",
    )
    (tests / "test_unrelated.py").write_text(
        'import os\nURL = os.getenv("KB_TEST_POSTGRES_URL")\n',
        encoding="utf-8",
    )

    discovered = discover_postgres_test_files(tmp_path)

    assert discovered == (
        "tests/test_migration_postgres.py",
        "tests/test_primary_postgres.py",
    )
    validate_postgres_test_mapping(tmp_path, discovered)
    with pytest.raises(AcceptanceGateError, match="mapping drift"):
        validate_postgres_test_mapping(tmp_path, discovered[:1])


def test_postgres_discovery_rejects_non_regular_named_candidate(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_valid_postgres.py").write_text("def test_ok(): pass\n", encoding="utf-8")
    (tests / "test_directory_postgres.py").mkdir()

    with pytest.raises(AcceptanceGateError, match="regular files"):
        discover_postgres_test_files(tmp_path)


def test_pytest_environment_and_commands_cannot_inherit_selection_controls() -> None:
    environment = sanitized_test_environment(
        {
            "PYTEST_ADDOPTS": "-k one_test --deselect tests/test_other.py",
            "PYTEST_PLUGINS": "untrusted_plugin",
            "PYTHONPATH": "/attacker/python",
            "PYTHONHOME": "/attacker/home",
            "VIRTUAL_ENV": "/attacker/venv",
            "UV_PROJECT": "/attacker/project",
            "COVERAGE_PROCESS_START": "/attacker/coverage.ini",
            "NODE_OPTIONS": "--require=/attacker/hook.js",
            "COMPOSE_FILE": "/attacker/compose.yml",
            "DOCKER_HOST": "tcp://attacker.invalid:2375",
            "LD_PRELOAD": "/attacker/preload.so",
            "LD_LIBRARY_PATH": "/attacker/lib",
            "LD_AUDIT": "/attacker/audit.so",
            "DYLD_INSERT_LIBRARIES": "/attacker/dyld.dylib",
            "DYLD_LIBRARY_PATH": "/attacker/dyld",
            "LIBPATH": "/attacker/aix",
            "SHLIB_PATH": "/attacker/hpux",
            "KB_DATABASE_URL": "postgresql://attacker.invalid/db",
            "KEEP_ME": "yes",
        }
    )
    base = ("uv", "run", "pytest", "tests/test_example.py")

    assert "PYTEST_ADDOPTS" not in environment
    assert "PYTEST_PLUGINS" not in environment
    for name in (
        "PYTHONPATH",
        "PYTHONHOME",
        "VIRTUAL_ENV",
        "UV_PROJECT",
        "COVERAGE_PROCESS_START",
        "NODE_OPTIONS",
        "COMPOSE_FILE",
        "DOCKER_HOST",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "LIBPATH",
        "SHLIB_PATH",
        "KB_DATABASE_URL",
    ):
        assert name not in environment
    assert environment["KEEP_ME"] == "yes"
    assert "--collect-only" in build_pytest_collection_command(base)
    execution = build_pytest_execution_command(base, Path("result.xml"))
    assert "-p" in execution
    assert "no:cacheprovider" in execution
    assert "--override-ini=addopts=" in execution
    assert "--override-ini=xfail_strict=true" in execution
    assert "--junitxml=result.xml" in execution


def test_collection_and_junit_require_the_exact_same_nodes(tmp_path: Path) -> None:
    collection = parse_pytest_collection(
        "\n".join(
            (
                "tests/test_example.py::test_one",
                "tests/test_example.py::test_two[value]",
                "2 tests collected in 0.01s",
            )
        )
    )
    report = tmp_path / "result.xml"
    report.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">
<testcase classname="tests.test_example" name="test_one" />
</testsuite></testsuites>
""",
        encoding="utf-8",
    )

    evidence = parse_pytest_junit(report, collection)

    assert evidence.collected == 2
    assert evidence.passed == 1
    assert evidence.deselected == 1
    assert evidence.is_success is False
    assert evidence.node_ids == ("tests/test_example.py::test_one",)


def test_collection_preserves_escaped_parameter_identity_across_path_styles(
    tmp_path: Path,
) -> None:
    parameter_name = r"test_payload[line\n\u4e2d\x00]"
    collection = parse_pytest_collection(
        "\n".join(
            (
                rf"tests\test_example.py::{parameter_name}",
                "1 test collected in 0.01s",
            )
        )
    )
    report = tmp_path / "escaped-parameters.xml"
    report.write_text(
        '<testsuites><testsuite><testcase classname="tests.test_example" '
        f'name="{parameter_name}" /></testsuite></testsuites>',
        encoding="utf-8",
    )

    evidence = parse_pytest_junit(report, collection)

    assert collection == (f"tests/test_example.py::{parameter_name}",)
    assert evidence.is_success is True
    assert evidence.node_ids == collection
    assert evidence.deselected == 0
    assert evidence.unexpected == 0


@pytest.mark.parametrize(
    ("child", "field"),
    (
        ('<skipped message="ordinary skip" />', "skipped"),
        ('<skipped type="pytest.xfail" message="expected" />', "xfailed"),
        ('<failure message="[XPASS(strict)] must fail" />', "xpassed"),
        ('<error message="fixture failed" />', "errors"),
    ),
)
def test_junit_rejects_every_non_pass_outcome(tmp_path: Path, child: str, field: str) -> None:
    node = "tests/test_example.py::test_one"
    report = tmp_path / f"{field}.xml"
    report.write_text(
        '<testsuites><testsuite><testcase classname="tests.test_example" '
        f'name="test_one">{child}</testcase></testsuite></testsuites>',
        encoding="utf-8",
    )

    evidence = parse_pytest_junit(report, (node,))

    assert getattr(evidence, field) == 1
    assert evidence.is_success is False


def test_junit_artifact_tampering_is_detected(tmp_path: Path) -> None:
    report = tmp_path / "result.xml"
    report.write_bytes(b"trusted")
    expected_hash = hashlib.sha256(report.read_bytes()).hexdigest()
    expected_bytes = report.stat().st_size
    verify_file_artifact(report, sha256=expected_hash, size=expected_bytes)

    report.write_bytes(b"tampered")

    with pytest.raises(AcceptanceGateError, match="artifact"):
        verify_file_artifact(report, sha256=expected_hash, size=expected_bytes)


def test_junit_rejects_dtd_and_entity_expansion(tmp_path: Path) -> None:
    node = "tests/test_example.py::test_one"
    report = tmp_path / "entity.xml"
    report.write_text(
        "<!DOCTYPE testsuites [<!ENTITY injected 'untrusted'>]>"
        '<testsuites><testsuite><testcase classname="tests.test_example" '
        'name="test_one"><system-out>&injected;</system-out></testcase>'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )

    with pytest.raises(AcceptanceGateError, match="malformed"):
        parse_pytest_junit(report, (node,))


def test_gate_identity_rejects_bad_nonce_and_mid_run_change(tmp_path: Path) -> None:
    first = _Identity("a" * 40, "b" * 64)
    changed = _Identity("a" * 40, "c" * 64)
    contract = start_gate_identity(
        tmp_path,
        expected_git_head=first.git_head,
        expected_content_fingerprint=first.content_fingerprint,
        run_nonce="d" * 32,
        collector=lambda _repository: first,
    )

    assert contract == GateIdentity(first.git_head, first.content_fingerprint, "d" * 32)
    with pytest.raises(AcceptanceGateError, match="changed during acceptance"):
        assert_gate_identity(tmp_path, contract, collector=lambda _repository: changed)
    with pytest.raises(AcceptanceGateError, match="run nonce"):
        start_gate_identity(
            tmp_path,
            expected_git_head=first.git_head,
            expected_content_fingerprint=first.content_fingerprint,
            run_nonce="too-short",
            collector=lambda _repository: first,
        )


def test_json_evidence_is_atomic_and_rejects_symlink_destination(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    write_json_evidence(evidence, {"status": "first"})
    write_json_evidence(evidence, {"status": "complete"})

    assert json.loads(evidence.read_text(encoding="utf-8")) == {"status": "complete"}
    assert not tuple(tmp_path.glob(".evidence.json.*.tmp"))

    actual = tmp_path / "actual.json"
    actual.write_text("{}", encoding="utf-8")
    evidence.unlink()
    try:
        evidence.symlink_to(actual)
    except OSError:
        pytest.skip("creating symlinks is unavailable on this test host")
    with pytest.raises(AcceptanceGateError, match="symlink"):
        write_json_evidence(evidence, {"status": "must-not-write"})
    assert actual.read_text(encoding="utf-8") == "{}"


def test_private_machine_report_is_exclusive_and_cleanup_is_scoped(tmp_path: Path) -> None:
    with private_artifact_directory(tmp_path, prefix="runner-") as directory:
        report = directory / "result.xml"
        reserve_machine_report(report)
        metadata = report.stat()
        if os.name == "posix":
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
            assert stat.S_IMODE(metadata.st_mode) == 0o600
        with pytest.raises(AcceptanceGateError, match="reserved exclusively"):
            reserve_machine_report(report)
    assert not directory.exists()


def test_nofollow_reader_and_atomic_writer_do_not_touch_symlink_victim(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"unchanged")
    linked = tmp_path / "linked.txt"
    try:
        linked.symlink_to(victim)
    except OSError:
        pytest.skip("creating symlinks is unavailable on this test host")

    with pytest.raises(AcceptanceGateError):
        read_regular_file_nofollow(linked, maximum_bytes=1024)
    with pytest.raises(AcceptanceGateError):
        atomic_write_bytes(linked, b"replacement")
    assert victim.read_bytes() == b"unchanged"
