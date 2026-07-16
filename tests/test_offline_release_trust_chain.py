from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
ADOPTION = REPOSITORY / "deploy/tencent/adopt-offline.sh"
IMPORTER = REPOSITORY / "deploy/tencent/import-offline-registry-bundle.sh"
PREFLIGHT = REPOSITORY / "deploy/tencent/preflight-offline.sh"
LEGACY_ADOPTION = REPOSITORY / "scripts/legacy_offline_adoption.py"


def _run_python(program: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-c", program, *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _canonical_json(document: object) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode()


def _legacy_adoption_module() -> ModuleType:
    name = "legacy_offline_adoption_release_trust_test"
    spec = importlib.util.spec_from_file_location(name, LEGACY_ADOPTION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _plan_document(git_sha: str = "a" * 40) -> dict[str, Any]:
    target_manifest = {
        "path": (
            "/srv/heyi-knowledgebases-offline/artifacts/2026.07.16/"
            "offline-registry-bundle/release.env.images"
        ),
        "sha256": "2" * 64,
        "size_bytes": 1,
    }
    authorization = {
        "schema_version": 1,
        "release_sequence": 202607160001,
        "release_id": "2026.07.16",
        "release_git_sha": git_sha,
        "release_schema_head": "20260715_0021",
        "release_sha256": "1" * 64,
        "release_assets_sha256": "3" * 64,
        "checksum_set_sha256": "4" * 64,
        "signature_sha256": "5" * 64,
        "target_manifest": target_manifest,
        "registry_import_receipt": {
            "path": "/srv/heyi-knowledgebases-offline/state/registry-import-" + "2" * 64 + ".json",
            "sha256": "6" * 64,
            "size_bytes": 1,
        },
        "highest_release": {
            "path": "/srv/heyi-knowledgebases-offline/state/highest-release.json",
            "sha256": "7" * 64,
            "size_bytes": 1,
        },
        "trusted_release_public_key": {
            "path": "/etc/heyi-release/trusted-release-public.pem",
            "sha256": "8" * 64,
            "size_bytes": 1,
        },
    }
    return {
        "schema_version": 4,
        "kind": "heyi-legacy-adoption-plan",
        "project": "heyi-kb-offline",
        "created_at": "2026-07-16T00:00:00Z",
        "git_sha": git_sha,
        "data_root": "/srv/heyi-knowledgebases-offline/data",
        "runtime_env": {},
        "legacy_compose": {},
        "host_isolation_guard": {},
        "target_manifest": target_manifest,
        "release_authorization": authorization,
        "release_authorization_sha256": hashlib.sha256(_canonical_json(authorization)).hexdigest(),
        "inventory_sha256": "b" * 64,
        "topology_sha256": "c" * 64,
        "inventory": {},
        "safety": {},
    }


def _receipt_documents(
    *,
    git_sha: str = "a" * 40,
    trusted_key_sha256: str = "7" * 64,
) -> tuple[dict[str, Any], dict[str, Any]]:
    receipt = {
        "schema_version": 2,
        "kind": "offline-registry-import",
        "status": "verified",
        "release_sequence": 202607160001,
        "release_id": "2026.07.16",
        "release_git_sha": git_sha,
        "release_schema_head": "20260715_0021",
        "release_sha256": "1" * 64,
        "manifest_sha256": "2" * 64,
        "release_assets_sha256": "3" * 64,
        "checksum_set_sha256": "4" * 64,
        "signature_sha256": "5" * 64,
        "trusted_key_sha256": trusted_key_sha256,
    }
    highest = {
        key: receipt[key]
        for key in (
            "schema_version",
            "release_sequence",
            "release_id",
            "release_git_sha",
            "release_schema_head",
            "manifest_sha256",
            "release_assets_sha256",
            "trusted_key_sha256",
        )
    }
    return receipt, highest


def test_importer_control_identity_is_canonical_and_path_safe() -> None:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")
    source = IMPORTER.read_text(encoding="utf-8")
    cases = (
        "    RELEASE_SEQUENCE)"
        + source.split("    RELEASE_SEQUENCE)", 1)[1].split("    RELEASE_GIT_SHA)", 1)[0]
    )
    harness = f"""\
set -eu
key=$1
value=$2
offline_fail() {{ printf '%s\\n' "$2" >&2; exit "$3"; }}
case "$key" in
{cases}
  *) exit 99 ;;
esac
"""

    def validate(key: str, value: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [shell, "-c", harness, "release-control", key, value],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    for sequence in ("1", "9", "10", "202607160001", "999999999999999999"):
        assert validate("RELEASE_SEQUENCE", sequence).returncode == 0
    for sequence in ("", "0", "00", "0001", "08", "-1", "1a", "1000000000000000000"):
        assert validate("RELEASE_SEQUENCE", sequence).returncode == 65

    for release_id in ("a", "A1", "2026.07.16", "release_1-test", "a" * 128):
        assert validate("RELEASE_ID", release_id).returncode == 0
    for release_id in (
        "",
        ".",
        "..",
        ".release",
        "release.",
        "-release",
        "release-",
        "release/id",
        r"release\id",
        "a" * 129,
    ):
        assert validate("RELEASE_ID", release_id).returncode == 65


def test_generated_release_trust_json_is_strictly_self_validated(tmp_path: Path) -> None:
    source = IMPORTER.read_text(encoding="utf-8")
    function = source.split("validate_expected_trust_documents() {", 1)[1].split(
        "\n}\n\n# Fail before any Docker",
        1,
    )[0]
    program = function.split("if ! python3 -I -c '\n", 1)[1].split(
        '\n\' "$expected_receipt"',
        1,
    )[0]
    receipt_path = tmp_path / "expected-receipt.json"
    highest_path = tmp_path / "expected-highest.json"
    receipt, highest = _receipt_documents()
    arguments = (
        str(receipt_path),
        str(highest_path),
        "202607160001",
        "2026.07.16",
        "a" * 40,
        "20260715_0021",
        "1" * 64,
        "2" * 64,
        "3" * 64,
        "4" * 64,
        "5" * 64,
        "7" * 64,
    )

    def write_documents(
        receipt_document: object = receipt,
        highest_document: object = highest,
    ) -> None:
        receipt_path.write_bytes(_canonical_json(receipt_document))
        highest_path.write_bytes(_canonical_json(highest_document))

    write_documents()
    assert _run_python(program, *arguments).returncode == 0

    receipt_path.write_text(
        '{"schema_version":2,"schema_version":2}\n',
        encoding="utf-8",
    )
    assert _run_python(program, *arguments).returncode != 0

    receipt_path.write_text('{"schema_version":NaN}\n', encoding="utf-8")
    assert _run_python(program, *arguments).returncode != 0

    boolean_sequence = dict(receipt)
    boolean_sequence["release_sequence"] = True
    write_documents(boolean_sequence)
    assert _run_python(program, *arguments).returncode != 0

    extra_highest = dict(highest)
    extra_highest["unexpected"] = True
    write_documents(receipt, extra_highest)
    assert _run_python(program, *arguments).returncode != 0

    write_documents()
    leading_zero_arguments = (*arguments[:2], "0001", *arguments[3:])
    assert _run_python(program, *leading_zero_arguments).returncode != 0

    validation_call = source.index("validate_expected_trust_documents\n")
    assert validation_call < source.index(
        "trust_state_directory=/srv/heyi-knowledgebases-offline/state"
    )
    assert validation_call < source.index("docker network create")


def test_legacy_release_manifest_rejects_unsafe_ids_and_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _legacy_adoption_module()
    artifact_root = Path("/srv/heyi-knowledgebases-offline/artifacts")
    monkeypatch.setattr(module, "ARTIFACT_ROOT", artifact_root)
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)

    expected = artifact_root / "2026.07.16" / "offline-registry-bundle" / "release.env.images"
    assert module._protected_release_manifest("2026.07.16") == expected
    for release_id in (".", "..", ".release", "release.", "release/id", "a" * 129):
        with pytest.raises(module.AdoptionError, match="release ID"):
            module._protected_release_manifest(release_id)

    monkeypatch.setattr(
        module,
        "protected_file",
        lambda path, **kwargs: Path("/tmp/escaped/release.env.images"),
    )
    with pytest.raises(module.AdoptionError, match="escapes"):
        module._protected_release_manifest("2026.07.16")


def test_legacy_release_manifest_rejects_a_symlinked_release_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _legacy_adoption_module()
    artifacts = tmp_path / "artifacts"
    external = tmp_path / "external-release"
    bundle = external / "offline-registry-bundle"
    bundle.mkdir(parents=True)
    (bundle / "release.env.images").write_text("manifest\n", encoding="utf-8")
    artifacts.mkdir()
    try:
        (artifacts / "linked-release").symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")
    monkeypatch.setattr(module, "ARTIFACT_ROOT", artifacts)

    with pytest.raises(module.AdoptionError, match="non-canonical"):
        module._protected_release_manifest("linked-release")


def test_importer_rejects_every_noncanonical_trust_key_argument() -> None:
    source = IMPORTER.read_text(encoding="utf-8")
    marker = 'if [ "$trusted_public_key" != "$canonical_trusted_public_key" ]; then'
    guard_body = source.split(marker, 1)[1].split("\nfi", 1)[0]
    harness = f"""\
set -eu
canonical_trusted_public_key=/etc/heyi-release/trusted-release-public.pem
trusted_public_key=$1
offline_fail() {{ exit "$3"; }}
{marker}{guard_body}
fi
"""
    arbitrary = subprocess.run(
        ["sh", "-c", harness, "trust-key-test", "/tmp/operator-selected.pem"],
        check=False,
        capture_output=True,
        text=True,
    )
    canonical = subprocess.run(
        [
            "sh",
            "-c",
            harness,
            "trust-key-test",
            "/etc/heyi-release/trusted-release-public.pem",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert arbitrary.returncode == 65
    assert canonical.returncode == 0
    assert "canonical trusted release public key changed during import" in source


def test_registry_import_same_release_is_an_exact_audited_noop(
    tmp_path: Path,
) -> None:
    source = IMPORTER.read_text(encoding="utf-8")
    marker = 'if [ "$release_sequence" -lt "$highest_release_sequence" ]; then'
    state_machine = (
        marker
        + source.split(marker, 1)[1].split(
            "\n# Registry import happens before the deployment preflight",
            1,
        )[0]
    )
    assert "docker network create" not in state_machine
    assert "docker run" not in state_machine
    assert "docker pull" not in state_machine

    state = tmp_path / "state"
    state.mkdir()
    manifest_digest = "2" * 64
    receipt = state / f"registry-import-{manifest_digest}.json"
    highest = state / "highest-release.json"
    expected_receipt = tmp_path / "expected-receipt.json"
    expected_highest = tmp_path / "expected-highest.json"
    trusted_key = tmp_path / "trusted.pem"
    expected_receipt.write_text('{"receipt":"exact"}\n', encoding="utf-8")
    expected_highest.write_text('{"highest":"exact"}\n', encoding="utf-8")
    receipt.write_bytes(expected_receipt.read_bytes())
    highest.write_bytes(expected_highest.read_bytes())
    trusted_key.write_bytes(b"trusted-key")
    trusted_key_sha256 = hashlib.sha256(trusted_key.read_bytes()).hexdigest()
    harness = f"""\
set -eu
release_sequence=$1
highest_release_sequence=$2
trust_state_directory=$3
manifest_digest=$4
expected_highest=$5
expected_receipt=$6
highest_release_file=$7
canonical_trusted_public_key=$8
trusted_key_digest=$9
offline_fail() {{ printf '%s\\n' "$2" >&2; exit "$3"; }}
validate_protected_path() {{ :; }}
verify_local_signed_images() {{ printf '%s\\n' local-images-verified; }}
{state_machine}
"""

    exact = subprocess.run(
        [
            "sh",
            "-c",
            harness,
            "registry-noop",
            "17",
            "17",
            state.as_posix(),
            manifest_digest,
            expected_highest.as_posix(),
            expected_receipt.as_posix(),
            highest.as_posix(),
            trusted_key.as_posix(),
            trusted_key_sha256,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert exact.returncode == 0
    assert "local-images-verified" in exact.stdout
    assert "AUDITED_NOOP" in exact.stdout

    receipt.unlink()
    missing_receipt = subprocess.run(
        [
            "sh",
            "-c",
            harness,
            "registry-noop",
            "17",
            "17",
            state.as_posix(),
            manifest_digest,
            expected_highest.as_posix(),
            expected_receipt.as_posix(),
            highest.as_posix(),
            trusted_key.as_posix(),
            trusted_key_sha256,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert missing_receipt.returncode == 65
    assert "without its exact import receipt" in missing_receipt.stderr

    downgraded = subprocess.run(
        [
            "sh",
            "-c",
            harness,
            "registry-noop",
            "16",
            "17",
            state.as_posix(),
            manifest_digest,
            expected_highest.as_posix(),
            expected_receipt.as_posix(),
            highest.as_posix(),
            trusted_key.as_posix(),
            trusted_key_sha256,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert downgraded.returncode == 65
    assert "replayed or downgraded" in downgraded.stderr


def test_registry_import_recovery_rejects_a_hardlinked_existing_receipt(
    tmp_path: Path,
) -> None:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")
    source = IMPORTER.read_text(encoding="utf-8")
    marker = 'if [ -e "$receipt_file" ]; then'
    existing_receipt_branch = (
        marker
        + source.split(marker, 1)[1].split(
            '\nsync -f "$receipt_file"',
            1,
        )[0]
    )
    assert 'stat -c %h -- "$receipt_file"' in existing_receipt_branch

    receipt = tmp_path / "registry-import-receipt.json"
    receipt_alias = tmp_path / "registry-import-receipt.alias"
    temporary_receipt = tmp_path / ".registry-import.pending"
    receipt.write_bytes(b'{"status":"verified"}\n')
    temporary_receipt.write_bytes(receipt.read_bytes())
    try:
        os.link(receipt, receipt_alias)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    harness = f"""\
set -eu
receipt_file=$1
temporary_receipt=$2
offline_fail() {{ printf '%s\\n' "$2" >&2; exit "$3"; }}
validate_protected_path() {{ :; }}
{existing_receipt_branch}
"""
    rejected = subprocess.run(
        [
            shell,
            "-c",
            harness,
            "registry-recovery-hardlink",
            receipt.as_posix(),
            temporary_receipt.as_posix(),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert rejected.returncode == 65
    assert "existing import receipt conflicts with this signature" in rejected.stderr
    assert receipt.read_bytes() == receipt_alias.read_bytes()
    assert not temporary_receipt.exists()


def test_plan_git_sha_is_read_only_from_exact_confirmed_canonical_v4_plan(
    tmp_path: Path,
) -> None:
    source = ADOPTION.read_text(encoding="utf-8")
    program = source.split(
        "read_confirmed_legacy_plan_git_sha() {\n  /usr/bin/python3 -I -c '\n",
        1,
    )[1].split('\n\' "$legacy_plan" "$confirmed_plan_sha256"', 1)[0]
    plan_path = tmp_path / "plan.json"
    plan = _plan_document()
    canonical = _canonical_json(plan)
    plan_path.write_bytes(canonical)
    digest = hashlib.sha256(canonical).hexdigest()

    valid = _run_python(program, str(plan_path), digest)
    assert valid.returncode == 0
    assert valid.stdout.strip() == "a" * 40

    assert _run_python(program, str(plan_path), "9" * 64).returncode != 0

    plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    noncanonical_digest = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    assert _run_python(program, str(plan_path), noncanonical_digest).returncode != 0

    for field, value in (
        ("schema_version", 3),
        ("kind", "operator-plan"),
        ("project", "another-project"),
        ("git_sha", "f" * 39),
    ):
        mutated = dict(plan)
        mutated[field] = value
        payload = _canonical_json(mutated)
        plan_path.write_bytes(payload)
        assert (
            _run_python(
                program,
                str(plan_path),
                hashlib.sha256(payload).hexdigest(),
            ).returncode
            != 0
        )


def test_adoption_rejects_mismatched_git_trust_key_and_legacy_highest_state(
    tmp_path: Path,
) -> None:
    source = ADOPTION.read_text(encoding="utf-8")
    function = source.split("validate_registry_release_receipts() {", 1)[1].split(
        "\n}\n\nverify_host_isolation()",
        1,
    )[0]
    program = function.split("/usr/bin/python3 -I -c '\n", 1)[1].split(
        '\n\' "$registry_receipt"',
        1,
    )[0]
    receipt_path = tmp_path / "receipt.json"
    highest_path = tmp_path / "highest-release.json"
    receipt, highest = _receipt_documents()

    def validate(
        *,
        expected_git_sha: str = "a" * 40,
        expected_key_sha256: str = "7" * 64,
    ) -> subprocess.CompletedProcess[str]:
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        highest_path.write_text(json.dumps(highest), encoding="utf-8")
        return _run_python(
            program,
            str(receipt_path),
            str(highest_path),
            "1" * 64,
            "2" * 64,
            "3" * 64,
            expected_git_sha,
            expected_key_sha256,
        )

    assert validate().returncode == 0
    assert validate(expected_git_sha="b" * 40).returncode != 0
    assert validate(expected_key_sha256="8" * 64).returncode != 0

    highest["schema_version"] = 1
    highest.pop("trusted_key_sha256")
    assert validate().returncode != 0

    receipt, highest = _receipt_documents()
    highest["unexpected"] = True
    assert validate().returncode != 0

    receipt, highest = _receipt_documents()
    receipt["release_sequence"] = 1
    highest["release_sequence"] = True
    assert validate().returncode != 0


def test_plan_binding_precedes_registry_authorization_in_every_adoption() -> None:
    source = ADOPTION.read_text(encoding="utf-8")
    preflight = source.split("predictive_target_preflight() {", 1)[1].split(
        "\n}\n\nprepare_target_install_contract()",
        1,
    )[0]

    dry_run = preflight.index("validate_legacy_retirement_dry_run")
    plan_identity = preflight.index("legacy_plan_git_sha=$(read_confirmed_legacy_plan_git_sha)")
    registry_authorization = preflight.index("validate_registry_release_receipts")

    assert dry_run < plan_identity < registry_authorization
    assert source.count("validate_legacy_retirement_dry_run") == 2
    assert ("trusted_release_public_key=/etc/heyi-release/trusted-release-public.pem") in source
    assert 'receipt["release_git_sha"] == sys.argv[6]' in source
    assert 'receipt["trusted_key_sha256"] == sys.argv[7]' in source


def test_preflight_strictly_binds_receipts_to_the_fixed_trust_root(
    tmp_path: Path,
) -> None:
    source = PREFLIGHT.read_text(encoding="utf-8")
    trust_block = source.split(
        "registry_receipt=$registry_receipt_directory/registry-import-",
        1,
    )[1]
    receipt_program = trust_block.split("if ! python3 -I -c '\n", 1)[1].split(
        '\n\' "$registry_receipt" "$release_digest" "$manifest_digest"',
        1,
    )[0]
    highest_program = (
        trust_block.split(
            "highest_release_file=$registry_receipt_directory/highest-release.json",
            1,
        )[1]
        .split("if ! python3 -I -c '\n", 1)[1]
        .split(
            '\n\' "$registry_receipt" "$highest_release_file"',
            1,
        )[0]
    )
    receipt_path = tmp_path / "receipt.json"
    highest_path = tmp_path / "highest-release.json"
    receipt, highest = _receipt_documents()

    def validate_receipt(expected_key: str = "7" * 64) -> subprocess.CompletedProcess[str]:
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        return _run_python(
            receipt_program,
            str(receipt_path),
            "1" * 64,
            "2" * 64,
            "3" * 64,
            expected_key,
        )

    def validate_highest(expected_key: str = "7" * 64) -> subprocess.CompletedProcess[str]:
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        highest_path.write_text(json.dumps(highest), encoding="utf-8")
        return _run_python(
            highest_program,
            str(receipt_path),
            str(highest_path),
            expected_key,
        )

    assert validate_receipt().returncode == 0
    assert validate_receipt("8" * 64).returncode != 0
    assert validate_highest().returncode == 0
    assert validate_highest("8" * 64).returncode != 0

    duplicate = json.dumps(receipt).replace(
        '"schema_version": 2',
        '"schema_version": 2, "schema_version": 2',
        1,
    )
    receipt_path.write_text(duplicate, encoding="utf-8")
    assert (
        _run_python(
            receipt_program,
            str(receipt_path),
            "1" * 64,
            "2" * 64,
            "3" * 64,
            "7" * 64,
        ).returncode
        != 0
    )

    nonfinite = dict(receipt)
    nonfinite["release_sequence"] = float("nan")
    receipt_path.write_text(json.dumps(nonfinite), encoding="utf-8")
    assert (
        _run_python(
            receipt_program,
            str(receipt_path),
            "1" * 64,
            "2" * 64,
            "3" * 64,
            "7" * 64,
        ).returncode
        != 0
    )

    receipt, highest = _receipt_documents()
    highest["schema_version"] = 1
    assert validate_highest().returncode != 0
    receipt, highest = _receipt_documents()
    highest.pop("trusted_key_sha256")
    assert validate_highest().returncode != 0
    receipt, highest = _receipt_documents()
    highest["unexpected"] = True
    assert validate_highest().returncode != 0

    receipt, highest = _receipt_documents()
    receipt["release_sequence"] = 1
    highest["release_sequence"] = True
    assert validate_highest().returncode != 0

    assert ("trusted_release_public_key=/etc/heyi-release/trusted-release-public.pem") in source
    assert "trusted release public key changed during validation" in source
