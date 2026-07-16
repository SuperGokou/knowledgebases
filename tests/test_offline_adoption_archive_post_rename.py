from __future__ import annotations

import hashlib
import os
import re
import shlex
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
ADOPTION_SCRIPT = REPOSITORY / "deploy/tencent/adopt-offline.sh"

IDENTITY_DIGEST = "d" * 64
EXPECTED_ARCHIVE_FILES = {
    "active-release.json",
    "receipts.sha256",
    "manifest.sha256",
    "adoption-receipt.json",
    "adoption-receipt.sig",
}

POST_RENAME_CUTS = (
    (
        "receipts_manifest_renamed",
        'mv -- "$archive_manifest_staging" "$archive_manifest" || exit 73',
        False,
        "receipts.sha256",
    ),
    (
        "archive_receipt_renamed",
        'mv -- "$archive_receipt_staging" "$archive_receipt" || exit 73',
        False,
        "adoption-receipt.json",
    ),
    (
        "archive_signature_renamed",
        'mv -- "$archive_signature_staging" "$archive_signature" || exit 73',
        False,
        "adoption-receipt.sig",
    ),
    (
        "top_manifest_renamed",
        'mv -- "$archive_top_manifest_staging" "$archive_top_manifest" || exit 73',
        False,
        "manifest.sha256",
    ),
    (
        "pending_directory_fsynced",
        'sync -f "$archive_pending" || exit 73',
        True,
        None,
    ),
)


def _source() -> str:
    return ADOPTION_SCRIPT.read_text(encoding="utf-8")


def _shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    following = re.search(r"\n[A-Za-z_][A-Za-z0-9_]*\(\) \{\n", source[start + 1 :])
    if following is None:
        terminal_call = f"\n{name}\n"
        end = source.index(terminal_call, start)
    else:
        end = start + 1 + following.start()
    return source[start:end].rstrip() + "\n"


def _linux_root_shell() -> str:
    if os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        pytest.skip("fresh-process archive recovery requires a root Linux runner")
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")
    for executable in ("/usr/bin/python3", "/usr/bin/openssl"):
        if not Path(executable).is_file():
            pytest.skip(f"required executable is unavailable: {executable}")
    return shell


def _quote(value: Path | str) -> str:
    return shlex.quote(str(value))


def _instrument_after(
    function: str,
    statement: str,
    fault: str,
    *,
    last_occurrence: bool,
) -> str:
    positions = [match.start() for match in re.finditer(re.escape(statement), function)]
    assert positions
    if not last_occurrence:
        assert len(positions) == 1
    position = positions[-1] if last_occurrence else positions[0]
    insertion = position + len(statement)
    return function[:insertion] + f"\n  fault_barrier {fault}" + function[insertion:]


def _kill_at_barrier(
    shell: str,
    harness: str,
    marker: Path,
    fault: str,
    *,
    timeout: float = 15,
) -> None:
    kill_process_group = getattr(os, "killpg", None)
    sigkill = getattr(signal, "SIGKILL", None)
    if not callable(kill_process_group) or sigkill is None:
        pytest.skip("process-group SIGKILL is unavailable")
    process = subprocess.Popen(
        [shell, "-c", harness, "archive-fault", fault, marker.as_posix(), "mark"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    stdout = ""
    stderr = ""
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not marker.exists():
            if process.poll() is not None:
                break
            time.sleep(0.02)
    finally:
        if process.poll() is None:
            kill_process_group(process.pid, sigkill)
        stdout, stderr = process.communicate(timeout=10)
    if not marker.exists() or process.returncode != -int(sigkill):
        pytest.fail(
            f"fault barrier {fault!r} was not killed as a fresh process; "
            f"returncode={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
        )


def _run_shell(
    shell: str,
    harness: str,
    *,
    mode: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [shell, "-c", harness, "archive-resume", "none", "/dev/null", mode],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _generate_signing_keypair(tmp_path: Path) -> tuple[Path, Path]:
    private_key = tmp_path / "archive-signing.pem"
    public_key = tmp_path / "archive-public.pem"
    subprocess.run(
        [
            "/usr/bin/openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(private_key),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "/usr/bin/openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return private_key, public_key


def _prepare_scenario(tmp_path: Path) -> dict[str, Path]:
    state = tmp_path / "state"
    state.mkdir()
    receipt = state / "active-release.json"
    receipt.write_text('{"status":"committed"}\n', encoding="utf-8")
    receipt.chmod(0o400)
    receipt_digest = hashlib.sha256(receipt.read_bytes()).hexdigest()

    inventory = tmp_path / "inventory.sha256"
    inventory.write_text(
        f"{receipt_digest}  {receipt.as_posix()}\n",
        encoding="utf-8",
    )
    planned_receipts = tmp_path / "planned-receipts.sha256"
    planned_receipts.write_text(
        f"{receipt_digest}  {receipt.name}\n",
        encoding="utf-8",
    )
    planned_digest = hashlib.sha256(planned_receipts.read_bytes()).hexdigest()
    planned_manifest = tmp_path / "planned-manifest.sha256"
    planned_manifest.write_text(
        f"{planned_digest}  receipts.sha256\n",
        encoding="utf-8",
    )

    archive_root = state / "legacy-adoption/receipts"
    pending = archive_root / f".pending-{IDENTITY_DIGEST}-{IDENTITY_DIGEST}"
    final = archive_root / f"adopted-{IDENTITY_DIGEST}-{IDENTITY_DIGEST}"
    failed = archive_root / f"failed-{IDENTITY_DIGEST}-{IDENTITY_DIGEST}"
    private_key, public_key = _generate_signing_keypair(tmp_path)
    migration_count = tmp_path / "migration-count"
    migration_count.write_text("0\n", encoding="utf-8")

    return {
        "state": state,
        "receipt": receipt,
        "inventory": inventory,
        "planned_receipts": planned_receipts,
        "planned_manifest": planned_manifest,
        "archive_root": archive_root,
        "pending": pending,
        "final": final,
        "failed": failed,
        "expected_receipt": tmp_path / "expected-archive-receipt.json",
        "private_key": private_key,
        "public_key": public_key,
        "migration_count": migration_count,
        "marker": tmp_path / "fault-barrier",
    }


def _build_harness(function: str, scenario: dict[str, Path]) -> str:
    source = _source()
    helper_names = (
        "validate_exact_incomplete_staging_file",
        "discard_exact_incomplete_staging_file",
        "prepare_expected_archive_receipt",
        "validate_resumable_archive_distribution",
        "archive_one_legacy_receipt",
    )
    helpers = "\n".join(_shell_function(source, name) for name in helper_names)
    return f"""
set -eu
fault=$1
marker=$2
execution_mode=$3
fault_barrier() {{
  [ "$fault" = "$1" ] || return 0
  : > "$marker"
  while :; do :; done
}}
offline_fail() {{ printf '%s\n' "$2" >&2; exit "$3"; }}
offline_validate_root_directory() {{
  [ -d "$2" ] && [ ! -L "$2" ] || exit 73
  [ "$(stat -c %u -- "$2")" -eq 0 ] || exit 73
  [ -z "${{3:-}}" ] || [ "$(stat -c %a -- "$2")" = "$3" ] || exit 73
}}
validate_protected_file() {{ [ -f "$2" ] && [ ! -L "$2" ]; }}
{helpers}
{function}
OFFLINE_STATE_DIRECTORY={_quote(scenario["state"])}
archive_root={_quote(scenario["archive_root"])}
archive_pending={_quote(scenario["pending"])}
archive_final={_quote(scenario["final"])}
archive_failed={_quote(scenario["failed"])}
receipt_inventory={_quote(scenario["inventory"])}
planned_receipts_manifest={_quote(scenario["planned_receipts"])}
planned_archive_manifest={_quote(scenario["planned_manifest"])}
expected_archive_receipt={_quote(scenario["expected_receipt"])}
confirmed_plan_sha256={IDENTITY_DIGEST}
contract_sha256={IDENTITY_DIGEST}
retirement_digest={IDENTITY_DIGEST}
retirement_signature_digest={IDENTITY_DIGEST}
evidence_signing_key={_quote(scenario["private_key"])}
evidence_public_key={_quote(scenario["public_key"])}
archive_started=false
archive_legacy_receipts
if [ "$execution_mode" = mark ]; then
  current=$(cat {_quote(scenario["migration_count"])})
  printf '%s\n' "$((current + 1))" > {_quote(scenario["migration_count"])}
fi
"""


def _verify_published_archive(scenario: dict[str, Path]) -> None:
    final = scenario["final"]
    assert final.is_dir()
    assert not scenario["pending"].exists()
    assert not scenario["failed"].exists()
    assert not scenario["receipt"].exists()
    assert {item.name for item in final.iterdir()} == EXPECTED_ARCHIVE_FILES
    assert {item.name for item in scenario["archive_root"].iterdir()} == {final.name}

    signature = subprocess.run(
        [
            "/usr/bin/openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(scenario["public_key"]),
            "-signature",
            str(final / "adoption-receipt.sig"),
            str(final / "adoption-receipt.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert signature.returncode == 0, signature.stderr
    hashes = subprocess.run(
        ["sha256sum", "-c", "manifest.sha256"],
        cwd=final,
        check=False,
        capture_output=True,
        text=True,
    )
    assert hashes.returncode == 0, hashes.stderr
    receipts = subprocess.run(
        ["sha256sum", "-c", "receipts.sha256"],
        cwd=final,
        check=False,
        capture_output=True,
        text=True,
    )
    assert receipts.returncode == 0, receipts.stderr


@pytest.mark.parametrize(
    ("fault", "statement", "last_occurrence", "published_name"),
    POST_RENAME_CUTS,
)
def test_archive_post_rename_retry_converges_without_repeating_migration(
    tmp_path: Path,
    fault: str,
    statement: str,
    last_occurrence: bool,
    published_name: str | None,
) -> None:
    shell = _linux_root_shell()
    source = _source()
    base_function = _shell_function(source, "archive_legacy_receipts")
    instrumented = _instrument_after(
        base_function,
        statement,
        fault,
        last_occurrence=last_occurrence,
    )
    scenario = _prepare_scenario(tmp_path)

    _kill_at_barrier(
        shell,
        _build_harness(instrumented, scenario),
        scenario["marker"],
        fault,
    )
    assert scenario["pending"].is_dir()
    assert not scenario["final"].exists()
    assert scenario["migration_count"].read_text(encoding="utf-8") == "0\n"
    if published_name is not None:
        assert (scenario["pending"] / published_name).is_file()

    resumed = _run_shell(
        shell,
        _build_harness(base_function, scenario),
        mode="mark",
    )
    assert resumed.returncode == 0, resumed.stderr
    assert scenario["migration_count"].read_text(encoding="utf-8") == "1\n"
    _verify_published_archive(scenario)

    idempotent = _run_shell(
        shell,
        _build_harness(base_function, scenario),
        mode="validate-only",
    )
    assert idempotent.returncode == 0, idempotent.stderr
    assert scenario["migration_count"].read_text(encoding="utf-8") == "1\n"
    _verify_published_archive(scenario)


def test_tampered_post_rename_metadata_fails_before_migration(tmp_path: Path) -> None:
    shell = _linux_root_shell()
    source = _source()
    base_function = _shell_function(source, "archive_legacy_receipts")
    statement = 'mv -- "$archive_manifest_staging" "$archive_manifest" || exit 73'
    fault = "receipts_manifest_renamed"
    instrumented = _instrument_after(
        base_function,
        statement,
        fault,
        last_occurrence=False,
    )
    scenario = _prepare_scenario(tmp_path)

    _kill_at_barrier(
        shell,
        _build_harness(instrumented, scenario),
        scenario["marker"],
        fault,
    )
    published_manifest = scenario["pending"] / "receipts.sha256"
    published_manifest.chmod(0o600)
    published_manifest.write_text(
        f"{'0' * 64}  active-release.json\n",
        encoding="utf-8",
    )
    published_manifest.chmod(0o400)

    resumed = _run_shell(
        shell,
        _build_harness(base_function, scenario),
        mode="mark",
    )
    assert resumed.returncode == 65
    assert "receipt archive distribution is ambiguous or tampered" in resumed.stderr
    assert scenario["migration_count"].read_text(encoding="utf-8") == "0\n"
    assert scenario["pending"].is_dir()
    assert not scenario["final"].exists()
    assert not scenario["receipt"].exists()
