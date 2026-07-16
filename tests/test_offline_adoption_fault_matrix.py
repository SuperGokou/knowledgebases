from __future__ import annotations

import base64
import hashlib
import json
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
        pytest.skip("fresh-process durability matrix requires a root Linux runner")
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")
    for executable in ("/usr/bin/python3", "/usr/bin/openssl"):
        if not Path(executable).is_file():
            pytest.skip(f"required executable is unavailable: {executable}")
    return shell


def _quote(path: Path | str) -> str:
    return shlex.quote(str(path))


def _instrument(function: str, statement: str, fault: str, *, after: bool = False) -> str:
    assert statement in function
    if after:
        replacement = f"{statement}\n  fault_barrier {fault}"
    else:
        replacement = f"fault_barrier {fault}\n  {statement}"
    return function.replace(statement, replacement)


def _kill_at_barrier(
    shell: str,
    harness: str,
    marker: Path,
    fault: str,
    *,
    timeout: float = 15,
) -> None:
    process = subprocess.Popen(
        [shell, "-c", harness, "fault-harness", fault, marker.as_posix()],
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
            os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=10)
    if not marker.exists():
        pytest.fail(
            f"fault barrier {fault!r} was not reached; returncode={process.returncode}, "
            f"stdout={stdout!r}, stderr={stderr!r}"
        )


def _run_shell(shell: str, harness: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [shell, "-c", harness, "resume-harness", "none", "/dev/null"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_journal_and_post_retirement_host_publish_survive_sigkill_matrix(
    tmp_path: Path,
) -> None:
    shell = _linux_root_shell()
    source = _source()
    helpers = "\n".join(
        (
            _shell_function(source, "validate_exact_incomplete_staging_file"),
            _shell_function(source, "discard_exact_incomplete_staging_file"),
        )
    )
    base_function = _shell_function(source, "write_adoption_journal")
    cuts = {
        "host_before_publish": (
            'mv -- "$host_after_retire_staging" "$persistent_host_after_retire" || exit 73',
            False,
        ),
        "journal_pending_before_publish": (
            'mv -- "$pending_adoption_journal" "$adoption_journal" || exit 73',
            False,
        ),
        "journal_final_after_publish": (
            'mv -- "$pending_adoption_journal" "$adoption_journal" || exit 73',
            True,
        ),
    }
    digest = "a" * 64

    def build_harness(
        function: str,
        *,
        state: Path,
        transaction: str,
        transaction_dir: Path,
        host_output: Path,
        backup: Path,
        baseline: Path,
        retirement_signature: Path,
        reconcile: Path,
        binding_key: Path,
    ) -> str:
        return f"""
set -eu
fault=$1
marker=$2
fault_barrier() {{
  [ "$fault" = "$1" ] || return 0
  : > "$marker"
  while :; do :; done
}}
offline_fail() {{ printf '%s\n' "$2" >&2; exit "$3"; }}
offline_validate_root_directory() {{ :; }}
validate_host_isolation_evidence() {{ [ -s "$1" ]; }}
validate_existing_adoption_journal() {{
  checked=${{1:-$adoption_journal}}
  [ -s "$checked" ] || exit 65
  journal_sha256=$(sha256sum "$checked" | awk '{{print $1}}')
}}
{helpers}
{function}
OFFLINE_STATE_DIRECTORY={_quote(state)}
adoption_transaction_id={transaction}
adoption_transaction_dir={_quote(transaction_dir)}
adoption_journal=$adoption_transaction_dir/journal.json
host_after_retire_output={_quote(host_output)}
backup_evidence={_quote(backup)}
host_isolation_baseline={_quote(baseline)}
retirement_signature={_quote(retirement_signature)}
reconcile_baseline_file={_quote(reconcile)}
legacy_binding_key={_quote(binding_key)}
confirmed_plan_sha256={digest}
contract_sha256={digest}
manifest_digest={digest}
legacy_source_schema_head=20260714_0019
target_schema_head=20260714_0020
retirement_digest={digest}
retirement_signature_digest={digest}
legacy_archive_manifest_digest={digest}
write_adoption_journal
"""

    for cut, (statement, after) in cuts.items():
        scenario = tmp_path / cut
        state = scenario / "state"
        state.mkdir(parents=True)
        host_output = scenario / "host-after.json"
        host_output.write_text('{"status":"PASS"}\n', encoding="utf-8")
        host_output.chmod(0o600)
        backup = scenario / "backup.json"
        backup.write_text("backup\n", encoding="utf-8")
        baseline = scenario / "baseline.json"
        baseline.write_text("baseline\n", encoding="utf-8")
        retirement_signature = scenario / "retirement.sig"
        retirement_signature.write_text("signature\n", encoding="utf-8")
        reconcile = scenario / "reconcile.json"
        reconcile.write_text("{}\n", encoding="utf-8")
        binding_key = scenario / "binding.key"
        binding_key.write_bytes(base64.urlsafe_b64encode(b"k" * 32))
        marker = scenario / "barrier"
        transaction = "b" * 32
        transaction_dir = state / "legacy-adoption/transactions" / transaction
        instrumented = _instrument(base_function, statement, cut, after=after)
        arguments = {
            "state": state,
            "transaction": transaction,
            "transaction_dir": transaction_dir,
            "host_output": host_output,
            "backup": backup,
            "baseline": baseline,
            "retirement_signature": retirement_signature,
            "reconcile": reconcile,
            "binding_key": binding_key,
        }

        _kill_at_barrier(
            shell, build_harness(instrumented, **arguments), marker, cut
        )
        resumed = _run_shell(shell, build_harness(base_function, **arguments))
        assert resumed.returncode == 0, resumed.stderr
        journal = transaction_dir / "journal.json"
        assert journal.is_file()
        assert (transaction_dir / "host-isolation-after-retire.json").is_file()
        assert not (transaction_dir / ".journal.write").exists()
        assert not (transaction_dir / ".journal.pending").exists()
        assert not (transaction_dir / ".host-isolation-after-retire.write").exists()

    partial = tmp_path / "partial-journal-write"
    state = partial / "state"
    state.mkdir(parents=True)
    transaction = "c" * 32
    adoption_root = state / "legacy-adoption"
    transactions_root = adoption_root / "transactions"
    transaction_dir = transactions_root / transaction
    for private_directory in (adoption_root, transactions_root, transaction_dir):
        private_directory.mkdir(mode=0o700)
        private_directory.chmod(0o700)
    staging = transaction_dir / ".journal.write"
    staging.write_bytes(b'{"payload":')
    staging.chmod(0o600)
    host_output = partial / "host-after.json"
    host_output.write_text('{"status":"PASS"}\n', encoding="utf-8")
    host_output.chmod(0o600)
    backup = partial / "backup.json"
    backup.write_text("backup\n", encoding="utf-8")
    baseline = partial / "baseline.json"
    baseline.write_text("baseline\n", encoding="utf-8")
    retirement_signature = partial / "retirement.sig"
    retirement_signature.write_text("signature\n", encoding="utf-8")
    reconcile = partial / "reconcile.json"
    reconcile.write_text("{}\n", encoding="utf-8")
    binding_key = partial / "binding.key"
    binding_key.write_bytes(base64.urlsafe_b64encode(b"m" * 32))
    recovered = _run_shell(
        shell,
        build_harness(
            base_function,
            state=state,
            transaction=transaction,
            transaction_dir=transaction_dir,
            host_output=host_output,
            backup=backup,
            baseline=baseline,
            retirement_signature=retirement_signature,
            reconcile=reconcile,
            binding_key=binding_key,
        ),
    )
    assert recovered.returncode == 0, recovered.stderr
    assert not staging.exists()
    assert (transaction_dir / "journal.json").is_file()


def test_archive_metadata_publish_survives_sigkill_matrix(tmp_path: Path) -> None:
    shell = _linux_root_shell()
    source = _source()
    helper_names = (
        "validate_exact_incomplete_staging_file",
        "discard_exact_incomplete_staging_file",
        "prepare_expected_archive_receipt",
        "validate_resumable_archive_distribution",
        "archive_one_legacy_receipt",
    )
    helpers = "\n".join(_shell_function(source, name) for name in helper_names)
    base_function = _shell_function(source, "archive_legacy_receipts")
    cuts = {
        "archive_receipts_manifest": (
            'mv -- "$archive_manifest_staging" "$archive_manifest" || exit 73',
            False,
        ),
        "archive_receipt": (
            'mv -- "$archive_receipt_staging" "$archive_receipt" || exit 73',
            False,
        ),
        "archive_signature": (
            'mv -- "$archive_signature_staging" "$archive_signature" || exit 73',
            False,
        ),
        "archive_top_manifest": (
            'mv -- "$archive_top_manifest_staging" "$archive_top_manifest" || exit 73',
            False,
        ),
        "archive_directory_published": (
            'mv -- "$archive_pending" "$archive_final" || exit 73',
            True,
        ),
    }
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
    identity_digest = "d" * 64

    for cut, (statement, after) in cuts.items():
        scenario = tmp_path / cut
        state = scenario / "state"
        state.mkdir(parents=True)
        receipt = state / "active-release.json"
        receipt.write_text('{"status":"committed"}\n', encoding="utf-8")
        receipt.chmod(0o400)
        receipt_digest = hashlib.sha256(receipt.read_bytes()).hexdigest()
        inventory = scenario / "inventory.sha256"
        inventory.write_text(
            f"{receipt_digest}  {receipt.as_posix()}\n", encoding="utf-8"
        )
        planned_receipts = scenario / "planned-receipts.sha256"
        planned_receipts.write_text(
            f"{receipt_digest}  {receipt.name}\n", encoding="utf-8"
        )
        planned_digest = hashlib.sha256(planned_receipts.read_bytes()).hexdigest()
        planned_manifest = scenario / "planned-manifest.sha256"
        planned_manifest.write_text(
            f"{planned_digest}  receipts.sha256\n", encoding="utf-8"
        )
        archive_root = state / "legacy-adoption/receipts"
        pending = archive_root / f".pending-{identity_digest}-{identity_digest}"
        final = archive_root / f"adopted-{identity_digest}-{identity_digest}"
        failed = archive_root / f"failed-{identity_digest}-{identity_digest}"
        expected_receipt = scenario / "expected-archive-receipt.json"
        marker = scenario / "barrier"
        instrumented = _instrument(base_function, statement, cut, after=after)

        def build_harness(
            function: str,
            *,
            state: Path = state,
            archive_root: Path = archive_root,
            pending: Path = pending,
            final: Path = final,
            failed: Path = failed,
            inventory: Path = inventory,
            planned_receipts: Path = planned_receipts,
            planned_manifest: Path = planned_manifest,
            expected_receipt: Path = expected_receipt,
        ) -> str:
            return f"""
set -eu
fault=$1
marker=$2
fault_barrier() {{
  [ "$fault" = "$1" ] || return 0
  : > "$marker"
  while :; do :; done
}}
offline_fail() {{ printf '%s\n' "$2" >&2; exit "$3"; }}
offline_validate_root_directory() {{ [ -d "$2" ] && [ ! -L "$2" ]; }}
validate_protected_file() {{ [ -f "$2" ] && [ ! -L "$2" ]; }}
{helpers}
{function}
OFFLINE_STATE_DIRECTORY={_quote(state)}
archive_root={_quote(archive_root)}
archive_pending={_quote(pending)}
archive_final={_quote(final)}
archive_failed={_quote(failed)}
receipt_inventory={_quote(inventory)}
planned_receipts_manifest={_quote(planned_receipts)}
planned_archive_manifest={_quote(planned_manifest)}
expected_archive_receipt={_quote(expected_receipt)}
confirmed_plan_sha256={identity_digest}
contract_sha256={identity_digest}
retirement_digest={identity_digest}
retirement_signature_digest={identity_digest}
evidence_signing_key={_quote(private_key)}
evidence_public_key={_quote(public_key)}
archive_started=false
archive_legacy_receipts
"""

        _kill_at_barrier(shell, build_harness(instrumented), marker, cut)
        resumed = _run_shell(shell, build_harness(base_function))
        assert resumed.returncode == 0, resumed.stderr
        assert final.is_dir()
        assert not pending.exists()
        assert not receipt.exists()
        assert {item.name for item in final.iterdir()} == {
            "active-release.json",
            "receipts.sha256",
            "manifest.sha256",
            "adoption-receipt.json",
            "adoption-receipt.sig",
        }
        verified = subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(public_key),
                "-signature",
                str(final / "adoption-receipt.sig"),
                str(final / "adoption-receipt.json"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert verified.returncode == 0, verified.stderr


def test_completion_publish_survives_sigkill_matrix(tmp_path: Path) -> None:
    shell = _linux_root_shell()
    source = _source()
    helpers = "\n".join(
        (
            _shell_function(source, "validate_exact_incomplete_staging_file"),
            _shell_function(source, "discard_exact_incomplete_staging_file"),
        )
    )
    base_function = _shell_function(source, "publish_completion_receipt")
    cuts = {
        "completion_host": (
            'mv -- "$completion_host_staging" "$persistent_host_final" || exit 73',
            False,
        ),
        "completion_receipt": (
            'mv -- "$completion_receipt_staging" "$completion_receipt" || exit 73',
            False,
        ),
        "completion_signature": (
            'mv -- "$completion_signature_staging" "$completion_signature" || exit 73',
            False,
        ),
        "completion_before_publish": (
            'mv -- "$completion_pending" "$completion_final" || exit 73',
            False,
        ),
        "completion_after_publish": (
            'mv -- "$completion_pending" "$completion_final" || exit 73',
            True,
        ),
    }
    private_key = tmp_path / "completion-signing.pem"
    public_key = tmp_path / "completion-public.pem"
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
    digest = "e" * 64

    for cut, (statement, after) in cuts.items():
        scenario = tmp_path / cut
        state = scenario / "state"
        transaction_dir = scenario / "transaction"
        state.mkdir(parents=True)
        transaction_dir.mkdir(mode=0o700)
        installed = state / f"installed-{digest}.json"
        installed.write_text('{"phase":"completed"}\n', encoding="utf-8")
        installed.chmod(0o400)
        active = state / "active-release.json"
        active.write_text('{"status":"committed"}\n', encoding="utf-8")
        active.chmod(0o400)
        host_output = scenario / "host-final.json"
        host_output.write_text('{"status":"PASS"}\n', encoding="utf-8")
        host_output.chmod(0o600)
        marker = scenario / "barrier"
        instrumented = _instrument(base_function, statement, cut, after=after)

        def build_harness(
            function: str,
            *,
            state: Path = state,
            transaction_dir: Path = transaction_dir,
            host_output: Path = host_output,
        ) -> str:
            return f"""
set -eu
fault=$1
marker=$2
fault_barrier() {{
  [ "$fault" = "$1" ] || return 0
  : > "$marker"
  while :; do :; done
}}
offline_fail() {{ printf '%s\n' "$2" >&2; exit "$3"; }}
validate_journal_bound_install_document() {{ :; }}
validate_target_active_release() {{ :; }}
validate_pending_adoption_completion_state() {{ :; }}
validate_host_isolation_evidence() {{ [ -s "$1" ]; }}
validate_adoption_completion_payload() {{ [ -s "$1" ] && [ -s "$2" ]; }}
validate_adoption_completion_directory() {{ [ -d "$1" ]; }}
validate_protected_file() {{ [ -f "$2" ] && [ ! -L "$2" ]; }}
{helpers}
{function}
OFFLINE_STATE_DIRECTORY={_quote(state)}
adoption_transaction_dir={_quote(transaction_dir)}
contract_sha256={digest}
manifest_digest={digest}
adoption_transaction_id={'f' * 32}
journal_sha256={digest}
confirmed_plan_sha256={digest}
retirement_digest={digest}
retirement_signature_digest={digest}
legacy_source_schema_head=20260714_0019
target_schema_head=20260714_0020
legacy_archive_manifest_digest={digest}
host_final_output={_quote(host_output)}
evidence_signing_key={_quote(private_key)}
evidence_public_key={_quote(public_key)}
transaction_committed=false
publish_completion_receipt
"""

        _kill_at_barrier(shell, build_harness(instrumented), marker, cut)
        resumed = _run_shell(shell, build_harness(base_function))
        assert resumed.returncode == 0, resumed.stderr
        completion = transaction_dir / "completion"
        assert transaction_dir.joinpath(".completion.pending").exists() is False
        assert {item.name for item in completion.iterdir()} == {
            "host-isolation-final.json",
            "receipt.json",
            "receipt.sig",
        }
        verified = subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(public_key),
                "-signature",
                str(completion / "receipt.sig"),
                str(completion / "receipt.json"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert verified.returncode == 0, verified.stderr


@pytest.mark.parametrize(
    ("completion_name", "abort_name"),
    (
        ("completion", "target-pre-migration-abort"),
        ("completion", ".target-pre-migration-abort.pending"),
        (".completion.pending", "target-pre-migration-abort"),
        (".completion.pending", ".target-pre-migration-abort.pending"),
    ),
)
def test_completion_and_abort_cross_family_states_fail_before_mutation(
    tmp_path: Path,
    completion_name: str,
    abort_name: str,
) -> None:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")
    transaction = tmp_path / "transaction"
    state = tmp_path / "state"
    transaction.mkdir()
    state.mkdir()
    (transaction / completion_name).mkdir()
    (transaction / abort_name).mkdir()
    classifier = _shell_function(_source(), "classify_journal_bound_target_state")
    mutation_marker = tmp_path / "mutation"
    harness = f"""
set -eu
offline_fail() {{ printf '%s\n' "$2" >&2; exit "$3"; }}
run_target_install() {{ : > {_quote(mutation_marker)}; }}
{classifier}
OFFLINE_STATE_DIRECTORY={_quote(state)}
adoption_transaction_dir={_quote(transaction)}
contract_sha256={'1' * 64}
transaction_committed=false
classify_journal_bound_target_state
run_target_install
"""
    completed = subprocess.run(
        [shell, "-c", harness, "classifier"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 65
    assert "completion and target abort states coexist" in completed.stderr
    assert not mutation_marker.exists()


def test_predictive_completion_staging_validation_is_read_only(tmp_path: Path) -> None:
    shell = _linux_root_shell()
    source = _source()
    validator = "\n".join(
        (
            _shell_function(source, "validate_exact_incomplete_staging_file"),
            _shell_function(source, "validate_pending_adoption_completion_state"),
        )
    )
    pending = tmp_path / ".completion.pending"
    pending.mkdir(mode=0o700)
    staging_paths = [
        pending / ".host-isolation-final.write",
        pending / ".receipt.write",
        pending / ".receipt.sig.write",
    ]
    for index, path in enumerate(staging_paths):
        path.write_bytes(f"partial-{index}".encode())
        path.chmod(0o600)
    before = {
        path.name: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in staging_paths
    }
    harness = f"""
set -eu
offline_fail() {{ printf '%s\n' "$2" >&2; exit "$3"; }}
offline_validate_root_directory() {{ :; }}
validate_host_isolation_evidence() {{ exit 99; }}
validate_adoption_completion_payload() {{ exit 99; }}
validate_protected_file() {{ exit 99; }}
{validator}
validate_pending_adoption_completion_state {_quote(pending)}
"""
    completed = subprocess.run(
        [shell, "-c", harness, "predictive"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    after = {
        path.name: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in staging_paths
    }
    assert after == before
    classifier = _shell_function(source, "classify_journal_bound_target_state")
    publish = _shell_function(source, "publish_completion_receipt")
    pending_validator = _shell_function(
        source, "validate_pending_adoption_completion_state"
    )
    assert "discard_exact_incomplete_staging_file" not in pending_validator
    assert "validate_pending_adoption_completion_state" in classifier
    assert "discard_exact_incomplete_staging_file" in publish


def test_archive_failed_and_no_archive_states_restore_idempotently(tmp_path: Path) -> None:
    shell = _linux_root_shell()
    source = _source()
    functions = "\n".join(
        (
            _shell_function(source, "validate_exact_legacy_receipt_for_restore"),
            _shell_function(source, "restore_archived_receipts"),
        )
    )

    def run_restore(
        *, state: Path, inventory: Path, pending: Path, final: Path, failed: Path
    ) -> subprocess.CompletedProcess[str]:
        harness = f"""
set -eu
offline_validate_root_directory() {{ :; }}
{functions}
archive_started=true
OFFLINE_STATE_DIRECTORY={_quote(state)}
receipt_inventory={_quote(inventory)}
archive_pending={_quote(pending)}
archive_final={_quote(final)}
archive_failed={_quote(failed)}
archive_root={_quote(failed.parent)}
restore_archived_receipts
"""
        return subprocess.run(
            [shell, "-c", harness, "restore"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    failed_case = tmp_path / "failed-case"
    state = failed_case / "state"
    failed = failed_case / "archive/failed"
    state.mkdir(parents=True)
    failed.mkdir(parents=True, mode=0o700)
    inventory = failed_case / "inventory"
    lines: list[str] = []
    for name in ("active-release.json", "installed-" + "2" * 64 + ".json"):
        source_receipt = failed / name
        source_receipt.write_text(f"{name}\n", encoding="utf-8")
        source_receipt.chmod(0o400)
        digest = hashlib.sha256(source_receipt.read_bytes()).hexdigest()
        lines.append(f"{digest}  {(state / name).as_posix()}\n")
    inventory.write_text("".join(lines), encoding="utf-8")
    already_restored = state / "active-release.json"
    shutil.copyfile(failed / already_restored.name, already_restored)
    already_restored.chmod(0o400)
    pending = failed_case / "archive/pending"
    final = failed_case / "archive/final"
    first = run_restore(
        state=state,
        inventory=inventory,
        pending=pending,
        final=final,
        failed=failed,
    )
    assert first.returncode == 0, first.stderr
    second = run_restore(
        state=state,
        inventory=inventory,
        pending=pending,
        final=final,
        failed=failed,
    )
    assert second.returncode == 0, second.stderr
    assert failed.is_dir()
    for line in lines:
        digest, path = line.strip().split("  ", 1)
        restored = Path(path)
        assert hashlib.sha256(restored.read_bytes()).hexdigest() == digest

    no_archive_case = tmp_path / "no-archive-case"
    live_state = no_archive_case / "state"
    live_state.mkdir(parents=True)
    live_receipt = live_state / "active-release.json"
    live_receipt.write_text("live\n", encoding="utf-8")
    live_receipt.chmod(0o400)
    live_digest = hashlib.sha256(live_receipt.read_bytes()).hexdigest()
    live_inventory = no_archive_case / "inventory"
    live_inventory.write_text(
        f"{live_digest}  {live_receipt.as_posix()}\n", encoding="utf-8"
    )
    no_archive = run_restore(
        state=live_state,
        inventory=live_inventory,
        pending=no_archive_case / "archive/pending",
        final=no_archive_case / "archive/final",
        failed=no_archive_case / "archive/failed",
    )
    assert no_archive.returncode == 0, no_archive.stderr
    assert live_receipt.read_text(encoding="utf-8") == "live\n"


@pytest.mark.parametrize("drift", ("resources", "reconcile", "host"))
def test_terminal_abort_current_drift_fails_before_legacy_reactivation(
    tmp_path: Path,
    drift: str,
) -> None:
    shell = _linux_root_shell()
    function = _shell_function(_source(), "verify_terminal_abort_receipt")
    transaction = tmp_path / "transaction"
    abort_directory = transaction / "target-pre-migration-abort"
    abort_directory.mkdir(parents=True, mode=0o700)
    baseline = tmp_path / "reconcile-baseline.json"
    baseline.write_text("{}\n", encoding="utf-8")
    after = tmp_path / "reconcile-after.json"
    host = abort_directory / "host-isolation-after-abort.json"
    host.write_text('{"status":"PASS"}\n', encoding="utf-8")
    host.chmod(0o400)
    host_digest = hashlib.sha256(host.read_bytes()).hexdigest()
    digest = "3" * 64
    transaction_id = "4" * 32
    receipt = abort_directory / "receipt.json"
    payload = {
        "schema_version": 1,
        "kind": "heyi-target-pre-migration-abort-receipt",
        "status": "aborted_pre_migration",
        "project": "heyi-kb-offline",
        "issued_at": "2026-07-15T00:00:00Z",
        "adoption_transaction_id": transaction_id,
        "journal_sha256": digest,
        "plan_sha256": digest,
        "retirement_receipt_sha256": digest,
        "target_contract_sha256": digest,
        "target_manifest_sha256": digest,
        "legacy_source_schema_head": "20260714_0019",
        "target_schema_head": "20260714_0020",
        "last_install_phase": "preflight_passed",
        "migration_command_invoked": False,
        "active_release_present": False,
        "installed_receipt_present": False,
        "removed_preflight_container_ids": [],
        "removed_owner_marker_volume": True,
        "archived_install_state": None,
        "archived_cutover_intent": None,
        "reconcile_baseline": {},
        "reconcile_result": {},
        "target_resource_counts_after": {
            "containers": 0,
            "networks": 0,
            "project_volumes": 0,
            "owner_marker": 0,
        },
        "host_isolation_verification": {
            "status": "PASS",
            "path": host.as_posix(),
            "sha256": host_digest,
        },
        "preserved_bind_root": "/srv/heyi-knowledgebases-offline/data",
        "bind_data_deleted": False,
        "named_volumes_deleted": False,
        "global_actions": [],
        "restore_boundary": "PRE_MIGRATION_ONLY",
    }
    receipt.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    receipt.chmod(0o400)
    private_key = tmp_path / "abort-signing.pem"
    public_key = tmp_path / "abort-public.pem"
    signature_path = abort_directory / "receipt.sig"
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
    subprocess.run(
        [
            "/usr/bin/openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(private_key),
            "-out",
            str(signature_path),
            str(receipt),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    signature_path.chmod(0o400)
    reactivated = tmp_path / "reactivated"
    resource_result = "1" if drift == "resources" else "0"
    reconcile_command = (
        f"printf '%s\\n' '{{\"drift\":true}}' > {_quote(after)}"
        if drift == "reconcile"
        else f"cp {_quote(baseline)} {_quote(after)}"
    )
    host_result = "1" if drift == "host" else "0"
    harness = f"""
set -eu
offline_fail() {{ printf '%s\n' "$2" >&2; exit "$3"; }}
offline_validate_root_directory() {{ :; }}
validate_protected_file() {{ [ -f "$2" ] && [ ! -L "$2" ]; }}
assert_target_resources_absent() {{ return {resource_result}; }}
capture_reconcile_baseline() {{ {reconcile_command}; }}
verify_host_isolation() {{ return {host_result}; }}
reactivate_legacy() {{ : > {_quote(reactivated)}; }}
{function}
adoption_transaction_dir={_quote(transaction)}
evidence_public_key={_quote(public_key)}
adoption_transaction_id={transaction_id}
journal_sha256={digest}
confirmed_plan_sha256={digest}
retirement_digest={digest}
contract_sha256={digest}
manifest_digest={digest}
legacy_source_schema_head=20260714_0019
target_schema_head=20260714_0020
reconcile_baseline_file={_quote(baseline)}
reconcile_after_abort_file={_quote(after)}
abort_independent_host_output={_quote(tmp_path / 'current-host.json')}
verify_terminal_abort_receipt
reactivate_legacy
"""
    completed = subprocess.run(
        [shell, "-c", harness, "terminal-abort"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 69
    assert not reactivated.exists()
    expected_error = {
        "resources": "target resources reappeared",
        "reconcile": "reconcile state drifted",
        "host": "host isolation drifted",
    }[drift]
    assert expected_error in completed.stderr


@pytest.mark.parametrize("abort_state", ("pending", "final"))
def test_fresh_abort_state_routes_restore_before_archive_or_install(
    tmp_path: Path,
    abort_state: str,
) -> None:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")
    function = _shell_function(_source(), "run_adoption_orchestrator")
    transaction = tmp_path / abort_state
    transaction.mkdir()
    final_abort = transaction / "target-pre-migration-abort"
    if abort_state == "final":
        final_abort.mkdir()
    else:
        (transaction / ".target-pre-migration-abort.pending").mkdir()
    log = tmp_path / f"{abort_state}.log"
    harness = f"""
set -eu
log={_quote(log)}
record() {{ printf '%s\n' "$1" >> "$log"; }}
offline_fail() {{ record "terminal:$3"; exit "$3"; }}
predictive_target_preflight() {{ target_adoption_state=target_abort_needs_reactivation; }}
prepare_target_install_contract() {{ record prepare; }}
retire_legacy() {{ record unexpected-retire; }}
verify_retirement_receipt() {{ record verify-retirement; }}
verify_host_isolation() {{ record verify-host; }}
prepare_signed_receipt_inventory() {{ record inventory; }}
write_adoption_journal() {{ record journal; }}
abort_target_pre_migration() {{
  record abort-close
  rm -rf -- "$adoption_transaction_dir/.target-pre-migration-abort.pending"
  mkdir "$adoption_transaction_dir/target-pre-migration-abort"
}}
restore_archived_receipts() {{ record restore; }}
reactivate_legacy() {{ record reactivate; }}
archive_legacy_receipts() {{ record unexpected-archive; }}
run_target_install() {{ record unexpected-install; }}
publish_completion_receipt() {{ record unexpected-completion; }}
{function}
execute_requested=true
resume_journal_present=true
legacy_retired=false
archive_started=false
transaction_terminal_aborted=false
transaction_committed=false
adoption_transaction_dir={_quote(transaction)}
host_after_retire_output={_quote(tmp_path / 'host-after-retire.json')}
run_adoption_orchestrator
"""
    completed = subprocess.run(
        [shell, "-c", harness, "abort-routing"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 75
    actions = log.read_text(encoding="utf-8").splitlines()
    assert actions.index("restore") < actions.index("reactivate")
    if abort_state == "pending":
        assert actions.index("abort-close") < actions.index("restore")
    else:
        assert "abort-close" not in actions
    assert not any(action.startswith("unexpected-") for action in actions)


def test_completed_adoption_retry_never_invokes_install_or_migration(tmp_path: Path) -> None:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")
    function = _shell_function(_source(), "run_adoption_orchestrator")
    migration_count = tmp_path / "migration-count"
    migration_count.write_text("0\n", encoding="utf-8")
    harness = f"""
set -eu
offline_fail() {{ exit "$3"; }}
predictive_target_preflight() {{ target_adoption_state=adoption_completed; }}
prepare_target_install_contract() {{ :; }}
retire_legacy() {{ exit 91; }}
verify_retirement_receipt() {{ :; }}
verify_host_isolation() {{ :; }}
prepare_signed_receipt_inventory() {{ :; }}
write_adoption_journal() {{ :; }}
archive_legacy_receipts() {{ :; }}
run_target_install() {{
  count=$(cat {_quote(migration_count)})
  printf '%s\n' "$((count + 1))" > {_quote(migration_count)}
}}
publish_completion_receipt() {{ exit 92; }}
{function}
execute_requested=true
resume_journal_present=true
legacy_retired=false
transaction_committed=false
host_after_retire_output={_quote(tmp_path / 'host-after-retire.json')}
host_final_output={_quote(tmp_path / 'host-final.json')}
run_adoption_orchestrator
"""
    for _ in range(2):
        completed = subprocess.run(
            [shell, "-c", harness, "completed-retry"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert completed.returncode == 0, completed.stderr
    assert migration_count.read_text(encoding="utf-8") == "0\n"


def test_active_provider_drift_fails_before_install_mutation(tmp_path: Path) -> None:
    shell = _linux_root_shell()
    function = _shell_function(_source(), "validate_target_active_release")
    state = tmp_path / "state"
    contract = tmp_path / "contract"
    state.mkdir()
    contract.mkdir()
    for name, content in (
        ("runtime.env", "runtime\n"),
        ("release.env", "release\n"),
        ("release.env.images", "images\n"),
    ):
        (contract / name).write_text(content, encoding="utf-8")
    contract_digest = "5" * 64
    compose_digest = "6" * 64
    inventory_digest = "7" * 64
    egress_digest = "8" * 64
    active = {
        "schema_version": 2,
        "kind": "offline-active-release",
        "project_name": "heyi-kb-offline",
        "transaction_id": "9" * 32,
        "contract_sha256": contract_digest,
        "runtime_sha256": hashlib.sha256(
            (contract / "runtime.env").read_bytes()
        ).hexdigest(),
        "release_sha256": hashlib.sha256(
            (contract / "release.env").read_bytes()
        ).hexdigest(),
        "manifest_sha256": hashlib.sha256(
            (contract / "release.env.images").read_bytes()
        ).hexdigest(),
        "compose_profile": "controlled-egress",
        "compose_config_sha256": compose_digest,
        "project_inventory_sha256": inventory_digest,
        "egress_proof_sha256": egress_digest,
        "active_provider_snapshot": "deepseek",
        "status": "committed",
    }
    active_path = state / "active-release.json"
    active_path.write_text(
        json.dumps(active, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    active_path.chmod(0o400)
    mutation = tmp_path / "mutation"
    harness = f"""
set -eu
offline_fail() {{ printf '%s\n' "$2" >&2; exit "$3"; }}
validate_protected_file() {{ [ -f "$2" ]; }}
offline_project_inventory_digest() {{ printf '%s\n' {inventory_digest}; }}
offline_compose_config_digest() {{ printf '%s\n' {compose_digest}; }}
offline_receipt_profile() {{ printf '%s\n' controlled-egress; }}
offline_egress_proof_fields() {{ printf '%s %s\n' {egress_digest} qwen; }}
run_target_install() {{ : > {_quote(mutation)}; }}
{function}
OFFLINE_STATE_DIRECTORY={_quote(state)}
contract_dir={_quote(contract)}
contract_sha256={contract_digest}
validate_target_active_release
run_target_install
"""
    completed = subprocess.run(
        [shell, "-c", harness, "provider-drift"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 65
    assert "active target release differs" in completed.stderr
    assert not mutation.exists()
