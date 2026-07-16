from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
ADOPTION_SCRIPT = REPOSITORY / "deploy/tencent/adopt-offline.sh"
COMMON_SCRIPT = REPOSITORY / "deploy/tencent/offline-operation-common.sh"
CONTRACT_SCRIPT = REPOSITORY / "deploy/tencent/prepare-offline-contract.sh"


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    following = re.search(r"\n[A-Za-z_][A-Za-z0-9_]*\(\) \{\n", source[start + 1 :])
    end = source.index(f"\n{name}\n", start) if following is None else start + 1 + following.start()
    return source[start:end].rstrip() + "\n"


def test_adoption_entrypoint_is_part_of_the_signed_materialized_contract() -> None:
    common = _source(COMMON_SCRIPT)
    contract = _source(CONTRACT_SCRIPT)
    canonical_listing = common.split("cat <<'EOF'\n", 1)[1].split("\nEOF", 1)[0]
    canonical_entries = canonical_listing.splitlines()

    for path in (
        "deploy/tencent/adopt-offline.sh",
        "deploy/tencent/offline-pre-migration-abort.py",
        "scripts/legacy_offline_adoption.py",
        "scripts/host_isolation_guard.py",
    ):
        assert f"release/{path}" in canonical_entries
    assert len(canonical_entries) == len(set(canonical_entries))
    assert contract.count("offline_contract_files") == 1
    assert 'offline_contract_files > "$contract_paths"' in contract
    assert 'copy_release_asset "$relative_path"' in contract
    assert "for release_asset in" not in contract
    assert "contract snapshot inventory differs from the canonical contract" in contract
    assert "find \"$contract_dir\" -type f -printf '%P\\n'" in contract


def test_adoption_transaction_has_one_inherited_project_lock() -> None:
    source = _source(ADOPTION_SCRIPT)

    assert '. "$script_dir/offline-operation-common.sh"' in source
    assert "offline_acquire_lock adoption" in source
    assert "KB_OFFLINE_LOCK_HELD=$OFFLINE_LOCK_TOKEN" in _source(COMMON_SCRIPT)
    assert 'exec sh "$materialized_entry"' in source


def test_production_adoption_pins_an_independent_evidence_trust_root() -> None:
    source = _source(ADOPTION_SCRIPT)
    argument_parser = source.split('while [ "$#" -gt 0 ]; do', 1)[1].split(
        'case "$confirmed_plan_sha256"', 1
    )[0]

    assert (
        "trusted_adoption_evidence_public_key=/etc/heyi-adoption/trusted-evidence-public.pem"
    ) in source
    assert (
        "trusted_adoption_evidence_signing_key=/run/heyi-adoption-signing/evidence-signing.key"
    ) in source
    assert "evidence_public_key=$trusted_adoption_evidence_public_key" in source
    assert "evidence_signing_key=$trusted_adoption_evidence_signing_key" in source
    assert "--evidence-public-key" not in argument_parser
    assert "--evidence-signing-key" not in argument_parser
    assert "validate_adoption_evidence_trust_root" in source
    assert (
        'validate-evidence-trust-root \\\n    --challenge-context-sha256 "$confirmed_plan_sha256"'
    ) in source
    assert "adoption-evidence-key-pair.challenge" not in source
    assert "adoption-evidence-key-pair.sig" not in source


def test_production_adoption_rejects_an_operator_selected_key_pair(
    tmp_path: Path,
) -> None:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")
    attacker_public = tmp_path / "attacker.pub"
    attacker_private = tmp_path / "attacker.key"
    attacker_public.write_text("attacker public key\n", encoding="utf-8")
    attacker_private.write_text("attacker private key\n", encoding="utf-8")

    rejected = subprocess.run(
        [
            shell,
            str(ADOPTION_SCRIPT),
            "--evidence-public-key",
            str(attacker_public),
            "--evidence-signing-key",
            str(attacker_private),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert rejected.returncode == 64
    assert "usage: adopt-offline.sh" in rejected.stderr


def test_adoption_trust_attacks_have_zero_downstream_mutations() -> None:
    source = _source(ADOPTION_SCRIPT)
    entry_gate = "\nvalidate_adoption_evidence_trust_root\noffline_acquire_lock adoption\n"
    assert entry_gate in source
    gate_position = source.index(entry_gate)

    mutation_boundaries = (
        "offline_acquire_lock adoption",
        'prepare-offline-contract.sh" \\\n    "$runtime_source" "$release_source"',
        "offline_materialize_release adoption",
        'mktemp -d "$OFFLINE_TMPDIR/adoption.',
        "capture_reconcile_baseline",
        "verify_backup_evidence_for_transaction_state",
        "docker ps",
        "systemctl",
        "retire_legacy",
        "write_adoption_journal",
    )
    reached_before_gate = [
        token for token in mutation_boundaries if source.index(token) < gate_position
    ]

    assert reached_before_gate == []
    validator = source.split("validate_adoption_evidence_trust_root() {", 1)[1].split(
        "\n}\n\n# The signer", 1
    )[0]
    assert "validate-evidence-trust-root" in validator
    assert "--challenge-context-sha256" in validator
    assert "mktemp" not in validator
    assert ">" not in validator.replace(">/dev/null", "")


def test_predictive_gates_run_before_exact_legacy_retirement() -> None:
    source = _source(ADOPTION_SCRIPT)

    assert source.index("predictive_target_preflight") < source.index("retire_legacy")
    predictive = source.split("predictive_target_preflight() {", 1)[1].split(
        "\nretire_legacy() {", 1
    )[0]
    for required in (
        "trusted_environment_validator",
        "verify_backup_evidence_for_transaction_state",
        "trusted_image_verifier",
        "verify_host_isolation",
        "validate_registry_release_receipts",
        "offline_verify_release_assets",
        "config --quiet",
    ):
        assert required in predictive
    assert 'receipt["release_schema_head"]' in source
    assert "trusted_backup_verifier" in source
    assert "target_schema_head=$(/usr/bin/python3" in source
    assert 'receipt["release_schema_head"] == "20260714_0020"' not in source


def test_legacy_commands_use_the_pinned_signed_cli_contract() -> None:
    source = _source(ADOPTION_SCRIPT)

    assert "trusted_legacy_tool=$OFFLINE_RELEASE_ROOT/scripts/legacy_offline_adoption.py" in source
    assert '/usr/bin/python3 -I "$trusted_legacy_tool" retire' in source
    assert '/usr/bin/python3 -I "$trusted_legacy_tool" reactivate' in source
    reactivate = source.split("reactivate_legacy() {", 1)[1].split("\n}", 1)[0]
    for argument in (
        '--retirement-receipt "$retirement_receipt"',
        '--retirement-signature "$retirement_signature"',
        '--target-abort-receipt "$abort_receipt"',
        '--target-abort-signature "$abort_signature"',
        '--adoption-transaction "$adoption_transaction_id"',
        '--host-isolation-baseline "$host_isolation_baseline"',
        '--host-isolation-hmac-key "$host_isolation_hmac_key"',
        "--confirm-restore-boundary PRE_MIGRATION_ONLY",
        '--confirm-project "$OFFLINE_PROJECT_NAME"',
        '--confirm-plan-sha256 "$confirmed_plan_sha256"',
    ):
        assert argument in reactivate


def test_retirement_receipt_and_old_state_are_hashed_and_archived() -> None:
    source = _source(ADOPTION_SCRIPT)

    assert "verify_retirement_receipt" in source
    assert 'document.get("schema_version") == 2' in source
    assert 'document.get("restore_boundary") == "PRE_MIGRATION_ONLY"' in source
    archive = source.split("archive_legacy_receipts() {", 1)[1].split(
        "\nrestore_archived_receipts() {", 1
    )[0]
    assert "sha256sum" in archive
    assert "receipts.sha256" in archive
    assert "mv --" in archive
    assert "sync -f" in archive
    assert "rm -f" not in archive
    assert "rm -rf" not in archive


def test_partial_legacy_receipt_archive_is_recoverable_without_deletion() -> None:
    source = _source(ADOPTION_SCRIPT)
    restore = source.split("restore_archived_receipts() {", 1)[1].split(
        "\nreactivate_legacy() {", 1
    )[0]

    assert "archive_started=true" in source
    for recoverable_state in (
        '"$archive_pending:pending"',
        '"$archive_final:final"',
        '"$archive_failed:failed"',
    ):
        assert recoverable_state in restore
    assert '[ "$source_count" -eq 1 ]' in restore
    assert '[ "$source_kind" = pending ]' in restore
    assert 'done < "$receipt_inventory"' in restore
    assert "sha256sum" in restore
    assert "sync -f" in restore
    assert "rm -f" not in restore
    assert "rm -rf" not in restore


def test_retirement_receipt_state_classifier_executes_fresh_intent_and_final(
    tmp_path: Path,
) -> None:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")
    classifier = _shell_function(_source(ADOPTION_SCRIPT), "classify_retirement_receipt_state")
    receipt = tmp_path / "receipt.json"
    signature = tmp_path / "receipt.sig"
    intent = tmp_path / ".retirement-in-progress"
    harness = f"""
offline_fail() {{ printf '%s\\n' "$2" >&2; exit "$3"; }}
{classifier}
classify_retirement_receipt_state "$1" "$2" "$3"
printf '%s %s\\n' "$retirement_already_published" "$retirement_resume_pending"
"""

    def classify() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                shell,
                "-c",
                harness,
                "classifier",
                *map(lambda path: path.as_posix(), (receipt, signature, intent)),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    assert classify().stdout.strip() == "false false"
    intent.mkdir()
    assert classify().stdout.strip() == "false true"
    intent.rmdir()
    receipt.write_text("{}\n", encoding="utf-8")
    signature.write_bytes(b"signature")
    assert classify().stdout.strip() == "true false"
    signature.unlink()
    incomplete = classify()
    assert incomplete.returncode == 65
    assert "receipt pair is incomplete" in incomplete.stderr


def test_archive_move_survives_process_kill_and_exact_retry(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("SIGKILL process-tree semantics require Linux; Git Bash leaves a wrapper child")
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")
    function = _shell_function(_source(ADOPTION_SCRIPT), "archive_one_legacy_receipt")
    state = tmp_path / "state"
    pending = tmp_path / "pending"
    state.mkdir()
    pending.mkdir()
    receipt = state / "active-release.json"
    receipt.write_text('{"status":"committed"}\n', encoding="utf-8")
    receipt.chmod(0o400)
    digest = hashlib.sha256(receipt.read_bytes()).hexdigest()
    marker = tmp_path / "entered-sync"
    harness = f"""
offline_fail() {{ printf '%s\\n' "$2" >&2; exit "$3"; }}
validate_protected_file() {{ [ -f "$2" ] && [ ! -L "$2" ] || exit 65; }}
marker_path=$4
if [ "$5" = pause ]; then
  sync() {{ : > "$marker_path"; while :; do :; done; }}
else
  sync() {{ :; }}
fi
{function}
archive_pending=$1
OFFLINE_STATE_DIRECTORY=$2
archive_one_legacy_receipt "$6" "$3"
"""
    command = [
        shell,
        "-c",
        harness,
        "archive-harness",
        pending.as_posix(),
        state.as_posix(),
        receipt.as_posix(),
        marker.as_posix(),
    ]
    interrupted = subprocess.Popen(
        [*command, "pause", digest],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout = ""
    stderr = ""
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not marker.exists():
            if interrupted.poll() is not None:
                break
            time.sleep(0.02)
    finally:
        if interrupted.poll() is None:
            interrupted.kill()
        stdout, stderr = interrupted.communicate(timeout=10)
    if not marker.exists():
        pytest.fail(
            "archive worker did not reach its post-move durability barrier; "
            f"returncode={interrupted.returncode}, stdout={stdout!r}, stderr={stderr!r}"
        )

    archived = pending / receipt.name
    assert archived.is_file()
    assert not receipt.exists()
    resumed = subprocess.run(
        [*command, "resume", digest],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert resumed.returncode == 0, resumed.stderr
    assert archived.read_text(encoding="utf-8") == '{"status":"committed"}\n'


def test_resume_is_bound_to_same_deterministic_transaction_and_fails_closed() -> None:
    source = _source(ADOPTION_SCRIPT)
    discovery = _shell_function(source, "discover_adoption_resume_state")

    assert "heyi-adoption-transaction-id-v1" in source
    assert "resume_journal_present=true" in discovery
    assert "journal exists without one unambiguous final retirement receipt" in discovery
    assert "archive state exists without its HMAC journal" in discovery
    assert "failed receipt archive state requires a new signed adoption plan" in source
    assert "receipt archive distribution is ambiguous or tampered" in source
    assert "actual_names <= set(entries) | metadata_names" in source
    assert "len(locations) != 1" in source


def test_freshness_is_required_only_before_a_durable_retirement_state(
    tmp_path: Path,
) -> None:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")
    source = _source(ADOPTION_SCRIPT)
    selector = _shell_function(source, "verify_backup_evidence_for_transaction_state")
    harness = f"""
verify_durable_backup_evidence() {{ printf durable; }}
verify_fresh_backup_evidence() {{ printf fresh; }}
{selector}
retirement_already_published=$1
retirement_resume_pending=$2
resume_journal_present=$3
verify_backup_evidence_for_transaction_state
"""

    def select(final: bool, intent: bool, journal: bool) -> str:
        completed = subprocess.run(
            [
                shell,
                "-c",
                harness,
                "freshness-selector",
                str(final).lower(),
                str(intent).lower(),
                str(journal).lower(),
            ],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return completed.stdout

    assert select(False, False, False) == "fresh"
    assert select(False, True, False) == "durable"
    assert select(True, False, False) == "durable"
    assert select(True, False, True) == "durable"


def test_durable_resume_has_no_wall_clock_expiry_but_rehashes_every_artifact() -> None:
    source = _source(ADOPTION_SCRIPT)
    verifier = (ADOPTION_SCRIPT.parent / "verify-upgrade-backup.py").read_text(encoding="utf-8")
    durable = source.split("verify_durable_backup_evidence() {", 1)[1].split(
        "\nverify_fresh_backup_evidence() {", 1
    )[0]
    fresh = _shell_function(source, "verify_fresh_backup_evidence")
    predictive = source.split("predictive_target_preflight() {", 1)[1].split(
        "\nprepare_target_install_contract() {", 1
    )[0]

    assert "datetime.now" not in durable
    assert '"$trusted_backup_verifier"' in durable
    assert "--durable-resume" in durable
    assert "--durable-resume" not in fresh
    assert "openssl dgst -sha256 -verify" not in durable
    assert "for field in" not in durable
    assert '_artifact(document, "database_backup")' in verifier
    assert '_artifact(document, "object_manifest")' in verifier
    assert '_artifact(document, "restore_evidence")' in verifier
    assert "issued_at < expires_at <= issued_at + timedelta(hours=24)" in verifier
    assert "issued_at - timedelta(days=30)" in verifier
    assert "_fixed_release_authorization_binding()" in verifier
    assert "trusted_backup_verifier" in fresh
    assert predictive.index("discover_adoption_resume_state") < predictive.index(
        "verify_backup_evidence_for_transaction_state"
    )


def test_failure_handler_never_reactivates_after_migration_boundary() -> None:
    source = _source(ADOPTION_SCRIPT)
    handler = source.split("handle_transaction_failure() {", 1)[1].split("\n}", 1)[0]

    assert "migration_boundary_is_open" in handler
    assert "reactivate_legacy" in handler
    assert "enter_forward_fix_maintenance" in handler
    assert handler.index("migration_boundary_is_open") < handler.index("reactivate_legacy")
    assert "POST_MIGRATION_FORWARD_FIX_ONLY" in source


def test_adoption_journal_binds_every_irreversible_input() -> None:
    source = _source(ADOPTION_SCRIPT)
    journal = source.split("write_adoption_journal() {", 1)[1].split("\nreactivate_legacy() {", 1)[
        0
    ]

    assert "/legacy-adoption/transactions" in source
    assert "heyi-adoption-transaction-v1" in journal
    for field in (
        "adoption_transaction_id",
        "plan_sha256",
        "target_contract_sha256",
        "target_manifest_sha256",
        "legacy_source_schema_head",
        "target_schema_head",
        "backup_evidence_sha256",
        "retirement_receipt_sha256",
        "retirement_signature_sha256",
        "legacy_receipt_archive_manifest_sha256",
        "host_isolation_baseline_sha256",
        "host_isolation_after_retire_sha256",
        "reconcile_baseline",
        "PRE_MIGRATION_ONLY",
    ):
        assert field in journal
    assert "os.fsync" in journal
    assert "os.replace" in journal


def test_target_install_and_abort_are_bound_to_the_adoption_transaction() -> None:
    source = _source(ADOPTION_SCRIPT)
    install = source.split("run_target_install() {", 1)[1].split("\n}", 1)[0]
    abort = source.split("abort_target_pre_migration() {", 1)[1].split(
        "\nmigration_boundary_is_open() {", 1
    )[0]

    for argument in (
        '--adoption-journal "$adoption_journal"',
        '--adoption-binding-key "$legacy_binding_key"',
        '--adoption-transaction "$adoption_transaction_id"',
    ):
        assert argument in install
    for argument in (
        "--abort-pre-migration",
        '--adoption-journal "$adoption_journal"',
        '--adoption-binding-key "$legacy_binding_key"',
        '--confirm-adoption-transaction "$adoption_transaction_id"',
        '--confirm-plan-sha256 "$confirmed_plan_sha256"',
        '--confirm-retirement-receipt-sha256 "$retirement_digest"',
        "--confirm-restore-boundary PRE_MIGRATION_ONLY",
    ):
        assert argument in abort
    assert "--evidence-public-key" not in abort
    assert "--evidence-signing-key" not in abort
    assert "verify_abort_receipt" in abort


def test_execute_order_is_predictive_retire_journal_archive_install_commit() -> None:
    source = _source(ADOPTION_SCRIPT)
    execute_path = source.split("predictive_target_preflight\n", 1)[1]
    ordered = (
        "prepare_target_install_contract",
        "retire_legacy",
        "verify_retirement_receipt",
        'verify_host_isolation "$host_after_retire_output"',
        "prepare_signed_receipt_inventory",
        "write_adoption_journal",
        "archive_legacy_receipts",
        "run_target_install",
        'verify_host_isolation "$host_final_output"',
        "publish_completion_receipt",
    )

    positions = [execute_path.index(token) for token in ordered]
    assert positions == sorted(positions)
    assert "cleanup interface is unavailable" not in execute_path


def test_abort_receipt_is_signed_and_independently_rechecked() -> None:
    source = _source(ADOPTION_SCRIPT)
    verification = source.split("verify_abort_receipt() {", 1)[1].split(
        "\nabort_target_pre_migration() {", 1
    )[0]

    for token in (
        "heyi-target-pre-migration-abort-receipt",
        '"migration_command_invoked"',
        '"active_release_present"',
        '"installed_receipt_present"',
        '"target_resource_counts_after"',
        '"host_isolation_verification"',
        '"reconcile_result"',
        '"global_actions"',
        "PRE_MIGRATION_ONLY",
        "openssl dgst -sha256 -verify",
        "assert_target_resources_absent",
        "capture_reconcile_baseline",
        "verify_host_isolation",
    ):
        assert token in verification


def test_completion_requires_the_journal_bound_install_state_v2() -> None:
    source = _source(ADOPTION_SCRIPT)
    install_validation = source.split("validate_journal_bound_install_document() {", 1)[1].split(
        "\nvalidate_target_active_release() {", 1
    )[0]
    active_validation = source.split("validate_target_active_release() {", 1)[1].split(
        "\nvalidate_resumable_target_runtime_resources() {", 1
    )[0]
    completion_payload = source.split("validate_adoption_completion_payload() {", 1)[1].split(
        "\nvalidate_adoption_completion_directory() {", 1
    )[0]
    publish = source.split("publish_completion_receipt() {", 1)[1].split(
        "\nenter_forward_fix_maintenance() {", 1
    )[0]
    completion = "\n".join((install_validation, active_validation, completion_payload, publish))

    for token in (
        'document.get("schema_version") == 2',
        'phase == "completed"',
        'document.get("migration_command_invoked")',
        'document.get("operation_mode") == "adoption"',
        'document.get("adoption_transaction_id")',
        'document.get("adoption_journal_sha256")',
        'document.get("adoption_plan_sha256")',
        'document.get("retirement_receipt_sha256")',
        'document.get("legacy_source_schema_head")',
        'document.get("target_schema_head")',
        'active.get("kind") == "offline-active-release"',
        'active.get("status") == "committed"',
        "heyi-offline-adoption-completion-receipt",
        "CLOSED_AFTER_MIGRATION",
        "forward-only",
    ):
        assert token in completion


def test_resume_classification_preserves_new_transaction_safety_gates() -> None:
    source = _source(ADOPTION_SCRIPT)
    host_validation = _shell_function(source, "validate_host_isolation_evidence")
    classifier = _shell_function(source, "classify_journal_bound_target_state")
    pending = _shell_function(source, "validate_pending_adoption_completion_state")
    active = _shell_function(source, "validate_target_active_release")
    publish = _shell_function(source, "publish_completion_receipt")
    orchestrator = _shell_function(source, "run_adoption_orchestrator")

    for token in (
        'integrity.get("algorithm") != "hmac-sha256"',
        'report.get("status") != "PASS"',
        'report.get("change_count") != 0',
        'report.get("changes") != []',
        "observed_projection != reference_projection",
    ):
        assert token in host_validation
    assert "completion and target abort states coexist" in classifier
    assert classifier.index("completion and target abort states coexist") < classifier.index(
        "validate_adoption_completion_directory"
    )
    assert "validate_pending_adoption_completion_state" in classifier
    assert "validate_exact_incomplete_staging_file" in pending
    assert "discard_exact_incomplete_staging_file" not in pending
    assert "discard_exact_incomplete_staging_file" in publish
    assert '"$persistent_host_final" "$host_final_output"' in publish
    assert "offline_egress_proof_fields" in active
    assert "active_egress_provider=$2" in active
    assert 'active.get("active_provider_snapshot") == sys.argv[8]' in active
    assert 'sys.argv[4] == "strict-offline"' in active
    assert 'active.get("active_provider_snapshot") == "none"' in active
    assert 'sys.argv[4] == "controlled-egress"' in active
    assert orchestrator.index("target_abort_needs_reactivation") < orchestrator.index(
        "archive_legacy_receipts"
    )


def test_adoption_transaction_forbids_global_or_ambiguous_docker_actions() -> None:
    source = _source(ADOPTION_SCRIPT)
    forbidden = (
        "docker compose down",
        " compose down",
        "--remove-orphans",
        "docker system prune",
        "docker volume prune",
        "docker network prune",
        "docker rm -f",
        "systemctl restart docker",
    )

    for token in forbidden:
        assert token not in source


def test_adoption_script_rejects_an_incomplete_cli_before_mutation() -> None:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")

    completed = subprocess.run(
        [shell, str(ADOPTION_SCRIPT)],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 64
    assert "usage:" in completed.stderr
