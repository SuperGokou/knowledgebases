from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import cast

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
DEPLOY = REPOSITORY / "deploy" / "tencent"


def _text(name: str) -> str:
    return (DEPLOY / name).read_text(encoding="utf-8")


def test_recovery_assets_are_part_of_the_canonical_offline_contract() -> None:
    common = _text("offline-operation-common.sh")
    prepare = _text("prepare-offline-contract.sh")
    canonical_listing = common.split("cat <<'EOF'\n", 1)[1].split("\nEOF", 1)[0]
    canonical_entries = canonical_listing.splitlines()
    assets = (
        "offline-recovery-state.py",
        "offline-recovery-dispatcher.sh",
        "reconcile-offline.sh",
        "heyi-kb-offline-reconcile.service",
        "heyi-kb-offline-reconcile.timer",
    )
    for asset in assets:
        assert f"release/deploy/tencent/{asset}" in canonical_entries
        assert (DEPLOY / asset).is_file()
    assert len(canonical_entries) == len(set(canonical_entries))
    assert prepare.count("offline_contract_files") == 1
    assert 'offline_contract_files > "$contract_paths"' in prepare
    assert 'copy_release_asset "$relative_path"' in prepare
    assert "for release_asset in" not in prepare
    assert "contract snapshot inventory differs from the canonical contract" in prepare
    assert "find \"$contract_dir\" -type f -printf '%P\\n'" in prepare


def test_cutover_receipt_is_the_only_business_recovery_authorization() -> None:
    state = _text("offline-recovery-state.py")
    common = _text("offline-operation-common.sh")
    install = _text("install-offline.sh")
    deploy = _text("deploy-offline.sh")

    for field in (
        '"transaction_id"',
        '"contract_sha256"',
        '"runtime_sha256"',
        '"release_sha256"',
        '"manifest_sha256"',
        '"compose_profile"',
        '"compose_config_sha256"',
        '"project_inventory_sha256"',
    ):
        assert field in state
    assert "_active_commits_intent" in state
    assert "os.replace(temporary, path)" in state
    assert "_fsync_directory(STATE_ROOT)" in state
    assert "offline_commit_active_release" in common

    install_final_audit = install.index("offline_verify_project_release_labels install")
    install_receipt = install.index("offline_commit_active_release", install_final_audit)
    install_clear = install.index("offline_clear_committed_cutover", install_receipt)
    assert install_final_audit < install_receipt < install_clear

    deploy_final_audit = deploy.index("offline_verify_project_release_labels deploy")
    deploy_receipt = deploy.index("offline_commit_active_release", deploy_final_audit)
    deploy_clear = deploy.index("offline_clear_committed_cutover", deploy_receipt)
    assert deploy_final_audit < deploy_receipt < deploy_clear


def test_uncommitted_dispatcher_stops_only_exact_project_writers_and_edge() -> None:
    dispatcher = _text("offline-recovery-dispatcher.sh")
    fail_closed = dispatcher.split("fail_closed_project() {", 1)[1].split("\n}", 1)[0]
    for service in (
        "proxy",
        "web",
        "api",
        "maintenance",
        "llm-egress",
        "minio-multipart-gc",
        "migrate",
        "bootstrap",
        "minio-init",
    ):
        assert service in fail_closed
    for label in (
        "com.docker.compose.project",
        "com.docker.compose.service",
        "io.heyi.knowledgebases.owner",
        "io.heyi.knowledgebases.stack",
    ):
        assert label in dispatcher
    assert dispatcher.index('if [ "$selection" = intent ]') < dispatcher.index('if sh "$worker"')
    assert "docker compose down" not in dispatcher
    assert "docker system prune" not in dispatcher
    assert "docker network rm" not in dispatcher
    assert "docker volume rm" not in dispatcher


def test_dispatcher_never_reports_missing_recovery_state_as_healthy() -> None:
    dispatcher = _text("offline-recovery-dispatcher.sh")
    missing_state = dispatcher.split(
        'if ! selection_json=$(python3 -I "$state_helper" select); then',
        1,
    )[1].split("\nfi", 1)[0]

    assert "fail_closed_project" in missing_state
    assert "exit 65" in missing_state
    assert "exit 0" not in missing_state


def test_reconciler_has_non_mutating_active_fast_path() -> None:
    reconciler = _text("reconcile-offline.sh")
    fast_path = reconciler.split("# The five-second watchdog is also a steady-state auditor.", 1)[
        1
    ].split("for operation_service in migrate bootstrap", 1)[0]
    assert "offline_verify_project_release_labels" in fast_path
    assert "offline_project_inventory_digest" in fast_path
    assert "--business-ready-compose-config-stdin" in fast_path
    assert "offline_compose" not in fast_path
    assert "docker stop" not in fast_path
    assert "docker rm" not in fast_path
    assert "docker start" not in fast_path
    assert "for readiness_attempt in 1 2 3" in fast_path
    assert fast_path.index("steady_business_ready") < fast_path.index("clear-intent")
    assert "cannot clear the recovered committed cutover intent" in fast_path
    assert "already matches its receipt" in fast_path

    repair = reconciler.split("for operation_service in migrate bootstrap", 1)[1]
    assert "stop_sensitive_services" in repair
    assert "up -d --pull never --no-build" in repair
    assert re.search(r"^\s+--force-recreate(?:\s|\\|$)", repair, re.MULTILINE) is None
    assert repair.count("llm-egress api maintenance web") == 1


def test_maintenance_intent_is_atomically_superseded_only_after_fail_closed_proof() -> None:
    common = _text("offline-operation-common.sh")
    state = _text("offline-recovery-state.py")
    deploy = _text("deploy-offline.sh")
    enter = _text("enter-maintenance-offline.sh")

    begin = common.split("offline_begin_cutover() {", 1)[1].split("\n}", 1)[0]
    assert begin.index("offline_assert_maintenance_hold") < begin.index(
        "supersede-maintenance-intent"
    )
    hold = common.split("offline_assert_maintenance_hold() {", 1)[1].split("\n}", 1)[0]
    assert "maintenance hold retained a running or foreign writer" in hold
    assert "maintenance hold is not strictly healthy" in hold
    assert "os.replace(temporary, path)" in state
    assert "only a standalone maintenance intent may be superseded" in state

    begin_position = deploy.index("offline_begin_cutover")
    maintenance_position = deploy.index('enter-maintenance-offline.sh"', begin_position)
    assert begin_position < maintenance_position
    assert '--cutover-transaction-id "$cutover_transaction_id"' in deploy
    assert "inherited cutover intent is not active" in enter


def test_upgrade_baseline_is_receipt_bound_before_preflight_or_cutover() -> None:
    common = _text("offline-operation-common.sh")
    deploy = _text("deploy-offline.sh")
    baseline = common.split("offline_validate_upgrade_recovery_baseline() (", 1)[1].split(
        "offline_begin_cutover() {", 1
    )[0]

    assert baseline.index('python3 -I "$state_helper" select') < baseline.index("stage-contract")
    assert "upgrade recovery baseline is missing, damaged or conflicting" in baseline
    assert "verify-materialized-release" in baseline
    assert baseline.index("verify-materialized-release") < baseline.index(
        "OFFLINE_COMPOSE_RELEASE_ROOT_OVERRIDE=$baseline_release_root"
    )
    assert "offline_receipt_profile" in baseline
    assert "offline_compose_config_digest" in baseline
    assert '"$baseline_release_root" install' in baseline
    assert baseline.index("offline_verify_project_release_labels") < baseline.index(
        "offline_release_bound_inventory_digest"
    )
    assert "active project inventory differs from its durable receipt" in baseline
    assert "egress_proof_sha256" in baseline
    assert "active_provider_snapshot" in baseline
    assert "offline_release_bound_egress_proof_fields" in baseline
    assert "active LLM egress proof differs from its durable receipt" in baseline
    assert '"$2" != "$baseline_provider_snapshot"' not in baseline
    assert "inventory_verifier=$expected_release_root" in common
    assert "network_verifier=$expected_release_root" in common
    assert '. "$script_dir/offline-operation-common.sh"' in common

    active_branch = baseline.split("\n    active)", 1)[1].split("\n    intent)", 1)[0]
    assert "OFFLINE_CUTOVER_INTENT" in active_branch
    assert "upgrade cannot bypass an existing cutover intent" in active_branch
    intent_branch = baseline.split("\n    intent)", 1)[1]
    assert '"$baseline_operation" != maintenance' in intent_branch
    assert "offline_assert_maintenance_hold" in intent_branch

    lock_position = deploy.index("offline_acquire_lock deploy")
    baseline_position = deploy.index("offline_validate_upgrade_recovery_baseline deploy")
    preflight_position = deploy.index('sh "$snapshot_script_dir/preflight-offline.sh"')
    cutover_position = deploy.index("offline_begin_cutover", preflight_position)
    assert lock_position < baseline_position < preflight_position < cutover_position

    begin = common.split("offline_begin_cutover() {", 1)[1]
    maintenance_path = begin.split("supersede-maintenance-intent", 1)[0]
    assert maintenance_path.index("stage-contract") < maintenance_path.index(
        "offline_assert_maintenance_hold"
    )
    assert '"$current_contract" "$OFFLINE_CONTRACT_ROOT"' in maintenance_path
    assert (
        maintenance_path.index("verify-materialized-release")
        < (maintenance_path.index("OFFLINE_COMPOSE_RELEASE_ROOT_OVERRIDE"))
        < maintenance_path.index("offline_assert_maintenance_hold")
    )


def test_upgrade_baseline_uses_the_old_contracts_self_describing_asset_set() -> None:
    common = _text("offline-operation-common.sh")
    state_path = DEPLOY / "offline-recovery-state.py"
    state = state_path.read_text(encoding="utf-8")
    baseline = common.split("offline_validate_upgrade_recovery_baseline() (", 1)[1].split(
        "offline_begin_cutover() {", 1
    )[0]
    materialized_verifier = state.split("def verify_materialized_release(", 1)[1].split(
        "def simulate_faults()", 1
    )[0]

    assert "OFFLINE_SELF_DESCRIBING_CONTRACT_SHA256" in baseline
    assert "offline_validate_materialized_release" not in baseline
    assert '_read_manifest(contract / "files.sha256")' in materialized_verifier
    assert "_release_manifest_paths(entries)" in materialized_verifier
    assert "actual_paths != set(expected_paths)" in materialized_verifier
    assert "offline_contract_files" not in materialized_verifier

    spec = importlib.util.spec_from_file_location("offline_recovery_state", state_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    release_paths = cast(
        Callable[
            [list[tuple[str, PurePosixPath]]],
            tuple[PurePosixPath, ...],
        ],
        module._release_manifest_paths,  # noqa: SLF001
    )
    old_assets = [("a" * 64, PurePosixPath("release/legacy-only.sh"))]
    new_assets = [("b" * 64, PurePosixPath("release/new-reconciler.py"))]
    assert release_paths(old_assets) == (PurePosixPath("legacy-only.sh"),)
    assert release_paths(new_assets) == (PurePosixPath("new-reconciler.py"),)


def test_self_describing_materialized_verifier_accepts_v1_when_v2_assets_differ(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = DEPLOY / "offline-recovery-state.py"
    spec = importlib.util.spec_from_file_location("offline_recovery_state_tree", state_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    persistent_root = tmp_path / "persistent"
    digest = "a" * 64
    contract = tmp_path / "contract-v1"
    release = persistent_root / "releases" / digest
    (contract / "release").mkdir(parents=True)
    release.mkdir(parents=True)
    legacy_payload = b"legacy release payload\n"
    (contract / "release" / "legacy-only.sh").write_bytes(legacy_payload)
    (release / "legacy-only.sh").write_bytes(legacy_payload)
    (contract / "files.sha256").write_text(
        f"{'b' * 64}  release/legacy-only.sh\n",
        encoding="ascii",
    )

    monkeypatch.setattr(module, "PERSISTENT_ROOT", persistent_root)
    monkeypatch.setattr(module, "_require_root", lambda: None)
    monkeypatch.setattr(module, "_contract_metadata", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(module, "_validate_directory", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module,
        "_regular_root_file",
        lambda path, _mode: path.read_bytes(),
    )

    # The target version's asset set is intentionally different.  Validation
    # still follows the v1 files.sha256 and does not consult this v2 list.
    v2_assets = {PurePosixPath("new-reconciler.py")}
    assert v2_assets != {PurePosixPath("legacy-only.sh")}
    module.verify_materialized_release(contract, digest, release)

    (release / "new-reconciler.py").write_bytes(b"unexpected v2 file\n")
    with pytest.raises(module.StateError, match="inventory differs"):
        module.verify_materialized_release(contract, digest, release)


def test_upgrade_inventory_executes_the_verified_old_policy_not_new_policy(
    tmp_path: Path,
) -> None:
    old_root = tmp_path / "old-release"
    new_root = tmp_path / "new-release"
    for root, outcome in ((old_root, 0), (new_root, 99)):
        deploy_dir = root / "deploy" / "tencent"
        deploy_dir.mkdir(parents=True)
        for name in (
            "verify-offline-project-inventory.py",
            "verify-offline-network-cidrs.py",
        ):
            marker = deploy_dir / f"{name}.used"
            (deploy_dir / name).write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('used', encoding='utf-8')\n"
                f"raise SystemExit({outcome})\n",
                encoding="utf-8",
            )

    python_stub = tmp_path / "bin" / "python3"
    python_stub.parent.mkdir()
    python_stub.write_text(
        "#!/bin/sh\n"
        '[ "$1" = -I ] && shift\n'
        "script=$1\n"
        'case "$script" in\n'
        '  *old-release*) : > "$script.used"; exit 0 ;;\n'
        '  *) : > "$script.used"; exit 99 ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    os.chmod(python_stub, 0o755)

    harness = r"""
set -eu
common_path=$1
runtime_tmp=$2
old_root=$3
new_root=$4
script_dir=$(dirname "$common_path")
. "$common_path"
OFFLINE_TMPDIR=$runtime_tmp
OFFLINE_RELEASE_ROOT=$new_root
PATH=$runtime_tmp/bin:$PATH
offline_compose_profile() { printf '\n'; }
offline_compose() {
  case " $* " in
    *" --format json "*) printf '{}\n' ;;
    *" --hash "*)
      printf 'proxy %s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ;;
    *) return 1 ;;
  esac
}
offline_capture_project_inventory_snapshot() {
  printf '%064d\n' 0 > "$2"
  printf '[]\n' > "$3"
  printf '%064d\n' 1 > "$4"
  printf '[]\n' > "$5"
}
docker() { return 0; }
offline_verify_project_release_labels test "$runtime_tmp/unused-contract" "$old_root" install
"""
    completed = subprocess.run(  # noqa: S603
        [
            "sh",
            "-c",
            harness,
            "upgrade-policy-harness",
            str(DEPLOY / "offline-operation-common.sh"),
            str(tmp_path),
            str(old_root),
            str(new_root),
        ],
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    assert (old_root / "deploy/tencent/verify-offline-project-inventory.py.used").is_file()
    assert (old_root / "deploy/tencent/verify-offline-network-cidrs.py.used").is_file()
    assert not (new_root / "deploy/tencent/verify-offline-project-inventory.py.used").exists()
    assert not (new_root / "deploy/tencent/verify-offline-network-cidrs.py.used").exists()


def test_maintenance_quiesces_writers_before_the_dual_edge_cutover() -> None:
    enter = _text("enter-maintenance-offline.sh")
    new_transition = enter.split("write_transition_evidence prepared", 1)[1]
    quiesce = new_transition.index("quiesce_business_writers")
    proxy_stop = new_transition.index('docker stop --time 30 "$proxy_id"')
    maintenance_start = new_transition.index("--wait --wait-timeout 60 maintenance-page")
    assert quiesce < proxy_stop < maintenance_start
    assert "evidence_file=$OFFLINE_STATE_DIRECTORY" in enter
    evidence_commit = enter.rindex(
        "write_transition_evidence active maintenance_ready_writers_quiesced"
    )
    committed = enter.rindex("transition_committed=true")
    assert evidence_commit < committed
    assert 'sync -f "$OFFLINE_STATE_DIRECTORY"' in enter
    assert "fail_closed_intent_retained" in enter


def test_systemd_boot_and_watchdog_contract_is_bounded_and_project_scoped() -> None:
    service = _text("heyi-kb-offline-reconcile.service")
    timer = _text("heyi-kb-offline-reconcile.timer")
    compose = _text("compose.offline.yml")

    assert "Requires=docker.service" in service
    assert "After=docker.service local-fs.target" in service
    assert "/srv/heyi-knowledgebases-offline/recovery/offline-recovery-dispatcher.sh" in service
    assert "OnBootSec=5s" in timer
    assert "OnUnitInactiveSec=5s" in timer
    assert "Unit=heyi-kb-offline-reconcile.service" in timer
    assert "Requires=heyi-kb-offline-reconcile.service" not in timer
    for service_name in ("api", "maintenance", "llm-egress", "web", "proxy"):
        match = re.search(
            rf"^  {re.escape(service_name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            compose,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match is not None
        block = match.group("body")
        assert 'restart: "no"' in block


def test_executable_fault_model_covers_precommit_and_committed_kill_points() -> None:
    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(DEPLOY / "offline-recovery-state.py"), "simulate-faults"],
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["status"] == "passed"
    assert report["maintenance_to_deploy_states"] == [
        "maintenance-intent",
        "deploy-intent",
    ]
    assert [scenario["business_authorized"] for scenario in report["scenarios"]] == [
        False,
        False,
        False,
        True,
    ]


def test_new_shell_entry_points_are_syntax_checked() -> None:
    for name in (
        "offline-recovery-dispatcher.sh",
        "reconcile-offline.sh",
        "offline-operation-common.sh",
        "install-offline.sh",
        "deploy-offline.sh",
        "enter-maintenance-offline.sh",
    ):
        completed = subprocess.run(  # noqa: S603
            ["sh", "-n", str(DEPLOY / name)],
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            timeout=10,
        )
        assert completed.returncode == 0, f"{name}: {completed.stderr}"
