#!/usr/bin/env sh
set -eu

# Closed, fail-closed adoption entry point for the one-time legacy-to-signed
# offline release transition.  All mutation remains under the normal project
# flock.  Operator-controlled files are parsed as data and are never sourced.

usage() {
  cat >&2 <<'EOF'
usage: adopt-offline.sh \
  --runtime-env PATH --release-env PATH \
  --legacy-plan PATH --legacy-binding-key PATH \
  --backup-evidence PATH --backup-signature PATH \
  --evidence-public-key PATH --evidence-signing-key PATH \
  --retirement-receipt PATH --retirement-signature PATH \
  --host-isolation-baseline PATH --host-isolation-hmac-key PATH \
  --confirm-project heyi-kb-offline --confirm-plan-sha256 SHA256 \
  --confirm-preserve-data PRESERVE_BIND_DATA_AND_NAMED_VOLUMES [--execute]

Without --execute the command performs the complete predictive, non-cutover
validation and the legacy retirement dry-run.  Contract materialization is
allowed, but it does not retire or change the legacy project or start the
target release.
EOF
  exit 64
}

entry_mode=external
runtime_source=
release_source=
contract_dir=
contract_sha256=
legacy_plan=
legacy_binding_key=
backup_evidence=
backup_signature=
evidence_public_key=
evidence_signing_key=
retirement_receipt=
retirement_signature=
host_isolation_baseline=
host_isolation_hmac_key=
confirmed_project=
confirmed_plan_sha256=
confirmed_preserve_data=
execute_requested=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --runtime-env|--release-env|--contract-dir|--contract-sha256|\
    --legacy-plan|--legacy-binding-key|--backup-evidence|--backup-signature|\
    --evidence-public-key|--evidence-signing-key|--retirement-receipt|\
    --retirement-signature|--host-isolation-baseline|--host-isolation-hmac-key|\
    --confirm-project|--confirm-plan-sha256|--confirm-preserve-data)
      [ "$#" -ge 2 ] || usage
      option=$1
      value=$2
      shift 2
      case "$option" in
        --runtime-env) runtime_source=$value ;;
        --release-env) release_source=$value ;;
        --contract-dir) contract_dir=$value; entry_mode=materialized ;;
        --contract-sha256) contract_sha256=$value ;;
        --legacy-plan) legacy_plan=$value ;;
        --legacy-binding-key) legacy_binding_key=$value ;;
        --backup-evidence) backup_evidence=$value ;;
        --backup-signature) backup_signature=$value ;;
        --evidence-public-key) evidence_public_key=$value ;;
        --evidence-signing-key) evidence_signing_key=$value ;;
        --retirement-receipt) retirement_receipt=$value ;;
        --retirement-signature) retirement_signature=$value ;;
        --host-isolation-baseline) host_isolation_baseline=$value ;;
        --host-isolation-hmac-key) host_isolation_hmac_key=$value ;;
        --confirm-project) confirmed_project=$value ;;
        --confirm-plan-sha256) confirmed_plan_sha256=$value ;;
        --confirm-preserve-data) confirmed_preserve_data=$value ;;
      esac
      ;;
    --execute)
      execute_requested=true
      shift
      ;;
    *) usage ;;
  esac
done

for required_value in \
  "$legacy_plan" "$legacy_binding_key" "$backup_evidence" "$backup_signature" \
  "$evidence_public_key" "$evidence_signing_key" "$retirement_receipt" \
  "$retirement_signature" "$host_isolation_baseline" \
  "$host_isolation_hmac_key" "$confirmed_project" \
  "$confirmed_plan_sha256" "$confirmed_preserve_data"; do
  [ -n "$required_value" ] || usage
done
if [ "$entry_mode" = external ]; then
  if [ -z "$runtime_source" ] || [ -z "$release_source" ]; then
    usage
  fi
  if [ -n "$contract_dir" ] || [ -n "$contract_sha256" ]; then
    usage
  fi
else
  if [ -n "$runtime_source" ] || [ -n "$release_source" ]; then
    usage
  fi
  if [ -z "$contract_dir" ] || [ -z "$contract_sha256" ]; then
    usage
  fi
fi

case "$confirmed_plan_sha256" in
  *[!0-9a-f]*|"") usage ;;
esac
[ "${#confirmed_plan_sha256}" -eq 64 ] || usage
[ "$confirmed_project" = heyi-kb-offline ] || usage
[ "$confirmed_preserve_data" = PRESERVE_BIND_DATA_AND_NAMED_VOLUMES ] || usage

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"

offline_acquire_lock adoption

if [ "$entry_mode" = external ]; then
  contract_result=$(sh "$script_dir/prepare-offline-contract.sh" \
    "$runtime_source" "$release_source")
  contract_dir=${contract_result%% *}
  contract_sha256=${contract_result#* }
  verified_contract_sha256=$(offline_verify_contract adoption "$contract_dir")
  if [ "$verified_contract_sha256" != "$contract_sha256" ]; then
    offline_fail adoption "contract SHA-256 changed after snapshot creation" 65
  fi
  materialized_release=$(offline_materialize_release adoption "$contract_dir")
  materialized_entry=$materialized_release/deploy/tencent/adopt-offline.sh
  if [ -L "$materialized_entry" ] || [ ! -f "$materialized_entry" ]; then
    offline_fail adoption "materialized adoption worker is missing or symbolic" 65
  fi
  if [ "$execute_requested" = true ]; then
    # The immutable worker replaces this wrapper and inherits fd 9/the lock token.
    exec sh "$materialized_entry" \
      --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256" \
      --legacy-plan "$legacy_plan" --legacy-binding-key "$legacy_binding_key" \
      --backup-evidence "$backup_evidence" --backup-signature "$backup_signature" \
      --evidence-public-key "$evidence_public_key" \
      --evidence-signing-key "$evidence_signing_key" \
      --retirement-receipt "$retirement_receipt" \
      --retirement-signature "$retirement_signature" \
      --host-isolation-baseline "$host_isolation_baseline" \
      --host-isolation-hmac-key "$host_isolation_hmac_key" \
      --confirm-project "$confirmed_project" \
      --confirm-plan-sha256 "$confirmed_plan_sha256" \
      --confirm-preserve-data "$confirmed_preserve_data" --execute
  fi
  # The immutable predictive worker also replaces this wrapper.
  # shellcheck disable=SC2093
  exec sh "$materialized_entry" \
    --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256" \
    --legacy-plan "$legacy_plan" --legacy-binding-key "$legacy_binding_key" \
    --backup-evidence "$backup_evidence" --backup-signature "$backup_signature" \
    --evidence-public-key "$evidence_public_key" \
    --evidence-signing-key "$evidence_signing_key" \
    --retirement-receipt "$retirement_receipt" \
    --retirement-signature "$retirement_signature" \
    --host-isolation-baseline "$host_isolation_baseline" \
    --host-isolation-hmac-key "$host_isolation_hmac_key" \
    --confirm-project "$confirmed_project" \
    --confirm-plan-sha256 "$confirmed_plan_sha256" \
    --confirm-preserve-data "$confirmed_preserve_data"
  offline_fail adoption "cannot execute the materialized adoption worker" 73
fi

expected_materialized_root=/srv/heyi-knowledgebases-offline/releases/$contract_sha256
if [ "$OFFLINE_RELEASE_ROOT" != "$expected_materialized_root" ]; then
  offline_fail adoption "internal worker is not running from the materialized release" 65
fi
verified_contract_sha256=$(offline_verify_contract adoption "$contract_dir")
if [ "$verified_contract_sha256" != "$contract_sha256" ]; then
  offline_fail adoption "materialized contract identity differs" 65
fi
offline_validate_materialized_release adoption "$contract_dir" "$OFFLINE_RELEASE_ROOT"
trusted_legacy_tool=$OFFLINE_RELEASE_ROOT/scripts/legacy_offline_adoption.py
trusted_host_guard=$OFFLINE_RELEASE_ROOT/scripts/host_isolation_guard.py
trusted_backup_verifier=$OFFLINE_RELEASE_ROOT/deploy/tencent/verify-upgrade-backup.py
trusted_environment_validator=$OFFLINE_RELEASE_ROOT/deploy/tencent/validate-offline-environment.py
trusted_image_verifier=$OFFLINE_RELEASE_ROOT/deploy/tencent/verify-offline-images.sh
trusted_install_worker=$OFFLINE_RELEASE_ROOT/deploy/tencent/install-offline.sh
trusted_abort_helper=$OFFLINE_RELEASE_ROOT/deploy/tencent/offline-pre-migration-abort.py
trusted_maintenance_worker=$OFFLINE_RELEASE_ROOT/deploy/tencent/enter-maintenance-offline.sh
trusted_contract_remover=$OFFLINE_RELEASE_ROOT/deploy/tencent/remove-offline-contract.sh
offline_clear_inherited_environment

transaction_tmp=$(mktemp -d "$OFFLINE_TMPDIR/adoption.XXXXXXXXXX") || \
  offline_fail adoption "cannot create protected transaction workspace" 73
chmod 0700 "$transaction_tmp"
host_before_output=$transaction_tmp/host-before-retire.json
host_after_retire_output=$transaction_tmp/host-after-retire.json
host_final_output=$transaction_tmp/host-final.json
legacy_dry_run_output=$transaction_tmp/legacy-retire-dry-run.json
legacy_retire_output=$transaction_tmp/legacy-retire.json
abort_dry_run_output=$transaction_tmp/target-abort-dry-run.json
abort_independent_host_output=$transaction_tmp/host-after-abort-independent.json
reconcile_baseline_file=$transaction_tmp/reconcile-baseline.json
reconcile_after_abort_file=$transaction_tmp/reconcile-after-abort.json
pre_retire_inventory=$transaction_tmp/pre-retire-receipts.sha256
receipt_inventory=$transaction_tmp/legacy-receipts.sha256
planned_receipts_manifest=$transaction_tmp/planned-receipts.sha256
planned_archive_manifest=$transaction_tmp/planned-archive-manifest.sha256
expected_archive_receipt=$transaction_tmp/expected-adoption-archive-receipt.json
release_hashes=$transaction_tmp/release-assets.sha256
archive_root=$OFFLINE_STATE_DIRECTORY/adoption-receipt-archives
archive_pending=$archive_root/.pending-$confirmed_plan_sha256-$contract_sha256
archive_final=$archive_root/$confirmed_plan_sha256-$contract_sha256
archive_failed=$archive_root/failed-$confirmed_plan_sha256-$contract_sha256
target_schema_head=
legacy_source_schema_head=
install_contract_dir=
install_contract_sha256=
adoption_transaction_id=
adoption_transaction_dir=
adoption_journal=
journal_sha256=
abort_receipt=
abort_signature=
retirement_digest=
retirement_signature_digest=
legacy_archive_manifest_digest=
legacy_retired=false
archive_started=false
target_pre_migration_cleanup_verified=false
transaction_committed=false
transaction_terminal_aborted=false
retirement_already_published=false
retirement_resume_pending=false
resume_journal_present=false
target_adoption_state=legacy_retired_target_not_started

cleanup_transaction_tmp() {
  for temporary_file in \
    "$host_before_output" "$host_after_retire_output" "$host_final_output" \
    "$legacy_dry_run_output" "$legacy_retire_output" "$abort_dry_run_output" \
    "$abort_independent_host_output" "$reconcile_baseline_file" \
    "$reconcile_after_abort_file" "$pre_retire_inventory" \
    "$receipt_inventory" "$planned_receipts_manifest" \
    "$planned_archive_manifest" "$expected_archive_receipt" "$release_hashes"; do
    if [ -f "$temporary_file" ] && [ ! -L "$temporary_file" ]; then
      rm -f -- "$temporary_file"
    fi
  done
  rmdir -- "$transaction_tmp" 2>/dev/null || true
}

cleanup_control_contract() {
  if [ -d "$contract_dir" ] && [ ! -L "$contract_dir" ]; then
    sh "$trusted_contract_remover" "$contract_dir" "$contract_sha256" >/dev/null || true
  fi
}

cleanup_target_install_contract() {
  if [ -n "$install_contract_dir" ] && [ -d "$install_contract_dir" ] && \
    [ ! -L "$install_contract_dir" ]; then
    sh "$trusted_contract_remover" \
      "$install_contract_dir" "$install_contract_sha256" >/dev/null || true
  fi
}

validate_protected_file() {
  label=$1
  candidate=$2
  accepted_modes=$3
  maximum_bytes=$4
  case "$candidate" in
    /*) ;;
    *) offline_fail adoption "$label path must be absolute" 65 ;;
  esac
  canonical=$(realpath -e -- "$candidate" 2>/dev/null || true)
  if [ "$canonical" != "$candidate" ] || [ -L "$candidate" ] || \
    [ ! -f "$candidate" ]; then
    offline_fail adoption "$label path must be canonical and regular" 65
  fi
  owner=$(stat -c %u -- "$candidate") || exit 66
  mode=$(stat -c %a -- "$candidate") || exit 66
  links=$(stat -c %h -- "$candidate") || exit 66
  bytes=$(stat -c %s -- "$candidate") || exit 66
  case " $accepted_modes " in
    *" $mode "*) ;;
    *) offline_fail adoption "$label permissions are unsafe" 65 ;;
  esac
  if [ "$owner" -ne 0 ] || [ "$links" -ne 1 ] || \
    [ "$bytes" -le 0 ] || [ "$bytes" -gt "$maximum_bytes" ]; then
    offline_fail adoption "$label metadata is unsafe" 65
  fi
  checked_path=$(dirname -- "$candidate")
  while :; do
    if [ -L "$checked_path" ] || [ ! -d "$checked_path" ] || \
      [ "$(stat -c %u -- "$checked_path")" -ne 0 ]; then
      offline_fail adoption "$label ancestor is unsafe" 65
    fi
    checked_mode=$(stat -c %a -- "$checked_path") || exit 66
    checked_value=$((0$checked_mode))
    if [ $((checked_value & 022)) -ne 0 ]; then
      offline_fail adoption "$label ancestor is writable by non-root" 65
    fi
    [ "$checked_path" = / ] && break
    checked_path=$(dirname -- "$checked_path")
  done
}

validate_exact_incomplete_staging_file() {
  staging_path=$1
  [ -e "$staging_path" ] || [ -L "$staging_path" ] || return 0
  if [ -L "$staging_path" ] || [ ! -f "$staging_path" ] || \
    [ "$(realpath -e -- "$staging_path")" != "$staging_path" ] || \
    [ "$(stat -c %u -- "$staging_path")" -ne 0 ] || \
    [ "$(stat -c %h -- "$staging_path")" -ne 1 ]; then
    offline_fail adoption "incomplete staging path is unsafe" 65
  fi
  staging_mode=$(stat -c %a -- "$staging_path") || exit 66
  case "$staging_mode" in
    400|600) ;;
    *) offline_fail adoption "incomplete staging permissions are unsafe" 65 ;;
  esac
}

discard_exact_incomplete_staging_file() {
  staging_path=$1
  [ -e "$staging_path" ] || [ -L "$staging_path" ] || return 0
  validate_exact_incomplete_staging_file "$staging_path"
  rm -f -- "$staging_path" || exit 73
  sync -f "$(dirname -- "$staging_path")" || exit 73
}

validate_host_isolation_evidence() {
  host_evidence_path=$1
  host_evidence_reference=${2:-}
  validate_protected_file \
    "host isolation verification evidence" "$host_evidence_path" "400" 8388608
  if [ -n "$host_evidence_reference" ]; then
    validate_protected_file \
      "current host isolation verification evidence" \
      "$host_evidence_reference" "600" 8388608
  fi
  /usr/bin/python3 -I -c '
import datetime, hashlib, hmac, json, pathlib, re, sys

report_path = pathlib.Path(sys.argv[1])
key = pathlib.Path(sys.argv[2]).read_bytes()
reference_path = pathlib.Path(sys.argv[3]) if sys.argv[3] else None
digest = re.compile(r"[0-9a-f]{64}")
expected_keys = {
    "schema_version", "evidence_type", "status", "verified_at",
    "baseline_captured_at", "baseline_digest", "current_snapshot_digest",
    "policy", "protected_container_count", "change_count", "changes",
    "current_snapshot", "integrity",
}
expected_integrity_keys = {"algorithm", "digest", "key_id"}
expected_policy = {
    "excluded_compose_projects": ["heyi-kb-acceptance", "heyi-kb-offline"],
    "excluded_compose_project_prefixes": ["heyi-kb-acceptance-"],
    "required_protected_host_ports": [10050],
    "required_systemd_units": ["zabbix-agent.service"],
    "required_tcp_listeners": [{
        "protocol": "tcp", "port": 10050,
        "owner_unit": "zabbix-agent.service",
    }],
    "process_identity_comparison": "exact",
    "service_restart_tolerance": "none",
    "comparison": "exact",
}
projection_keys = {
    "policy", "docker_host", "protected_containers", "protected_image_ids",
    "protected_host_resources", "required_port_owners",
}

def reject_duplicates(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result

def read(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)

def canonical(value):
    return json.dumps(
        value, allow_nan=False, ensure_ascii=False,
        separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")

def validate(report):
    if not isinstance(report, dict) or set(report) != expected_keys:
        raise ValueError("unexpected host evidence schema")
    integrity = report.get("integrity")
    if not isinstance(integrity, dict) or set(integrity) != expected_integrity_keys:
        raise ValueError("unexpected host evidence integrity schema")
    body = {name: value for name, value in report.items() if name != "integrity"}
    expected_key_id = hashlib.sha256(key).hexdigest()
    expected_digest = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    if (
        len(key) < 32
        or integrity.get("algorithm") != "hmac-sha256"
        or not hmac.compare_digest(str(integrity.get("key_id", "")), expected_key_id)
        or not hmac.compare_digest(str(integrity.get("digest", "")), expected_digest)
    ):
        raise ValueError("invalid host evidence HMAC")
    for timestamp_name in ("verified_at", "baseline_captured_at"):
        timestamp = datetime.datetime.fromisoformat(
            str(report.get(timestamp_name, "")).replace("Z", "+00:00")
        )
        if timestamp.tzinfo is None or timestamp.utcoffset() != datetime.timedelta(0):
            raise ValueError("host evidence timestamp is not UTC")
    if (
        report.get("schema_version") != 1
        or report.get("evidence_type") != "host_isolation_verification"
        or report.get("status") != "PASS"
        or report.get("change_count") != 0
        or report.get("changes") != []
        or report.get("policy") != expected_policy
        or not isinstance(report.get("protected_container_count"), int)
        or isinstance(report.get("protected_container_count"), bool)
        or report["protected_container_count"] < 0
        or not isinstance(report.get("current_snapshot"), dict)
        or digest.fullmatch(str(report.get("baseline_digest", ""))) is None
        or digest.fullmatch(str(report.get("current_snapshot_digest", ""))) is None
    ):
        raise ValueError("host isolation evidence is not an exact PASS")
    return report

observed = validate(read(report_path))
if reference_path is not None:
    reference = validate(read(reference_path))
    observed_projection = {
        name: observed["current_snapshot"].get(name) for name in projection_keys
    }
    reference_projection = {
        name: reference["current_snapshot"].get(name) for name in projection_keys
    }
    if (
        observed.get("baseline_digest") != reference.get("baseline_digest")
        or observed_projection != reference_projection
    ):
        raise ValueError("persisted host evidence differs from current host state")
' "$host_evidence_path" "$host_isolation_hmac_key" \
    "$host_evidence_reference" || \
    offline_fail adoption "host isolation evidence is invalid or stale" 65
}

classify_retirement_receipt_state() {
  classified_receipt=$1
  classified_signature=$2
  classified_intent=$3
  receipt_present=false
  signature_present=false
  retirement_already_published=false
  retirement_resume_pending=false
  if [ -e "$classified_receipt" ] || [ -L "$classified_receipt" ]; then
    receipt_present=true
  fi
  if [ -e "$classified_signature" ] || [ -L "$classified_signature" ]; then
    signature_present=true
  fi
  if [ "$receipt_present" != "$signature_present" ]; then
    offline_fail adoption "retirement receipt pair is incomplete" 65
  fi
  if [ "$receipt_present" = true ]; then
    retirement_already_published=true
    if [ -e "$classified_intent" ] || [ -L "$classified_intent" ]; then
      offline_fail adoption "published and in-progress retirement states coexist" 65
    fi
  elif [ -e "$classified_intent" ] || [ -L "$classified_intent" ]; then
    retirement_resume_pending=true
  fi
}

validate_retirement_output_paths() {
  case "$retirement_receipt" in
    /srv/heyi-knowledgebases-offline/backups/*/evidence/retirement/receipt.json) ;;
    *) offline_fail adoption "retirement receipt path is outside the fixed backup run" 65 ;;
  esac
  expected_signature=$(dirname -- "$retirement_receipt")/receipt.sig
  if [ "$retirement_signature" != "$expected_signature" ]; then
    offline_fail adoption "retirement signature path differs from the fixed receipt pair" 65
  fi
  retirement_evidence_parent=$(dirname -- "$(dirname -- "$retirement_receipt")")
  offline_validate_root_directory adoption "$retirement_evidence_parent" 700
  retirement_intent=$retirement_evidence_parent/.retirement-in-progress
  classify_retirement_receipt_state \
    "$retirement_receipt" "$retirement_signature" "$retirement_intent"
}

validate_registry_release_receipts() {
  release_digest=$(sha256sum "$contract_dir/release.env" | awk '{print $1}') || exit 66
  manifest_digest=$(sha256sum "$contract_dir/release.env.images" | awk '{print $1}') || exit 66
  sed -n '/  release\//p' "$contract_dir/files.sha256" | LC_ALL=C sort \
    > "$release_hashes" || offline_fail adoption "cannot hash release assets" 66
  release_assets_digest=$(sha256sum "$release_hashes" | awk '{print $1}') || exit 66
  registry_receipt=$OFFLINE_STATE_DIRECTORY/registry-import-$manifest_digest.json
  highest_release=$OFFLINE_STATE_DIRECTORY/highest-release.json
  validate_protected_file "registry import receipt" "$registry_receipt" "400" 65536
  validate_protected_file "highest release receipt" "$highest_release" "400" 65536
  /usr/bin/python3 -I -c '
import json, pathlib, re, sys
receipt_path, highest_path = map(pathlib.Path, sys.argv[1:3])
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
highest = json.loads(highest_path.read_text(encoding="utf-8"))
digest = re.compile(r"[0-9a-f]{64}")
expected = {
    "schema_version", "kind", "status", "release_sequence", "release_id",
    "release_git_sha", "release_schema_head", "release_sha256", "manifest_sha256",
    "release_assets_sha256", "checksum_set_sha256", "signature_sha256",
    "trusted_key_sha256",
}
valid = (
    isinstance(receipt, dict) and set(receipt) == expected
    and receipt["schema_version"] == 2
    and receipt["kind"] == "offline-registry-import"
    and receipt["status"] == "verified"
    and receipt["release_sha256"] == sys.argv[3]
    and receipt["manifest_sha256"] == sys.argv[4]
    and receipt["release_assets_sha256"] == sys.argv[5]
    and isinstance(receipt["release_schema_head"], str)
    and re.fullmatch(r"[0-9]{8}_[0-9]{4}", receipt["release_schema_head"]) is not None
    and isinstance(receipt["release_sequence"], int)
    and 0 < receipt["release_sequence"] <= 999_999_999_999_999_999
    and re.fullmatch(r"[A-Za-z0-9._-]+", receipt["release_id"] or "") is not None
    and re.fullmatch(r"[0-9a-f]{40}", receipt["release_git_sha"] or "") is not None
    and all(
        isinstance(receipt[key], str) and digest.fullmatch(receipt[key])
        for key in ("checksum_set_sha256", "signature_sha256", "trusted_key_sha256")
    )
)
shared = (
    "release_sequence", "release_id", "release_git_sha", "release_schema_head",
    "manifest_sha256", "release_assets_sha256",
)
valid = valid and isinstance(highest, dict) and all(
    highest.get(key) == receipt.get(key) for key in shared
)
raise SystemExit(0 if valid else 1)
' "$registry_receipt" "$highest_release" "$release_digest" \
    "$manifest_digest" "$release_assets_digest" || \
    offline_fail adoption "signed target release receipt is invalid or not highest" 65
  target_schema_head=$(/usr/bin/python3 -I -c \
    'import json,pathlib,sys; print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["release_schema_head"])' \
    "$registry_receipt") || offline_fail adoption "cannot read target schema identity" 66
  case "$target_schema_head" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9]) ;;
    *) offline_fail adoption "target schema identity is invalid" 65 ;;
  esac
  rm -f -- "$release_hashes"
}

verify_host_isolation() {
  output_path=$1
  echo "adoption: verify-host-isolation against protected baseline"
  /usr/bin/python3 -I "$trusted_host_guard" verify \
    --baseline "$host_isolation_baseline" \
    --output "$output_path" \
    --hmac-key-file "$host_isolation_hmac_key" >/dev/null || \
    offline_fail adoption "host isolation evidence differs" 65
  validate_protected_file "host isolation verification" "$output_path" "600" 8388608
}

validate_legacy_retirement_dry_run() {
  retirement_mode=fresh
  if [ "$retirement_already_published" = true ]; then
    retirement_mode=final
  elif [ "$retirement_resume_pending" = true ]; then
    retirement_mode=intent
  fi
  /usr/bin/python3 -I "$trusted_legacy_tool" retire \
    --plan "$legacy_plan" \
    --binding-key "$legacy_binding_key" \
    --evidence "$backup_evidence" \
    --evidence-signature "$backup_signature" \
    --evidence-public-key "$evidence_public_key" \
    --evidence-signing-key "$evidence_signing_key" \
    --confirm-preserve-data "$confirmed_preserve_data" \
    > "$legacy_dry_run_output" || \
    offline_fail adoption "legacy retirement predictive dry-run failed" 65
  /usr/bin/python3 -I -c '
import json, pathlib, sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
mode = sys.argv[3]
valid = isinstance(document, dict) and document.get("project") == "heyi-kb-offline"
if mode == "fresh":
    valid = valid and (
        document.get("status") == "dry-run"
        and document.get("operation") == "retire"
        and document.get("plan_sha256") == sys.argv[2]
        and document.get("global_actions") == []
        and document.get("preserved_named_volumes") == []
    )
elif mode == "intent":
    valid = valid and (
        document.get("status") == "retirement-in-progress"
        and document.get("operation") == "retire"
        and document.get("plan_sha256") == sys.argv[2]
        and document.get("resume_requires_execute") is True
        and document.get("global_actions") == []
    )
elif mode == "final":
    valid = valid and (
        document.get("status") == "already-retired"
        and document.get("receipt") == sys.argv[4]
        and document.get("receipt_signature") == sys.argv[5]
        and document.get("preserved_named_volumes") == []
    )
else:
    valid = False
raise SystemExit(0 if valid else 1)
' "$legacy_dry_run_output" "$confirmed_plan_sha256" "$retirement_mode" \
    "$retirement_receipt" "$retirement_signature" || \
    offline_fail adoption \
      "legacy dry-run is ambiguous or retained named volumes block target install" 65
}

enumerate_legacy_receipts() {
  inventory_output=$1
  : > "$inventory_output"
  for candidate in \
    "$OFFLINE_STATE_DIRECTORY"/installed-*.json \
    "$OFFLINE_STATE_DIRECTORY"/install-in-progress.json \
    "$OFFLINE_STATE_DIRECTORY"/active-release.json \
    "$OFFLINE_STATE_DIRECTORY"/cutover-intent.json; do
    [ -e "$candidate" ] || continue
    validate_protected_file "legacy state receipt" "$candidate" "400" 8388608
    /usr/bin/python3 -I -c \
      'import json,pathlib,sys; value=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")); raise SystemExit(0 if isinstance(value,dict) else 1)' \
      "$candidate" || offline_fail adoption "legacy state receipt is not valid JSON" 65
    receipt_digest=$(sha256sum "$candidate" | awk '{print $1}') || exit 66
    printf '%s  %s\n' "$receipt_digest" "$candidate" >> "$inventory_output"
  done
  LC_ALL=C sort -o "$inventory_output" "$inventory_output" || exit 73
  chmod 0600 "$inventory_output"
}

capture_reconcile_baseline() {
  baseline_output=$1
  /usr/bin/python3 -I -c '
import importlib.util, json, pathlib, sys

guard_path = pathlib.Path(sys.argv[1])
output_path = pathlib.Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("heyi_adoption_host_guard", guard_path)
if spec is None or spec.loader is None:
    raise SystemExit(1)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
expected = {
    "load_state": "not-found",
    "active_state": "inactive",
    "unit_file_state": "not-found",
}
result = {}
for unit in (
    "heyi-kb-offline-reconcile.service",
    "heyi-kb-offline-reconcile.timer",
):
    raw = module._systemctl_show(unit)
    normalized = {
        "load_state": raw.get("LoadState"),
        "active_state": raw.get("ActiveState"),
        "unit_file_state": raw.get("UnitFileState") or "not-found",
    }
    if normalized != expected:
        raise SystemExit(1)
    result[unit] = normalized
output_path.write_text(
    json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
' "$trusted_host_guard" "$baseline_output" || \
    offline_fail adoption \
      "target reconcile units are not in the exact never-installed baseline" 69
  chmod 0600 "$baseline_output" || exit 73
  sync -f "$baseline_output" || exit 73
}

validate_target_transaction_assets() {
  for transaction_asset in "$trusted_install_worker" "$trusted_abort_helper"; do
    if [ -L "$transaction_asset" ] || [ ! -f "$transaction_asset" ]; then
      offline_fail adoption \
        "signed target transaction asset is missing or symbolic" 69
    fi
  done
}

verify_durable_backup_evidence() {
  /usr/bin/openssl dgst -sha256 -verify "$evidence_public_key" \
    -signature "$backup_signature" "$backup_evidence" >/dev/null 2>&1 || \
    offline_fail adoption "durable upgrade backup evidence signature is invalid" 65
  /usr/bin/python3 -I -c '
import importlib.util, json, pathlib, sys
from datetime import timedelta

verifier_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("heyi_durable_backup_verifier", verifier_path)
if spec is None or spec.loader is None:
    raise SystemExit(1)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
evidence = module._protected_regular_file(pathlib.Path(sys.argv[2]), max_bytes=65_536)
document = json.loads(evidence.read_text(encoding="utf-8"))
expected_keys = {
    "schema_version", "kind", "project", "issued_at", "expires_at",
    "target_manifest_sha256", "database_backup", "object_manifest",
    "restore_evidence", "restore_drill",
}
if not isinstance(document, dict) or set(document) != expected_keys:
    raise SystemExit(1)
if (
    document.get("schema_version") != 1
    or document.get("kind") != "offline-upgrade-backup"
    or document.get("project") != "heyi-kb-offline"
    or document.get("target_manifest_sha256") != sys.argv[3]
):
    raise SystemExit(1)
issued = module._timestamp(document.get("issued_at"), "issued_at")
expires = module._timestamp(document.get("expires_at"), "expires_at")
if not issued < expires <= issued + timedelta(hours=24):
    raise SystemExit(1)
for field in ("database_backup", "object_manifest", "restore_evidence"):
    module._artifact(document, field)
drill = document.get("restore_drill")
if not isinstance(drill, dict) or set(drill) != {
    "status", "tested_at", "source_schema_head",
}:
    raise SystemExit(1)
tested = module._timestamp(drill.get("tested_at"), "restore_drill.tested_at")
if (
    drill.get("status") != "passed"
    or not isinstance(drill.get("source_schema_head"), str)
    or module._SCHEMA_HEAD.fullmatch(drill["source_schema_head"]) is None
    or not issued - timedelta(days=30) <= tested <= issued + timedelta(minutes=5)
):
    raise SystemExit(1)
' "$trusted_backup_verifier" "$backup_evidence" "$manifest_digest" || \
    offline_fail adoption \
      "durable upgrade backup evidence or signed backup artifacts differ" 65
  echo "adoption: durable signed backup evidence and artifact hashes verified"
}

verify_fresh_backup_evidence() {
  /usr/bin/python3 -I "$trusted_backup_verifier" \
    --evidence "$backup_evidence" \
    --signature "$backup_signature" \
    --public-key "$evidence_public_key" \
    --expected-manifest-sha256 "$manifest_digest" || \
    offline_fail adoption "fresh upgrade backup evidence is not current" 65
}

verify_backup_evidence_for_transaction_state() {
  if [ "$retirement_already_published" = true ] || \
    [ "$retirement_resume_pending" = true ] || \
    [ "$resume_journal_present" = true ]; then
    verify_durable_backup_evidence
  else
    verify_fresh_backup_evidence
  fi
}

predictive_target_preflight() {
  validate_protected_file "legacy plan" "$legacy_plan" "400 440 444" 8388608
  validate_protected_file "legacy binding key" "$legacy_binding_key" "400 600" 65536
  validate_protected_file "backup evidence" "$backup_evidence" "400 440 444" 65536
  validate_protected_file "backup signature" "$backup_signature" "400 440 444" 16384
  validate_protected_file "evidence public key" "$evidence_public_key" "400 440 444" 65536
  validate_protected_file "evidence signing key" "$evidence_signing_key" "400 600" 65536
  validate_protected_file "host isolation baseline" "$host_isolation_baseline" \
    "400 440 444 600" 8388608
  validate_protected_file "host isolation HMAC key" "$host_isolation_hmac_key" \
    "400 600" 4096
  validate_retirement_output_paths
  offline_verify_release_assets adoption "$contract_dir"
  /usr/bin/python3 -I "$trusted_environment_validator" \
    "$contract_dir/runtime.env" "$contract_dir/release.env" \
    --require-bootstrap-password
  manifest_digest=$(sha256sum "$contract_dir/release.env.images" | awk '{print $1}') || exit 66
  derive_adoption_transaction_identity
  discover_adoption_resume_state
  verify_backup_evidence_for_transaction_state
  legacy_source_schema_head=$(/usr/bin/python3 -I -c '
import json, pathlib, re, sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
value = document.get("restore_drill", {}).get("source_schema_head")
if not isinstance(value, str) or re.fullmatch(r"[0-9]{8}_[0-9]{4}", value) is None:
    raise SystemExit(1)
print(value)
' "$backup_evidence") || \
    offline_fail adoption "cannot read the verified legacy schema identity" 65
  validate_registry_release_receipts
  sh "$trusted_image_verifier" verify \
    --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256"
  offline_compose adoption "$contract_dir" \
    --profile ops --profile maintenance config --quiet
  verify_host_isolation "$host_before_output"
  validate_target_transaction_assets
  if [ "$resume_journal_present" = true ]; then
    verify_retirement_receipt
    prepare_signed_receipt_inventory
    validate_existing_adoption_journal
    classify_journal_bound_target_state
    if [ "$target_adoption_state" != target_abort_needs_reactivation ]; then
      validate_resumable_archive_distribution
    fi
    echo "adoption: verified resumable transaction=$adoption_transaction_id"
  else
    capture_reconcile_baseline "$reconcile_baseline_file"
    validate_legacy_retirement_dry_run
    if [ "$retirement_already_published" != true ] && \
      [ "$retirement_resume_pending" != true ]; then
      enumerate_legacy_receipts "$pre_retire_inventory"
    fi
  fi
  echo "adoption: predictive target preflight passed before legacy retirement"
}

prepare_target_install_contract() {
  install_contract_result=$(sh \
    "$OFFLINE_RELEASE_ROOT/deploy/tencent/prepare-offline-contract.sh" \
    "$contract_dir/runtime.env" "$contract_dir/release.env") || \
    offline_fail adoption "cannot prepare the isolated target install contract" 73
  install_contract_dir=${install_contract_result%% *}
  install_contract_sha256=${install_contract_result#* }
  if [ "$install_contract_sha256" != "$contract_sha256" ] || \
    [ "$install_contract_dir" = "$contract_dir" ]; then
    offline_fail adoption "target install contract identity differs" 65
  fi
  verified_install_contract=$(offline_verify_contract adoption "$install_contract_dir")
  if [ "$verified_install_contract" != "$contract_sha256" ]; then
    offline_fail adoption "target install contract failed exact verification" 65
  fi
}

retire_legacy() {
  /usr/bin/python3 -I "$trusted_legacy_tool" retire \
    --plan "$legacy_plan" \
    --binding-key "$legacy_binding_key" \
    --evidence "$backup_evidence" \
    --evidence-signature "$backup_signature" \
    --evidence-public-key "$evidence_public_key" \
    --evidence-signing-key "$evidence_signing_key" \
    --confirm-preserve-data "$confirmed_preserve_data" \
    --execute \
    --confirm-project "$OFFLINE_PROJECT_NAME" \
    --confirm-plan-sha256 "$confirmed_plan_sha256" \
    > "$legacy_retire_output" || \
    offline_fail adoption "exact legacy retirement failed" 65
  /usr/bin/python3 -I -c '
import json, pathlib, sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
valid = (
    isinstance(document, dict)
    and document.get("status") in {"retired", "already-retired"}
    and document.get("project") == "heyi-kb-offline"
    and document.get("receipt") == sys.argv[2]
    and document.get("receipt_signature") == sys.argv[3]
    and document.get("preserved_named_volumes") == []
)
raise SystemExit(0 if valid else 1)
' "$legacy_retire_output" "$retirement_receipt" "$retirement_signature" || \
    offline_fail adoption "legacy retirement result is ambiguous" 65
  retirement_already_published=true
  retirement_resume_pending=false
  legacy_retired=true
}

verify_retirement_receipt() {
  validate_protected_file "retirement receipt" "$retirement_receipt" "400" 65536
  validate_protected_file "retirement signature" "$retirement_signature" "400" 16384
  /usr/bin/openssl dgst -sha256 -verify "$evidence_public_key" \
    -signature "$retirement_signature" "$retirement_receipt" >/dev/null 2>&1 || \
    offline_fail adoption "retirement receipt signature is invalid" 65
  /usr/bin/python3 -I -c '
import json, pathlib, sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
valid = (
    isinstance(document, dict)
    and document.get("schema_version") == 2
    and document.get("kind") == "heyi-legacy-retirement-receipt"
    and document.get("status") == "retired"
    and document.get("project") == "heyi-kb-offline"
    and document.get("plan_sha256") == sys.argv[2]
    and document.get("source_schema_head") == sys.argv[3]
    and document.get("named_volumes_deleted") is False
    and document.get("bind_data_deleted") is False
    and document.get("global_prune_used") is False
    and document.get("docker_daemon_restarted") is False
    and document.get("restore_boundary") == "PRE_MIGRATION_ONLY"
    and document.get("post_migration_rollback_policy") == "forward-only"
)
raise SystemExit(0 if valid else 1)
' "$retirement_receipt" "$confirmed_plan_sha256" "$legacy_source_schema_head" || \
    offline_fail adoption "retirement receipt does not satisfy the adoption policy" 65
  retirement_digest=$(sha256sum "$retirement_receipt" | awk '{print $1}') || exit 66
  retirement_signature_digest=$(sha256sum \
    "$retirement_signature" | awk '{print $1}') || exit 66
}

prepare_signed_receipt_inventory() {
  /usr/bin/python3 -I -c '
import json, pathlib, re, sys
receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
state_root = pathlib.Path(sys.argv[2])
output = pathlib.Path(sys.argv[3])
binding = receipt.get("release_state_binding")
if not isinstance(binding, dict) or binding.get("schema_version") != 1:
    raise SystemExit(1)
entries = binding.get("control_files")
if not isinstance(entries, list) or not entries:
    raise SystemExit(1)
safe = re.compile(r"(?:install-in-progress|active-release|cutover-intent)\.json|installed-[0-9a-f]{64}\.json")
seen = set()
lines = []
for entry in entries:
    if not isinstance(entry, dict) or set(entry) != {"name", "sha256", "size_bytes"}:
        raise SystemExit(1)
    name = entry.get("name")
    digest = entry.get("sha256")
    size = entry.get("size_bytes")
    if (
        not isinstance(name, str) or safe.fullmatch(name) is None or name in seen
        or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= 8_388_608
    ):
        raise SystemExit(1)
    seen.add(name)
    lines.append(f"{digest}  {state_root / name}\n")
output.write_text("".join(sorted(lines)), encoding="utf-8")
' "$retirement_receipt" "$OFFLINE_STATE_DIRECTORY" "$receipt_inventory" || \
    offline_fail adoption "signed retirement state inventory is invalid" 65
  chmod 0600 "$receipt_inventory" || exit 73
  if [ -f "$pre_retire_inventory" ] && \
    ! cmp -s "$pre_retire_inventory" "$receipt_inventory"; then
    offline_fail adoption \
      "signed retirement inventory differs from the pre-retirement snapshot" 65
  fi
  : > "$planned_receipts_manifest"
  while IFS='  ' read -r expected_digest receipt_path; do
    [ -n "$expected_digest" ] || continue
    receipt_name=${receipt_path##*/}
    printf '%s  %s\n' "$expected_digest" "$receipt_name" \
      >> "$planned_receipts_manifest" || exit 73
  done < "$receipt_inventory"
  chmod 0600 "$planned_receipts_manifest" || exit 73
  planned_receipts_digest=$(sha256sum \
    "$planned_receipts_manifest" | awk '{print $1}') || exit 66
  printf '%s  receipts.sha256\n' "$planned_receipts_digest" \
    > "$planned_archive_manifest" || exit 73
  chmod 0600 "$planned_archive_manifest" || exit 73
  legacy_archive_manifest_digest=$(sha256sum \
    "$planned_archive_manifest" | awk '{print $1}') || exit 66
}

prepare_expected_archive_receipt() {
  /usr/bin/python3 -I -c '
import json, pathlib, sys
payload = {
    "schema_version": 1,
    "kind": "offline-adoption-archive-receipt",
    "status": "legacy-retired-and-receipts-archived",
    "project": "heyi-kb-offline",
    "plan_sha256": sys.argv[2],
    "contract_sha256": sys.argv[3],
    "retirement_receipt_sha256": sys.argv[4],
    "retirement_signature_sha256": sys.argv[5],
}
pathlib.Path(sys.argv[1]).write_text(
    json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
' "$expected_archive_receipt" "$confirmed_plan_sha256" \
    "$contract_sha256" "$retirement_digest" "$retirement_signature_digest" || \
    offline_fail adoption "cannot construct the expected receipt archive identity" 73
  chmod 0600 "$expected_archive_receipt" || exit 73
}

validate_resumable_archive_distribution() {
  prepare_expected_archive_receipt
  if [ -e "$archive_root" ] || [ -L "$archive_root" ]; then
    offline_validate_root_directory adoption "$archive_root" 700
  fi
  for archive_directory in "$archive_pending" "$archive_final"; do
    if [ -e "$archive_directory" ] || [ -L "$archive_directory" ]; then
      offline_validate_root_directory adoption "$archive_directory" 700
    fi
  done
  if [ -e "$archive_pending" ] || [ -L "$archive_pending" ]; then
    for archive_write_staging in \
      "$archive_pending/.receipts.write" \
      "$archive_pending/.adoption-receipt.write" \
      "$archive_pending/.adoption-receipt.sig.write" \
      "$archive_pending/.manifest.write"; do
      validate_exact_incomplete_staging_file "$archive_write_staging"
    done
  fi
  if [ -e "$archive_failed" ] || [ -L "$archive_failed" ]; then
    offline_fail adoption \
      "failed receipt archive state requires a new signed adoption plan" 65
  fi

  /usr/bin/python3 -I -c '
import hashlib, os, pathlib, stat, sys

(
    inventory_raw, state_root_raw, pending_raw, final_raw,
    receipts_manifest_raw, archive_manifest_raw, expected_receipt_raw,
) = sys.argv[1:]
inventory_path = pathlib.Path(inventory_raw)
state_root = pathlib.Path(state_root_raw)
pending = pathlib.Path(pending_raw)
final = pathlib.Path(final_raw)
receipts_manifest = pathlib.Path(receipts_manifest_raw).read_bytes()
archive_manifest = pathlib.Path(archive_manifest_raw).read_bytes()
expected_receipt = pathlib.Path(expected_receipt_raw).read_bytes()

entries: dict[str, str] = {}
for line in inventory_path.read_text(encoding="utf-8").splitlines():
    digest, separator, source = line.partition("  ")
    source_path = pathlib.Path(source)
    if not separator or source_path.parent != state_root or source_path.name in entries:
        raise SystemExit(1)
    entries[source_path.name] = digest

pending_exists = pending.exists() or pending.is_symlink()
final_exists = final.exists() or final.is_symlink()
if pending_exists and final_exists:
    raise SystemExit(1)

def regular_root_file(path: pathlib.Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_uid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o400
        and 0 < metadata.st_size <= 8_388_608
    )

archive_directory = final if final_exists else pending if pending_exists else None
for name, expected_digest in entries.items():
    live = state_root / name
    archived = archive_directory / name if archive_directory is not None else None
    locations = [path for path in (live, archived) if path is not None and (path.exists() or path.is_symlink())]
    if len(locations) != 1 or not regular_root_file(locations[0]):
        raise SystemExit(1)
    if hashlib.sha256(locations[0].read_bytes()).hexdigest() != expected_digest:
        raise SystemExit(1)
    if final_exists and locations[0] == live:
        raise SystemExit(1)

metadata_names = {
    "receipts.sha256", "manifest.sha256",
    "adoption-receipt.json", "adoption-receipt.sig",
}
staging_names = {
    ".receipts.write", ".adoption-receipt.write",
    ".adoption-receipt.sig.write", ".manifest.write",
}
if archive_directory is not None:
    actual_names = {item.name for item in archive_directory.iterdir()}
    if not actual_names <= set(entries) | metadata_names | staging_names:
        raise SystemExit(1)
    for item in archive_directory.iterdir():
        if item.name in staging_names:
            continue
        if not regular_root_file(item):
            raise SystemExit(1)
    expected_content = {
        "receipts.sha256": receipts_manifest,
        "manifest.sha256": archive_manifest,
        "adoption-receipt.json": expected_receipt,
    }
    for name, content in expected_content.items():
        path = archive_directory / name
        if path.exists() and path.read_bytes() != content:
            raise SystemExit(1)
    signature = archive_directory / "adoption-receipt.sig"
    receipt = archive_directory / "adoption-receipt.json"
    if signature.exists() and not receipt.exists():
        raise SystemExit(1)

if final_exists:
    required = set(entries) | {
        "receipts.sha256", "manifest.sha256",
        "adoption-receipt.json", "adoption-receipt.sig",
    }
    if {item.name for item in final.iterdir()} != required:
        raise SystemExit(1)
' "$receipt_inventory" "$OFFLINE_STATE_DIRECTORY" "$archive_pending" \
    "$archive_final" "$planned_receipts_manifest" \
    "$planned_archive_manifest" "$expected_archive_receipt" || \
    offline_fail adoption "receipt archive distribution is ambiguous or tampered" 65

  if [ -f "$archive_pending/adoption-receipt.sig" ]; then
    /usr/bin/openssl dgst -sha256 -verify "$evidence_public_key" \
      -signature "$archive_pending/adoption-receipt.sig" \
      "$archive_pending/adoption-receipt.json" >/dev/null 2>&1 || \
      offline_fail adoption "pending receipt archive signature is invalid" 65
  fi
  if [ -e "$archive_final" ] || [ -L "$archive_final" ]; then
    /usr/bin/openssl dgst -sha256 -verify "$evidence_public_key" \
      -signature "$archive_final/adoption-receipt.sig" \
      "$archive_final/adoption-receipt.json" >/dev/null 2>&1 || \
      offline_fail adoption "published receipt archive signature is invalid" 65
    (
      cd -- "$archive_final"
      sha256sum -c manifest.sha256 >/dev/null
      if [ -s receipts.sha256 ]; then
        sha256sum -c receipts.sha256 >/dev/null
      fi
    ) || offline_fail adoption "published receipt archive hashes are invalid" 65
  fi
}

archive_one_legacy_receipt() {
  expected_digest=$1
  receipt_path=$2
  receipt_name=${receipt_path##*/}
  case "$receipt_name" in
    *[!A-Za-z0-9._-]*|"") offline_fail adoption "legacy receipt name is unsafe" 65 ;;
  esac
  archived_path=$archive_pending/$receipt_name
  if [ -e "$archived_path" ] || [ -L "$archived_path" ]; then
    validate_protected_file "pending archived receipt" "$archived_path" "400" 8388608
    if [ -e "$receipt_path" ] || [ -L "$receipt_path" ]; then
      offline_fail adoption "legacy receipt exists both live and archived" 65
    fi
  else
    validate_protected_file "legacy state receipt" "$receipt_path" "400" 8388608
    mv -- "$receipt_path" "$archived_path" || exit 73
    sync -f "$archive_pending" "$OFFLINE_STATE_DIRECTORY" || exit 73
  fi
  observed_digest=$(sha256sum "$archived_path" | awk '{print $1}') || exit 66
  [ "$observed_digest" = "$expected_digest" ] || \
    offline_fail adoption "legacy receipt changed during archival" 65
}

archive_legacy_receipts() {
  if [ ! -e "$archive_root" ] && [ ! -L "$archive_root" ]; then
    install -d -o root -g root -m 0700 "$archive_root" || exit 73
    sync -f "$OFFLINE_STATE_DIRECTORY" || exit 73
  fi
  offline_validate_root_directory adoption "$archive_root" 700
  if [ -e "$archive_pending" ] || [ -L "$archive_pending" ]; then
    offline_validate_root_directory adoption "$archive_pending" 700
    for archive_write_staging in \
      "$archive_pending/.receipts.write" \
      "$archive_pending/.adoption-receipt.write" \
      "$archive_pending/.adoption-receipt.sig.write" \
      "$archive_pending/.manifest.write"; do
      discard_exact_incomplete_staging_file "$archive_write_staging"
    done
  fi
  validate_resumable_archive_distribution
  archive_started=true
  if [ -e "$archive_final" ] || [ -L "$archive_final" ]; then
    offline_validate_root_directory adoption "$archive_final" 700
    for published_file in \
      "$archive_final/receipts.sha256" "$archive_final/manifest.sha256" \
      "$archive_final/adoption-receipt.json" "$archive_final/adoption-receipt.sig"; do
      validate_protected_file "published adoption archive" "$published_file" "400" 8388608
    done
    cmp -s "$planned_receipts_manifest" "$archive_final/receipts.sha256" || \
      offline_fail adoption "published receipt archive inventory differs" 65
    cmp -s "$planned_archive_manifest" "$archive_final/manifest.sha256" || \
      offline_fail adoption "published receipt archive manifest differs" 65
    (
      cd -- "$archive_final"
      sha256sum -c manifest.sha256 >/dev/null
      if [ -s receipts.sha256 ]; then
        sha256sum -c receipts.sha256 >/dev/null
      fi
    ) || offline_fail adoption "published receipt archive hashes are invalid" 65
    /usr/bin/openssl dgst -sha256 -verify "$evidence_public_key" \
      -signature "$archive_final/adoption-receipt.sig" \
      "$archive_final/adoption-receipt.json" >/dev/null 2>&1 || \
      offline_fail adoption "published receipt archive signature is invalid" 65
    /usr/bin/python3 -I -c '
import json, pathlib, sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "schema_version": 1,
    "kind": "offline-adoption-archive-receipt",
    "status": "legacy-retired-and-receipts-archived",
    "project": "heyi-kb-offline",
    "plan_sha256": sys.argv[2],
    "contract_sha256": sys.argv[3],
    "retirement_receipt_sha256": sys.argv[4],
    "retirement_signature_sha256": sys.argv[5],
}
raise SystemExit(0 if document == expected else 1)
' "$archive_final/adoption-receipt.json" "$confirmed_plan_sha256" \
      "$contract_sha256" "$retirement_digest" "$retirement_signature_digest" || \
      offline_fail adoption "published receipt archive identity differs" 65
    while IFS='  ' read -r _ receipt_path; do
      [ -n "$receipt_path" ] || continue
      if [ -e "$receipt_path" ] || [ -L "$receipt_path" ]; then
        offline_fail adoption "published archive still has a live legacy receipt" 65
      fi
    done < "$receipt_inventory"
    return 0
  fi
  if [ -e "$archive_pending" ] || [ -L "$archive_pending" ]; then
    offline_validate_root_directory adoption "$archive_pending" 700
  else
    install -d -o root -g root -m 0700 "$archive_pending" || exit 73
    sync -f "$archive_root" || exit 73
  fi
  archive_manifest=$archive_pending/receipts.sha256
  while IFS='  ' read -r expected_digest receipt_path; do
    [ -n "$expected_digest" ] || continue
    archive_one_legacy_receipt "$expected_digest" "$receipt_path"
  done < "$receipt_inventory"
  if [ -e "$archive_manifest" ] || [ -L "$archive_manifest" ]; then
    validate_protected_file \
      "pending receipt manifest" "$archive_manifest" "400" 8388608
    cmp -s "$planned_receipts_manifest" "$archive_manifest" || \
      offline_fail adoption "pending receipt manifest differs" 65
  else
    archive_manifest_staging=$archive_pending/.receipts.write
    install -o root -g root -m 0400 \
      "$planned_receipts_manifest" "$archive_manifest_staging" || exit 73
    sync -f "$archive_manifest_staging" || exit 73
    mv -- "$archive_manifest_staging" "$archive_manifest" || exit 73
    sync -f "$archive_pending" || exit 73
  fi
  archive_receipt=$archive_pending/adoption-receipt.json
  if [ -e "$archive_receipt" ] || [ -L "$archive_receipt" ]; then
    validate_protected_file "pending archive receipt" "$archive_receipt" "400" 65536
    cmp -s "$expected_archive_receipt" "$archive_receipt" || \
      offline_fail adoption "pending archive receipt identity differs" 65
  else
    archive_receipt_staging=$archive_pending/.adoption-receipt.write
    install -o root -g root -m 0400 \
      "$expected_archive_receipt" "$archive_receipt_staging" || exit 73
    sync -f "$archive_receipt_staging" || exit 73
    mv -- "$archive_receipt_staging" "$archive_receipt" || exit 73
    sync -f "$archive_pending" || exit 73
  fi
  archive_signature=$archive_pending/adoption-receipt.sig
  if [ -e "$archive_signature" ] || [ -L "$archive_signature" ]; then
    validate_protected_file "pending archive signature" "$archive_signature" "400" 16384
    /usr/bin/openssl dgst -sha256 -verify "$evidence_public_key" \
      -signature "$archive_signature" "$archive_receipt" >/dev/null 2>&1 || \
      offline_fail adoption "pending archive signature is invalid" 65
  else
    archive_signature_staging=$archive_pending/.adoption-receipt.sig.write
    /usr/bin/openssl dgst -sha256 -sign "$evidence_signing_key" \
      -out "$archive_signature_staging" "$archive_receipt" || exit 73
    chmod 0400 "$archive_signature_staging" || exit 73
    sync -f "$archive_signature_staging" || exit 73
    mv -- "$archive_signature_staging" "$archive_signature" || exit 73
    sync -f "$archive_pending" || exit 73
  fi
  archive_top_manifest=$archive_pending/manifest.sha256
  if [ -e "$archive_top_manifest" ] || [ -L "$archive_top_manifest" ]; then
    validate_protected_file \
      "pending top manifest" "$archive_top_manifest" "400" 8388608
    cmp -s "$planned_archive_manifest" "$archive_top_manifest" || \
      offline_fail adoption "pending top manifest differs" 65
  else
    archive_top_manifest_staging=$archive_pending/.manifest.write
    install -o root -g root -m 0400 \
      "$planned_archive_manifest" "$archive_top_manifest_staging" || exit 73
    sync -f "$archive_top_manifest_staging" || exit 73
    mv -- "$archive_top_manifest_staging" "$archive_top_manifest" || exit 73
    sync -f "$archive_pending" || exit 73
  fi
  sync -f "$archive_manifest" "$archive_top_manifest" \
    "$archive_receipt" "$archive_signature" || exit 73
  sync -f "$archive_pending" || exit 73
  mv -- "$archive_pending" "$archive_final" || exit 73
  archive_pending=
  sync -f "$archive_root" || exit 73
}

validate_exact_legacy_receipt_for_restore() {
  restore_receipt_path=$1
  restore_expected_digest=$2
  [ -f "$restore_receipt_path" ] && [ ! -L "$restore_receipt_path" ] || return 1
  [ "$(realpath -e -- "$restore_receipt_path")" = "$restore_receipt_path" ] || return 1
  [ "$(stat -c %u -- "$restore_receipt_path")" -eq 0 ] || return 1
  [ "$(stat -c %h -- "$restore_receipt_path")" -eq 1 ] || return 1
  [ "$(stat -c %a -- "$restore_receipt_path")" = 400 ] || return 1
  restore_receipt_size=$(stat -c %s -- "$restore_receipt_path") || return 1
  [ "$restore_receipt_size" -gt 0 ] && [ "$restore_receipt_size" -le 8388608 ] || return 1
  restore_observed_digest=$(sha256sum "$restore_receipt_path" | awk '{print $1}') || return 1
  [ "$restore_observed_digest" = "$restore_expected_digest" ]
}

restore_archived_receipts() {
  [ "$archive_started" = true ] || return 0
  source_directory=
  source_kind=
  source_count=0
  for archive_restore_candidate in \
    "$archive_pending:pending" "$archive_final:final" "$archive_failed:failed"; do
    candidate_directory=${archive_restore_candidate%:*}
    candidate_kind=${archive_restore_candidate##*:}
    if [ -e "$candidate_directory" ] || [ -L "$candidate_directory" ]; then
      source_count=$((source_count + 1))
      source_directory=$candidate_directory
      source_kind=$candidate_kind
    fi
  done
  if [ "$source_count" -eq 0 ]; then
    while IFS='  ' read -r expected_digest receipt_path; do
      [ -n "$expected_digest" ] || continue
      validate_exact_legacy_receipt_for_restore \
        "$receipt_path" "$expected_digest" || return 1
    done < "$receipt_inventory"
    return 0
  fi
  [ "$source_count" -eq 1 ] || return 1
  [ -d "$source_directory" ] && [ ! -L "$source_directory" ] || return 1
  offline_validate_root_directory adoption "$source_directory" 700
  if [ "$source_kind" = final ]; then
    (
      cd -- "$source_directory"
      sha256sum -c manifest.sha256 >/dev/null
      if [ -s receipts.sha256 ]; then
        sha256sum -c receipts.sha256 >/dev/null
      fi
    ) || return 1
  fi
  while IFS='  ' read -r expected_digest receipt_path; do
    [ -n "$expected_digest" ] || continue
    receipt_name=${receipt_path##*/}
    case "$receipt_name" in
      *[!A-Za-z0-9._-]*|"") return 1 ;;
    esac
    destination=$OFFLINE_STATE_DIRECTORY/$receipt_name
    if [ -e "$destination" ] || [ -L "$destination" ]; then
      validate_exact_legacy_receipt_for_restore \
        "$destination" "$expected_digest" || return 1
      continue
    fi
    archived_receipt=$source_directory/$receipt_name
    validate_exact_legacy_receipt_for_restore \
      "$archived_receipt" "$expected_digest" || return 1
    install -o root -g root -m 0400 "$archived_receipt" "$destination" || return 1
    sync -f "$destination" || return 1
    validate_exact_legacy_receipt_for_restore \
      "$destination" "$expected_digest" || return 1
  done < "$receipt_inventory"
  sync -f "$OFFLINE_STATE_DIRECTORY" || return 1
  if [ "$source_kind" = pending ]; then
    [ ! -e "$archive_failed" ] && [ ! -L "$archive_failed" ] || return 1
    mv -- "$source_directory" "$archive_failed" || return 1
    archive_pending=
    sync -f "$archive_root" || return 1
  fi
}

derive_adoption_transaction_identity() {
  adoption_transaction_id=$(/usr/bin/python3 -I -c '
import base64, hashlib, hmac, pathlib, sys
payload = pathlib.Path(sys.argv[1]).read_bytes().strip()
try:
    key = base64.urlsafe_b64decode(payload + b"=" * (-len(payload) % 4))
except (TypeError, ValueError) as error:
    raise SystemExit(1) from error
if len(key) < 32:
    raise SystemExit(1)
message = (
    b"heyi-adoption-transaction-id-v1\0"
    + sys.argv[2].encode("ascii")
    + b"\0"
    + sys.argv[3].encode("ascii")
)
print(hmac.new(key, message, hashlib.sha256).hexdigest()[:32])
' "$legacy_binding_key" "$confirmed_plan_sha256" "$contract_sha256") || \
    offline_fail adoption "cannot derive the durable adoption transaction identity" 65
  case "$adoption_transaction_id" in
    *[!0-9a-f]*|"") offline_fail adoption "adoption transaction identity is invalid" 65 ;;
  esac
  [ "${#adoption_transaction_id}" -eq 32 ] || \
    offline_fail adoption "adoption transaction identity has invalid length" 65
}

discover_adoption_resume_state() {
  adoption_transactions_root=$OFFLINE_STATE_DIRECTORY/legacy-adoption/transactions
  adoption_transaction_dir=$adoption_transactions_root/$adoption_transaction_id
  adoption_journal=$adoption_transaction_dir/journal.json
  resume_journal_present=false

  if [ -e "$adoption_transactions_root" ] || [ -L "$adoption_transactions_root" ]; then
    offline_validate_root_directory adoption "$OFFLINE_STATE_DIRECTORY/legacy-adoption" 700
    offline_validate_root_directory adoption "$adoption_transactions_root" 700
  fi
  if [ -e "$adoption_transaction_dir" ] || [ -L "$adoption_transaction_dir" ]; then
    offline_validate_root_directory adoption "$adoption_transaction_dir" 700
    for unknown_journal_pending in "$adoption_transaction_dir"/.journal*.pending; do
      [ -e "$unknown_journal_pending" ] || [ -L "$unknown_journal_pending" ] || continue
      [ "$unknown_journal_pending" = "$adoption_transaction_dir/.journal.pending" ] || \
        offline_fail adoption "unknown adoption journal pending state exists" 65
    done
  fi
  if [ -e "$adoption_journal" ] || [ -L "$adoption_journal" ]; then
    resume_journal_present=true
  fi

  archive_state_present=false
  for existing_archive_state in "$archive_pending" "$archive_final" "$archive_failed"; do
    if [ -e "$existing_archive_state" ] || [ -L "$existing_archive_state" ]; then
      archive_state_present=true
    fi
  done
  if [ "$resume_journal_present" = true ]; then
    if [ "$retirement_already_published" != true ] || \
      [ "$retirement_resume_pending" = true ]; then
      offline_fail adoption \
        "adoption journal exists without one unambiguous final retirement receipt" 65
    fi
  elif [ "$archive_state_present" = true ]; then
    offline_fail adoption "receipt archive state exists without its HMAC journal" 65
  fi
}

validate_existing_adoption_journal() {
  journal_to_validate=${1:-$adoption_journal}
  allow_pending_journal=${2:-false}
  validate_protected_file "adoption journal" "$journal_to_validate" "400" 65536
  persistent_host_after_retire=$adoption_transaction_dir/host-isolation-after-retire.json
  validate_host_isolation_evidence "$persistent_host_after_retire"
  if [ "$allow_pending_journal" = true ]; then
    verified_journal=$(/usr/bin/python3 -I "$trusted_abort_helper" validate-journal \
      --journal "$journal_to_validate" --binding-key "$legacy_binding_key" \
      --adoption-transaction "$adoption_transaction_id" \
      --contract-sha256 "$contract_sha256" --allow-pending-journal) || \
      offline_fail adoption "pending adoption journal failed HMAC verification" 65
  else
    verified_journal=$(/usr/bin/python3 -I "$trusted_abort_helper" validate-journal \
      --journal "$journal_to_validate" --binding-key "$legacy_binding_key" \
      --adoption-transaction "$adoption_transaction_id" \
      --contract-sha256 "$contract_sha256") || \
      offline_fail adoption "existing adoption journal failed HMAC verification" 65
  fi
  journal_sha256=$(printf '%s\n' "$verified_journal" | /usr/bin/python3 -I -c '
import json, sys
document = json.load(sys.stdin)
expected = {
    "status": "verified",
    "adoption_transaction_id": sys.argv[1],
    "plan_sha256": sys.argv[2],
    "retirement_receipt_sha256": sys.argv[3],
    "target_contract_sha256": sys.argv[4],
    "target_manifest_sha256": sys.argv[5],
    "target_schema_head": sys.argv[6],
    "legacy_source_schema_head": sys.argv[7],
}
if any(document.get(key) != value for key, value in expected.items()):
    raise SystemExit(1)
print(document.get("journal_sha256", ""))
' "$adoption_transaction_id" "$confirmed_plan_sha256" "$retirement_digest" \
    "$contract_sha256" "$manifest_digest" "$target_schema_head" \
    "$legacy_source_schema_head") || \
    offline_fail adoption "existing adoption journal identity differs" 65
  /usr/bin/python3 -I -c '
import json, pathlib, sys
journal = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
baseline = journal.get("payload", {}).get("reconcile_baseline")
expected_unit = {
    "load_state": "not-found",
    "active_state": "inactive",
    "unit_file_state": "not-found",
}
expected_units = {
    "heyi-kb-offline-reconcile.service",
    "heyi-kb-offline-reconcile.timer",
}
if (
    not isinstance(baseline, dict)
    or set(baseline) != expected_units
    or any(value != expected_unit for value in baseline.values())
):
    raise SystemExit(1)
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(baseline, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
' "$journal_to_validate" "$reconcile_baseline_file" || \
    offline_fail adoption "journal reconcile baseline is invalid" 65
  chmod 0600 "$reconcile_baseline_file" || exit 73
  current_backup_digest=$(sha256sum "$backup_evidence" | awk '{print $1}') || exit 66
  current_host_baseline_digest=$(sha256sum \
    "$host_isolation_baseline" | awk '{print $1}') || exit 66
  current_retirement_signature_digest=$(sha256sum \
    "$retirement_signature" | awk '{print $1}') || exit 66
  /usr/bin/python3 -I -c '
import hashlib, json, pathlib, sys
journal = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
payload = journal.get("payload", {})
host_digest = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
valid = (
    payload.get("legacy_receipt_archive_manifest_sha256") == sys.argv[3]
    and payload.get("host_isolation_after_retire_sha256") == host_digest
    and payload.get("backup_evidence_sha256") == sys.argv[4]
    and payload.get("host_isolation_baseline_sha256") == sys.argv[5]
    and payload.get("retirement_signature_sha256") == sys.argv[6]
)
raise SystemExit(0 if valid else 1)
' "$journal_to_validate" "$persistent_host_after_retire" \
    "$legacy_archive_manifest_digest" "$current_backup_digest" \
    "$current_host_baseline_digest" "$current_retirement_signature_digest" || \
    offline_fail adoption "existing adoption journal durable evidence differs" 65
}

write_adoption_journal() {
  adoption_transactions_root=$OFFLINE_STATE_DIRECTORY/legacy-adoption/transactions
  for private_parent in \
    "$OFFLINE_STATE_DIRECTORY/legacy-adoption" "$adoption_transactions_root"; do
    if [ ! -e "$private_parent" ] && [ ! -L "$private_parent" ]; then
      install -d -o root -g root -m 0700 "$private_parent" || exit 73
    fi
    if [ -L "$private_parent" ] || [ ! -d "$private_parent" ] || \
      [ "$(realpath -e -- "$private_parent")" != "$private_parent" ] || \
      [ "$(stat -c %u -- "$private_parent")" -ne 0 ] || \
      [ "$(stat -c %a -- "$private_parent")" != 700 ]; then
      offline_fail adoption "adoption transaction directory is unsafe" 65
    fi
  done
  adoption_transaction_dir=$adoption_transactions_root/$adoption_transaction_id
  if [ ! -e "$adoption_transaction_dir" ] && [ ! -L "$adoption_transaction_dir" ]; then
    install -d -o root -g root -m 0700 "$adoption_transaction_dir" || exit 73
  elif [ -L "$adoption_transaction_dir" ] || \
    [ ! -d "$adoption_transaction_dir" ] || \
    [ "$(realpath -e -- "$adoption_transaction_dir")" != "$adoption_transaction_dir" ] || \
    [ "$(stat -c %u -- "$adoption_transaction_dir")" -ne 0 ] || \
    [ "$(stat -c %a -- "$adoption_transaction_dir")" != 700 ]; then
    offline_fail adoption "existing adoption transaction directory is unsafe" 65
  fi
  persistent_host_after_retire=$adoption_transaction_dir/host-isolation-after-retire.json
  adoption_journal=$adoption_transaction_dir/journal.json
  pending_adoption_journal=$adoption_transaction_dir/.journal.pending
  if { [ -e "$adoption_journal" ] || [ -L "$adoption_journal" ]; } && \
    { [ -e "$pending_adoption_journal" ] || [ -L "$pending_adoption_journal" ]; }; then
    offline_fail adoption "published and pending adoption journals coexist" 65
  fi
  if [ -e "$adoption_journal" ] || [ -L "$adoption_journal" ]; then
    validate_host_isolation_evidence \
      "$persistent_host_after_retire" "$host_after_retire_output"
    validate_existing_adoption_journal
    return 0
  fi
  host_after_retire_staging=$adoption_transaction_dir/.host-isolation-after-retire.write
  discard_exact_incomplete_staging_file "$host_after_retire_staging"
  if [ -e "$persistent_host_after_retire" ] || [ -L "$persistent_host_after_retire" ]; then
    validate_host_isolation_evidence \
      "$persistent_host_after_retire" "$host_after_retire_output"
  else
    install -o root -g root -m 0400 \
      "$host_after_retire_output" "$host_after_retire_staging" || exit 73
    sync -f "$host_after_retire_staging" || exit 73
    validate_host_isolation_evidence \
      "$host_after_retire_staging" "$host_after_retire_output"
    mv -- "$host_after_retire_staging" "$persistent_host_after_retire" || exit 73
    sync -f "$adoption_transaction_dir" || exit 73
  fi
  if [ -e "$pending_adoption_journal" ] || [ -L "$pending_adoption_journal" ]; then
    validate_existing_adoption_journal "$pending_adoption_journal" true
    mv -- "$pending_adoption_journal" "$adoption_journal" || exit 73
    sync -f "$adoption_transaction_dir" || exit 73
    validate_existing_adoption_journal
    return 0
  fi
  journal_write_staging=$adoption_transaction_dir/.journal.write
  discard_exact_incomplete_staging_file "$journal_write_staging"

  backup_evidence_digest=$(sha256sum "$backup_evidence" | awk '{print $1}') || exit 66
  host_baseline_digest=$(sha256sum "$host_isolation_baseline" | awk '{print $1}') || exit 66
  host_after_retire_digest=$(sha256sum "$persistent_host_after_retire" | awk '{print $1}') || exit 66
  /usr/bin/python3 -I -c '
import base64, datetime, hashlib, hmac, json, os, pathlib, sys

(
    destination_raw, key_raw, transaction_id, plan_sha256,
    contract_sha256, manifest_sha256, legacy_schema_head,
    target_schema_head, backup_sha256, retirement_sha256,
    retirement_signature_sha256, archive_manifest_sha256,
    host_baseline_sha256, host_after_sha256, reconcile_raw,
) = sys.argv[1:]
destination = pathlib.Path(destination_raw)
key_payload = pathlib.Path(key_raw).read_bytes().strip()
try:
    key = base64.urlsafe_b64decode(key_payload + b"=" * (-len(key_payload) % 4))
except (ValueError, TypeError) as error:
    raise SystemExit(1) from error
if len(key) < 32:
    raise SystemExit(1)
reconcile = json.loads(pathlib.Path(reconcile_raw).read_text(encoding="utf-8"))
payload = {
    "schema_version": 1,
    "kind": "heyi-offline-adoption-transaction",
    "status": "legacy_retired_target_not_started",
    "project": "heyi-kb-offline",
    "created_at": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
    "adoption_transaction_id": transaction_id,
    "plan_sha256": plan_sha256,
    "target_contract_sha256": contract_sha256,
    "target_manifest_sha256": manifest_sha256,
    "legacy_source_schema_head": legacy_schema_head,
    "target_schema_head": target_schema_head,
    "backup_evidence_sha256": backup_sha256,
    "retirement_receipt_sha256": retirement_sha256,
    "retirement_signature_sha256": retirement_signature_sha256,
    "legacy_receipt_archive_manifest_sha256": archive_manifest_sha256,
    "host_isolation_baseline_sha256": host_baseline_sha256,
    "host_isolation_after_retire_sha256": host_after_sha256,
    "restore_boundary": "PRE_MIGRATION_ONLY",
    "reconcile_baseline": reconcile,
}
canonical_payload = (
    json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
).encode("utf-8")
binding = hmac.new(
    key,
    b"heyi-adoption-transaction-v1\0" + canonical_payload,
    hashlib.sha256,
).hexdigest()
wrapper = {"payload": payload, "opaque_hmac_sha256": binding}
encoded = (
    json.dumps(wrapper, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
).encode("utf-8")
temporary = destination.with_name(".journal.write")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(temporary, flags, 0o400)
try:
    with os.fdopen(descriptor, "wb", closefd=False) as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.fchmod(descriptor, 0o400)
finally:
    os.close(descriptor)
os.replace(temporary, destination)
directory_descriptor = os.open(destination.parent, os.O_RDONLY)
try:
    os.fsync(directory_descriptor)
finally:
    os.close(directory_descriptor)
' "$pending_adoption_journal" "$legacy_binding_key" "$adoption_transaction_id" \
    "$confirmed_plan_sha256" "$contract_sha256" "$manifest_digest" \
    "$legacy_source_schema_head" "$target_schema_head" \
    "$backup_evidence_digest" "$retirement_digest" \
    "$retirement_signature_digest" "$legacy_archive_manifest_digest" \
    "$host_baseline_digest" "$host_after_retire_digest" \
  "$reconcile_baseline_file" || \
    offline_fail adoption "cannot publish the HMAC-bound adoption journal" 73
  validate_existing_adoption_journal "$pending_adoption_journal" true
  mv -- "$pending_adoption_journal" "$adoption_journal" || exit 73
  sync -f "$adoption_transaction_dir" || exit 73
  validate_existing_adoption_journal
}

reactivate_legacy() {
  /usr/bin/python3 -I "$trusted_legacy_tool" reactivate \
    --plan "$legacy_plan" \
    --binding-key "$legacy_binding_key" \
    --retirement-receipt "$retirement_receipt" \
    --retirement-signature "$retirement_signature" \
    --evidence-public-key "$evidence_public_key" \
    --target-abort-receipt "$abort_receipt" \
    --target-abort-signature "$abort_signature" \
    --adoption-transaction "$adoption_transaction_id" \
    --host-isolation-baseline "$host_isolation_baseline" \
    --host-isolation-hmac-key "$host_isolation_hmac_key" \
    --execute \
    --confirm-project "$OFFLINE_PROJECT_NAME" \
    --confirm-plan-sha256 "$confirmed_plan_sha256" \
    --confirm-restore-boundary PRE_MIGRATION_ONLY
}

run_target_install() {
  sh "$trusted_install_worker" \
    --contract-dir "$install_contract_dir" \
    --contract-sha256 "$install_contract_sha256" \
    --adoption-journal "$adoption_journal" \
    --adoption-binding-key "$legacy_binding_key" \
    --adoption-transaction "$adoption_transaction_id"
}

validate_journal_bound_install_document() {
  document_path=$1
  expected_document_phase=$2
  validate_protected_file "journal-bound target install state" "$document_path" "400" 8388608
  /usr/bin/python3 -I -c '
import hashlib, json, pathlib, sys

path = pathlib.Path(sys.argv[1])
contract = pathlib.Path(sys.argv[2])
document = json.loads(path.read_text(encoding="utf-8"))
expected_keys = {
    "schema_version", "contract_sha256", "runtime_sha256", "release_sha256",
    "manifest_sha256", "phase", "migration_command_invoked", "operation_mode",
    "adoption_transaction_id", "adoption_journal_sha256", "adoption_plan_sha256",
    "retirement_receipt_sha256", "target_schema_head", "legacy_source_schema_head",
}
allowed_phases = {
    "prepared", "preflight_passed", "migration_invoked", "migrated",
    "bootstrapped", "core_ready", "proxy_started", "completed",
}
phase = document.get("phase")
def digest(name: str) -> str:
    return hashlib.sha256((contract / name).read_bytes()).hexdigest()
valid = (
    isinstance(document, dict) and set(document) == expected_keys
    and document.get("schema_version") == 2
    and document.get("contract_sha256") == sys.argv[3]
    and document.get("runtime_sha256") == digest("runtime.env")
    and document.get("release_sha256") == digest("release.env")
    and document.get("manifest_sha256") == digest("release.env.images")
    and phase in allowed_phases
    and document.get("migration_command_invoked") is (phase not in {"prepared", "preflight_passed"})
    and document.get("operation_mode") == "adoption"
    and document.get("adoption_transaction_id") == sys.argv[4]
    and document.get("adoption_journal_sha256") == sys.argv[5]
    and document.get("adoption_plan_sha256") == sys.argv[6]
    and document.get("retirement_receipt_sha256") == sys.argv[7]
    and document.get("target_schema_head") == sys.argv[8]
    and document.get("legacy_source_schema_head") == sys.argv[9]
    and (sys.argv[10] == "resumable" or phase == "completed")
)
if not valid:
    raise SystemExit(1)
print(phase)
' "$document_path" "$contract_dir" "$contract_sha256" \
    "$adoption_transaction_id" "$journal_sha256" "$confirmed_plan_sha256" \
    "$retirement_digest" "$target_schema_head" "$legacy_source_schema_head" \
    "$expected_document_phase" || \
    offline_fail adoption "target install state differs from the HMAC journal" 65
}

validate_target_active_release() {
  active_path=$OFFLINE_STATE_DIRECTORY/active-release.json
  validate_protected_file "active target release" "$active_path" "400" 8388608
  active_inventory_digest=$(offline_project_inventory_digest adoption) || \
    offline_fail adoption "cannot hash the active target project inventory" 69
  active_compose_digest=$(offline_compose_config_digest adoption "$contract_dir") || \
    offline_fail adoption "cannot hash the active target compose configuration" 69
  active_profile=$(offline_receipt_profile adoption "$contract_dir") || \
    offline_fail adoption "cannot determine the active target profile" 69
  active_egress_fields=$(offline_egress_proof_fields \
    adoption "$contract_dir" "$contract_sha256") || \
    offline_fail adoption "cannot reproduce the active target egress proof" 70
  # The canonical proof helper emits exactly a digest and the current provider.
  # shellcheck disable=SC2086
  set -- $active_egress_fields
  [ "$#" -eq 2 ] || \
    offline_fail adoption "active target egress proof fields are incomplete" 70
  active_egress_digest=$1
  active_egress_provider=$2
  /usr/bin/python3 -I -c '
import hashlib, json, pathlib, re, sys
active = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
contract = pathlib.Path(sys.argv[2])
expected_keys = {
    "schema_version", "kind", "project_name", "transaction_id",
    "contract_sha256", "runtime_sha256", "release_sha256", "manifest_sha256",
    "compose_profile", "compose_config_sha256", "project_inventory_sha256",
    "egress_proof_sha256", "active_provider_snapshot", "status",
}
def digest(name: str) -> str:
    return hashlib.sha256((contract / name).read_bytes()).hexdigest()
valid = (
    isinstance(active, dict) and set(active) == expected_keys
    and active.get("schema_version") == 2
    and active.get("kind") == "offline-active-release"
    and active.get("project_name") == "heyi-kb-offline"
    and active.get("status") == "committed"
    and re.fullmatch(r"[0-9a-f]{32}", active.get("transaction_id", "")) is not None
    and active.get("contract_sha256") == sys.argv[3]
    and active.get("runtime_sha256") == digest("runtime.env")
    and active.get("release_sha256") == digest("release.env")
    and active.get("manifest_sha256") == digest("release.env.images")
    and active.get("compose_profile") == sys.argv[4]
    and active.get("compose_config_sha256") == sys.argv[5]
    and active.get("project_inventory_sha256") == sys.argv[6]
    and active.get("egress_proof_sha256") == sys.argv[7]
    and active.get("active_provider_snapshot") == sys.argv[8]
    and (
        (sys.argv[4] == "strict-offline" and active.get("active_provider_snapshot") == "none")
        or (
            sys.argv[4] == "controlled-egress"
            and active.get("active_provider_snapshot") in {"deepseek", "qwen", "minimax"}
        )
    )
)
if not valid:
    raise SystemExit(1)
print(active["transaction_id"])
' "$active_path" "$contract_dir" "$contract_sha256" "$active_profile" \
    "$active_compose_digest" "$active_inventory_digest" "$active_egress_digest" \
    "$active_egress_provider" || \
    offline_fail adoption "active target release differs from the canonical project" 65
}

validate_resumable_target_runtime_resources() {
  target_inventory=$(mktemp "$OFFLINE_TMPDIR/adoption-target-inventory.XXXXXXXXXX") || return 1
  runtime_inventory_valid=true
  seen_services=" "
  docker ps -aq --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    > "$target_inventory" || runtime_inventory_valid=false
  if [ "$runtime_inventory_valid" = true ]; then
    while IFS= read -r target_container_id; do
      [ -n "$target_container_id" ] || continue
      target_service=$(docker inspect --format \
        '{{ index .Config.Labels "com.docker.compose.service" }}' \
        "$target_container_id" 2>/dev/null) || { runtime_inventory_valid=false; break; }
      target_owner=$(docker inspect --format \
        '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' \
        "$target_container_id" 2>/dev/null) || { runtime_inventory_valid=false; break; }
      target_stack=$(docker inspect --format \
        '{{ index .Config.Labels "io.heyi.knowledgebases.stack" }}' \
        "$target_container_id" 2>/dev/null) || { runtime_inventory_valid=false; break; }
      if [ "$target_owner" != jiangsu-heyi-knowledgebases ] || \
        [ "$target_stack" != offline ]; then
        runtime_inventory_valid=false
        break
      fi
      case "$target_service" in
        api-preflight|clamav-db-preflight|llm-egress-preflight|migrate|bootstrap)
          target_oneoff=$(docker inspect --format \
            '{{ index .Config.Labels "com.docker.compose.oneoff" }}' \
            "$target_container_id" 2>/dev/null) || { runtime_inventory_valid=false; break; }
          target_running=$(docker inspect --format '{{.State.Running}}' \
            "$target_container_id" 2>/dev/null) || { runtime_inventory_valid=false; break; }
          case "$target_oneoff" in
            True|true) ;;
            *) runtime_inventory_valid=false; break ;;
          esac
          if [ "$target_running" != false ]; then
            runtime_inventory_valid=false
            break
          fi
          ;;
        postgres|redis|minio|minio-init|minio-multipart-gc|clamd|api|maintenance|web|proxy|llm-egress)
          case "$seen_services" in
            *" $target_service "*) runtime_inventory_valid=false; break ;;
          esac
          seen_services="$seen_services$target_service "
          ;;
        *) runtime_inventory_valid=false; break ;;
      esac
    done < "$target_inventory"
  fi
  seen_networks=" "
  docker network ls -q --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    > "$target_inventory" || runtime_inventory_valid=false
  if [ "$runtime_inventory_valid" = true ]; then
    while IFS= read -r target_network_id; do
      [ -n "$target_network_id" ] || continue
      target_network_name=$(docker network inspect --format '{{.Name}}' \
        "$target_network_id" 2>/dev/null) || { runtime_inventory_valid=false; break; }
      target_network_owner=$(docker network inspect --format \
        '{{ index .Labels "io.heyi.knowledgebases.owner" }}' \
        "$target_network_id" 2>/dev/null) || { runtime_inventory_valid=false; break; }
      target_network_stack=$(docker network inspect --format \
        '{{ index .Labels "io.heyi.knowledgebases.stack" }}' \
        "$target_network_id" 2>/dev/null) || { runtime_inventory_valid=false; break; }
      case "$target_network_name" in
        heyi-kb-offline_edge|heyi-kb-offline_backend|heyi-kb-offline_frontend|\
        heyi-kb-offline_llm-control|heyi-kb-offline_llm-uplink) ;;
        *) runtime_inventory_valid=false; break ;;
      esac
      case "$seen_networks" in
        *" $target_network_name "*) runtime_inventory_valid=false; break ;;
      esac
      if [ "$target_network_owner" != jiangsu-heyi-knowledgebases ] || \
        [ "$target_network_stack" != offline ]; then
        runtime_inventory_valid=false
        break
      fi
      seen_networks="$seen_networks$target_network_name "
    done < "$target_inventory"
  fi
  docker volume ls -q --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    > "$target_inventory" || runtime_inventory_valid=false
  [ ! -s "$target_inventory" ] || runtime_inventory_valid=false
  if docker volume inspect heyi-kb-offline-owner-marker >/dev/null 2>&1; then
    marker_owner=$(docker volume inspect --format \
      '{{ index .Labels "io.heyi.knowledgebases.owner" }}' \
      heyi-kb-offline-owner-marker 2>/dev/null) || runtime_inventory_valid=false
    marker_project=$(docker volume inspect --format \
      '{{ index .Labels "io.heyi.knowledgebases.compose-project" }}' \
      heyi-kb-offline-owner-marker 2>/dev/null) || runtime_inventory_valid=false
    marker_contract=$(docker volume inspect --format \
      '{{ index .Labels "io.heyi.knowledgebases.contract-sha256" }}' \
      heyi-kb-offline-owner-marker 2>/dev/null) || runtime_inventory_valid=false
    marker_adoption=$(docker volume inspect --format \
      '{{ index .Labels "io.heyi.knowledgebases.adoption-transaction" }}' \
      heyi-kb-offline-owner-marker 2>/dev/null) || runtime_inventory_valid=false
    [ "$marker_owner" = jiangsu-heyi-knowledgebases ] && \
      [ "$marker_project" = "$OFFLINE_PROJECT_NAME" ] && \
      [ "$marker_contract" = "$contract_sha256" ] && \
      [ "$marker_adoption" = "$adoption_transaction_id" ] || runtime_inventory_valid=false
  fi
  rm -f -- "$target_inventory"
  [ "$runtime_inventory_valid" = true ]
}

verify_terminal_abort_receipt() {
  terminal_abort_directory=$adoption_transaction_dir/target-pre-migration-abort
  offline_validate_root_directory adoption "$terminal_abort_directory" 700
  terminal_abort_receipt=$terminal_abort_directory/receipt.json
  terminal_abort_signature=$terminal_abort_directory/receipt.sig
  terminal_abort_host=$terminal_abort_directory/host-isolation-after-abort.json
  validate_protected_file "terminal abort receipt" "$terminal_abort_receipt" "400" 65536
  validate_protected_file "terminal abort signature" "$terminal_abort_signature" "400" 16384
  validate_protected_file "terminal abort host evidence" "$terminal_abort_host" "400" 8388608
  /usr/bin/openssl dgst -sha256 -verify "$evidence_public_key" \
    -signature "$terminal_abort_signature" "$terminal_abort_receipt" \
    >/dev/null 2>&1 || offline_fail adoption "terminal abort signature is invalid" 65
  terminal_abort_host_digest=$(sha256sum "$terminal_abort_host" | awk '{print $1}') || exit 66
  /usr/bin/python3 -I -c '
import json, pathlib, sys
receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
baseline = json.loads(pathlib.Path(sys.argv[9]).read_text(encoding="utf-8"))
host = receipt.get("host_isolation_verification")
expected_keys = {
    "schema_version", "kind", "status", "project", "issued_at",
    "adoption_transaction_id", "journal_sha256", "plan_sha256",
    "retirement_receipt_sha256", "target_contract_sha256",
    "target_manifest_sha256", "legacy_source_schema_head", "target_schema_head",
    "last_install_phase", "migration_command_invoked", "active_release_present",
    "installed_receipt_present", "removed_preflight_container_ids",
    "removed_owner_marker_volume", "archived_install_state",
    "archived_cutover_intent", "reconcile_baseline", "reconcile_result",
    "target_resource_counts_after", "host_isolation_verification",
    "preserved_bind_root", "bind_data_deleted", "named_volumes_deleted",
    "global_actions", "restore_boundary",
}
valid = (
    isinstance(receipt, dict) and set(receipt) == expected_keys
    and receipt.get("schema_version") == 1
    and receipt.get("kind") == "heyi-target-pre-migration-abort-receipt"
    and receipt.get("status") == "aborted_pre_migration"
    and receipt.get("project") == "heyi-kb-offline"
    and receipt.get("adoption_transaction_id") == sys.argv[2]
    and receipt.get("journal_sha256") == sys.argv[3]
    and receipt.get("plan_sha256") == sys.argv[4]
    and receipt.get("retirement_receipt_sha256") == sys.argv[5]
    and receipt.get("target_contract_sha256") == sys.argv[6]
    and receipt.get("target_manifest_sha256") == sys.argv[7]
    and receipt.get("legacy_source_schema_head") == sys.argv[11]
    and receipt.get("target_schema_head") == sys.argv[12]
    and receipt.get("last_install_phase") in {"not_started", "prepared", "preflight_passed"}
    and receipt.get("migration_command_invoked") is False
    and receipt.get("active_release_present") is False
    and receipt.get("installed_receipt_present") is False
    and receipt.get("reconcile_baseline") == baseline
    and receipt.get("reconcile_result") == baseline
    and receipt.get("target_resource_counts_after")
        == {"containers": 0, "networks": 0, "project_volumes": 0, "owner_marker": 0}
    and isinstance(host, dict)
    and host.get("status") == "PASS"
    and host.get("path") == sys.argv[8]
    and host.get("sha256") == sys.argv[10]
    and receipt.get("bind_data_deleted") is False
    and receipt.get("named_volumes_deleted") is False
    and receipt.get("global_actions") == []
    and receipt.get("restore_boundary") == "PRE_MIGRATION_ONLY"
)
raise SystemExit(0 if valid else 1)
' "$terminal_abort_receipt" "$adoption_transaction_id" "$journal_sha256" \
    "$confirmed_plan_sha256" "$retirement_digest" "$contract_sha256" \
    "$manifest_digest" "$terminal_abort_host" "$reconcile_baseline_file" \
    "$terminal_abort_host_digest" "$legacy_source_schema_head" \
    "$target_schema_head" || \
    offline_fail adoption "terminal abort receipt binding differs" 65
  assert_target_resources_absent || \
    offline_fail adoption "terminal abort target resources reappeared" 69
  capture_reconcile_baseline "$reconcile_after_abort_file" || \
    offline_fail adoption "cannot verify terminal abort reconcile state" 69
  cmp -s "$reconcile_baseline_file" "$reconcile_after_abort_file" || \
    offline_fail adoption "terminal abort reconcile state drifted" 69
  verify_host_isolation "$abort_independent_host_output" || \
    offline_fail adoption "terminal abort host isolation drifted" 69
}

validate_pending_adoption_completion_state() {
  pending_completion_directory=$1
  offline_validate_root_directory adoption "$pending_completion_directory" 700
  for pending_completion_staging in \
    "$pending_completion_directory/.host-isolation-final.write" \
    "$pending_completion_directory/.receipt.write" \
    "$pending_completion_directory/.receipt.sig.write"; do
    validate_exact_incomplete_staging_file "$pending_completion_staging"
  done
  /usr/bin/python3 -I -c '
import pathlib, sys
directory = pathlib.Path(sys.argv[1])
allowed = {
    "host-isolation-final.json", "receipt.json", "receipt.sig",
    ".host-isolation-final.write", ".receipt.write", ".receipt.sig.write",
}
if not {item.name for item in directory.iterdir()} <= allowed:
    raise SystemExit(1)
' "$pending_completion_directory" || \
    offline_fail adoption "pending completion contains unknown state" 65

  pending_host=$pending_completion_directory/host-isolation-final.json
  pending_receipt=$pending_completion_directory/receipt.json
  pending_signature=$pending_completion_directory/receipt.sig
  pending_host_present=false
  pending_receipt_present=false
  pending_signature_present=false
  [ ! -e "$pending_host" ] && [ ! -L "$pending_host" ] || pending_host_present=true
  [ ! -e "$pending_receipt" ] && [ ! -L "$pending_receipt" ] || \
    pending_receipt_present=true
  [ ! -e "$pending_signature" ] && [ ! -L "$pending_signature" ] || \
    pending_signature_present=true
  if [ "$pending_signature_present" = true ] && \
    [ "$pending_receipt_present" != true ]; then
    offline_fail adoption "pending completion signature lacks its receipt" 65
  fi
  if [ "$pending_receipt_present" = true ] && [ "$pending_host_present" != true ]; then
    offline_fail adoption "pending completion receipt lacks host evidence" 65
  fi
  if [ "$pending_host_present" = true ]; then
    validate_host_isolation_evidence "$pending_host"
  fi
  if [ "$pending_receipt_present" = true ]; then
    validate_adoption_completion_payload "$pending_receipt" "$pending_host"
  fi
  if [ "$pending_signature_present" = true ]; then
    validate_protected_file \
      "pending adoption completion signature" "$pending_signature" "400" 16384
    /usr/bin/openssl dgst -sha256 -verify "$evidence_public_key" \
      -signature "$pending_signature" "$pending_receipt" >/dev/null 2>&1 || \
      offline_fail adoption "pending adoption completion signature is invalid" 65
  fi
}

classify_journal_bound_target_state() {
  install_state=$OFFLINE_STATE_DIRECTORY/install-in-progress.json
  target_installed=$OFFLINE_STATE_DIRECTORY/installed-$contract_sha256.json
  target_active=$OFFLINE_STATE_DIRECTORY/active-release.json
  abort_final=$adoption_transaction_dir/target-pre-migration-abort
  abort_pending=$adoption_transaction_dir/.target-pre-migration-abort.pending
  completion_final=$adoption_transaction_dir/completion
  completion_pending=$adoption_transaction_dir/.completion.pending
  for unknown_completion_pending in "$adoption_transaction_dir"/.completion.*; do
    [ -e "$unknown_completion_pending" ] || [ -L "$unknown_completion_pending" ] || continue
    [ "$unknown_completion_pending" = "$completion_pending" ] || \
      offline_fail adoption "unknown completion pending state exists" 65
  done
  completion_state_present=false
  abort_state_present=false
  if [ -e "$completion_final" ] || [ -L "$completion_final" ] || \
    [ -e "$completion_pending" ] || [ -L "$completion_pending" ]; then
    completion_state_present=true
  fi
  if [ -e "$abort_final" ] || [ -L "$abort_final" ] || \
    [ -e "$abort_pending" ] || [ -L "$abort_pending" ]; then
    abort_state_present=true
  fi
  if [ "$completion_state_present" = true ] && [ "$abort_state_present" = true ]; then
    offline_fail adoption "completion and target abort states coexist" 65
  fi
  if { [ -e "$completion_final" ] || [ -L "$completion_final" ]; } && \
    { [ -e "$completion_pending" ] || [ -L "$completion_pending" ]; }; then
    offline_fail adoption "published and pending adoption completions coexist" 65
  fi
  if [ -e "$completion_final" ] || [ -L "$completion_final" ]; then
    validate_adoption_completion_directory "$completion_final"
    target_adoption_state=adoption_completed
    transaction_committed=true
    return 0
  fi
  if { [ -e "$completion_pending" ] || [ -L "$completion_pending" ]; } && \
    { [ ! -e "$target_installed" ] && [ ! -L "$target_installed" ]; }; then
    offline_fail adoption "pending completion exists without a committed target install" 65
  fi
  if [ -e "$completion_pending" ] || [ -L "$completion_pending" ]; then
    validate_pending_adoption_completion_state "$completion_pending"
  fi
  if { [ -e "$abort_final" ] || [ -L "$abort_final" ]; } && \
    { [ -e "$abort_pending" ] || [ -L "$abort_pending" ]; }; then
    offline_fail adoption "published and pending target abort states coexist" 65
  fi
  if [ -e "$abort_final" ] || [ -L "$abort_final" ]; then
    verify_terminal_abort_receipt
    target_adoption_state=target_abort_needs_reactivation
    return 0
  fi
  if [ -e "$abort_pending" ] || [ -L "$abort_pending" ]; then
    offline_validate_root_directory adoption "$abort_pending" 700
    target_adoption_state=target_abort_needs_reactivation
    return 0
  fi

  installed_count=0
  for installed_candidate in "$OFFLINE_STATE_DIRECTORY"/installed-*.json; do
    [ -e "$installed_candidate" ] || continue
    installed_count=$((installed_count + 1))
    [ "$installed_candidate" = "$target_installed" ] || \
      offline_fail adoption "an installed receipt from another release is live" 65
  done
  [ "$installed_count" -le 1 ] || \
    offline_fail adoption "multiple installed target receipts are ambiguous" 65

  if [ -e "$target_installed" ] || [ -L "$target_installed" ]; then
    if [ -e "$install_state" ] || [ -L "$install_state" ]; then
      offline_fail adoption "completed and in-progress target states coexist" 65
    fi
    if [ ! -e "$target_active" ] || [ -L "$target_active" ]; then
      offline_fail adoption "completed target install lacks its active release" 65
    fi
    validate_journal_bound_install_document "$target_installed" completed >/dev/null
    validate_target_active_release >/dev/null
    target_adoption_state=target_install_committed
    return 0
  fi

  if [ -e "$install_state" ] || [ -L "$install_state" ]; then
    target_install_phase=$(validate_journal_bound_install_document \
      "$install_state" resumable)
    if [ -e "$target_active" ] || [ -L "$target_active" ]; then
      case "$target_install_phase" in
        proxy_started|completed) ;;
        *) offline_fail adoption "active release appeared before target commit phase" 65 ;;
      esac
      validate_target_active_release >/dev/null
    fi
    validate_resumable_target_runtime_resources || \
      offline_fail adoption "resumable target runtime resources are unknown or mixed" 69
    target_adoption_state=target_install_resumable
    return 0
  fi

  if [ -e "$target_active" ] || [ -L "$target_active" ]; then
    offline_fail adoption "active target release exists without install state" 65
  fi
  assert_target_runtime_resources_absent || \
    offline_fail adoption "target-not-started journal has runtime resources" 69
  capture_reconcile_baseline "$reconcile_after_abort_file"
  cmp -s "$reconcile_baseline_file" "$reconcile_after_abort_file" || \
    offline_fail adoption "target-not-started reconcile state differs from journal" 69
  target_adoption_state=legacy_retired_target_not_started
}

assert_target_runtime_resources_absent() {
  target_resource_ids=$(docker ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME") || return 1
  [ -z "$target_resource_ids" ] || return 1
  target_resource_ids=$(docker network ls -q --no-trunc \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME") || return 1
  [ -z "$target_resource_ids" ] || return 1
  target_resource_ids=$(docker volume ls -q \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME") || return 1
  [ -z "$target_resource_ids" ] || return 1
  owner_marker_ids=$(docker volume ls -q \
    --filter name=heyi-kb-offline-owner-marker) || return 1
  [ -z "$owner_marker_ids" ] || return 1
}

assert_target_resources_absent() {
  assert_target_runtime_resources_absent || return 1
  for forbidden_target_state in \
    "$OFFLINE_STATE_DIRECTORY/install-in-progress.json" \
    "$OFFLINE_STATE_DIRECTORY/active-release.json" \
    "$OFFLINE_STATE_DIRECTORY/cutover-intent.json" \
    "$OFFLINE_STATE_DIRECTORY/installed-$contract_sha256.json"; do
    [ ! -e "$forbidden_target_state" ] && [ ! -L "$forbidden_target_state" ] || return 1
  done
}

verify_abort_receipt() {
  abort_directory=$adoption_transaction_dir/target-pre-migration-abort
  abort_receipt=$abort_directory/receipt.json
  abort_signature=$abort_directory/receipt.sig
  abort_host_evidence=$abort_directory/host-isolation-after-abort.json
  validate_protected_file "pre-migration abort receipt" "$abort_receipt" "400" 65536
  validate_protected_file "pre-migration abort signature" "$abort_signature" "400" 16384
  validate_protected_file \
    "pre-migration abort host evidence" "$abort_host_evidence" "400" 8388608
  /usr/bin/openssl dgst -sha256 -verify "$evidence_public_key" \
    -signature "$abort_signature" "$abort_receipt" >/dev/null 2>&1 || return 1
  observed_journal_sha256=$(sha256sum "$adoption_journal" | awk '{print $1}') || return 1
  [ "$observed_journal_sha256" = "$journal_sha256" ] || return 1
  abort_host_sha256=$(sha256sum "$abort_host_evidence" | awk '{print $1}') || return 1
  /usr/bin/python3 -I -c '
import json, pathlib, re, sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
baseline = json.loads(pathlib.Path(sys.argv[9]).read_text(encoding="utf-8"))
expected_keys = {
    "schema_version", "kind", "status", "project", "issued_at",
    "adoption_transaction_id", "journal_sha256", "plan_sha256",
    "retirement_receipt_sha256", "target_contract_sha256",
    "target_manifest_sha256", "legacy_source_schema_head", "target_schema_head",
    "last_install_phase", "migration_command_invoked", "active_release_present",
    "installed_receipt_present", "removed_preflight_container_ids",
    "removed_owner_marker_volume", "archived_install_state",
    "archived_cutover_intent", "reconcile_baseline", "reconcile_result",
    "target_resource_counts_after", "host_isolation_verification",
    "preserved_bind_root", "bind_data_deleted", "named_volumes_deleted",
    "global_actions", "restore_boundary",
}
counts = receipt.get("target_resource_counts_after")
host = receipt.get("host_isolation_verification")
valid = (
    isinstance(receipt, dict) and set(receipt) == expected_keys
    and receipt.get("schema_version") == 1
    and receipt.get("kind") == "heyi-target-pre-migration-abort-receipt"
    and receipt.get("status") == "aborted_pre_migration"
    and receipt.get("project") == "heyi-kb-offline"
    and receipt.get("adoption_transaction_id") == sys.argv[2]
    and receipt.get("journal_sha256") == sys.argv[3]
    and receipt.get("plan_sha256") == sys.argv[4]
    and receipt.get("retirement_receipt_sha256") == sys.argv[5]
    and receipt.get("target_contract_sha256") == sys.argv[6]
    and receipt.get("target_manifest_sha256") == sys.argv[7]
    and receipt.get("legacy_source_schema_head") == sys.argv[10]
    and receipt.get("target_schema_head") == sys.argv[11]
    and receipt.get("last_install_phase") in {"not_started", "prepared", "preflight_passed"}
    and receipt.get("migration_command_invoked") is False
    and receipt.get("active_release_present") is False
    and receipt.get("installed_receipt_present") is False
    and isinstance(receipt.get("removed_preflight_container_ids"), list)
    and receipt.get("reconcile_baseline") == baseline
    and receipt.get("reconcile_result") == baseline
    and counts == {"containers": 0, "networks": 0, "project_volumes": 0, "owner_marker": 0}
    and isinstance(host, dict)
    and host.get("status") == "PASS"
    and host.get("path") == sys.argv[8]
    and host.get("sha256") == sys.argv[12]
    and receipt.get("bind_data_deleted") is False
    and receipt.get("named_volumes_deleted") is False
    and receipt.get("global_actions") == []
    and receipt.get("restore_boundary") == "PRE_MIGRATION_ONLY"
    and re.fullmatch(r"[0-9]{8}_[0-9]{4}", receipt.get("target_schema_head", ""))
)
raise SystemExit(0 if valid else 1)
' "$abort_receipt" "$adoption_transaction_id" "$journal_sha256" \
    "$confirmed_plan_sha256" "$retirement_digest" "$contract_sha256" \
    "$manifest_digest" "$abort_host_evidence" "$reconcile_baseline_file" \
    "$legacy_source_schema_head" "$target_schema_head" "$abort_host_sha256" || return 1
  assert_target_resources_absent || return 1
  capture_reconcile_baseline "$reconcile_after_abort_file" || return 1
  cmp -s "$reconcile_baseline_file" "$reconcile_after_abort_file" || return 1
  verify_host_isolation "$abort_independent_host_output" || return 1
}

abort_target_pre_migration() {
  sh "$trusted_install_worker" \
    --abort-pre-migration \
    --adoption-journal "$adoption_journal" \
    --adoption-binding-key "$legacy_binding_key" \
    --evidence-signing-key "$evidence_signing_key" \
    --evidence-public-key "$evidence_public_key" \
    --host-isolation-baseline "$host_isolation_baseline" \
    --host-isolation-hmac-key "$host_isolation_hmac_key" \
    > "$abort_dry_run_output" || return 1
  /usr/bin/python3 -I -c '
import json, pathlib, sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_keys = {
    "schema_version", "status", "project", "adoption_transaction_id",
    "contract_sha256", "last_install_phase", "preflight_container_ids",
    "owner_marker_present", "migration_command_invoked", "restore_boundary",
}
valid = (
    isinstance(document, dict) and set(document) == expected_keys
    and document.get("schema_version") == 1
    and document.get("status") == "dry-run"
    and document.get("project") == "heyi-kb-offline"
    and document.get("adoption_transaction_id") == sys.argv[2]
    and document.get("contract_sha256") == sys.argv[3]
    and document.get("last_install_phase") in {"not_started", "prepared", "preflight_passed"}
    and isinstance(document.get("preflight_container_ids"), list)
    and isinstance(document.get("owner_marker_present"), bool)
    and document.get("restore_boundary") == "PRE_MIGRATION_ONLY"
    and document.get("migration_command_invoked") is False
)
raise SystemExit(0 if valid else 1)
' "$abort_dry_run_output" "$adoption_transaction_id" "$contract_sha256" || return 1
  sh "$trusted_install_worker" \
    --abort-pre-migration \
    --adoption-journal "$adoption_journal" \
    --adoption-binding-key "$legacy_binding_key" \
    --evidence-signing-key "$evidence_signing_key" \
    --evidence-public-key "$evidence_public_key" \
    --host-isolation-baseline "$host_isolation_baseline" \
    --host-isolation-hmac-key "$host_isolation_hmac_key" \
    --execute \
    --confirm-project "$OFFLINE_PROJECT_NAME" \
    --confirm-contract-sha256 "$contract_sha256" \
    --confirm-adoption-transaction "$adoption_transaction_id" \
    --confirm-plan-sha256 "$confirmed_plan_sha256" \
    --confirm-retirement-receipt-sha256 "$retirement_digest" \
    --confirm-restore-boundary PRE_MIGRATION_ONLY || return 1
  verify_abort_receipt
}

migration_boundary_is_open() {
  [ "$target_pre_migration_cleanup_verified" = true ]
}

validate_adoption_completion_payload() {
  completion_receipt_path=$1
  completion_host_path=$2
  validate_protected_file "adoption completion receipt" "$completion_receipt_path" "400" 65536
  validate_host_isolation_evidence "$completion_host_path"
  completed_installed=$OFFLINE_STATE_DIRECTORY/installed-$contract_sha256.json
  completed_active=$OFFLINE_STATE_DIRECTORY/active-release.json
  validate_journal_bound_install_document "$completed_installed" completed >/dev/null
  validate_target_active_release >/dev/null
  completed_installed_digest=$(sha256sum "$completed_installed" | awk '{print $1}') || exit 66
  completed_active_digest=$(sha256sum "$completed_active" | awk '{print $1}') || exit 66
  completed_host_digest=$(sha256sum "$completion_host_path" | awk '{print $1}') || exit 66
  /usr/bin/python3 -I -c '
import datetime, json, pathlib, sys
receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_keys = {
    "schema_version", "kind", "status", "project", "issued_at",
    "adoption_transaction_id", "journal_sha256", "plan_sha256",
    "retirement_receipt_sha256", "retirement_signature_sha256",
    "target_contract_sha256", "target_manifest_sha256",
    "legacy_source_schema_head", "target_schema_head",
    "legacy_receipt_archive_manifest_sha256", "installed_receipt_sha256",
    "active_release_sha256", "host_isolation_final_sha256",
    "restore_boundary", "post_migration_failure_policy", "global_actions",
}
try:
    issued = datetime.datetime.fromisoformat(
        str(receipt.get("issued_at", "")).replace("Z", "+00:00")
    )
except ValueError:
    raise SystemExit(1)
valid = (
    isinstance(receipt, dict) and set(receipt) == expected_keys
    and issued.tzinfo is not None
    and issued.utcoffset() == datetime.timedelta(0)
    and receipt.get("schema_version") == 1
    and receipt.get("kind") == "heyi-offline-adoption-completion-receipt"
    and receipt.get("status") == "completed"
    and receipt.get("project") == "heyi-kb-offline"
    and receipt.get("adoption_transaction_id") == sys.argv[2]
    and receipt.get("journal_sha256") == sys.argv[3]
    and receipt.get("plan_sha256") == sys.argv[4]
    and receipt.get("retirement_receipt_sha256") == sys.argv[5]
    and receipt.get("retirement_signature_sha256") == sys.argv[6]
    and receipt.get("target_contract_sha256") == sys.argv[7]
    and receipt.get("target_manifest_sha256") == sys.argv[8]
    and receipt.get("legacy_source_schema_head") == sys.argv[9]
    and receipt.get("target_schema_head") == sys.argv[10]
    and receipt.get("legacy_receipt_archive_manifest_sha256") == sys.argv[11]
    and receipt.get("installed_receipt_sha256") == sys.argv[12]
    and receipt.get("active_release_sha256") == sys.argv[13]
    and receipt.get("host_isolation_final_sha256") == sys.argv[14]
    and receipt.get("restore_boundary") == "CLOSED_AFTER_MIGRATION"
    and receipt.get("post_migration_failure_policy") == "forward-only"
    and receipt.get("global_actions") == []
)
raise SystemExit(0 if valid else 1)
' "$completion_receipt_path" "$adoption_transaction_id" "$journal_sha256" \
    "$confirmed_plan_sha256" "$retirement_digest" "$retirement_signature_digest" \
    "$contract_sha256" "$manifest_digest" "$legacy_source_schema_head" \
    "$target_schema_head" "$legacy_archive_manifest_digest" \
    "$completed_installed_digest" "$completed_active_digest" \
    "$completed_host_digest" || \
    offline_fail adoption "completion receipt identity or evidence differs" 65
}

validate_adoption_completion_directory() {
  completion_directory=$1
  offline_validate_root_directory adoption "$completion_directory" 700
  /usr/bin/python3 -I -c '
import pathlib, stat, sys
directory = pathlib.Path(sys.argv[1])
expected = {"host-isolation-final.json", "receipt.json", "receipt.sig"}
items = list(directory.iterdir())
if {item.name for item in items} != expected:
    raise SystemExit(1)
for item in items:
    metadata = item.lstat()
    if item.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        raise SystemExit(1)
' "$completion_directory" || \
    offline_fail adoption "completion directory contains mixed or unknown state" 65
  validate_adoption_completion_payload \
    "$completion_directory/receipt.json" \
    "$completion_directory/host-isolation-final.json"
  validate_protected_file \
    "adoption completion signature" "$completion_directory/receipt.sig" "400" 16384
  /usr/bin/openssl dgst -sha256 -verify "$evidence_public_key" \
    -signature "$completion_directory/receipt.sig" \
    "$completion_directory/receipt.json" >/dev/null 2>&1 || \
    offline_fail adoption "adoption completion signature is invalid" 65
}

publish_completion_receipt() {
  installed_receipt=$OFFLINE_STATE_DIRECTORY/installed-$contract_sha256.json
  active_release=$OFFLINE_STATE_DIRECTORY/active-release.json
  validate_journal_bound_install_document "$installed_receipt" completed >/dev/null
  validate_target_active_release >/dev/null
  completion_final=$adoption_transaction_dir/completion
  completion_pending=$adoption_transaction_dir/.completion.pending
  if { [ -e "$completion_final" ] || [ -L "$completion_final" ]; } && \
    { [ -e "$completion_pending" ] || [ -L "$completion_pending" ]; }; then
    offline_fail adoption "published and pending adoption completions coexist" 65
  fi
  if [ -e "$completion_final" ] || [ -L "$completion_final" ]; then
    validate_adoption_completion_directory "$completion_final"
    transaction_committed=true
    return 0
  fi
  if [ -e "$completion_pending" ] || [ -L "$completion_pending" ]; then
    validate_pending_adoption_completion_state "$completion_pending"
    for completion_write_staging in \
      "$completion_pending/.host-isolation-final.write" \
      "$completion_pending/.receipt.write" \
      "$completion_pending/.receipt.sig.write"; do
      discard_exact_incomplete_staging_file "$completion_write_staging"
    done
  else
    install -d -o root -g root -m 0700 "$completion_pending" || exit 73
    sync -f "$adoption_transaction_dir" || exit 73
  fi
  persistent_host_final=$completion_pending/host-isolation-final.json
  if [ -e "$persistent_host_final" ] || [ -L "$persistent_host_final" ]; then
    validate_host_isolation_evidence \
      "$persistent_host_final" "$host_final_output"
  else
    completion_host_staging=$completion_pending/.host-isolation-final.write
    install -o root -g root -m 0400 \
      "$host_final_output" "$completion_host_staging" || exit 73
    sync -f "$completion_host_staging" || exit 73
    validate_host_isolation_evidence \
      "$completion_host_staging" "$host_final_output"
    mv -- "$completion_host_staging" "$persistent_host_final" || exit 73
    sync -f "$completion_pending" || exit 73
  fi
  installed_digest=$(sha256sum "$installed_receipt" | awk '{print $1}') || exit 66
  active_digest=$(sha256sum "$active_release" | awk '{print $1}') || exit 66
  host_final_digest=$(sha256sum "$persistent_host_final" | awk '{print $1}') || exit 66
  completion_receipt=$completion_pending/receipt.json
  if [ -e "$completion_receipt" ] || [ -L "$completion_receipt" ]; then
    validate_adoption_completion_payload "$completion_receipt" "$persistent_host_final"
  else
    completion_receipt_staging=$completion_pending/.receipt.write
    /usr/bin/python3 -I -c '
import datetime, json, pathlib, sys
payload = {
    "schema_version": 1,
    "kind": "heyi-offline-adoption-completion-receipt",
    "status": "completed",
    "project": "heyi-kb-offline",
    "issued_at": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
    "adoption_transaction_id": sys.argv[2],
    "journal_sha256": sys.argv[3],
    "plan_sha256": sys.argv[4],
    "retirement_receipt_sha256": sys.argv[5],
    "retirement_signature_sha256": sys.argv[6],
    "target_contract_sha256": sys.argv[7],
    "target_manifest_sha256": sys.argv[8],
    "legacy_source_schema_head": sys.argv[9],
    "target_schema_head": sys.argv[10],
    "legacy_receipt_archive_manifest_sha256": sys.argv[11],
    "installed_receipt_sha256": sys.argv[12],
    "active_release_sha256": sys.argv[13],
    "host_isolation_final_sha256": sys.argv[14],
    "restore_boundary": "CLOSED_AFTER_MIGRATION",
    "post_migration_failure_policy": "forward-only",
    "global_actions": [],
}
pathlib.Path(sys.argv[1]).write_text(
    json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
' "$completion_receipt_staging" "$adoption_transaction_id" "$journal_sha256" \
    "$confirmed_plan_sha256" "$retirement_digest" \
    "$retirement_signature_digest" "$contract_sha256" "$manifest_digest" \
    "$legacy_source_schema_head" "$target_schema_head" \
    "$legacy_archive_manifest_digest" "$installed_digest" "$active_digest" \
    "$host_final_digest" || exit 73
    chmod 0400 "$completion_receipt_staging" || exit 73
    sync -f "$completion_receipt_staging" || exit 73
    mv -- "$completion_receipt_staging" "$completion_receipt" || exit 73
    sync -f "$completion_pending" || exit 73
  fi
  completion_signature=$completion_pending/receipt.sig
  if [ -e "$completion_signature" ] || [ -L "$completion_signature" ]; then
    validate_protected_file "pending completion signature" "$completion_signature" "400" 16384
  else
    completion_signature_staging=$completion_pending/.receipt.sig.write
    /usr/bin/openssl dgst -sha256 -sign "$evidence_signing_key" \
      -out "$completion_signature_staging" "$completion_receipt" || exit 73
    chmod 0400 "$completion_signature_staging" || exit 73
    sync -f "$completion_signature_staging" || exit 73
    mv -- "$completion_signature_staging" "$completion_signature" || exit 73
    sync -f "$completion_pending" || exit 73
  fi
  /usr/bin/openssl dgst -sha256 -verify "$evidence_public_key" \
    -signature "$completion_signature" "$completion_receipt" \
    >/dev/null 2>&1 || \
    offline_fail adoption "adoption completion signature verification failed" 73
  validate_adoption_completion_directory "$completion_pending"
  sync -f "$persistent_host_final" "$completion_receipt" "$completion_signature" || exit 73
  sync -f "$completion_pending" || exit 73
  mv -- "$completion_pending" "$completion_final" || exit 73
  sync -f "$adoption_transaction_dir" || exit 73
  validate_adoption_completion_directory "$completion_final"
  transaction_committed=true
}

enter_forward_fix_maintenance() {
  echo "adoption: POST_MIGRATION_FORWARD_FIX_ONLY" >&2
  sh "$trusted_maintenance_worker" \
    --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256" || return 1
  return 0
}

handle_transaction_failure() {
  failure_code=$1
  trap - EXIT HUP INT TERM
  final_code=$failure_code
  if [ "$transaction_committed" = true ]; then
    final_code=0
  elif [ "$transaction_terminal_aborted" = true ]; then
    final_code=$failure_code
  elif [ "$legacy_retired" = true ]; then
    if [ -n "$adoption_journal" ] && [ -f "$adoption_journal" ] && \
      [ ! -L "$adoption_journal" ] && (abort_target_pre_migration); then
      target_pre_migration_cleanup_verified=true
    fi
    if migration_boundary_is_open; then
      if restore_archived_receipts && reactivate_legacy; then
        echo "adoption: target failed before migration; exact legacy release reactivated" >&2
      else
        enter_forward_fix_maintenance || true
        final_code=71
      fi
    else
      enter_forward_fix_maintenance || true
      final_code=71
    fi
  fi
  cleanup_transaction_tmp
  cleanup_target_install_contract
  cleanup_control_contract
  exit "$final_code"
}

trap 'handle_transaction_failure $?' EXIT
trap 'exit 130' HUP INT TERM

run_adoption_orchestrator() {
  predictive_target_preflight
  if [ "$execute_requested" != true ]; then
    echo "adoption: predictive-only PASS; legacy project unchanged; execute=false"
    return 0
  fi

  prepare_target_install_contract
  if [ "$resume_journal_present" = true ]; then
    legacy_retired=true
  else
    retire_legacy
  fi
  verify_retirement_receipt
  verify_host_isolation "$host_after_retire_output"
  prepare_signed_receipt_inventory
  write_adoption_journal
  if [ "$target_adoption_state" = target_abort_needs_reactivation ]; then
    archive_started=true
    if { [ -e "$adoption_transaction_dir/target-pre-migration-abort" ] || \
      abort_target_pre_migration; } && \
      restore_archived_receipts && reactivate_legacy; then
      transaction_terminal_aborted=true
      offline_fail adoption \
        "interrupted pre-migration abort completed; transaction is terminal" 75
    fi
    offline_fail adoption "interrupted pre-migration abort could not be closed" 71
  fi
  archive_legacy_receipts
  if [ "$target_adoption_state" = adoption_completed ]; then
    transaction_committed=true
  else
    run_target_install
    verify_host_isolation "$host_final_output"
    publish_completion_receipt
  fi
}

run_adoption_orchestrator
cleanup_transaction_tmp
cleanup_target_install_contract
cleanup_control_contract
trap - EXIT HUP INT TERM
if [ "$execute_requested" = true ]; then
  echo "adoption: signed legacy release adopted successfully; transaction=$adoption_transaction_id"
fi
