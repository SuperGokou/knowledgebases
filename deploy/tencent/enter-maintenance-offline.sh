#!/usr/bin/env sh
set -eu

entry_mode=external
contract_owned=false
inherited_cutover=false
if [ "$#" -eq 4 ] && [ "$1" = "--contract-dir" ] && \
  [ "$3" = "--contract-sha256" ]; then
  entry_mode=materialized
  supplied_contract_dir=$2
  supplied_contract_sha256=$4
elif [ "$#" -eq 5 ] && [ "$1" = "--contract-dir" ] && \
  [ "$3" = "--contract-sha256" ] && [ "$5" = "--cleanup-contract" ]; then
  entry_mode=materialized
  contract_owned=true
  supplied_contract_dir=$2
  supplied_contract_sha256=$4
elif [ "$#" -eq 6 ] && [ "$1" = "--contract-dir" ] && \
  [ "$3" = "--contract-sha256" ] && [ "$5" = "--cutover-transaction-id" ]; then
  entry_mode=materialized
  inherited_cutover=true
  supplied_contract_dir=$2
  supplied_contract_sha256=$4
  supplied_cutover_transaction_id=$6
elif [ "$#" -eq 2 ]; then
  runtime_env_file=$1
  release_env_file=$2
else
  echo "usage: $0 /absolute/path/to/runtime.env /absolute/path/to/release.env" >&2
  echo "   or: $0 --contract-dir DIR --contract-sha256 SHA256" >&2
  exit 64
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"

offline_acquire_lock maintenance
if [ "$entry_mode" = external ]; then
  contract_result=$(sh "$script_dir/prepare-offline-contract.sh" \
    "$runtime_env_file" "$release_env_file")
  contract_dir=${contract_result%% *}
  contract_sha256=${contract_result#* }
  verified_contract_sha256=$(offline_verify_contract maintenance "$contract_dir")
  if [ "$verified_contract_sha256" != "$contract_sha256" ]; then
    offline_fail maintenance "contract SHA-256 changed after snapshot creation" 65
  fi
  materialized_release=$(offline_materialize_release maintenance "$contract_dir")
  materialized_entry=$materialized_release/deploy/tencent/enter-maintenance-offline.sh
  if [ ! -f "$materialized_entry" ] || [ -L "$materialized_entry" ]; then
    offline_fail maintenance "materialized maintenance worker is missing or symbolic" 65
  fi
  # The external wrapper ends here; the immutable worker replaces this process.
  # shellcheck disable=SC2093
  exec sh "$materialized_entry" \
    --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256" \
    --cleanup-contract
  offline_fail maintenance "cannot execute the materialized maintenance worker" 73
else
  contract_dir=$supplied_contract_dir
  contract_sha256=$supplied_contract_sha256
fi
verified_contract_sha256=$(offline_verify_contract maintenance "$contract_dir")
if [ "$verified_contract_sha256" != "$contract_sha256" ]; then
  offline_fail maintenance "contract SHA-256 changed after snapshot creation" 65
fi
expected_materialized_root=/srv/heyi-knowledgebases-offline/releases/$contract_sha256
offline_validate_materialized_release maintenance "$contract_dir" "$expected_materialized_root"
snapshot_script_dir=$expected_materialized_root/deploy/tencent
script_dir=$snapshot_script_dir
# The verified contract determines this immutable source path at runtime.
# shellcheck disable=SC1091
. "$snapshot_script_dir/offline-operation-common.sh"
offline_clear_inherited_environment

sh "$snapshot_script_dir/preflight-maintenance-offline.sh" \
  --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256"

maintenance_fields=$(python3 -I "$snapshot_script_dir/validate-offline-environment.py" \
  "$(offline_contract_runtime_env "$contract_dir")" \
  "$(offline_contract_release_env "$contract_dir")" \
  --emit-maintenance-fields)
tab=$(printf '\t')
old_ifs=$IFS
IFS=$tab
# Values are split only after the strict validator rejects whitespace and shell
# metacharacters in every emitted field.
# shellcheck disable=SC2086
set -- $maintenance_fields
IFS=$old_ifs
if [ "$#" -ne 6 ]; then
  offline_fail maintenance "validated maintenance fields are incomplete" 65
fi
data_root=$2
maintenance_config_directory=$data_root/maintenance
offline_validate_root_directory maintenance "$maintenance_config_directory" 700
persistent_caddyfile=$maintenance_config_directory/Caddyfile.maintenance
if [ -L "$persistent_caddyfile" ] || \
  { [ -e "$persistent_caddyfile" ] && [ ! -f "$persistent_caddyfile" ]; }; then
  offline_fail maintenance "persistent maintenance configuration is unsafe" 65
fi
temporary_caddyfile=$(mktemp "$maintenance_config_directory/.Caddyfile.XXXXXXXXXX")
install -o root -g root -m 0444 \
  "$snapshot_script_dir/Caddyfile.maintenance" "$temporary_caddyfile"
source_caddy_digest=$(sha256sum \
  "$snapshot_script_dir/Caddyfile.maintenance" | awk '{print $1}')
installed_caddy_digest=$(sha256sum "$temporary_caddyfile" | awk '{print $1}')
if [ "$source_caddy_digest" != "$installed_caddy_digest" ]; then
  rm -f "$temporary_caddyfile"
  offline_fail maintenance "persistent maintenance configuration copy changed" 65
fi
# Validate the exact candidate inode with the already preflighted, digest-pinned
# Caddy image before atomically replacing the reboot-persistent configuration.
# This closes the case where an existing maintenance process keeps serving its
# old loaded config while a broken new file would only fail after a reboot.
maintenance_compose_config=$(offline_compose maintenance "$contract_dir" \
  --profile maintenance config --format json) || {
  rm -f "$temporary_caddyfile"
  offline_fail maintenance "maintenance Compose contract could not be rendered" 70
}
maintenance_image=$(printf '%s\n' "$maintenance_compose_config" | python3 -I -c \
  'import json,sys; print(json.load(sys.stdin)["services"]["maintenance-page"]["image"])') || {
  unset maintenance_compose_config
  rm -f "$temporary_caddyfile"
  offline_fail maintenance "maintenance image identity could not be read" 70
}
unset maintenance_compose_config
case "$maintenance_image" in
  127.0.0.1:5000/*@sha256:*) ;;
  *)
    rm -f "$temporary_caddyfile"
    offline_fail maintenance "maintenance image is not an exact loopback digest" 65
    ;;
esac
if ! docker run --rm --pull never --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=32m,mode=1777 \
  --env "KB_PUBLIC_HOST=$4" \
  --volume "$temporary_caddyfile:/etc/caddy/Caddyfile:ro" \
  --entrypoint caddy "$maintenance_image" \
  validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null; then
  rm -f "$temporary_caddyfile"
  offline_fail maintenance "candidate maintenance configuration is invalid" 65
fi
if [ "$(sha256sum "$temporary_caddyfile" | awk '{print $1}')" != \
  "$source_caddy_digest" ]; then
  rm -f "$temporary_caddyfile"
  offline_fail maintenance "validated maintenance configuration changed" 65
fi
mv -f -- "$temporary_caddyfile" "$persistent_caddyfile"
if [ -L "$persistent_caddyfile" ] || [ ! -f "$persistent_caddyfile" ] || \
  [ "$(stat -c %u -- "$persistent_caddyfile")" -ne 0 ] || \
  [ "$(stat -c %a -- "$persistent_caddyfile")" != 444 ] || \
  [ "$(sha256sum "$persistent_caddyfile" | awk '{print $1}')" != "$source_caddy_digest" ]; then
  offline_fail maintenance "persistent maintenance configuration verification failed" 65
fi

if [ "$inherited_cutover" = true ]; then
  printf '%s\n' "$supplied_cutover_transaction_id" | \
    grep -Eq '^[0-9a-f]{32}$' || \
    offline_fail maintenance "inherited cutover transaction is invalid" 65
  selected_transaction=$(python3 -I \
    "$snapshot_script_dir/offline-recovery-state.py" select | python3 -I -c '
import json,sys
d=json.load(sys.stdin)
if d.get("selection") != "intent":
    raise SystemExit(1)
print(d.get("contract_sha256", ""), d.get("transaction_id", ""))
') || offline_fail maintenance "inherited cutover intent is not active" 65
  # The trusted helper emits two whitespace-free identifiers; cardinality is checked next.
  # shellcheck disable=SC2086
  set -- $selected_transaction
  if [ "$#" -ne 2 ] || [ "$1" != "$contract_sha256" ] || \
    [ "$2" != "$supplied_cutover_transaction_id" ]; then
    offline_fail maintenance "inherited cutover intent changed" 65
  fi
  cutover_transaction_id=$supplied_cutover_transaction_id
else
  cutover_transaction_id=$(offline_begin_cutover \
    maintenance "$contract_dir" "$contract_sha256" maintenance)
fi

proxy_id=
original_proxy_running=false
proxy_project_label=
proxy_service_label=
original_maintenance_id=
original_maintenance_running=false
transition_started=false
transition_committed=false
fail_closed_required=false
evidence_file=$OFFLINE_STATE_DIRECTORY/maintenance-transition-$contract_sha256.json

write_transition_evidence() {
  status=$1
  restoration=$2
  temporary_evidence=$(mktemp \
    "$OFFLINE_STATE_DIRECTORY/.maintenance-evidence.XXXXXXXXXX") || return 1
  printf '%s\n' \
    "{\"schema_version\":3,\"status\":\"$status\",\"contract_sha256\":\"$contract_sha256\",\"transaction_id\":\"$cutover_transaction_id\",\"proxy\":{\"container_id\":\"$proxy_id\",\"project_label\":\"$proxy_project_label\",\"service_label\":\"$proxy_service_label\",\"originally_running\":$original_proxy_running},\"maintenance\":{\"container_id\":\"$original_maintenance_id\",\"originally_running\":$original_maintenance_running},\"restoration\":\"$restoration\"}" \
    > "$temporary_evidence" || {
      rm -f "$temporary_evidence"
      return 1
    }
  chmod 0400 "$temporary_evidence" || return 1
  sync -f "$temporary_evidence" || return 1
  if ! mv -f -- "$temporary_evidence" "$evidence_file"; then
    rm -f "$temporary_evidence"
    return 1
  fi
  sync -f "$evidence_file" || return 1
  sync -f "$OFFLINE_STATE_DIRECTORY" || return 1
}

validate_exact_proxy() {
  candidate_id=$1
  [ -n "$candidate_id" ] || return 1
  observed_project=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}' "$candidate_id" 2>/dev/null) || \
    return 1
  observed_service=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.service" }}' "$candidate_id" 2>/dev/null) || \
    return 1
  observed_owner=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' \
    "$candidate_id" 2>/dev/null) || return 1
  observed_stack=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.stack" }}' \
    "$candidate_id" 2>/dev/null) || return 1
  [ "$observed_project" = "$OFFLINE_PROJECT_NAME" ] && \
    [ "$observed_service" = proxy ] && \
    [ "$observed_owner" = jiangsu-heyi-knowledgebases ] && \
    [ "$observed_stack" = offline ]
}

validate_exact_maintenance() {
  candidate_id=$1
  [ -n "$candidate_id" ] || return 1
  observed_project=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}' "$candidate_id" 2>/dev/null) || \
    return 1
  observed_service=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.service" }}' "$candidate_id" 2>/dev/null) || \
    return 1
  observed_owner=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' \
    "$candidate_id" 2>/dev/null) || return 1
  observed_stack=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.stack" }}' \
    "$candidate_id" 2>/dev/null) || return 1
  [ "$observed_project" = "$OFFLINE_PROJECT_NAME" ] && \
    [ "$observed_service" = maintenance-page ] && \
    [ "$observed_owner" = jiangsu-heyi-knowledgebases ] && \
    [ "$observed_stack" = offline ]
}

validate_exact_project_service() {
  candidate_id=$1
  expected_service=$2
  [ -n "$candidate_id" ] || return 1
  observed_project=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}' \
    "$candidate_id" 2>/dev/null) || return 1
  observed_service=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.service" }}' \
    "$candidate_id" 2>/dev/null) || return 1
  observed_owner=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' \
    "$candidate_id" 2>/dev/null) || return 1
  observed_stack=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.stack" }}' \
    "$candidate_id" 2>/dev/null) || return 1
  [ "$observed_project" = "$OFFLINE_PROJECT_NAME" ] && \
    [ "$observed_service" = "$expected_service" ] && \
    [ "$observed_owner" = jiangsu-heyi-knowledgebases ] && \
    [ "$observed_stack" = offline ]
}

quiesce_business_writers() {
  for writer_service in api maintenance web llm-egress minio-multipart-gc; do
    writer_ids=$(docker ps -aq \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$writer_service") || return 1
    old_ifs=$IFS
    IFS="$(printf '\n ')"
    # shellcheck disable=SC2086
    set -- $writer_ids
    IFS=$old_ifs
    [ "$#" -le 1 ] || return 1
    if [ "$#" -eq 1 ] && \
      ! validate_exact_project_service "$writer_ids" "$writer_service"; then
      return 1
    fi
  done
  operation_writer_list=$(mktemp "$OFFLINE_TMPDIR/maintenance-operation-writers.XXXXXXXXXX") || \
    return 1
  for operation_writer in migrate bootstrap minio-init; do
    if ! docker ps -aq \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$operation_writer" \
      > "$operation_writer_list"; then
      rm -f "$operation_writer_list"
      return 1
    fi
    operation_writer_failed=false
    while IFS= read -r operation_writer_id; do
      [ -n "$operation_writer_id" ] || continue
      if ! validate_exact_project_service \
        "$operation_writer_id" "$operation_writer"; then
        operation_writer_failed=true
        break
      fi
      operation_writer_running=$(docker inspect --format '{{.State.Running}}' \
        "$operation_writer_id" 2>/dev/null) || {
        operation_writer_failed=true
        break
      }
      if [ "$operation_writer_running" = true ] && \
        ! docker stop --time 130 "$operation_writer_id" >/dev/null; then
        operation_writer_failed=true
        break
      fi
    done < "$operation_writer_list"
    if [ "$operation_writer_failed" = true ]; then
      rm -f "$operation_writer_list"
      return 1
    fi
  done
  rm -f "$operation_writer_list"
  offline_compose maintenance "$contract_dir" \
    stop --timeout 60 api maintenance web llm-egress minio-multipart-gc || return 1
  for writer_service in api maintenance web llm-egress minio-multipart-gc; do
    running_writer_ids=$(docker ps -q \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$writer_service") || return 1
    [ -z "$running_writer_ids" ] || return 1
  done
  for operation_writer in migrate bootstrap minio-init; do
    running_operation_ids=$(docker ps -q \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$operation_writer") || return 1
    [ -z "$running_operation_ids" ] || return 1
  done
}

verify_restored_proxy() {
  restored_config=$(mktemp "$OFFLINE_TMPDIR/restored-proxy-config.XXXXXXXXXX")
  if ! offline_compose maintenance "$contract_dir" \
    --profile maintenance config --format json > "$restored_config"; then
    rm -f "$restored_config"
    return 1
  fi
  verifier=$snapshot_script_dir/verify-maintenance-endpoint.py
  restored_ready=false
  for _attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if ! validate_exact_proxy "$proxy_id" || \
      [ "$(docker inspect --format '{{.State.Running}}' "$proxy_id" 2>/dev/null || true)" != true ]; then
      break
    fi
    if python3 -I "$verifier" --business-ready-compose-config-stdin \
      < "$restored_config" >/dev/null 2>&1; then
      restored_ready=true
      break
    fi
    sleep 2
  done
  rm -f "$restored_config"
  [ "$restored_ready" = true ]
}

verify_restored_maintenance() {
  restored_config=$(mktemp "$OFFLINE_TMPDIR/restored-maintenance-config.XXXXXXXXXX")
  if ! offline_compose maintenance "$contract_dir" \
    --profile maintenance config --format json > "$restored_config"; then
    rm -f "$restored_config"
    return 1
  fi
  verifier=$snapshot_script_dir/verify-maintenance-endpoint.py
  restored_ready=false
  for _attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if ! validate_exact_maintenance "$original_maintenance_id" || \
      [ "$(docker inspect --format '{{.State.Running}}' \
        "$original_maintenance_id" 2>/dev/null || true)" != true ]; then
      break
    fi
    if python3 -I "$verifier" --compose-config-stdin \
      < "$restored_config" >/dev/null 2>&1; then
      restored_ready=true
      break
    fi
    sleep 2
  done
  rm -f "$restored_config"
  [ "$restored_ready" = true ]
}

stop_owned_maintenance() {
  maintenance_ids=$(docker ps -q \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=maintenance-page") || return 1
  old_ifs=$IFS
  IFS="$(printf '\n ')"
  # Container IDs never contain shell whitespace.
  # shellcheck disable=SC2086
  set -- $maintenance_ids
  IFS=$old_ifs
  maintenance_count=$#
  if [ "$maintenance_count" -gt 1 ]; then
    echo "maintenance: RESTORE_FAILED multiple maintenance containers were found" >&2
    return 1
  fi
  [ "$maintenance_count" -eq 1 ] || return 0
  maintenance_id=$maintenance_ids
  observed_project=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}' "$maintenance_id") || return 1
  observed_service=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.service" }}' "$maintenance_id") || return 1
  if [ "$observed_project" != "$OFFLINE_PROJECT_NAME" ] || \
    [ "$observed_service" != maintenance-page ]; then
    echo "maintenance: RESTORE_FAILED maintenance ownership changed" >&2
    return 1
  fi
  docker stop --time 30 "$maintenance_id" >/dev/null || return 1
  [ "$(docker inspect --format '{{.State.Running}}' "$maintenance_id" 2>/dev/null)" = false ]
}

restore_original_state() {
  if [ "$original_maintenance_running" = true ]; then
    if ! validate_exact_maintenance "$original_maintenance_id"; then
      echo "maintenance: RESTORE_FAILED original maintenance identity changed" >&2
      write_transition_evidence failed restoration_failed || true
      return 1
    fi
    current_maintenance_running=$(docker inspect --format '{{.State.Running}}' \
      "$original_maintenance_id" 2>/dev/null || true)
    if [ "$current_maintenance_running" != true ] && \
      ! docker start "$original_maintenance_id" >/dev/null; then
      echo "maintenance: RESTORE_FAILED original maintenance endpoint could not start" >&2
      write_transition_evidence failed restoration_failed || true
      return 1
    fi
    if ! verify_restored_maintenance; then
      echo "maintenance: RESTORE_FAILED original maintenance endpoint is not strictly healthy" >&2
      write_transition_evidence failed restoration_failed || true
      return 1
    fi
    write_transition_evidence failed exact_original_maintenance_ready || return 1
    return 0
  fi
  if ! stop_owned_maintenance; then
    write_transition_evidence failed restoration_failed || true
    return 1
  fi
  if [ "$original_proxy_running" != true ]; then
    write_transition_evidence failed not_required_originally_stopped || return 1
    return 0
  fi
  if ! validate_exact_proxy "$proxy_id"; then
    echo "maintenance: RESTORE_FAILED original proxy identity or labels changed" >&2
    write_transition_evidence failed restoration_failed || true
    return 1
  fi
  if ! docker start "$proxy_id" >/dev/null; then
    echo "maintenance: RESTORE_FAILED exact original proxy could not be started" >&2
    write_transition_evidence failed restoration_failed || true
    return 1
  fi
  if ! verify_restored_proxy; then
    echo "maintenance: RESTORE_FAILED exact original proxy did not pass strict readiness" >&2
    if validate_exact_proxy "$proxy_id"; then
      docker stop --time 30 "$proxy_id" >/dev/null 2>&1 || true
    fi
    restored_running=$(docker inspect --format '{{.State.Running}}' \
      "$proxy_id" 2>/dev/null || true)
    if [ "$restored_running" = true ]; then
      echo "maintenance: RESTORE_FAILED unready proxy could not be stopped" >&2
      write_transition_evidence failed fail_closed_stop_failed || true
    else
      write_transition_evidence failed fail_closed_proxy_stopped || true
    fi
    return 1
  fi
  write_transition_evidence failed exact_original_proxy_ready || return 1
  return 0
}

cleanup_failed_contract() {
  [ "$contract_owned" = true ] || return 0
  if verified_digest=$(offline_verify_contract maintenance "$contract_dir" 2>/dev/null) && \
    [ "$verified_digest" = "$contract_sha256" ]; then
    rm -rf -- "$contract_dir"
  fi
}

handle_exit() {
  original_code=$1
  trap - EXIT HUP INT TERM
  final_code=$original_code
  if [ "$transition_committed" != true ]; then
    if [ "$fail_closed_required" = true ]; then
      if ! quiesce_business_writers; then
        final_code=71
      fi
      if [ -n "$proxy_id" ] && validate_exact_proxy "$proxy_id" && \
        [ "$(docker inspect --format '{{.State.Running}}' \
          "$proxy_id" 2>/dev/null || true)" = true ] && \
        ! docker stop --time 30 "$proxy_id" >/dev/null; then
        final_code=71
      fi
      write_transition_evidence failed fail_closed_intent_retained || final_code=71
    elif [ "$transition_started" = true ] && ! restore_original_state; then
      final_code=71
    fi
    cleanup_failed_contract
  fi
  exit "$final_code"
}
trap 'handle_exit $?' EXIT
trap 'exit 130' HUP INT TERM

proxy_ids=$(docker ps -aq \
  --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
  --filter "label=com.docker.compose.service=proxy") || \
  offline_fail maintenance "cannot enumerate proxy containers" 69
old_ifs=$IFS
IFS="$(printf '\n ')"
# shellcheck disable=SC2086
set -- $proxy_ids
IFS=$old_ifs
proxy_count=$#
if [ "$proxy_count" -gt 1 ]; then
  offline_fail maintenance "multiple proxy containers violate the ownership boundary" 69
fi
if [ "$proxy_count" -eq 1 ]; then
  proxy_id=$proxy_ids
  if ! printf '%s\n' "$proxy_id" | grep -Eq '^[0-9a-f]{12,64}$'; then
    offline_fail maintenance "proxy container ID has an invalid form" 69
  fi
  proxy_project_label=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}' "$proxy_id")
  proxy_service_label=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.service" }}' "$proxy_id")
  if [ "$proxy_project_label" != "$OFFLINE_PROJECT_NAME" ] || \
    [ "$proxy_service_label" != proxy ]; then
    offline_fail maintenance "proxy labels do not match the approved project" 69
  fi
  original_proxy_running=$(docker inspect --format '{{.State.Running}}' "$proxy_id")
  case "$original_proxy_running" in
    true|false) ;;
    *) offline_fail maintenance "proxy running state is invalid" 69 ;;
  esac
fi

maintenance_ids=$(docker ps -aq \
  --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
  --filter "label=com.docker.compose.service=maintenance-page") || \
  offline_fail maintenance "cannot enumerate maintenance containers" 69
old_ifs=$IFS
IFS="$(printf '\n ')"
# shellcheck disable=SC2086
set -- $maintenance_ids
IFS=$old_ifs
maintenance_count=$#
if [ "$maintenance_count" -gt 1 ]; then
  offline_fail maintenance "multiple maintenance containers violate the ownership boundary" 69
fi
if [ "$maintenance_count" -eq 1 ]; then
  original_maintenance_id=$maintenance_ids
  if ! printf '%s\n' "$original_maintenance_id" | grep -Eq '^[0-9a-f]{12,64}$' || \
    ! validate_exact_maintenance "$original_maintenance_id"; then
    offline_fail maintenance "maintenance container identity is invalid" 69
  fi
  original_maintenance_running=$(docker inspect --format '{{.State.Running}}' \
    "$original_maintenance_id")
  case "$original_maintenance_running" in
    true|false) ;;
    *) offline_fail maintenance "maintenance running state is invalid" 69 ;;
  esac
fi
if [ "$original_proxy_running" = true ] && \
  [ "$original_maintenance_running" = true ]; then
  offline_fail maintenance "proxy and maintenance cannot both be running" 69
fi

write_transition_evidence prepared not_started || \
  offline_fail maintenance "cannot persist transition evidence" 73
transition_started=true
if [ "$original_maintenance_running" = true ]; then
  if ! verify_restored_maintenance; then
    offline_fail maintenance "existing maintenance endpoint is not strictly healthy" 70
  fi
  fail_closed_required=true
  quiesce_business_writers || \
    offline_fail maintenance "maintenance is active but business writers did not quiesce" 70
  final_contract_digest=$(offline_verify_contract maintenance "$contract_dir")
  if [ "$final_contract_digest" != "$contract_sha256" ]; then
    offline_fail maintenance "contract changed before idempotent transition commit" 70
  fi
  write_transition_evidence \
    active exact_original_maintenance_preserved_writers_quiesced || \
    offline_fail maintenance "cannot persist quiesced maintenance evidence" 73
  transition_committed=true
  if [ "$contract_owned" = true ]; then
    rm -rf -- "$contract_dir"
    [ ! -e "$contract_dir" ] || \
      offline_fail maintenance "verified maintenance contract cleanup failed" 73
  fi
  trap - EXIT HUP INT TERM
  echo "maintenance: existing fail-closed endpoint remains healthy; contract_sha256=$contract_sha256"
  echo "maintenance: evidence=$evidence_file"
  exit 0
fi
fail_closed_required=true
quiesce_business_writers || \
  offline_fail maintenance "business writers did not quiesce before edge cutover" 70
if [ "$original_proxy_running" = true ]; then
  if ! validate_exact_proxy "$proxy_id"; then
    offline_fail maintenance "proxy identity changed before stop" 69
  fi
  docker stop --time 30 "$proxy_id" >/dev/null
  stopped_running=$(docker inspect --format '{{.State.Running}}' "$proxy_id")
  if [ "$stopped_running" != false ]; then
    offline_fail maintenance "exact proxy did not stop" 70
  fi
fi

if ! offline_compose maintenance "$contract_dir" \
  --profile maintenance up -d --pull never --no-build --no-deps \
  --wait --wait-timeout 60 maintenance-page; then
  offline_fail maintenance "independent maintenance endpoint failed to start" 70
fi

verifier=$contract_dir/release/deploy/tencent/verify-maintenance-endpoint.py
if ! maintenance_config=$(offline_compose maintenance "$contract_dir" \
  --profile maintenance config --format json); then
  offline_fail maintenance "maintenance Compose contract could not be rendered" 70
fi
if ! printf '%s\n' "$maintenance_config" | \
  python3 -I "$verifier" --compose-config-stdin; then
  unset maintenance_config
  offline_fail maintenance "strict CA/SAN/200/503 endpoint contract failed" 70
fi
unset maintenance_config

final_contract_digest=$(offline_verify_contract maintenance "$contract_dir")
if [ "$final_contract_digest" != "$contract_sha256" ]; then
  offline_fail maintenance "contract changed before transition commit" 70
fi
write_transition_evidence active maintenance_ready_writers_quiesced || \
  offline_fail maintenance "cannot persist quiesced maintenance evidence" 73
transition_committed=true
if [ "$contract_owned" = true ]; then
  rm -rf -- "$contract_dir"
  if [ -e "$contract_dir" ]; then
    offline_fail maintenance "verified maintenance contract cleanup failed" 73
  fi
fi
echo "maintenance: fail-closed endpoint is healthy; contract_sha256=$contract_sha256"
echo "maintenance: evidence=$evidence_file"
