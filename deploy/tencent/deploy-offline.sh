#!/usr/bin/env sh
set -eu

entry_mode=external
if [ "$#" -eq 2 ]; then
  runtime_source=$1
  release_source=$2
elif [ "$#" -eq 4 ] && [ "$1" = "--contract-dir" ] && \
  [ "$3" = "--contract-sha256" ]; then
  entry_mode=materialized
  supplied_contract_dir=$2
  supplied_contract_sha256=$4
else
  echo "usage: $0 /absolute/path/to/runtime.env /absolute/path/to/release.env" >&2
  echo "deploy: internal contract arguments are reserved for the verified release worker" >&2
  exit 64
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"

# One root-owned flock covers source snapshotting, full preflight, maintenance
# isolation, migration, optional bootstrap, service reconciliation and cutover.
offline_acquire_lock deploy
if [ "$entry_mode" = external ]; then
  contract_result=$(sh "$script_dir/prepare-offline-contract.sh" \
    "$runtime_source" "$release_source")
  contract_dir=${contract_result%% *}
  contract_sha256=${contract_result#* }
  verified_contract_sha256=$(offline_verify_contract deploy "$contract_dir")
  if [ "$verified_contract_sha256" != "$contract_sha256" ]; then
    offline_fail deploy "contract SHA-256 changed after snapshot creation" 65
  fi
  materialized_release=$(offline_materialize_release deploy "$contract_dir")
  materialized_entry=$materialized_release/deploy/tencent/deploy-offline.sh
  if [ ! -f "$materialized_entry" ] || [ -L "$materialized_entry" ]; then
    offline_fail deploy "materialized deployment worker is missing or symbolic" 65
  fi
  # The external wrapper ends here; the immutable worker replaces this process.
  # shellcheck disable=SC2093
  exec sh "$materialized_entry" \
    --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256"
  offline_fail deploy "cannot execute the materialized deployment worker" 73
fi
contract_dir=$supplied_contract_dir
contract_sha256=$supplied_contract_sha256
expected_materialized_root=/srv/heyi-knowledgebases-offline/releases/$contract_sha256
if [ "$OFFLINE_RELEASE_ROOT" != "$expected_materialized_root" ]; then
  offline_fail deploy "internal worker is not running from the materialized release" 65
fi
offline_validate_materialized_release deploy "$contract_dir" "$OFFLINE_RELEASE_ROOT"
runtime_env_file=$(offline_contract_runtime_env "$contract_dir")
release_env_file=$(offline_contract_release_env "$contract_dir")
snapshot_script_dir=$contract_dir/release/deploy/tencent
offline_clear_inherited_environment

business_writer_stop_timeout_seconds=150
maintenance_container_id=
maintenance_active=false
deployment_committed=false
endpoint_config_file=$OFFLINE_TMPDIR/deploy-endpoint-$contract_sha256.json

validate_exact_service() {
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

capture_single_running_service() {
  service_name=$1
  service_ids=$(docker ps -q \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=$service_name") || return 1
  old_ifs=$IFS
  IFS="$(printf '\n ')"
  # shellcheck disable=SC2086
  set -- $service_ids
  IFS=$old_ifs
  service_count=$#
  [ "$service_count" -eq 1 ] || return 1
  service_id=$service_ids
  case "$service_id" in
    *[!0-9a-f]*) return 1 ;;
  esac
  service_id_length=${#service_id}
  [ "$service_id_length" -ge 12 ] && [ "$service_id_length" -le 64 ] || return 1
  validate_exact_service "$service_id" "$service_name" || return 1
  printf '%s\n' "$service_id"
}

stop_owned_proxy_for_fail_closed_restore() {
  proxy_ids=$(docker ps -q \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=proxy") || return 1
  old_ifs=$IFS
  IFS="$(printf '\n ')"
  # shellcheck disable=SC2086
  set -- $proxy_ids
  IFS=$old_ifs
  proxy_count=$#
  if [ "$proxy_count" -gt 1 ]; then
    echo "deploy: RESTORE_FAILED multiple running proxy containers were found" >&2
    return 1
  fi
  [ "$proxy_count" -eq 1 ] || return 0
  proxy_id=$proxy_ids
  if ! validate_exact_service "$proxy_id" proxy; then
    echo "deploy: RESTORE_FAILED proxy ownership changed" >&2
    return 1
  fi
  docker stop --time 30 "$proxy_id" >/dev/null || return 1
  [ "$(docker inspect --format '{{.State.Running}}' "$proxy_id" 2>/dev/null)" = false ]
}

remove_exact_llm_egress() {
  service_ids=$(docker ps -aq \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=llm-egress") || return 1
  old_ifs=$IFS
  IFS="$(printf '\n ')"
  # shellcheck disable=SC2086
  set -- $service_ids
  IFS=$old_ifs
  [ "$#" -le 1 ] || return 1
  [ "$#" -eq 1 ] || return 0
  validate_exact_service "$service_ids" llm-egress || return 1
  [ "$(docker inspect --format '{{.State.Running}}' \
    "$service_ids" 2>/dev/null)" = false ] || return 1
  docker rm "$service_ids" >/dev/null || return 1
  remaining_ids=$(docker ps -aq \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=llm-egress") || return 1
  [ -z "$remaining_ids" ]
}

remove_exact_llm_uplink_network() {
  network_ids=$(docker network ls -q \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.network=llm-uplink") || return 1
  old_ifs=$IFS
  IFS="$(printf '\n ')"
  # shellcheck disable=SC2086
  set -- $network_ids
  IFS=$old_ifs
  [ "$#" -le 1 ] || return 1
  [ "$#" -eq 1 ] || return 0
  network_id=$network_ids
  observed_network_name=$(docker network inspect --format '{{.Name}}' \
    "$network_id" 2>/dev/null) || return 1
  observed_project=$(docker network inspect --format \
    '{{ index .Labels "com.docker.compose.project" }}' \
    "$network_id" 2>/dev/null) || return 1
  observed_logical_name=$(docker network inspect --format \
    '{{ index .Labels "com.docker.compose.network" }}' \
    "$network_id" 2>/dev/null) || return 1
  observed_owner=$(docker network inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.owner" }}' \
    "$network_id" 2>/dev/null) || return 1
  observed_stack=$(docker network inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.stack" }}' \
    "$network_id" 2>/dev/null) || return 1
  observed_internal=$(docker network inspect --format '{{.Internal}}' \
    "$network_id" 2>/dev/null) || return 1
  observed_endpoints=$(docker network inspect --format '{{len .Containers}}' \
    "$network_id" 2>/dev/null) || return 1
  [ "$observed_network_name" = "${OFFLINE_PROJECT_NAME}_llm-uplink" ] && \
    [ "$observed_project" = "$OFFLINE_PROJECT_NAME" ] && \
    [ "$observed_logical_name" = llm-uplink ] && \
    [ "$observed_owner" = jiangsu-heyi-knowledgebases ] && \
    [ "$observed_stack" = offline ] && \
    [ "$observed_internal" = false ] && \
    [ "$observed_endpoints" -eq 0 ] || return 1
  docker network rm "$network_id" >/dev/null || return 1
  remaining_networks=$(docker network ls -q \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.network=llm-uplink") || return 1
  [ -z "$remaining_networks" ]
}

assert_no_orphan_operations() {
  # A Compose `run --rm` cannot guarantee cleanup after daemon loss or a host
  # crash.  A retained one-off writer may still be changing PostgreSQL
  # while a later deployment starts, so fail closed before maintenance or any
  # new migration is attempted.  Operators must investigate and remove the
  # exact stale container deliberately; this routine never deletes evidence.
  for operation_service in migrate bootstrap; do
    operation_ids=$(docker ps -aq \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$operation_service") || \
      offline_fail deploy "cannot enumerate $operation_service operations" 69
    if [ -n "$operation_ids" ]; then
      offline_fail deploy \
        "orphan $operation_service container blocks a concurrent database operation" 69
    fi
  done
}

validate_completed_installation_state() {
  state_directory=/srv/heyi-knowledgebases-offline/state
  offline_validate_root_directory deploy "$state_directory" 700
  if [ -e "$state_directory/install-in-progress.json" ] || \
    [ -L "$state_directory/install-in-progress.json" ]; then
    return 1
  fi
  set -- "$state_directory"/installed-*.json
  if [ "$1" = "$state_directory/installed-*.json" ] || [ "$#" -ne 1 ]; then
    return 1
  fi
  installed_receipt=$1
  if [ -L "$installed_receipt" ] || [ ! -f "$installed_receipt" ] || \
    [ "$(stat -c %u -- "$installed_receipt")" -ne 0 ] || \
    [ "$(stat -c %a -- "$installed_receipt")" != 400 ] || \
    [ "$(stat -c %h -- "$installed_receipt")" -ne 1 ] || \
    [ "$(realpath -e -- "$installed_receipt")" != "$installed_receipt" ]; then
    return 1
  fi
  python3 -I "$OFFLINE_RELEASE_ROOT/deploy/tencent/offline-recovery-state.py" \
    validate-installed-receipt "$installed_receipt" 20260715_0021 >/dev/null
}

quiesce_owned_business_writers() {
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
    if [ "$#" -eq 1 ] && ! validate_exact_service "$writer_ids" "$writer_service"; then
      return 1
    fi
  done
  offline_compose deploy "$contract_dir" --profile controlled-egress \
    stop --timeout "$business_writer_stop_timeout_seconds" \
    api maintenance web llm-egress minio-multipart-gc || return 1
  for writer_service in api maintenance web llm-egress minio-multipart-gc; do
    running_writer_ids=$(docker ps -q \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$writer_service") || return 1
    [ -z "$running_writer_ids" ] || return 1
  done
}

restore_exact_maintenance() {
  if ! quiesce_owned_business_writers; then
    echo "deploy: RESTORE_FAILED business writers could not be quiesced" >&2
    return 1
  fi
  if ! stop_owned_proxy_for_fail_closed_restore; then
    return 1
  fi
  if ! validate_exact_service "$maintenance_container_id" maintenance-page; then
    echo "deploy: RESTORE_FAILED exact maintenance container identity changed" >&2
    return 1
  fi
  maintenance_running=$(docker inspect --format '{{.State.Running}}' \
    "$maintenance_container_id" 2>/dev/null || true)
  if [ "$maintenance_running" != true ]; then
    if ! docker start "$maintenance_container_id" >/dev/null; then
      echo "deploy: RESTORE_FAILED exact maintenance container could not start" >&2
      return 1
    fi
  fi
  restored_maintenance_ready=false
  for _attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if ! validate_exact_service "$maintenance_container_id" maintenance-page || \
      [ "$(docker inspect --format '{{.State.Running}}' \
        "$maintenance_container_id" 2>/dev/null || true)" != true ]; then
      break
    fi
    if python3 -I "$snapshot_script_dir/verify-maintenance-endpoint.py" \
      --compose-config-stdin < "$endpoint_config_file" >/dev/null 2>&1; then
      restored_maintenance_ready=true
      break
    fi
    sleep 2
  done
  if [ "$restored_maintenance_ready" != true ]; then
    echo "deploy: RESTORE_FAILED maintenance endpoint did not fail closed" >&2
    if validate_exact_service "$maintenance_container_id" maintenance-page; then
      docker stop --time 30 "$maintenance_container_id" >/dev/null 2>&1 || true
    fi
    return 1
  fi
  echo "deploy: deployment failed; exact maintenance endpoint remains active" >&2
}

cleanup_deploy_contract() {
  rm -f -- "$endpoint_config_file"
  if verified_digest=$(offline_verify_contract deploy "$contract_dir" 2>/dev/null) && \
    [ "$verified_digest" = "$contract_sha256" ]; then
    rm -rf -- "$contract_dir"
  fi
}

handle_exit() {
  original_code=$1
  trap - EXIT HUP INT TERM
  final_code=$original_code
  if [ "$deployment_committed" != true ] && [ "$maintenance_active" = true ]; then
    if ! restore_exact_maintenance; then
      final_code=71
    fi
  fi
  cleanup_deploy_contract
  exit "$final_code"
}
trap 'handle_exit $?' EXIT
trap 'exit 130' HUP INT TERM

verified_contract_sha256=$(offline_verify_contract deploy "$contract_dir")
if [ "$verified_contract_sha256" != "$contract_sha256" ]; then
  offline_fail deploy "contract SHA-256 changed after snapshot creation" 65
fi
selected_egress_profile=$(offline_compose_profile deploy "$contract_dir")
if ! validate_completed_installation_state; then
  offline_fail deploy \
    "upgrade requires one verified completed-install receipt and no in-progress install" 69
fi
offline_validate_upgrade_recovery_baseline deploy
assert_no_orphan_operations

# Execute the snapshotted preflight and transition code. Neither helper reopens
# the operator's original env files; the nested maintenance contract is derived
# exclusively from this root-only canonical contract.
sh "$snapshot_script_dir/preflight-offline.sh" \
  --upgrade --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256"
cutover_transaction_id=$(offline_begin_cutover \
  deploy "$contract_dir" "$contract_sha256" deploy)
sh "$OFFLINE_RELEASE_ROOT/deploy/tencent/enter-maintenance-offline.sh" \
  --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256" \
  --cutover-transaction-id "$cutover_transaction_id"

maintenance_container_id=$(capture_single_running_service maintenance-page) || \
  offline_fail deploy "one verified maintenance container must own the cutover" 70
offline_compose deploy "$contract_dir" \
  --profile maintenance config --format json > "$endpoint_config_file"
chmod 0400 "$endpoint_config_file"
python3 -I "$snapshot_script_dir/verify-maintenance-endpoint.py" \
  --compose-config-stdin < "$endpoint_config_file"
maintenance_active=true

# The old release must not keep writing while the forward-only migration runs.
# Data services remain available, but every API/BFF/background/object-cleanup
# writer is stopped and verified silent under the same deployment flock.  The
# same routine is called again by the failure handler after any partial start.
if ! quiesce_owned_business_writers; then
  offline_fail deploy "business writers remained active before migration" 70
fi
if [ "$selected_egress_profile" != controlled-egress ] && \
  ! remove_exact_llm_egress; then
  offline_fail deploy "strict_offline could not remove the exact stale LLM gateway" 71
fi
if [ "$selected_egress_profile" != controlled-egress ] && \
  ! remove_exact_llm_uplink_network; then
  offline_fail deploy "strict_offline could not remove the exact stale LLM uplink network" 71
fi

offline_compose deploy "$contract_dir" \
  --profile ops run --pull never --rm migrate
# The migration gate retains one PostgreSQL advisory lock across Alembic,
# runtime-role reconciliation and the idempotent bootstrap.  This prevents a
# second operator from entering any part of the database write sequence.

# Reconcile dependencies while the independently verified maintenance endpoint
# owns both published TLS ports. The business proxy is deliberately excluded.
if [ "$selected_egress_profile" = controlled-egress ]; then
  offline_compose deploy "$contract_dir" \
    up -d --pull never --no-build --force-recreate \
    --wait --wait-timeout 120 llm-egress
  offline_compose deploy "$contract_dir" \
    up -d --pull never --no-build --force-recreate --wait --wait-timeout 300 \
    postgres redis minio minio-init minio-multipart-gc clamd \
    llm-egress api maintenance web
else
  offline_compose deploy "$contract_dir" \
    up -d --pull never --no-build --force-recreate --wait --wait-timeout 300 \
    postgres redis minio minio-init minio-multipart-gc clamd api maintenance web
fi

if ! validate_exact_service "$maintenance_container_id" maintenance-page; then
  offline_fail deploy "maintenance ownership changed before business cutover" 70
fi
docker stop --time 30 "$maintenance_container_id" >/dev/null
if [ "$(docker inspect --format '{{.State.Running}}' \
  "$maintenance_container_id" 2>/dev/null || true)" != false ]; then
  offline_fail deploy "exact maintenance container did not stop for cutover" 70
fi

offline_compose deploy "$contract_dir" \
  up -d --pull never --no-build --no-deps --force-recreate \
  --wait --wait-timeout 120 proxy
proxy_id=$(capture_single_running_service proxy) || \
  offline_fail deploy "one verified business proxy must own the cutover" 70
if ! validate_exact_service "$proxy_id" proxy; then
  offline_fail deploy "business proxy identity changed during cutover" 70
fi
business_ready=false
for _attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if python3 -I "$snapshot_script_dir/verify-maintenance-endpoint.py" \
    --business-ready-compose-config-stdin < "$endpoint_config_file" \
    >/dev/null 2>&1; then
    business_ready=true
    break
  fi
  sleep 2
done
if [ "$business_ready" != true ]; then
  offline_fail deploy "business endpoint did not pass strict CA and readiness checks" 70
fi

final_contract_sha256=$(offline_verify_contract deploy "$contract_dir")
if [ "$final_contract_sha256" != "$contract_sha256" ]; then
  offline_fail deploy "contract changed before deployment commit" 70
fi
offline_verify_release_assets deploy "$contract_dir"
offline_verify_project_release_labels deploy "$contract_dir"
offline_commit_active_release \
  deploy "$contract_dir" "$contract_sha256" "$cutover_transaction_id"
deployment_committed=true
maintenance_active=false
if ! validate_exact_service "$maintenance_container_id" maintenance-page || \
  ! docker rm "$maintenance_container_id" >/dev/null; then
  echo "deploy: WARNING stopped maintenance container cleanup requires operator attention" >&2
fi
offline_clear_committed_cutover \
  deploy "$contract_sha256" "$cutover_transaction_id"
cleanup_deploy_contract
trap - EXIT HUP INT TERM
echo "deploy: offline release is healthy; contract_sha256=$contract_sha256"
