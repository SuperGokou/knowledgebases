#!/usr/bin/env sh
set -eu

if [ "$#" -ne 6 ] || [ "$1" != --selection ] || \
  [ "$3" != --contract-sha256 ] || [ "$5" != --transaction-id ]; then
  echo "usage: $0 --selection intent|active --contract-sha256 SHA256 --transaction-id ID" >&2
  exit 64
fi
expected_selection=$2
contract_sha256=$4
expected_transaction_id=$6
case "$expected_selection" in intent|active) ;; *) exit 64 ;; esac
printf '%s\n' "$contract_sha256" | grep -Eq '^[0-9a-f]{64}$' || exit 64
printf '%s\n' "$expected_transaction_id" | grep -Eq '^[0-9a-f]{32}$' || exit 64

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"
offline_acquire_lock recovery
offline_clear_inherited_environment
expected_materialized_root=$OFFLINE_PERSISTENT_ROOT/releases/$contract_sha256
if [ "$OFFLINE_RELEASE_ROOT" != "$expected_materialized_root" ]; then
  offline_fail recovery "reconciler is not running from the selected immutable release" 65
fi

state_helper=$script_dir/offline-recovery-state.py
selection_json=$(python3 -I "$state_helper" select) || \
  offline_fail recovery "durable transaction cannot be revalidated" 65
selection_fields=$(printf '%s\n' "$selection_json" | python3 -I -c '
import json,re,sys
d=json.load(sys.stdin)
values=(d.get("selection"),d.get("contract_sha256"),d.get("transaction_id"),d.get("compose_profile"),d.get("compose_config_sha256"),d.get("project_inventory_sha256", "-"),d.get("egress_proof_sha256", "-"),d.get("active_provider_snapshot", "none"))
if values[0] not in {"intent","active"} or not re.fullmatch(r"[0-9a-f]{64}",str(values[1])) or not re.fullmatch(r"[0-9a-f]{32}",str(values[2])) or values[3] not in {"strict-offline","controlled-egress"} or not re.fullmatch(r"[0-9a-f]{64}",str(values[4])) or (values[0] == "active" and (not re.fullmatch(r"[0-9a-f]{64}",str(values[5])) or not re.fullmatch(r"[0-9a-f]{64}",str(values[6])) or (values[3] == "strict-offline" and values[7] != "none") or (values[3] == "controlled-egress" and values[7] not in {"deepseek","qwen","minimax"}))):
    raise SystemExit(1)
print(*values)
') || offline_fail recovery "durable transaction fields are invalid" 65
# The trusted parser validates all eight whitespace-free fields before printing them.
# shellcheck disable=SC2086
set -- $selection_fields
[ "$#" -eq 8 ] || offline_fail recovery "durable transaction fields are incomplete" 65
selection=$1
selected_contract_sha256=$2
transaction_id=$3
receipt_profile=$4
receipt_compose_digest=$5
receipt_inventory_digest=$6
receipt_egress_proof_digest=$7
if [ "$selection" != "$expected_selection" ] || \
  [ "$selected_contract_sha256" != "$contract_sha256" ] || \
  [ "$transaction_id" != "$expected_transaction_id" ]; then
  offline_fail recovery "durable transaction changed after dispatcher selection" 65
fi

contract_dir=$(python3 -I "$state_helper" stage-contract \
  "$contract_sha256" "$OFFLINE_CONTRACT_ROOT") || \
  offline_fail recovery "cannot stage the persistent recovery contract" 73
endpoint_config_file=$OFFLINE_TMPDIR/recovery-endpoint-$contract_sha256.json
recovery_succeeded=false

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

stop_sensitive_services() {
  stop_list=$(mktemp "$OFFLINE_TMPDIR/recovery-stop.XXXXXXXXXX") || return 1
  for sensitive_service in \
    proxy web api maintenance llm-egress minio-multipart-gc \
    migrate bootstrap minio-init; do
    service_ids=$(docker ps -aq \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$sensitive_service") || {
      rm -f "$stop_list"
      return 1
    }
    old_ifs=$IFS
    IFS="$(printf '\n ')"
    # shellcheck disable=SC2086
    set -- $service_ids
    IFS=$old_ifs
    for service_id in "$@"; do
      [ -n "$service_id" ] || continue
      validate_exact_service "$service_id" "$sensitive_service" || {
        rm -f "$stop_list"
        return 1
      }
      printf '%s\t%s\n' "$sensitive_service" "$service_id" >> "$stop_list"
    done
  done
  stop_failed=false
  while IFS="$(printf '\t')" read -r sensitive_service service_id; do
    [ -n "$service_id" ] || continue
    running=$(docker inspect --format '{{.State.Running}}' "$service_id" 2>/dev/null) || {
      stop_failed=true
      break
    }
    if [ "$running" = true ]; then
      timeout=130
      [ "$sensitive_service" = llm-egress ] && timeout=140
      docker stop --time "$timeout" "$service_id" >/dev/null || {
        stop_failed=true
        break
      }
    fi
  done < "$stop_list"
  rm -f "$stop_list"
  [ "$stop_failed" = false ]
}

remove_exact_service() {
  service_name=$1
  service_ids=$(docker ps -aq \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=$service_name") || return 1
  old_ifs=$IFS
  IFS="$(printf '\n ')"
  # shellcheck disable=SC2086
  set -- $service_ids
  IFS=$old_ifs
  [ "$#" -le 1 ] || return 1
  [ "$#" -eq 1 ] || return 0
  validate_exact_service "$service_ids" "$service_name" || return 1
  [ "$(docker inspect --format '{{.State.Running}}' "$service_ids")" = false ] || return 1
  docker rm "$service_ids" >/dev/null
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
  observed_name=$(docker network inspect --format '{{.Name}}' "$network_id") || return 1
  observed_project=$(docker network inspect --format \
    '{{ index .Labels "com.docker.compose.project" }}' "$network_id") || return 1
  observed_logical=$(docker network inspect --format \
    '{{ index .Labels "com.docker.compose.network" }}' "$network_id") || return 1
  observed_owner=$(docker network inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.owner" }}' "$network_id") || return 1
  observed_stack=$(docker network inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.stack" }}' "$network_id") || return 1
  observed_internal=$(docker network inspect --format '{{.Internal}}' "$network_id") || return 1
  observed_endpoints=$(docker network inspect --format '{{len .Containers}}' "$network_id") || return 1
  [ "$observed_name" = "${OFFLINE_PROJECT_NAME}_llm-uplink" ] && \
    [ "$observed_project" = "$OFFLINE_PROJECT_NAME" ] && \
    [ "$observed_logical" = llm-uplink ] && \
    [ "$observed_owner" = jiangsu-heyi-knowledgebases ] && \
    [ "$observed_stack" = offline ] && \
    [ "$observed_internal" = false ] && \
    [ "$observed_endpoints" -eq 0 ] || return 1
  docker network rm "$network_id" >/dev/null
}

cleanup_recovery() {
  rm -f "$endpoint_config_file"
  if [ -n "${contract_dir:-}" ] && [ -d "$contract_dir" ] && \
    verified=$(offline_verify_contract recovery "$contract_dir" 2>/dev/null) && \
    [ "$verified" = "$contract_sha256" ]; then
    rm -rf -- "$contract_dir"
  fi
}

handle_exit() {
  original_code=$1
  trap - EXIT HUP INT TERM
  final_code=$original_code
  if [ "$recovery_succeeded" != true ] && ! stop_sensitive_services; then
    final_code=71
  fi
  cleanup_recovery
  exit "$final_code"
}
trap 'handle_exit $?' EXIT
trap 'exit 130' HUP INT TERM

verified_contract_sha256=$(offline_verify_contract recovery "$contract_dir")
[ "$verified_contract_sha256" = "$contract_sha256" ] || \
  offline_fail recovery "staged recovery contract changed" 65
offline_validate_materialized_release recovery "$contract_dir" "$OFFLINE_RELEASE_ROOT"
observed_profile=$(offline_receipt_profile recovery "$contract_dir")
observed_compose_digest=$(offline_compose_config_digest recovery "$contract_dir")
if [ "$observed_profile" != "$receipt_profile" ] || \
  [ "$observed_compose_digest" != "$receipt_compose_digest" ]; then
  offline_fail recovery "recovery contract differs from the durable receipt" 65
fi

offline_compose recovery "$contract_dir" \
  --profile maintenance config --format json > "$endpoint_config_file"
chmod 0400 "$endpoint_config_file"

if [ "$selection" = intent ]; then
  # The dispatcher already stopped every sensitive service.  Starting a
  # verified independent maintenance endpoint is best effort; failure leaves
  # both TLS ports closed and the intent remains authoritative.
  offline_compose recovery "$contract_dir" \
    --profile maintenance up -d --pull never --no-build --no-deps \
    --wait --wait-timeout 60 maintenance-page
  python3 -I "$script_dir/verify-maintenance-endpoint.py" \
    --compose-config-stdin < "$endpoint_config_file"
  recovery_succeeded=true
  cleanup_recovery
  trap - EXIT HUP INT TERM
  echo "recovery: uncommitted cutover remains fail closed; contract_sha256=$contract_sha256"
  exit 0
fi

# A committed active receipt is the only authorization to start business
# writers after daemon/host recovery.  Never run migration or bootstrap here.
# The five-second watchdog is also a steady-state auditor.  It must not mutate
# containers in an already exact and healthy deployment; it may remove one
# matching, already-committed intent left by a crash.  Run validators in subshells so
# their fail-closed exits become a recovery decision instead of terminating the
# outer reconciler before it can isolate the boundary.
steady_inventory=
steady_contract_matches=false
steady_business_ready=false
if (offline_verify_project_release_labels recovery "$contract_dir") \
    >/dev/null 2>&1 && \
  steady_inventory=$(offline_project_inventory_digest recovery 2>/dev/null) && \
  [ "$steady_inventory" = "$receipt_inventory_digest" ] && \
  (offline_verify_local_egress_liveness recovery "$contract_dir") \
    >/dev/null 2>&1; then
  steady_contract_matches=true
  # Do not isolate an exact release because of one transient readiness sample.
  # Three strictly verified samples bound the delay while avoiding needless
  # business churn from a single scheduler/network hiccup.
  for readiness_attempt in 1 2 3; do
    if python3 -I "$script_dir/verify-maintenance-endpoint.py" \
      --business-ready-compose-config-stdin < "$endpoint_config_file" \
      >/dev/null 2>&1; then
      steady_business_ready=true
      break
    fi
    [ "$readiness_attempt" = 3 ] || sleep 1
  done
fi
if "$steady_contract_matches" && "$steady_business_ready"; then
  # A crash can occur after the active receipt commit point but before the
  # deploy worker removes its matching intent.  Once the exact release,
  # receipt digest and TLS readiness have all been revalidated, converge that
  # one-time state so a later upgrade cannot mistake it for a pending cutover.
  if [ -e "$OFFLINE_CUTOVER_INTENT" ] || [ -L "$OFFLINE_CUTOVER_INTENT" ]; then
    python3 -I "$state_helper" clear-intent \
      "$contract_sha256" "$transaction_id" || \
      offline_fail recovery "cannot clear the recovered committed cutover intent" 73
  fi
  recovery_succeeded=true
  cleanup_recovery
  trap - EXIT HUP INT TERM
  echo "recovery: committed active release already matches its receipt"
  exit 0
fi

for operation_service in migrate bootstrap; do
  operation_ids=$(docker ps -aq \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=$operation_service") || \
    offline_fail recovery "cannot enumerate stale database operations" 69
  [ -z "$operation_ids" ] || \
    offline_fail recovery "stale database operation blocks active recovery" 70
done

# A mismatched or unhealthy committed deployment is isolated before repair.
# Data services remain online; Compose starts/recreates only services whose
# reviewed config changed.  `--force-recreate` is forbidden in recovery because
# the watchdog runs repeatedly and must never churn PostgreSQL/Redis/MinIO.
stop_sensitive_services || \
  offline_fail recovery "cannot isolate the active release before repair" 70

maintenance_ids=$(docker ps -aq \
  --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
  --filter "label=com.docker.compose.service=maintenance-page") || exit 69
old_ifs=$IFS
IFS="$(printf '\n ')"
# shellcheck disable=SC2086
set -- $maintenance_ids
IFS=$old_ifs
[ "$#" -le 1 ] || offline_fail recovery "multiple maintenance endpoints are unsafe" 70
if [ "$#" -eq 1 ]; then
  validate_exact_service "$maintenance_ids" maintenance-page || \
    offline_fail recovery "maintenance endpoint ownership changed" 70
  if [ "$(docker inspect --format '{{.State.Running}}' "$maintenance_ids")" = true ]; then
    docker stop --time 30 "$maintenance_ids" >/dev/null
  fi
  remove_exact_service maintenance-page || \
    offline_fail recovery "cannot remove the exact stopped maintenance endpoint" 70
fi

if [ "$receipt_profile" = controlled-egress ]; then
  offline_compose recovery "$contract_dir" \
    up -d --pull never --no-build --wait --wait-timeout 300 \
    postgres redis minio minio-init minio-multipart-gc clamd \
    llm-egress api maintenance web
else
  stale_egress_ids=$(docker ps -q \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=llm-egress") || exit 69
  if [ -n "$stale_egress_ids" ]; then
    stop_sensitive_services || \
      offline_fail recovery "strict recovery could not stop the stale LLM gateway" 70
  fi
  if ! remove_exact_service llm-egress; then
    offline_fail recovery "strict recovery found an unsafe stale LLM gateway" 70
  fi
  if ! remove_exact_llm_uplink_network; then
    offline_fail recovery "strict recovery found an unsafe stale LLM uplink" 70
  fi
  offline_compose recovery "$contract_dir" \
    up -d --pull never --no-build --wait --wait-timeout 300 \
    postgres redis minio minio-init minio-multipart-gc clamd api maintenance web
fi

# Re-establish the complete egress proof before opening either business TLS
# port.  A repaired controlled gateway must prove every approved provider
# route, and strict mode must prove both application namespaces have no
# external path.  The active provider snapshot is intentionally informational:
# operators may switch dynamically within the receipt-bound approved set.
observed_egress_fields=$(offline_egress_proof_fields \
  recovery "$contract_dir" "$contract_sha256")
# The proof helper emits exactly two constrained fields; cardinality is checked next.
# shellcheck disable=SC2086
set -- $observed_egress_fields
[ "$#" -eq 2 ] || offline_fail recovery "repaired egress proof is incomplete" 70
observed_egress_proof_digest=$1
observed_active_provider_snapshot=$2
[ -n "$observed_active_provider_snapshot" ] || \
  offline_fail recovery "repaired active provider snapshot is empty" 70
if [ "$observed_egress_proof_digest" != "$receipt_egress_proof_digest" ]; then
  offline_fail recovery "repaired egress proof differs from the durable receipt" 70
fi

offline_compose recovery "$contract_dir" \
  up -d --pull never --no-build --no-deps \
  --wait --wait-timeout 120 proxy
python3 -I "$script_dir/verify-maintenance-endpoint.py" \
  --business-ready-compose-config-stdin < "$endpoint_config_file"
offline_verify_project_release_labels recovery "$contract_dir"
observed_inventory_digest=$(offline_project_inventory_digest recovery)
if [ "$observed_inventory_digest" != "$receipt_inventory_digest" ]; then
  offline_fail recovery "active project inventory differs from the durable receipt" 70
fi

recovery_succeeded=true
cleanup_recovery
trap - EXIT HUP INT TERM
echo "recovery: committed active release is healthy; contract_sha256=$contract_sha256"
