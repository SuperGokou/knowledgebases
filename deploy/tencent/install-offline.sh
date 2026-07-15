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
  echo "install: internal contract arguments are reserved for the verified release worker" >&2
  exit 64
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"

offline_acquire_lock install
if [ "$entry_mode" = external ]; then
  contract_result=$(sh "$script_dir/prepare-offline-contract.sh" \
    "$runtime_source" "$release_source")
  contract_dir=${contract_result%% *}
  contract_sha256=${contract_result#* }
  verified_contract_sha256=$(offline_verify_contract install "$contract_dir")
  if [ "$verified_contract_sha256" != "$contract_sha256" ]; then
    offline_fail install "contract SHA-256 changed after snapshot creation" 65
  fi
  materialized_release=$(offline_materialize_release install "$contract_dir")
  materialized_entry=$materialized_release/deploy/tencent/install-offline.sh
  if [ ! -f "$materialized_entry" ] || [ -L "$materialized_entry" ]; then
    offline_fail install "materialized installation worker is missing or symbolic" 65
  fi
  # The external wrapper ends here; the immutable worker replaces this process.
  # shellcheck disable=SC2093
  exec sh "$materialized_entry" \
    --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256"
  offline_fail install "cannot execute the materialized installation worker" 73
fi
contract_dir=$supplied_contract_dir
contract_sha256=$supplied_contract_sha256
expected_materialized_root=/srv/heyi-knowledgebases-offline/releases/$contract_sha256
if [ "$OFFLINE_RELEASE_ROOT" != "$expected_materialized_root" ]; then
  offline_fail install "internal worker is not running from the materialized release" 65
fi
offline_validate_materialized_release install "$contract_dir" "$OFFLINE_RELEASE_ROOT"
snapshot_script_dir=$contract_dir/release/deploy/tencent
endpoint_config_file=$OFFLINE_TMPDIR/install-endpoint-$contract_sha256.json
installation_committed=false
install_state_owned=false
resume_install=false
state_directory=/srv/heyi-knowledgebases-offline/state
state_file=$state_directory/install-in-progress.json
installed_receipt=$state_directory/installed-$contract_sha256.json
offline_clear_inherited_environment

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

write_install_state() {
  phase=$1
  temporary_state=$(mktemp "$state_directory/.install-state.XXXXXXXXXX")
  runtime_digest=$(sha256sum "$contract_dir/runtime.env" | awk '{print $1}') || {
    rm -f "$temporary_state"
    offline_fail install "cannot hash runtime contract for installation state" 66
  }
  release_digest=$(sha256sum "$contract_dir/release.env" | awk '{print $1}') || {
    rm -f "$temporary_state"
    offline_fail install "cannot hash release contract for installation state" 66
  }
  manifest_digest=$(sha256sum "$contract_dir/release.env.images" | awk '{print $1}') || {
    rm -f "$temporary_state"
    offline_fail install "cannot hash image manifest for installation state" 66
  }
  printf '%s\n' \
    "{\"schema_version\":1,\"contract_sha256\":\"$contract_sha256\",\"runtime_sha256\":\"$runtime_digest\",\"release_sha256\":\"$release_digest\",\"manifest_sha256\":\"$manifest_digest\",\"phase\":\"$phase\"}" \
    > "$temporary_state" || {
    rm -f "$temporary_state"
    offline_fail install "cannot write installation state" 73
  }
  chmod 0400 "$temporary_state" || exit 73
  sync -f "$temporary_state" || exit 73
  mv -f -- "$temporary_state" "$state_file" || exit 73
  sync -f "$state_file" || exit 73
  sync -f "$state_directory" || exit 73
}

validate_resume_resources() {
  resource_list=$(mktemp "$OFFLINE_TMPDIR/install-resources.XXXXXXXXXX")
  seen_services=" "
  docker ps -aq --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    > "$resource_list" || return 1
  while IFS= read -r container_id; do
    [ -n "$container_id" ] || continue
    service_name=$(docker inspect --format \
      '{{ index .Config.Labels "com.docker.compose.service" }}' "$container_id") || return 1
    case "$seen_services" in
      *" $service_name "*) return 1 ;;
    esac
    seen_services="$seen_services$service_name "
    case "$service_name" in
      postgres|redis|minio|minio-init|minio-multipart-gc|clamd|\
      api|maintenance|web|proxy|llm-egress) ;;
      *) return 1 ;;
    esac
    validate_exact_service "$container_id" "$service_name" || return 1
  done < "$resource_list"

  docker network ls -q --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    > "$resource_list" || return 1
  while IFS= read -r network_id; do
    [ -n "$network_id" ] || continue
    network_name=$(docker network inspect --format '{{.Name}}' "$network_id") || return 1
    network_owner=$(docker network inspect --format \
      '{{ index .Labels "io.heyi.knowledgebases.owner" }}' "$network_id") || return 1
    network_stack=$(docker network inspect --format \
      '{{ index .Labels "io.heyi.knowledgebases.stack" }}' "$network_id") || return 1
    case "$network_name" in
      heyi-kb-offline_edge|heyi-kb-offline_backend|heyi-kb-offline_frontend|\
      heyi-kb-offline_llm-control|heyi-kb-offline_llm-uplink) ;;
      *) return 1 ;;
    esac
    [ "$network_owner" = jiangsu-heyi-knowledgebases ] && \
      [ "$network_stack" = offline ] || return 1
  done < "$resource_list"

  docker volume ls -q --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    > "$resource_list" || return 1
  if [ -s "$resource_list" ]; then
    return 1
  fi
  rm -f "$resource_list"
}

remove_stopped_resume_oneoffs() {
  oneoff_list=$(mktemp "$OFFLINE_TMPDIR/install-oneoffs.XXXXXXXXXX") || return 1
  for oneoff_service in api-preflight clamav-db-preflight migrate bootstrap; do
    if ! docker ps -aq \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$oneoff_service" > "$oneoff_list"; then
      rm -f "$oneoff_list"
      return 1
    fi
    oneoff_validation_failed=false
    while IFS= read -r oneoff_id; do
      [ -n "$oneoff_id" ] || continue
      if ! validate_exact_service "$oneoff_id" "$oneoff_service"; then
        oneoff_validation_failed=true
        break
      fi
      oneoff_marker=$(docker inspect --format \
        '{{ index .Config.Labels "com.docker.compose.oneoff" }}' \
        "$oneoff_id" 2>/dev/null) || {
          oneoff_validation_failed=true
          break
        }
      oneoff_running=$(docker inspect --format '{{.State.Running}}' \
        "$oneoff_id" 2>/dev/null) || {
          oneoff_validation_failed=true
          break
        }
      if { [ "$oneoff_marker" != True ] && [ "$oneoff_marker" != true ]; } || \
        [ "$oneoff_running" != false ] || ! docker rm "$oneoff_id" >/dev/null; then
        oneoff_validation_failed=true
        break
      fi
    done < "$oneoff_list"
    if [ "$oneoff_validation_failed" = true ]; then
      rm -f "$oneoff_list"
      return 1
    fi
    remaining_oneoffs=$(docker ps -aq \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$oneoff_service") || {
        rm -f "$oneoff_list"
        return 1
      }
    if [ -n "$remaining_oneoffs" ]; then
      rm -f "$oneoff_list"
      return 1
    fi
  done
  rm -f "$oneoff_list"
}

stop_exact_install_services() {
  cleanup_failed=false
  for service_name in proxy web api maintenance minio-multipart-gc llm-egress; do
    service_ids=$(docker ps -q \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$service_name") || {
      cleanup_failed=true
      continue
    }
    old_ifs=$IFS
    IFS="$(printf '\n ')"
    # shellcheck disable=SC2086
    set -- $service_ids
    IFS=$old_ifs
    if [ "$#" -gt 1 ]; then
      echo "install: CLEANUP_FAILED multiple $service_name containers were found" >&2
      cleanup_failed=true
      continue
    fi
    [ "$#" -eq 1 ] || continue
    if ! validate_exact_service "$service_ids" "$service_name"; then
      echo "install: CLEANUP_FAILED $service_name ownership changed" >&2
      cleanup_failed=true
      continue
    fi
    if ! docker stop --time 30 "$service_ids" >/dev/null; then
      echo "install: CLEANUP_FAILED exact $service_name container did not stop" >&2
      cleanup_failed=true
    fi
  done
  [ "$cleanup_failed" = false ]
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
  docker rm -f "$service_ids" >/dev/null || return 1
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

cleanup_install_contract() {
  rm -f -- "$endpoint_config_file"
  if verified_digest=$(offline_verify_contract install "$contract_dir" 2>/dev/null) && \
    [ "$verified_digest" = "$contract_sha256" ]; then
    rm -rf -- "$contract_dir"
  fi
}

handle_exit() {
  original_code=$1
  trap - EXIT HUP INT TERM
  final_code=$original_code
  if [ "$installation_committed" != true ] && \
    [ "$install_state_owned" = true ] && ! stop_exact_install_services; then
    final_code=71
  fi
  cleanup_install_contract
  exit "$final_code"
}
trap 'handle_exit $?' EXIT
trap 'exit 130' HUP INT TERM

verified_contract_sha256=$(offline_verify_contract install "$contract_dir")
if [ "$verified_contract_sha256" != "$contract_sha256" ]; then
  offline_fail install "contract SHA-256 changed after snapshot creation" 65
fi

# Validate secrets before creating a resumable state. This lets an operator fix
# an invalid bootstrap password without leaving a receipt bound to bad input.
python3 -I "$snapshot_script_dir/validate-offline-environment.py" \
  "$contract_dir/runtime.env" "$contract_dir/release.env" \
  --require-bootstrap-password
selected_egress_profile=$(offline_compose_profile install "$contract_dir")

for protected_directory in /srv /srv/heyi-knowledgebases-offline; do
  if [ -L "$protected_directory" ]; then
    offline_fail install "installation state path must not be symbolic" 65
  fi
  if [ -e "$protected_directory" ]; then
    owner=$(stat -c %u -- "$protected_directory") || exit 66
    mode=$(stat -c %a -- "$protected_directory") || exit 66
    mode_value=$((0$mode))
    if [ "$owner" -ne 0 ] || [ $((mode_value & 022)) -ne 0 ]; then
      offline_fail install "installation state ancestor is writable by non-root" 65
    fi
  fi
done
install -d -o root -g root -m 0750 /srv/heyi-knowledgebases-offline
install -d -o root -g root -m 0700 "$state_directory"
offline_validate_root_directory install "$state_directory" 700

set -- "$state_directory"/installed-*.json
if [ "$1" != "$state_directory/installed-*.json" ]; then
  offline_fail install \
    "a completed installation receipt already exists; use deploy-offline.sh or the audited disaster-recovery procedure" 69
fi
if [ -e "$state_file" ]; then
  if [ -L "$state_file" ] || [ ! -f "$state_file" ] || \
    [ "$(stat -c %u -- "$state_file")" -ne 0 ] || \
    [ "$(stat -c %a -- "$state_file")" != 400 ] || \
    [ "$(stat -c %h -- "$state_file")" -ne 1 ] || \
    [ "$(realpath -e -- "$state_file")" != "$state_file" ]; then
    offline_fail install "installation state has unsafe ownership or permissions" 65
  fi
  if ! python3 -I -c '
import hashlib, json, pathlib, re, sys
state_path = pathlib.Path(sys.argv[1])
contract_dir = pathlib.Path(sys.argv[2])
expected_contract = sys.argv[3]
document = json.loads(state_path.read_text(encoding="utf-8"))
expected_keys = {
    "schema_version", "contract_sha256", "runtime_sha256",
    "release_sha256", "manifest_sha256", "phase",
}
allowed_phases = {
    "prepared", "preflight_passed", "migrated", "bootstrapped",
    "core_ready", "proxy_started", "completed",
}
def digest(name):
    return hashlib.sha256((contract_dir / name).read_bytes()).hexdigest()
valid = (
    set(document) == expected_keys
    and document["schema_version"] == 1
    and document["contract_sha256"] == expected_contract
    and re.fullmatch(r"[0-9a-f]{64}", expected_contract) is not None
    and document["runtime_sha256"] == digest("runtime.env")
    and document["release_sha256"] == digest("release.env")
    and document["manifest_sha256"] == digest("release.env.images")
    and document["phase"] in allowed_phases
)
raise SystemExit(0 if valid else 1)
' "$state_file" "$contract_dir" "$contract_sha256"; then
    offline_fail install "installation state does not match this canonical contract" 65
  fi
  install_state_owned=true
  resume_install=true
  if ! remove_stopped_resume_oneoffs; then
    offline_fail install \
      "running or unverified one-off operations block safe installation resume" 69
  fi
  if ! validate_resume_resources; then
    offline_fail install "resumable project resources failed exact ownership validation" 69
  fi
  if ! stop_exact_install_services; then
    offline_fail install "resumable business writers could not be stopped" 71
  fi
  for stopped_service in proxy web api maintenance minio-multipart-gc llm-egress; do
    running_ids=$(docker ps -q \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$stopped_service") || \
      offline_fail install "cannot verify $stopped_service is stopped" 69
    if [ -n "$running_ids" ]; then
      offline_fail install "$stopped_service remained active during resume" 71
    fi
  done
else
  baseline_resources=$(mktemp "$OFFLINE_TMPDIR/install-baseline.XXXXXXXXXX")
  docker ps -aq --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    >> "$baseline_resources" || offline_fail install "cannot inspect existing containers" 69
  docker network ls -q --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    >> "$baseline_resources" || offline_fail install "cannot inspect existing networks" 69
  docker volume ls -q --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    >> "$baseline_resources" || offline_fail install "cannot inspect existing volumes" 69
  if [ -s "$baseline_resources" ]; then
    rm -f "$baseline_resources"
    offline_fail install "initial installation found an unowned project resource" 69
  fi
  rm -f "$baseline_resources"
  write_install_state prepared
  install_state_owned=true
fi

# Publish a durable root-only intent and install the boot/timer reconciler
# before the first migration or business writer can be created.  A SIGKILL or
# power loss from this point therefore converges to a closed business boundary.
cutover_transaction_id=$(offline_begin_cutover \
  install "$contract_dir" "$contract_sha256" install)

# Install preflight rejects every existing Compose resource. Both TLS ports stay
# closed until migration, bootstrap and all internal services are healthy.
if [ "$resume_install" = true ]; then
  sh "$snapshot_script_dir/preflight-offline.sh" --resume-install \
    --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256"
else
  sh "$snapshot_script_dir/preflight-offline.sh" \
    --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256"
fi
write_install_state preflight_passed

offline_compose install "$contract_dir" \
  --profile ops run --pull never --rm migrate
write_install_state migrated
# The migrate one-off holds one database advisory lock across migration,
# runtime-role reconciliation and bootstrap.
write_install_state bootstrapped
if [ "$selected_egress_profile" = controlled-egress ]; then
  offline_compose install "$contract_dir" \
    up -d --pull never --no-build --force-recreate \
    --wait --wait-timeout 120 llm-egress
  offline_compose install "$contract_dir" \
    up -d --pull never --no-build --force-recreate --wait --wait-timeout 300 \
    postgres redis minio minio-init minio-multipart-gc clamd \
    llm-egress api maintenance web
else
  if ! remove_exact_llm_egress; then
    offline_fail install "strict_offline could not remove the exact stale LLM gateway" 71
  fi
  if ! remove_exact_llm_uplink_network; then
    offline_fail install "strict_offline could not remove the exact stale LLM uplink network" 71
  fi
  offline_compose install "$contract_dir" \
    up -d --pull never --no-build --force-recreate --wait --wait-timeout 300 \
    postgres redis minio minio-init minio-multipart-gc clamd api maintenance web
fi
write_install_state core_ready

offline_compose install "$contract_dir" \
  --profile maintenance config --format json > "$endpoint_config_file"
chmod 0400 "$endpoint_config_file"
offline_compose install "$contract_dir" \
  up -d --pull never --no-build --no-deps --force-recreate \
  --wait --wait-timeout 120 proxy
write_install_state proxy_started

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
  offline_fail install "business endpoint did not pass strict CA and readiness checks" 70
fi

final_contract_sha256=$(offline_verify_contract install "$contract_dir")
if [ "$final_contract_sha256" != "$contract_sha256" ]; then
  offline_fail install "contract changed before installation commit" 70
fi
offline_verify_release_assets install "$contract_dir"
offline_verify_project_release_labels install "$contract_dir"
offline_commit_active_release \
  install "$contract_dir" "$contract_sha256" "$cutover_transaction_id"
write_install_state completed
mv -f -- "$state_file" "$installed_receipt"
sync -f "$installed_receipt"
sync -f "$state_directory"
offline_clear_committed_cutover \
  install "$contract_sha256" "$cutover_transaction_id"
installation_committed=true
cleanup_install_contract
trap - EXIT HUP INT TERM
echo "install: offline release is healthy; contract_sha256=$contract_sha256"
