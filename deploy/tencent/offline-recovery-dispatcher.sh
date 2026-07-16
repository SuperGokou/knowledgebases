#!/usr/bin/env sh
set -eu

# Stable systemd entry point for crash recovery.  This dispatcher never trusts
# an operator environment or a mutable checkout.  It either selects one exact
# root-only transaction/receipt, or stops only the sensitive containers that
# carry all four offline ownership labels.
unset ENV BASH_ENV CDPATH \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  http_proxy https_proxy all_proxy no_proxy \
  LD_PRELOAD LD_LIBRARY_PATH \
  PYTHONHOME PYTHONSTARTUP PYTHONINSPECT PYTHONWARNINGS PYTHONPATH \
  SSL_CERT_FILE SSL_CERT_DIR \
  DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG COMPOSE_PROJECT_NAME
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
LANG=C
export LC_ALL LANG
umask 077

project_name=heyi-kb-offline
owner_label=jiangsu-heyi-knowledgebases
stack_label=offline
runtime_root=/run/heyi-kb-offline
lock_file=$runtime_root/heyi-kb-offline.preflight.lock
lock_token=heyi-kb-offline-operation-v2
persistent_root=/srv/heyi-knowledgebases-offline
recovery_root=$persistent_root/recovery
state_helper=$recovery_root/offline-recovery-state.py

if [ "$(id -u)" -ne 0 ]; then
  echo "recovery-dispatcher: run as root" >&2
  exit 77
fi
if [ -L /run ] || [ ! -d /run ] || [ "$(stat -c %u /run)" -ne 0 ]; then
  echo "recovery-dispatcher: /run is unsafe" >&2
  exit 73
fi
if [ -e "$runtime_root" ]; then
  if [ -L "$runtime_root" ] || [ ! -d "$runtime_root" ] || \
    [ "$(stat -c %u "$runtime_root")" -ne 0 ] || \
    [ "$(stat -c %a "$runtime_root")" != 700 ]; then
    echo "recovery-dispatcher: runtime root is unsafe" >&2
    exit 73
  fi
else
  install -d -o root -g root -m 0700 "$runtime_root"
fi
command -v flock >/dev/null 2>&1 || {
  echo "recovery-dispatcher: flock is required" >&2
  exit 69
}
if [ -L "$lock_file" ]; then
  echo "recovery-dispatcher: deployment lock is symbolic" >&2
  exit 73
fi
if [ -e "$lock_file" ]; then
  if [ ! -f "$lock_file" ] || [ "$(stat -c %u "$lock_file")" -ne 0 ] || \
    [ "$(stat -c %a "$lock_file")" != 600 ] || \
    [ "$(stat -c %h "$lock_file")" -ne 1 ] || \
    [ "$(realpath -e "$lock_file")" != "$lock_file" ]; then
    echo "recovery-dispatcher: deployment lock is unsafe" >&2
    exit 73
  fi
fi
exec 9>"$lock_file"
chmod 0600 "$lock_file"
if ! flock -n 9; then
  # A live deployment owns the transaction.  A dead process releases this
  # descriptor and the next five-second timer tick performs reconciliation.
  echo "recovery-dispatcher: deployment operation is active; reconciliation deferred"
  exit 0
fi
KB_OFFLINE_LOCK_HELD=$lock_token
export KB_OFFLINE_LOCK_HELD

validate_exact_container() {
  candidate_id=$1
  expected_service=$2
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
  [ "$observed_project" = "$project_name" ] && \
    [ "$observed_service" = "$expected_service" ] && \
    [ "$observed_owner" = "$owner_label" ] && \
    [ "$observed_stack" = "$stack_label" ]
}

fail_closed_project() {
  candidate_list=$(mktemp "$runtime_root/recovery-stop.XXXXXXXXXX") || return 1
  validated_list=$(mktemp "$runtime_root/recovery-validated.XXXXXXXXXX") || {
    rm -f "$candidate_list"
    return 1
  }
  # Stop the edge first, then every business/background/model/database writer.
  # Core data services are deliberately left running.  This routine never
  # removes a container, network or volume and never addresses another project.
  for sensitive_service in \
    proxy web api maintenance llm-egress minio-multipart-gc \
    migrate bootstrap minio-init; do
    if ! docker ps -aq \
      --filter "label=com.docker.compose.project=$project_name" \
      --filter "label=com.docker.compose.service=$sensitive_service" \
      > "$candidate_list"; then
      rm -f "$candidate_list" "$validated_list"
      return 1
    fi
    candidate_validation_failed=false
    while IFS= read -r candidate_id; do
      [ -n "$candidate_id" ] || continue
      case "$candidate_id" in
        *[!0-9a-f]*)
          candidate_validation_failed=true
          break
          ;;
      esac
      if ! validate_exact_container "$candidate_id" "$sensitive_service"; then
        candidate_validation_failed=true
        break
      fi
      printf '%s\t%s\n' "$sensitive_service" "$candidate_id" >> "$validated_list"
    done < "$candidate_list"
    if [ "$candidate_validation_failed" = true ]; then
      rm -f "$candidate_list" "$validated_list"
      return 1
    fi
  done
  stop_failed=false
  while IFS="$(printf '\t')" read -r sensitive_service candidate_id; do
    [ -n "$candidate_id" ] || continue
    running=$(docker inspect --format '{{.State.Running}}' "$candidate_id" 2>/dev/null) || {
      stop_failed=true
      break
    }
    if [ "$running" = true ]; then
      timeout=130
      [ "$sensitive_service" = llm-egress ] && timeout=140
      if ! docker stop --time "$timeout" "$candidate_id" >/dev/null; then
        stop_failed=true
        break
      fi
    fi
  done < "$validated_list"
  if [ "$stop_failed" = true ]; then
    rm -f "$candidate_list" "$validated_list"
    return 1
  fi
  running_verification_failed=false
  while IFS="$(printf '\t')" read -r _service candidate_id; do
    [ -n "$candidate_id" ] || continue
    if [ "$(docker inspect --format '{{.State.Running}}' "$candidate_id" 2>/dev/null)" != false ]; then
      running_verification_failed=true
      break
    fi
  done < "$validated_list"
  rm -f "$candidate_list" "$validated_list"
  [ "$running_verification_failed" = false ]
}

if [ -L "$state_helper" ] || [ ! -f "$state_helper" ] || \
  [ "$(stat -c %u "$state_helper" 2>/dev/null || echo -1)" -ne 0 ] || \
  [ "$(stat -c %a "$state_helper" 2>/dev/null || echo 0)" != 500 ] || \
  [ "$(stat -c %h "$state_helper" 2>/dev/null || echo 0)" -ne 1 ]; then
  echo "recovery-dispatcher: trusted state helper is missing or unsafe" >&2
  fail_closed_project || exit 71
  exit 65
fi

if ! selection_json=$(python3 -I "$state_helper" select); then
  echo "recovery-dispatcher: no valid transaction exists; stopping the offline business boundary" >&2
  fail_closed_project || exit 71
  # A missing/invalid receipt is a durable safety incident, not a healthy
  # steady state.  Keep the boundary stopped and make systemd surface failure.
  exit 65
fi
selection_fields=$(printf '%s\n' "$selection_json" | python3 -I -c '
import json,re,sys
document=json.load(sys.stdin)
selection=document.get("selection")
digest=document.get("contract_sha256")
transaction=document.get("transaction_id")
if selection not in {"intent","active"} or not isinstance(digest,str) or not re.fullmatch(r"[0-9a-f]{64}",digest) or not isinstance(transaction,str) or not re.fullmatch(r"[0-9a-f]{32}",transaction):
    raise SystemExit(1)
print(selection, digest, transaction)
') || {
  fail_closed_project || exit 71
  exit 65
}
# The trusted parser emits three validated whitespace-free fields.
# shellcheck disable=SC2086
set -- $selection_fields
[ "$#" -eq 3 ] || {
  fail_closed_project || exit 71
  exit 65
}
selection=$1
contract_sha256=$2
transaction_id=$3

if [ "$selection" = intent ]; then
  fail_closed_project || {
    echo "recovery-dispatcher: exact fail-closed stop failed" >&2
    exit 71
  }
fi

materialized_root=$persistent_root/releases/$contract_sha256
worker=$materialized_root/deploy/tencent/reconcile-offline.sh
for protected_path in "$persistent_root" "$persistent_root/releases" "$materialized_root"; do
  if [ -L "$protected_path" ] || [ ! -d "$protected_path" ] || \
    [ "$(stat -c %u "$protected_path" 2>/dev/null || echo -1)" -ne 0 ]; then
    [ "$selection" = intent ] || fail_closed_project || exit 71
    echo "recovery-dispatcher: selected release path is unsafe" >&2
    exit 65
  fi
  protected_mode=$(stat -c %a "$protected_path")
  protected_value=$((0$protected_mode))
  if [ $((protected_value & 022)) -ne 0 ]; then
    [ "$selection" = intent ] || fail_closed_project || exit 71
    echo "recovery-dispatcher: selected release path is writable by non-root" >&2
    exit 65
  fi
done
if [ -L "$worker" ] || [ ! -f "$worker" ] || \
  [ "$(stat -c %u "$worker" 2>/dev/null || echo -1)" -ne 0 ] || \
  [ "$(stat -c %a "$worker" 2>/dev/null || echo 0)" != 444 ] || \
  [ "$(stat -c %h "$worker" 2>/dev/null || echo 0)" -ne 1 ]; then
  [ "$selection" = intent ] || fail_closed_project || exit 71
  echo "recovery-dispatcher: selected recovery worker is unsafe" >&2
  exit 65
fi

if sh "$worker" \
  --selection "$selection" \
  --contract-sha256 "$contract_sha256" \
  --transaction-id "$transaction_id"; then
  exit 0
else
  worker_status=$?
fi
echo "recovery-dispatcher: selected recovery worker failed; isolating the business boundary" >&2
fail_closed_project || exit 71
exit "$worker_status"
