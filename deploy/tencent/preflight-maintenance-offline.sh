#!/usr/bin/env sh
set -eu

if [ "$#" -ne 4 ] || [ "$1" != "--contract-dir" ] || \
  [ "$3" != "--contract-sha256" ]; then
  echo "usage: $0 --contract-dir DIR --contract-sha256 SHA256" >&2
  exit 64
fi

contract_dir=$2
expected_contract_sha256=$4
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"

offline_acquire_lock maintenance-preflight
contract_sha256=$(offline_verify_contract maintenance-preflight "$contract_dir")
if [ "$contract_sha256" != "$expected_contract_sha256" ]; then
  offline_fail maintenance-preflight "contract SHA-256 does not match" 65
fi
runtime_env_file=$(offline_contract_runtime_env "$contract_dir")
release_env_file=$(offline_contract_release_env "$contract_dir")
snapshot_script_dir=$contract_dir/release/deploy/tencent
# Re-anchor every Compose-relative asset to the verified operation snapshot.
script_dir=$snapshot_script_dir
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$snapshot_script_dir/offline-operation-common.sh"
offline_clear_inherited_environment

validator=$contract_dir/release/deploy/tencent/validate-offline-environment.py
maintenance_fields=$(python3 -I "$validator" \
  "$runtime_env_file" "$release_env_file" --emit-maintenance-fields) || exit $?
tab=$(printf '\t')
old_ifs=$IFS
IFS=$tab
# Word splitting is intentional after the strict validator rejects whitespace
# and every shell metacharacter for these six fields.
# shellcheck disable=SC2086
set -- $maintenance_fields
IFS=$old_ifs
if [ "$#" -ne 6 ]; then
  offline_fail maintenance-preflight "validated maintenance fields are incomplete" 65
fi
project_name=$1
data_root=$2
bind_address=$3
public_host=$4
https_port=$5
objects_https_port=$6

if [ "$project_name" != "$OFFLINE_PROJECT_NAME" ]; then
  offline_fail maintenance-preflight "unexpected Compose project" 65
fi

# Render-only validation is permitted here. This maintenance preflight must not
# create or start API, Web, worker, database, cache, object-storage, or app images.
offline_compose maintenance-preflight "$contract_dir" \
  --profile maintenance config --quiet

maintenance_config=$(mktemp "$OFFLINE_TMPDIR/maintenance-compose.XXXXXXXXXX")
port_listener_evidence=$(mktemp "$OFFLINE_TMPDIR/maintenance-port-listeners.XXXXXXXXXX")
cleanup_preflight_evidence() {
  rm -f "$maintenance_config" "$port_listener_evidence"
}
trap cleanup_preflight_evidence EXIT
trap 'exit 130' HUP INT TERM
if ! offline_compose maintenance-preflight "$contract_dir" \
  --profile maintenance config --format json > "$maintenance_config"; then
  offline_fail maintenance-preflight "maintenance Compose rendering failed" 69
fi
maintenance_image=$(python3 -I -c \
  'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); print(d["services"]["maintenance-page"]["image"])' \
  "$maintenance_config") || \
  offline_fail maintenance-preflight "maintenance image identity is missing" 69
if ! printf '%s\n' "$maintenance_image" | \
  grep -Eq '^127\.0\.0\.1:5000/.+@sha256:[0-9a-f]{64}$'; then
  offline_fail maintenance-preflight "maintenance image is not an exact loopback RepoDigest" 65
fi
tab=$(printf '\t')
manifest=$(offline_contract_manifest "$contract_dir")
manifest_entry=$(awk -F "$tab" -v image="$maintenance_image" \
  '$1 == image { if (found++) exit 2; print $0 } END { if (found != 1) exit 3 }' \
  "$manifest") || \
  offline_fail maintenance-preflight "maintenance image has no unique signed manifest entry" 65
old_ifs=$IFS
IFS=$tab
# shellcheck disable=SC2086
set -- $manifest_entry
IFS=$old_ifs
if [ "$#" -ne 4 ] || [ "$3" != linux ] || [ "$4" != amd64 ]; then
  offline_fail maintenance-preflight "maintenance image manifest entry is invalid" 65
fi
expected_image_id=$2
observed_image_id=$(docker image inspect --format '{{.Id}}' \
  "$maintenance_image" 2>/dev/null) || \
  offline_fail maintenance-preflight "maintenance image is not locally available" 66
observed_image_os=$(docker image inspect --format '{{.Os}}' "$maintenance_image") || exit 66
observed_image_arch=$(docker image inspect --format '{{.Architecture}}' \
  "$maintenance_image") || exit 66
observed_repo_digests=$(docker image inspect \
  --format '{{range .RepoDigests}}{{println .}}{{end}}' "$maintenance_image") || exit 66
reference_without_digest=${maintenance_image%@sha256:*}
image_digest=sha256:${maintenance_image##*@sha256:}
last_component=${reference_without_digest##*/}
case "$last_component" in
  *:*) image_repository=${reference_without_digest%:*} ;;
  *) image_repository=$reference_without_digest ;;
esac
if [ "$observed_image_id" != "$expected_image_id" ] || \
  [ "$observed_image_os" != linux ] || [ "$observed_image_arch" != amd64 ] || \
  ! printf '%s\n' "$observed_repo_digests" | \
    grep -Fqx "$image_repository@$image_digest"; then
  offline_fail maintenance-preflight \
    "maintenance image ID, platform or RepoDigest differs from the signed manifest" 65
fi

project_marker_volume=heyi-kb-offline-owner-marker
project_owner_label=jiangsu-heyi-knowledgebases
if ! docker volume inspect "$project_marker_volume" >/dev/null 2>&1; then
  offline_fail maintenance-preflight "verified project ownership marker is missing" 69
fi
marker_owner=$(docker volume inspect --format \
  '{{ index .Labels "io.heyi.knowledgebases.owner" }}' "$project_marker_volume")
marker_project=$(docker volume inspect --format \
  '{{ index .Labels "io.heyi.knowledgebases.compose-project" }}' "$project_marker_volume")
if [ "$marker_owner" != "$project_owner_label" ] || \
  [ "$marker_project" != "$project_name" ]; then
  offline_fail maintenance-preflight "Compose project ownership marker is invalid" 65
fi

validate_project_service_containers() {
  service_name=$1
  service_ids=$(docker ps -aq \
    --filter "label=com.docker.compose.project=$project_name" \
    --filter "label=com.docker.compose.service=$service_name")
  service_count=$(printf '%s\n' "$service_ids" | sed '/^$/d' | wc -l)
  if [ "$service_count" -gt 1 ]; then
    offline_fail maintenance-preflight "multiple $service_name containers violate ownership" 69
  fi
  [ "$service_count" -eq 1 ] || return 0
  service_id=$service_ids
  observed_project=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}' "$service_id") || exit 69
  observed_service=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.service" }}' "$service_id") || exit 69
  observed_owner=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' "$service_id") || exit 69
  observed_stack=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.stack" }}' "$service_id") || exit 69
  if [ "$observed_project" != "$project_name" ] || \
    [ "$observed_service" != "$service_name" ] || \
    [ "$observed_owner" != jiangsu-heyi-knowledgebases ] || \
    [ "$observed_stack" != offline ]; then
    offline_fail maintenance-preflight "container labels do not match the selected project" 69
  fi
}

validate_project_service_containers proxy
validate_project_service_containers maintenance-page

command -v ss >/dev/null 2>&1 || \
  offline_fail maintenance-preflight "ss is required for port ownership validation" 69
validate_edge_port() {
  host_port=$1
  container_port=$2
  : > "$port_listener_evidence"
  if ! ss -H -ltn "sport = :$host_port" > "$port_listener_evidence"; then
    offline_fail maintenance-preflight "cannot inspect HTTPS port" 69
  fi
  if [ ! -s "$port_listener_evidence" ]; then
    return 0
  fi
  published_ids=$(docker ps -q --filter "publish=$host_port")
  published_count=$(printf '%s\n' "$published_ids" | sed '/^$/d' | wc -l)
  if [ "$published_count" -ne 1 ]; then
    offline_fail maintenance-preflight "HTTPS port is occupied by an unverified process" 69
  fi
  published_id=$published_ids
  published_project=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}' "$published_id") || exit 69
  published_service=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.service" }}' "$published_id") || exit 69
  published_owner=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' "$published_id") || exit 69
  published_stack=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.stack" }}' "$published_id") || exit 69
  case "$published_service" in
    proxy|maintenance-page) ;;
    *) offline_fail maintenance-preflight "HTTPS port owner is not an approved edge service" 69 ;;
  esac
  if [ "$published_project" != "$project_name" ]; then
    offline_fail maintenance-preflight "HTTPS port belongs to another Compose project" 69
  fi
  if [ "$published_owner" != jiangsu-heyi-knowledgebases ] || \
    [ "$published_stack" != offline ]; then
    offline_fail maintenance-preflight "HTTPS port owner lacks the offline ownership labels" 69
  fi
  published_binding=$(docker port "$published_id" "$container_port/tcp") || exit 69
  if [ "$published_binding" != "$bind_address:$host_port" ]; then
    offline_fail maintenance-preflight "HTTPS port binding differs from the approved contract" 69
  fi
}
validate_edge_port "$https_port" 8443
validate_edge_port "$objects_https_port" 9443

validate_protected_ca_path() {
  checked_path=$1
  if [ -L "$checked_path" ] || [ ! -f "$checked_path" ]; then
    offline_fail maintenance-preflight "enterprise CA root is missing or symbolic" 69
  fi
  canonical_path=$(realpath -e -- "$checked_path" 2>/dev/null || true)
  if [ "$canonical_path" != "$checked_path" ]; then
    offline_fail maintenance-preflight "enterprise CA path contains a symbolic link" 65
  fi
  while :; do
    if [ -L "$checked_path" ]; then
      offline_fail maintenance-preflight "enterprise CA path contains a symbolic link" 65
    fi
    owner=$(stat -c %u -- "$checked_path") || exit 66
    mode=$(stat -c %a -- "$checked_path") || exit 66
    if [ "$owner" -ne 0 ]; then
      offline_fail maintenance-preflight "enterprise CA path must be owned by root" 65
    fi
    mode_value=$((0$mode))
    if [ $((mode_value & 022)) -ne 0 ]; then
      offline_fail maintenance-preflight "enterprise CA path is writable by non-root" 65
    fi
    [ "$checked_path" = / ] && break
    checked_path=$(dirname -- "$checked_path")
  done
}

ca_root=$data_root/caddy-data/caddy/pki/authorities/local/root.crt
validate_protected_ca_path "$ca_root"
ca_size=$(stat -c %s -- "$ca_root") || exit 66
case "$ca_size" in
  ""|*[!0-9]*) offline_fail maintenance-preflight "enterprise CA size is invalid" 65 ;;
esac
if [ "$ca_size" -lt 256 ] || [ "$ca_size" -gt 65536 ]; then
  offline_fail maintenance-preflight "enterprise CA size is outside the accepted boundary" 65
fi
command -v openssl >/dev/null 2>&1 || \
  offline_fail maintenance-preflight "openssl is required for enterprise CA validation" 69
ca_fingerprint=$(openssl x509 -in "$ca_root" -noout -sha256 -fingerprint 2>/dev/null) || \
  offline_fail maintenance-preflight "enterprise CA is not a valid PEM X.509 certificate" 65
if ! printf '%s\n' "$ca_fingerprint" | \
  grep -Eq '^sha256 Fingerprint=([0-9A-F]{2}:){31}[0-9A-F]{2}$'; then
  offline_fail maintenance-preflight "enterprise CA SHA-256 fingerprint is invalid" 65
fi
ca_text=$(openssl x509 -in "$ca_root" -noout -text 2>/dev/null) || \
  offline_fail maintenance-preflight "enterprise CA details cannot be inspected" 65
if ! printf '%s\n' "$ca_text" | grep -Fq 'CA:TRUE'; then
  offline_fail maintenance-preflight "enterprise CA certificate is not a CA" 65
fi
maintenance_config_directory=$data_root/maintenance
if [ -e "$maintenance_config_directory" ]; then
  offline_validate_root_directory \
    maintenance-preflight "$maintenance_config_directory" 700
else
  install -d -o root -g root -m 0700 "$maintenance_config_directory"
  offline_validate_root_directory \
    maintenance-preflight "$maintenance_config_directory" 700
fi
echo "maintenance-preflight: safe; host=$public_host; contract_sha256=$contract_sha256"
