#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"

offline_acquire_lock preflight
cleanup_contract=
project_resource_candidates=
port_listener_evidence=
disk_usage_evidence=
docker_storage_evidence=
preflight_mode=install
preflight_adoption_transaction=none
if [ "${1:-}" = "--upgrade" ]; then
  preflight_mode=upgrade
  shift
elif [ "${1:-}" = "--resume-install" ]; then
  preflight_mode=install-resume
  shift
fi
if [ "$#" -eq 6 ] && [ "$1" = "--contract-dir" ] && \
  [ "$3" = "--contract-sha256" ] && \
  [ "$5" = "--adoption-transaction" ]; then
  contract_dir=$2
  expected_contract_sha256=$4
  preflight_adoption_transaction=$6
elif [ "$#" -eq 4 ] && [ "$1" = "--contract-dir" ] && \
  [ "$3" = "--contract-sha256" ]; then
  contract_dir=$2
  expected_contract_sha256=$4
elif [ "$#" -eq 2 ]; then
  runtime_source=$1
  release_source=$2
  contract_result=$(sh "$script_dir/prepare-offline-contract.sh" \
    "$runtime_source" "$release_source")
  contract_dir=${contract_result%% *}
  expected_contract_sha256=${contract_result#* }
  cleanup_contract=$contract_dir
else
  echo "usage: $0 RUNTIME_ENV RELEASE_ENV" >&2
  echo "   or: $0 [--upgrade|--resume-install] --contract-dir DIR --contract-sha256 SHA256 [--adoption-transaction TX]" >&2
  exit 64
fi

cleanup_preflight_contract() {
  if [ -n "$project_resource_candidates" ]; then
    rm -f "$project_resource_candidates"
  fi
  if [ -n "$port_listener_evidence" ]; then
    rm -f "$port_listener_evidence"
  fi
  if [ -n "$disk_usage_evidence" ]; then
    rm -f "$disk_usage_evidence"
  fi
  if [ -n "$docker_storage_evidence" ]; then
    rm -f "$docker_storage_evidence"
  fi
  if [ -n "$cleanup_contract" ]; then
    verified_cleanup_digest=$(offline_verify_contract preflight "$cleanup_contract") || return
    if [ "$verified_cleanup_digest" = "$expected_contract_sha256" ]; then
      rm -rf -- "$cleanup_contract"
    fi
  fi
}
trap cleanup_preflight_contract EXIT
trap 'exit 130' HUP INT TERM

contract_sha256=$(offline_verify_contract preflight "$contract_dir")
if [ "$contract_sha256" != "$expected_contract_sha256" ]; then
  offline_fail preflight "contract SHA-256 does not match the accepted snapshot" 65
fi
case "$preflight_adoption_transaction" in
  none) ;;
  *)
    if ! printf '%s\n' "$preflight_adoption_transaction" | \
      grep -Eq '^[0-9a-f]{32}$'; then
      offline_fail preflight "adoption transaction identifier is invalid" 65
    fi
    ;;
esac
snapshot_script_dir=$contract_dir/release/deploy/tencent
# From this point onward every helper and Compose primitive is loaded from the
# verified snapshot, so replacing the release directory cannot change the
# accepted operation after its contract digest has been recorded.
script_dir=$snapshot_script_dir
# The verified contract determines this immutable source path at runtime.
# shellcheck disable=SC1091
. "$snapshot_script_dir/offline-operation-common.sh"
runtime_env_file=$(offline_contract_runtime_env "$contract_dir")
release_env_file=$(offline_contract_release_env "$contract_dir")
image_manifest=$(offline_contract_manifest "$contract_dir")
compose_file=$(offline_contract_compose_file "$contract_dir")
offline_clear_inherited_environment

command -v python3 >/dev/null 2>&1 || \
  offline_fail preflight "python3 is required for environment validation" 69
if [ "$preflight_mode" != upgrade ]; then
  python3 -I "$snapshot_script_dir/validate-offline-environment.py" \
    "$runtime_env_file" "$release_env_file" --require-bootstrap-password
else
  python3 -I "$snapshot_script_dir/validate-offline-environment.py" \
    "$runtime_env_file" "$release_env_file"
fi

fail_env() {
  echo "preflight: $1" >&2
  exit 65
}

require_safe_token() {
  token_name=$1
  token_value=$2
  case "$token_value" in
    ""|*[!a-zA-Z0-9_.@:/-]*) fail_env "unsafe value for $token_name" ;;
  esac
}

require_url_component() {
  component_name=$1
  component_value=$2
  # These values are interpolated into PostgreSQL/Redis URLs without percent
  # encoding. Restrict them to RFC 3986 unreserved characters so delimiters
  # cannot alter the authority, host, port, path, or query interpretation.
  case "$component_value" in
    ""|*[!a-zA-Z0-9._~-]*) fail_env "unsafe URL component for $component_name" ;;
  esac
}

require_unsigned_integer() {
  integer_name=$1
  integer_value=$2
  case "$integer_value" in
    ""|*[!0-9]*) fail_env "unsafe value for $integer_name" ;;
  esac
}

require_pinned_image_reference() {
  image_name=$1
  image_value=$2
  if ! printf '%s\n' "$image_value" | grep -Eq '^.+@sha256:[0-9a-f]{64}$'; then
    fail_env "$image_name must be pinned by an exact sha256 digest"
  fi
  case "$image_value" in
    *@sha256:0000000000000000000000000000000000000000000000000000000000000000)
      fail_env "$image_name still contains the example zero digest"
      ;;
  esac
}

is_ipv4() {
  candidate=$1
  case "$candidate" in
    ""|.*|*.|*..*|*[!0-9.]*) return 1 ;;
  esac
  old_ifs=$IFS
  IFS=.
  # Word splitting is intentional: each field is one IPv4 octet.
  # shellcheck disable=SC2086
  set -- $candidate
  IFS=$old_ifs
  [ "$#" -eq 4 ] || return 1
  for octet in "$@"; do
    case "$octet" in
      ""|*[!0-9]*) return 1 ;;
    esac
    [ "$octet" -le 255 ] 2>/dev/null || return 1
  done
}

is_approved_private_host() {
  candidate=$1
  [ "$candidate" = "localhost" ] && return 0
  is_ipv4 "$candidate" || return 1
  old_ifs=$IFS
  IFS=.
  # shellcheck disable=SC2086
  set -- $candidate
  IFS=$old_ifs
  first=$1
  second=$2
  case "$first" in
    10|127) return 0 ;;
    169) [ "$second" -eq 254 ] ; return ;;
    172) [ "$second" -ge 16 ] && [ "$second" -le 31 ] ; return ;;
    192) [ "$second" -eq 168 ] ; return ;;
    *) return 1 ;;
  esac
}

seen_keys=" "
line_number=0
carriage_return=$(printf '\r')
while IFS= read -r raw_line || [ -n "$raw_line" ]; do
  line_number=$((line_number + 1))
  case "$raw_line" in
    *"$carriage_return") line=${raw_line%"$carriage_return"} ;;
    *) line=$raw_line ;;
  esac
  case "$line" in
    ""|'#'*) continue ;;
    *'='*) ;;
    *) fail_env "invalid environment syntax on line $line_number" ;;
  esac

  key=${line%%=*}
  value=${line#*=}
  case "$key" in
    ""|*[!A-Z0-9_]*|[0-9]*) fail_env "invalid environment key on line $line_number" ;;
  esac
  case "$seen_keys" in
    *" $key "*) fail_env "duplicate environment key: $key" ;;
  esac
  seen_keys="$seen_keys$key "

  case "$value" in
    \'*\') value=${value#\'}; value=${value%\'} ;;
    \"*\") value=${value#\"}; value=${value%\"} ;;
    \'*|*\'|\"*|*\") fail_env "unbalanced quotes for $key" ;;
  esac
  case "$value" in
    *'$'*|*'`'*|*\\*|*';'*|*'&'*|*'|'*|*'<'*|*'>'*)
      fail_env "unsafe value for $key"
      ;;
  esac

  case "$key" in
    KB_HTTPS_PORT|KB_OBJECTS_HTTPS_PORT|KB_MULTIPART_THRESHOLD_BYTES|\
    CLAMAV_DATABASE_MAX_AGE_SECONDS|KB_MALWARE_SCAN_TIMEOUT_SECONDS|\
    KB_MALWARE_SCAN_CHUNK_SIZE_BYTES|KB_MALWARE_SCAN_RECLAIM_SECONDS|\
    MINIO_MULTIPART_CLEANUP_INTERVAL_SECONDS|KB_DATABASE_POOL_SIZE|\
    KB_DATABASE_MAX_OVERFLOW|KB_DATABASE_POOL_TIMEOUT_SECONDS|\
    KB_DATABASE_STATEMENT_TIMEOUT_MS|KB_DATABASE_LOCK_TIMEOUT_MS|\
    KB_DATABASE_IDLE_TRANSACTION_TIMEOUT_MS|KB_CHAT_REPLAY_ACTIVE_KEY_VERSION)
      require_unsigned_integer "$key" "$value"
      ;;
    POSTGRES_PASSWORD|POSTGRES_APP_PASSWORD|REDIS_PASSWORD)
      require_url_component "$key" "$value"
      ;;
    MINIO_ROOT_PASSWORD|MINIO_APP_PASSWORD|KB_JWT_SECRET|\
    KB_BFF_SHARED_SECRET|KB_LLM_CREDENTIAL_ENCRYPTION_KEY)
      require_safe_token "$key" "$value"
      ;;
    KB_BOOTSTRAP_ADMIN_PASSWORD)
      [ -z "$value" ] || require_safe_token "$key" "$value"
      ;;
    KB_LLM_EGRESS_MODE)
      require_safe_token "$key" "$value"
      ;;
    KB_LLM_EGRESS_GATEWAY_URL)
      [ -z "$value" ] || require_safe_token "$key" "$value"
      ;;
    KB_LLM_EGRESS_APPROVED_PROVIDERS)
      case "$value" in
        ""|deepseek|qwen|minimax|deepseek,qwen|deepseek,minimax|qwen,minimax|deepseek,qwen,minimax) ;;
        *) fail_env "unsafe value for $key" ;;
      esac
      ;;
    KB_UPGRADE_BACKUP_EVIDENCE_PATH|KB_UPGRADE_BACKUP_SIGNATURE_PATH|\
    KB_UPGRADE_BACKUP_PUBLIC_KEY_PATH)
      [ -z "$value" ] || require_safe_token "$key" "$value"
      ;;
    COMPOSE_PROJECT_NAME|KB_DATA_ROOT|KB_BIND_ADDRESS|KB_PUBLIC_HOST|\
    KB_PUBLIC_ORIGIN|POSTGRES_DB|POSTGRES_USER|\
    POSTGRES_APP_USER|MINIO_ROOT_USER|MINIO_APP_USER|MINIO_REGION|\
    MINIO_BUCKET|MINIO_MULTIPART_MAX_AGE|KB_BOOTSTRAP_ADMIN_EMAIL)
      require_safe_token "$key" "$value"
      ;;
    KB_TRUSTED_HOSTS|KB_CORS_ORIGINS|KB_CHAT_REPLAY_ENCRYPTION_KEYS) ;;
    *) fail_env "unknown environment key: $key" ;;
  esac

  # Only retain values consumed by this verifier. Docker Compose reads the
  # complete, already validated contract from its immutable --env-file inputs.
  case "$key" in
    COMPOSE_PROJECT_NAME) COMPOSE_PROJECT_NAME=$value ;;
    KB_DATA_ROOT) KB_DATA_ROOT=$value ;;
    KB_BIND_ADDRESS) KB_BIND_ADDRESS=$value ;;
    KB_PUBLIC_HOST) KB_PUBLIC_HOST=$value ;;
    KB_HTTPS_PORT) KB_HTTPS_PORT=$value ;;
    KB_OBJECTS_HTTPS_PORT) KB_OBJECTS_HTTPS_PORT=$value ;;
    KB_PUBLIC_ORIGIN) KB_PUBLIC_ORIGIN=$value ;;
    POSTGRES_DB) POSTGRES_DB=$value ;;
    POSTGRES_USER) POSTGRES_USER=$value ;;
    POSTGRES_APP_USER) POSTGRES_APP_USER=$value ;;
    KB_LLM_EGRESS_MODE) KB_LLM_EGRESS_MODE=$value ;;
    KB_LLM_EGRESS_GATEWAY_URL) KB_LLM_EGRESS_GATEWAY_URL=$value ;;
    KB_LLM_EGRESS_APPROVED_PROVIDERS) KB_LLM_EGRESS_APPROVED_PROVIDERS=$value ;;
    KB_UPGRADE_BACKUP_EVIDENCE_PATH) KB_UPGRADE_BACKUP_EVIDENCE_PATH=$value ;;
    KB_UPGRADE_BACKUP_SIGNATURE_PATH) KB_UPGRADE_BACKUP_SIGNATURE_PATH=$value ;;
    KB_UPGRADE_BACKUP_PUBLIC_KEY_PATH) KB_UPGRADE_BACKUP_PUBLIC_KEY_PATH=$value ;;
    KB_TRUSTED_HOSTS) KB_TRUSTED_HOSTS=$value ;;
    KB_CORS_ORIGINS) KB_CORS_ORIGINS=$value ;;
    KB_CHAT_REPLAY_ENCRYPTION_KEYS) KB_CHAT_REPLAY_ENCRYPTION_KEYS=$value ;;
    KB_CHAT_REPLAY_ACTIVE_KEY_VERSION) KB_CHAT_REPLAY_ACTIVE_KEY_VERSION=$value ;;
  esac
done < "$runtime_env_file"

# Release files contain no secrets. They are parsed separately and loaded after
# runtime.env so a rollback cannot accidentally inherit the current release's
# application images.
seen_keys=" "
line_number=0
while IFS= read -r raw_line || [ -n "$raw_line" ]; do
  line_number=$((line_number + 1))
  case "$raw_line" in
    *"$carriage_return") line=${raw_line%"$carriage_return"} ;;
    *) line=$raw_line ;;
  esac
  case "$line" in
    ""|'#'*) continue ;;
    *'='*) ;;
    *) fail_env "invalid release environment syntax on line $line_number" ;;
  esac

  key=${line%%=*}
  value=${line#*=}
  case "$key" in
    ""|*[!A-Z0-9_]*|[0-9]*) fail_env "invalid release environment key on line $line_number" ;;
  esac
  case "$seen_keys" in
    *" $key "*) fail_env "duplicate release environment key: $key" ;;
  esac
  seen_keys="$seen_keys$key "

  case "$value" in
    \'*\') value=${value#\'}; value=${value%\'} ;;
    \"*\") value=${value#\"}; value=${value%\"} ;;
    \'*|*\'|\"*|*\") fail_env "unbalanced quotes for $key" ;;
  esac
  case "$value" in
    *'$'*|*'`'*|*\\*|*';'*|*'&'*|*'|'*|*'<'*|*'>'*)
      fail_env "unsafe value for $key"
      ;;
  esac

  case "$key" in
    KB_API_IMAGE|KB_MIGRATION_IMAGE|KB_WEB_IMAGE)
      require_pinned_image_reference "$key" "$value"
      ;;
    *) fail_env "unknown release environment key: $key" ;;
  esac

  case "$key" in
    KB_API_IMAGE) KB_API_IMAGE=$value ;;
    KB_MIGRATION_IMAGE) KB_MIGRATION_IMAGE=$value ;;
    KB_WEB_IMAGE) KB_WEB_IMAGE=$value ;;
  esac
done < "$release_env_file"

: "${KB_API_IMAGE:?required}"
: "${KB_MIGRATION_IMAGE:?required}"
: "${KB_WEB_IMAGE:?required}"

: "${COMPOSE_PROJECT_NAME:?required}"
: "${KB_DATA_ROOT:?required}"
: "${KB_PUBLIC_HOST:?required}"
: "${KB_HTTPS_PORT:?required}"
: "${KB_OBJECTS_HTTPS_PORT:?required}"
: "${POSTGRES_USER:?required}"
: "${POSTGRES_APP_USER:?required}"
: "${KB_CHAT_REPLAY_ENCRYPTION_KEYS:?required}"
: "${KB_CHAT_REPLAY_ACTIVE_KEY_VERSION:?required}"
: "${KB_LLM_EGRESS_MODE:?required}"
if [ "${KB_LLM_EGRESS_GATEWAY_URL+x}" != x ]; then
  fail_env "KB_LLM_EGRESS_GATEWAY_URL is required (empty in strict_offline)"
fi
if [ "${KB_LLM_EGRESS_APPROVED_PROVIDERS+x}" != x ]; then
  fail_env "KB_LLM_EGRESS_APPROVED_PROVIDERS is required (empty in strict_offline)"
fi

for database_role in "$POSTGRES_USER" "$POSTGRES_APP_USER"; do
  require_url_component "database role" "$database_role"
done
require_url_component "POSTGRES_DB" "$POSTGRES_DB"

if ! [ "$POSTGRES_USER" != "$POSTGRES_APP_USER" ]; then
  echo "preflight: database owner and runtime role must be different" >&2
  exit 65
fi

if [ "$COMPOSE_PROJECT_NAME" != "heyi-kb-offline" ]; then
  echo "preflight: COMPOSE_PROJECT_NAME must be heyi-kb-offline" >&2
  exit 65
fi

case "$KB_DATA_ROOT" in
  /srv/heyi-knowledgebases-offline/data) ;;
  *) echo "preflight: unexpected KB_DATA_ROOT" >&2; exit 65 ;;
esac

if ! is_approved_private_host "$KB_PUBLIC_HOST"; then
  echo "preflight: KB_PUBLIC_HOST must be an approved private or local address" >&2
  exit 65
fi
if ! is_approved_private_host "$KB_BIND_ADDRESS"; then
  echo "preflight: KB_BIND_ADDRESS must be an approved private or local address" >&2
  exit 65
fi
for port in "$KB_HTTPS_PORT" "$KB_OBJECTS_HTTPS_PORT"; do
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo "preflight: HTTPS ports must be between 1 and 65535" >&2
    exit 65
  fi
done
if [ "$KB_HTTPS_PORT" -eq "$KB_OBJECTS_HTTPS_PORT" ]; then
  echo "preflight: HTTPS and object HTTPS ports must be different" >&2
  exit 65
fi
expected_public_origin=https://$KB_PUBLIC_HOST:$KB_HTTPS_PORT
if [ "$KB_PUBLIC_ORIGIN" != "$expected_public_origin" ]; then
  echo "preflight: KB_PUBLIC_ORIGIN must exactly match the approved public host and port" >&2
  exit 65
fi
if [ "$KB_TRUSTED_HOSTS" != "[\"$KB_PUBLIC_HOST\",\"api\"]" ]; then
  echo "preflight: KB_TRUSTED_HOSTS must contain only KB_PUBLIC_HOST and the internal api service" >&2
  exit 65
fi
if [ "$KB_CORS_ORIGINS" != "[]" ]; then
  echo "preflight: KB_CORS_ORIGINS must remain empty in the offline profile" >&2
  exit 65
fi

host_arch=$(uname -m) || offline_fail preflight "cannot inspect host architecture" 69
if [ "$host_arch" != x86_64 ]; then
  offline_fail preflight "host architecture must be native x86_64" 69
fi
docker_server_platform=$(docker info --format '{{.OSType}} {{.Architecture}}') || \
  offline_fail preflight "cannot inspect Docker server platform" 69
case "$docker_server_platform" in
  "linux x86_64"|"linux amd64") ;;
  *) offline_fail preflight "Docker server must be native linux/amd64" 69 ;;
esac
docker_root=$(docker info --format '{{.DockerRootDir}}') || \
  offline_fail preflight "cannot inspect DockerRootDir" 69
case "$docker_root" in
  /*) ;;
  *) offline_fail preflight "DockerRootDir must be an absolute path" 69 ;;
esac
canonical_docker_root=$(realpath -e -- "$docker_root" 2>/dev/null || true)
if [ "$canonical_docker_root" != "$docker_root" ] || [ ! -d "$docker_root" ] || \
  [ -L "$docker_root" ]; then
  offline_fail preflight "DockerRootDir must be a canonical non-symbolic directory" 69
fi
docker_root_owner=$(stat -c %u -- "$docker_root") || \
  offline_fail preflight "cannot inspect DockerRootDir owner" 69
docker_root_mode=$(stat -c %a -- "$docker_root") || \
  offline_fail preflight "cannot inspect DockerRootDir permissions" 69
docker_root_mode_value=$((0$docker_root_mode))
if [ "$docker_root_owner" -ne 0 ] || [ $((docker_root_mode_value & 022)) -ne 0 ]; then
  offline_fail preflight "DockerRootDir must be root owned and non-writable by other users" 69
fi
docker_storage_evidence=$(mktemp "$OFFLINE_TMPDIR/docker-storage.XXXXXXXXXX")
if ! df -Pk "$docker_root" > "$docker_storage_evidence"; then
  offline_fail preflight "cannot inspect DockerRootDir free space" 69
fi
docker_available_kib=$(awk \
  'NR == 2 { available=$4 } END { if (NR != 2) exit 1; print available }' \
  "$docker_storage_evidence") || \
  offline_fail preflight "DockerRootDir capacity evidence is malformed" 69
case "$docker_available_kib" in
  ""|*[!0-9]*) offline_fail preflight "DockerRootDir free space is invalid" 69 ;;
esac
if [ "$docker_available_kib" -lt 41943040 ]; then
  offline_fail preflight "DockerRootDir requires at least 40 GiB free for images and rollback" 69
fi
if ! df -Pi "$docker_root" > "$docker_storage_evidence"; then
  offline_fail preflight "cannot inspect DockerRootDir inode capacity" 69
fi
docker_inode_fields=$(awk \
  'NR == 2 { total=$2; available=$4 } END { if (NR != 2) exit 1; print total, available }' \
  "$docker_storage_evidence") || \
  offline_fail preflight "DockerRootDir inode evidence is malformed" 69
# awk emits exactly two numeric fields; cardinality and type are checked next.
# shellcheck disable=SC2086
set -- $docker_inode_fields
if [ "$#" -ne 2 ]; then
  offline_fail preflight "DockerRootDir inode fields are incomplete" 69
fi
docker_total_inodes=$1
docker_available_inodes=$2
for inode_value in "$docker_total_inodes" "$docker_available_inodes"; do
  case "$inode_value" in
    ""|*[!0-9]*) offline_fail preflight "DockerRootDir inode capacity is invalid" 69 ;;
  esac
done
if [ "$docker_total_inodes" -le 0 ]; then
  offline_fail preflight "DockerRootDir reports no inode capacity" 69
fi
required_docker_inodes=$((docker_total_inodes / 10))
if [ "$required_docker_inodes" -lt 100000 ]; then
  required_docker_inodes=100000
fi
if [ "$docker_available_inodes" -lt "$required_docker_inodes" ]; then
  offline_fail preflight "DockerRootDir requires at least 10 percent and 100000 free inodes" 69
fi
compose_version=$(docker compose version --short) || \
  offline_fail preflight "cannot inspect Docker Compose version" 69
compose_version=${compose_version#v}
compose_version=${compose_version%%-*}
old_ifs=$IFS
IFS=.
# shellcheck disable=SC2086
set -- $compose_version
IFS=$old_ifs
if [ "$#" -lt 2 ]; then
  offline_fail preflight "Docker Compose version is invalid" 69
fi
compose_major=$1
compose_minor=$2
case "$compose_major:$compose_minor" in
  *[!0-9:]*) offline_fail preflight "Docker Compose version is invalid" 69 ;;
esac
if [ "$compose_major" -lt 2 ] || \
  { [ "$compose_major" -eq 2 ] && [ "$compose_minor" -lt 20 ]; }; then
  offline_fail preflight "Docker Compose 2.20 or newer is required" 69
fi

cpu_count=$(getconf _NPROCESSORS_ONLN) || \
  offline_fail preflight "cannot inspect logical CPU count" 69
memory_kib=$(awk '/MemTotal:/ {print $2; found=1} END {if (!found) exit 1}' \
  /proc/meminfo) || offline_fail preflight "cannot inspect usable memory" 69
for capacity_value in "$cpu_count" "$memory_kib"; do
  case "$capacity_value" in
    ""|*[!0-9]*) offline_fail preflight "host capacity evidence is invalid" 69 ;;
  esac
done
if [ "$cpu_count" -lt 8 ]; then
  echo "preflight: at least 8 logical CPUs are required" >&2
  exit 69
fi
if [ "$memory_kib" -lt 15000000 ]; then
  echo "preflight: at least 15 GB usable memory is required" >&2
  exit 69
fi

deployment_root=/srv/heyi-knowledgebases-offline
expected_data_root=$deployment_root/data
canonical_data_root=$(realpath -m -- "$KB_DATA_ROOT") || {
  echo "preflight: cannot canonicalize KB_DATA_ROOT" >&2
  exit 65
}
if [ "$canonical_data_root" != "$expected_data_root" ]; then
  echo "preflight: KB_DATA_ROOT or one of its parents must not be symbolic" >&2
  exit 65
fi

# Every existing parent that can redirect the first directory creation must be
# a root-owned, non-writable directory. Child service directories may later be
# chowned by their containers, so ownership enforcement intentionally stops at
# the data root.
for secure_directory in /srv "$deployment_root" "$expected_data_root"; do
  if [ -L "$secure_directory" ]; then
    echo "preflight: deployment path must not contain symbolic links" >&2
    exit 65
  fi
  if [ -e "$secure_directory" ]; then
    if [ ! -d "$secure_directory" ]; then
      echo "preflight: deployment path component must be a directory" >&2
      exit 65
    fi
    secure_owner=$(stat -c %u -- "$secure_directory") || exit 66
    secure_mode=$(stat -c %a -- "$secure_directory") || exit 66
    case "$secure_mode" in
      *[2367][0-7]|*[2367])
        echo "preflight: deployment path must not be group or world writable" >&2
        exit 65
        ;;
    esac
    if [ "$secure_owner" -ne 0 ]; then
      echo "preflight: deployment path must be owned by root" >&2
      exit 65
    fi
  fi
done

install -d -o root -g root -m 0750 "$deployment_root" "$KB_DATA_ROOT"

chat_safety_directory=$KB_DATA_ROOT/chat-safety
if [ -L "$chat_safety_directory" ]; then
  offline_fail preflight "chat safety directory must not be symbolic" 65
fi
if [ -e "$chat_safety_directory" ]; then
  [ -d "$chat_safety_directory" ] || \
    offline_fail preflight "chat safety path must be a directory" 65
else
  install -d -o 10001 -g 10001 -m 0700 "$chat_safety_directory"
fi
chat_safety_canonical=$(realpath -e -- "$chat_safety_directory" 2>/dev/null || true)
chat_safety_uid=$(stat -c %u -- "$chat_safety_directory") || \
  offline_fail preflight "cannot inspect chat safety directory owner" 66
chat_safety_gid=$(stat -c %g -- "$chat_safety_directory") || \
  offline_fail preflight "cannot inspect chat safety directory group" 66
chat_safety_mode=$(stat -c %a -- "$chat_safety_directory") || \
  offline_fail preflight "cannot inspect chat safety directory mode" 66
if [ "$chat_safety_canonical" != "$chat_safety_directory" ] || \
  [ "$chat_safety_uid" -ne 10001 ] || [ "$chat_safety_gid" -ne 10001 ] || \
  [ "$chat_safety_mode" != 700 ]; then
  offline_fail preflight "chat safety directory ownership or mode is invalid" 65
fi
sync -f "$chat_safety_directory" || \
  offline_fail preflight "cannot sync chat safety directory" 73
sync -f "$KB_DATA_ROOT" || \
  offline_fail preflight "cannot sync chat safety parent directory" 73
offline_require_no_chat_safety_poison preflight

project_marker_volume=heyi-kb-offline-owner-marker
project_owner_label=jiangsu-heyi-knowledgebases
project_resource_candidates=$(mktemp "$OFFLINE_TMPDIR/project-resources.XXXXXXXXXX")
docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
  >> "$project_resource_candidates" || \
  offline_fail preflight "cannot enumerate project containers" 69
docker network ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
  >> "$project_resource_candidates" || \
  offline_fail preflight "cannot enumerate project networks" 69
docker volume ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
  >> "$project_resource_candidates" || \
  offline_fail preflight "cannot enumerate project volumes" 69
project_resources=$(LC_ALL=C sort -u "$project_resource_candidates") || \
  offline_fail preflight "cannot normalize project resources" 69

if docker volume inspect "$project_marker_volume" >/dev/null 2>&1; then
  marker_owner=$(docker volume inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.owner" }}' "$project_marker_volume")
  marker_project=$(docker volume inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.compose-project" }}' "$project_marker_volume")
  marker_contract=$(docker volume inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.contract-sha256" }}' "$project_marker_volume")
  marker_adoption=$(docker volume inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.adoption-transaction" }}' \
    "$project_marker_volume")
  if [ "$marker_owner" != "$project_owner_label" ] || \
    [ "$marker_project" != "$COMPOSE_PROJECT_NAME" ]; then
    echo "preflight: compose project ownership marker is invalid" >&2
    exit 65
  fi
  if [ "$preflight_mode" != upgrade ] && \
    { [ "$marker_contract" != "$contract_sha256" ] || \
      [ "$marker_adoption" != "$preflight_adoption_transaction" ]; }; then
    echo "preflight: compose project marker transaction binding differs" >&2
    exit 65
  fi
elif [ "$preflight_mode" = upgrade ]; then
  echo "preflight: upgrade requires the verified project ownership marker" >&2
  exit 69
elif [ -n "$project_resources" ]; then
  echo "preflight: compose project name is already owned by an unverified deployment" >&2
  exit 69
else
  docker volume create \
    --label "io.heyi.knowledgebases.owner=$project_owner_label" \
    --label "io.heyi.knowledgebases.compose-project=$COMPOSE_PROJECT_NAME" \
    --label "io.heyi.knowledgebases.contract-sha256=$contract_sha256" \
    --label "io.heyi.knowledgebases.adoption-transaction=$preflight_adoption_transaction" \
    "$project_marker_volume" >/dev/null
  marker_owner=$(docker volume inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.owner" }}' "$project_marker_volume")
  marker_project=$(docker volume inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.compose-project" }}' "$project_marker_volume")
  marker_contract=$(docker volume inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.contract-sha256" }}' "$project_marker_volume")
  marker_adoption=$(docker volume inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.adoption-transaction" }}' \
    "$project_marker_volume")
  if [ "$marker_owner" != "$project_owner_label" ] || \
    [ "$marker_project" != "$COMPOSE_PROJECT_NAME" ] || \
    [ "$marker_contract" != "$contract_sha256" ] || \
    [ "$marker_adoption" != "$preflight_adoption_transaction" ]; then
    echo "preflight: compose project ownership marker creation was not verifiable" >&2
    exit 73
  fi
fi

if [ "$preflight_mode" = install ]; then
  if [ -n "$project_resources" ]; then
    echo "preflight: initial installation requires an unused project identity" >&2
    exit 69
  fi
elif [ "$preflight_mode" = upgrade ] && [ -z "$project_resources" ]; then
  echo "preflight: upgrade requires an existing verified project deployment" >&2
  exit 69
fi

validate_existing_project_inventory() {
  inventory_file=$(mktemp "$OFFLINE_TMPDIR/project-inventory.XXXXXXXXXX") || return 1
  if ! docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
    > "$inventory_file"; then
    rm -f "$inventory_file"
    return 1
  fi
  seen_services=" "
  inventory_valid=true
  while IFS= read -r container_id; do
    [ -n "$container_id" ] || continue
    service_name=$(docker inspect --format \
      '{{ index .Config.Labels "com.docker.compose.service" }}' "$container_id") || {
        inventory_valid=false
        break
      }
    case "$service_name" in
      postgres|redis|minio|minio-init|minio-multipart-gc|clamd|\
      api|maintenance|web|proxy|llm-egress|maintenance-page) ;;
      *) inventory_valid=false; break ;;
    esac
    case "$seen_services" in
      *" $service_name "*) inventory_valid=false; break ;;
    esac
    seen_services="$seen_services$service_name "
    owner_label=$(docker inspect --format \
      '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' "$container_id") || {
        inventory_valid=false
        break
      }
    stack_label=$(docker inspect --format \
      '{{ index .Config.Labels "io.heyi.knowledgebases.stack" }}' "$container_id") || {
        inventory_valid=false
        break
      }
    oneoff_label=$(docker inspect --format \
      '{{ index .Config.Labels "com.docker.compose.oneoff" }}' "$container_id") || {
        inventory_valid=false
        break
      }
    config_label=$(docker inspect --format \
      '{{ index .Config.Labels "com.docker.compose.project.config_files" }}' \
      "$container_id") || {
        inventory_valid=false
        break
      }
    image_reference=$(docker inspect --format '{{.Config.Image}}' "$container_id") || {
      inventory_valid=false
      break
    }
    case "$config_label" in
      /srv/heyi-knowledgebases-offline/releases/*/deploy/tencent/compose.offline.yml) ;;
      *) inventory_valid=false; break ;;
    esac
    release_digest=${config_label#/srv/heyi-knowledgebases-offline/releases/}
    release_digest=${release_digest%%/*}
    if ! printf '%s\n' "$release_digest" | grep -Eq '^[0-9a-f]{64}$' || \
      [ "$(realpath -e -- "$config_label" 2>/dev/null || true)" != "$config_label" ] || \
      [ -L "$config_label" ] || [ "$(stat -c %u -- "$config_label")" -ne 0 ] || \
      [ "$(stat -c %a -- "$config_label")" != 444 ] || \
      [ "$owner_label" != "$project_owner_label" ] || \
      [ "$stack_label" != offline ] || \
      { [ "$oneoff_label" != False ] && [ "$oneoff_label" != false ]; } || \
      ! printf '%s\n' "$image_reference" | \
        grep -Eq '^127\.0\.0\.1:5000/.+@sha256:[0-9a-f]{64}$'; then
      inventory_valid=false
      break
    fi
  done < "$inventory_file"
  if [ "$inventory_valid" != true ]; then
    rm -f "$inventory_file"
    return 1
  fi
  if ! docker volume ls -q \
    --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
    > "$inventory_file" || [ -s "$inventory_file" ]; then
    rm -f "$inventory_file"
    return 1
  fi
  rm -f "$inventory_file"
}

if [ "$preflight_mode" != install ] && ! validate_existing_project_inventory; then
  offline_fail preflight \
    "existing project resources failed the exact offline ownership inventory" 69
fi

port_is_owned_by_project_edge_service() {
  host_port=$1
  container_port=$2
  allowed_services=$3
  published_ids=$(docker ps -q --filter "publish=$host_port")
  [ "$(printf '%s\n' "$published_ids" | sed '/^$/d' | wc -l)" -eq 1 ] || return 1
  edge_id=$published_ids
  project_label=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}' "$edge_id") || return 1
  service_label=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.service" }}' "$edge_id") || return 1
  owner_label=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' "$edge_id") || return 1
  stack_label=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.stack" }}' "$edge_id") || return 1
  [ "$project_label" = "$COMPOSE_PROJECT_NAME" ] && \
    [ "$owner_label" = "$project_owner_label" ] && \
    [ "$stack_label" = offline ] || return 1
  case " $allowed_services " in
    *" $service_label "*) ;;
    *) return 1 ;;
  esac
  published_binding=$(docker port "$edge_id" "$container_port/tcp") || return 1
  [ "$published_binding" = "$KB_BIND_ADDRESS:$host_port" ] || return 1
}

port_listener_evidence=$(mktemp "$OFFLINE_TMPDIR/port-listeners.XXXXXXXXXX")
for port_mapping in \
  "$KB_HTTPS_PORT:8443:proxy maintenance-page" \
  "$KB_OBJECTS_HTTPS_PORT:9443:proxy maintenance-page"; do
  host_port=${port_mapping%%:*}
  mapping_tail=${port_mapping#*:}
  container_port=${mapping_tail%%:*}
  allowed_services=${mapping_tail#*:}
  : > "$port_listener_evidence"
  if ! ss -H -ltn "sport = :$host_port" > "$port_listener_evidence"; then
    offline_fail preflight "cannot inspect TCP port $host_port" 69
  fi
  if [ -s "$port_listener_evidence" ]; then
    if ! port_is_owned_by_project_edge_service \
      "$host_port" "$container_port" "$allowed_services"; then
      echo "preflight: TCP port $host_port is occupied by an unverified process" >&2
      exit 69
    fi
  fi
done

command -v python3 >/dev/null 2>&1 || {
  echo "preflight: python3 is required for network overlap validation" >&2
  exit 69
}
python3 -I "$contract_dir/release/deploy/tencent/verify-offline-network-cidrs.py" \
  "$COMPOSE_PROJECT_NAME" \
  172.30.240.0/24 \
  172.30.241.0/24 \
  172.30.242.0/24 \
  172.30.243.0/24 \
  172.30.244.0/24

install -d -o 999 -g 999 -m 0700 "$KB_DATA_ROOT/postgres"
install -d -m 0700 \
  "$KB_DATA_ROOT/redis" \
  "$KB_DATA_ROOT/minio" \
  "$KB_DATA_ROOT/caddy-data" \
  "$KB_DATA_ROOT/caddy-config"
install -d -o root -g root -m 0700 "$KB_DATA_ROOT/maintenance"
# API and maintenance run as the unprivileged UID 10001.  They only need to
# traverse this read-only bind mount so they can call statvfs for upload
# capacity enforcement; write access remains root-only.
install -d -o root -g root -m 0755 "$KB_DATA_ROOT/capacity-probe"
install -d -m 0755 "$KB_DATA_ROOT/clamav-db"

disk_usage_evidence=$(mktemp "$OFFLINE_TMPDIR/disk-usage.XXXXXXXXXX")
if ! df -Pk "$KB_DATA_ROOT" > "$disk_usage_evidence"; then
  offline_fail preflight "cannot inspect available storage capacity" 69
fi
capacity_fields=$(awk \
  'NR == 2 { total=$2; available=$4 } END { if (NR != 2) exit 1; print total, available }' \
  "$disk_usage_evidence") || \
  offline_fail preflight "storage capacity evidence is malformed" 69
# awk emits exactly two numeric fields; cardinality and type are checked next.
# shellcheck disable=SC2086
set -- $capacity_fields
if [ "$#" -ne 2 ]; then
  offline_fail preflight "storage capacity fields are incomplete" 69
fi
total_kib=$1
available_kib=$2
for capacity_value in "$total_kib" "$available_kib"; do
  case "$capacity_value" in
    ""|*[!0-9]*) offline_fail preflight "available storage capacity is invalid" 69 ;;
  esac
done
# Cloud providers advertise the target disk in decimal GB.  Enforce the
# enterprise 300 GB floor on the actual filesystem that holds KB_DATA_ROOT;
# a smaller partition on an otherwise large host must not pass.
minimum_total_kib=292968750
if [ "$total_kib" -lt "$minimum_total_kib" ]; then
  offline_fail preflight \
    "the KB_DATA_ROOT filesystem must provide at least 300 GB total capacity" 69
fi
if [ "$preflight_mode" != upgrade ]; then
  required_available_kib=234375000
  capacity_requirement="at least 240 GB free space is required for initial installation"
else
  required_available_kib=$((total_kib / 5))
  if [ "$required_available_kib" -lt 41943040 ]; then
    required_available_kib=41943040
  fi
  capacity_requirement="upgrade requires at least 20 percent free space and never less than 40 GiB"
fi
if [ "$available_kib" -lt "$required_available_kib" ]; then
  echo "preflight: $capacity_requirement" >&2
  exit 69
fi

if ! [ -f "$image_manifest" ]; then
  echo "preflight: compose image manifest is missing next to the environment file" >&2
  exit 66
fi

registry_receipt_directory=/srv/heyi-knowledgebases-offline/state
offline_validate_root_directory preflight "$registry_receipt_directory" 700
release_digest=$(sha256sum "$release_env_file" | awk '{print $1}') || exit 66
manifest_digest=$(sha256sum "$image_manifest" | awk '{print $1}') || exit 66
if [ "$preflight_mode" = upgrade ]; then
  if [ -e "$registry_receipt_directory/install-in-progress.json" ] || \
    [ -L "$registry_receipt_directory/install-in-progress.json" ]; then
    offline_fail preflight "upgrade is blocked by an incomplete installation state" 69
  fi
  set -- "$registry_receipt_directory"/installed-*.json
  if [ "$1" = "$registry_receipt_directory/installed-*.json" ] || [ "$#" -ne 1 ]; then
    offline_fail preflight "upgrade requires exactly one completed-install receipt" 69
  fi
  completed_install_receipt=$1
  if [ -L "$completed_install_receipt" ] || [ ! -f "$completed_install_receipt" ] || \
    [ "$(stat -c %u -- "$completed_install_receipt")" -ne 0 ] || \
    [ "$(stat -c %a -- "$completed_install_receipt")" != 400 ] || \
    [ "$(stat -c %h -- "$completed_install_receipt")" -ne 1 ] || \
    [ "$(realpath -e -- "$completed_install_receipt")" != \
      "$completed_install_receipt" ] || \
    ! python3 -I "$snapshot_script_dir/offline-recovery-state.py" \
      validate-installed-receipt "$completed_install_receipt" \
      20260715_0021 >/dev/null; then
    offline_fail preflight "completed-install receipt is unsafe or malformed" 65
  fi
  if [ -z "${KB_UPGRADE_BACKUP_EVIDENCE_PATH:-}" ] || \
    [ -z "${KB_UPGRADE_BACKUP_SIGNATURE_PATH:-}" ] || \
    [ -z "${KB_UPGRADE_BACKUP_PUBLIC_KEY_PATH:-}" ]; then
    offline_fail preflight "upgrade requires signed backup and restore-drill evidence" 65
  fi
  if [ ! -x /usr/bin/openssl ]; then
    offline_fail preflight "the reviewed /usr/bin/openssl verifier is required" 69
  fi
fi
contract_release_checksums=$(mktemp "$OFFLINE_TMPDIR/contract-release-assets.XXXXXXXXXX")
if ! sed -n '/  release\//p' "$contract_dir/files.sha256" | LC_ALL=C sort \
  > "$contract_release_checksums"; then
  rm -f "$contract_release_checksums"
  offline_fail preflight "cannot normalize contract release assets" 66
fi
release_assets_digest=$(sha256sum "$contract_release_checksums" | awk '{print $1}') || {
  rm -f "$contract_release_checksums"
  exit 66
}
rm -f "$contract_release_checksums"
trusted_release_public_key=/etc/heyi-release/trusted-release-public.pem
trusted_release_public_key_mode=$(stat -c %a -- \
  "$trusted_release_public_key" 2>/dev/null || echo 0)
trusted_release_public_key_size=$(stat -c %s -- \
  "$trusted_release_public_key" 2>/dev/null || echo 0)
if [ -L "$trusted_release_public_key" ] || \
  [ ! -f "$trusted_release_public_key" ] || \
  [ "$(realpath -e -- "$trusted_release_public_key" 2>/dev/null || true)" != \
    "$trusted_release_public_key" ] || \
  [ "$(stat -c %u -- "$trusted_release_public_key" 2>/dev/null || echo -1)" -ne 0 ] || \
  [ "$(stat -c %h -- "$trusted_release_public_key" 2>/dev/null || echo 0)" -ne 1 ]; then
  offline_fail preflight "trusted release public key is missing or unsafe" 65
fi
case "$trusted_release_public_key_mode" in
  400|444) ;;
  *) offline_fail preflight "trusted release public key permissions are unsafe" 65 ;;
esac
case "$trusted_release_public_key_size" in
  ""|*[!0-9]*|0) offline_fail preflight "trusted release public key size is invalid" 65 ;;
esac
if [ "$trusted_release_public_key_size" -gt 65536 ]; then
  offline_fail preflight "trusted release public key is oversized" 65
fi
trusted_release_ancestor=$(dirname -- "$trusted_release_public_key")
while :; do
  if [ -L "$trusted_release_ancestor" ] || \
    [ ! -d "$trusted_release_ancestor" ] || \
    [ "$(stat -c %u -- "$trusted_release_ancestor")" -ne 0 ]; then
    offline_fail preflight "trusted release public key ancestor is unsafe" 65
  fi
  trusted_release_ancestor_mode=$(stat -c %a -- "$trusted_release_ancestor") || exit 66
  trusted_release_ancestor_mode_value=$((0$trusted_release_ancestor_mode))
  if [ $((trusted_release_ancestor_mode_value & 022)) -ne 0 ]; then
    offline_fail preflight \
      "trusted release public key ancestor is writable by non-root" 65
  fi
  [ "$trusted_release_ancestor" = / ] && break
  trusted_release_ancestor=$(dirname -- "$trusted_release_ancestor")
done
trusted_release_key_digest=$(sha256sum \
  "$trusted_release_public_key" | awk '{print $1}') || exit 66
if ! printf '%s\n' "$trusted_release_key_digest" | grep -Eq '^[0-9a-f]{64}$'; then
  offline_fail preflight "trusted release public key digest is invalid" 65
fi
registry_receipt=$registry_receipt_directory/registry-import-$manifest_digest.json
if [ -L "$registry_receipt" ] || [ ! -f "$registry_receipt" ] || \
  [ "$(realpath -e -- "$registry_receipt" 2>/dev/null || true)" != "$registry_receipt" ] || \
  [ "$(stat -c %u -- "$registry_receipt" 2>/dev/null || echo -1)" -ne 0 ] || \
  [ "$(stat -c %a -- "$registry_receipt" 2>/dev/null || echo 0)" != 400 ] || \
  [ "$(stat -c %h -- "$registry_receipt" 2>/dev/null || echo 0)" -ne 1 ] || \
  [ "$(stat -c %s -- "$registry_receipt" 2>/dev/null || echo 0)" -le 0 ] || \
  [ "$(stat -c %s -- "$registry_receipt" 2>/dev/null || echo 65537)" -gt 65536 ]; then
  offline_fail preflight "signed registry import receipt is missing or unsafe" 65
fi
if ! python3 -I -c '
import json, pathlib, re, sys

def reject_duplicates(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result

def reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")

document = json.loads(
    pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"),
    object_pairs_hook=reject_duplicates,
    parse_constant=reject_constant,
)
expected_keys = {
    "schema_version", "kind", "status", "release_sequence", "release_id",
    "release_git_sha", "release_schema_head", "release_sha256", "manifest_sha256",
    "release_assets_sha256", "checksum_set_sha256", "signature_sha256", "trusted_key_sha256",
}
digest = re.compile(r"[0-9a-f]{64}")
valid = (
    set(document) == expected_keys
    and document["schema_version"] == 2
    and document["kind"] == "offline-registry-import"
    and document["status"] == "verified"
    and document["release_sha256"] == sys.argv[2]
    and document["manifest_sha256"] == sys.argv[3]
    and document["release_assets_sha256"] == sys.argv[4]
    and document["trusted_key_sha256"] == sys.argv[5]
    and type(document["release_sequence"]) is int
    and 0 < document["release_sequence"] <= 999_999_999_999_999_999
    and isinstance(document["release_id"], str)
    and re.fullmatch(r"[A-Za-z0-9._-]+", document["release_id"])
    and isinstance(document["release_git_sha"], str)
    and re.fullmatch(r"[0-9a-f]{40}", document["release_git_sha"])
    and document["release_schema_head"] == "20260715_0021"
    and all(
        isinstance(document[key], str) and digest.fullmatch(document[key])
        for key in (
            "release_assets_sha256", "checksum_set_sha256", "signature_sha256", "trusted_key_sha256"
        )
    )
)
raise SystemExit(0 if valid else 1)
' "$registry_receipt" "$release_digest" "$manifest_digest" \
  "$release_assets_digest" "$trusted_release_key_digest"; then
  offline_fail preflight "signed registry import receipt does not match this release" 65
fi

highest_release_file=$registry_receipt_directory/highest-release.json
if [ -L "$highest_release_file" ] || [ ! -f "$highest_release_file" ] || \
  [ "$(realpath -e -- "$highest_release_file" 2>/dev/null || true)" != "$highest_release_file" ] || \
  [ "$(stat -c %u -- "$highest_release_file" 2>/dev/null || echo -1)" -ne 0 ] || \
  [ "$(stat -c %a -- "$highest_release_file" 2>/dev/null || echo 0)" != 400 ] || \
  [ "$(stat -c %h -- "$highest_release_file" 2>/dev/null || echo 0)" -ne 1 ] || \
  [ "$(stat -c %s -- "$highest_release_file" 2>/dev/null || echo 0)" -le 0 ] || \
  [ "$(stat -c %s -- "$highest_release_file" 2>/dev/null || echo 65537)" -gt 65536 ]; then
  offline_fail preflight "highest accepted release state is missing or unsafe" 65
fi
if ! python3 -I -c '
import json, pathlib, re, sys

def reject_duplicates(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result

def reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")

def read(path):
    return json.loads(
        pathlib.Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant,
    )

receipt = read(sys.argv[1])
highest = read(sys.argv[2])
trusted_key_sha256 = sys.argv[3]
receipt_expected = {
    "schema_version", "kind", "status", "release_sequence", "release_id",
    "release_git_sha", "release_schema_head", "release_sha256", "manifest_sha256",
    "release_assets_sha256", "checksum_set_sha256", "signature_sha256",
    "trusted_key_sha256",
}
highest_expected = {
    "schema_version", "release_sequence", "release_id", "release_git_sha",
    "release_schema_head", "manifest_sha256", "release_assets_sha256",
    "trusted_key_sha256",
}
shared = (
    "release_sequence", "release_id", "release_git_sha", "release_schema_head",
    "manifest_sha256", "release_assets_sha256", "trusted_key_sha256",
)
valid = (
    isinstance(receipt, dict)
    and set(receipt) == receipt_expected
    and receipt.get("schema_version") == 2
    and receipt.get("kind") == "offline-registry-import"
    and receipt.get("status") == "verified"
    and isinstance(highest, dict)
    and set(highest) == highest_expected
    and highest.get("schema_version") == 2
    and type(highest.get("release_sequence")) is int
    and 0 < highest["release_sequence"] <= 999_999_999_999_999_999
    and re.fullmatch(r"[0-9a-f]{64}", trusted_key_sha256) is not None
    and receipt.get("trusted_key_sha256") == trusted_key_sha256
    and highest.get("trusted_key_sha256") == trusted_key_sha256
    and all(receipt.get(key) == highest.get(key) for key in shared)
)
raise SystemExit(0 if valid else 1)
' "$registry_receipt" "$highest_release_file" "$trusted_release_key_digest"; then
  offline_fail preflight "release receipt is not the highest issuer-accepted release" 65
fi
trusted_release_key_digest_after=$(sha256sum \
  "$trusted_release_public_key" | awk '{print $1}') || exit 66
if [ "$trusted_release_key_digest_after" != "$trusted_release_key_digest" ]; then
  offline_fail preflight "trusted release public key changed during validation" 65
fi
if [ "$preflight_mode" = upgrade ]; then
  python3 -I "$snapshot_script_dir/verify-upgrade-backup.py" \
    --evidence "$KB_UPGRADE_BACKUP_EVIDENCE_PATH" \
    --signature "$KB_UPGRADE_BACKUP_SIGNATURE_PATH" \
    --public-key "$KB_UPGRADE_BACKUP_PUBLIC_KEY_PATH" \
    --expected-manifest-sha256 "$manifest_digest" \
    --expected-operation-scope active_upgrade || \
    offline_fail preflight "signed backup and restore-drill gate failed" 65
fi

sh "$snapshot_script_dir/verify-offline-images.sh" verify \
  --contract-dir "$contract_dir" --contract-sha256 "$contract_sha256"

offline_compose preflight "$contract_dir" \
  --profile ops \
  --profile maintenance \
  config --quiet

selected_egress_profile=$(offline_compose_profile preflight "$contract_dir")
if [ "$selected_egress_profile" = controlled-egress ]; then
  egress_config=$(offline_compose preflight "$contract_dir" \
    --profile controlled-egress config --format json) || \
    offline_fail preflight "controlled egress Compose contract cannot be rendered" 65
  egress_image=$(printf '%s\n' "$egress_config" | python3 -I -c \
    'import json,sys; print(json.load(sys.stdin)["services"]["llm-egress"]["image"])') || \
    offline_fail preflight "controlled egress image identity is missing" 65
  unset egress_config
  case "$egress_image" in
    127.0.0.1:5000/*@sha256:*) ;;
    *) offline_fail preflight "controlled egress image is not an exact loopback digest" 65 ;;
  esac
  if ! docker run --rm --pull never --network none --read-only \
    --label "com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
    --label "com.docker.compose.service=llm-egress-preflight" \
    --label "com.docker.compose.oneoff=True" \
    --label "com.docker.compose.project.config_files=$compose_file" \
    --label "io.heyi.knowledgebases.owner=$project_owner_label" \
    --label "io.heyi.knowledgebases.stack=offline" \
    --label "io.heyi.knowledgebases.contract-sha256=$contract_sha256" \
    --label "io.heyi.knowledgebases.adoption-transaction=$preflight_adoption_transaction" \
    --user 10001:10001 --cap-drop ALL --cap-add NET_BIND_SERVICE \
    --security-opt no-new-privileges:true \
    --tmpfs /tmp:size=16m,uid=10001,gid=10001,mode=0700 \
    --env XDG_CONFIG_HOME=/tmp/config --env XDG_DATA_HOME=/tmp/data \
    --volume "$snapshot_script_dir/Caddyfile.llm-egress:/etc/caddy/Caddyfile:ro" \
    --entrypoint caddy "$egress_image" \
    validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null; then
    offline_fail preflight "controlled egress Caddy contract is invalid" 65
  fi
  egress_applets=$(docker run --rm --pull never --network none --read-only \
    --label "com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
    --label "com.docker.compose.service=llm-egress-preflight" \
    --label "com.docker.compose.oneoff=True" \
    --label "com.docker.compose.project.config_files=$compose_file" \
    --label "io.heyi.knowledgebases.owner=$project_owner_label" \
    --label "io.heyi.knowledgebases.stack=offline" \
    --label "io.heyi.knowledgebases.contract-sha256=$contract_sha256" \
    --label "io.heyi.knowledgebases.adoption-transaction=$preflight_adoption_transaction" \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --volume "$snapshot_script_dir/Caddyfile.llm-egress:/etc/caddy/Caddyfile:ro" \
    --entrypoint /bin/busybox "$egress_image" --list) || \
    offline_fail preflight "controlled egress BusyBox inventory is unavailable" 65
  for required_applet in sh wget sha256sum; do
    if ! printf '%s\n' "$egress_applets" | grep -Fxq "$required_applet"; then
      unset egress_applets
      offline_fail preflight "controlled egress image lacks a required health applet" 65
    fi
  done
  unset egress_applets
fi

offline_compose preflight "$contract_dir" \
  --profile ops \
  run --pull never --rm --no-deps \
  --label "io.heyi.knowledgebases.contract-sha256=$contract_sha256" \
  --label "io.heyi.knowledgebases.adoption-transaction=$preflight_adoption_transaction" \
  --label "com.docker.compose.project.config_files=$compose_file" \
  api-preflight \
  python -c 'import shutil; probe = "/var/lib/kb-capacity"; usage = shutil.disk_usage(probe); assert usage.total > 0 and usage.free >= 0'

offline_compose preflight "$contract_dir" \
  --profile ops \
  run --pull never --rm --no-deps \
  --label "io.heyi.knowledgebases.contract-sha256=$contract_sha256" \
  --label "io.heyi.knowledgebases.adoption-transaction=$preflight_adoption_transaction" \
  --label "com.docker.compose.project.config_files=$compose_file" \
  api-preflight \
  python -m app.document_parser_preflight --require-all

offline_compose preflight "$contract_dir" \
  --profile ops \
  run --pull never --rm --no-deps \
  --label "io.heyi.knowledgebases.contract-sha256=$contract_sha256" \
  --label "io.heyi.knowledgebases.adoption-transaction=$preflight_adoption_transaction" \
  --label "com.docker.compose.project.config_files=$compose_file" \
  clamav-db-preflight

echo "preflight: offline deployment requirements satisfied; contract_sha256=$contract_sha256"
