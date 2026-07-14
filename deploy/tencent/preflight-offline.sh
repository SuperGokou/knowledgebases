#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 /absolute/path/to/offline.env" >&2
  exit 64
fi

env_file=$1
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compose_file=$script_dir/compose.offline.yml
lock_directory=/run/lock
lock_file=$lock_directory/heyi-kb-offline.preflight.lock
lock_token=heyi-kb-offline-preflight-v1

if [ -L "$env_file" ]; then
  echo "preflight: environment file must not be a symbolic link" >&2
  exit 65
fi
if [ ! -f "$env_file" ]; then
  echo "preflight: environment file not found" >&2
  exit 66
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "preflight: run as root so data-directory ownership can be verified" >&2
  exit 77
fi

env_owner=$(stat -c %u -- "$env_file") || {
  echo "preflight: cannot inspect environment file owner" >&2
  exit 66
}
if [ "$env_owner" -ne 0 ]; then
  echo "preflight: environment file must be owned by root" >&2
  exit 65
fi

env_mode=$(stat -c %a -- "$env_file") || {
  echo "preflight: cannot inspect environment file permissions" >&2
  exit 66
}
case "$env_mode" in
  400|600) ;;
  *)
    echo "preflight: environment file permissions must be 0600 or 0400" >&2
    exit 65
    ;;
esac

# Serialize every preflight that can create ownership markers or inspect ports. The
# fixed, root-owned lock directory prevents callers from selecting a different lock
# and defeating the deployment-wide exclusion boundary.
if [ "${KB_PREFLIGHT_LOCK_HELD:-}" != "$lock_token" ]; then
  if [ -L "$lock_directory" ] || [ ! -d "$lock_directory" ]; then
    echo "preflight: deployment lock directory is missing or symbolic" >&2
    exit 73
  fi
  lock_directory_owner=$(stat -c %u -- "$lock_directory") || {
    echo "preflight: cannot inspect deployment lock directory owner" >&2
    exit 73
  }
  if [ "$lock_directory_owner" -ne 0 ]; then
    echo "preflight: deployment lock directory must be owned by root" >&2
    exit 73
  fi
  if [ -L "$lock_file" ]; then
    echo "preflight: deployment lock file must not be symbolic" >&2
    exit 73
  fi
  if [ -e "$lock_file" ]; then
    lock_owner=$(stat -c %u -- "$lock_file") || exit 73
    lock_mode=$(stat -c %a -- "$lock_file") || exit 73
    if [ "$lock_owner" -ne 0 ] || [ "$lock_mode" != 600 ]; then
      echo "preflight: deployment lock file has unsafe ownership or permissions" >&2
      exit 73
    fi
  fi
  command -v flock >/dev/null 2>&1 || {
    echo "preflight: flock is required for deployment serialization" >&2
    exit 69
  }
  umask 077
  exec 9>"$lock_file"
  if ! flock -n 9; then
    echo "preflight: another deployment or preflight is already running" >&2
    exit 75
  fi
  lock_owner=$(stat -c %u -- "$lock_file") || exit 73
  lock_mode=$(stat -c %a -- "$lock_file") || exit 73
  if [ "$lock_owner" -ne 0 ] || [ "$lock_mode" != 600 ]; then
    echo "preflight: deployment lock file has unsafe ownership or permissions" >&2
    exit 73
  fi
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
    *'$'*|*'`'*|*'\\'*|*';'*|*'&'*|*'|'*|*'<'*|*'>'*)
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
    KB_DATABASE_IDLE_TRANSACTION_TIMEOUT_MS)
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
    COMPOSE_PROJECT_NAME|KB_DATA_ROOT|KB_BIND_ADDRESS|KB_PUBLIC_HOST|\
    KB_PUBLIC_ORIGIN|KB_API_IMAGE|KB_WEB_IMAGE|POSTGRES_DB|POSTGRES_USER|\
    POSTGRES_APP_USER|MINIO_ROOT_USER|MINIO_APP_USER|MINIO_REGION|\
    MINIO_BUCKET|MINIO_MULTIPART_MAX_AGE|KB_BOOTSTRAP_ADMIN_EMAIL)
      require_safe_token "$key" "$value"
      ;;
    KB_TRUSTED_HOSTS|KB_CORS_ORIGINS) ;;
    *) fail_env "unknown environment key: $key" ;;
  esac

  case "$key" in
    COMPOSE_PROJECT_NAME) COMPOSE_PROJECT_NAME=$value ;;
    KB_DATA_ROOT) KB_DATA_ROOT=$value ;;
    KB_BIND_ADDRESS) KB_BIND_ADDRESS=$value ;;
    KB_PUBLIC_HOST) KB_PUBLIC_HOST=$value ;;
    KB_HTTPS_PORT) KB_HTTPS_PORT=$value ;;
    KB_OBJECTS_HTTPS_PORT) KB_OBJECTS_HTTPS_PORT=$value ;;
    KB_PUBLIC_ORIGIN) KB_PUBLIC_ORIGIN=$value ;;
    KB_API_IMAGE) KB_API_IMAGE=$value ;;
    KB_WEB_IMAGE) KB_WEB_IMAGE=$value ;;
    POSTGRES_DB) POSTGRES_DB=$value ;;
    POSTGRES_USER) POSTGRES_USER=$value ;;
    POSTGRES_PASSWORD) POSTGRES_PASSWORD=$value ;;
    POSTGRES_APP_USER) POSTGRES_APP_USER=$value ;;
    POSTGRES_APP_PASSWORD) POSTGRES_APP_PASSWORD=$value ;;
    REDIS_PASSWORD) REDIS_PASSWORD=$value ;;
    MINIO_ROOT_USER) MINIO_ROOT_USER=$value ;;
    MINIO_ROOT_PASSWORD) MINIO_ROOT_PASSWORD=$value ;;
    MINIO_APP_USER) MINIO_APP_USER=$value ;;
    MINIO_APP_PASSWORD) MINIO_APP_PASSWORD=$value ;;
    MINIO_REGION) MINIO_REGION=$value ;;
    MINIO_BUCKET) MINIO_BUCKET=$value ;;
    MINIO_MULTIPART_MAX_AGE) MINIO_MULTIPART_MAX_AGE=$value ;;
    MINIO_MULTIPART_CLEANUP_INTERVAL_SECONDS) MINIO_MULTIPART_CLEANUP_INTERVAL_SECONDS=$value ;;
    KB_JWT_SECRET) KB_JWT_SECRET=$value ;;
    KB_BFF_SHARED_SECRET) KB_BFF_SHARED_SECRET=$value ;;
    KB_LLM_CREDENTIAL_ENCRYPTION_KEY) KB_LLM_CREDENTIAL_ENCRYPTION_KEY=$value ;;
    KB_BOOTSTRAP_ADMIN_EMAIL) KB_BOOTSTRAP_ADMIN_EMAIL=$value ;;
    KB_BOOTSTRAP_ADMIN_PASSWORD) KB_BOOTSTRAP_ADMIN_PASSWORD=$value ;;
    KB_TRUSTED_HOSTS) KB_TRUSTED_HOSTS=$value ;;
    KB_CORS_ORIGINS) KB_CORS_ORIGINS=$value ;;
    KB_MULTIPART_THRESHOLD_BYTES) KB_MULTIPART_THRESHOLD_BYTES=$value ;;
    CLAMAV_DATABASE_MAX_AGE_SECONDS) CLAMAV_DATABASE_MAX_AGE_SECONDS=$value ;;
    KB_MALWARE_SCAN_TIMEOUT_SECONDS) KB_MALWARE_SCAN_TIMEOUT_SECONDS=$value ;;
    KB_MALWARE_SCAN_CHUNK_SIZE_BYTES) KB_MALWARE_SCAN_CHUNK_SIZE_BYTES=$value ;;
    KB_MALWARE_SCAN_RECLAIM_SECONDS) KB_MALWARE_SCAN_RECLAIM_SECONDS=$value ;;
    KB_DATABASE_POOL_SIZE) KB_DATABASE_POOL_SIZE=$value ;;
    KB_DATABASE_MAX_OVERFLOW) KB_DATABASE_MAX_OVERFLOW=$value ;;
    KB_DATABASE_POOL_TIMEOUT_SECONDS) KB_DATABASE_POOL_TIMEOUT_SECONDS=$value ;;
    KB_DATABASE_STATEMENT_TIMEOUT_MS) KB_DATABASE_STATEMENT_TIMEOUT_MS=$value ;;
    KB_DATABASE_LOCK_TIMEOUT_MS) KB_DATABASE_LOCK_TIMEOUT_MS=$value ;;
    KB_DATABASE_IDLE_TRANSACTION_TIMEOUT_MS) KB_DATABASE_IDLE_TRANSACTION_TIMEOUT_MS=$value ;;
  esac
done < "$env_file"

image_manifest=$env_file.images

: "${COMPOSE_PROJECT_NAME:?required}"
: "${KB_DATA_ROOT:?required}"
: "${KB_PUBLIC_HOST:?required}"
: "${KB_HTTPS_PORT:?required}"
: "${KB_OBJECTS_HTTPS_PORT:?required}"
: "${POSTGRES_USER:?required}"
: "${POSTGRES_APP_USER:?required}"

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
case "$KB_BIND_ADDRESS" in
  0.0.0.0) ;;
  *)
    if ! is_approved_private_host "$KB_BIND_ADDRESS"; then
      echo "preflight: KB_BIND_ADDRESS must be wildcard, private or local" >&2
      exit 65
    fi
    ;;
esac
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

cpu_count=$(getconf _NPROCESSORS_ONLN)
memory_kib=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
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

project_marker_volume=heyi-kb-offline-owner-marker
project_owner_label=jiangsu-heyi-knowledgebases
project_resources=$(
  {
    docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"
    docker network ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"
    docker volume ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"
  } | sed '/^$/d' | sort -u
)

if docker volume inspect "$project_marker_volume" >/dev/null 2>&1; then
  marker_owner=$(docker volume inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.owner" }}' "$project_marker_volume")
  marker_project=$(docker volume inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.compose-project" }}' "$project_marker_volume")
  if [ "$marker_owner" != "$project_owner_label" ] || \
    [ "$marker_project" != "$COMPOSE_PROJECT_NAME" ]; then
    echo "preflight: compose project ownership marker is invalid" >&2
    exit 65
  fi
elif [ -n "$project_resources" ]; then
  echo "preflight: compose project name is already owned by an unverified deployment" >&2
  exit 69
else
  docker volume create \
    --label "io.heyi.knowledgebases.owner=$project_owner_label" \
    --label "io.heyi.knowledgebases.compose-project=$COMPOSE_PROJECT_NAME" \
    "$project_marker_volume" >/dev/null
  marker_owner=$(docker volume inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.owner" }}' "$project_marker_volume")
  marker_project=$(docker volume inspect --format \
    '{{ index .Labels "io.heyi.knowledgebases.compose-project" }}' "$project_marker_volume")
  if [ "$marker_owner" != "$project_owner_label" ] || \
    [ "$marker_project" != "$COMPOSE_PROJECT_NAME" ]; then
    echo "preflight: compose project ownership marker creation was not verifiable" >&2
    exit 73
  fi
fi

port_is_owned_by_project_proxy() {
  host_port=$1
  container_port=$2
  proxy_ids=$(docker ps -q \
    --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=proxy")
  [ -n "$proxy_ids" ] || return 1
  [ "$(printf '%s\n' "$proxy_ids" | sed '/^$/d' | wc -l)" -eq 1 ] || return 1
  proxy_id=$proxy_ids

  published_ids=$(docker ps -q --filter "publish=$host_port")
  [ "$published_ids" = "$proxy_id" ] || return 1
  project_label=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}' "$proxy_id") || return 1
  service_label=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.service" }}' "$proxy_id") || return 1
  [ "$project_label" = "$COMPOSE_PROJECT_NAME" ] || return 1
  [ "$service_label" = proxy ] || return 1
  published_binding=$(docker port "$proxy_id" "$container_port/tcp") || return 1
  [ "$published_binding" = "$KB_BIND_ADDRESS:$host_port" ] || return 1
}

for port_mapping in \
  "$KB_HTTPS_PORT:8443" \
  "$KB_OBJECTS_HTTPS_PORT:9443"; do
  host_port=${port_mapping%%:*}
  container_port=${port_mapping#*:}
  if ss -H -ltn "sport = :$host_port" | grep -q .; then
    if ! port_is_owned_by_project_proxy "$host_port" "$container_port"; then
      echo "preflight: TCP port $host_port is occupied by an unverified process" >&2
      exit 69
    fi
  fi
done

command -v python3 >/dev/null 2>&1 || {
  echo "preflight: python3 is required for network overlap validation" >&2
  exit 69
}
python3 "$script_dir/verify-offline-network-cidrs.py" \
  "$COMPOSE_PROJECT_NAME" \
  172.30.240.0/24 \
  172.30.241.0/24 \
  172.30.242.0/24

install -d -o 999 -g 999 -m 0700 "$KB_DATA_ROOT/postgres"
install -d -m 0700 \
  "$KB_DATA_ROOT/redis" \
  "$KB_DATA_ROOT/minio" \
  "$KB_DATA_ROOT/caddy-data" \
  "$KB_DATA_ROOT/caddy-config"
# API and maintenance run as the unprivileged UID 10001.  They only need to
# traverse this read-only bind mount so they can call statvfs for upload
# capacity enforcement; write access remains root-only.
install -d -o root -g root -m 0755 "$KB_DATA_ROOT/capacity-probe"
install -d -m 0755 "$KB_DATA_ROOT/clamav-db"

available_kib=$(df -Pk "$KB_DATA_ROOT" | awk 'NR == 2 {print $4}')
if [ "$available_kib" -lt 234375000 ]; then
  echo "preflight: at least 240 GB free space is required for this 300 GB profile" >&2
  exit 69
fi

if ! [ -f "$image_manifest" ]; then
  echo "preflight: compose image manifest is missing next to the environment file" >&2
  exit 66
fi

sh "$script_dir/verify-offline-images.sh" verify "$env_file" "$image_manifest"

docker compose \
  --project-name "$COMPOSE_PROJECT_NAME" \
  --env-file "$env_file" \
  --file "$compose_file" \
  config --quiet

docker compose \
  --project-name "$COMPOSE_PROJECT_NAME" \
  --env-file "$env_file" \
  --file "$compose_file" \
  run --pull never --rm --no-deps api \
  python -c 'import shutil; probe = "/var/lib/kb-capacity"; usage = shutil.disk_usage(probe); assert usage.total > 0 and usage.free >= 0'

docker compose \
  --project-name "$COMPOSE_PROJECT_NAME" \
  --env-file "$env_file" \
  --file "$compose_file" \
  run --pull never --rm --no-deps api \
  python -m app.document_parser_preflight --require-all

docker compose \
  --project-name "$COMPOSE_PROJECT_NAME" \
  --env-file "$env_file" \
  --file "$compose_file" \
  --profile ops \
  run --pull never --rm --no-deps clamav-db-preflight

echo "preflight: offline deployment requirements satisfied"
