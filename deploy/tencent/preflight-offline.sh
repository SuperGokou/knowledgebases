#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 /absolute/path/to/offline.env" >&2
  exit 64
fi

env_file=$1
compose_file=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/compose.offline.yml

if [ ! -f "$env_file" ]; then
  echo "preflight: environment file not found" >&2
  exit 66
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "preflight: run as root so data-directory ownership can be verified" >&2
  exit 77
fi

set -a
# The operator-owned environment file is trusted configuration.
# shellcheck disable=SC1090
. "$env_file"
set +a

: "${COMPOSE_PROJECT_NAME:?required}"
: "${KB_DATA_ROOT:?required}"
: "${KB_PUBLIC_HOST:?required}"
: "${KB_HTTPS_PORT:?required}"
: "${KB_OBJECTS_HTTPS_PORT:?required}"
: "${POSTGRES_USER:?required}"
: "${POSTGRES_APP_USER:?required}"

for database_role in "$POSTGRES_USER" "$POSTGRES_APP_USER"; do
  case "$database_role" in
    ""|*[!a-zA-Z0-9_-]*)
      echo "preflight: database role names may contain only letters, numbers, underscore and hyphen" >&2
      exit 65
      ;;
  esac
done

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

for port in "$KB_HTTPS_PORT" "$KB_OBJECTS_HTTPS_PORT"; do
  if ss -H -ltn "sport = :$port" | grep -q .; then
    echo "preflight: TCP port $port is already in use" >&2
    exit 69
  fi
done

if grep -Eiq 'supabase|upstash|myqcloud|api\.deepseek|dashscope|api\.minimax' "$env_file"; then
  echo "preflight: external data or LLM endpoint detected in offline environment" >&2
  exit 65
fi

install -d -m 0750 "$KB_DATA_ROOT"
install -d -m 0700 \
  "$KB_DATA_ROOT/postgres" \
  "$KB_DATA_ROOT/redis" \
  "$KB_DATA_ROOT/minio" \
  "$KB_DATA_ROOT/caddy-data" \
  "$KB_DATA_ROOT/caddy-config"

available_kib=$(df -Pk "$KB_DATA_ROOT" | awk 'NR == 2 {print $4}')
if [ "$available_kib" -lt 200000000 ]; then
  echo "preflight: at least 200 GB free space is required for this 300 GB profile" >&2
  exit 69
fi

docker compose \
  --project-name "$COMPOSE_PROJECT_NAME" \
  --env-file "$env_file" \
  --file "$compose_file" \
  config --quiet

echo "preflight: offline deployment requirements satisfied"
