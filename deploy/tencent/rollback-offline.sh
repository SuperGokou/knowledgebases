#!/usr/bin/env sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 /path/to/runtime.env /path/to/current-release.env" >&2
  exit 64
fi

runtime_env_file=$1
release_env_file=$2
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

# A schema migration changes more than the readiness constant. Old 0013 code
# lacks the 0014-0018 concurrency and replay contracts, so a schema-only shim
# could silently accept writes that current code must reject. This command is
# intentionally a fail-closed maintenance transition, not a business rollback.
sh "$script_dir/enter-maintenance-offline.sh" \
  "$runtime_env_file" "$release_env_file"

cat <<'EOF'
rollback: business traffic remains blocked by the independent maintenance endpoint
rollback: old API/Web images were not started and the database was not changed
rollback: build, validate and deploy a complete forward-fix before restoring proxy
EOF
