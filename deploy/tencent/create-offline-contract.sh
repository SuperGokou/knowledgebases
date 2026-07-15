#!/usr/bin/env sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 /absolute/path/to/runtime.env /absolute/path/to/release.env" >&2
  exit 64
fi

runtime_env_file=$1
release_env_file=$2
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"

offline_acquire_lock contract
sh "$script_dir/prepare-offline-contract.sh" "$runtime_env_file" "$release_env_file"
