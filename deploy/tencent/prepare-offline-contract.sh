#!/usr/bin/env sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 /absolute/path/to/runtime.env /absolute/path/to/release.env" >&2
  exit 64
fi

runtime_source=$1
release_source=$2
manifest_source=$release_source.images
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"

offline_require_root contract
if ! offline_lock_is_inherited; then
  offline_fail contract "the deployment lock must cover snapshot creation and use" 75
fi
offline_prepare_runtime_root contract
offline_clear_inherited_environment

contract_dir=$(mktemp -d "$OFFLINE_CONTRACT_ROOT/contract.XXXXXXXXXX")
chmod 0700 "$contract_dir"
cleanup_contract() {
  rm -rf -- "$contract_dir"
}
trap cleanup_contract EXIT
trap 'exit 130' HUP INT TERM

validate_source_path() {
  label=$1
  source_path=$2
  accepted_modes=$3
  maximum_bytes=$4

  case "$source_path" in
    /*) ;;
    *) offline_fail contract "$label path must be absolute" 65 ;;
  esac
  canonical_source=$(realpath -e -- "$source_path" 2>/dev/null || true)
  if [ "$canonical_source" != "$source_path" ]; then
    offline_fail contract "$label path must be canonical and contain no symbolic links" 65
  fi
  if [ -L "$source_path" ] || [ ! -f "$source_path" ]; then
    offline_fail contract "$label must be a regular non-symbolic file" 65
  fi

  checked_path=$source_path
  first_component=1
  while :; do
    if [ -L "$checked_path" ]; then
      offline_fail contract "$label path contains a symbolic link" 65
    fi
    owner=$(stat -c %u -- "$checked_path") || \
      offline_fail contract "cannot inspect $label path ownership" 66
    mode=$(stat -c %a -- "$checked_path") || \
      offline_fail contract "cannot inspect $label path permissions" 66
    if [ "$owner" -ne 0 ]; then
      offline_fail contract "$label and every ancestor must be owned by root" 65
    fi
    if [ "$first_component" -eq 1 ]; then
      case " $accepted_modes " in
        *" $mode "*) ;;
        *) offline_fail contract "$label has unsafe permissions" 65 ;;
      esac
      first_component=0
    else
      mode_value=$((0$mode))
      if [ $((mode_value & 022)) -ne 0 ]; then
        offline_fail contract "$label ancestor is group or world writable" 65
      fi
    fi
    [ "$checked_path" = / ] && break
    checked_path=$(dirname -- "$checked_path")
  done

  byte_count=$(stat -c %s -- "$source_path") || exit 66
  if [ "$byte_count" -le 0 ] || [ "$byte_count" -gt "$maximum_bytes" ]; then
    offline_fail contract "$label size is outside the accepted boundary" 65
  fi
  if ! python3 -I -c \
    'import pathlib,sys; data=pathlib.Path(sys.argv[1]).read_bytes(); raise SystemExit(1 if b"\0" in data or any(len(line)>4096 for line in data.splitlines()) else 0)' \
    "$source_path"; then
    offline_fail contract "$label contains NUL data or an overlong line" 65
  fi
}

copy_stable_file() {
  label=$1
  source_path=$2
  destination=$3
  accepted_modes=$4
  maximum_bytes=$5
  validate_source_path "$label" "$source_path" "$accepted_modes" "$maximum_bytes"
  before_digest=$(sha256sum "$source_path" | awk '{print $1}') || exit 66
  install -D -o root -g root -m 0400 "$source_path" "$destination"
  after_digest=$(sha256sum "$source_path" | awk '{print $1}') || exit 66
  snapshot_digest=$(sha256sum "$destination" | awk '{print $1}') || exit 66
  if [ "$before_digest" != "$after_digest" ] || \
    [ "$before_digest" != "$snapshot_digest" ]; then
    offline_fail contract "$label changed while the canonical snapshot was created" 65
  fi
}

copy_release_asset() {
  relative_path=$1
  source_path=$script_dir/../..//$relative_path
  canonical_source=$(realpath -e -- "$source_path" 2>/dev/null || true)
  destination=$contract_dir/release/$relative_path
  copy_stable_file "$relative_path" "$canonical_source" "$destination" "400 444 500 544 555 600 644 700 744 755" 1048576
}

copy_stable_file runtime.env "$runtime_source" "$contract_dir/runtime.env" "400 600" 65536
copy_stable_file release.env "$release_source" "$contract_dir/release.env" "400 444" 16384
copy_stable_file release.env.images "$manifest_source" \
  "$contract_dir/release.env.images" "400 444" 65536

for release_asset in \
  deploy/tencent/compose.offline.yml \
  deploy/tencent/Caddyfile.offline \
  deploy/tencent/Caddyfile.maintenance \
  deploy/tencent/Caddyfile.llm-egress \
  deploy/tencent/offline-recovery-state.py \
  deploy/tencent/offline-recovery-dispatcher.sh \
  deploy/tencent/reconcile-offline.sh \
  deploy/tencent/heyi-kb-offline-reconcile.service \
  deploy/tencent/heyi-kb-offline-reconcile.timer \
  deploy/tencent/offline-operation-common.sh \
  deploy/tencent/prepare-offline-contract.sh \
  deploy/tencent/preflight-offline.sh \
  deploy/tencent/preflight-maintenance-offline.sh \
  deploy/tencent/verify-offline-images.sh \
  deploy/tencent/enter-maintenance-offline.sh \
  deploy/tencent/install-offline.sh \
  deploy/tencent/offline-pre-migration-abort.py \
  deploy/tencent/deploy-offline.sh \
  deploy/tencent/adopt-offline.sh \
  deploy/tencent/create-offline-contract.sh \
  deploy/tencent/remove-offline-contract.sh \
  deploy/tencent/rollback-offline.sh \
  deploy/tencent/import-offline-registry-bundle.sh \
  deploy/tencent/verify-maintenance-endpoint.py \
  deploy/tencent/verify-upgrade-backup.py \
  deploy/tencent/run-migration-with-lock.py \
  deploy/tencent/verify-offline-network-cidrs.py \
  deploy/tencent/verify-offline-project-inventory.py \
  deploy/tencent/validate-offline-environment.py \
  docker/postgres/init-runtime-role.sh \
  docker/minio/init.sh \
  docker/minio/cleanup-multipart.sh \
  docker/clamav/clamd.conf \
  docker/clamav/preflight-database.sh \
  scripts/legacy_offline_adoption.py \
  scripts/host_isolation_guard.py; do
  copy_release_asset "$release_asset"
done

metadata=$contract_dir/files.sha256
: > "$metadata"
offline_contract_files | while IFS= read -r relative_path; do
  [ -n "$relative_path" ] || continue
  digest=$(sha256sum "$contract_dir/$relative_path" | awk '{print $1}') || exit 66
  printf '%s  %s\n' "$digest" "$relative_path" >> "$metadata"
done
chmod 0400 "$metadata"
contract_digest=$(sha256sum "$metadata" | awk '{print $1}') || exit 66
printf '%s\n' "$contract_digest" > "$contract_dir/contract.sha256"
chmod 0400 "$contract_dir/contract.sha256"

verified_digest=$(offline_verify_contract contract "$contract_dir")
if [ "$verified_digest" != "$contract_digest" ]; then
  offline_fail contract "snapshot verification returned a different contract digest" 65
fi

trap - EXIT HUP INT TERM
printf '%s %s\n' "$contract_dir" "$contract_digest"
