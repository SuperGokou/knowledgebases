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
contract_paths=
expected_inventory=
actual_inventory=
cleanup_contract() {
  [ -z "$contract_paths" ] || rm -f -- "$contract_paths"
  [ -z "$expected_inventory" ] || rm -f -- "$expected_inventory"
  [ -z "$actual_inventory" ] || rm -f -- "$actual_inventory"
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
  contract_path=$1
  source_relative=${contract_path#release/}
  source_path=$repository_root/$source_relative
  destination=$contract_dir/$contract_path
  copy_stable_file "$contract_path" "$source_path" "$destination" \
    "400 444 500 544 555 600 644 700 744 755" 1048576
}

repository_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd -P)
contract_paths=$(mktemp "$OFFLINE_TMPDIR/contract-source-paths.XXXXXXXXXX") || \
  offline_fail contract "cannot create the canonical contract inventory" 66
chmod 0600 "$contract_paths"
offline_contract_files > "$contract_paths" || \
  offline_fail contract "cannot enumerate the canonical contract" 66

entry_count=$(wc -l < "$contract_paths" | tr -d '[:space:]')
unique_count=$(LC_ALL=C sort -u "$contract_paths" | wc -l | tr -d '[:space:]')
if [ -z "$entry_count" ] || [ "$entry_count" -ne "$unique_count" ]; then
  offline_fail contract "canonical contract contains an empty or duplicate inventory" 65
fi

copy_stable_file runtime.env "$runtime_source" "$contract_dir/runtime.env" "400 600" 65536
copy_stable_file release.env "$release_source" "$contract_dir/release.env" "400 444" 16384
copy_stable_file release.env.images "$manifest_source" \
  "$contract_dir/release.env.images" "400 444" 65536

runtime_entries=0
release_entries=0
manifest_entries=0
release_asset_entries=0
while IFS= read -r relative_path; do
  if ! printf '%s\n' "$relative_path" | \
    grep -Eq '^[A-Za-z0-9][A-Za-z0-9._/-]*$'; then
    offline_fail contract "canonical contract contains an unsafe path" 65
  fi
  case "/$relative_path/" in
    *//*|*/../*|*/./*)
      offline_fail contract "canonical contract contains a non-canonical path" 65
      ;;
  esac
  case "$relative_path" in
    runtime.env)
      runtime_entries=$((runtime_entries + 1))
      ;;
    release.env)
      release_entries=$((release_entries + 1))
      ;;
    release.env.images)
      manifest_entries=$((manifest_entries + 1))
      ;;
    release/*)
      source_relative=${relative_path#release/}
      [ -n "$source_relative" ] || \
        offline_fail contract "canonical release asset path is empty" 65
      copy_release_asset "$relative_path"
      release_asset_entries=$((release_asset_entries + 1))
      ;;
    *)
      offline_fail contract "canonical contract contains an unsupported path" 65
      ;;
  esac
done < "$contract_paths"

if [ "$runtime_entries" -ne 1 ] || [ "$release_entries" -ne 1 ] || \
  [ "$manifest_entries" -ne 1 ] || [ "$release_asset_entries" -le 0 ] || \
  [ "$entry_count" -ne $((release_asset_entries + 3)) ]; then
  offline_fail contract "canonical contract has an invalid environment or release boundary" 65
fi

unsafe_object=$(find "$contract_dir" -mindepth 1 \
  ! -type d ! -type f -print -quit) || \
  offline_fail contract "cannot inspect the contract snapshot object types" 66
if [ -n "$unsafe_object" ]; then
  offline_fail contract "contract snapshot contains an unsafe filesystem object" 65
fi
expected_inventory=$(mktemp "$OFFLINE_TMPDIR/contract-expected.XXXXXXXXXX") || \
  offline_fail contract "cannot create the expected contract inventory" 66
actual_inventory=$(mktemp "$OFFLINE_TMPDIR/contract-actual.XXXXXXXXXX") || \
  offline_fail contract "cannot create the actual contract inventory" 66
chmod 0600 "$expected_inventory" "$actual_inventory"
LC_ALL=C sort "$contract_paths" > "$expected_inventory" || \
  offline_fail contract "cannot sort the expected contract inventory" 66
find "$contract_dir" -type f -printf '%P\n' | LC_ALL=C sort > "$actual_inventory" || \
  offline_fail contract "cannot enumerate the contract snapshot" 66
if ! cmp -s "$expected_inventory" "$actual_inventory"; then
  offline_fail contract "contract snapshot inventory differs from the canonical contract" 65
fi
rm -f -- "$expected_inventory" "$actual_inventory"
expected_inventory=
actual_inventory=

metadata=$contract_dir/files.sha256
: > "$metadata"
while IFS= read -r relative_path; do
  digest=$(sha256sum "$contract_dir/$relative_path" | awk '{print $1}') || exit 66
  printf '%s  %s\n' "$digest" "$relative_path" >> "$metadata"
done < "$contract_paths"
rm -f -- "$contract_paths"
contract_paths=
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
