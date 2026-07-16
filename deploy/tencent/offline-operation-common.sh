#!/usr/bin/env sh

# Shared fail-closed primitives for the offline deployment entry points.
# This file is trusted release code. It never sources operator-controlled env files.

unset LD_PRELOAD LD_LIBRARY_PATH \
  PYTHONHOME PYTHONSTARTUP PYTHONINSPECT PYTHONWARNINGS \
  SSL_CERT_FILE SSL_CERT_DIR OFFLINE_COMPOSE_RELEASE_ROOT_OVERRIDE \
  OFFLINE_SELF_DESCRIBING_CONTRACT_SHA256

OFFLINE_SYSTEM_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PATH=$OFFLINE_SYSTEM_PATH
export PATH
LC_ALL=C
LANG=C
export LC_ALL LANG
umask 077

OFFLINE_PROJECT_NAME=heyi-kb-offline
OFFLINE_RUNTIME_ROOT=/run/heyi-kb-offline
OFFLINE_CONTRACT_ROOT=$OFFLINE_RUNTIME_ROOT/contracts
OFFLINE_TMPDIR=$OFFLINE_RUNTIME_ROOT/tmp
OFFLINE_HOME=$OFFLINE_RUNTIME_ROOT/home
OFFLINE_DOCKER_CONFIG=$OFFLINE_RUNTIME_ROOT/docker-config
OFFLINE_LOCK_DIRECTORY=$OFFLINE_RUNTIME_ROOT
OFFLINE_LOCK_FILE=$OFFLINE_LOCK_DIRECTORY/heyi-kb-offline.preflight.lock
OFFLINE_LOCK_TOKEN=heyi-kb-offline-operation-v2
OFFLINE_PERSISTENT_ROOT=/srv/heyi-knowledgebases-offline
OFFLINE_STATE_DIRECTORY=$OFFLINE_PERSISTENT_ROOT/state
OFFLINE_RECOVERY_DIRECTORY=$OFFLINE_PERSISTENT_ROOT/recovery
OFFLINE_CUTOVER_INTENT=$OFFLINE_STATE_DIRECTORY/cutover-intent.json
OFFLINE_RELEASE_DEPLOY_DIR=${script_dir:?trusted caller must define script_dir before sourcing}
OFFLINE_RELEASE_ROOT=$(realpath -e -- "$OFFLINE_RELEASE_DEPLOY_DIR/../..")

offline_fail() {
  prefix=$1
  message=$2
  code=${3:-65}
  echo "$prefix: $message" >&2
  exit "$code"
}

offline_require_root() {
  prefix=$1
  if [ "$(id -u)" -ne 0 ]; then
    offline_fail "$prefix" "run as root" 77
  fi
}

offline_validate_root_directory() {
  prefix=$1
  directory=$2
  expected_mode=${3:-}
  if [ -L "$directory" ] || [ ! -d "$directory" ]; then
    offline_fail "$prefix" "required directory is missing or symbolic: $directory" 73
  fi
  owner=$(stat -c %u -- "$directory") || \
    offline_fail "$prefix" "cannot inspect directory owner: $directory" 73
  mode=$(stat -c %a -- "$directory") || \
    offline_fail "$prefix" "cannot inspect directory mode: $directory" 73
  if [ "$owner" -ne 0 ]; then
    offline_fail "$prefix" "directory must be owned by root: $directory" 73
  fi
  if [ -n "$expected_mode" ] && [ "$mode" != "$expected_mode" ]; then
    offline_fail "$prefix" "directory has unsafe permissions: $directory" 73
  fi
}

offline_prepare_runtime_root() {
  prefix=$1
  offline_validate_root_directory "$prefix" /run
  if [ -e "$OFFLINE_RUNTIME_ROOT" ] && [ -L "$OFFLINE_RUNTIME_ROOT" ]; then
    offline_fail "$prefix" "runtime root must not be symbolic" 73
  fi
  for protected_directory in \
    "$OFFLINE_RUNTIME_ROOT" "$OFFLINE_CONTRACT_ROOT" "$OFFLINE_TMPDIR" \
    "$OFFLINE_HOME" "$OFFLINE_DOCKER_CONFIG"; do
    if [ -e "$protected_directory" ]; then
      offline_validate_root_directory "$prefix" "$protected_directory" 700
    else
      install -d -o root -g root -m 0700 "$protected_directory"
    fi
  done
  offline_validate_root_directory "$prefix" "$OFFLINE_RUNTIME_ROOT" 700
  offline_validate_root_directory "$prefix" "$OFFLINE_CONTRACT_ROOT" 700
  offline_validate_root_directory "$prefix" "$OFFLINE_TMPDIR" 700
  offline_validate_root_directory "$prefix" "$OFFLINE_HOME" 700
  offline_validate_root_directory "$prefix" "$OFFLINE_DOCKER_CONFIG" 700
  TMPDIR=$OFFLINE_TMPDIR
  HOME=$OFFLINE_HOME
  DOCKER_CONFIG=$OFFLINE_DOCKER_CONFIG
  export TMPDIR HOME DOCKER_CONFIG
}

offline_lock_is_inherited() {
  [ "${KB_OFFLINE_LOCK_HELD:-}" = "$OFFLINE_LOCK_TOKEN" ] || return 1
  [ -e /proc/$$/fd/9 ] || return 1
  inherited_lock=$(readlink /proc/$$/fd/9 2>/dev/null || true)
  [ "$inherited_lock" = "$OFFLINE_LOCK_FILE" ]
}

offline_acquire_lock() {
  prefix=$1
  offline_require_root "$prefix"
  offline_prepare_runtime_root "$prefix"
  if offline_lock_is_inherited; then
    return 0
  fi

  offline_validate_root_directory "$prefix" "$OFFLINE_LOCK_DIRECTORY"
  if [ -L "$OFFLINE_LOCK_FILE" ]; then
    offline_fail "$prefix" "deployment lock file must not be symbolic" 73
  fi
  if [ -e "$OFFLINE_LOCK_FILE" ]; then
    lock_owner=$(stat -c %u -- "$OFFLINE_LOCK_FILE") || exit 73
    lock_mode=$(stat -c %a -- "$OFFLINE_LOCK_FILE") || exit 73
    lock_links=$(stat -c %h -- "$OFFLINE_LOCK_FILE") || exit 73
    lock_canonical=$(realpath -e -- "$OFFLINE_LOCK_FILE" 2>/dev/null || true)
    if [ ! -f "$OFFLINE_LOCK_FILE" ] || [ "$lock_owner" -ne 0 ] || \
      [ "$lock_mode" != 600 ] || [ "$lock_links" -ne 1 ] || \
      [ "$lock_canonical" != "$OFFLINE_LOCK_FILE" ]; then
      offline_fail "$prefix" "deployment lock file has unsafe ownership or permissions" 73
    fi
  fi
  command -v flock >/dev/null 2>&1 || \
    offline_fail "$prefix" "flock is required for deployment serialization" 69
  exec 9>"$OFFLINE_LOCK_FILE"
  chmod 0600 "$OFFLINE_LOCK_FILE"
  if ! flock -n 9; then
    offline_fail "$prefix" "another deployment operation is already running" 75
  fi
  lock_owner=$(stat -c %u -- "$OFFLINE_LOCK_FILE") || exit 73
  lock_mode=$(stat -c %a -- "$OFFLINE_LOCK_FILE") || exit 73
  lock_links=$(stat -c %h -- "$OFFLINE_LOCK_FILE") || exit 73
  if [ "$lock_owner" -ne 0 ] || [ "$lock_mode" != 600 ] || \
    [ "$lock_links" -ne 1 ]; then
    offline_fail "$prefix" "deployment lock file has unsafe ownership or permissions" 73
  fi
  KB_OFFLINE_LOCK_HELD=$OFFLINE_LOCK_TOKEN
  export KB_OFFLINE_LOCK_HELD
}

offline_clear_inherited_environment() {
  inherited_lock=${KB_OFFLINE_LOCK_HELD:-}
  inherited_names=$(env | sed -n \
    -e 's/^\(KB_[A-Z0-9_]*\)=.*/\1/p' \
    -e 's/^\(COMPOSE_[A-Z0-9_]*\)=.*/\1/p' \
    -e 's/^\(DOCKER_[A-Z0-9_]*\)=.*/\1/p' \
    -e 's/^\(POSTGRES_[A-Z0-9_]*\)=.*/\1/p' \
    -e 's/^\(MINIO_[A-Z0-9_]*\)=.*/\1/p' \
    -e 's/^\(REDIS_PASSWORD\)=.*/\1/p' \
    -e 's/^\(CLAMAV_[A-Z0-9_]*\)=.*/\1/p' \
    -e 's/^\(PYTEST_ADDOPTS\)=.*/\1/p' \
    -e 's/^\(PYTHONPATH\)=.*/\1/p')
  for inherited_name in $inherited_names; do
    unset "$inherited_name"
  done
  unset ENV BASH_ENV CDPATH \
    HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
    http_proxy https_proxy all_proxy no_proxy \
    LD_PRELOAD LD_LIBRARY_PATH \
    PYTHONHOME PYTHONSTARTUP PYTHONINSPECT PYTHONWARNINGS \
    SSL_CERT_FILE SSL_CERT_DIR
  if [ "$inherited_lock" = "$OFFLINE_LOCK_TOKEN" ]; then
    KB_OFFLINE_LOCK_HELD=$inherited_lock
    export KB_OFFLINE_LOCK_HELD
  fi
  PATH=$OFFLINE_SYSTEM_PATH
  TMPDIR=$OFFLINE_TMPDIR
  HOME=$OFFLINE_HOME
  DOCKER_CONFIG=$OFFLINE_DOCKER_CONFIG
  export PATH TMPDIR HOME DOCKER_CONFIG
}

offline_contract_files() {
  cat <<'EOF'
runtime.env
release.env
release.env.images
release/deploy/tencent/compose.offline.yml
release/deploy/tencent/Caddyfile.offline
release/deploy/tencent/Caddyfile.maintenance
release/deploy/tencent/Caddyfile.llm-egress
release/deploy/tencent/offline-recovery-state.py
release/deploy/tencent/offline-recovery-dispatcher.sh
release/deploy/tencent/reconcile-offline.sh
release/deploy/tencent/heyi-kb-offline-reconcile.service
release/deploy/tencent/heyi-kb-offline-reconcile.timer
release/deploy/tencent/offline-operation-common.sh
release/deploy/tencent/prepare-offline-contract.sh
release/deploy/tencent/preflight-offline.sh
release/deploy/tencent/preflight-maintenance-offline.sh
release/deploy/tencent/verify-offline-images.sh
release/deploy/tencent/enter-maintenance-offline.sh
release/deploy/tencent/install-offline.sh
release/deploy/tencent/offline-pre-migration-abort.py
release/deploy/tencent/deploy-offline.sh
release/deploy/tencent/adopt-offline.sh
release/deploy/tencent/create-offline-contract.sh
release/deploy/tencent/remove-offline-contract.sh
release/deploy/tencent/rollback-offline.sh
release/deploy/tencent/import-offline-registry-bundle.sh
release/deploy/tencent/verify-maintenance-endpoint.py
release/deploy/tencent/verify-upgrade-backup.py
release/deploy/tencent/run-migration-with-lock.py
release/deploy/tencent/verify-offline-network-cidrs.py
release/deploy/tencent/verify-offline-project-inventory.py
release/deploy/tencent/validate-offline-environment.py
release/docker/postgres/init-runtime-role.sh
release/docker/minio/init.sh
release/docker/minio/cleanup-multipart.sh
release/docker/clamav/clamd.conf
release/docker/clamav/preflight-database.sh
release/scripts/legacy_offline_adoption.py
release/scripts/host_isolation_guard.py
EOF
}

offline_contract_path_is_safe() {
  contract_dir=$1
  case "$contract_dir" in
    "$OFFLINE_CONTRACT_ROOT"/contract.*) ;;
    *) return 1 ;;
  esac
  canonical_contract=$(realpath -e -- "$contract_dir" 2>/dev/null || true)
  [ "$canonical_contract" = "$contract_dir" ] || return 1
  offline_validate_root_directory contract "$contract_dir" 700
}

offline_verify_contract() {
  prefix=$1
  contract_dir=$2
  offline_contract_path_is_safe "$contract_dir" || \
    offline_fail "$prefix" "contract path is outside the protected runtime root" 65

  if [ -n "${OFFLINE_SELF_DESCRIBING_CONTRACT_SHA256:-}" ]; then
    case "$OFFLINE_SELF_DESCRIBING_CONTRACT_SHA256" in
      ""|*[!0-9a-f]*)
        offline_fail "$prefix" "self-describing contract identity is invalid" 65
        ;;
    esac
    if [ "${#OFFLINE_SELF_DESCRIBING_CONTRACT_SHA256}" -ne 64 ]; then
      offline_fail "$prefix" "self-describing contract identity is invalid" 65
    fi
    python3 -I "$OFFLINE_RELEASE_ROOT/deploy/tencent/offline-recovery-state.py" \
      verify-contract-path "$contract_dir" \
      "$OFFLINE_SELF_DESCRIBING_CONTRACT_SHA256" || \
      offline_fail "$prefix" "self-describing contract verification failed" 65
    printf '%s\n' "$OFFLINE_SELF_DESCRIBING_CONTRACT_SHA256"
    return 0
  fi

  expected_list=$(mktemp "$OFFLINE_TMPDIR/contract-hashes.XXXXXXXXXX")
  chmod 0600 "$expected_list"
  contract_paths=$(mktemp "$OFFLINE_TMPDIR/contract-paths.XXXXXXXXXX")
  chmod 0600 "$contract_paths"
  offline_contract_files > "$contract_paths"
  while IFS= read -r relative_path; do
    [ -n "$relative_path" ] || continue
    candidate=$contract_dir/$relative_path
    if [ -L "$candidate" ] || [ ! -f "$candidate" ]; then
      offline_fail "$prefix" "contract file is missing or symbolic: $relative_path" 65
    fi
    owner=$(stat -c %u -- "$candidate") || exit 66
    mode=$(stat -c %a -- "$candidate") || exit 66
    if [ "$owner" -ne 0 ] || [ "$mode" != 400 ]; then
      offline_fail "$prefix" "contract file has unsafe ownership or permissions: $relative_path" 65
    fi
    digest=$(sha256sum "$candidate" | awk '{print $1}') || exit 66
    printf '%s  %s\n' "$digest" "$relative_path" >> "$expected_list"
  done < "$contract_paths"
  rm -f "$contract_paths"

  metadata=$contract_dir/files.sha256
  contract_digest_file=$contract_dir/contract.sha256
  for protected_file in "$metadata" "$contract_digest_file"; do
    if [ -L "$protected_file" ] || [ ! -f "$protected_file" ]; then
      rm -f "$expected_list"
      offline_fail "$prefix" "contract metadata is missing or symbolic" 65
    fi
    owner=$(stat -c %u -- "$protected_file") || exit 66
    mode=$(stat -c %a -- "$protected_file") || exit 66
    if [ "$owner" -ne 0 ] || [ "$mode" != 400 ]; then
      rm -f "$expected_list"
      offline_fail "$prefix" "contract metadata has unsafe ownership or permissions" 65
    fi
  done
  if ! cmp -s "$metadata" "$expected_list"; then
    rm -f "$expected_list"
    offline_fail "$prefix" "contract file hashes changed after snapshot" 65
  fi
  rm -f "$expected_list"

  expected_contract_digest=$(sha256sum "$metadata" | awk '{print $1}') || exit 66
  recorded_contract_digest=$(awk 'NR == 1 {print $1} NR > 1 {exit 1}' \
    "$contract_digest_file") || exit 66
  if ! printf '%s\n' "$recorded_contract_digest" | grep -Eq '^[0-9a-f]{64}$' || \
    [ "$recorded_contract_digest" != "$expected_contract_digest" ]; then
    offline_fail "$prefix" "contract digest is invalid" 65
  fi
  printf '%s\n' "$recorded_contract_digest"
}

offline_contract_runtime_env() {
  printf '%s/runtime.env\n' "$1"
}

offline_contract_release_env() {
  printf '%s/release.env\n' "$1"
}

offline_contract_manifest() {
  printf '%s/release.env.images\n' "$1"
}

offline_contract_compose_file() {
  compose_release_root=${OFFLINE_COMPOSE_RELEASE_ROOT_OVERRIDE:-$OFFLINE_RELEASE_ROOT}
  printf '%s/deploy/tencent/compose.offline.yml\n' "$compose_release_root"
}

offline_verify_release_assets() {
  prefix=$1
  contract_dir=$2
  if [ -n "${OFFLINE_SELF_DESCRIBING_CONTRACT_SHA256:-}" ]; then
    if [ -z "${OFFLINE_COMPOSE_RELEASE_ROOT_OVERRIDE:-}" ]; then
      offline_fail "$prefix" "self-describing release root is missing" 65
    fi
    python3 -I "$OFFLINE_RELEASE_ROOT/deploy/tencent/offline-recovery-state.py" \
      verify-materialized-release "$contract_dir" \
      "$OFFLINE_SELF_DESCRIBING_CONTRACT_SHA256" \
      "$OFFLINE_COMPOSE_RELEASE_ROOT_OVERRIDE" || \
      offline_fail "$prefix" "self-describing release asset verification failed" 65
    return 0
  fi
  release_paths=$(mktemp "$OFFLINE_TMPDIR/release-paths.XXXXXXXXXX") || \
    offline_fail "$prefix" "cannot create the release asset list" 66
  offline_contract_files > "$release_paths" || {
    rm -f "$release_paths"
    offline_fail "$prefix" "cannot enumerate release assets" 66
  }
  while IFS= read -r relative_path; do
    case "$relative_path" in
      release/*)
        source_relative=${relative_path#release/}
        source_path=$OFFLINE_RELEASE_ROOT/$source_relative
        snapshot_path=$contract_dir/$relative_path
        canonical_source=$(realpath -e -- "$source_path" 2>/dev/null || true)
        if [ "$canonical_source" != "$source_path" ] || [ -L "$source_path" ] || \
          [ ! -f "$source_path" ] || ! cmp -s "$source_path" "$snapshot_path"; then
          offline_fail "$prefix" "trusted release asset changed after contract creation" 65
        fi
        checked_path=$source_path
        while :; do
          if [ -L "$checked_path" ]; then
            offline_fail "$prefix" "trusted release asset path became symbolic" 65
          fi
          owner=$(stat -c %u -- "$checked_path") || \
            offline_fail "$prefix" "cannot inspect trusted release asset ownership" 66
          mode=$(stat -c %a -- "$checked_path") || \
            offline_fail "$prefix" "cannot inspect trusted release asset permissions" 66
          mode_value=$((0$mode))
          if [ "$owner" -ne 0 ] || [ $((mode_value & 022)) -ne 0 ]; then
            offline_fail "$prefix" "trusted release asset path is writable by non-root" 65
          fi
          [ "$checked_path" = / ] && break
          checked_path=$(dirname -- "$checked_path")
        done
        ;;
    esac
  done < "$release_paths"
  rm -f "$release_paths"
}

offline_validate_materialized_release() {
  prefix=$1
  contract_dir=$2
  materialized_root=$3
  materialized_digest=${materialized_root##*/}
  if ! printf '%s\n' "$materialized_digest" | grep -Eq '^[0-9a-f]{64}$' || \
    [ "$materialized_root" != "/srv/heyi-knowledgebases-offline/releases/$materialized_digest" ]; then
    offline_fail "$prefix" "materialized release path is outside the protected root" 65
  fi
  canonical_root=$(realpath -e -- "$materialized_root" 2>/dev/null || true)
  if [ "$canonical_root" != "$materialized_root" ] || [ -L "$materialized_root" ]; then
    offline_fail "$prefix" "materialized release root is missing or symbolic" 65
  fi
  expected_files=$(mktemp "$OFFLINE_TMPDIR/materialized-expected.XXXXXXXXXX") || exit 66
  actual_files=$(mktemp "$OFFLINE_TMPDIR/materialized-actual.XXXXXXXXXX") || {
    rm -f "$expected_files"
    exit 66
  }
  offline_contract_files | sed -n 's#^release/##p' | LC_ALL=C sort \
    > "$expected_files" || {
    rm -f "$expected_files" "$actual_files"
    offline_fail "$prefix" "cannot build materialized release inventory" 66
  }
  if ! python3 -I -c '
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
for current, directories, files in os.walk(root, followlinks=False):
    current_path = pathlib.Path(current)
    current_info = current_path.lstat()
    if not stat.S_ISDIR(current_info.st_mode) or current_info.st_uid != 0 or current_info.st_mode & 0o022:
        raise SystemExit(1)
    for name in [*directories, *files]:
        path = current_path / name
        info = path.lstat()
        if path.is_symlink() or info.st_uid != 0:
            raise SystemExit(1)
        if stat.S_ISDIR(info.st_mode):
            if info.st_mode & 0o022:
                raise SystemExit(1)
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o444:
                raise SystemExit(1)
        else:
            raise SystemExit(1)
' "$materialized_root"; then
    rm -f "$expected_files" "$actual_files"
    offline_fail "$prefix" "materialized release contains unsafe filesystem objects" 65
  fi
  if ! find "$materialized_root" -type f -printf '%P\n' | LC_ALL=C sort \
    > "$actual_files"; then
    rm -f "$expected_files" "$actual_files"
    offline_fail "$prefix" "cannot enumerate materialized release" 66
  fi
  if ! cmp -s "$expected_files" "$actual_files"; then
    rm -f "$expected_files" "$actual_files"
    offline_fail "$prefix" "materialized release inventory differs from the contract" 65
  fi
  content_mismatch=
  while IFS= read -r relative_path; do
    source_path=$contract_dir/release/$relative_path
    destination_path=$materialized_root/$relative_path
    if ! cmp -s "$source_path" "$destination_path"; then
      content_mismatch=$relative_path
      break
    fi
  done < "$expected_files"
  rm -f "$expected_files" "$actual_files"
  if [ -n "$content_mismatch" ]; then
    offline_fail "$prefix" "materialized release content differs: $content_mismatch" 65
  fi
}

offline_materialize_release() {
  prefix=$1
  contract_dir=$2
  contract_digest=$(offline_verify_contract "$prefix" "$contract_dir")
  releases_root=/srv/heyi-knowledgebases-offline/releases
  materialized_root=$releases_root/$contract_digest
  for protected_directory in /srv /srv/heyi-knowledgebases-offline "$releases_root"; do
    if [ -L "$protected_directory" ]; then
      offline_fail "$prefix" "persistent release path must not be symbolic" 65
    fi
    if [ -e "$protected_directory" ]; then
      owner=$(stat -c %u -- "$protected_directory") || exit 66
      mode=$(stat -c %a -- "$protected_directory") || exit 66
      mode_value=$((0$mode))
      if [ "$owner" -ne 0 ] || [ $((mode_value & 022)) -ne 0 ]; then
        offline_fail "$prefix" "persistent release path is writable by non-root" 65
      fi
    fi
  done
  install -d -o root -g root -m 0750 /srv/heyi-knowledgebases-offline "$releases_root"
  if [ -e "$materialized_root" ]; then
    offline_validate_materialized_release "$prefix" "$contract_dir" "$materialized_root"
    printf '%s\n' "$materialized_root"
    return 0
  fi
  staging_root=$(mktemp -d "$releases_root/.release-$contract_digest.XXXXXXXXXX") || \
    offline_fail "$prefix" "cannot create persistent release staging directory" 73
  chmod 0700 "$staging_root"
  release_paths=$(mktemp "$OFFLINE_TMPDIR/materialize-paths.XXXXXXXXXX") || {
    rm -rf -- "$staging_root"
    exit 66
  }
  offline_contract_files | sed -n 's#^release/##p' > "$release_paths" || {
    rm -rf -- "$staging_root"
    rm -f "$release_paths"
    offline_fail "$prefix" "cannot enumerate release contract assets" 66
  }
  materialize_error=
  while IFS= read -r relative_path; do
    [ -n "$relative_path" ] || continue
    destination_path=$staging_root/$relative_path
    if ! install -d -o root -g root -m 0555 "$(dirname -- "$destination_path")"; then
      materialize_error="cannot create persistent release directory"
      break
    fi
    if ! install -o root -g root -m 0444 \
      "$contract_dir/release/$relative_path" "$destination_path"; then
      materialize_error="cannot materialize release asset"
      break
    fi
  done < "$release_paths"
  rm -f "$release_paths"
  if [ -n "$materialize_error" ]; then
    rm -rf -- "$staging_root"
    offline_fail "$prefix" "$materialize_error" 73
  fi
  find "$staging_root" -type d -exec chmod 0555 {} + || {
    rm -rf -- "$staging_root"
    offline_fail "$prefix" "cannot seal persistent release directories" 73
  }
  if ! python3 -I -c '
import os, pathlib, sys
root = pathlib.Path(sys.argv[1])
for path in root.rglob("*"):
    if path.is_file():
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
for path in sorted((item for item in root.rglob("*") if item.is_dir()), key=lambda item: len(item.parts), reverse=True):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
' "$staging_root"; then
    chmod -R u+w "$staging_root" 2>/dev/null || true
    rm -rf -- "$staging_root"
    offline_fail "$prefix" "cannot durably flush persistent release" 73
  fi
  if ! mv -- "$staging_root" "$materialized_root"; then
    chmod -R u+w "$staging_root" 2>/dev/null || true
    rm -rf -- "$staging_root"
    offline_fail "$prefix" "cannot atomically publish persistent release" 73
  fi
  sync -f "$materialized_root" || offline_fail "$prefix" "cannot sync persistent release" 73
  sync -f "$releases_root" || offline_fail "$prefix" "cannot sync releases directory" 73
  offline_validate_materialized_release "$prefix" "$contract_dir" "$materialized_root"
  printf '%s\n' "$materialized_root"
}

offline_capture_project_inventory_snapshot() {
  prefix=$1
  container_ids_file=$2
  container_inspect_file=$3
  network_ids_file=$4
  network_inspect_file=$5
  container_ids_raw=$container_ids_file.raw
  container_ids_unique=$container_ids_file.unique
  network_ids_raw=$network_ids_file.raw
  network_ids_unique=$network_ids_file.unique

  if ! docker ps --all --quiet --no-trunc \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    > "$container_ids_raw"; then
    offline_fail "$prefix" "cannot enumerate project containers" 69
  fi
  if ! LC_ALL=C sort "$container_ids_raw" > "$container_ids_file"; then
    offline_fail "$prefix" "cannot sort project container identities" 69
  fi
  if ! awk '
    length($0) != 64 || $0 !~ /^[0-9a-f]+$/ { exit 1 }
    END { if (NR == 0) exit 1 }
  ' "$container_ids_file" || \
    ! uniq "$container_ids_file" > "$container_ids_unique" || \
    ! cmp -s "$container_ids_file" "$container_ids_unique"; then
    offline_fail "$prefix" "project container identities are incomplete or ambiguous" 70
  fi
  container_ids=$(cat "$container_ids_file")
  old_ifs=$IFS
  IFS="$(printf '\n ')"
  # shellcheck disable=SC2086
  set -- $container_ids
  IFS=$old_ifs
  if ! docker inspect "$@" > "$container_inspect_file"; then
    offline_fail "$prefix" "cannot inspect the exact project containers" 69
  fi

  if ! docker network ls --quiet --no-trunc \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    > "$network_ids_raw"; then
    offline_fail "$prefix" "cannot enumerate project networks" 69
  fi
  if ! LC_ALL=C sort "$network_ids_raw" > "$network_ids_file"; then
    offline_fail "$prefix" "cannot sort project network identities" 69
  fi
  if ! awk '
    length($0) != 64 || $0 !~ /^[0-9a-f]+$/ { exit 1 }
    END { if (NR == 0) exit 1 }
  ' "$network_ids_file" || \
    ! uniq "$network_ids_file" > "$network_ids_unique" || \
    ! cmp -s "$network_ids_file" "$network_ids_unique"; then
    offline_fail "$prefix" "project network identities are incomplete or ambiguous" 70
  fi
  network_ids=$(cat "$network_ids_file")
  old_ifs=$IFS
  IFS="$(printf '\n ')"
  # shellcheck disable=SC2086
  set -- $network_ids
  IFS=$old_ifs
  if ! docker network inspect "$@" > "$network_inspect_file"; then
    offline_fail "$prefix" "cannot inspect the exact project networks" 69
  fi
}

offline_verify_project_release_labels() (
  prefix=$1
  contract_dir=$2
  expected_release_root=${3:-$OFFLINE_RELEASE_ROOT}
  requested_verifier_phase=${4:-}
  expected_compose_file=$expected_release_root/deploy/tencent/compose.offline.yml
  inventory_verifier=$expected_release_root/deploy/tencent/verify-offline-project-inventory.py
  network_verifier=$expected_release_root/deploy/tencent/verify-offline-network-cidrs.py
  selected_profile=$(offline_compose_profile "$prefix" "$contract_dir")
  case "$selected_profile" in
    "") verifier_profile=strict ;;
    controlled-egress) verifier_profile=controlled-egress ;;
    *) offline_fail "$prefix" "cannot map the reviewed Compose profile" 65 ;;
  esac
  if [ -n "$requested_verifier_phase" ]; then
    case "$requested_verifier_phase" in
      install|deploy|recovery) verifier_phase=$requested_verifier_phase ;;
      *) offline_fail "$prefix" "unsupported requested inventory verification phase" 64 ;;
    esac
  else
    case "$prefix" in
      deploy) verifier_phase=deploy ;;
      install) verifier_phase=install ;;
      recovery) verifier_phase=recovery ;;
      *) offline_fail "$prefix" "unsupported final inventory verification phase" 64 ;;
    esac
  fi

  evidence_dir=$(mktemp -d "$OFFLINE_TMPDIR/final-inventory.XXXXXXXXXX") || \
    offline_fail "$prefix" "cannot create protected inventory evidence" 66
  chmod 0700 "$evidence_dir"
  trap 'rm -rf -- "$evidence_dir"' EXIT HUP INT TERM
  compose_config=$evidence_dir/compose.json
  compose_hashes=$evidence_dir/compose-hashes.txt
  containers_first=$evidence_dir/containers-first.json
  container_ids_first=$evidence_dir/container-ids-first.txt
  networks_first=$evidence_dir/networks-first.json
  network_ids_first=$evidence_dir/network-ids-first.txt
  containers_second=$evidence_dir/containers-second.json
  container_ids_second=$evidence_dir/container-ids-second.txt
  networks_second=$evidence_dir/networks-second.json
  network_ids_second=$evidence_dir/network-ids-second.txt

  if [ "$verifier_phase" = deploy ]; then
    offline_compose "$prefix" "$contract_dir" \
      --profile maintenance config --format json > "$compose_config" || \
      offline_fail "$prefix" "cannot render final Compose inventory" 69
    offline_compose "$prefix" "$contract_dir" \
      --profile maintenance config --hash '*' > "$compose_hashes" || \
      offline_fail "$prefix" "cannot render final Compose service hashes" 69
  else
    offline_compose "$prefix" "$contract_dir" \
      config --format json > "$compose_config" || \
      offline_fail "$prefix" "cannot render final Compose inventory" 69
    offline_compose "$prefix" "$contract_dir" \
      config --hash '*' > "$compose_hashes" || \
      offline_fail "$prefix" "cannot render final Compose service hashes" 69
  fi
  chmod 0600 "$evidence_dir"/*

  offline_capture_project_inventory_snapshot "$prefix" \
    "$container_ids_first" "$containers_first" \
    "$network_ids_first" "$networks_first"
  python3 -I "$inventory_verifier" \
    --project-name "$OFFLINE_PROJECT_NAME" \
    --profile "$verifier_profile" \
    --phase "$verifier_phase" \
    --expected-config-file "$expected_compose_file" \
    --compose-config-json "$compose_config" \
    --compose-hashes "$compose_hashes" \
    --container-inspect-json "$containers_first" \
    --network-inspect-json "$networks_first" || \
    offline_fail "$prefix" "final project inventory is not exact" 70

  offline_capture_project_inventory_snapshot "$prefix" \
    "$container_ids_second" "$containers_second" \
    "$network_ids_second" "$networks_second"
  if ! cmp -s "$container_ids_first" "$container_ids_second" || \
    ! cmp -s "$network_ids_first" "$network_ids_second"; then
    offline_fail "$prefix" "project topology changed during final verification" 70
  fi
  python3 -I "$inventory_verifier" \
    --project-name "$OFFLINE_PROJECT_NAME" \
    --profile "$verifier_profile" \
    --phase "$verifier_phase" \
    --expected-config-file "$expected_compose_file" \
    --compose-config-json "$compose_config" \
    --compose-hashes "$compose_hashes" \
    --container-inspect-json "$containers_second" \
    --network-inspect-json "$networks_second" || \
    offline_fail "$prefix" "final project inventory changed during verification" 70

  python3 -I "$network_verifier" \
    "$OFFLINE_PROJECT_NAME" \
    172.30.240.0/24 172.30.241.0/24 172.30.242.0/24 \
    172.30.243.0/24 172.30.244.0/24 || \
    offline_fail "$prefix" "final project network boundary is invalid" 70
  project_volumes=$(docker volume ls -q \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME") || \
    offline_fail "$prefix" "cannot enumerate final project volumes" 69
  [ -z "$project_volumes" ] || \
    offline_fail "$prefix" "unexpected Compose volumes remain in the final project" 70
)

offline_compose_profile() {
  prefix=$1
  contract_dir=$2
  offline_verify_contract "$prefix" "$contract_dir" >/dev/null
  offline_verify_release_assets "$prefix" "$contract_dir"
  runtime_env_file=$(offline_contract_runtime_env "$contract_dir")
  release_env_file=$(offline_contract_release_env "$contract_dir")
  validator=$contract_dir/release/deploy/tencent/validate-offline-environment.py
  selected_profile=$(python3 -I "$validator" \
    "$runtime_env_file" "$release_env_file" --emit-compose-profile) || \
    offline_fail "$prefix" "cannot derive the reviewed Compose profile" 65
  case "$selected_profile" in
    ""|controlled-egress) ;;
    *) offline_fail "$prefix" "environment selected an unknown Compose profile" 65 ;;
  esac
  printf '%s\n' "$selected_profile"
}

offline_compose() {
  prefix=$1
  contract_dir=$2
  shift 2
  if ! offline_verify_contract "$prefix" "$contract_dir" >/dev/null; then
    offline_fail "$prefix" "contract verification failed before Compose" 65
  fi
  if ! offline_verify_release_assets "$prefix" "$contract_dir"; then
    offline_fail "$prefix" "release asset verification failed before Compose" 65
  fi
  runtime_env_file=$(offline_contract_runtime_env "$contract_dir")
  release_env_file=$(offline_contract_release_env "$contract_dir")
  compose_file=$(offline_contract_compose_file "$contract_dir")
  selected_profile=$(offline_compose_profile "$prefix" "$contract_dir")
  offline_clear_inherited_environment
  if [ -n "$selected_profile" ]; then
    docker compose \
      --project-name "$OFFLINE_PROJECT_NAME" \
      --env-file "$runtime_env_file" \
      --env-file "$release_env_file" \
      --file "$compose_file" \
      --profile "$selected_profile" \
      "$@"
  else
    docker compose \
      --project-name "$OFFLINE_PROJECT_NAME" \
      --env-file "$runtime_env_file" \
      --env-file "$release_env_file" \
      --file "$compose_file" \
      "$@"
  fi
}

offline_receipt_profile() {
  prefix=$1
  contract_dir=$2
  selected_profile=$(offline_compose_profile "$prefix" "$contract_dir")
  case "$selected_profile" in
    "") printf '%s\n' strict-offline ;;
    controlled-egress) printf '%s\n' controlled-egress ;;
    *) offline_fail "$prefix" "cannot normalize the offline Compose profile" 65 ;;
  esac
}

offline_egress_contract_fields() {
  prefix=$1
  contract_dir=$2
  offline_verify_contract "$prefix" "$contract_dir" >/dev/null
  validator=$contract_dir/release/deploy/tencent/validate-offline-environment.py
  fields=$(python3 -I "$validator" \
    "$(offline_contract_runtime_env "$contract_dir")" \
    "$(offline_contract_release_env "$contract_dir")" \
    --emit-egress-fields) || \
    offline_fail "$prefix" "cannot derive the reviewed LLM egress contract" 65
  # The trusted validator emits two constrained fields; cardinality is checked next.
  # shellcheck disable=SC2086
  set -- $fields
  if [ "$#" -ne 2 ]; then
    offline_fail "$prefix" "LLM egress contract fields are incomplete" 65
  fi
  case "$1:$2" in
    strict_offline:-|controlled_gateway:deepseek|controlled_gateway:qwen|\
    controlled_gateway:minimax|controlled_gateway:deepseek,qwen|\
    controlled_gateway:deepseek,minimax|controlled_gateway:qwen,minimax|\
    controlled_gateway:deepseek,qwen,minimax) ;;
    *) offline_fail "$prefix" "LLM egress contract fields are invalid" 65 ;;
  esac
  printf '%s\t%s\n' "$1" "$2"
}

offline_single_running_service() {
  prefix=$1
  service=$2
  service_ids=$(docker ps --quiet --no-trunc \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=$service") || \
    offline_fail "$prefix" "cannot enumerate the required service" 69
  old_ifs=$IFS
  IFS="$(printf '\n ')"
  # shellcheck disable=SC2086
  set -- $service_ids
  IFS=$old_ifs
  if [ "$#" -ne 1 ] || \
    ! printf '%s\n' "$1" | grep -Eq '^[0-9a-f]{64}$'; then
    offline_fail "$prefix" "required service identity is absent or ambiguous" 70
  fi
  candidate_id=$1
  observed=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }} {{ index .Config.Labels "com.docker.compose.service" }} {{ index .Config.Labels "io.heyi.knowledgebases.owner" }} {{ index .Config.Labels "io.heyi.knowledgebases.stack" }} {{.State.Running}}' \
    "$candidate_id" 2>/dev/null) || \
    offline_fail "$prefix" "cannot inspect the required service" 69
  if [ "$observed" != "$OFFLINE_PROJECT_NAME $service jiangsu-heyi-knowledgebases offline true" ]; then
    offline_fail "$prefix" "required service ownership or state is invalid" 70
  fi
  printf '%s\n' "$candidate_id"
}

offline_gateway_response_sha256() {
  prefix=$1
  gateway_id=$2
  path=$3
  timeout_seconds=$4
  observed_sha256=$(docker exec "$gateway_id" /bin/busybox sh -ec '
result=$(/bin/busybox wget -q -t 1 -T "$1" -O - "http://127.0.0.1:8080$2" 2>/dev/null | /bin/busybox sha256sum)
set -- $result
[ "$#" -eq 2 ] && [ "$2" = "-" ] || exit 1
printf "%s\n" "$1"
' probe "$timeout_seconds" "$path" 2>/dev/null) || \
    offline_fail "$prefix" "LLM gateway HTTP proof did not complete" 70
  if ! printf '%s\n' "$observed_sha256" | grep -Eq '^[0-9a-f]{64}$'; then
    offline_fail "$prefix" "LLM gateway HTTP proof was malformed" 70
  fi
  printf '%s\n' "$observed_sha256"
}

offline_verify_local_egress_liveness() {
  prefix=$1
  contract_dir=$2
  egress_fields=$(offline_egress_contract_fields "$prefix" "$contract_dir")
  # The trusted helper emits two constrained fields; its own validation precedes this split.
  # shellcheck disable=SC2086
  set -- $egress_fields
  mode=$1
  if [ "$mode" = strict_offline ]; then
    stale_gateway=$(docker ps --all --quiet \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=llm-egress") || return 1
    stale_uplink=$(docker network ls --quiet \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.network=llm-uplink") || return 1
    if [ -n "$stale_gateway" ] || [ -n "$stale_uplink" ]; then
      offline_fail "$prefix" "strict_offline retained a materialized egress boundary" 70
    fi
    return 0
  fi
  gateway_id=$(offline_single_running_service "$prefix" llm-egress)
  observed=$(offline_gateway_response_sha256 \
    "$prefix" "$gateway_id" /_heyi/health/live 3)
  [ "$observed" = 2317a728584609144fec1b10db497c29614244fcdc1d769ec031ce6a3f90255f ] || \
    offline_fail "$prefix" "LLM gateway exact liveness body differs" 70
}

offline_strict_container_egress_probe() {
  prefix=$1
  service=$2
  container_id=$(offline_single_running_service "$prefix" "$service")
  observed=$(timeout 12 docker exec "$container_id" python -I -c '
import ipaddress, os, pathlib, socket, sys

service = sys.argv[1]
failed = any(os.environ.get(name) for name in (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
))
try:
    hosts = pathlib.Path("/etc/hosts").read_text(encoding="utf-8", errors="replace")
except OSError:
    failed = True
else:
    failed = failed or "host.docker.internal" in hosts.casefold()

try:
    socket.setdefaulttimeout(1.0)
    socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)
except OSError:
    pass
else:
    failed = True

for host, port in (("1.1.1.1", 443), ("169.254.169.254", 80)):
    try:
        connection = socket.create_connection((host, port), timeout=1.0)
    except OSError:
        continue
    else:
        connection.close()
        failed = True

try:
    lines = pathlib.Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]
except OSError:
    failed = True
else:
    for line in lines:
        columns = line.split()
        if len(columns) < 4 or columns[3] != "01":
            continue
        address_hex, port_hex = columns[2].split(":", 1)
        address = ipaddress.ip_address(bytes.fromhex(address_hex)[::-1])
        if int(port_hex, 16) and address.is_global:
            failed = True

if failed:
    raise SystemExit(1)
print(f"heyi-strict-container-egress-v1:{service}")
' "$service" 2>/dev/null) || \
    offline_fail "$prefix" "strict_offline container namespace retained an egress path" 70
  [ "$observed" = "heyi-strict-container-egress-v1:$service" ] || \
    offline_fail "$prefix" "strict_offline container proof body differs" 70
}

offline_active_provider_snapshot() {
  prefix=$1
  approved_csv=$2
  api_id=$(offline_single_running_service "$prefix" api)
  active_provider=$(timeout 20 docker exec "$api_id" \
    python -I -m app.services.llm_egress_attestation 2>/dev/null) || \
    offline_fail "$prefix" "active LLM provider snapshot could not be locked" 70
  case ",$approved_csv," in
    *,"$active_provider",*) ;;
    *) offline_fail "$prefix" "active LLM provider is outside the approval contract" 70 ;;
  esac
  case "$active_provider" in deepseek|qwen|minimax) ;; *) \
    offline_fail "$prefix" "active LLM provider snapshot is invalid" 70 ;; esac
  printf '%s\n' "$active_provider"
}

offline_egress_proof_fields() {
  prefix=$1
  contract_dir=$2
  contract_sha256=$3
  egress_fields=$(offline_egress_contract_fields "$prefix" "$contract_dir")
  # The trusted helper emits two constrained fields; its own validation precedes this split.
  # shellcheck disable=SC2086
  set -- $egress_fields
  mode=$1
  approved_csv=$2
  receipt_profile=$(offline_receipt_profile "$prefix" "$contract_dir")
  compose_sha256=$(offline_compose_config_digest "$prefix" "$contract_dir")
  egress_release_root=${OFFLINE_COMPOSE_RELEASE_ROOT_OVERRIDE:-$OFFLINE_RELEASE_ROOT}
  caddy_sha256=$(sha256sum \
    "$egress_release_root/deploy/tencent/Caddyfile.llm-egress" | awk '{print $1}') || \
    offline_fail "$prefix" "cannot hash the LLM gateway contract" 66
  active_provider=none
  route_contract=-

  offline_verify_local_egress_liveness "$prefix" "$contract_dir"
  if [ "$mode" = strict_offline ]; then
    offline_strict_container_egress_probe "$prefix" api
    offline_strict_container_egress_probe "$prefix" maintenance
  else
    gateway_id=$(offline_single_running_service "$prefix" llm-egress)
    route_contract=
    old_ifs=$IFS
    IFS=,
    # The approved-provider grammar forbids whitespace and metacharacters.
    # shellcheck disable=SC2086
    set -- $approved_csv
    IFS=$old_ifs
    for provider in "$@"; do
      case "$provider" in
        deepseek)
          probe_path=/_heyi/probe/deepseek
          expected_sha256=ef69eef517be9aa925c3eed3aeb33840c3a9aaad9e599204287f0ca99f88c5c7
          ;;
        qwen)
          probe_path=/_heyi/probe/qwen
          expected_sha256=0cefb7e073b81c0ba6a655ebf4739eff522f056267c1a38b475170c61263714d
          ;;
        minimax)
          probe_path=/_heyi/probe/minimax
          expected_sha256=d3d272f0634db889b84a193bcc3def9d0c92842fe6740d10940370b5f9c920a3
          ;;
        *) offline_fail "$prefix" "approved provider contract is invalid" 65 ;;
      esac
      observed_sha256=$(offline_gateway_response_sha256 \
        "$prefix" "$gateway_id" "$probe_path" 15)
      [ "$observed_sha256" = "$expected_sha256" ] || \
        offline_fail "$prefix" "approved provider route proof failed" 70
      route_contract=${route_contract}${route_contract:+,}$provider:$expected_sha256
    done
    # Sample direct public and metadata paths from the only uplink namespace.
    # Exact nftables/DNS set equality is independently proven by runtime evidence.
    if docker exec "$gateway_id" /bin/busybox nc -z -w 2 1.1.1.1 443 \
        >/dev/null 2>&1 || \
      docker exec "$gateway_id" /bin/busybox nc -z -w 2 169.254.169.254 80 \
        >/dev/null 2>&1; then
      offline_fail "$prefix" "LLM gateway reached an unapproved direct endpoint" 70
    fi
    active_provider=$(offline_active_provider_snapshot "$prefix" "$approved_csv")
  fi

  proof_sha256=$(python3 -I -c '
import hashlib, json, sys
document = {
    "schema_version": 1,
    "kind": "offline-egress-release-proof",
    "contract_sha256": sys.argv[1],
    "receipt_profile": sys.argv[2],
    "approved_providers": [] if sys.argv[3] == "-" else sys.argv[3].split(","),
    "compose_config_sha256": sys.argv[4],
    "caddyfile_sha256": sys.argv[5],
    "local_liveness_sha256": "2317a728584609144fec1b10db497c29614244fcdc1d769ec031ce6a3f90255f",
    "route_contract": sys.argv[6],
    "strict_namespace_services": ["api", "maintenance"] if sys.argv[2] == "strict-offline" else [],
}
payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
print(hashlib.sha256(payload).hexdigest())
' "$contract_sha256" "$receipt_profile" "$approved_csv" \
    "$compose_sha256" "$caddy_sha256" "$route_contract") || \
    offline_fail "$prefix" "cannot canonicalize the LLM egress proof" 66
  printf '%s\t%s\n' "$proof_sha256" "$active_provider"
}

offline_compose_config_digest() {
  prefix=$1
  contract_dir=$2
  rendered_config=$(mktemp "$OFFLINE_TMPDIR/compose-receipt.XXXXXXXXXX") || \
    offline_fail "$prefix" "cannot create Compose receipt input" 66
  canonical_config=$(mktemp "$OFFLINE_TMPDIR/compose-canonical.XXXXXXXXXX") || {
    rm -f "$rendered_config"
    offline_fail "$prefix" "cannot create canonical Compose receipt input" 66
  }
  if ! offline_compose "$prefix" "$contract_dir" config --format json \
    > "$rendered_config"; then
    rm -f "$rendered_config" "$canonical_config"
    offline_fail "$prefix" "cannot render Compose config for the release receipt" 69
  fi
  if ! python3 -I -c '
import json, pathlib, sys
source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
document = json.loads(source.read_text(encoding="utf-8"))
target.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8")
' "$rendered_config" "$canonical_config"; then
    rm -f "$rendered_config" "$canonical_config"
    offline_fail "$prefix" "Compose config is not canonical JSON" 65
  fi
  digest=$(sha256sum "$canonical_config" | awk '{print $1}') || {
    rm -f "$rendered_config" "$canonical_config"
    exit 66
  }
  rm -f "$rendered_config" "$canonical_config"
  printf '%s\n' "$digest"
}

offline_project_inventory_digest() {
  prefix=$1
  container_ids=$(docker ps -aq \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME") || \
    offline_fail "$prefix" "cannot enumerate the active project inventory" 69
  [ -n "$container_ids" ] || \
    offline_fail "$prefix" "active project inventory is empty" 70
  inventory_json=$(mktemp "$OFFLINE_TMPDIR/project-inventory.XXXXXXXXXX") || exit 66
  canonical_inventory=$(mktemp "$OFFLINE_TMPDIR/project-inventory-canonical.XXXXXXXXXX") || {
    rm -f "$inventory_json"
    exit 66
  }
  old_ifs=$IFS
  IFS="$(printf '\n ')"
  # shellcheck disable=SC2086
  set -- $container_ids
  IFS=$old_ifs
  if ! docker inspect "$@" > "$inventory_json"; then
    rm -f "$inventory_json" "$canonical_inventory"
    offline_fail "$prefix" "cannot inspect the active project inventory" 69
  fi
  if ! python3 -I -c '
import json, pathlib, sys
source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
containers = json.loads(source.read_text(encoding="utf-8"))
records = []
for container in containers:
    labels = container.get("Config", {}).get("Labels") or {}
    service = labels.get("com.docker.compose.service")
    if service == "maintenance-page" or labels.get("com.docker.compose.oneoff") in {"True", "true"}:
        continue
    records.append({
        "service": service,
        "project": labels.get("com.docker.compose.project"),
        "config_files": labels.get("com.docker.compose.project.config_files"),
        "config_hash": labels.get("com.docker.compose.config-hash"),
        "owner": labels.get("io.heyi.knowledgebases.owner"),
        "stack": labels.get("io.heyi.knowledgebases.stack"),
        "image": container.get("Config", {}).get("Image"),
        "running": container.get("State", {}).get("Running"),
        "exit_code": container.get("State", {}).get("ExitCode"),
        "health": (
            container.get("State", {}).get("Health", {}).get("Status")
            if isinstance(container.get("State", {}).get("Health"), dict)
            else None
        ),
        "restart_policy": container.get("HostConfig", {}).get("RestartPolicy", {}).get("Name"),
    })
records.sort(key=lambda item: str(item["service"]))
if not records or len({item["service"] for item in records}) != len(records):
    raise SystemExit(1)
target.write_text(json.dumps(records, sort_keys=True, separators=(",", ":")), encoding="utf-8")
' "$inventory_json" "$canonical_inventory"; then
    rm -f "$inventory_json" "$canonical_inventory"
    offline_fail "$prefix" "active project inventory is ambiguous" 70
  fi
  digest=$(sha256sum "$canonical_inventory" | awk '{print $1}') || {
    rm -f "$inventory_json" "$canonical_inventory"
    exit 66
  }
  rm -f "$inventory_json" "$canonical_inventory"
  printf '%s\n' "$digest"
}

offline_prepare_persistent_recovery() {
  prefix=$1
  contract_dir=$2
  contract_sha256=$3
  state_helper=$OFFLINE_RELEASE_ROOT/deploy/tencent/offline-recovery-state.py
  dispatcher_source=$OFFLINE_RELEASE_ROOT/deploy/tencent/offline-recovery-dispatcher.sh
  service_source=$OFFLINE_RELEASE_ROOT/deploy/tencent/heyi-kb-offline-reconcile.service
  timer_source=$OFFLINE_RELEASE_ROOT/deploy/tencent/heyi-kb-offline-reconcile.timer
  for required_asset in \
    "$state_helper" "$dispatcher_source" "$service_source" "$timer_source"; do
    if [ -L "$required_asset" ] || [ ! -f "$required_asset" ]; then
      offline_fail "$prefix" "recovery asset is missing or symbolic" 65
    fi
  done
  python3 -I "$state_helper" persist-contract "$contract_dir" "$contract_sha256" || \
    offline_fail "$prefix" "cannot persist the canonical recovery contract" 73

  command -v systemctl >/dev/null 2>&1 || \
    offline_fail "$prefix" "systemd is required for crash reconciliation" 69
  if [ "$(ps -p 1 -o comm= | tr -d '[:space:]')" != systemd ]; then
    offline_fail "$prefix" "PID 1 must be systemd for crash reconciliation" 69
  fi
  for protected_directory in /etc /etc/systemd /etc/systemd/system; do
    if [ -L "$protected_directory" ] || [ ! -d "$protected_directory" ]; then
      offline_fail "$prefix" "systemd unit path is missing or symbolic" 73
    fi
    owner=$(stat -c %u "$protected_directory") || exit 73
    mode=$(stat -c %a "$protected_directory") || exit 73
    mode_value=$((0$mode))
    if [ "$owner" -ne 0 ] || [ $((mode_value & 022)) -ne 0 ]; then
      offline_fail "$prefix" "systemd unit path is writable by non-root" 73
    fi
  done
  install -d -o root -g root -m 0700 "$OFFLINE_RECOVERY_DIRECTORY"
  offline_validate_root_directory "$prefix" "$OFFLINE_RECOVERY_DIRECTORY" 700
  for source_and_target in \
    "$dispatcher_source:$OFFLINE_RECOVERY_DIRECTORY/offline-recovery-dispatcher.sh:0500" \
    "$state_helper:$OFFLINE_RECOVERY_DIRECTORY/offline-recovery-state.py:0500" \
    "$service_source:/etc/systemd/system/heyi-kb-offline-reconcile.service:0444" \
    "$timer_source:/etc/systemd/system/heyi-kb-offline-reconcile.timer:0444"; do
    source_path=${source_and_target%%:*}
    remainder=${source_and_target#*:}
    destination_path=${remainder%:*}
    destination_mode=${remainder##*:}
    destination_directory=$(dirname "$destination_path")
    temporary_path=$(mktemp "$destination_directory/.heyi-recovery.XXXXXXXXXX") || exit 73
    if ! install -o root -g root -m "$destination_mode" "$source_path" "$temporary_path" || \
      ! sync -f "$temporary_path" || ! mv -f "$temporary_path" "$destination_path" || \
      ! sync -f "$destination_path" || ! sync -f "$destination_directory"; then
      rm -f "$temporary_path"
      offline_fail "$prefix" "cannot atomically install the recovery watchdog" 73
    fi
  done
  systemctl daemon-reload || offline_fail "$prefix" "systemd daemon-reload failed" 71
  systemctl enable --now heyi-kb-offline-reconcile.timer >/dev/null || \
    offline_fail "$prefix" "cannot enable the crash-reconciliation timer" 71
  [ "$(systemctl is-enabled heyi-kb-offline-reconcile.timer)" = enabled ] || \
    offline_fail "$prefix" "crash-reconciliation timer is not enabled" 71
}

offline_assert_maintenance_hold() {
  prefix=$1
  contract_dir=$2
  state_helper=$OFFLINE_RELEASE_ROOT/deploy/tencent/offline-recovery-state.py
  state_fields=$(python3 -I "$state_helper" select | python3 -I -c '
import json,sys
d=json.load(sys.stdin)
print(d.get("selection", ""), d.get("operation", ""))
') || offline_fail "$prefix" "cannot inspect the durable maintenance hold" 65
  # The trusted state helper emits two enumerated fields; cardinality is checked next.
  # shellcheck disable=SC2086
  set -- $state_fields
  if [ "$#" -ne 2 ] || [ "$1" != intent ] || [ "$2" != maintenance ]; then
    offline_fail "$prefix" "only a durable standalone maintenance hold can be superseded" 65
  fi
  for stopped_service in \
    proxy web api maintenance llm-egress minio-multipart-gc \
    migrate bootstrap minio-init; do
    service_ids=$(docker ps -aq \
      --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$stopped_service") || \
      offline_fail "$prefix" "cannot inspect the maintenance hold" 69
    old_ifs=$IFS
    IFS="$(printf '\n ')"
    # shellcheck disable=SC2086
    set -- $service_ids
    IFS=$old_ifs
    for service_id in "$@"; do
      [ -n "$service_id" ] || continue
      observed_project=$(docker inspect --format \
        '{{ index .Config.Labels "com.docker.compose.project" }}' \
        "$service_id" 2>/dev/null) || exit 69
      observed_service=$(docker inspect --format \
        '{{ index .Config.Labels "com.docker.compose.service" }}' \
        "$service_id" 2>/dev/null) || exit 69
      observed_owner=$(docker inspect --format \
        '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' \
        "$service_id" 2>/dev/null) || exit 69
      observed_stack=$(docker inspect --format \
        '{{ index .Config.Labels "io.heyi.knowledgebases.stack" }}' \
        "$service_id" 2>/dev/null) || exit 69
      observed_running=$(docker inspect --format '{{.State.Running}}' \
        "$service_id" 2>/dev/null) || exit 69
      if [ "$observed_project" != "$OFFLINE_PROJECT_NAME" ] || \
        [ "$observed_service" != "$stopped_service" ] || \
        [ "$observed_owner" != jiangsu-heyi-knowledgebases ] || \
        [ "$observed_stack" != offline ] || [ "$observed_running" != false ]; then
        offline_fail "$prefix" "maintenance hold retained a running or foreign writer" 70
      fi
    done
  done
  maintenance_ids=$(docker ps -q \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=maintenance-page") || exit 69
  old_ifs=$IFS
  IFS="$(printf '\n ')"
  # shellcheck disable=SC2086
  set -- $maintenance_ids
  IFS=$old_ifs
  [ "$#" -eq 1 ] || \
    offline_fail "$prefix" "maintenance hold requires one running edge endpoint" 70
  observed_owner=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' "$maintenance_ids") || exit 69
  observed_stack=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.stack" }}' "$maintenance_ids") || exit 69
  observed_project=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}' "$maintenance_ids") || exit 69
  observed_service=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.service" }}' "$maintenance_ids") || exit 69
  if [ "$observed_project" != "$OFFLINE_PROJECT_NAME" ] || \
    [ "$observed_service" != maintenance-page ] || \
    [ "$observed_owner" != jiangsu-heyi-knowledgebases ] || \
    [ "$observed_stack" != offline ]; then
    offline_fail "$prefix" "maintenance edge ownership is invalid" 70
  fi
  maintenance_config=$(mktemp "$OFFLINE_TMPDIR/maintenance-hold.XXXXXXXXXX") || exit 66
  offline_compose "$prefix" "$contract_dir" \
    --profile maintenance config --format json > "$maintenance_config" || {
    rm -f "$maintenance_config"
    offline_fail "$prefix" "cannot render the maintenance hold verifier" 69
  }
  if ! python3 -I \
    "$OFFLINE_RELEASE_ROOT/deploy/tencent/verify-maintenance-endpoint.py" \
    --compose-config-stdin < "$maintenance_config"; then
    rm -f "$maintenance_config"
    offline_fail "$prefix" "maintenance hold is not strictly healthy" 70
  fi
  rm -f "$maintenance_config"
}

offline_release_bound_inventory_digest() {
  prefix=$1
  release_root=$2
  sh -c '
set -eu
script_dir=$1/deploy/tencent
. "$script_dir/offline-operation-common.sh"
offline_project_inventory_digest "$2"
' recovery-baseline "$release_root" "$prefix" || \
    offline_fail "$prefix" "release-bound project inventory digest failed" 70
}

offline_release_bound_egress_proof_fields() {
  prefix=$1
  release_root=$2
  contract_dir=$3
  contract_sha256=$4
  sh -c '
set -eu
script_dir=$1/deploy/tencent
. "$script_dir/offline-operation-common.sh"
offline_egress_proof_fields "$2" "$3" "$4"
' recovery-baseline "$release_root" "$prefix" "$contract_dir" \
    "$contract_sha256" || \
    offline_fail "$prefix" "release-bound LLM egress proof failed" 70
}

offline_validate_upgrade_recovery_baseline() (
  prefix=$1
  state_helper=$OFFLINE_RELEASE_ROOT/deploy/tencent/offline-recovery-state.py
  baseline_contract=
  # The EXIT trap expands the validated mktemp path only when the subshell exits.
  trap '[ -z "$baseline_contract" ] || rm -rf -- "$baseline_contract"' EXIT
  trap 'exit 130' HUP INT TERM

  # `select` validates both state documents (when present) and their immutable
  # persistent contracts before returning a decision.  Missing, malformed or
  # conflicting state is therefore a hard upgrade boundary, not a legacy
  # fallback to the handwritten project scan.
  baseline_json=$(python3 -I "$state_helper" select) || \
    offline_fail "$prefix" "upgrade recovery baseline is missing, damaged or conflicting" 65
  baseline_fields=$(printf '%s\n' "$baseline_json" | python3 -I -c '
import json, re, sys
d = json.load(sys.stdin)
selection = d.get("selection")
operation = d.get("operation", "-")
contract = d.get("contract_sha256")
profile = d.get("compose_profile")
config = d.get("compose_config_sha256")
inventory = d.get("project_inventory_sha256", "-")
egress = d.get("egress_proof_sha256", "-")
provider = d.get("active_provider_snapshot", "-")
digest = re.compile(r"[0-9a-f]{64}")
valid = (
    selection in {"active", "intent"}
    and operation in {"-", "install", "deploy", "maintenance"}
    and isinstance(contract, str) and digest.fullmatch(contract)
    and profile in {"strict-offline", "controlled-egress"}
    and isinstance(config, str) and digest.fullmatch(config)
    and (
        (
            selection == "active"
            and isinstance(inventory, str) and digest.fullmatch(inventory)
            and isinstance(egress, str) and digest.fullmatch(egress)
            and (
                (profile == "strict-offline" and provider == "none")
                or (profile == "controlled-egress" and provider in {"deepseek", "qwen", "minimax"})
            )
        )
        or (selection == "intent" and inventory == "-" and egress == "-" and provider == "-")
    )
)
if not valid:
    raise SystemExit(1)
print(selection, operation, contract, profile, config, inventory, egress, provider)
') || offline_fail "$prefix" "upgrade recovery baseline fields are invalid" 65
  # The trusted parser validates eight whitespace-free fields before printing them.
  # shellcheck disable=SC2086
  set -- $baseline_fields
  [ "$#" -eq 8 ] || \
    offline_fail "$prefix" "upgrade recovery baseline fields are incomplete" 65
  baseline_selection=$1
  baseline_operation=$2
  baseline_contract_sha256=$3
  baseline_profile=$4
  baseline_compose_sha256=$5
  baseline_inventory_sha256=$6
  baseline_egress_sha256=$7

  baseline_contract=$(python3 -I "$state_helper" stage-contract \
    "$baseline_contract_sha256" "$OFFLINE_CONTRACT_ROOT") || \
    offline_fail "$prefix" "cannot stage the durable upgrade baseline contract" 73
  OFFLINE_SELF_DESCRIBING_CONTRACT_SHA256=$baseline_contract_sha256
  verified_baseline=$(offline_verify_contract "$prefix" "$baseline_contract")
  [ "$verified_baseline" = "$baseline_contract_sha256" ] || \
    offline_fail "$prefix" "staged upgrade baseline contract changed" 65
  baseline_release_root=/srv/heyi-knowledgebases-offline/releases/$baseline_contract_sha256
  python3 -I "$state_helper" verify-materialized-release \
    "$baseline_contract" "$baseline_contract_sha256" "$baseline_release_root" || \
    offline_fail "$prefix" "durable active release assets are not self-consistent" 65
  OFFLINE_COMPOSE_RELEASE_ROOT_OVERRIDE=$baseline_release_root
  observed_profile=$(offline_receipt_profile "$prefix" "$baseline_contract")
  observed_compose_sha256=$(offline_compose_config_digest "$prefix" "$baseline_contract")
  if [ "$observed_profile" != "$baseline_profile" ] || \
    [ "$observed_compose_sha256" != "$baseline_compose_sha256" ]; then
    offline_fail "$prefix" "running release contract differs from durable recovery state" 65
  fi

  case "$baseline_selection" in
    active)
      # Any surviving intent must go through the explicit standalone
      # maintenance supersede path.  Even a matching stale intent is not
      # silently cleared by the upgrade preflight.
      if [ -e "$OFFLINE_CUTOVER_INTENT" ] || [ -L "$OFFLINE_CUTOVER_INTENT" ]; then
        offline_fail "$prefix" "upgrade cannot bypass an existing cutover intent" 65
      fi
      [ "$baseline_operation" = - ] || \
        offline_fail "$prefix" "active upgrade baseline contains an operation" 65
      offline_verify_project_release_labels \
        "$prefix" "$baseline_contract" "$baseline_release_root" install
      observed_inventory_sha256=$(offline_release_bound_inventory_digest \
        "$prefix" "$baseline_release_root")
      [ "$observed_inventory_sha256" = "$baseline_inventory_sha256" ] || \
        offline_fail "$prefix" "active project inventory differs from its durable receipt" 70
      observed_egress_fields=$(offline_release_bound_egress_proof_fields \
        "$prefix" "$baseline_release_root" "$baseline_contract" \
        "$baseline_contract_sha256")
      # The release-bound helper emits exactly two constrained fields.
      # shellcheck disable=SC2086
      set -- $observed_egress_fields
      # The default provider is intentionally mutable through the reviewed
      # management API.  The durable proof binds the approved provider set and
      # exact gateway routes; it must not freeze that mutable selection.
      if [ "$#" -ne 2 ] || [ "$1" != "$baseline_egress_sha256" ]; then
        offline_fail "$prefix" "active LLM egress proof differs from its durable receipt" 70
      fi
      ;;
    intent)
      if [ "$baseline_operation" != maintenance ] || \
        { [ ! -e "$OFFLINE_CUTOVER_INTENT" ] && [ ! -L "$OFFLINE_CUTOVER_INTENT" ]; }; then
        offline_fail "$prefix" \
          "only a durable standalone maintenance intent may precede an upgrade" 65
      fi
      offline_assert_maintenance_hold "$prefix" "$baseline_contract"
      ;;
    *) offline_fail "$prefix" "unsupported upgrade recovery baseline" 65 ;;
  esac
)

offline_begin_cutover() {
  prefix=$1
  contract_dir=$2
  contract_sha256=$3
  operation=$4
  receipt_profile=$(offline_receipt_profile "$prefix" "$contract_dir")
  compose_config_sha256=$(offline_compose_config_digest "$prefix" "$contract_dir")
  offline_prepare_persistent_recovery "$prefix" "$contract_dir" "$contract_sha256"
  state_helper=$OFFLINE_RELEASE_ROOT/deploy/tencent/offline-recovery-state.py
  current_state=$(python3 -I "$state_helper" select 2>/dev/null || true)
  current_fields=$(printf '%s\n' "$current_state" | python3 -I -c '
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    print("none", "none", "none", "none")
else:
    print(d.get("selection", "none"), d.get("operation", "none"), d.get("contract_sha256", "none"), d.get("transaction_id", "none"))
') || offline_fail "$prefix" "cannot parse the existing cutover state" 65
  # The trusted parser emits four whitespace-free fields; cardinality is checked next.
  # shellcheck disable=SC2086
  set -- $current_fields
  current_selection=$1
  current_operation=$2
  current_contract=$3
  current_transaction=$4
  if [ "$current_selection" = active ] && [ -e "$OFFLINE_CUTOVER_INTENT" ]; then
    python3 -I "$state_helper" clear-intent \
      "$current_contract" "$current_transaction" || \
      offline_fail "$prefix" "cannot clear an already committed stale intent" 73
    current_selection=active
    current_operation=none
  fi
  if [ "$operation" = deploy ] && [ "$current_selection" = intent ] && \
    [ "$current_operation" = maintenance ]; then
    if ! (
      maintenance_contract=$(python3 -I "$state_helper" stage-contract \
        "$current_contract" "$OFFLINE_CONTRACT_ROOT") || exit 73
      trap 'rm -rf -- "$maintenance_contract"' EXIT
      trap 'exit 130' HUP INT TERM
      maintenance_release_root=/srv/heyi-knowledgebases-offline/releases/$current_contract
      OFFLINE_SELF_DESCRIBING_CONTRACT_SHA256=$current_contract
      python3 -I "$state_helper" verify-materialized-release \
        "$maintenance_contract" "$current_contract" "$maintenance_release_root" || exit 65
      OFFLINE_COMPOSE_RELEASE_ROOT_OVERRIDE=$maintenance_release_root
      offline_assert_maintenance_hold "$prefix" "$maintenance_contract"
    ); then
      offline_fail "$prefix" "durable maintenance hold failed supersede validation" 70
    fi
    transaction_id=$(python3 -I "$state_helper" \
      supersede-maintenance-intent "$contract_sha256" "$receipt_profile" \
      "$compose_config_sha256") || \
      offline_fail "$prefix" "cannot atomically supersede the maintenance hold" 73
  else
    transaction_id=$(python3 -I "$state_helper" \
      write-intent "$contract_sha256" "$operation" "$receipt_profile" \
      "$compose_config_sha256") || \
      offline_fail "$prefix" "cannot durably publish the cutover intent" 73
  fi
  printf '%s\n' "$transaction_id"
}

offline_commit_active_release() {
  prefix=$1
  contract_dir=$2
  contract_sha256=$3
  transaction_id=$4
  receipt_profile=$(offline_receipt_profile "$prefix" "$contract_dir")
  compose_config_sha256=$(offline_compose_config_digest "$prefix" "$contract_dir")
  project_inventory_sha256=$(offline_project_inventory_digest "$prefix")
  egress_proof_fields=$(offline_egress_proof_fields \
    "$prefix" "$contract_dir" "$contract_sha256")
  # The proof helper emits exactly two constrained fields; cardinality is checked next.
  # shellcheck disable=SC2086
  set -- $egress_proof_fields
  [ "$#" -eq 2 ] || offline_fail "$prefix" "LLM egress proof fields are incomplete" 70
  egress_proof_sha256=$1
  active_provider_snapshot=$2
  python3 -I "$OFFLINE_RELEASE_ROOT/deploy/tencent/offline-recovery-state.py" \
    write-active "$contract_sha256" "$transaction_id" "$receipt_profile" \
    "$compose_config_sha256" "$project_inventory_sha256" \
    "$egress_proof_sha256" "$active_provider_snapshot" || \
    offline_fail "$prefix" "cannot durably commit the active release receipt" 73
}

offline_clear_committed_cutover() {
  prefix=$1
  contract_sha256=$2
  transaction_id=$3
  python3 -I "$OFFLINE_RELEASE_ROOT/deploy/tencent/offline-recovery-state.py" \
    clear-intent "$contract_sha256" "$transaction_id" || \
    offline_fail "$prefix" "cannot clear the committed cutover intent" 73
}
