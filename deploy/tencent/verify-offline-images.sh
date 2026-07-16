#!/usr/bin/env sh
set -eu

action=${1:-}
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"

expected_repo_digest_for() {
  image=$1
  reference_without_digest=${image%@sha256:*}
  digest=sha256:${image##*@sha256:}
  last_component=${reference_without_digest##*/}
  case "$last_component" in
    *:*) repository=${reference_without_digest%:*} ;;
    *) repository=$reference_without_digest ;;
  esac
  printf '%s@%s\n' "$repository" "$digest"
}

validate_pinned_image() {
  image=$1
  if ! printf '%s\n' "$image" | grep -Eq '^.+@sha256:[0-9a-f]{64}$'; then
    offline_fail offline-images "image must be pinned by sha256 digest: $image" 65
  fi
  case "$image" in
    127.0.0.1:5000/*@sha256:*) ;;
    *) offline_fail offline-images "image must use the controlled loopback registry: $image" 65 ;;
  esac
}

inspect_image() {
  image=$1
  expected_id=${2:-}
  expected_os=${3:-linux}
  expected_arch=${4:-amd64}
  validate_pinned_image "$image"
  expected_repo_digest=$(expected_repo_digest_for "$image")

  if ! image_id=$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null); then
    echo "offline-images: exact digest reference is unavailable in the local image store" >&2
    echo "offline-images: classic docker save/load does not preserve RepoDigests; use the controlled local-registry import workflow" >&2
    return 66
  fi
  image_os=$(docker image inspect --format '{{.Os}}' "$image") || return 66
  image_arch=$(docker image inspect --format '{{.Architecture}}' "$image") || return 66
  repo_digests=$(docker image inspect \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image") || return 66

  if ! printf '%s\n' "$image_id" | grep -Eq '^sha256:[0-9a-f]{64}$'; then
    offline_fail offline-images "local image ID is not a sha256 config digest: $image" 65
  fi
  if [ "$image_os" != linux ] || [ "$image_arch" != amd64 ]; then
    offline_fail offline-images "local image platform must be linux/amd64: $image" 65
  fi
  if [ "$image_os" != "$expected_os" ] || [ "$image_arch" != "$expected_arch" ]; then
    offline_fail offline-images "local image platform differs from the signed manifest: $image" 65
  fi
  if [ -n "$expected_id" ] && [ "$image_id" != "$expected_id" ]; then
    offline_fail offline-images "local image ID differs from the signed manifest: $image" 65
  fi
  if ! printf '%s\n' "$repo_digests" | grep -Fqx "$expected_repo_digest"; then
    offline_fail offline-images "local image RepoDigest does not match manifest: $image" 65
  fi
  printf '%s\t%s\t%s\t%s\n' "$image" "$image_id" "$image_os" "$image_arch"
}

case "$action" in
  generate)
    if [ "$#" -ne 3 ]; then
      echo "usage: $0 generate /absolute/path/to/runtime.env /absolute/path/to/release.env" >&2
      exit 64
    fi
    runtime_env_file=$2
    release_env_file=$3
    manifest=$release_env_file.images
    offline_acquire_lock offline-images
    offline_clear_inherited_environment
    python3 -I "$script_dir/validate-offline-environment.py" \
      "$runtime_env_file" "$release_env_file"
    image_list=$(mktemp "$OFFLINE_TMPDIR/offline-image-list.XXXXXXXXXX")
    raw_image_list=$(mktemp "$OFFLINE_TMPDIR/offline-image-list-raw.XXXXXXXXXX")
    generated_manifest=$(mktemp "$OFFLINE_TMPDIR/offline-image-manifest.XXXXXXXXXX")
    raw_generated_manifest=$(mktemp "$OFFLINE_TMPDIR/offline-image-manifest-raw.XXXXXXXXXX")
    trap 'rm -f "$image_list" "$raw_image_list" "$generated_manifest" "$raw_generated_manifest"' EXIT
    trap 'exit 130' HUP INT TERM
    if ! docker compose \
      --project-name "$OFFLINE_PROJECT_NAME" \
      --env-file "$runtime_env_file" \
      --env-file "$release_env_file" \
      --file "$script_dir/compose.offline.yml" \
      --profile ops --profile maintenance --profile controlled-egress \
      config --images > "$raw_image_list"; then
      offline_fail offline-images "Compose image enumeration failed" 66
    fi
    LC_ALL=C sort -u "$raw_image_list" > "$image_list"
    while IFS= read -r image; do
      [ -n "$image" ] || continue
      inspect_image "$image"
    done < "$image_list" > "$raw_generated_manifest"
    LC_ALL=C sort -t "$(printf '\t')" -k1,1 \
      "$raw_generated_manifest" > "$generated_manifest"
    install -o root -g root -m 0444 "$generated_manifest" "$manifest"
    echo "offline-images: generated linux/amd64 RepoDigest+ID manifest at <release.env>.images"
    ;;
  verify)
    if [ "$#" -ne 5 ] || [ "$2" != "--contract-dir" ] || \
      [ "$4" != "--contract-sha256" ]; then
      echo "usage: $0 verify --contract-dir DIR --contract-sha256 SHA256" >&2
      exit 64
    fi
    contract_dir=$3
    expected_contract_sha256=$5
    offline_acquire_lock offline-images
    contract_sha256=$(offline_verify_contract offline-images "$contract_dir")
    if [ "$contract_sha256" != "$expected_contract_sha256" ]; then
      offline_fail offline-images "contract SHA-256 does not match" 65
    fi
    manifest=$(offline_contract_manifest "$contract_dir")
    image_list=$(mktemp "$OFFLINE_TMPDIR/offline-image-list.XXXXXXXXXX")
    raw_image_list=$(mktemp "$OFFLINE_TMPDIR/offline-image-list-raw.XXXXXXXXXX")
    manifest_image_list=$(mktemp "$OFFLINE_TMPDIR/offline-manifest-list.XXXXXXXXXX")
    trap 'rm -f "$image_list" "$raw_image_list" "$manifest_image_list"' EXIT
    trap 'exit 130' HUP INT TERM
    if ! offline_compose offline-images "$contract_dir" \
      --profile ops --profile maintenance --profile controlled-egress \
      config --images > "$raw_image_list"; then
      offline_fail offline-images "verified Compose image enumeration failed" 66
    fi
    LC_ALL=C sort -u "$raw_image_list" > "$image_list"

    tab=$(printf '\t')
    while IFS="$tab" read -r image expected_id expected_os expected_arch extra || \
      [ -n "${image:-}" ]; do
      if [ -z "${image:-}" ] || [ -n "${extra:-}" ] || \
        [ -z "${expected_id:-}" ] || [ -z "${expected_os:-}" ] || \
        [ -z "${expected_arch:-}" ]; then
        offline_fail offline-images "manifest entry must contain image, ID, OS and architecture" 65
      fi
      inspect_image "$image" "$expected_id" "$expected_os" "$expected_arch" >/dev/null
      printf '%s\n' "$image" >> "$manifest_image_list"
    done < "$manifest"
    LC_ALL=C sort -u -o "$manifest_image_list" "$manifest_image_list"
    if ! cmp -s "$image_list" "$manifest_image_list"; then
      offline_fail offline-images "manifest does not match docker compose config --images" 65
    fi
    echo "offline-images: manifest, RepoDigest, image ID and linux/amd64 platform match; contract_sha256=$contract_sha256"
    ;;
  *)
    echo "offline-images: action must be generate or verify" >&2
    exit 64
    ;;
esac
