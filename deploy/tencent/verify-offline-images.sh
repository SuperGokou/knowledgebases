#!/usr/bin/env sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 generate|verify /absolute/path/to/offline.env /path/to/images.txt" >&2
  exit 64
fi

action=$1
env_file=$2
manifest=$3
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compose_file=$script_dir/compose.offline.yml
temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT HUP INT TERM

docker compose \
  --project-name heyi-kb-offline \
  --env-file "$env_file" \
  --file "$compose_file" \
  --profile ops \
  config --images | LC_ALL=C sort -u > "$temporary"

validate_pinned_image() {
  image=$1
  if ! printf '%s\n' "$image" | grep -Eq '^.+@sha256:[0-9a-f]{64}$'; then
    echo "offline-images: image must be pinned by sha256 digest: $image" >&2
    return 65
  fi

  reference_without_digest=${image%@sha256:*}
  digest=sha256:${image##*@sha256:}
  last_component=${reference_without_digest##*/}
  case "$last_component" in
    *:*) repository=${reference_without_digest%:*} ;;
    *) repository=$reference_without_digest ;;
  esac
  expected_repo_digest=$repository@$digest

  repo_digests=$(docker image inspect \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' \
    "$image") || return 66
  if ! printf '%s\n' "$repo_digests" | grep -Fqx "$expected_repo_digest"; then
    echo "offline-images: local image digest does not match manifest: $image" >&2
    return 65
  fi
}

case "$action" in
  generate)
    while IFS= read -r image; do
      [ -n "$image" ] || continue
      validate_pinned_image "$image"
    done < "$temporary"
    install -m 0644 "$temporary" "$manifest"
    echo "offline-images: generated compose image manifest"
    ;;
  verify)
    if ! [ -f "$manifest" ] || ! cmp -s "$manifest" "$temporary"; then
      echo "offline-images: manifest does not match docker compose config --images" >&2
      exit 65
    fi
    while IFS= read -r image; do
      [ -n "$image" ] || continue
      validate_pinned_image "$image"
    done < "$manifest"
    echo "offline-images: manifest matches compose and every image is loaded"
    ;;
  *)
    echo "offline-images: action must be generate or verify" >&2
    exit 64
    ;;
esac
