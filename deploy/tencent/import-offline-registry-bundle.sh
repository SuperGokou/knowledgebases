#!/usr/bin/env sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 BUNDLE_ROOT TRUSTED_RELEASE_PUBLIC_KEY RELEASE_ENV" >&2
  exit 64
fi

bundle_root=$1
trusted_public_key=$2
release_env_file=$3
release_manifest=$release_env_file.images
canonical_trusted_public_key=/etc/heyi-release/trusted-release-public.pem
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"

offline_acquire_lock registry-import
offline_clear_inherited_environment

if [ "$trusted_public_key" != "$canonical_trusted_public_key" ]; then
  offline_fail registry-import \
    "trusted release public key must be the canonical host trust root" 65
fi

validate_protected_path() {
  label=$1
  checked_path=$2
  expected_kind=$3
  accepted_modes=$4
  case "$checked_path" in
    /*) ;;
    *) offline_fail registry-import "$label path must be absolute" 65 ;;
  esac
  canonical_path=$(realpath -e -- "$checked_path" 2>/dev/null || true)
  if [ "$canonical_path" != "$checked_path" ] || [ -L "$checked_path" ]; then
    offline_fail registry-import "$label path must be canonical and contain no symbolic links" 65
  fi
  case "$expected_kind" in
    file) [ -f "$checked_path" ] || offline_fail registry-import "$label is not a file" 65 ;;
    directory)
      [ -d "$checked_path" ] || offline_fail registry-import "$label is not a directory" 65
      ;;
    *) exit 64 ;;
  esac
  first_component=true
  while :; do
    if [ -L "$checked_path" ]; then
      offline_fail registry-import "$label path contains a symbolic link" 65
    fi
    owner=$(stat -c %u -- "$checked_path") || exit 66
    mode=$(stat -c %a -- "$checked_path") || exit 66
    if [ "$owner" -ne 0 ]; then
      offline_fail registry-import "$label and all ancestors must be owned by root" 65
    fi
    if [ "$first_component" = true ]; then
      case " $accepted_modes " in
        *" $mode "*) ;;
        *) offline_fail registry-import "$label has unsafe permissions" 65 ;;
      esac
      first_component=false
    else
      mode_value=$((0$mode))
      if [ $((mode_value & 022)) -ne 0 ]; then
        offline_fail registry-import "$label ancestor is group or world writable" 65
      fi
    fi
    [ "$checked_path" = / ] && break
    checked_path=$(dirname -- "$checked_path")
  done
}

validate_protected_path bundle "$bundle_root" directory "500 700 750"
validate_protected_path trusted-public-key "$trusted_public_key" file "400 444"
validate_protected_path release.env "$release_env_file" file "400 444"
validate_protected_path release.env.images "$release_manifest" file "400 444"

source_checksums=$bundle_root/SHA256SUMS
source_signature=$bundle_root/SHA256SUMS.sig
source_control=$bundle_root/bundle.control
source_signed_release=$bundle_root/release.env
source_signed_manifest=$bundle_root/release.env.images
registry_data=$bundle_root/registry
for signed_file in \
  "$source_checksums" "$source_signature" "$source_control" \
  "$source_signed_release" "$source_signed_manifest"; do
  validate_protected_path signed-bundle-file "$signed_file" file "400 444"
done
validate_protected_path registry-data "$registry_data" directory "500 700 750"

# Freeze every small control-plane input before signature verification. The
# potentially large registry tree remains read-only in place; every pulled
# manifest/blob is still content-addressed by the signed image manifest.
import_snapshot=$(mktemp -d "$OFFLINE_RUNTIME_ROOT/registry-import.XXXXXXXXXX")
chmod 0700 "$import_snapshot"
cleanup_import_snapshot() {
  rm -rf -- "$import_snapshot"
}
trap cleanup_import_snapshot EXIT
trap 'exit 130' HUP INT TERM

copy_stable_control_file() {
  source_file=$1
  destination_file=$2
  before_line=$(sha256sum "$source_file") || \
    offline_fail registry-import "cannot hash signed control input" 66
  before_digest=${before_line%% *}
  install -o root -g root -m 0400 "$source_file" "$destination_file" || \
    offline_fail registry-import "cannot snapshot signed control input" 66
  after_line=$(sha256sum "$source_file") || \
    offline_fail registry-import "cannot re-hash signed control input" 66
  after_digest=${after_line%% *}
  snapshot_line=$(sha256sum "$destination_file") || \
    offline_fail registry-import "cannot hash signed control snapshot" 66
  snapshot_digest=${snapshot_line%% *}
  if [ "$before_digest" != "$after_digest" ] || \
    [ "$before_digest" != "$snapshot_digest" ]; then
    offline_fail registry-import "signed control input changed during snapshot" 65
  fi
}

copy_stable_control_file "$trusted_public_key" "$import_snapshot/trusted-release.pem"
copy_stable_control_file "$source_checksums" "$import_snapshot/SHA256SUMS"
copy_stable_control_file "$source_signature" "$import_snapshot/SHA256SUMS.sig"
copy_stable_control_file "$source_control" "$import_snapshot/bundle.control"
copy_stable_control_file "$source_signed_release" "$import_snapshot/signed-release.env"
copy_stable_control_file \
  "$source_signed_manifest" "$import_snapshot/signed-release.env.images"
copy_stable_control_file "$release_env_file" "$import_snapshot/operator-release.env"
copy_stable_control_file "$release_manifest" "$import_snapshot/operator-release.env.images"

trusted_public_key=$import_snapshot/trusted-release.pem
trusted_key_digest=$(sha256sum "$trusted_public_key" | awk '{print $1}') || exit 66
if ! printf '%s\n' "$trusted_key_digest" | grep -Eq '^[0-9a-f]{64}$'; then
  offline_fail registry-import "trusted release public key digest is invalid" 65
fi
checksums=$import_snapshot/SHA256SUMS
signature=$import_snapshot/SHA256SUMS.sig
control=$import_snapshot/bundle.control
signed_release=$import_snapshot/signed-release.env
signed_manifest=$import_snapshot/signed-release.env.images
operator_release=$import_snapshot/operator-release.env
operator_manifest=$import_snapshot/operator-release.env.images
if ! python3 -I -c '
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
for current, directories, files in os.walk(root, followlinks=False):
    for name in [*directories, *files]:
        path = pathlib.Path(current, name)
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if path.is_symlink() or info.st_uid != 0 or any(part in {"", ".", ".."} for part in pathlib.PurePosixPath(relative).parts):
            raise SystemExit(1)
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise SystemExit(1)
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise SystemExit(1)
        if stat.S_ISDIR(info.st_mode) and info.st_mode & 0o022:
            raise SystemExit(1)
' "$bundle_root"; then
  offline_fail registry-import "bundle tree contains unsafe ownership, links or directories" 65
fi

command -v openssl >/dev/null 2>&1 || \
  offline_fail registry-import "openssl is required for release signature verification" 69
if ! openssl dgst -sha256 -verify "$trusted_public_key" \
  -signature "$signature" "$checksums" >/dev/null; then
  offline_fail registry-import "offline registry bundle signature is invalid" 65
fi
if ! python3 -I -c '
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
declared = set()
for line in (root / "SHA256SUMS").read_text(encoding="ascii").splitlines():
    match = re.fullmatch(r"[0-9a-f]{64}  ([A-Za-z0-9._/-]+)", line)
    if match is None or match.group(1) in declared:
        raise SystemExit(1)
    declared.add(match.group(1))
actual = {"bundle.control", "release.env", "release.env.images"}
for directory in ("registry", "release", "sbom"):
    base = root / directory
    if not base.is_dir():
        raise SystemExit(1)
    actual.update(path.relative_to(root).as_posix() for path in base.rglob("*") if path.is_file())
raise SystemExit(0 if declared == actual else 1)
' "$bundle_root"; then
  offline_fail registry-import "signed checksum inventory is incomplete or contains extras" 65
fi

seen_control=false
seen_release=false
seen_manifest=false
seen_registry=false
seen_release_asset=false
seen_sbom=false
while IFS= read -r checksum_line || [ -n "$checksum_line" ]; do
  digest=${checksum_line%%  *}
  relative_path=${checksum_line#*  }
  if ! printf '%s\n' "$digest" | grep -Eq '^[0-9a-f]{64}$' || \
    [ "$relative_path" = "$checksum_line" ]; then
    offline_fail registry-import "signed checksum entry has invalid syntax" 65
  fi
  case "$relative_path" in
    ""|/*|../*|*/../*|*/..|*//*|*[!A-Za-z0-9._/-]*)
      offline_fail registry-import "signed checksum path escapes the bundle" 65
      ;;
  esac
  signed_path=$bundle_root/$relative_path
  canonical_signed_path=$(realpath -e -- "$signed_path" 2>/dev/null || true)
  if [ "$canonical_signed_path" != "$signed_path" ]; then
    offline_fail registry-import "signed checksum path contains a symbolic redirect" 65
  fi
  case "$canonical_signed_path" in
    "$bundle_root"/*) ;;
    *) offline_fail registry-import "signed checksum path escapes the bundle" 65 ;;
  esac
  validate_protected_path signed-object "$canonical_signed_path" file "400 444 600 640 644"
  observed_digest=$(sha256sum "$canonical_signed_path" | awk '{print $1}') || exit 66
  if [ "$observed_digest" != "$digest" ]; then
    offline_fail registry-import "signed bundle object digest mismatch" 65
  fi
  case "$relative_path" in
    bundle.control) seen_control=true ;;
    release.env) seen_release=true ;;
    release.env.images) seen_manifest=true ;;
    registry/*) seen_registry=true ;;
    release/*) seen_release_asset=true ;;
    sbom/*) seen_sbom=true ;;
  esac
done < "$checksums"
if [ "$seen_control" != true ] || [ "$seen_release" != true ] || \
  [ "$seen_manifest" != true ] || [ "$seen_registry" != true ] || \
  [ "$seen_release_asset" != true ] || [ "$seen_sbom" != true ]; then
  offline_fail registry-import "signed bundle is incomplete" 65
fi
if ! python3 -I -c '
import hashlib, json, pathlib, re, sys

root = pathlib.Path(sys.argv[1])
manifest_path = root / "release.env.images"
manifest_bytes = manifest_path.read_bytes()
rows = manifest_bytes.decode("utf-8").splitlines()
images = []
for row in rows:
    fields = row.split("\t")
    if len(fields) != 4:
        raise SystemExit(1)
    reference, config_id, operating_system, architecture = fields
    match = re.fullmatch(r"127\.0\.0\.1:5000/.+@(sha256:[0-9a-f]{64})", reference)
    if (
        match is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", config_id) is None
        or operating_system != "linux"
        or architecture != "amd64"
    ):
        raise SystemExit(1)
    images.append((reference, match.group(1), config_id, operating_system, architecture))
if len(images) != 9 or len({item[0] for item in images}) != 9 or images != sorted(images):
    raise SystemExit(1)

control = {}
for row in (root / "bundle.control").read_text(encoding="ascii").splitlines():
    key, separator, value = row.partition("=")
    if not separator or key in control:
        raise SystemExit(1)
    control[key] = value
index = json.loads((root / "sbom/image-sbom-index.json").read_text(encoding="utf-8"))
scanner = index.get("scanner")
schema_key = "\u0024schema"
if (
    index.get(schema_key)
    != "https://knowledgebases.local/schemas/image-sbom-index-v1.schema.json"
    or index.get("schema_version") != 1
    or index.get("release_git_sha") != control.get("RELEASE_GIT_SHA")
    or index.get("release_id") != control.get("RELEASE_ID")
    or index.get("source_manifest_path") != "release.env.images"
    or index.get("source_manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest()
    or not isinstance(scanner, dict)
    or not isinstance(scanner.get("name"), str)
    or re.fullmatch(r"[0-9a-f]{64}", str(scanner.get("sha256"))) is None
):
    raise SystemExit(1)
records = index.get("images")
if not isinstance(records, list) or len(records) != 9:
    raise SystemExit(1)
record_by_reference = {
    record.get("reference"): record for record in records if isinstance(record, dict)
}
if len(record_by_reference) != 9 or set(record_by_reference) != {item[0] for item in images}:
    raise SystemExit(1)
scan_identities = []
for reference, manifest_digest, config_id, operating_system, architecture in images:
    record = record_by_reference[reference]
    sbom_relative = record.get("sbom_path")
    scan_identity = record.get("scan_identity")
    expected_relative = "sbom/image-{}.cdx.json".format(manifest_digest[7:])
    if (
        record.get("manifest_digest") != manifest_digest
        or record.get("config_id") != config_id
        or scan_identity not in {manifest_digest, config_id}
        or record.get("os") != operating_system
        or record.get("architecture") != architecture
        or sbom_relative != expected_relative
    ):
        raise SystemExit(1)
    scan_identities.append(scan_identity)
    sbom_path = root / expected_relative
    if hashlib.sha256(sbom_path.read_bytes()).hexdigest() != record.get("sbom_sha256"):
        raise SystemExit(1)
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    components = sbom.get("components")
    metadata = sbom.get("metadata")
    raw_properties = metadata.get("properties") if isinstance(metadata, dict) else None
    if (
        sbom.get("bomFormat") != "CycloneDX"
        or sbom.get("specVersion") != "1.6"
        or not isinstance(components, list)
        or len(components) != record.get("component_count")
        or not isinstance(raw_properties, list)
    ):
        raise SystemExit(1)
    properties = {
        item.get("name"): item.get("value")
        for item in raw_properties
        if isinstance(item, dict)
    }
    expected_properties = {
        "io.heyi.image.architecture": architecture,
        "io.heyi.image.config_id": config_id,
        "io.heyi.image.manifest_digest": manifest_digest,
        "io.heyi.image.os": operating_system,
        "io.heyi.image.reference": reference,
        "io.heyi.image.scan_identity": scan_identity,
        "io.heyi.release.git_sha": control.get("RELEASE_GIT_SHA"),
        "io.heyi.release.id": control.get("RELEASE_ID"),
        "io.heyi.scanner.sha256": scanner.get("sha256"),
        "io.heyi.source_manifest.sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }
    if len(properties) != len(raw_properties) or any(
        properties.get(key) != value for key, value in expected_properties.items()
    ):
        raise SystemExit(1)
if len(set(scan_identities)) != len(images):
    raise SystemExit(1)
' "$bundle_root"; then
  offline_fail registry-import \
    "image SBOM evidence does not match the signed nine-image manifest" 65
fi

# The issuer signature must cover the exact control-plane release archive, not
# only image metadata. Compare that archive with every local asset that can be
# snapshotted or executed before accepting the imported images.
expected_release_assets=$(mktemp "$OFFLINE_TMPDIR/signed-release-assets.XXXXXXXXXX")
actual_release_assets=$(mktemp "$OFFLINE_TMPDIR/bundle-release-assets.XXXXXXXXXX")
offline_contract_files | sed -n 's#^release/##p' | LC_ALL=C sort \
  > "$expected_release_assets" || exit 66
find "$bundle_root/release" -type f -printf '%P\n' | LC_ALL=C sort \
  > "$actual_release_assets" || exit 66
if ! cmp -s "$expected_release_assets" "$actual_release_assets"; then
  rm -f "$expected_release_assets" "$actual_release_assets"
  offline_fail registry-import "signed release asset inventory differs from the deployment contract" 65
fi
release_asset_mismatch=
while IFS= read -r relative_path; do
  if ! cmp -s "$bundle_root/release/$relative_path" \
    "$OFFLINE_RELEASE_ROOT/$relative_path"; then
    release_asset_mismatch=$relative_path
    break
  fi
done < "$expected_release_assets"
rm -f "$expected_release_assets" "$actual_release_assets"
if [ -n "$release_asset_mismatch" ]; then
  offline_fail registry-import \
    "local release asset differs from the issuer-signed archive: $release_asset_mismatch" 65
fi
if ! cmp -s "$operator_release" "$signed_release" || \
  ! cmp -s "$operator_manifest" "$signed_manifest"; then
  offline_fail registry-import "release environment or image manifest differs from signed bundle" 65
fi

registry_image=
registry_image_id=
release_sequence=
release_id=
release_git_sha=
release_schema_head=
registry_unpacked_bytes=
registry_unpacked_inodes=
seen_control_keys=" "
while IFS= read -r control_line || [ -n "$control_line" ]; do
  case "$control_line" in
    ""|'#'*) continue ;;
    *=*) ;;
    *) offline_fail registry-import "bundle control syntax is invalid" 65 ;;
  esac
  key=${control_line%%=*}
  value=${control_line#*=}
  case "$seen_control_keys" in
    *" $key "*) offline_fail registry-import "bundle control key is duplicated" 65 ;;
  esac
  seen_control_keys="$seen_control_keys$key "
  case "$key" in
    REGISTRY_BOOTSTRAP_IMAGE)
      case "$value" in
        heyi-bootstrap/registry:*)
          registry_tag=${value#heyi-bootstrap/registry:}
          case "$registry_tag" in
            ""|*[!A-Za-z0-9._-]*)
              offline_fail registry-import "bootstrap registry image tag is invalid" 65
              ;;
          esac
          registry_image=$value
          ;;
        *) offline_fail registry-import "bootstrap registry image tag is invalid" 65 ;;
      esac
      ;;
    REGISTRY_BOOTSTRAP_IMAGE_ID)
      if ! printf '%s\n' "$value" | grep -Eq '^sha256:[0-9a-f]{64}$'; then
        offline_fail registry-import "bootstrap registry image ID is invalid" 65
      fi
      registry_image_id=$value
      ;;
    RELEASE_SEQUENCE)
      case "$value" in
        ""|0*|*[!0-9]*) offline_fail registry-import "release sequence is invalid" 65 ;;
      esac
      if [ "${#value}" -gt 18 ]; then
        offline_fail registry-import "release sequence exceeds the signed boundary" 65
      fi
      release_sequence=$value
      ;;
    RELEASE_ID)
      case "$value" in
        ""|"."|".."|*[!A-Za-z0-9._-]*|[!A-Za-z0-9]*|*[!A-Za-z0-9])
          offline_fail registry-import "release ID is invalid" 65
          ;;
      esac
      [ "${#value}" -le 128 ] || \
        offline_fail registry-import "release ID exceeds the signed boundary" 65
      release_id=$value
      ;;
    RELEASE_GIT_SHA)
      if ! printf '%s\n' "$value" | grep -Eq '^[0-9a-f]{40}$'; then
        offline_fail registry-import "release Git SHA is invalid" 65
      fi
      release_git_sha=$value
      ;;
    RELEASE_SCHEMA_HEAD)
      if [ "$value" != 20260715_0021 ]; then
        offline_fail registry-import "release schema head is not approved by this deployer" 65
      fi
      release_schema_head=$value
      ;;
    REGISTRY_UNPACKED_BYTES)
      case "$value" in
        ""|0|*[!0-9]*) offline_fail registry-import "unpacked image bytes are invalid" 65 ;;
      esac
      [ "${#value}" -le 18 ] || \
        offline_fail registry-import "unpacked image bytes exceed the signed boundary" 65
      registry_unpacked_bytes=$value
      ;;
    REGISTRY_UNPACKED_INODES)
      case "$value" in
        ""|0|*[!0-9]*) offline_fail registry-import "unpacked image inodes are invalid" 65 ;;
      esac
      [ "${#value}" -le 18 ] || \
        offline_fail registry-import "unpacked image inodes exceed the signed boundary" 65
      registry_unpacked_inodes=$value
      ;;
    *) offline_fail registry-import "unknown bundle control key" 65 ;;
  esac
done < "$control"
if [ -z "$registry_image" ] || [ -z "$registry_image_id" ] || \
  [ -z "$release_sequence" ] || [ -z "$release_id" ] || \
  [ -z "$release_git_sha" ] || [ -z "$release_schema_head" ] || \
  [ -z "$registry_unpacked_bytes" ] || [ -z "$registry_unpacked_inodes" ]; then
  offline_fail registry-import "bootstrap registry identity is incomplete" 65
fi

release_digest=$(sha256sum "$operator_release" | awk '{print $1}') || exit 66
manifest_digest=$(sha256sum "$operator_manifest" | awk '{print $1}') || exit 66
checksums_digest=$(sha256sum "$checksums" | awk '{print $1}') || exit 66
signature_digest=$(sha256sum "$signature" | awk '{print $1}') || exit 66
release_asset_checksums=$(mktemp "$OFFLINE_TMPDIR/release-asset-checksums.XXXXXXXXXX")
if ! sed -n '/  release\//p' "$checksums" | LC_ALL=C sort \
  > "$release_asset_checksums"; then
  rm -f "$release_asset_checksums"
  offline_fail registry-import "cannot normalize signed release asset checksums" 66
fi
if [ ! -s "$release_asset_checksums" ]; then
  rm -f "$release_asset_checksums"
  offline_fail registry-import "signed release asset checksums are missing" 65
fi
release_assets_digest=$(sha256sum "$release_asset_checksums" | awk '{print $1}') || {
  rm -f "$release_asset_checksums"
  exit 66
}
rm -f "$release_asset_checksums"
expected_receipt=$import_snapshot/expected-registry-import-receipt.json
expected_highest=$import_snapshot/expected-highest-release.json
printf '%s\n' \
  "{\"schema_version\":2,\"kind\":\"offline-registry-import\",\"status\":\"verified\",\"release_sequence\":$release_sequence,\"release_id\":\"$release_id\",\"release_git_sha\":\"$release_git_sha\",\"release_schema_head\":\"$release_schema_head\",\"release_sha256\":\"$release_digest\",\"manifest_sha256\":\"$manifest_digest\",\"release_assets_sha256\":\"$release_assets_digest\",\"checksum_set_sha256\":\"$checksums_digest\",\"signature_sha256\":\"$signature_digest\",\"trusted_key_sha256\":\"$trusted_key_digest\"}" \
  > "$expected_receipt" || exit 73
printf '%s\n' \
  "{\"schema_version\":2,\"release_sequence\":$release_sequence,\"release_id\":\"$release_id\",\"release_git_sha\":\"$release_git_sha\",\"release_schema_head\":\"$release_schema_head\",\"manifest_sha256\":\"$manifest_digest\",\"release_assets_sha256\":\"$release_assets_digest\",\"trusted_key_sha256\":\"$trusted_key_digest\"}" \
  > "$expected_highest" || exit 73
chmod 0400 "$expected_receipt" "$expected_highest" || exit 73
sync -f "$expected_receipt" || exit 73
sync -f "$expected_highest" || exit 73

validate_expected_trust_documents() {
  if ! python3 -I -c '
import json
import pathlib
import re
import sys


def reject_duplicates(pairs):
    document = {}
    for name, value in pairs:
        if name in document:
            raise ValueError("duplicate JSON key")
        document[name] = value
    return document


def reject_constant(value):
    raise ValueError(f"non-finite JSON constant: {value}")


(
    receipt_path,
    highest_path,
    sequence_text,
    release_id,
    release_git_sha,
    release_schema_head,
    release_sha256,
    manifest_sha256,
    release_assets_sha256,
    checksum_set_sha256,
    signature_sha256,
    trusted_key_sha256,
) = sys.argv[1:]
if re.fullmatch(r"[1-9][0-9]{0,17}", sequence_text) is None:
    raise SystemExit(1)
if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?", release_id) is None:
    raise SystemExit(1)

load_options = {
    "object_pairs_hook": reject_duplicates,
    "parse_constant": reject_constant,
}
receipt = json.loads(pathlib.Path(receipt_path).read_text(encoding="utf-8"), **load_options)
highest = json.loads(pathlib.Path(highest_path).read_text(encoding="utf-8"), **load_options)
sequence = int(sequence_text)
expected_receipt = {
    "schema_version": 2,
    "kind": "offline-registry-import",
    "status": "verified",
    "release_sequence": sequence,
    "release_id": release_id,
    "release_git_sha": release_git_sha,
    "release_schema_head": release_schema_head,
    "release_sha256": release_sha256,
    "manifest_sha256": manifest_sha256,
    "release_assets_sha256": release_assets_sha256,
    "checksum_set_sha256": checksum_set_sha256,
    "signature_sha256": signature_sha256,
    "trusted_key_sha256": trusted_key_sha256,
}
expected_highest = {
    key: expected_receipt[key]
    for key in (
        "schema_version",
        "release_sequence",
        "release_id",
        "release_git_sha",
        "release_schema_head",
        "manifest_sha256",
        "release_assets_sha256",
        "trusted_key_sha256",
    )
}
valid = (
    isinstance(receipt, dict)
    and isinstance(highest, dict)
    and type(receipt.get("release_sequence")) is int
    and type(highest.get("release_sequence")) is int
    and receipt == expected_receipt
    and highest == expected_highest
)
if not valid:
    raise SystemExit(1)
' "$expected_receipt" "$expected_highest" "$release_sequence" "$release_id" \
    "$release_git_sha" "$release_schema_head" "$release_digest" "$manifest_digest" \
    "$release_assets_digest" "$checksums_digest" "$signature_digest" \
    "$trusted_key_digest"; then
    offline_fail registry-import \
      "deterministic release trust documents failed strict self-validation" 65
  fi
}

# Fail before any Docker or durable trust-state mutation if the generated JSON
# cannot be parsed as the exact schema and types that later readers require.
validate_expected_trust_documents

tab=$(printf '\t')
verify_registry_manifest_and_config() {
  image=$1
  expected_config_id=$2
  python3 -I - "$image" "$expected_config_id" <<'PY'
import hashlib
import http.client
import json
import re
import sys
import urllib.parse

REFERENCE = re.compile(
    r"^127\.0\.0\.1:5000/"
    r"(?P<repository>[a-z0-9][a-z0-9._/-]*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?)"
    r"@(?P<digest>sha256:[0-9a-f]{64})$"
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MANIFEST_TYPES = {
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
}
CONFIG_TYPES = {
    "application/vnd.docker.container.image.v1+json",
    "application/vnd.oci.image.config.v1+json",
}
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 16 * 1024 * 1024


def fail(message):
    raise SystemExit(f"registry-byte-verifier: {message}")


def reject_constant(value):
    fail(f"JSON contains a non-finite number: {value}")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail("JSON contains a duplicate object key")
        value[key] = item
    return value


def load_object(data, label):
    try:
        value = json.loads(
            data,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is not valid UTF-8 JSON")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def read_exact_response(connection, path, *, accept, maximum, label):
    headers = {"Accept": accept} if accept else {}
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    if response.status != 200:
        fail(f"{label} returned HTTP {response.status}")
    data = response.read(maximum + 1)
    if len(data) > maximum:
        fail(f"{label} exceeds the approved size")
    return response, data


image, expected_config = sys.argv[1:]
match = REFERENCE.fullmatch(image)
if match is None or DIGEST.fullmatch(expected_config) is None:
    fail("signed image identity is invalid")
repository_and_tag = match.group("repository")
repository = repository_and_tag.rsplit(":", 1)[0]
if any(part in {"", ".", ".."} for part in repository.split("/")):
    fail("repository path is unsafe")
manifest_digest = match.group("digest")
repository_path = urllib.parse.quote(repository, safe="/._-")
connection = http.client.HTTPConnection("127.0.0.1", 5000, timeout=10)
try:
    manifest_response, manifest_bytes = read_exact_response(
        connection,
        f"/v2/{repository_path}/manifests/{manifest_digest}",
        accept=", ".join(sorted(MANIFEST_TYPES)),
        maximum=MAX_MANIFEST_BYTES,
        label="manifest",
    )
    response_digest = manifest_response.getheader("Docker-Content-Digest")
    if response_digest != manifest_digest:
        fail("manifest response content digest differs from the signed reference")
    if f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}" != manifest_digest:
        fail("manifest bytes differ from the signed content address")
    manifest = load_object(manifest_bytes, "manifest")
    if type(manifest.get("schemaVersion")) is not int or manifest["schemaVersion"] != 2:
        fail("manifest schemaVersion must be 2")
    if manifest.get("mediaType") not in MANIFEST_TYPES:
        fail("manifest is not an approved single-image media type")
    config_descriptor = manifest.get("config")
    if not isinstance(config_descriptor, dict):
        fail("manifest config descriptor is missing")
    config_digest = config_descriptor.get("digest")
    config_size = config_descriptor.get("size")
    if (
        config_descriptor.get("mediaType") not in CONFIG_TYPES
        or config_digest != expected_config
        or type(config_size) is not int
        or not 0 < config_size <= MAX_CONFIG_BYTES
    ):
        fail("manifest config descriptor differs from the signed contract")
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        fail("manifest layer descriptor set is empty")
    for layer in layers:
        if (
            not isinstance(layer, dict)
            or DIGEST.fullmatch(str(layer.get("digest", ""))) is None
            or type(layer.get("size")) is not int
            or layer["size"] <= 0
        ):
            fail("manifest contains an invalid layer descriptor")

    config_response, config_bytes = read_exact_response(
        connection,
        f"/v2/{repository_path}/blobs/{config_digest}",
        accept="application/octet-stream",
        maximum=MAX_CONFIG_BYTES,
        label="config blob",
    )
    content_length = config_response.getheader("Content-Length")
    if content_length is not None and content_length != str(config_size):
        fail("config blob Content-Length differs from its descriptor")
    if len(config_bytes) != config_size:
        fail("config blob size differs from its descriptor")
    if f"sha256:{hashlib.sha256(config_bytes).hexdigest()}" != config_digest:
        fail("config blob bytes differ from their content address")
    config = load_object(config_bytes, "config blob")
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        fail("config blob platform must be linux/amd64")
finally:
    connection.close()
PY
}

verify_local_signed_images() {
  while IFS="$tab" read -r image expected_id expected_os expected_arch extra || \
    [ -n "${image:-}" ]; do
    if [ -z "${image:-}" ] || [ -n "${extra:-}" ] || \
      ! printf '%s\n' "$image" | grep -Eq '^127\.0\.0\.1:5000/.+@sha256:[0-9a-f]{64}$' || \
      ! printf '%s\n' "$expected_id" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
      [ "$expected_os" != linux ] || [ "$expected_arch" != amd64 ]; then
      offline_fail registry-import "signed image manifest entry is invalid" 65
    fi
    observed_id=$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null) || \
      offline_fail registry-import "previously imported image is missing" 65
    observed_config_id=$(offline_local_image_config_id registry-import "$image") || \
      offline_fail registry-import "previously imported image config is unavailable" 65
    observed_os=$(docker image inspect --format '{{.Os}}' "$image") || exit 66
    observed_arch=$(docker image inspect --format '{{.Architecture}}' "$image") || exit 66
    observed_repo_digests=$(docker image inspect \
      --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image") || exit 66
    reference_without_digest=${image%@sha256:*}
    digest=sha256:${image##*@sha256:}
    last_component=${reference_without_digest##*/}
    case "$last_component" in
      *:*) repository=${reference_without_digest%:*} ;;
      *) repository=$reference_without_digest ;;
    esac
    signed_manifest_id=sha256:${image##*@sha256:}
    if [ "$observed_config_id" != "$expected_id" ] || \
      { [ "$observed_id" != "$expected_id" ] && \
      [ "$observed_id" != "$signed_manifest_id" ]; } || \
      [ "$observed_os" != linux ] || [ "$observed_arch" != amd64 ] || \
      ! printf '%s\n' "$observed_repo_digests" | grep -Fqx "$repository@$digest"; then
      offline_fail registry-import \
        "previously imported image identity, platform or RepoDigest differs" 65
    fi
  done < "$signed_manifest"
}

trust_state_directory=/srv/heyi-knowledgebases-offline/state
for protected_directory in /srv /srv/heyi-knowledgebases-offline; do
  if [ -L "$protected_directory" ]; then
    offline_fail registry-import "trust state path must not contain symbolic links" 65
  fi
  if [ -e "$protected_directory" ]; then
    protected_owner=$(stat -c %u -- "$protected_directory") || exit 66
    protected_mode=$(stat -c %a -- "$protected_directory") || exit 66
    protected_mode_value=$((0$protected_mode))
    if [ "$protected_owner" -ne 0 ] || [ $((protected_mode_value & 022)) -ne 0 ]; then
      offline_fail registry-import "trust state path is writable by non-root" 65
    fi
  fi
done
install -d -o root -g root -m 0750 /srv/heyi-knowledgebases-offline
install -d -o root -g root -m 0700 "$trust_state_directory"
validate_protected_path trust-state-directory \
  "$trust_state_directory" directory "700"
highest_release_file=$trust_state_directory/highest-release.json
highest_release_sequence=0
if [ -e "$highest_release_file" ]; then
  validate_protected_path highest-release-state "$highest_release_file" file "400"
  if [ "$(stat -c %h -- "$highest_release_file")" -ne 1 ]; then
    offline_fail registry-import "highest release state must have one link" 65
  fi
  highest_release_sequence=$(python3 -I -c '
import json, pathlib, re, sys

def reject_duplicates(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result

document = json.loads(
    pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"),
    object_pairs_hook=reject_duplicates,
)
target_schema_head = sys.argv[2]
trusted_key_sha256 = sys.argv[3]
required = {
    "schema_version", "release_sequence", "release_id", "release_git_sha",
    "release_schema_head", "manifest_sha256", "release_assets_sha256",
    "trusted_key_sha256",
}
schema_head = document.get("release_schema_head")
schema_match = re.fullmatch(r"([0-9]{8})_([0-9]{4})", schema_head) if isinstance(schema_head, str) else None
target_match = re.fullmatch(r"([0-9]{8})_([0-9]{4})", target_schema_head)
valid = (
    set(document) == required
    and document["schema_version"] == 2
    and type(document["release_sequence"]) is int
    and 0 < document["release_sequence"] <= 999_999_999_999_999_999
    and isinstance(document["release_id"], str)
    and re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?",
        document["release_id"],
    )
    and isinstance(document["release_git_sha"], str)
    and re.fullmatch(r"[0-9a-f]{40}", document["release_git_sha"])
    and schema_match is not None
    and target_match is not None
    and tuple(map(int, schema_match.groups())) <= tuple(map(int, target_match.groups()))
    and all(re.fullmatch(r"[0-9a-f]{64}", document[key]) for key in ("manifest_sha256", "release_assets_sha256"))
    and re.fullmatch(r"[0-9a-f]{64}", trusted_key_sha256) is not None
    and document["trusted_key_sha256"] == trusted_key_sha256
)
if not valid:
    raise SystemExit(1)
print(document["release_sequence"])
' "$highest_release_file" "$release_schema_head" "$trusted_key_digest") || \
    offline_fail registry-import \
      "highest release state is invalid or predates the trusted-key binding; re-import is required" 65
fi
if [ "$release_sequence" -lt "$highest_release_sequence" ]; then
  offline_fail registry-import "signed release sequence is replayed or downgraded" 65
fi
if [ "$release_sequence" -eq "$highest_release_sequence" ]; then
  receipt_file=$trust_state_directory/registry-import-$manifest_digest.json
  if [ ! -e "$receipt_file" ]; then
    offline_fail registry-import \
      "highest release state exists without its exact import receipt" 65
  fi
  validate_protected_path registry-import-receipt "$receipt_file" file "400"
  if [ "$(stat -c %h -- "$receipt_file")" -ne 1 ] || \
    ! cmp -s "$highest_release_file" "$expected_highest" || \
    ! cmp -s "$receipt_file" "$expected_receipt"; then
    offline_fail registry-import \
      "same-sequence release conflicts with the committed issuer state" 65
  fi
  validate_protected_path trusted-public-key \
    "$canonical_trusted_public_key" file "400 444"
  canonical_trusted_key_digest_noop=$(sha256sum \
    "$canonical_trusted_public_key" | awk '{print $1}') || exit 66
  if [ "$canonical_trusted_key_digest_noop" != "$trusted_key_digest" ]; then
    offline_fail registry-import \
      "canonical trusted release public key changed before no-op validation" 65
  fi
  verify_local_signed_images
  echo "registry-import: AUDITED_NOOP exact signed release is already imported; receipt=$receipt_file"
  exit 0
fi

# Registry import happens before the deployment preflight, so it must protect
# DockerRootDir itself.  Otherwise a valid but large signed bundle can exhaust
# a shared host before the normal 8C/16G/300G gate is reached.
docker_root=$(docker info --format '{{.DockerRootDir}}') || \
  offline_fail registry-import "cannot inspect DockerRootDir" 69
case "$docker_root" in
  /*) ;;
  *) offline_fail registry-import "DockerRootDir must be an absolute path" 69 ;;
esac
canonical_docker_root=$(realpath -e -- "$docker_root" 2>/dev/null || true)
if [ "$canonical_docker_root" != "$docker_root" ] || [ ! -d "$docker_root" ] || \
  [ -L "$docker_root" ]; then
  offline_fail registry-import "DockerRootDir must be a canonical non-symbolic directory" 69
fi
docker_root_owner=$(stat -c %u -- "$docker_root") || \
  offline_fail registry-import "cannot inspect DockerRootDir owner" 69
docker_root_mode=$(stat -c %a -- "$docker_root") || \
  offline_fail registry-import "cannot inspect DockerRootDir permissions" 69
docker_root_mode_value=$((0$docker_root_mode))
if [ "$docker_root_owner" -ne 0 ] || [ $((docker_root_mode_value & 022)) -ne 0 ]; then
  offline_fail registry-import \
    "DockerRootDir must be root owned and non-writable by other users" 69
fi
docker_available_kib=$(df -Pk "$docker_root" | awk \
  'NR == 2 { available=$4 } END { if (NR != 2) exit 1; print available }') || \
  offline_fail registry-import "cannot inspect DockerRootDir free space" 69
for capacity_value in "$docker_available_kib" "$registry_unpacked_bytes" \
  "$registry_unpacked_inodes"; do
  case "$capacity_value" in
    ""|*[!0-9]*) offline_fail registry-import "Docker storage capacity is invalid" 69 ;;
  esac
done
unpacked_image_kib=$(((registry_unpacked_bytes + 1023) / 1024))
required_docker_kib=$((unpacked_image_kib + 41943040))
if [ "$docker_available_kib" -lt "$required_docker_kib" ]; then
  offline_fail registry-import \
    "DockerRootDir lacks signed unpacked-image capacity plus the 40 GiB rollback reserve" 69
fi
docker_inode_fields=$(df -Pi "$docker_root" | awk \
  'NR == 2 { total=$2; available=$4 } END { if (NR != 2) exit 1; print total, available }') || \
  offline_fail registry-import "cannot inspect DockerRootDir inode capacity" 69
# awk emits exactly two numeric fields; cardinality and type are checked next.
# shellcheck disable=SC2086
set -- $docker_inode_fields
[ "$#" -eq 2 ] || offline_fail registry-import "DockerRootDir inode evidence is malformed" 69
docker_total_inodes=$1
docker_available_inodes=$2
for inode_value in "$docker_total_inodes" "$docker_available_inodes"; do
  case "$inode_value" in
    ""|*[!0-9]*) offline_fail registry-import "DockerRootDir inode capacity is invalid" 69 ;;
  esac
done
rollback_inode_reserve=$((docker_total_inodes / 10))
if [ "$rollback_inode_reserve" -lt 100000 ]; then
  rollback_inode_reserve=100000
fi
required_docker_inodes=$((registry_unpacked_inodes + rollback_inode_reserve))
if [ "$docker_available_inodes" -lt "$required_docker_inodes" ]; then
  offline_fail registry-import \
    "DockerRootDir lacks signed unpacked-image inodes plus the rollback reserve" 69
fi

observed_registry_config_id=$(offline_local_image_config_id \
  registry-import "$registry_image") || \
  offline_fail registry-import "bootstrap registry config identity is unavailable" 65
observed_registry_id=$(docker image inspect --format '{{.Id}}' "$registry_image" 2>/dev/null) || \
  offline_fail registry-import "bootstrap registry image is not loaded" 66
observed_registry_os=$(docker image inspect --format '{{.Os}}' "$registry_image") || exit 66
observed_registry_arch=$(docker image inspect --format '{{.Architecture}}' "$registry_image") || \
  exit 66
if ! printf '%s\n' "$observed_registry_id" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
  [ "$observed_registry_config_id" != "$registry_image_id" ] || \
  [ "$observed_registry_os" != linux ] || [ "$observed_registry_arch" != amd64 ]; then
  offline_fail registry-import "bootstrap registry image identity or platform differs" 65
fi

command -v ss >/dev/null 2>&1 || offline_fail registry-import "ss is required" 69
registry_port_evidence=$(mktemp "$OFFLINE_TMPDIR/registry-port.XXXXXXXXXX")
if ! ss -H -ltn "sport = :5000" > "$registry_port_evidence"; then
  rm -f "$registry_port_evidence"
  offline_fail registry-import "cannot inspect loopback registry port 5000" 69
fi
if [ -s "$registry_port_evidence" ]; then
  rm -f "$registry_port_evidence"
  offline_fail registry-import "loopback registry port 5000 is already occupied" 69
fi
rm -f "$registry_port_evidence"

container_name=heyi-kb-offline-registry-import-${registry_image_id#sha256:}
container_name=$(printf '%.60s' "$container_name")
if docker container inspect "$container_name" >/dev/null 2>&1; then
  offline_fail registry-import "a prior registry import container requires manual review" 69
fi
network_name=heyi-kb-offline-registry-import
if docker network inspect "$network_name" >/dev/null 2>&1; then
  offline_fail registry-import "a prior registry import network requires manual review" 69
fi

registry_container_id=
registry_network_id=
cleanup_registry() {
  cleanup_failed=false
  if [ -n "$registry_container_id" ]; then
    observed_owner=$(docker inspect --format \
      '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' \
      "$registry_container_id" 2>/dev/null || true)
    observed_purpose=$(docker inspect --format \
      '{{ index .Config.Labels "io.heyi.knowledgebases.purpose" }}' \
      "$registry_container_id" 2>/dev/null || true)
    if [ "$observed_owner" != jiangsu-heyi-knowledgebases ] || \
      [ "$observed_purpose" != offline-registry-import ]; then
      echo "registry-import: CLEANUP_FAILED exact container labels changed" >&2
      cleanup_failed=true
    elif ! docker rm -f "$registry_container_id" >/dev/null; then
      echo "registry-import: CLEANUP_FAILED exact container could not be removed" >&2
      cleanup_failed=true
    else
      # Clear the identity only after the exact owned resource is gone.  This
      # makes the EXIT handler idempotent while still allowing it to retry a
      # partially failed cleanup.
      registry_container_id=
    fi
  fi
  if [ -n "$registry_network_id" ]; then
    observed_network_name=$(docker network inspect --format '{{.Name}}' \
      "$registry_network_id" 2>/dev/null || true)
    observed_network_owner=$(docker network inspect --format \
      '{{ index .Labels "io.heyi.knowledgebases.owner" }}' \
      "$registry_network_id" 2>/dev/null || true)
    observed_network_purpose=$(docker network inspect --format \
      '{{ index .Labels "io.heyi.knowledgebases.purpose" }}' \
      "$registry_network_id" 2>/dev/null || true)
    observed_network_internal=$(docker network inspect --format '{{.Internal}}' \
      "$registry_network_id" 2>/dev/null || true)
    observed_network_ipv6=$(docker network inspect --format '{{.EnableIPv6}}' \
      "$registry_network_id" 2>/dev/null || true)
    observed_network_masquerade=$(docker network inspect --format \
      '{{ index .Options "com.docker.network.bridge.enable_ip_masquerade" }}' \
      "$registry_network_id" 2>/dev/null || true)
    observed_network_icc=$(docker network inspect --format \
      '{{ index .Options "com.docker.network.bridge.enable_icc" }}' \
      "$registry_network_id" 2>/dev/null || true)
    if [ "$observed_network_name" != "$network_name" ] || \
      [ "$observed_network_owner" != jiangsu-heyi-knowledgebases ] || \
      [ "$observed_network_purpose" != offline-registry-import ] || \
      [ "$observed_network_internal" != false ] || \
      [ "$observed_network_ipv6" != false ] || \
      [ "$observed_network_masquerade" != false ] || \
      [ "$observed_network_icc" != false ]; then
      echo "registry-import: CLEANUP_FAILED exact isolated network identity changed" >&2
      cleanup_failed=true
    elif ! docker network rm "$registry_network_id" >/dev/null; then
      echo "registry-import: CLEANUP_FAILED exact isolated network could not be removed" >&2
      cleanup_failed=true
    else
      registry_network_id=
    fi
  fi
  [ "$cleanup_failed" = false ]
}
handle_exit() {
  original_code=$1
  trap - EXIT HUP INT TERM
  if ! cleanup_registry; then
    cleanup_import_snapshot
    exit 71
  fi
  cleanup_import_snapshot
  exit "$original_code"
}
trap 'handle_exit $?' EXIT
trap 'exit 130' HUP INT TERM

registry_network_id=$(docker network create --driver bridge --ipv6=false \
  --opt com.docker.network.bridge.enable_ip_masquerade=false \
  --opt com.docker.network.bridge.enable_icc=false \
  --label io.heyi.knowledgebases.owner=jiangsu-heyi-knowledgebases \
  --label io.heyi.knowledgebases.purpose=offline-registry-import \
  "$network_name")
if ! printf '%s\n' "$registry_network_id" | grep -Eq '^[0-9a-f]{64}$'; then
  offline_fail registry-import "registry isolated network ID is invalid" 69
fi
if [ "$(docker network inspect --format '{{.Internal}}' "$registry_network_id")" != false ] || \
  [ "$(docker network inspect --format '{{.EnableIPv6}}' \
    "$registry_network_id")" != false ] || \
  [ "$(docker network inspect --format \
    '{{ index .Options "com.docker.network.bridge.enable_ip_masquerade" }}' \
    "$registry_network_id")" != false ] || \
  [ "$(docker network inspect --format \
    '{{ index .Options "com.docker.network.bridge.enable_icc" }}' \
    "$registry_network_id")" != false ]; then
  offline_fail registry-import "registry import network isolation options are invalid" 69
fi

registry_startup_command='while [ ! -f /tmp/heyi-network-ready ]; do sleep 0.1; done; exec /entrypoint.sh /etc/docker/registry/config.yml'
registry_container_id=$(docker run -d --pull never \
  --name "$container_name" \
  --label io.heyi.knowledgebases.owner=jiangsu-heyi-knowledgebases \
  --label io.heyi.knowledgebases.purpose=offline-registry-import \
  --network "$registry_network_id" \
  --dns 127.0.0.1 --dns-search . \
  --dns-opt timeout:1 --dns-opt attempts:1 \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  --sysctl net.ipv6.conf.default.disable_ipv6=1 \
  --publish 127.0.0.1:5000:5000 \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=32m,mode=1777 \
  --memory 256m --cpus 0.50 --pids-limit 128 \
  --volume "$registry_data:/var/lib/registry:ro" \
  --entrypoint /bin/sh \
  "$observed_registry_id" -ceu "$registry_startup_command")
if ! printf '%s\n' "$registry_container_id" | grep -Eq '^[0-9a-f]{64}$'; then
  offline_fail registry-import "registry container ID is invalid" 69
fi

registry_dns=$(docker inspect --format '{{json .HostConfig.Dns}}' \
  "$registry_container_id") || \
  offline_fail registry-import "cannot inspect the temporary Registry DNS policy" 69
registry_dns_search=$(docker inspect --format '{{json .HostConfig.DnsSearch}}' \
  "$registry_container_id") || \
  offline_fail registry-import "cannot inspect the temporary Registry DNS search policy" 69
registry_dns_options=$(docker inspect --format '{{json .HostConfig.DnsOptions}}' \
  "$registry_container_id") || \
  offline_fail registry-import "cannot inspect the temporary Registry DNS options" 69
registry_ipv6_all=$(docker inspect --format \
  '{{ index .HostConfig.Sysctls "net.ipv6.conf.all.disable_ipv6" }}' \
  "$registry_container_id") || \
  offline_fail registry-import "cannot inspect the temporary Registry IPv6 policy" 69
registry_ipv6_default=$(docker inspect --format \
  '{{ index .HostConfig.Sysctls "net.ipv6.conf.default.disable_ipv6" }}' \
  "$registry_container_id") || \
  offline_fail registry-import "cannot inspect the temporary Registry IPv6 policy" 69
if [ "$registry_dns" != '["127.0.0.1"]' ] || \
  [ "$registry_dns_search" != '["."]' ] || \
  [ "$registry_dns_options" != '["timeout:1","attempts:1"]' ] || \
  [ "$registry_ipv6_all" != 1 ] || [ "$registry_ipv6_default" != 1 ]; then
  offline_fail registry-import \
    "temporary Registry DNS or IPv6 isolation differs from the sealed policy" 69
fi

network_seal_command='/sbin/ip route del default; /sbin/ip route add blackhole 127.0.0.11/32 table local'
if ! docker run --rm --pull never \
  --label io.heyi.knowledgebases.owner=jiangsu-heyi-knowledgebases \
  --label io.heyi.knowledgebases.purpose=offline-registry-import-route-seal \
  --network "container:$registry_container_id" \
  --cap-drop ALL --cap-add NET_ADMIN \
  --security-opt no-new-privileges:true \
  --entrypoint /bin/sh \
  "$observed_registry_id" -ceu "$network_seal_command" >/dev/null; then
  offline_fail registry-import "cannot seal the temporary Registry network namespace" 69
fi
sealed_routes=$(docker exec "$registry_container_id" /sbin/ip route show) || \
  offline_fail registry-import "cannot inspect the sealed Registry routes" 69
sealed_route_count=$(printf '%s\n' "$sealed_routes" | sed '/^$/d' | wc -l | tr -d ' ')
if [ "$sealed_route_count" != 1 ] || \
  ! printf '%s\n' "$sealed_routes" | \
    grep -Eq '^[0-9.]+/[0-9]+ dev eth0 scope link( |$)' || \
  printf '%s\n' "$sealed_routes" | grep -Eq '(^default | via )'; then
  offline_fail registry-import "temporary Registry retained a non-local network route" 69
fi
sealed_local_routes=$(docker exec \
  "$registry_container_id" /sbin/ip route show table local) || \
  offline_fail registry-import "cannot inspect the sealed Registry local routes" 69
if ! printf '%s\n' "$sealed_local_routes" | \
  grep -Eq '^blackhole 127\.0\.0\.11( |$)' || \
  docker exec "$registry_container_id" \
    /sbin/ip route get 127.0.0.11 >/dev/null 2>&1; then
  offline_fail registry-import \
    "Docker embedded DNS remained reachable after the network seal" 69
fi
sealed_ipv6_all=$(docker exec "$registry_container_id" \
  /bin/cat /proc/sys/net/ipv6/conf/all/disable_ipv6) || \
  offline_fail registry-import "cannot inspect the sealed Registry IPv6 state" 69
sealed_ipv6_default=$(docker exec "$registry_container_id" \
  /bin/cat /proc/sys/net/ipv6/conf/default/disable_ipv6) || \
  offline_fail registry-import "cannot inspect the sealed Registry IPv6 state" 69
sealed_ipv6_addresses=$(docker exec \
  "$registry_container_id" /sbin/ip -6 address show) || \
  offline_fail registry-import "cannot inspect the sealed Registry IPv6 addresses" 69
sealed_ipv6_routes=$(docker exec \
  "$registry_container_id" /sbin/ip -6 route show table all) || \
  offline_fail registry-import "cannot inspect the sealed Registry IPv6 routes" 69
if [ "$sealed_ipv6_all" != 1 ] || [ "$sealed_ipv6_default" != 1 ] || \
  [ -n "$(printf '%s\n' "$sealed_ipv6_addresses" | sed '/^$/d')" ] || \
  [ -n "$(printf '%s\n' "$sealed_ipv6_routes" | sed '/^$/d')" ]; then
  offline_fail registry-import \
    "temporary Registry retained an IPv6 address or route" 69
fi
if ! docker exec "$registry_container_id" /bin/sh -ceu \
  ': > /tmp/heyi-network-ready'; then
  offline_fail registry-import "cannot open the sealed Registry startup gate" 69
fi

ready=false
for _attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if python3 -I -c \
    'import urllib.request; urllib.request.urlopen("http://127.0.0.1:5000/v2/", timeout=2)' \
    >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
[ "$ready" = true ] || offline_fail registry-import "loopback registry did not become ready" 70

while IFS="$tab" read -r image expected_id expected_os expected_arch extra || \
  [ -n "${image:-}" ]; do
  if [ -z "${image:-}" ] || [ -n "${extra:-}" ] || \
    ! printf '%s\n' "$image" | grep -Eq '^127\.0\.0\.1:5000/.+@sha256:[0-9a-f]{64}$' || \
    ! printf '%s\n' "$expected_id" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
    [ "$expected_os" != linux ] || [ "$expected_arch" != amd64 ]; then
    offline_fail registry-import "signed image manifest entry is invalid" 65
  fi
  if ! verify_registry_manifest_and_config "$image" "$expected_id"; then
    offline_fail registry-import \
      "Registry manifest/config bytes differ from the signed image contract" 65
  fi
  docker pull --platform linux/amd64 "$image" >/dev/null
  observed_id=$(docker image inspect --format '{{.Id}}' "$image") || exit 66
  observed_config_id=$(offline_local_image_config_id registry-import "$image") || \
    offline_fail registry-import "imported image config is unavailable" 65
  observed_os=$(docker image inspect --format '{{.Os}}' "$image") || exit 66
  observed_arch=$(docker image inspect --format '{{.Architecture}}' "$image") || exit 66
  observed_repo_digests=$(docker image inspect \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image") || exit 66
  reference_without_digest=${image%@sha256:*}
  digest=sha256:${image##*@sha256:}
  last_component=${reference_without_digest##*/}
  case "$last_component" in
    *:*) repository=${reference_without_digest%:*} ;;
    *) repository=$reference_without_digest ;;
  esac
  signed_manifest_id=sha256:${image##*@sha256:}
  if [ "$observed_config_id" != "$expected_id" ] || \
    { [ "$observed_id" != "$expected_id" ] && \
    [ "$observed_id" != "$signed_manifest_id" ]; } || \
    [ "$observed_os" != linux ] || [ "$observed_arch" != amd64 ] || \
    ! printf '%s\n' "$observed_repo_digests" | grep -Fqx "$repository@$digest"; then
    offline_fail registry-import "imported image identity, platform or RepoDigest differs" 65
  fi
done < "$signed_manifest"

# A verified receipt is a deployment authorization artifact, not merely an
# image-pull log.  Do not publish it while the temporary listener or network
# still exists: cleanup failure must leave the release unauthorized and
# safely retryable.
if ! cleanup_registry; then
  offline_fail registry-import \
    "temporary registry resources could not be removed before receipt commit" 71
fi
validate_protected_path trusted-public-key \
  "$canonical_trusted_public_key" file "400 444"
canonical_trusted_key_digest_after=$(sha256sum \
  "$canonical_trusted_public_key" | awk '{print $1}') || exit 66
if [ "$canonical_trusted_key_digest_after" != "$trusted_key_digest" ]; then
  offline_fail registry-import \
    "canonical trusted release public key changed during import" 65
fi

# Persist a root-only, deterministic receipt that binds the verified signature
# ceremony to the exact release and image manifest consumed by deployment.
receipt_directory=/srv/heyi-knowledgebases-offline/state
for protected_directory in /srv /srv/heyi-knowledgebases-offline; do
  if [ -L "$protected_directory" ]; then
    offline_fail registry-import "receipt path must not contain symbolic links" 65
  fi
  if [ -e "$protected_directory" ]; then
    protected_owner=$(stat -c %u -- "$protected_directory") || exit 66
    protected_mode=$(stat -c %a -- "$protected_directory") || exit 66
    protected_mode_value=$((0$protected_mode))
    if [ "$protected_owner" -ne 0 ] || [ $((protected_mode_value & 022)) -ne 0 ]; then
      offline_fail registry-import "receipt path is writable by non-root" 65
    fi
  fi
done
install -d -o root -g root -m 0750 /srv/heyi-knowledgebases-offline
install -d -o root -g root -m 0700 "$receipt_directory"
validate_protected_path registry-import-receipt-directory \
  "$receipt_directory" directory "700"

receipt_file=$receipt_directory/registry-import-$manifest_digest.json
temporary_receipt=$(mktemp "$receipt_directory/.registry-import.XXXXXXXXXX")
install -o root -g root -m 0400 "$expected_receipt" "$temporary_receipt" || exit 73
sync -f "$temporary_receipt" || exit 73
if [ -e "$receipt_file" ]; then
  validate_protected_path registry-import-receipt "$receipt_file" file "400"
  if [ "$(stat -c %h -- "$receipt_file")" -ne 1 ] || \
    ! cmp -s "$receipt_file" "$temporary_receipt"; then
    rm -f "$temporary_receipt"
    offline_fail registry-import "existing import receipt conflicts with this signature" 65
  fi
  rm -f "$temporary_receipt"
else
  mv -- "$temporary_receipt" "$receipt_file" || exit 73
fi
sync -f "$receipt_file" || exit 73
sync -f "$receipt_directory" || exit 73

temporary_highest=$(mktemp "$trust_state_directory/.highest-release.XXXXXXXXXX")
install -o root -g root -m 0400 "$expected_highest" "$temporary_highest" || exit 73
sync -f "$temporary_highest" || exit 73
mv -f -- "$temporary_highest" "$highest_release_file" || exit 73
sync -f "$highest_release_file" || exit 73
sync -f "$receipt_directory" || exit 73

echo "registry-import: signed loopback registry bundle imported and verified; receipt=$receipt_file"
