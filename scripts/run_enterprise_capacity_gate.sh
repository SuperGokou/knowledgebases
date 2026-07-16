#!/usr/bin/env bash
# Formal 8C/16G/300GB gate. Destructive only to its exact acceptance project/data child.
set -eu
umask 077

fail() { printf '%s\n' "capacity gate: $*" >&2; exit 2; }
require_env() {
  variable_name=$1
  eval "variable_value=\${$variable_name-}"
  [ -n "$variable_value" ] || fail "$variable_name is required"
}

for variable_name in \
  KB_LOAD_RUN_ID KB_LOAD_ACCEPTANCE_PROJECT KB_LOAD_COMPOSE_FILE \
  KB_LOAD_COMPOSE_ENV_FILE KB_LOAD_ACCEPTANCE_ROOT KB_LOAD_ACCEPTANCE_DATA_ROOT \
  KB_LOAD_OUTPUT_ROOT KB_LOAD_GIT_COMMIT KB_LOAD_BASE_URL \
  KB_LOAD_KNOWLEDGE_BASE_ID KB_LOAD_USERS_FILE KB_LOAD_QUOTA_FILE KB_LOAD_CA_CERT
do
  require_env "$variable_name"
done

[ "$(uname -s)" = Linux ] || fail "formal execution requires Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "formal execution requires amd64" ;; esac
for executable in docker k6 python3 realpath sha256sum stat; do
  command -v "$executable" >/dev/null 2>&1 || fail "$executable is required"
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd -P)
run_id=$KB_LOAD_RUN_ID
project=$KB_LOAD_ACCEPTANCE_PROJECT
expected_project="heyi-kb-acceptance-$run_id"
[ "$project" = "$expected_project" ] || fail "project must equal $expected_project"
[ "$project" != heyi-kb-offline ] || fail "delivery/production project is forbidden"

compose_file=$(realpath -- "$KB_LOAD_COMPOSE_FILE")
env_file=$(realpath -- "$KB_LOAD_COMPOSE_ENV_FILE")
acceptance_root=$(realpath -- "$KB_LOAD_ACCEPTANCE_ROOT")
data_root=$(realpath -- "$KB_LOAD_ACCEPTANCE_DATA_ROOT")
output_parent=$(realpath -- "$KB_LOAD_OUTPUT_ROOT")
users_file=$(realpath -- "$KB_LOAD_USERS_FILE")
quota_file=$(realpath -- "$KB_LOAD_QUOTA_FILE")
ca_cert=$(realpath -- "$KB_LOAD_CA_CERT")
[ "$(dirname -- "$data_root")" = "$acceptance_root" ] || fail "data root must be a direct child of acceptance root"
[ "$(basename -- "$data_root")" = "$run_id" ] || fail "data root basename must equal run id"
case "$output_parent/" in "$data_root/"*) fail "evidence output cannot be disposable" ;; esac
probe_root="$data_root/capacity-probe"
case "$users_file" in "$probe_root"/*) ;; *) fail "users fixture must be disposable" ;; esac
case "$quota_file" in "$probe_root"/*) ;; *) fail "quota fixture must be disposable" ;; esac
[ "$(stat -c '%a' "$users_file")" -le 600 ] || fail "users fixture must be 0600 or stricter"
[ "$(stat -c '%a' "$quota_file")" -le 600 ] || fail "quota fixture must be 0600 or stricter"
[ -r "$ca_cert" ] || fail "trusted CA certificate is unreadable"

other_projects=$(docker ps \
  --filter label=io.heyi.knowledgebases.owner=jiangsu-heyi-knowledgebases \
  --format '{{.Label "com.docker.compose.project"}}' | sort -u | grep -v "^${project}$" || true)
[ -z "$other_projects" ] || fail "another knowledge-base project is running"

duration_seconds=${KB_LOAD_RESOURCE_DURATION_SECONDS:-1800}
interval_seconds=${KB_LOAD_RESOURCE_INTERVAL_SECONDS:-5}
output_dir="$output_parent/$run_id"
[ ! -e "$output_dir" ] || fail "refusing to overwrite evidence"
mkdir -m 700 -- "$output_dir"
manifest="$output_dir/capacity-manifest.json"
resources="$output_dir/capacity-resources.jsonl"
cleanup_evidence="$output_dir/capacity-cleanup.json"
report="$output_dir/capacity-gate-report.json"
marker="$data_root/.capacity-acceptance-owned.json"
[ -f "$marker" ] || fail "acceptance ownership marker is missing"

python3 "$script_dir/capacity_evidence_manifest.py" create \
  --run-id "$run_id" --project "$project" --compose-file "$compose_file" \
  --env-file "$env_file" --acceptance-root "$acceptance_root" \
  --data-root "$data_root" --duration-seconds "$duration_seconds" \
  --interval-seconds "$interval_seconds" --git-commit "$KB_LOAD_GIT_COMMIT" \
  --output "$manifest"
manifest_sha256=$(sha256sum "$manifest" | awk '{print $1}')

compose() {
  docker compose --project-name "$project" --file "$compose_file" --env-file "$env_file" "$@"
}

sampler_pid=
cleaned=0
cleanup_run() {
  [ "$cleaned" -eq 0 ] || return 0
  cleaned=1
  set +e
  if [ -n "$sampler_pid" ]; then
    kill "$sampler_pid" >/dev/null 2>&1 || true
    wait "$sampler_pid" >/dev/null 2>&1 || true
  fi
  compose down --remove-orphans --volumes --timeout 120 >/dev/null 2>&1
  compose_status=$?
  current_marker_sha=
  [ -f "$marker" ] && current_marker_sha=$(sha256sum "$marker" | awk '{print $1}')
  expected_marker_sha=$(python3 - "$manifest" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["acceptance"]["ownership_marker_sha256"])
PY
)
  if [ "$compose_status" -eq 0 ] && [ "$current_marker_sha" = "$expected_marker_sha" ]; then
    rm -rf --one-file-system -- "$data_root"
  fi
  python3 "$script_dir/capacity_evidence_manifest.py" verify-cleanup \
    --manifest "$manifest" --output "$cleanup_evidence"
  cleanup_status=$?
  set -e
  return "$cleanup_status"
}
trap 'cleanup_run || true' EXIT HUP INT TERM

python3 "$script_dir/capacity_resource_sampler.py" \
  --project "$project" --manifest "$manifest" --compose-file "$compose_file" \
  --env-file "$env_file" --data-path "$data_root" --output "$resources" \
  --duration-seconds "$duration_seconds" --interval-seconds "$interval_seconds" &
sampler_pid=$!

set +e
(
  cd -- "$output_dir"
  SSL_CERT_FILE="$ca_cert" \
  KB_LOAD_PROFILE=formal KB_LOAD_ISOLATED_ACCEPTANCE=1 \
  KB_LOAD_ACCEPTANCE_PROJECT="$project" KB_LOAD_MANIFEST_FILE="$manifest" \
  KB_LOAD_MANIFEST_SHA256="$manifest_sha256" KB_LOAD_BASE_URL="$KB_LOAD_BASE_URL" \
  KB_LOAD_KNOWLEDGE_BASE_ID="$KB_LOAD_KNOWLEDGE_BASE_ID" \
  KB_LOAD_USERS_FILE="$users_file" KB_LOAD_QUOTA_FILE="$quota_file" \
  KB_LOAD_REQUIRE_QUOTA_CONTRACTS=1 KB_LOAD_ENABLE_MULTIPART=1 \
  KB_LOAD_CHAT_MODE="${KB_LOAD_CHAT_MODE:-stub}" \
  KB_LOAD_STEADY_DURATION="${duration_seconds}s" KB_LOAD_STEADY_START=0s \
  k6 run "$repo_root/scripts/load/enterprise_capacity.js"
)
k6_status=$?
if [ "$k6_status" -ne 0 ] && kill -0 "$sampler_pid" >/dev/null 2>&1; then
  kill "$sampler_pid" >/dev/null 2>&1 || true
fi
wait "$sampler_pid"
sampler_status=$?
sampler_pid=
set -e

# Scan while the disposable fixture still exists; the fixture is deleted immediately below.
set +e
python3 - "$users_file" "$quota_file" "$output_dir" <<'PY'
import json, pathlib, sys
secrets = set()
for fixture_name in sys.argv[1:3]:
    stack = [json.loads(pathlib.Path(fixture_name).read_text(encoding="utf-8"))]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if key in {"email", "password"} and isinstance(child, str) and child:
                    secrets.add(child)
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
for artifact in pathlib.Path(sys.argv[3]).rglob("*"):
    if artifact.is_file():
        text = artifact.read_text(encoding="utf-8", errors="replace")
        if any(secret in text for secret in secrets):
            raise SystemExit(f"credential leaked into artifact: {artifact.name}")
PY
leak_status=$?
set -e

cleanup_status=0
cleanup_run || cleanup_status=$?
gate_status=2
if [ -f "$output_dir/capacity-k6-summary.json" ] && [ -f "$resources" ] && [ -f "$cleanup_evidence" ]; then
  set +e
  python3 "$script_dir/enterprise_capacity_gate.py" evaluate \
    --summary "$output_dir/capacity-k6-summary.json" --resources "$resources" \
    --manifest "$manifest" --cleanup "$cleanup_evidence" \
    --require-llm-stub --require-quota-contracts --require-multipart --output "$report"
  gate_status=$?
  set -e
fi

trap - EXIT HUP INT TERM
if [ "$k6_status" -ne 0 ] || [ "$sampler_status" -ne 0 ] || \
   [ "$cleanup_status" -ne 0 ] || [ "$gate_status" -ne 0 ] || [ "$leak_status" -ne 0 ]; then
  fail "failed (k6=$k6_status sampler=$sampler_status cleanup=$cleanup_status gate=$gate_status leak=$leak_status)"
fi
printf '%s\n' "capacity gate passed: $report"
