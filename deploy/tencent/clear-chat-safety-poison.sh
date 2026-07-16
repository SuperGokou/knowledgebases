#!/usr/bin/env sh
set -eu

if [ "$#" -ne 4 ] || [ "$1" != --expected-sha256 ] || [ "$3" != --evidence ]; then
  echo "usage: $0 --expected-sha256 SHA256 --evidence /protected/reconciliation.json" >&2
  exit 64
fi
expected_digest=$2
evidence_file=$4
printf '%s\n' "$expected_digest" | grep -Eq '^[0-9a-f]{64}$' || exit 64
case "$evidence_file" in /*) ;; *) exit 64 ;; esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"
offline_require_root chat-safety-clear
offline_acquire_lock chat-safety-clear
offline_clear_inherited_environment
[ "$evidence_file" = "$OFFLINE_STATE_DIRECTORY/chat-safety-reconciliation.json" ] || \
  offline_fail chat-safety-clear "evidence must use the fixed protected state path" 65
offline_validate_root_directory \
  chat-safety-clear "$OFFLINE_STATE_DIRECTORY" 700

state_helper=$script_dir/offline-recovery-state.py
selection_json=$(python3 -I "$state_helper" select) || \
  offline_fail chat-safety-clear "cannot read the durable active release" 65
selection_fields=$(printf '%s\n' "$selection_json" | python3 -I -c '
import json,re,sys
d=json.load(sys.stdin)
selection=d.get("selection")
digest=d.get("contract_sha256")
transaction=d.get("transaction_id")
operation=d.get("operation","none")
if selection not in {"intent","active"} or not re.fullmatch(r"[0-9a-f]{64}",str(digest)) or not re.fullmatch(r"[0-9a-f]{32}",str(transaction)):
    raise SystemExit(1)
if (selection == "active" and operation != "none") or (selection == "intent" and operation not in {"install","deploy","maintenance"}):
    raise SystemExit(1)
print(selection, digest, transaction, operation)
') || offline_fail chat-safety-clear "selected release state is invalid" 65
# The trusted parser emits exactly four whitespace-free constrained fields.
# shellcheck disable=SC2086
set -- $selection_fields
[ "$#" -eq 4 ] || offline_fail chat-safety-clear "selected release fields are incomplete" 65
state_selection=$1
contract_sha256=$2
transaction_id=$3
state_operation=$4
expected_release_root=$OFFLINE_PERSISTENT_ROOT/releases/$contract_sha256
[ "$OFFLINE_RELEASE_ROOT" = "$expected_release_root" ] || \
  offline_fail chat-safety-clear "command is not running from the selected release" 65

contract_dir=$(python3 -I "$state_helper" stage-contract \
  "$contract_sha256" "$OFFLINE_CONTRACT_ROOT") || \
  offline_fail chat-safety-clear "cannot stage the active release contract" 73
cleanup() {
  if [ -n "${contract_dir:-}" ] && [ -d "$contract_dir" ]; then
    rm -rf -- "$contract_dir"
  fi
}
trap cleanup EXIT HUP INT TERM
offline_validate_materialized_release \
  chat-safety-clear "$contract_dir" "$OFFLINE_RELEASE_ROOT"

sentinel=$OFFLINE_PERSISTENT_ROOT/data/chat-safety/poison.json
clear_pending=$OFFLINE_STATE_DIRECTORY/chat-safety-clear-pending.json
sentinel_status=$(python3 -I "$script_dir/chat-safety-sentinel.py" status \
  "$sentinel" --expected-uid 10001 --expected-gid 10001) || \
  offline_fail chat-safety-clear "persistent poison sentinel state is invalid" 65
case "$sentinel_status" in
  absent)
    sentinel_present=false
    observed_digest=$expected_digest
    ;;
  "present "[0-9a-f][0-9a-f]*)
    sentinel_present=true
    observed_digest=${sentinel_status#present }
    ;;
  *) offline_fail chat-safety-clear "persistent poison sentinel status is malformed" 65 ;;
esac
[ "$observed_digest" = "$expected_digest" ] || \
  offline_fail chat-safety-clear "persistent poison sentinel digest changed" 65

pending_status=$(python3 -I - "$clear_pending" "$expected_digest" \
  "$contract_sha256" "$transaction_id" "$state_selection" "$state_operation" <<'PY'
import datetime as dt
import json
import os
import pathlib
import re
import stat
import sys

path=pathlib.Path(sys.argv[1])
expected={
    "sentinel_sha256":sys.argv[2],
    "contract_sha256":sys.argv[3],
    "transaction_id":sys.argv[4],
    "state_selection":sys.argv[5],
    "state_operation":sys.argv[6],
}
try:
    before=path.lstat()
except FileNotFoundError:
    print("absent")
    raise SystemExit(0)
except OSError:
    raise SystemExit(1)
if (
    stat.S_ISLNK(before.st_mode)
    or not stat.S_ISREG(before.st_mode)
    or before.st_uid != 0
    or before.st_nlink != 1
    or stat.S_IMODE(before.st_mode) != 0o600
    or not 0 < before.st_size <= 65536
):
    raise SystemExit(1)
flags=os.O_RDONLY
if hasattr(os,"O_NOFOLLOW"):
    flags|=os.O_NOFOLLOW
fd=os.open(path,flags)
try:
    after=os.fstat(fd)
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_uid != 0
        or after.st_nlink != 1
        or stat.S_IMODE(after.st_mode) != 0o600
        or after.st_size != before.st_size
    ):
        raise SystemExit(1)
    raw=b""
    while len(raw) <= 65536:
        chunk=os.read(fd,min(8192,65537-len(raw)))
        if not chunk:
            break
        raw+=chunk
    if len(raw) != after.st_size or len(raw) > 65536:
        raise SystemExit(1)
finally:
    os.close(fd)
def unique(items):
    result={}
    for key,value in items:
        if key in result:
            raise ValueError(key)
        result[key]=value
    return result
document=json.loads(
    raw,
    object_pairs_hook=unique,
    parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
)
required={"schema_version","created_at","evidence_sha256",*expected}
created=document.get("created_at")
if (
    not isinstance(document,dict)
    or set(document) != required
    or type(document.get("schema_version")) is not int
    or document["schema_version"] != 1
    or any(document.get(key) != value for key,value in expected.items())
    or not isinstance(created,str)
    or re.fullmatch(r"[0-9a-f]{64}",str(document.get("evidence_sha256"))) is None
):
    raise SystemExit(1)
parsed=dt.datetime.fromisoformat(created.replace("Z","+00:00"))
if parsed.tzinfo is None:
    raise SystemExit(1)
print("present",document["evidence_sha256"])
PY
) || offline_fail chat-safety-clear "clear-pending transaction state is invalid" 65
case "$pending_status" in
  absent)
    resume_pending=false
    pending_evidence_digest=-
    ;;
  "present "[0-9a-f][0-9a-f]*)
    resume_pending=true
    pending_evidence_digest=${pending_status#present }
    printf '%s\n' "$pending_evidence_digest" | grep -Eq '^[0-9a-f]{64}$' || \
      offline_fail chat-safety-clear "clear-pending evidence digest is malformed" 65
    ;;
  *) offline_fail chat-safety-clear "clear-pending transaction status is malformed" 65 ;;
esac
if [ "$sentinel_present" = false ] && [ "$resume_pending" = false ]; then
  offline_fail chat-safety-clear "no poison sentinel or resumable clear transaction exists" 65
fi

for writer_service in api proxy maintenance llm-egress migrate bootstrap; do
  running_ids=$(docker ps -q \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=$writer_service") || \
    offline_fail chat-safety-clear "cannot inspect stopped writer services" 69
  [ -z "$running_ids" ] || \
    offline_fail chat-safety-clear "all API and provider writers must remain stopped" 70
done

evidence_fields=$(python3 -I - "$evidence_file" "$expected_digest" \
  "$state_selection" "$state_operation" "$contract_sha256" "$transaction_id" \
  "$resume_pending" "$pending_evidence_digest" <<'PY'
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

path=pathlib.Path(sys.argv[1])
expected=sys.argv[2]
selection=sys.argv[3]
operation=sys.argv[4]
contract=sys.argv[5]
transaction=sys.argv[6]
resume=sys.argv[7] == "true"
pending_evidence=sys.argv[8]
info=path.lstat()
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 65536:
    raise SystemExit(1)
raw=path.read_bytes()
def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key]=value
    return result
def reject_constant(value):
    raise ValueError(value)
document=json.loads(raw,object_pairs_hook=unique_object,parse_constant=reject_constant)
required={
    "schema_version","sentinel_sha256","captured_at","operator_id","change_ticket",
    "processing_claims_reconciled","provider_usage_reconciled","audit_log_reviewed",
    "provider_reconciliation_reference","audit_review_reference",
    "state_selection","state_operation","contract_sha256","transaction_id",
}
if (
    set(document) != required
    or type(document.get("schema_version")) is not int
    or document["schema_version"] != 1
    or document["sentinel_sha256"] != expected
    or document.get("state_selection") != selection
    or document.get("state_operation") != operation
    or document.get("contract_sha256") != contract
    or document.get("transaction_id") != transaction
):
    raise SystemExit(1)
for key in ("operator_id","change_ticket","provider_reconciliation_reference","audit_review_reference"):
    value=document.get(key)
    if not isinstance(value,str) or re.fullmatch(r"[A-Za-z0-9_.@:/-]{1,200}",value) is None:
        raise SystemExit(1)
for key in ("processing_claims_reconciled","provider_usage_reconciled","audit_log_reviewed"):
    if document.get(key) is not True:
        raise SystemExit(1)
captured=dt.datetime.fromisoformat(document["captured_at"].replace("Z","+00:00"))
now=dt.datetime.now(dt.UTC)
if captured.tzinfo is None or captured > now + dt.timedelta(minutes=5):
    raise SystemExit(1)
digest=hashlib.sha256(raw).hexdigest()
if (not resume and now - captured > dt.timedelta(hours=24)) or (resume and digest != pending_evidence):
    raise SystemExit(1)
print(digest, document["operator_id"], document["change_ticket"])
PY
) || offline_fail chat-safety-clear "operator reconciliation evidence is invalid" 65
# The validator emits three whitespace-free fields after rejecting controls.
# shellcheck disable=SC2086
set -- $evidence_fields
[ "$#" -eq 3 ] || offline_fail chat-safety-clear "operator evidence fields are incomplete" 65
evidence_digest=$1
operator_id=$2
change_ticket=$3

# The quoted command expands database variables inside the trusted container,
# never in the operator shell.
# shellcheck disable=SC2016
processing_count=$(offline_compose chat-safety-clear "$contract_dir" exec -T postgres \
  sh -eu -c 'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc \
    "SELECT count(*) FROM chat_idempotency_records WHERE status = '\''PROCESSING'\''"') || \
  offline_fail chat-safety-clear "cannot verify the chat idempotency ledger" 69
[ "$processing_count" = 0 ] || \
  offline_fail chat-safety-clear "PROCESSING chat claims remain unreconciled" 70

audit_directory=$OFFLINE_STATE_DIRECTORY/chat-safety-audit
install -d -o root -g root -m 0700 "$audit_directory"
audit_file=$audit_directory/clear-events.jsonl
evidence_archive=$audit_directory/reconciliation-$evidence_digest.json
python3 -I - "$evidence_file" "$evidence_archive" "$evidence_digest" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

source=pathlib.Path(sys.argv[1])
target=pathlib.Path(sys.argv[2])
expected=sys.argv[3]
payload=source.read_bytes()
if hashlib.sha256(payload).hexdigest() != expected:
    raise SystemExit(1)
try:
    info=target.lstat()
except FileNotFoundError:
    info=None
except OSError:
    raise SystemExit(1)
if info is not None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400 or target.read_bytes() != payload:
        raise SystemExit(1)
else:
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
    if hasattr(os,"O_NOFOLLOW"):
        flags|=os.O_NOFOLLOW
    fd=os.open(target,flags,0o400)
    try:
        offset=0
        while offset < len(payload):
            written=os.write(fd,payload[offset:])
            if written <= 0:
                raise SystemExit(1)
            offset+=written
        os.fsync(fd)
    finally:
        os.close(fd)
directory_fd=os.open(target.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
if [ "$resume_pending" != true ]; then
  python3 -I - "$audit_file" authorized "$expected_digest" "$evidence_digest" \
    "$operator_id" "$change_ticket" "$contract_sha256" "$transaction_id" \
    "$state_selection" "$state_operation" <<'PY'
import datetime as dt
import json
import os
import pathlib
import stat
import sys

path=pathlib.Path(sys.argv[1])
try:
    info=path.lstat()
except FileNotFoundError:
    info=None
except OSError:
    raise SystemExit(1)
if info is not None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise SystemExit(1)
flags=os.O_WRONLY|os.O_APPEND|os.O_CREAT
if hasattr(os,"O_NOFOLLOW"):
    flags|=os.O_NOFOLLOW
fd=os.open(path,flags,0o600)
try:
    event={
        "schema_version":1,
        "phase":sys.argv[2],
        "recorded_at":dt.datetime.now(dt.UTC).isoformat(),
        "sentinel_sha256":sys.argv[3],
        "evidence_sha256":sys.argv[4],
        "operator_id":sys.argv[5],
        "change_ticket":sys.argv[6],
        "contract_sha256":sys.argv[7],
        "transaction_id":sys.argv[8],
        "state_selection":sys.argv[9],
        "state_operation":sys.argv[10],
    }
    encoded=(json.dumps(event,sort_keys=True,separators=(",",":"))+"\n").encode()
    offset=0
    while offset < len(encoded):
        written=os.write(fd,encoded[offset:])
        if written <= 0:
            raise SystemExit(1)
        offset+=written
    os.fsync(fd)
finally:
    os.close(fd)
directory_fd=os.open(path.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
fi

python3 -I - "$clear_pending" "$sentinel_present" "$expected_digest" \
  "$evidence_digest" "$contract_sha256" "$transaction_id" \
  "$state_selection" "$state_operation" <<'PY'
import datetime as dt
import json
import os
import pathlib
import stat
import sys

path=pathlib.Path(sys.argv[1])
allow_create=sys.argv[2] == "true"
expected={
    "sentinel_sha256":sys.argv[3],
    "evidence_sha256":sys.argv[4],
    "contract_sha256":sys.argv[5],
    "transaction_id":sys.argv[6],
    "state_selection":sys.argv[7],
    "state_operation":sys.argv[8],
}
required={"schema_version","created_at",*expected}
def validate(document):
    if (
        not isinstance(document,dict)
        or set(document) != required
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
        or any(document.get(key) != value for key,value in expected.items())
        or not isinstance(document.get("created_at"),str)
    ):
        raise SystemExit(1)
def load_existing():
    try:
        before=path.lstat()
    except OSError:
        raise SystemExit(1)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= 65536:
        raise SystemExit(1)
    flags=os.O_RDONLY
    if hasattr(os,"O_NOFOLLOW"):
        flags|=os.O_NOFOLLOW
    fd=os.open(path,flags)
    try:
        after=os.fstat(fd)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_uid != 0
            or after.st_nlink != 1
            or stat.S_IMODE(after.st_mode) != 0o600
            or not 0 < after.st_size <= 65536
        ):
            raise SystemExit(1)
        raw=b""
        while len(raw) <= 65536:
            chunk=os.read(fd,min(8192,65537-len(raw)))
            if not chunk:
                break
            raw+=chunk
        if len(raw) != after.st_size or len(raw) > 65536:
            raise SystemExit(1)
    finally:
        os.close(fd)
    def unique(items):
        result={}
        for key,value in items:
            if key in result:
                raise ValueError(key)
            result[key]=value
        return result
    document=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    validate(document)
    return raw
try:
    existing=path.lstat()
except FileNotFoundError:
    existing=None
except OSError:
    raise SystemExit(1)
if existing is not None:
    load_existing()
elif not allow_create:
    raise SystemExit(1)
else:
    document={"schema_version":1,"created_at":dt.datetime.now(dt.UTC).isoformat(),**expected}
    encoded=(json.dumps(document,sort_keys=True,separators=(",",":"))+"\n").encode()
    temporary=path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
    if hasattr(os,"O_NOFOLLOW"):
        flags|=os.O_NOFOLLOW
    fd=os.open(temporary,flags,0o600)
    try:
        offset=0
        while offset < len(encoded):
            written=os.write(fd,encoded[offset:])
            if written <= 0:
                raise SystemExit(1)
            offset+=written
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        raise SystemExit(1)
    else:
        raise SystemExit(1)
    os.rename(temporary,path)
directory_fd=os.open(path.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY

api_witness_ids=$(docker ps -aq --no-trunc \
  --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
  --filter "label=com.docker.compose.service=api") || \
  offline_fail chat-safety-clear "cannot enumerate API persistence witnesses" 69
old_ifs=$IFS
IFS="$(printf '\n ')"
# shellcheck disable=SC2086
set -- $api_witness_ids
IFS=$old_ifs
[ "$#" -le 1 ] || \
  offline_fail chat-safety-clear "multiple API persistence witnesses are unsafe" 70
if [ "$#" -eq 1 ]; then
  api_witness_id=$1
  api_witness_project=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}' \
    "$api_witness_id") || offline_fail chat-safety-clear "cannot inspect API witness project" 69
  api_witness_service=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.service" }}' \
    "$api_witness_id") || offline_fail chat-safety-clear "cannot inspect API witness service" 69
  api_witness_owner=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' \
    "$api_witness_id") || offline_fail chat-safety-clear "cannot inspect API witness owner" 69
  api_witness_stack=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.stack" }}' \
    "$api_witness_id") || offline_fail chat-safety-clear "cannot inspect API witness stack" 69
  if ! { \
    [ "$api_witness_project" = "$OFFLINE_PROJECT_NAME" ] && \
      [ "$api_witness_service" = api ] && \
      [ "$api_witness_owner" = jiangsu-heyi-knowledgebases ] && \
      [ "$api_witness_stack" = offline ]; \
  }; then
    offline_fail chat-safety-clear "API persistence witness ownership changed" 70
  fi
  api_witness_running=$(docker inspect --format '{{.State.Running}}' "$api_witness_id") || \
    offline_fail chat-safety-clear "cannot inspect API witness running state" 69
  api_witness_exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$api_witness_id") || \
    offline_fail chat-safety-clear "cannot inspect API witness exit code" 69
  [ "$api_witness_running" = false ] || \
    offline_fail chat-safety-clear "API persistence witness must remain stopped" 70
  case "$api_witness_exit_code" in
    ""|*[!0-9]*) offline_fail chat-safety-clear "API witness exit code is invalid" 70 ;;
  esac
  consume_api_witness=false
  if [ "$api_witness_exit_code" -ne 0 ]; then
    expected_api_image=$(docker inspect --format '{{.Config.Image}}' "$api_witness_id") || \
      offline_fail chat-safety-clear "cannot inspect API witness image reference" 69
    printf '%s\n' "$expected_api_image" | \
      grep -Eq '^.+@sha256:[0-9a-f]{64}$' || \
      offline_fail chat-safety-clear "API witness image reference is not pinned" 70
    expected_api_image_id=$(docker image inspect --format '{{.Id}}' \
      "$expected_api_image") || \
      offline_fail chat-safety-clear "cannot inspect the selected API image" 69
    api_witness_image_id=$(docker inspect --format '{{.Image}}' "$api_witness_id") || \
      offline_fail chat-safety-clear "cannot inspect API witness image" 69
    [ "$api_witness_image_id" = "$expected_api_image_id" ] || \
      offline_fail chat-safety-clear "API persistence witness image changed" 70
    api_witness_finished_at=$(docker inspect --format '{{.State.FinishedAt}}' \
      "$api_witness_id") || \
      offline_fail chat-safety-clear "cannot inspect API witness finish time" 69
    api_witness_archive=$audit_directory/worker-exit-$api_witness_exit_code-$api_witness_id.json
    python3 -I - "$api_witness_archive" "$api_witness_id" \
      "$api_witness_image_id" "$api_witness_finished_at" "$contract_sha256" \
      "$transaction_id" "$expected_digest" "$state_selection" "$state_operation" \
      "$api_witness_exit_code" <<'PY'
import json
import os
import pathlib
import re
import stat
import sys

path=pathlib.Path(sys.argv[1])
document={
    "schema_version":1,
    "container_id":sys.argv[2],
    "image_id":sys.argv[3],
    "finished_at":sys.argv[4],
    "exit_code":int(sys.argv[10]),
    "contract_sha256":sys.argv[5],
    "transaction_id":sys.argv[6],
    "sentinel_sha256":sys.argv[7],
    "state_selection":sys.argv[8],
    "state_operation":sys.argv[9],
}
if (
    re.fullmatch(r"[0-9a-f]{64}",document["container_id"]) is None
    or re.fullmatch(r"sha256:[0-9a-f]{64}",document["image_id"]) is None
    or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z?",document["finished_at"]) is None
    or re.fullmatch(r"[0-9a-f]{64}",document["contract_sha256"]) is None
    or re.fullmatch(r"[0-9a-f]{32}",document["transaction_id"]) is None
    or re.fullmatch(r"[0-9a-f]{64}",document["sentinel_sha256"]) is None
    or document["state_selection"] not in {"intent","active"}
    or document["state_operation"] not in {"install","deploy","maintenance","none"}
    or not 1 <= document["exit_code"] <= 255
):
    raise SystemExit(1)
encoded=(json.dumps(document,sort_keys=True,separators=(",",":"))+"\n").encode()
try:
    info=path.lstat()
except FileNotFoundError:
    info=None
except OSError:
    raise SystemExit(1)
if info is not None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400 or path.read_bytes() != encoded:
        raise SystemExit(1)
else:
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
    if hasattr(os,"O_NOFOLLOW"):
        flags|=os.O_NOFOLLOW
    fd=os.open(path,flags,0o400)
    try:
        offset=0
        while offset < len(encoded):
            written=os.write(fd,encoded[offset:])
            if written <= 0:
                raise SystemExit(1)
            offset+=written
        os.fsync(fd)
    finally:
        os.close(fd)
directory_fd=os.open(path.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
    consume_api_witness=true
  fi
  [ "$state_selection" = active ] && consume_api_witness=true
  if [ "$consume_api_witness" = true ]; then
    docker rm "$api_witness_id" >/dev/null || \
      offline_fail chat-safety-clear "cannot consume the API persistence witness" 71
    if docker inspect "$api_witness_id" >/dev/null 2>&1; then
      offline_fail chat-safety-clear "API persistence witness remained after consumption" 71
    fi
  fi
fi

if [ "$state_selection" = active ]; then
  # Establish a release-bound, stopped ExitCode=0 handoff before removing the
  # poison. The reconciler may start this exact clean container, but no proxy
  # or provider writer is opened by the operator-clear transaction.
  offline_compose chat-safety-clear "$contract_dir" \
    create --pull never --no-build --no-deps api || \
    offline_fail chat-safety-clear "cannot create the clean API recovery handoff" 73
  clean_api_ids=$(docker ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=$OFFLINE_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=api") || \
    offline_fail chat-safety-clear "cannot enumerate the clean API handoff" 69
  old_ifs=$IFS
  IFS="$(printf '\n ')"
  # shellcheck disable=SC2086
  set -- $clean_api_ids
  IFS=$old_ifs
  [ "$#" -eq 1 ] || \
    offline_fail chat-safety-clear "clean API handoff cardinality is invalid" 70
  clean_api_id=$1
  clean_api_project=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}' \
    "$clean_api_id") || offline_fail chat-safety-clear "cannot inspect clean API project" 69
  clean_api_service=$(docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.service" }}' \
    "$clean_api_id") || offline_fail chat-safety-clear "cannot inspect clean API service" 69
  clean_api_owner=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.owner" }}' \
    "$clean_api_id") || offline_fail chat-safety-clear "cannot inspect clean API owner" 69
  clean_api_stack=$(docker inspect --format \
    '{{ index .Config.Labels "io.heyi.knowledgebases.stack" }}' \
    "$clean_api_id") || offline_fail chat-safety-clear "cannot inspect clean API stack" 69
  if ! { \
    [ "$clean_api_project" = "$OFFLINE_PROJECT_NAME" ] && \
      [ "$clean_api_service" = api ] && \
      [ "$clean_api_owner" = jiangsu-heyi-knowledgebases ] && \
      [ "$clean_api_stack" = offline ]; \
  }; then
    offline_fail chat-safety-clear "clean API handoff ownership changed" 70
  fi
  clean_api_running=$(docker inspect --format '{{.State.Running}}' "$clean_api_id") || \
    offline_fail chat-safety-clear "cannot inspect clean API running state" 69
  clean_api_exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$clean_api_id") || \
    offline_fail chat-safety-clear "cannot inspect clean API exit code" 69
  if ! { [ "$clean_api_running" = false ] && [ "$clean_api_exit_code" = 0 ]; }; then
    offline_fail chat-safety-clear "clean API handoff is not stopped with ExitCode 0" 70
  fi
  clean_api_image_reference=$(docker inspect --format '{{.Config.Image}}' "$clean_api_id") || \
    offline_fail chat-safety-clear "cannot inspect clean API image reference" 69
  printf '%s\n' "$clean_api_image_reference" | \
    grep -Eq '^.+@sha256:[0-9a-f]{64}$' || \
    offline_fail chat-safety-clear "clean API image reference is not pinned" 70
  clean_api_expected_image_id=$(docker image inspect --format '{{.Id}}' \
    "$clean_api_image_reference") || \
    offline_fail chat-safety-clear "cannot inspect the clean API selected image" 69
  clean_api_image_id=$(docker inspect --format '{{.Image}}' "$clean_api_id") || \
    offline_fail chat-safety-clear "cannot inspect clean API image" 69
  [ "$clean_api_image_id" = "$clean_api_expected_image_id" ] || \
    offline_fail chat-safety-clear "clean API handoff image changed" 70
fi

sentinel_status=$(python3 -I "$script_dir/chat-safety-sentinel.py" status \
  "$sentinel" --expected-uid 10001 --expected-gid 10001) || \
  offline_fail chat-safety-clear "cannot revalidate the poison sentinel before commit" 73
case "$sentinel_status" in
  absent)
    cleared_digest=$expected_digest
    ;;
  "present "*)
    current_digest=${sentinel_status#present }
    [ "$current_digest" = "$expected_digest" ] || \
      offline_fail chat-safety-clear "poison sentinel changed before commit" 73
    run_state_digest=$(python3 -I "$script_dir/chat-safety-sentinel.py" \
      mark-run-clean "$sentinel" --expected-uid 10001 --expected-gid 10001 \
      --expected-sha256 "$expected_digest") || \
      offline_fail chat-safety-clear \
        "cannot commit the clean restart latch before clearing poison" 73
    printf '%s\n' "$run_state_digest" | grep -Eq '^[0-9a-f]{64}$' || \
      offline_fail chat-safety-clear "clean restart latch digest is malformed" 73
    cleared_digest=$(python3 -I "$script_dir/chat-safety-sentinel.py" clear \
      "$sentinel" --expected-uid 10001 --expected-gid 10001 \
      --expected-sha256 "$expected_digest") || \
      offline_fail chat-safety-clear "cannot clear the exact verified poison sentinel" 73
    ;;
  *)
    offline_fail chat-safety-clear "poison sentinel status is malformed before commit" 73
    ;;
esac
[ "$cleared_digest" = "$expected_digest" ] || \
  offline_fail chat-safety-clear "cleared sentinel acknowledgement changed" 73

python3 -I - "$audit_file" cleared "$expected_digest" "$evidence_digest" \
  "$operator_id" "$change_ticket" "$contract_sha256" "$transaction_id" \
  "$state_selection" "$state_operation" <<'PY'
import datetime as dt
import json
import os
import pathlib
import stat
import sys

path=pathlib.Path(sys.argv[1])
try:
    info=path.lstat()
except FileNotFoundError:
    info=None
except OSError:
    raise SystemExit(1)
if info is not None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise SystemExit(1)
flags=os.O_WRONLY|os.O_APPEND|os.O_CREAT
if hasattr(os,"O_NOFOLLOW"):
    flags|=os.O_NOFOLLOW
fd=os.open(path,flags,0o600)
try:
    event={
        "schema_version":1,
        "phase":sys.argv[2],
        "recorded_at":dt.datetime.now(dt.UTC).isoformat(),
        "sentinel_sha256":sys.argv[3],
        "evidence_sha256":sys.argv[4],
        "operator_id":sys.argv[5],
        "change_ticket":sys.argv[6],
        "contract_sha256":sys.argv[7],
        "transaction_id":sys.argv[8],
        "state_selection":sys.argv[9],
        "state_operation":sys.argv[10],
    }
    encoded=(json.dumps(event,sort_keys=True,separators=(",",":"))+"\n").encode()
    offset=0
    while offset < len(encoded):
        written=os.write(fd,encoded[offset:])
        if written <= 0:
            raise SystemExit(1)
        offset+=written
    os.fsync(fd)
finally:
    os.close(fd)
directory_fd=os.open(path.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY

# Removing this marker is the transaction commit point. It happens only after
# the cleared audit record and its parent directory have both been fsynced.
python3 -I - "$clear_pending" "$expected_digest" "$evidence_digest" \
  "$contract_sha256" "$transaction_id" "$state_selection" "$state_operation" <<'PY'
import json
import os
import pathlib
import stat
import sys

path=pathlib.Path(sys.argv[1])
expected={
    "sentinel_sha256":sys.argv[2],
    "evidence_sha256":sys.argv[3],
    "contract_sha256":sys.argv[4],
    "transaction_id":sys.argv[5],
    "state_selection":sys.argv[6],
    "state_operation":sys.argv[7],
}
required={"schema_version","created_at",*expected}
try:
    before=path.lstat()
except OSError:
    raise SystemExit(1)
if (
    stat.S_ISLNK(before.st_mode)
    or not stat.S_ISREG(before.st_mode)
    or before.st_uid != 0
    or before.st_nlink != 1
    or stat.S_IMODE(before.st_mode) != 0o600
    or not 0 < before.st_size <= 65536
):
    raise SystemExit(1)
flags=os.O_RDONLY
if hasattr(os,"O_NOFOLLOW"):
    flags|=os.O_NOFOLLOW
fd=os.open(path,flags)
try:
    after=os.fstat(fd)
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_uid != 0
        or after.st_nlink != 1
        or stat.S_IMODE(after.st_mode) != 0o600
        or after.st_size != before.st_size
    ):
        raise SystemExit(1)
    raw=b""
    while len(raw) <= 65536:
        chunk=os.read(fd,min(8192,65537-len(raw)))
        if not chunk:
            break
        raw+=chunk
    if len(raw) != after.st_size or len(raw) > 65536:
        raise SystemExit(1)
finally:
    os.close(fd)
def unique(items):
    result={}
    for key,value in items:
        if key in result:
            raise ValueError(key)
        result[key]=value
    return result
document=json.loads(
    raw,
    object_pairs_hook=unique,
    parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
)
if (
    not isinstance(document,dict)
    or set(document) != required
    or type(document.get("schema_version")) is not int
    or document["schema_version"] != 1
    or any(document.get(key) != value for key,value in expected.items())
    or not isinstance(document.get("created_at"),str)
):
    raise SystemExit(1)
current=path.lstat()
if current.st_dev != before.st_dev or current.st_ino != before.st_ino:
    raise SystemExit(1)
os.unlink(path)
directory_fd=os.open(path.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY

cleanup
trap - EXIT HUP INT TERM
echo "chat-safety-clear: exact sentinel cleared after audited reconciliation; sha256=$expected_digest"
