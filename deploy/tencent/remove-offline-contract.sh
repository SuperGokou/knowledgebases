#!/usr/bin/env sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 /run/heyi-kb-offline/contracts/contract.ID SHA256" >&2
  exit 64
fi

contract_dir=$1
expected_digest=$2
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/tencent/offline-operation-common.sh
. "$script_dir/offline-operation-common.sh"

offline_acquire_lock contract-cleanup
actual_digest=$(offline_verify_contract contract-cleanup "$contract_dir")
if [ "$actual_digest" != "$expected_digest" ]; then
  offline_fail contract-cleanup "refusing to remove a contract with a different digest" 65
fi
canonical_contract=$(realpath -e -- "$contract_dir")
case "$canonical_contract" in
  "$OFFLINE_CONTRACT_ROOT"/contract.*) ;;
  *) offline_fail contract-cleanup "refusing to remove a path outside the contract root" 65 ;;
esac
rm -rf -- "$canonical_contract"
if [ -e "$canonical_contract" ]; then
  offline_fail contract-cleanup "contract removal could not be verified" 73
fi
echo "contract-cleanup: removed verified snapshot $expected_digest"
