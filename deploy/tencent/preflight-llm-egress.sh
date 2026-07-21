#!/usr/bin/env sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 /absolute/path/to/offline.env /absolute/path/to/llm-egress.env" >&2
  exit 64
fi

base_env=$1
llm_env=$2
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project=heyi-kb-offline

fail() {
  echo "llm-egress-preflight: $1" >&2
  exit 65
}

case "$base_env:$llm_env" in
  /*:/*) ;;
  *) fail "both environment paths must be absolute" ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "llm-egress-preflight: run as root so credential ownership can be verified" >&2
  exit 77
fi

for candidate in "$base_env" "$llm_env"; do
  [ ! -L "$candidate" ] || fail "environment files must not be symbolic links"
  [ -f "$candidate" ] || fail "an environment file is missing"
  [ "$(stat -c %u -- "$candidate")" -eq 0 ] || fail "environment files must be owned by root"
  mode=$(stat -c %a -- "$candidate")
  case "$mode" in
    400|600) ;;
    *) fail "environment file permissions must be 0600 or 0400" ;;
  esac
done

default_provider=
deepseek_key=
qwen_key=
minimax_key=
deepseek_base_url=
deepseek_model=
qwen_base_url=
qwen_model=
qwen_workspace_hosts=
minimax_base_url=
minimax_model=
seen_keys=" "
line_number=0
carriage_return=$(printf '\r')
while IFS= read -r raw_line || [ -n "$raw_line" ]; do
  line_number=$((line_number + 1))
  case "$raw_line" in
    *"$carriage_return") line=${raw_line%"$carriage_return"} ;;
    *) line=$raw_line ;;
  esac
  case "$line" in
    ""|'#'*) continue ;;
    *'='*) ;;
    *) fail "invalid LLM environment syntax on line $line_number" ;;
  esac
  key=${line%%=*}
  value=${line#*=}
  case "$key" in
    ""|*[!A-Z0-9_]*|[0-9]*) fail "invalid LLM environment key" ;;
  esac
  case "$seen_keys" in
    *" $key "*) fail "duplicate LLM environment key: $key" ;;
  esac
  seen_keys="$seen_keys$key "
  case "$value" in
    *'$'*|*'`'*|*'\'*|*';'*|*'&'*|*'|'*|*'<'*|*'>'*|*' '*|*"$(printf '\t')"*)
      fail "unsafe value in the LLM credential file"
      ;;
  esac
  case "$key" in
    KB_LLM_DEFAULT_PROVIDER) default_provider=$value ;;
    KB_DEEPSEEK_API_KEY) deepseek_key=$value ;;
    KB_DEEPSEEK_BASE_URL) deepseek_base_url=$value ;;
    KB_DEEPSEEK_MODEL) deepseek_model=$value ;;
    KB_QWEN_API_KEY) qwen_key=$value ;;
    KB_QWEN_BASE_URL) qwen_base_url=$value ;;
    KB_QWEN_MODEL) qwen_model=$value ;;
    KB_QWEN_ALLOWED_WORKSPACE_HOSTS) qwen_workspace_hosts=$value ;;
    KB_MINIMAX_API_KEY) minimax_key=$value ;;
    KB_MINIMAX_BASE_URL) minimax_base_url=$value ;;
    KB_MINIMAX_MODEL) minimax_model=$value ;;
    *) fail "unknown LLM environment key: $key" ;;
  esac
done < "$llm_env"

for required_key in \
  KB_LLM_DEFAULT_PROVIDER \
  KB_DEEPSEEK_API_KEY \
  KB_DEEPSEEK_BASE_URL \
  KB_DEEPSEEK_MODEL \
  KB_QWEN_API_KEY \
  KB_QWEN_BASE_URL \
  KB_QWEN_MODEL \
  KB_QWEN_ALLOWED_WORKSPACE_HOSTS \
  KB_MINIMAX_API_KEY \
  KB_MINIMAX_BASE_URL \
  KB_MINIMAX_MODEL; do
  case "$seen_keys" in
    *" $required_key "*) ;;
    *) fail "missing LLM environment key: $required_key" ;;
  esac
done

for provider_setting in \
  "$deepseek_base_url" \
  "$deepseek_model" \
  "$qwen_base_url" \
  "$qwen_model" \
  "$qwen_workspace_hosts" \
  "$minimax_base_url" \
  "$minimax_model"; do
  [ -n "$provider_setting" ] || fail "model URLs, names and workspace host policy must be explicit"
  case "$provider_setting" in
    *REPLACE*|*replace*|*CHANGEME*|*changeme*) fail "placeholder model settings are forbidden" ;;
  esac
done

case "$default_provider" in
  deepseek|qwen|minimax) ;;
  *) fail "KB_LLM_DEFAULT_PROVIDER must be deepseek, qwen or minimax" ;;
esac

configured_count=0
for provider_key in "$deepseek_key" "$qwen_key" "$minimax_key"; do
  [ -z "$provider_key" ] && continue
  case "$provider_key" in
    *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~+/@:=,-]*)
      fail "model credentials contain unsupported characters"
      ;;
  esac
  case "$provider_key" in
    *REPLACE*|*replace*|*CHANGEME*|*changeme*) fail "placeholder model credentials are forbidden" ;;
  esac
  [ "${#provider_key}" -ge 8 ] || fail "configured model credentials are unexpectedly short"
  configured_count=$((configured_count + 1))
done
[ "$configured_count" -ge 2 ] || fail "two independent model provider credentials are required"

case "$default_provider" in
  deepseek) [ -n "$deepseek_key" ] || fail "the default DeepSeek credential is missing" ;;
  qwen) [ -n "$qwen_key" ] || fail "the default Qwen credential is missing" ;;
  minimax) [ -n "$minimax_key" ] || fail "the default MiniMax credential is missing" ;;
esac

command -v docker >/dev/null 2>&1 || {
  echo "llm-egress-preflight: Docker is required" >&2
  exit 69
}
command -v python3 >/dev/null 2>&1 || {
  echo "llm-egress-preflight: Python 3 is required" >&2
  exit 69
}

python3 "$script_dir/verify-offline-network-cidrs.py" \
  "$project" \
  172.30.240.0/24 \
  172.30.241.0/24 \
  172.30.242.0/24 \
  172.30.243.0/28 \
  172.30.244.0/28

python3 "$script_dir/verify-llm-egress-compose.py" \
  "$project" \
  "$base_env" \
  "$llm_env" \
  "$script_dir/compose.offline.yml" \
  "$script_dir/compose.llm-egress.yml"

echo "llm-egress-preflight: private-connected deployment requirements satisfied"
