from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import json
import re
import sys
from pathlib import Path

_KEY = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_PINNED_IMAGE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_UNSAFE_VALUE = re.compile(r"[$`\\;&|<>]")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.@:/-]+$")
_URL_COMPONENT = re.compile(r"^[A-Za-z0-9._~-]+$")
_CONTROLLED_LLM_GATEWAY_URL = "http://llm-egress:8080"
_LLM_EGRESS_MODES = {"strict_offline", "controlled_gateway"}
_LLM_PROVIDER_ORDER = ("deepseek", "qwen", "minimax")

_INTEGER_KEYS = {
    "KB_HTTPS_PORT",
    "KB_OBJECTS_HTTPS_PORT",
    "KB_MULTIPART_THRESHOLD_BYTES",
    "CLAMAV_DATABASE_MAX_AGE_SECONDS",
    "KB_MALWARE_SCAN_TIMEOUT_SECONDS",
    "KB_MALWARE_SCAN_CHUNK_SIZE_BYTES",
    "KB_MALWARE_SCAN_RECLAIM_SECONDS",
    "MINIO_MULTIPART_CLEANUP_INTERVAL_SECONDS",
    "KB_DATABASE_POOL_SIZE",
    "KB_DATABASE_MAX_OVERFLOW",
    "KB_DATABASE_POOL_TIMEOUT_SECONDS",
    "KB_DATABASE_STATEMENT_TIMEOUT_MS",
    "KB_DATABASE_LOCK_TIMEOUT_MS",
    "KB_DATABASE_IDLE_TRANSACTION_TIMEOUT_MS",
    "KB_CHAT_REPLAY_ACTIVE_KEY_VERSION",
}
_URL_COMPONENT_KEYS = {"POSTGRES_PASSWORD", "POSTGRES_APP_PASSWORD", "REDIS_PASSWORD"}
_SECRET_TOKEN_KEYS = {
    "MINIO_ROOT_PASSWORD",
    "MINIO_APP_PASSWORD",
    "KB_JWT_SECRET",
    "KB_BFF_SHARED_SECRET",
    "KB_LLM_CREDENTIAL_ENCRYPTION_KEY",
}
_SAFE_TOKEN_KEYS = {
    "COMPOSE_PROJECT_NAME",
    "KB_DATA_ROOT",
    "KB_BIND_ADDRESS",
    "KB_PUBLIC_HOST",
    "KB_PUBLIC_ORIGIN",
    "POSTGRES_DB",
    "POSTGRES_USER",
    "POSTGRES_APP_USER",
    "MINIO_ROOT_USER",
    "MINIO_APP_USER",
    "MINIO_REGION",
    "MINIO_BUCKET",
    "MINIO_MULTIPART_MAX_AGE",
    "KB_BOOTSTRAP_ADMIN_EMAIL",
}
_JSON_KEYS = {
    "KB_TRUSTED_HOSTS",
    "KB_CORS_ORIGINS",
    "KB_CHAT_REPLAY_ENCRYPTION_KEYS",
}
_OPTIONAL_TOKEN_KEYS = {"KB_BOOTSTRAP_ADMIN_PASSWORD"}
_LLM_EGRESS_KEYS = {
    "KB_LLM_EGRESS_MODE",
    "KB_LLM_EGRESS_GATEWAY_URL",
    "KB_LLM_EGRESS_APPROVED_PROVIDERS",
}
_OPTIONAL_PATH_KEYS = {
    "KB_UPGRADE_BACKUP_EVIDENCE_PATH",
    "KB_UPGRADE_BACKUP_SIGNATURE_PATH",
    "KB_UPGRADE_BACKUP_PUBLIC_KEY_PATH",
}
_RUNTIME_KEYS = (
    _INTEGER_KEYS
    | _URL_COMPONENT_KEYS
    | _SECRET_TOKEN_KEYS
    | _SAFE_TOKEN_KEYS
    | _JSON_KEYS
    | _OPTIONAL_TOKEN_KEYS
    | _LLM_EGRESS_KEYS
    | _OPTIONAL_PATH_KEYS
)
_RELEASE_KEYS = {"KB_API_IMAGE", "KB_MIGRATION_IMAGE", "KB_WEB_IMAGE"}
_OPTIONAL_RUNTIME_KEYS = {
    "KB_BOOTSTRAP_ADMIN_PASSWORD",
    "KB_DATABASE_POOL_SIZE",
    "KB_DATABASE_MAX_OVERFLOW",
    "KB_DATABASE_POOL_TIMEOUT_SECONDS",
    "KB_DATABASE_STATEMENT_TIMEOUT_MS",
    "KB_DATABASE_LOCK_TIMEOUT_MS",
    "KB_DATABASE_IDLE_TRANSACTION_TIMEOUT_MS",
    *_OPTIONAL_PATH_KEYS,
}


def _parse(path: Path, *, accepted_keys: set[str], release: bool) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.removesuffix("\r")
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"invalid environment syntax on line {line_number}")
        key, value = line.split("=", 1)
        if _KEY.fullmatch(key) is None:
            raise ValueError(f"invalid environment key on line {line_number}")
        if key in values:
            raise ValueError(f"duplicate environment key: {key}")
        if key not in accepted_keys:
            prefix = "release " if release else ""
            raise ValueError(f"unknown {prefix}environment key: {key}")
        if value[:1] in {"'", '"'}:
            if len(value) < 2 or value[-1] != value[0]:
                raise ValueError(f"unbalanced quotes for {key}")
            value = value[1:-1]
        elif value[-1:] in {"'", '"'}:
            raise ValueError(f"unbalanced quotes for {key}")
        if _UNSAFE_VALUE.search(value):
            raise ValueError(f"unsafe value for {key}")
        values[key] = value
    return values


def _private_host(value: str) -> bool:
    if value == "localhost":
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.version != 4:
        return False
    accepted_networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    return any(address in network for network in accepted_networks)


def _is_base64url_256_key(value: object) -> bool:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}={0,1}", value) is None:
        return False
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError):
        return False
    return len(decoded) == 32


def _parse_chat_replay_keyring(value: str) -> dict[str, object]:
    def reject_duplicate_versions(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        parsed: dict[str, object] = {}
        for key, item in pairs:
            if key in parsed:
                raise ValueError("chat replay key versions are duplicated")
            parsed[key] = item
        return parsed

    try:
        parsed = json.loads(value, object_pairs_hook=reject_duplicate_versions)
    except json.JSONDecodeError as exc:
        raise ValueError("KB_CHAT_REPLAY_ENCRYPTION_KEYS must be valid JSON") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise ValueError("KB_CHAT_REPLAY_ENCRYPTION_KEYS must be a non-empty object")
    return parsed


def _approved_llm_providers(value: str) -> tuple[str, ...]:
    if not value:
        return ()
    providers = tuple(value.split(","))
    if (
        any(not item or item != item.strip() for item in providers)
        or len(set(providers)) != len(providers)
        or any(item not in _LLM_PROVIDER_ORDER for item in providers)
        or providers != tuple(item for item in _LLM_PROVIDER_ORDER if item in providers)
    ):
        raise ValueError(
            "KB_LLM_EGRESS_APPROVED_PROVIDERS must be a canonical subset of deepseek,qwen,minimax"
        )
    return providers


def _validate(
    runtime: dict[str, str],
    release: dict[str, str],
    *,
    require_bootstrap_password: bool = False,
) -> None:
    missing = sorted(
        ((_RUNTIME_KEYS - _OPTIONAL_RUNTIME_KEYS) - runtime.keys())
        | (_RELEASE_KEYS - release.keys())
    )
    if missing:
        raise ValueError(f"required environment keys are missing: {','.join(missing)}")
    for key in _INTEGER_KEYS & runtime.keys():
        if not runtime[key].isdigit():
            raise ValueError(f"unsafe value for {key}")
    for key in _URL_COMPONENT_KEYS:
        if _URL_COMPONENT.fullmatch(runtime[key]) is None:
            raise ValueError(f"unsafe URL component for {key}")
    for key in _SECRET_TOKEN_KEYS | _SAFE_TOKEN_KEYS:
        if _SAFE_TOKEN.fullmatch(runtime[key]) is None:
            raise ValueError(f"unsafe value for {key}")
    optional_password = runtime.get("KB_BOOTSTRAP_ADMIN_PASSWORD", "")
    if optional_password and _SAFE_TOKEN.fullmatch(optional_password) is None:
        raise ValueError("unsafe value for KB_BOOTSTRAP_ADMIN_PASSWORD")
    for key in _OPTIONAL_PATH_KEYS:
        value = runtime.get(key, "")
        if not value:
            continue
        if _SAFE_TOKEN.fullmatch(value) is None or not value.startswith("/"):
            raise ValueError(f"unsafe absolute path for {key}")
        if key == "KB_UPGRADE_BACKUP_PUBLIC_KEY_PATH":
            approved = value.startswith("/etc/heyi-knowledgebases/") or value.startswith(
                "/srv/heyi-knowledgebases-offline/"
            )
        else:
            approved = value.startswith("/srv/heyi-knowledgebases-offline/")
        if not approved:
            raise ValueError(f"{key} is outside the approved protected roots")
    for key in _RELEASE_KEYS:
        value = release[key]
        if _PINNED_IMAGE.fullmatch(value) is None or value.endswith("@sha256:" + "0" * 64):
            raise ValueError(f"{key} must be pinned by an exact non-placeholder sha256 digest")
        if not value.startswith("127.0.0.1:5000/"):
            raise ValueError(f"{key} must use the controlled loopback registry namespace")

    if runtime["COMPOSE_PROJECT_NAME"] != "heyi-kb-offline":
        raise ValueError("COMPOSE_PROJECT_NAME must be heyi-kb-offline")
    if runtime["KB_DATA_ROOT"] != "/srv/heyi-knowledgebases-offline/data":
        raise ValueError("unexpected KB_DATA_ROOT")
    if not _private_host(runtime["KB_PUBLIC_HOST"]):
        raise ValueError("KB_PUBLIC_HOST must be an approved private or local address")
    if not _private_host(runtime["KB_BIND_ADDRESS"]):
        raise ValueError("KB_BIND_ADDRESS must be an approved private or local address")
    https_port = int(runtime["KB_HTTPS_PORT"])
    object_port = int(runtime["KB_OBJECTS_HTTPS_PORT"])
    if not 1 <= https_port <= 65535 or not 1 <= object_port <= 65535:
        raise ValueError("HTTPS ports must be between 1 and 65535")
    if https_port == object_port:
        raise ValueError("HTTPS and object HTTPS ports must be different")
    expected_origin = f"https://{runtime['KB_PUBLIC_HOST']}:{https_port}"
    if runtime["KB_PUBLIC_ORIGIN"] != expected_origin:
        raise ValueError("KB_PUBLIC_ORIGIN must exactly match the approved public host and port")
    try:
        trusted_hosts = json.loads(runtime["KB_TRUSTED_HOSTS"])
        cors_origins = json.loads(runtime["KB_CORS_ORIGINS"])
    except json.JSONDecodeError as exc:
        raise ValueError("trusted hosts and CORS origins must be valid JSON arrays") from exc
    if trusted_hosts != [runtime["KB_PUBLIC_HOST"], "api"]:
        raise ValueError("KB_TRUSTED_HOSTS must contain only KB_PUBLIC_HOST and api")
    if cors_origins != []:
        raise ValueError("KB_CORS_ORIGINS must remain empty in the offline profile")
    egress_mode = runtime["KB_LLM_EGRESS_MODE"]
    gateway_url = runtime["KB_LLM_EGRESS_GATEWAY_URL"]
    approved_providers = _approved_llm_providers(runtime["KB_LLM_EGRESS_APPROVED_PROVIDERS"])
    if egress_mode not in _LLM_EGRESS_MODES:
        raise ValueError("KB_LLM_EGRESS_MODE must be strict_offline or controlled_gateway")
    if egress_mode == "strict_offline":
        if gateway_url:
            raise ValueError("strict_offline requires an empty gateway URL")
        if approved_providers:
            raise ValueError("strict_offline requires an empty approved provider set")
    elif gateway_url != _CONTROLLED_LLM_GATEWAY_URL:
        raise ValueError("controlled_gateway requires the fixed gateway URL")
    elif not approved_providers:
        raise ValueError("controlled_gateway requires at least one approved provider")
    replay_keys = _parse_chat_replay_keyring(runtime["KB_CHAT_REPLAY_ENCRYPTION_KEYS"])
    normalized_versions: set[int] = set()
    for raw_version, encoded_key in replay_keys.items():
        if (
            not isinstance(raw_version, str)
            or not raw_version.isdigit()
            or raw_version.startswith("0")
        ):
            raise ValueError("chat replay key versions must be positive integer strings")
        version = int(raw_version)
        if not 1 <= version <= 2_147_483_647 or version in normalized_versions:
            raise ValueError("chat replay key versions are invalid or duplicated")
        if not _is_base64url_256_key(encoded_key):
            raise ValueError("chat replay keys must be 32-byte base64url values")
        normalized_versions.add(version)
    active_version = int(runtime["KB_CHAT_REPLAY_ACTIVE_KEY_VERSION"])
    if active_version not in normalized_versions:
        raise ValueError("active chat replay key version is not present in the keyring")
    if require_bootstrap_password:
        bootstrap_password = runtime.get("KB_BOOTSTRAP_ADMIN_PASSWORD", "")
        placeholder_markers = ("replace", "changeme", "development", "example")
        if len(bootstrap_password) < 16 or any(
            marker in bootstrap_password.lower() for marker in placeholder_markers
        ):
            raise ValueError(
                "initial installation requires a non-example bootstrap password "
                "with at least 16 characters"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("runtime", type=Path)
    parser.add_argument("release", type=Path)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--emit-maintenance-fields", action="store_true")
    output.add_argument("--emit-compose-profile", action="store_true")
    output.add_argument("--emit-egress-fields", action="store_true")
    parser.add_argument("--require-bootstrap-password", action="store_true")
    arguments = parser.parse_args()
    try:
        runtime = _parse(arguments.runtime, accepted_keys=_RUNTIME_KEYS, release=False)
        release = _parse(arguments.release, accepted_keys=_RELEASE_KEYS, release=True)
        _validate(
            runtime,
            release,
            require_bootstrap_password=arguments.require_bootstrap_password,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"offline-environment: {exc}", file=sys.stderr)
        return 65
    if arguments.emit_maintenance_fields:
        print(
            "\t".join(
                runtime[key]
                for key in (
                    "COMPOSE_PROJECT_NAME",
                    "KB_DATA_ROOT",
                    "KB_BIND_ADDRESS",
                    "KB_PUBLIC_HOST",
                    "KB_HTTPS_PORT",
                    "KB_OBJECTS_HTTPS_PORT",
                )
            )
        )
    elif arguments.emit_compose_profile and runtime["KB_LLM_EGRESS_MODE"] == "controlled_gateway":
        print("controlled-egress")
    elif arguments.emit_egress_fields:
        print(
            "\t".join(
                (
                    runtime["KB_LLM_EGRESS_MODE"],
                    runtime["KB_LLM_EGRESS_APPROVED_PROVIDERS"] or "-",
                )
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
