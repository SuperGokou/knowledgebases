from __future__ import annotations

import hashlib
import http.client
import importlib.util
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from types import ModuleType

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
DEPLOY = REPOSITORY / "deploy/tencent"
EXAMPLE_RUNTIME_ENV = DEPLOY / "offline.env.example"
EXAMPLE_RELEASE_ENV = DEPLOY / "release.env.example"


def _validator() -> ModuleType:
    path = DEPLOY / "validate-offline-environment.py"
    spec = importlib.util.spec_from_file_location("offline_environment_validator", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _network_validator() -> ModuleType:
    path = DEPLOY / "verify-offline-network-cidrs.py"
    spec = importlib.util.spec_from_file_location("offline_network_validator", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _registry_byte_verifier_program() -> str:
    script = (DEPLOY / "import-offline-registry-bundle.sh").read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^verify_registry_manifest_and_config\(\) \{.*?"
        r"<<'PY'\n(?P<body>.*?)\nPY\n\}",
        script,
    )
    assert match is not None
    return match.group("body")


def _local_image_archive_verifier_program() -> str:
    script = (DEPLOY / "offline-operation-common.sh").read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^offline_local_image_config_id\(\) \(.*?"
        r"python3 -I - \"\$archive\" <<'PY'\n(?P<body>.*?)\nPY\n\)",
        script,
    )
    assert match is not None
    return match.group("body")


def _write_single_image_archive(
    path: Path,
    config: bytes,
    *,
    claimed_config_digest: str | None = None,
) -> str:
    actual_config_digest = hashlib.sha256(config).hexdigest()
    config_digest = claimed_config_digest or actual_config_digest
    config_path = f"{config_digest}.json"
    manifest = json.dumps(
        [
            {
                "Config": config_path,
                "Layers": [],
                "RepoTags": ["heyi-bootstrap/registry:tested"],
            }
        ],
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with tarfile.open(path, mode="w") as archive:
        for name, data in (("manifest.json", manifest), (config_path, config)):
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.mtime = 0
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return "sha256:" + actual_config_digest


class _RegistryResponse:
    def __init__(self, data: bytes, *, content_digest: str | None = None) -> None:
        self.status = 200
        self._data = data
        self._headers = {"Content-Length": str(len(data))}
        if content_digest is not None:
            self._headers["Docker-Content-Digest"] = content_digest

    def read(self, amount: int) -> bytes:
        return self._data[:amount]

    def getheader(self, name: str) -> str | None:
        return self._headers.get(name)


class _RegistryConnection:
    responses: list[_RegistryResponse] = []
    paths: list[str] = []

    def __init__(self, host: str, port: int, timeout: int) -> None:
        assert (host, port, timeout) == ("127.0.0.1", 5000, 10)
        self._responses = list(type(self).responses)

    def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
        assert method == "GET"
        assert headers["Accept"]
        type(self).paths.append(path)

    def getresponse(self) -> _RegistryResponse:
        return self._responses.pop(0)

    def close(self) -> None:
        return None


def _registry_identity_fixture() -> tuple[str, str, list[_RegistryResponse]]:
    config = json.dumps(
        {"architecture": "amd64", "os": "linux", "rootfs": {"diff_ids": ["sha256:" + "3" * 64]}},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    config_id = "sha256:" + hashlib.sha256(config).hexdigest()
    manifest = json.dumps(
        {
            "config": {
                "digest": config_id,
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": len(config),
            },
            "layers": [
                {
                    "digest": "sha256:" + "4" * 64,
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "size": 123,
                }
            ],
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    manifest_id = "sha256:" + hashlib.sha256(manifest).hexdigest()
    image = f"127.0.0.1:5000/heyi-release/api@{manifest_id}"
    return (
        image,
        config_id,
        [
            _RegistryResponse(manifest, content_digest=manifest_id),
            _RegistryResponse(config),
        ],
    )


def test_registry_byte_verifier_binds_manifest_config_and_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image, config_id, responses = _registry_identity_fixture()
    _RegistryConnection.responses = responses
    _RegistryConnection.paths = []
    monkeypatch.setattr(http.client, "HTTPConnection", _RegistryConnection)
    monkeypatch.setattr(sys, "argv", ["registry-byte-verifier", image, config_id])

    exec(compile(_registry_byte_verifier_program(), "<registry-byte-verifier>", "exec"), {})

    assert _RegistryConnection.paths == [
        f"/v2/heyi-release/api/manifests/{image.rsplit('@', 1)[1]}",
        f"/v2/heyi-release/api/blobs/{config_id}",
    ]


def test_registry_byte_verifier_rejects_a_signed_config_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image, _config_id, responses = _registry_identity_fixture()
    _RegistryConnection.responses = responses
    _RegistryConnection.paths = []
    monkeypatch.setattr(http.client, "HTTPConnection", _RegistryConnection)
    monkeypatch.setattr(sys, "argv", ["registry-byte-verifier", image, "sha256:" + "9" * 64])

    with pytest.raises(SystemExit, match="config descriptor differs"):
        exec(compile(_registry_byte_verifier_program(), "<registry-byte-verifier>", "exec"), {})


def test_local_image_config_identity_is_always_recomputed_from_archive_bytes(
    tmp_path: Path,
) -> None:
    common = (DEPLOY / "offline-operation-common.sh").read_text(encoding="utf-8")
    helper = common.split("offline_local_image_config_id() (", 1)[1].split(
        "\noffline_require_no_chat_safety_poison()", 1
    )[0]
    config = json.dumps(
        {"architecture": "amd64", "os": "linux", "rootfs": {"diff_ids": []}},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    archive = tmp_path / "single-image.tar"
    expected = _write_single_image_archive(archive, config)

    result = subprocess.run(
        [sys.executable, "-I", "-c", _local_image_archive_verifier_program(), str(archive)],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected
    assert "docker image inspect" not in helper
    assert "archive-required" not in helper
    assert 'image.get("Descriptor")' not in helper
    assert "annotations.get" not in helper
    assert helper.count('docker image save --output "$archive" "$image"') == 1
    assert "hashlib.sha256(config_bytes).hexdigest() != config_digest" in helper


def test_local_image_config_identity_rejects_config_bytes_under_a_false_digest(
    tmp_path: Path,
) -> None:
    config = json.dumps(
        {"architecture": "amd64", "os": "linux", "rootfs": {"diff_ids": []}},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    archive = tmp_path / "false-config-address.tar"
    _write_single_image_archive(archive, config, claimed_config_digest="f" * 64)

    result = subprocess.run(
        [sys.executable, "-I", "-c", _local_image_archive_verifier_program(), str(archive)],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert result.returncode != 0
    assert "config bytes do not match their content address" in result.stderr


def _valid_runtime() -> str:
    return EXAMPLE_RUNTIME_ENV.read_text(encoding="utf-8").replace(
        "REPLACE_WITH_32_BYTE_BASE64URL_KEY",
        "cnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnI=",
    )


def _valid_release() -> str:
    return (
        EXAMPLE_RELEASE_ENV.read_text(encoding="utf-8")
        .replace(
            "127.0.0.1:5000/heyi-release/api@sha256:" + "0" * 64,
            "127.0.0.1:5000/heyi-release/api@sha256:" + "a" * 64,
        )
        .replace(
            "127.0.0.1:5000/heyi-release/migration@sha256:" + "0" * 64,
            "127.0.0.1:5000/heyi-release/migration@sha256:" + "b" * 64,
        )
        .replace(
            "127.0.0.1:5000/heyi-release/web@sha256:" + "0" * 64,
            "127.0.0.1:5000/heyi-release/web@sha256:" + "c" * 64,
        )
    )


def _parse_and_validate(runtime: str, release: str) -> None:
    validator = _validator()
    parsed_runtime = validator._parse(  # noqa: SLF001
        _TextPath(runtime),
        accepted_keys=validator._RUNTIME_KEYS,  # noqa: SLF001
        release=False,
    )
    parsed_release = validator._parse(  # noqa: SLF001
        _TextPath(release),
        accepted_keys=validator._RELEASE_KEYS,  # noqa: SLF001
        release=True,
    )
    validator._validate(parsed_runtime, parsed_release)  # noqa: SLF001


class _TextPath:
    def __init__(self, value: str) -> None:
        self._value = value

    def read_text(self, *, encoding: str) -> str:
        assert encoding == "utf-8"
        return self._value


def test_validator_accepts_the_reviewed_private_runtime_and_release_contract() -> None:
    _parse_and_validate(_valid_runtime(), _valid_release())


def test_existing_offline_network_must_preserve_driver_internal_ipam_and_owner() -> None:
    validator = _network_validator()
    requested = {item[0] for item in validator.EXPECTED_NETWORKS.values()}
    network = {
        "Id": "a" * 64,
        "Name": "heyi-kb-offline_backend",
        "Driver": "bridge",
        "Internal": True,
        "IPAM": {"Config": [{"Subnet": "172.30.241.0/24"}]},
        "Labels": {
            "com.docker.compose.project": "heyi-kb-offline",
            "com.docker.compose.network": "backend",
            "io.heyi.knowledgebases.owner": "jiangsu-heyi-knowledgebases",
            "io.heyi.knowledgebases.stack": "offline",
        },
    }

    subnet, _device = validator._validate_owned_network(  # noqa: SLF001
        "heyi-kb-offline", network, requested
    )
    assert str(subnet) == "172.30.241.0/24"

    for field, unsafe_value in (
        ("Driver", "host"),
        ("Internal", False),
        ("Name", "foreign_backend"),
    ):
        unsafe = {**network, field: unsafe_value}
        with pytest.raises(RuntimeError):
            validator._validate_owned_network(  # noqa: SLF001
                "heyi-kb-offline", unsafe, requested
            )

    unsafe_labels = {
        **network,
        "Labels": {**network["Labels"], "io.heyi.knowledgebases.owner": "foreign"},
    }
    with pytest.raises(RuntimeError):
        validator._validate_owned_network(  # noqa: SLF001
            "heyi-kb-offline", unsafe_labels, requested
        )


def test_validator_accepts_only_the_fixed_controlled_llm_gateway_pair() -> None:
    controlled_runtime = (
        _valid_runtime()
        .replace(
            "KB_LLM_EGRESS_MODE=strict_offline",
            "KB_LLM_EGRESS_MODE=controlled_gateway",
        )
        .replace(
            "KB_LLM_EGRESS_GATEWAY_URL=",
            "KB_LLM_EGRESS_GATEWAY_URL=http://llm-egress:8080",
        )
        .replace(
            "KB_LLM_EGRESS_APPROVED_PROVIDERS=",
            "KB_LLM_EGRESS_APPROVED_PROVIDERS=deepseek",
        )
    )

    _parse_and_validate(controlled_runtime, _valid_release())


@pytest.mark.parametrize(
    ("replacements", "expected"),
    [
        (
            {"KB_LLM_EGRESS_GATEWAY_URL=": ("KB_LLM_EGRESS_GATEWAY_URL=http://llm-egress:8080")},
            "strict_offline requires",
        ),
        (
            {"KB_LLM_EGRESS_MODE=strict_offline": "KB_LLM_EGRESS_MODE=direct"},
            "must be strict_offline or controlled_gateway",
        ),
        (
            {
                "KB_LLM_EGRESS_MODE=strict_offline": ("KB_LLM_EGRESS_MODE=controlled_gateway"),
                "KB_LLM_EGRESS_GATEWAY_URL=": (
                    "KB_LLM_EGRESS_GATEWAY_URL=http://attacker.invalid:8080"
                ),
            },
            "controlled_gateway requires",
        ),
    ],
)
def test_validator_rejects_inconsistent_or_unreviewed_llm_egress_modes(
    replacements: dict[str, str],
    expected: str,
) -> None:
    runtime = _valid_runtime()
    for before, after in replacements.items():
        runtime = runtime.replace(before, after)

    with pytest.raises(ValueError, match=expected):
        _parse_and_validate(runtime, _valid_release())


def test_validator_accepts_the_fixed_controlled_llm_gateway() -> None:
    runtime = (
        _valid_runtime()
        .replace(
            "KB_LLM_EGRESS_MODE=strict_offline",
            "KB_LLM_EGRESS_MODE=controlled_gateway",
        )
        .replace(
            "KB_LLM_EGRESS_GATEWAY_URL=",
            "KB_LLM_EGRESS_GATEWAY_URL=http://llm-egress:8080",
        )
        .replace(
            "KB_LLM_EGRESS_APPROVED_PROVIDERS=",
            "KB_LLM_EGRESS_APPROVED_PROVIDERS=deepseek",
        )
    )

    _parse_and_validate(runtime, _valid_release())


def test_initial_install_requires_a_non_example_bootstrap_password() -> None:
    validator = _validator()
    parsed_release = validator._parse(  # noqa: SLF001
        _TextPath(_valid_release()),
        accepted_keys=validator._RELEASE_KEYS,  # noqa: SLF001
        release=True,
    )
    placeholder_runtime = validator._parse(  # noqa: SLF001
        _TextPath(_valid_runtime()),
        accepted_keys=validator._RUNTIME_KEYS,  # noqa: SLF001
        release=False,
    )
    with pytest.raises(ValueError, match="initial installation requires"):
        validator._validate(  # noqa: SLF001
            placeholder_runtime,
            parsed_release,
            require_bootstrap_password=True,
        )

    reviewed_runtime = validator._parse(  # noqa: SLF001
        _TextPath(
            _valid_runtime().replace(
                "REPLACE_WITH_A_UNIQUE_ADMIN_PASSWORD",
                "Reviewed-Admin-Password-2026",
            )
        ),
        accepted_keys=validator._RUNTIME_KEYS,  # noqa: SLF001
        release=False,
    )
    validator._validate(  # noqa: SLF001
        reviewed_runtime,
        parsed_release,
        require_bootstrap_password=True,
    )


@pytest.mark.parametrize(
    ("keyring", "active_version", "expected"),
    [
        ("{}", "1", "non-empty object"),
        ('{"1":"too-short"}', "1", "32-byte base64url"),
        (
            '{"1":"cnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnI=",'
            '"1":"cnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnI="}',
            "1",
            "duplicated",
        ),
        (
            '{"01":"cnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnI="}',
            "1",
            "positive integer strings",
        ),
        (
            '{"2":"cnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnI="}',
            "1",
            "active chat replay key version",
        ),
    ],
)
def test_validator_rejects_missing_weak_or_inactive_chat_replay_keys(
    keyring: str,
    active_version: str,
    expected: str,
) -> None:
    runtime = (
        _valid_runtime()
        .replace(
            '{"1":"cnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnI="}',
            keyring,
        )
        .replace(
            "KB_CHAT_REPLAY_ACTIVE_KEY_VERSION=1",
            f"KB_CHAT_REPLAY_ACTIVE_KEY_VERSION={active_version}",
        )
    )
    with pytest.raises(ValueError, match=expected):
        _parse_and_validate(runtime, _valid_release())


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ("UNREVIEWED_ENDPOINT=https://example.com\n", "unknown environment key"),
        ("KB_API_IMAGE=example/override@sha256:" + "d" * 64 + "\n", "unknown environment key"),
        ("POSTGRES_PASSWORD=duplicate\n", "duplicate environment key"),
    ],
)
def test_validator_rejects_unknown_cross_boundary_or_duplicate_runtime_keys(
    extra: str,
    expected: str,
) -> None:
    with pytest.raises(ValueError, match=expected):
        _parse_and_validate(_valid_runtime() + extra, _valid_release())


def test_validator_rejects_unknown_release_environment_keys() -> None:
    with pytest.raises(ValueError, match="unknown release environment key"):
        _parse_and_validate(
            _valid_runtime(),
            _valid_release() + "POSTGRES_PASSWORD=must-not-be-in-release\n",
        )


@pytest.mark.parametrize(
    "bad_reference",
    [
        "example/migration:latest",
        "example/migration@sha256:" + "0" * 64,
        "example/migration@sha256:" + "g" * 64,
    ],
)
def test_validator_rejects_unpinned_or_placeholder_migration_images(
    bad_reference: str,
) -> None:
    release = _valid_release().replace(
        "127.0.0.1:5000/heyi-release/migration@sha256:" + "b" * 64,
        bad_reference,
    )
    with pytest.raises(ValueError, match="KB_MIGRATION_IMAGE"):
        _parse_and_validate(_valid_runtime(), release)


def test_validator_treats_environment_as_data_and_rejects_command_substitution() -> None:
    runtime = _valid_runtime().replace(
        "POSTGRES_PASSWORD=REPLACE_WITH_URL_SAFE_RANDOM_VALUE",
        "POSTGRES_PASSWORD=$(touch should-never-run)",
        1,
    )
    with pytest.raises(ValueError, match="unsafe value for POSTGRES_PASSWORD"):
        _parse_and_validate(runtime, _valid_release())


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (
            "KB_PUBLIC_HOST=10.0.0.10",
            "KB_PUBLIC_HOST=example.com",
            "KB_PUBLIC_HOST must be an approved private or local address",
        ),
        (
            "KB_BIND_ADDRESS=10.0.0.10",
            "KB_BIND_ADDRESS=0.0.0.0",
            "KB_BIND_ADDRESS must be an approved private or local address",
        ),
        (
            "KB_PUBLIC_ORIGIN=https://10.0.0.10:19443",
            "KB_PUBLIC_ORIGIN=https://example.com:19443",
            "KB_PUBLIC_ORIGIN must exactly match",
        ),
        (
            'KB_TRUSTED_HOSTS=\'["10.0.0.10","api"]\'',
            "KB_TRUSTED_HOSTS='[\"10.0.0.10\"]'",
            "KB_TRUSTED_HOSTS must contain only",
        ),
        ("KB_CORS_ORIGINS='[]'", "KB_CORS_ORIGINS='[\"*\"]'", "must remain empty"),
        ("KB_OBJECTS_HTTPS_PORT=19444", "KB_OBJECTS_HTTPS_PORT=19443", "must be different"),
    ],
)
def test_validator_rejects_external_or_ambiguous_network_boundaries(
    before: str,
    after: str,
    expected: str,
) -> None:
    with pytest.raises(ValueError, match=expected):
        _parse_and_validate(_valid_runtime().replace(before, after), _valid_release())


@pytest.mark.parametrize("delimiter", ["@", ":", "/", "?", "#", "%"])
def test_validator_rejects_url_delimiters_in_database_passwords(delimiter: str) -> None:
    runtime = _valid_runtime().replace(
        "POSTGRES_APP_PASSWORD=REPLACE_WITH_A_DIFFERENT_URL_SAFE_RANDOM_VALUE",
        f"POSTGRES_APP_PASSWORD=safe{delimiter}host",
    )
    with pytest.raises(ValueError, match="unsafe URL component for POSTGRES_APP_PASSWORD"):
        _parse_and_validate(runtime, _valid_release())


def test_contract_snapshot_rejects_unsafe_sources_and_detects_toctou() -> None:
    script = (DEPLOY / "prepare-offline-contract.sh").read_text(encoding="utf-8")

    assert 'case "$source_path" in' in script and "path must be absolute" in script
    assert 'canonical_source=$(realpath -e -- "$source_path"' in script
    assert "contain no symbolic links" in script
    assert "every ancestor must be owned by root" in script
    assert "ancestor is group or world writable" in script
    assert "NUL data or an overlong line" in script
    assert 'before_digest=$(sha256sum "$source_path"' in script
    assert 'after_digest=$(sha256sum "$source_path"' in script
    assert 'snapshot_digest=$(sha256sum "$destination"' in script
    assert '"$before_digest" != "$after_digest"' in script
    assert '"$before_digest" != "$snapshot_digest"' in script


def test_contract_snapshot_has_one_derived_manifest_and_root_only_runtime() -> None:
    prepare = (DEPLOY / "prepare-offline-contract.sh").read_text(encoding="utf-8")
    common = (DEPLOY / "offline-operation-common.sh").read_text(encoding="utf-8")

    assert "manifest_source=$release_source.images" in prepare
    assert prepare.count("offline_contract_files") == 1
    assert 'offline_contract_files > "$contract_paths"' in prepare
    assert 'done < "$contract_paths"' in prepare
    assert 'copy_release_asset "$relative_path"' in prepare
    assert "for release_asset in" not in prepare
    assert "canonical contract contains an unsafe path" in prepare
    assert "canonical contract contains a non-canonical path" in prepare
    assert "canonical contract contains an empty or duplicate inventory" in prepare
    assert "contract snapshot inventory differs from the canonical contract" in prepare
    assert "find \"$contract_dir\" -type f -printf '%P\\n'" in prepare
    assert "OFFLINE_CONTRACT_ROOT=$OFFLINE_RUNTIME_ROOT/contracts" in common
    assert "install -d -o root -g root -m 0700" in common
    assert "runtime.env\nrelease.env\nrelease.env.images" in common
    assert "contract.sha256" in common
    assert "contract file hashes changed after snapshot" in common


def test_compose_environment_is_fixed_and_caller_overrides_are_cleared() -> None:
    common = (DEPLOY / "offline-operation-common.sh").read_text(encoding="utf-8")

    fixed_path = "OFFLINE_SYSTEM_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    assert fixed_path in common
    for prefix in (
        "KB_[A-Z0-9_]*",
        "COMPOSE_[A-Z0-9_]*",
        "DOCKER_[A-Z0-9_]*",
        "POSTGRES_[A-Z0-9_]*",
        "MINIO_[A-Z0-9_]*",
        "PYTEST_ADDOPTS",
        "PYTHONPATH",
    ):
        assert prefix in common
    runtime_position = common.index('--env-file "$runtime_env_file"')
    release_position = common.index('--env-file "$release_env_file"')
    assert runtime_position < release_position
    assert "offline_verify_contract" in common
    assert "trusted release asset path is writable by non-root" in common
    assert 'if ! offline_verify_release_assets "$prefix" "$contract_dir"; then' in common


def test_full_preflight_uses_only_the_verified_snapshot_for_compose_and_images() -> None:
    script = (DEPLOY / "preflight-offline.sh").read_text(encoding="utf-8")

    assert "prepare-offline-contract.sh" in script
    assert 'contract_sha256=$(offline_verify_contract preflight "$contract_dir")' in script
    assert 'runtime_env_file=$(offline_contract_runtime_env "$contract_dir")' in script
    assert 'release_env_file=$(offline_contract_release_env "$contract_dir")' in script
    assert 'image_manifest=$(offline_contract_manifest "$contract_dir")' in script
    assert 'verify-offline-images.sh" verify' in script
    assert script.count("run --pull never --rm --no-deps") == 3
    assert "offline deployment requirements satisfied; contract_sha256=" in script
    assert '"$KB_HTTPS_PORT:8443:proxy maintenance-page"' in script
    assert '"$KB_OBJECTS_HTTPS_PORT:9443:proxy maintenance-page"' in script
    assert "initial installation requires an unused project identity" in script
    assert "upgrade requires the verified project ownership marker" in script
    assert "upgrade requires an existing verified project deployment" in script
    assert "--require-bootstrap-password" in script


def test_maintenance_preflight_is_render_only_and_never_starts_app_containers() -> None:
    script = (DEPLOY / "preflight-maintenance-offline.sh").read_text(encoding="utf-8")

    assert "config --quiet" in script
    assert "verified project ownership marker is missing" in script
    assert "HTTPS port is occupied by an unverified process" in script
    assert "enterprise CA root is missing or symbolic" in script
    for forbidden in ("run --pull", "up -d", "docker start", "docker stop", "docker exec"):
        assert forbidden not in script


def test_maintenance_transition_records_and_restores_only_the_exact_original_proxy() -> None:
    script = (DEPLOY / "enter-maintenance-offline.sh").read_text(encoding="utf-8")

    assert "original_proxy_running=false" in script
    assert "container_id" in script and "project_label" in script and "service_label" in script
    assert 'if [ "$original_proxy_running" != true ]; then' in script
    assert 'docker start "$proxy_id"' in script
    assert "compose start proxy" not in script
    assert "RESTORE_FAILED" in script
    assert "preflight-maintenance-offline.sh" in script
    assert "preflight-offline.sh" not in script
    assert "original_maintenance_running=false" in script
    assert "exact_original_maintenance_ready" in script
    assert "exact_original_maintenance_preserved" in script
    assert "proxy and maintenance cannot both be running" in script
    assert "candidate maintenance configuration is invalid" in script
    assert "docker run --rm --pull never --network none --read-only" in script
    assert "offline_materialize_release maintenance" in script
    assert "materialized maintenance worker is missing or symbolic" in script
    assert (
        "expected_materialized_root=/srv/heyi-knowledgebases-offline/releases/$contract_sha256"
    ) in script
    assert "snapshot_script_dir=$expected_materialized_root/deploy/tencent" in script
    assert "snapshot_script_dir=$contract_dir/release/deploy/tencent" not in script


def test_business_writer_shutdown_budget_is_bounded_and_never_force_kills() -> None:
    scripts = {
        name: (DEPLOY / name).read_text(encoding="utf-8")
        for name in (
            "deploy-offline.sh",
            "enter-maintenance-offline.sh",
            "install-offline.sh",
        )
    }
    required_services = "api maintenance web llm-egress minio-multipart-gc"

    for script in scripts.values():
        timeout_line = next(
            line
            for line in script.splitlines()
            if line.startswith("business_writer_stop_timeout_seconds=")
        )
        timeout_seconds = int(timeout_line.partition("=")[2])
        assert 140 <= timeout_seconds <= 300

    for name, function_name in (
        ("deploy-offline.sh", "quiesce_owned_business_writers"),
        ("enter-maintenance-offline.sh", "quiesce_business_writers"),
    ):
        block = scripts[name].split(f"{function_name}() {{", 1)[1].split("\n}", 1)[0]
        normalized_block = " ".join(block.replace("\\\n", " ").split())
        assert (
            f'stop --timeout "$business_writer_stop_timeout_seconds" {required_services}'
        ) in normalized_block
        for forbidden in (
            "docker kill",
            "docker rm -f",
            "stop --timeout 30",
            "stop --timeout 60",
            "stop --timeout 130",
        ):
            assert forbidden not in block

    install_stop = (
        scripts["install-offline.sh"]
        .split("stop_exact_install_services() {", 1)[1]
        .split("\n}", 1)[0]
    )
    assert "for service_name in proxy web api maintenance minio-multipart-gc llm-egress" in (
        install_stop
    )
    assert 'docker stop --time "$business_writer_stop_timeout_seconds"' in install_stop
    assert "docker kill" not in install_stop
    assert "docker rm -f" not in install_stop

    for name in ("deploy-offline.sh", "install-offline.sh"):
        removal = scripts[name].split("remove_exact_llm_egress() {", 1)[1].split("\n}", 1)[0]
        stopped_check = "{{.State.Running}}"
        graceful_remove = 'docker rm "$service_ids"'
        assert stopped_check in removal
        assert graceful_remove in removal
        assert removal.index(stopped_check) < removal.index(graceful_remove)
        assert "docker rm -f" not in removal


def test_one_flock_covers_snapshot_preflight_and_maintenance_switch() -> None:
    common = (DEPLOY / "offline-operation-common.sh").read_text(encoding="utf-8")
    enter = (DEPLOY / "enter-maintenance-offline.sh").read_text(encoding="utf-8")

    assert "OFFLINE_LOCK_FILE=$OFFLINE_LOCK_DIRECTORY/heyi-kb-offline.preflight.lock" in common
    assert 'exec 9>"$OFFLINE_LOCK_FILE"' in common
    assert "flock -n 9" in common
    assert "offline_acquire_lock maintenance" in enter
    assert enter.index("offline_acquire_lock maintenance") < enter.index(
        "prepare-offline-contract.sh"
    )
    assert enter.index("prepare-offline-contract.sh") < enter.index(
        'docker stop --time 30 "$proxy_id"'
    )


def test_registry_import_uses_signed_loopback_bundle_not_classic_save_load() -> None:
    script = (DEPLOY / "import-offline-registry-bundle.sh").read_text(encoding="utf-8")

    assert 'openssl dgst -sha256 -verify "$trusted_public_key"' in script
    assert "signed checksum path escapes the bundle" in script
    assert 'cmp -s "$operator_release" "$signed_release"' in script
    assert 'cmp -s "$operator_manifest" "$signed_manifest"' in script
    assert "--publish 127.0.0.1:5000:5000" in script
    assert 'docker pull --platform linux/amd64 "$image"' in script
    assert "RepoDigest differs" in script
    assert "stat.S_ISREG(info.st_mode) and info.st_nlink != 1" in script
    assert "docker network create --driver bridge --ipv6=false" in script
    assert "docker network create --internal --driver bridge" not in script
    assert "com.docker.network.bridge.enable_ip_masquerade=false" in script
    assert "com.docker.network.bridge.enable_icc=false" in script
    assert '--network "container:$registry_container_id"' in script
    assert "--cap-drop ALL --cap-add NET_ADMIN" in script
    assert "/sbin/ip route del default;" in script
    assert "/sbin/ip route add blackhole 127.0.0.11/32 table local" in script
    assert "temporary Registry retained a non-local network route" in script
    assert "registry_startup_command=" in script
    assert "heyi-network-ready" in script
    assert "verify_registry_manifest_and_config" in script
    assert script.count("offline_local_image_config_id registry-import") == 2
    assert "offline_local_image_config_id \\\n  registry-import" in script
    assert '[ "$observed_config_id" != "$expected_id" ]' in script
    assert "manifest bytes differ from the signed content address" in script
    assert "config blob bytes differ from their content address" in script
    assert script.index('verify_registry_manifest_and_config "$image" "$expected_id"') < (
        script.index('docker pull --platform linux/amd64 "$image"')
    )
    assert '--network "$registry_network_id"' in script
    assert 'docker network rm "$registry_network_id"' in script
    assert "docker save" not in script
    assert "docker load" not in script
    assert 'docker rm -f "$registry_container_id"' in script
    assert 'for directory in ("registry", "release", "sbom")' in script
    assert "image SBOM evidence does not match the signed nine-image manifest" in script
    assert "len(images) != 9" in script
    assert '"https://knowledgebases.local/schemas/image-sbom-index-v1.schema.json"' in script
    assert 'scan_identity = record.get("scan_identity")' in script
    assert "scan_identity not in {manifest_digest, config_id}" in script
    assert '"io.heyi.image.scan_identity": scan_identity' in script
    assert "len(set(scan_identities)) != len(images)" in script
    assert "signed release asset inventory differs" in script
    assert "RELEASE_SEQUENCE" in script
    assert "signed release sequence is replayed or downgraded" in script
    assert "AUDITED_NOOP exact signed release is already imported" in script
    assert 'if [ "$release_sequence" -lt "$highest_release_sequence" ]; then' in script
    assert 'if [ "$release_sequence" -eq "$highest_release_sequence" ]; then' in script
    assert '! cmp -s "$highest_release_file" "$expected_highest"' in script
    assert '! cmp -s "$receipt_file" "$expected_receipt"' in script
    assert "verify_local_signed_images" in script
    assert "highest-release.json" in script
    assert ("canonical_trusted_public_key=/etc/heyi-release/trusted-release-public.pem") in script
    assert 'if [ "$trusted_public_key" != "$canonical_trusted_public_key" ]; then' in script
    assert "trusted_key_sha256" in script
    assert "predates the trusted-key binding; re-import is required" in script
    assert "release_assets_sha256" in script
    assert "20260715_0021" in script
    assert "20260714_0020" not in script
    assert "target_schema_head = sys.argv[2]" in script
    assert (
        "tuple(map(int, schema_match.groups())) <= tuple(map(int, target_match.groups()))"
    ) in script
    docker_capacity_gate = script.index("docker_root=$(docker info")
    first_registry_pull = script.index('docker pull --platform linux/amd64 "$image"')
    assert docker_capacity_gate < first_registry_pull
    assert "REGISTRY_UNPACKED_BYTES" in script
    assert "REGISTRY_UNPACKED_INODES" in script
    assert "unpacked_image_kib + 41943040" in script
    assert "signed unpacked-image capacity plus the 40 GiB rollback reserve" in script
    assert "registry_unpacked_inodes + rollback_inode_reserve" in script


def test_registry_import_accepts_a_valid_previous_schema_head_but_rejects_downgrade(
    tmp_path: Path,
) -> None:
    script = (DEPLOY / "import-offline-registry-bundle.sh").read_text(encoding="utf-8")
    program = script.split("highest_release_sequence=$(python3 -I -c '\n", 1)[1].split(
        '\n\' "$highest_release_file" "$release_schema_head" "$trusted_key_digest")',
        1,
    )[0]
    trusted_key_sha256 = "d" * 64
    state = {
        "schema_version": 2,
        "release_sequence": 17,
        "release_id": "previous-release",
        "release_git_sha": "a" * 40,
        "release_schema_head": "20260714_0020",
        "manifest_sha256": "b" * 64,
        "release_assets_sha256": "c" * 64,
        "trusted_key_sha256": trusted_key_sha256,
    }
    state_path = tmp_path / "highest-release.json"

    def validate(
        existing_head: str,
        target_head: str = "20260715_0021",
    ) -> subprocess.CompletedProcess[str]:
        state["release_schema_head"] = existing_head
        state_path.write_text(json.dumps(state), encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                program,
                str(state_path),
                target_head,
                trusted_key_sha256,
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    previous = validate("20260714_0020")
    assert previous.returncode == 0
    assert previous.stdout.strip() == "17"
    assert validate("20260715_0021").returncode == 0
    assert validate("20260716_0022").returncode != 0
    assert validate("not-a-schema-head").returncode != 0

    state["release_sequence"] = True
    state_path.write_text(json.dumps(state), encoding="utf-8")
    boolean_sequence = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(state_path),
            "20260715_0021",
            trusted_key_sha256,
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert boolean_sequence.returncode != 0

    legacy_state = dict(state)
    legacy_state["release_sequence"] = 17
    legacy_state["schema_version"] = 1
    legacy_state.pop("trusted_key_sha256")
    state_path.write_text(json.dumps(legacy_state), encoding="utf-8")
    legacy = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(state_path),
            "20260715_0021",
            trusted_key_sha256,
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert legacy.returncode != 0


def test_every_hashed_release_asset_exists_and_is_copied_into_the_contract() -> None:
    common = (DEPLOY / "offline-operation-common.sh").read_text(encoding="utf-8")
    prepare = (DEPLOY / "prepare-offline-contract.sh").read_text(encoding="utf-8")
    contract_listing = common.split("cat <<'EOF'\n", 1)[1].split("\nEOF", 1)[0]
    release_assets = [
        line.removeprefix("release/")
        for line in contract_listing.splitlines()
        if line.startswith("release/")
    ]

    assert release_assets
    for relative_path in release_assets:
        assert (REPOSITORY / relative_path).is_file(), relative_path
    assert "release/scripts/offline_ca_restore_drill.py" in contract_listing
    assert "release/*)" in prepare
    assert "source_relative=${relative_path#release/}" in prepare
    assert 'copy_release_asset "$relative_path"' in prepare
    assert "for release_asset in" not in prepare
    assert 'copy_release_asset "deploy/' not in prepare
    assert 'copy_release_asset "docker/' not in prepare
    assert 'copy_release_asset "scripts/' not in prepare


def test_deploy_wrapper_keeps_one_contract_and_flock_through_verified_cutover() -> None:
    script = (DEPLOY / "deploy-offline.sh").read_text(encoding="utf-8")
    common = (DEPLOY / "offline-operation-common.sh").read_text(encoding="utf-8")
    inventory_verifier = (DEPLOY / "verify-offline-project-inventory.py").read_text(
        encoding="utf-8"
    )

    lock_position = script.index("offline_acquire_lock deploy")
    snapshot_position = script.index("prepare-offline-contract.sh")
    preflight_position = script.index('preflight-offline.sh"')
    maintenance_position = script.index('enter-maintenance-offline.sh"')
    migration_position = script.index("run --pull never --rm migrate")
    cutover_position = script.index("--business-ready-compose-config-stdin")
    final_verify_position = script.index(
        'final_contract_sha256=$(offline_verify_contract deploy "$contract_dir")'
    )

    assert lock_position < snapshot_position < preflight_position
    assert preflight_position < maintenance_position < migration_position < cutover_position
    assert cutover_position < final_verify_position
    assert '--contract-dir "$contract_dir" --contract-sha256 "$contract_sha256"' in script
    assert '"$runtime_env_file" "$release_env_file"' not in script
    assert script.count('--contract-dir "$contract_dir" --contract-sha256 "$contract_sha256"') >= 2
    assert script.count("offline_compose deploy") >= 5
    writer_stop = (
        'stop --timeout "$business_writer_stop_timeout_seconds" '
        "api maintenance web llm-egress minio-multipart-gc"
    )
    normalized_script = " ".join(script.replace("\\\n", " ").split())
    assert writer_stop in normalized_script
    assert normalized_script.index(writer_stop) < normalized_script.index(
        "run --pull never --rm migrate"
    )
    assert "remained active before migration" in script
    restore_block = script.split("restore_exact_maintenance() {", 1)[1].split("\n}", 1)[0]
    assert restore_block.index("quiesce_owned_business_writers") < restore_block.index(
        "stop_owned_proxy_for_fail_closed_restore"
    )
    assert "RESTORE_FAILED business writers could not be quiesced" in restore_block
    assert "docker compose" not in script
    assert 'docker start "$maintenance_container_id"' in script
    assert "RESTORE_FAILED" in script
    assert "docker system prune" not in script
    assert "docker compose down" not in script
    assert "offline_materialize_release deploy" in script
    assert "internal worker is not running from the materialized release" in script
    assert "validate_completed_installation_state" in script
    assert "install-in-progress.json" in script
    assert "one verified completed-install receipt" in script
    assert "strict_offline could not remove the exact stale LLM gateway" in script
    assert "strict_offline could not remove the exact stale LLM uplink network" in script
    assert "label=com.docker.compose.network=llm-uplink" in script
    assert "{{len .Containers}}" in script
    assert "offline_verify_project_release_labels deploy" in script
    assert 'offline_verify_project_release_labels deploy "$contract_dir"' in script
    assert "verify-offline-project-inventory.py" in common
    assert common.count("--container-inspect-json") == 2
    assert "project topology changed during final verification" in common
    capture = common.split("offline_capture_project_inventory_snapshot() {", 1)[1].split("\n}", 1)[
        0
    ]
    assert '> "$container_ids_raw"' in capture
    assert 'sort "$container_ids_raw" > "$container_ids_file"' in capture
    assert '> "$network_ids_raw"' in capture
    assert 'sort "$network_ids_raw" > "$network_ids_file"' in capture
    assert "|" not in capture.split("docker ps", 1)[1].split("; then", 1)[0]
    assert "|" not in capture.split("docker network ls", 1)[1].split("; then", 1)[0]
    assert "io.heyi.knowledgebases.owner" in inventory_verifier
    assert "com.docker.compose.oneoff" in inventory_verifier
    assert "unexpected Compose volumes remain in the final project" in common
    assert 'sh "$OFFLINE_RELEASE_ROOT/deploy/tencent/enter-maintenance-offline.sh"' in script
    assert "assert_no_orphan_operations" in script
    assert "orphan $operation_service container blocks" in script
    commit_position = script.index("deployment_committed=true")
    provenance_position = script.index("offline_verify_project_release_labels deploy")
    assert provenance_position < commit_position


def test_install_wrapper_keeps_ports_closed_until_strict_business_cutover() -> None:
    script = (DEPLOY / "install-offline.sh").read_text(encoding="utf-8")
    execution_marker = 'verified_contract_sha256=$(offline_verify_contract install "$contract_dir")'
    # The same verifier assignment also appears in the materialized-contract
    # setup path.  The last occurrence is the actual main execution boundary,
    # after all helper function definitions.
    execution = script.rsplit(execution_marker, 1)[1]

    lock_position = script.index("offline_acquire_lock install")
    snapshot_position = script.index("prepare-offline-contract.sh")
    execution_position = script.rindex(execution_marker)
    preflight_position = execution.index('preflight-offline.sh"')
    migration_position = execution.index("run --pull never --rm migrate")
    bootstrap_position = execution.index("write_install_state bootstrapped")
    proxy_position = execution.index("--wait --wait-timeout 120 proxy")
    readiness_position = execution.index("--business-ready-compose-config-stdin")
    final_verify_position = execution.index(
        'final_contract_sha256=$(offline_verify_contract install "$contract_dir")'
    )

    assert lock_position < snapshot_position < execution_position
    assert preflight_position < migration_position
    assert migration_position < bootstrap_position < proxy_position < readiness_position
    assert readiness_position < final_verify_position
    assert "enter-maintenance-offline.sh" not in script
    assert "CLEANUP_FAILED" in script
    assert "install-in-progress.json" in script
    assert "installed-$contract_sha256.json" in script
    assert 'preflight-offline.sh" --resume-install' in script
    assert "installation state does not match this canonical contract" in script
    assert "a different or ambiguous completed installation receipt already exists" in script
    assert 'set -- "$state_directory"/installed-*.json' in script
    assert '[ "$install_state_owned" = true ]' in script
    assert "remove_stopped_resume_oneoffs" in script
    for oneoff_service in (
        "api-preflight",
        "clamav-db-preflight",
        "llm-egress-preflight",
        "migrate",
        "bootstrap",
    ):
        assert oneoff_service in script
    assert "com.docker.compose.oneoff" in script
    assert "running or unverified one-off operations block safe installation resume" in script
    assert "selected_egress_profile" in script
    assert "llm-egress api maintenance web" in script
    assert 'docker stop --time "$business_writer_stop_timeout_seconds"' in script
    assert "docker compose" not in script
    assert "docker system prune" not in script
    assert "docker compose down" not in script
    assert "offline_materialize_release install" in script
    assert "internal worker is not running from the materialized release" in script
    assert "strict_offline could not remove the exact stale LLM gateway" in script
    assert "offline_verify_project_release_labels install" in script


def test_database_operation_gate_serializes_migration_and_bootstrap() -> None:
    wrapper = (DEPLOY / "run-migration-with-lock.py").read_text(encoding="utf-8")
    compose = (DEPLOY / "compose.offline.yml").read_text(encoding="utf-8")
    deploy = (DEPLOY / "deploy-offline.sh").read_text(encoding="utf-8")
    install = (DEPLOY / "install-offline.sh").read_text(encoding="utf-8")

    assert "pg_try_advisory_lock" in wrapper
    assert "pg_advisory_unlock" in wrapper
    assert '(sys.executable, "-m", "app.bootstrap")' in wrapper
    assert '"--migrate-and-bootstrap"' in wrapper
    assert '"--bootstrap-only"' in wrapper
    assert "start_new_session=True" in wrapper
    assert "os.killpg" in wrapper
    assert "KB_BOOTSTRAP_DATABASE_URL" in compose
    assert "/opt/heyi/run-migration-with-lock.py:ro" in compose
    assert "run --pull never --rm bootstrap" not in deploy
    assert "run --pull never --rm bootstrap" not in install


def test_upgrade_requires_signed_current_backup_and_restore_drill() -> None:
    preflight = (DEPLOY / "preflight-offline.sh").read_text(encoding="utf-8")
    verifier = (DEPLOY / "verify-upgrade-backup.py").read_text(encoding="utf-8")

    assert 'if [ "$preflight_mode" = upgrade ]; then' in preflight
    assert "upgrade requires signed backup and restore-drill evidence" in preflight
    assert 'verify-upgrade-backup.py"' in preflight
    assert "--expected-manifest-sha256" in preflight
    assert '"status"] != "passed"' in verifier
    assert "target_manifest_sha256" in verifier
    assert "database_backup" in verifier
    assert "object_manifest" in verifier
    assert "restore_evidence" in verifier
    assert '"/usr/bin/openssl"' in verifier
    assert "upgrade is blocked by an incomplete installation state" in preflight
    assert "upgrade requires exactly one completed-install receipt" in preflight
    assert "completed-install receipt is unsafe or malformed" in preflight


def test_preflight_parses_llm_contract_and_validates_gateway_config_offline() -> None:
    preflight = (DEPLOY / "preflight-offline.sh").read_text(encoding="utf-8")

    assert "KB_LLM_EGRESS_MODE) KB_LLM_EGRESS_MODE=$value" in preflight
    assert "KB_LLM_EGRESS_GATEWAY_URL) KB_LLM_EGRESS_GATEWAY_URL=$value" in preflight
    assert "controlled egress Caddy contract is invalid" in preflight
    assert "docker run --rm --pull never --network none --read-only" in preflight


def test_offline_shell_entry_points_are_syntactically_valid() -> None:
    scripts = (
        "offline-operation-common.sh",
        "prepare-offline-contract.sh",
        "create-offline-contract.sh",
        "remove-offline-contract.sh",
        "install-offline.sh",
        "deploy-offline.sh",
        "import-offline-registry-bundle.sh",
        "preflight-offline.sh",
        "preflight-maintenance-offline.sh",
        "verify-offline-images.sh",
        "enter-maintenance-offline.sh",
        "rollback-offline.sh",
    )
    for name in scripts:
        completed = subprocess.run(  # noqa: S603
            ["sh", "-n", str(DEPLOY / name)],
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            timeout=10,
        )
        assert completed.returncode == 0, f"{name}: {completed.stderr}"


def test_registry_import_persists_a_release_bound_receipt_required_by_preflight() -> None:
    importer = (DEPLOY / "import-offline-registry-bundle.sh").read_text(encoding="utf-8")
    preflight = (DEPLOY / "preflight-offline.sh").read_text(encoding="utf-8")

    image_import_finished = importer.index('done < "$signed_manifest"')
    cleanup_before_commit = importer.index("if ! cleanup_registry; then", image_import_finished)
    receipt_commit = importer.index(
        "# Persist a root-only, deterministic receipt", cleanup_before_commit
    )

    assert 'kind\\":\\"offline-registry-import' in importer
    assert "registry-import-$manifest_digest.json" in importer
    assert "existing import receipt conflicts with this signature" in importer
    assert 'sync -f "$receipt_directory"' in importer
    receipt_sync = importer.index('sync -f "$receipt_file"')
    directory_barrier = importer.index('sync -f "$receipt_directory"', receipt_sync)
    highest_commit = importer.index('mv -f -- "$temporary_highest"', directory_barrier)
    assert receipt_sync < directory_barrier < highest_commit
    assert image_import_finished < cleanup_before_commit < receipt_commit
    assert "temporary registry resources could not be removed before receipt commit" in importer
    assert "signed registry import receipt is missing or unsafe" in preflight
    assert "signed registry import receipt does not match this release" in preflight
