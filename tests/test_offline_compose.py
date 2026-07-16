from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest
import yaml

REPOSITORY = Path(__file__).resolve().parents[1]


def maintenance_verifier_module() -> Any:
    path = REPOSITORY / "deploy/tencent/verify-maintenance-endpoint.py"
    spec = importlib.util.spec_from_file_location("maintenance_endpoint_verifier", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def offline_compose_config(
    *,
    profiles: tuple[str, ...] = ("ops", "maintenance"),
    environment_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    allowed_environment = os.environ.copy()
    for key in tuple(allowed_environment):
        upper_key = key.upper()
        if upper_key.startswith(
            ("KB_", "COMPOSE_", "DOCKER_", "POSTGRES_", "MINIO_", "CLAMAV_")
        ) or upper_key in {
            "POSTGRES_DB",
            "POSTGRES_USER",
            "POSTGRES_PASSWORD",
            "REDIS_PASSWORD",
            "PYTHONPATH",
            "PYTEST_ADDOPTS",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "PYTHONHOME",
            "PYTHONSTARTUP",
            "PYTHONINSPECT",
            "PYTHONWARNINGS",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        }:
            allowed_environment.pop(key)
    if environment_overrides:
        allowed_environment.update(environment_overrides)
    profile_arguments = [item for profile in profiles for item in ("--profile", profile)]
    completed = subprocess.run(  # noqa: S603
        [
            "docker",
            "compose",
            "--project-name",
            "heyi-kb-offline",
            "--env-file",
            str(REPOSITORY / "deploy/tencent/offline.env.example"),
            "--env-file",
            str(REPOSITORY / "deploy/tencent/release.env.example"),
            "--file",
            str(REPOSITORY / "deploy/tencent/compose.offline.yml"),
            *profile_arguments,
            "config",
        ],
        cwd=REPOSITORY,
        env=allowed_environment,
        capture_output=True,
        check=True,
        shell=False,
        text=True,
        timeout=30,
    )
    parsed = yaml.safe_load(completed.stdout)
    assert isinstance(parsed, dict)
    return parsed


def test_offline_redis_has_only_restart_safe_entrypoint_capabilities() -> None:
    config = offline_compose_config()
    redis = config["services"]["redis"]

    assert set(redis["cap_drop"]) == {"ALL"}
    assert set(redis["cap_add"]) == {
        "CHOWN",
        "DAC_READ_SEARCH",
        "SETGID",
        "SETPCAP",
        "SETUID",
    }
    assert redis["security_opt"] == ["no-new-privileges:true"]
    maxmemory_index = redis["command"].index("--maxmemory")
    assert redis["command"][maxmemory_index + 1] == "512mb"


def test_offline_data_services_do_not_publish_host_ports() -> None:
    config = offline_compose_config()

    for service in ("postgres", "redis", "minio", "clamd", "api", "web"):
        assert not config["services"][service].get("ports"), service
    assert config["networks"]["backend"]["internal"] is True
    assert config["networks"]["frontend"]["internal"] is True
    assert config["networks"]["edge"]["internal"] is True
    assert config["networks"]["backend"]["ipam"]["config"] == [{"subnet": "172.30.241.0/24"}]
    assert config["networks"]["edge"]["ipam"]["config"] == [{"subnet": "172.30.242.0/24"}]
    assert config["networks"]["edge"]["internal"] is True
    assert config["services"]["proxy"]["networks"] == {
        "edge": None,
        "frontend": None,
    }
    edge_services = {
        service_name
        for service_name, service in config["services"].items()
        if "edge" in service.get("networks", {})
    }
    assert edge_services == {"proxy", "maintenance-page"}
    assert config["services"]["maintenance-page"]["networks"] == {"edge": None}


def test_uncommitted_business_and_egress_services_never_auto_restart() -> None:
    config = offline_compose_config(
        profiles=("ops", "maintenance", "controlled-egress"),
        environment_overrides={
            "KB_LLM_EGRESS_MODE": "controlled_gateway",
            "KB_LLM_EGRESS_GATEWAY_URL": "http://llm-egress:8080",
            "KB_LLM_EGRESS_APPROVED_PROVIDERS": "deepseek,qwen,minimax",
        },
    )

    for service_name in (
        "api",
        "maintenance",
        "web",
        "proxy",
        "llm-egress",
        "minio-multipart-gc",
    ):
        assert config["services"][service_name]["restart"] == "no"

    for service_name in ("postgres", "redis", "minio", "clamd", "maintenance-page"):
        assert config["services"][service_name]["restart"] == "unless-stopped"


def test_strict_offline_is_the_default_and_never_materializes_the_egress_service() -> None:
    config = offline_compose_config()

    assert "llm-egress" not in config["services"]
    assert config["services"]["api"]["environment"]["KB_LLM_EGRESS_MODE"] == ("strict_offline")
    assert config["services"]["api"]["environment"]["KB_LLM_EGRESS_GATEWAY_URL"] == ""
    assert config["networks"]["llm-control"]["internal"] is True
    # Compose omits the profile-only uplink when controlled egress is disabled;
    # strict-offline must not materialize an externally routed bridge at all.
    assert "llm-uplink" not in config["networks"]


def test_controlled_egress_has_one_fixed_gateway_and_no_direct_api_uplink() -> None:
    config = offline_compose_config(
        profiles=("ops", "maintenance", "controlled-egress"),
        environment_overrides={
            "KB_LLM_EGRESS_MODE": "controlled_gateway",
            "KB_LLM_EGRESS_GATEWAY_URL": "http://llm-egress:8080",
            "KB_LLM_EGRESS_APPROVED_PROVIDERS": "deepseek,qwen,minimax",
        },
    )
    services = config["services"]
    gateway = services["llm-egress"]

    assert services["api"]["environment"]["KB_LLM_EGRESS_MODE"] == "controlled_gateway"
    assert services["api"]["environment"]["KB_LLM_EGRESS_GATEWAY_URL"] == ("http://llm-egress:8080")
    assert services["api"]["networks"] == {
        "backend": None,
        "frontend": None,
        "llm-control": None,
    }
    assert services["maintenance"]["networks"] == {
        "backend": None,
        "llm-control": None,
    }
    assert gateway["profiles"] == ["controlled-egress"]
    assert gateway["networks"] == {"llm-control": None, "llm-uplink": None}
    assert not gateway.get("ports")
    assert gateway["read_only"] is True
    assert gateway["user"] == "10001:10001"
    assert gateway["cap_drop"] == ["ALL"]
    assert gateway["cap_add"] == ["NET_BIND_SERVICE"]
    assert gateway["security_opt"] == ["no-new-privileges:true"]
    assert gateway["mem_limit"] == "134217728"
    assert gateway["cpus"] == 0.15
    assert gateway["pull_policy"] == "never"
    assert config["networks"]["llm-control"]["internal"] is True
    assert config["networks"]["llm-uplink"].get("internal", False) is False
    uplink_services = {
        name for name, service in services.items() if "llm-uplink" in service.get("networks", {})
    }
    assert uplink_services == {"llm-egress"}


def test_llm_egress_caddyfile_separates_business_routes_from_local_probes() -> None:
    caddyfile = (REPOSITORY / "deploy/tencent/Caddyfile.llm-egress").read_text(encoding="utf-8")
    expected_routes = {
        "/deepseek/chat/completions": "https://api.deepseek.com",
        "/qwen/compatible-mode/v1/chat/completions": "https://dashscope.aliyuncs.com",
        "/minimax/v1/chat/completions": "https://api.minimax.io",
    }

    probe_block = caddyfile[
        caddyfile.index("\t@local_liveness {") : caddyfile.index("\t@deepseek {")
    ]
    business_block = caddyfile[
        caddyfile.index("\t@deepseek {") : caddyfile.index("\t@reviewed_path {")
    ]

    # The credential-carrying surface remains exactly three POST-only routes.
    assert business_block.count("method POST") == len(expected_routes)
    assert business_block.count("reverse_proxy https://") == len(expected_routes)
    assert "remote_ip" not in business_block

    # Liveness and provider route probes are loopback-only and provider probes
    # are rewritten to empty POSTs.  A bridge/host request falls through to the
    # final 404 because no probe path appears in the reviewed business matcher.
    assert probe_block.count("method GET") == len(expected_routes) + 1
    assert probe_block.count("method POST") == len(expected_routes)
    assert probe_block.count("reverse_proxy https://") == len(expected_routes)
    assert probe_block.count("remote_ip 127.0.0.1 ::1") == len(expected_routes) + 1
    assert probe_block.count("status 400 401 403") == len(expected_routes)
    assert probe_block.count('respond "heyi-provider-route-failed-v1" 502') == len(expected_routes)
    assert caddyfile.rstrip().endswith("handle {\n\t\trespond 404\n\t}\n}")
    reviewed_path = caddyfile[
        caddyfile.index("\t@reviewed_path {") : caddyfile.index("\n\thandle @reviewed_path")
    ]
    assert "/_heyi/" not in reviewed_path

    provider_routes = {
        "deepseek": "/deepseek/chat/completions",
        "qwen": "/qwen/compatible-mode/v1/chat/completions",
        "minimax": "/minimax/v1/chat/completions",
    }
    expected_probe_sha256 = {
        "deepseek": "ef69eef517be9aa925c3eed3aeb33840c3a9aaad9e599204287f0ca99f88c5c7",
        "qwen": "0cefb7e073b81c0ba6a655ebf4739eff522f056267c1a38b475170c61263714d",
        "minimax": "d3d272f0634db889b84a193bcc3def9d0c92842fe6740d10940370b5f9c920a3",
    }
    for provider, route in provider_routes.items():
        upstream = expected_routes[route]
        assert caddyfile.count(route) == 2
        assert caddyfile.count(f"reverse_proxy {upstream}") == 2
        assert caddyfile.count(f"tls_server_name {upstream.removeprefix('https://')}") == 2
        assert f"path /_heyi/probe/{provider}" in caddyfile
        exact_body = f"heyi-provider-route-{provider}-v1"
        assert f'respond "{exact_body}" 200' in caddyfile
        assert hashlib.sha256(exact_body.encode()).hexdigest() == (expected_probe_sha256[provider])
    for stripped_header in (
        "Authorization",
        "Cookie",
        "Proxy-Authorization",
        "X-Api-Key",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
    ):
        assert probe_block.count(f"header_up -{stripped_header}") == len(expected_routes)
    for stripped_response_header in ("Location", "Set-Cookie", "WWW-Authenticate"):
        assert probe_block.count(f"header -{stripped_response_header}") == 2 * len(expected_routes)

    live_body = "heyi-llm-egress-live-v1"
    assert "path /_heyi/health/live" in probe_block
    assert 'respond "heyi-llm-egress-live-v1" 200' in probe_block
    assert hashlib.sha256(live_body.encode()).hexdigest() == (
        "2317a728584609144fec1b10db497c29614244fcdc1d769ec031ce6a3f90255f"
    )

    config = offline_compose_config(
        profiles=("ops", "maintenance", "controlled-egress"),
        environment_overrides={
            "KB_LLM_EGRESS_MODE": "controlled_gateway",
            "KB_LLM_EGRESS_GATEWAY_URL": "http://llm-egress:8080",
            "KB_LLM_EGRESS_APPROVED_PROVIDERS": "deepseek,qwen,minimax",
        },
    )
    healthcheck = config["services"]["llm-egress"]["healthcheck"]["test"]
    assert healthcheck[:4] == ["CMD", "/bin/busybox", "sh", "-ec"]
    assert "/bin/busybox wget -q -t 1 -T 2 -O -" in healthcheck[4]
    assert hashlib.sha256(live_body.encode()).hexdigest() in healthcheck[4]

    assert "output discard" in caddyfile
    assert "max_size 8MB" in caddyfile
    assert "respond 405" in caddyfile
    assert "respond 404" in caddyfile
    assert "forward_proxy" not in caddyfile
    assert "tls_insecure_skip_verify" not in caddyfile
    assert "0.0.0.0" not in caddyfile


def test_controlled_egress_preflight_verifies_caddy_and_health_applets() -> None:
    script = (REPOSITORY / "deploy/tencent/preflight-offline.sh").read_text(encoding="utf-8")

    assert "--cap-drop ALL --cap-add NET_BIND_SERVICE" in script
    assert "--entrypoint /bin/busybox" in script
    assert '"$egress_image" --list' in script
    assert "for required_applet in sh wget sha256sum" in script


def test_offline_minio_healthcheck_uses_readiness_not_liveness() -> None:
    config = offline_compose_config()

    assert config["services"]["minio"]["healthcheck"]["test"] == [
        "CMD",
        "curl",
        "-f",
        "http://127.0.0.1:9000/minio/health/ready",
    ]


def test_offline_api_healthcheck_uses_the_only_trusted_host() -> None:
    config = offline_compose_config()
    api = config["services"]["api"]
    healthcheck = api["healthcheck"]["test"]

    assert healthcheck[:2] == ["CMD", "python"]
    assert "http://127.0.0.1:8000/health/ready" in healthcheck[3]
    assert "headers={'Host':'10.0.0.10'}" in healthcheck[3]


def test_offline_application_services_receive_the_required_chat_replay_keyring() -> None:
    config = offline_compose_config()

    for service_name in ("migrate", "bootstrap", "api", "maintenance"):
        environment = config["services"][service_name]["environment"]
        assert environment["KB_CHAT_REPLAY_ENCRYPTION_KEYS"] == (
            '{"1":"REPLACE_WITH_32_BYTE_BASE64URL_KEY"}'
        )
        assert environment["KB_CHAT_REPLAY_ACTIVE_KEY_VERSION"] == "1"


def test_offline_preflight_api_is_secret_free_and_network_isolated() -> None:
    config = offline_compose_config()
    service = config["services"]["api-preflight"]

    assert service["profiles"] == ["ops"]
    assert service["network_mode"] == "none"
    assert not service.get("networks")
    assert not service.get("environment")
    assert service["read_only"] is True
    capacity_mount = next(
        mount for mount in service["volumes"] if mount["target"] == "/var/lib/kb-capacity"
    )
    assert capacity_mount["read_only"] is True
    assert all(mount["target"] != "/var/lib/kb-chat-safety" for mount in service["volumes"])


def test_offline_resources_carry_the_explicit_stack_owner_labels() -> None:
    config = offline_compose_config()
    expected = {
        "io.heyi.knowledgebases.owner": "jiangsu-heyi-knowledgebases",
        "io.heyi.knowledgebases.stack": "offline",
    }

    for service_name, service in config["services"].items():
        assert service["labels"] == expected, service_name
    for network_name, network in config["networks"].items():
        assert network["labels"] == expected, network_name


def test_offline_images_are_content_addressed() -> None:
    config = offline_compose_config()

    for service_name, service in config["services"].items():
        image = service.get("image")
        if image is not None:
            assert "@sha256:" in image, service_name
            assert len(image.rsplit("@sha256:", maxsplit=1)[1]) == 64, service_name


def test_offline_compose_uses_exported_amd64_platform_digests() -> None:
    compose_text = (REPOSITORY / "deploy/tencent/compose.offline.yml").read_text(encoding="utf-8")
    expected_platform_images = {
        "127.0.0.1:5000/heyi-mirror/docker.io/library/postgres:17.5-bookworm@sha256:2088c1744625793a8a89118d2dee63fb121139141ff0ff53bd72e63bb6089d0d",
        "127.0.0.1:5000/heyi-mirror/docker.io/library/redis:8.0.3-bookworm@sha256:97a98080e13ec15bc4684baa57e6f25a8cbce5c0372789194d04bfd178cb34d4",
        "127.0.0.1:5000/heyi-mirror/quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z@sha256:3f97c5651cb6662b880c787a232b6b34fec8d8922e08d6617b25d241a21164bb",
        "127.0.0.1:5000/heyi-mirror/quay.io/minio/mc:RELEASE.2025-04-16T18-13-26Z@sha256:2582c2f48b1e31545143ba5285c67d7b38c8b8f6912142d0630686dc7aaac28b",
        "127.0.0.1:5000/heyi-mirror/docker.io/library/caddy:2.10.2-alpine@sha256:d8c17a862962def15cde69863a3a463f25a2664942eafd7bdbf050e9c3116b83",
    }
    for image in expected_platform_images:
        assert image in compose_text

    retired_multi_arch_indexes = {
        "fbcea1bd13b6a882cd6caa6b58db3ae5c102efe50ec625b3e2a5cbc50db5bfe4",
        "be0a135f1955140436b9114da96dd22fbedb874469400b6ef458cc0d42155de0",
        "a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e",
        "aead63c77f9db9107f1696fb08ecb0faeda23729cde94b0f663edf4fe09728e3",
        "4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d",
    }
    assert all(digest not in compose_text for digest in retired_multi_arch_indexes)


def test_offline_application_images_are_preloaded_and_never_built_or_pulled() -> None:
    config = offline_compose_config()

    for service_name in ("migrate", "bootstrap", "api", "maintenance", "web"):
        service = config["services"][service_name]
        assert "build" not in service, service_name
        assert service["pull_policy"] == "never", service_name

    assert config["services"]["migrate"]["image"].startswith(
        "127.0.0.1:5000/heyi-release/migration@sha256:"
    )
    assert config["services"]["migrate"]["image"] != config["services"]["api"]["image"]


def test_offline_image_verifier_rejects_mutable_manifest_entries() -> None:
    script = (REPOSITORY / "deploy/tencent/verify-offline-images.sh").read_text(encoding="utf-8")

    assert "image must be pinned by sha256 digest" in script
    assert "RepoDigests" in script
    assert "local image RepoDigest does not match manifest" in script
    assert "local image ID differs from the signed manifest" in script
    assert "local image platform must be linux/amd64" in script
    assert "classic docker save/load does not preserve RepoDigests" in script


def test_offline_image_verifier_has_one_canonical_contract_interface() -> None:
    script = (REPOSITORY / "deploy/tencent/verify-offline-images.sh").read_text(encoding="utf-8")

    assert "verify --contract-dir DIR --contract-sha256 SHA256" in script
    assert "generate /absolute/path/to/runtime.env /absolute/path/to/release.env" in script
    assert "manifest=$release_env_file.images" in script
    assert "manifest does not match docker compose config --images" in script
    assert "expected_id expected_os expected_arch" in script


def test_offline_web_uses_a_fixed_public_origin_for_csrf_validation() -> None:
    config = offline_compose_config()

    assert config["services"]["web"]["environment"]["KB_PUBLIC_ORIGIN"] == (
        "https://10.0.0.10:19443"
    )


def test_release_environment_is_loaded_after_runtime_and_owns_all_app_images(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KB_API_IMAGE", "127.0.0.1:5000/attacker/api@sha256:" + "d" * 64)
    monkeypatch.setenv("KB_MIGRATION_IMAGE", "127.0.0.1:5000/attacker/migration@sha256:" + "e" * 64)
    monkeypatch.setenv("KB_WEB_IMAGE", "127.0.0.1:5000/attacker/web@sha256:" + "f" * 64)
    config = offline_compose_config()
    runtime_text = (REPOSITORY / "deploy/tencent/offline.env.example").read_text(encoding="utf-8")
    release_text = (REPOSITORY / "deploy/tencent/release.env.example").read_text(encoding="utf-8")
    common = (REPOSITORY / "deploy/tencent/offline-operation-common.sh").read_text(encoding="utf-8")

    for key in ("KB_API_IMAGE", "KB_MIGRATION_IMAGE", "KB_WEB_IMAGE"):
        assert f"{key}=" not in runtime_text
        assert release_text.count(f"{key}=") == 1
    release_values = {
        key: value
        for line in release_text.splitlines()
        if line and not line.startswith("#")
        for key, value in [line.split("=", 1)]
    }
    assert common.index('--env-file "$runtime_env_file"') < common.index(
        '--env-file "$release_env_file"'
    )
    assert config["services"]["api"]["image"] == release_values["KB_API_IMAGE"]
    assert config["services"]["migrate"]["image"] == release_values["KB_MIGRATION_IMAGE"]
    assert config["services"]["web"]["image"] == release_values["KB_WEB_IMAGE"]


def test_maintenance_page_is_independent_and_mutually_exclusive_with_proxy() -> None:
    config = offline_compose_config()
    maintenance_page = config["services"]["maintenance-page"]
    proxy = config["services"]["proxy"]

    assert maintenance_page["profiles"] == ["maintenance"]
    assert "depends_on" not in maintenance_page
    assert maintenance_page["networks"] == {"edge": None}
    assert maintenance_page["ports"] == proxy["ports"]
    assert len(maintenance_page["ports"]) == 2
    assert maintenance_page["volumes"][1:] == proxy["volumes"][1:]
    assert maintenance_page["healthcheck"]["test"] == [
        "CMD",
        "/bin/busybox",
        "nc",
        "-z",
        "-w",
        "2",
        "127.0.0.1",
        "8443",
    ]

    caddyfile = (REPOSITORY / "deploy/tencent/Caddyfile.maintenance").read_text(encoding="utf-8")
    assert 'respond `{"status":"ok","mode":"maintenance","traffic":"blocked"}` 200' in caddyfile
    assert "maintenance_mode" in caddyfile
    assert caddyfile.count(" 503") == 3
    assert "reverse_proxy" not in caddyfile
    assert "系统正在受控维护，请稍后重试。" in caddyfile
    assert "企业知识中台正在维护" in caddyfile


def test_runtime_maintenance_verifier_requires_503_for_every_business_sample(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    verifier = maintenance_verifier_module()
    ca_bundle = tmp_path / "root.crt"
    ca_bundle.write_text("test-only", encoding="utf-8")
    requested_targets: list[tuple[str, str]] = []
    monkeypatch.setattr(
        verifier,
        "_compose_contract",
        lambda _document: (
            "https://10.0.0.10:19443",
            "https://10.0.0.10:19444",
            ca_bundle,
        ),
    )
    monkeypatch.setattr(verifier.ssl, "create_default_context", lambda **_kwargs: object())

    def fake_request_status(_origin: str, path: str, _context: object) -> tuple[int, str, bytes]:
        requested_targets.append((_origin, path))
        if path == "/maintenance/ready":
            return (
                200,
                "application/json",
                json.dumps({"status": "ok", "mode": "maintenance", "traffic": "blocked"}).encode(),
            )
        if path.startswith("/api/") or path in {"/health/ready", "/openapi.json"}:
            return (
                503,
                "application/json",
                b'{"error":{"code":"maintenance_mode"}}',
            )
        if _origin.endswith(":19444"):
            return 503, "application/json", b'{"error":{"code":"maintenance_mode"}}'
        return 503, "text/html", b"maintenance"

    monkeypatch.setattr(verifier, "_request_status", fake_request_status)

    verifier.verify_maintenance_contract({})

    assert requested_targets == [
        ("https://10.0.0.10:19443", "/maintenance/ready"),
        *(("https://10.0.0.10:19443", path) for path in verifier._BUSINESS_PATHS),
        ("https://10.0.0.10:19444", "/"),
    ]


def test_runtime_maintenance_verifier_rejects_any_reachable_business_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    verifier = maintenance_verifier_module()
    ca_bundle = tmp_path / "root.crt"
    ca_bundle.write_text("test-only", encoding="utf-8")
    monkeypatch.setattr(
        verifier,
        "_compose_contract",
        lambda _document: (
            "https://10.0.0.10:19443",
            "https://10.0.0.10:19444",
            ca_bundle,
        ),
    )
    monkeypatch.setattr(verifier.ssl, "create_default_context", lambda **_kwargs: object())

    def unsafe_request_status(_origin: str, path: str, _context: object) -> tuple[int, str, bytes]:
        if path == "/maintenance/ready":
            return (
                200,
                "application/json",
                b'{"status":"ok","mode":"maintenance","traffic":"blocked"}',
            )
        return 200, "text/html", b"unsafe business response"

    monkeypatch.setattr(verifier, "_request_status", unsafe_request_status)

    with pytest.raises(ValueError, match="business path did not fail closed"):
        verifier.verify_maintenance_contract({})


def test_offline_api_uses_a_distinct_non_admin_database_identity() -> None:
    config = offline_compose_config()
    api_database = urlparse(config["services"]["api"]["environment"]["KB_DATABASE_URL"])
    migration_database = urlparse(config["services"]["migrate"]["environment"]["KB_DATABASE_URL"])

    assert api_database.username == "knowledge-runtime"
    assert migration_database.username == "knowledge"
    assert api_database.username != migration_database.username


def test_runtime_database_role_is_initialized_without_cluster_privileges() -> None:
    script = (REPOSITORY / "docker/postgres/init-runtime-role.sh").read_text(encoding="utf-8")

    for restriction in (
        "NOSUPERUSER",
        "NOCREATEDB",
        "NOCREATEROLE",
        "NOREPLICATION",
        "NOBYPASSRLS",
    ):
        assert restriction in script
    assert "ALTER DEFAULT PRIVILEGES" in script
    assert "GRANT SELECT, INSERT, UPDATE, DELETE" in script


def test_runtime_database_role_cannot_mutate_audit_logs() -> None:
    script = (REPOSITORY / "docker/postgres/init-runtime-role.sh").read_text(encoding="utf-8")

    assert "REVOKE UPDATE, DELETE, TRUNCATE" in script
    assert "GRANT SELECT, INSERT ON TABLE public.audit_logs" in script
    assert "CREATE EVENT TRIGGER enforce_audit_log_runtime_privileges" in script
    assert "ON ddl_command_end" in script
    assert "WHEN TAG IN ('CREATE TABLE', 'ALTER TABLE')" in script


def test_offline_preflight_rejects_shared_database_identity() -> None:
    script = (REPOSITORY / "deploy/tencent/preflight-offline.sh").read_text(encoding="utf-8")

    assert '[ "$POSTGRES_USER" != "$POSTGRES_APP_USER" ]' in script
    assert "database owner and runtime role must be different" in script


def test_offline_object_proxy_does_not_log_presigned_request_uris() -> None:
    caddyfile = (REPOSITORY / "deploy/tencent/Caddyfile.offline").read_text(encoding="utf-8")
    object_server = caddyfile.split("https://{$KB_PUBLIC_HOST}:9443", maxsplit=1)[1]

    assert "\n\tlog {" not in object_server


def test_offline_stack_reserves_cpu_and_graceful_shutdown_budget() -> None:
    config = offline_compose_config()
    steady_services = (
        "postgres",
        "redis",
        "minio",
        "minio-multipart-gc",
        "clamd",
        "api",
        "maintenance",
        "web",
        "proxy",
    )

    allocated_cpu = sum(float(config["services"][name]["cpus"]) for name in steady_services)
    allocated_memory = sum(int(config["services"][name]["mem_limit"]) for name in steady_services)
    assert allocated_cpu <= 4.85
    assert allocated_memory <= int(9.375 * 1024**3)
    long_running_request_services = {
        "api": "2m0s",
        "maintenance": "2m0s",
        "web": "2m0s",
    }
    for name, expected_grace_period in long_running_request_services.items():
        assert config["services"][name]["stop_grace_period"] == expected_grace_period

    for name in set(steady_services) - long_running_request_services.keys():
        assert config["services"][name]["stop_grace_period"] == "30s", name

    controlled_config = offline_compose_config(profiles=("ops", "maintenance", "controlled-egress"))
    assert controlled_config["services"]["llm-egress"]["stop_grace_period"] == "2m15s"

    for script_name in (
        "deploy-offline.sh",
        "enter-maintenance-offline.sh",
        "install-offline.sh",
    ):
        script = (REPOSITORY / "deploy/tencent" / script_name).read_text(encoding="utf-8")
        timeout_line = next(
            line
            for line in script.splitlines()
            if line.startswith("business_writer_stop_timeout_seconds=")
        )
        timeout_seconds = int(timeout_line.partition("=")[2])
        assert 140 <= timeout_seconds <= 300
        assert timeout_seconds > 135


def test_offline_one_shot_services_have_bounded_resources_and_processes() -> None:
    config = offline_compose_config()

    for service_name in (
        "minio-init",
        "clamav-db-preflight",
        "api-preflight",
        "migrate",
        "bootstrap",
    ):
        service = config["services"][service_name]
        assert float(service["cpus"]) > 0, service_name
        assert int(service["mem_limit"]) > 0, service_name
        assert int(service["pids_limit"]) > 0, service_name


def test_offline_minio_jobs_use_a_writable_ephemeral_mc_config() -> None:
    config = offline_compose_config()

    for service_name in ("minio-init", "minio-multipart-gc"):
        service = config["services"][service_name]
        assert service["environment"]["MC_CONFIG_DIR"] == "/tmp/.mc"
        assert service["tmpfs"] == ["/tmp:size=32m,mode=1777"]

    for relative_path in (
        "docker/minio/init.sh",
        "docker/minio/cleanup-multipart.sh",
    ):
        script = (REPOSITORY / relative_path).read_text(encoding="utf-8")
        assert 'MC_CONFIG_DIR="${MC_CONFIG_DIR:-/tmp/.mc}"' in script
        assert "export MC_CONFIG_DIR" in script
        assert script.count("    --api S3v4 \\\n    --path on") == 1

    init_script = (REPOSITORY / "docker/minio/init.sh").read_text(encoding="utf-8")
    assert "MinIO did not become ready in time" not in init_script


def test_offline_postgres_tuning_matches_the_shared_host_memory_budget() -> None:
    config = offline_compose_config()
    postgres = config["services"]["postgres"]
    command = postgres["command"]

    assert "max_connections=80" in command
    assert "shared_buffers=512MB" in command
    assert "effective_cache_size=1536MB" in command
    assert "maintenance_work_mem=128MB" in command
    assert "work_mem=4MB" in command
    assert int(postgres["mem_limit"]) == 2 * 1024**3


def test_offline_clamd_is_private_fail_closed_and_required_by_maintenance() -> None:
    config = offline_compose_config()
    clamd = config["services"]["clamd"]
    maintenance = config["services"]["maintenance"]

    assert not clamd.get("ports")
    assert clamd["networks"] == {"backend": None}
    assert set(clamd["cap_drop"]) == {"ALL"}
    assert set(clamd["cap_add"]) == {"SETGID", "SETUID"}
    assert clamd["security_opt"] == ["no-new-privileges:true"]
    assert float(clamd["cpus"]) <= 0.5
    assert clamd["mem_limit"] <= "2g"
    assert maintenance["depends_on"]["clamd"]["condition"] == "service_healthy"
    assert maintenance["environment"]["KB_MALWARE_SCAN_HOST"] == "clamd"
    clamd_config = (REPOSITORY / "docker/clamav/clamd.conf").read_text(encoding="utf-8")
    assert "User clamav" in clamd_config.splitlines()


def test_offline_clamd_uses_operator_supplied_read_only_signature_database() -> None:
    config = offline_compose_config()
    clamd = config["services"]["clamd"]
    preflight = config["services"]["clamav-db-preflight"]

    database_mount = next(
        mount for mount in clamd["volumes"] if mount["target"] == "/var/lib/clamav"
    )
    assert database_mount["source"].endswith("/clamav-db")
    assert database_mount["read_only"] is True
    assert preflight["profiles"] == ["ops"]
    preflight_database_mount = next(
        mount for mount in preflight["volumes"] if mount["target"] == "/var/lib/clamav"
    )
    assert preflight_database_mount == database_mount


def test_offline_api_has_read_only_capacity_probe_and_aligned_hard_upload_limit() -> None:
    config = offline_compose_config()
    api = config["services"]["api"]
    maintenance = config["services"]["maintenance"]

    for service in (api, maintenance):
        capacity_mount = next(
            mount for mount in service["volumes"] if mount["target"] == "/var/lib/kb-capacity"
        )
        assert capacity_mount["source"].endswith("/capacity-probe")
        assert capacity_mount["read_only"] is True
        assert service["environment"]["KB_STORAGE_CAPACITY_PROBE_PATH"] == ("/var/lib/kb-capacity")
        assert (
            service["environment"]["KB_PLATFORM_MAX_UPLOAD_BYTES"]
            == (service["environment"]["KB_MALWARE_SCAN_MAX_STREAM_BYTES"])
        )

    hard_limit = int(api["environment"]["KB_PLATFORM_MAX_UPLOAD_BYTES"])
    clamd_config = (REPOSITORY / "docker/clamav/clamd.conf").read_text(encoding="utf-8")
    directives = {
        parts[0]: int(parts[1])
        for line in clamd_config.splitlines()
        if len(parts := line.split()) == 2
        and parts[0]
        in {
            "StreamMaxLength",
            "MaxScanSize",
            "MaxFileSize",
        }
    }
    assert directives == {
        "StreamMaxLength": hard_limit,
        "MaxScanSize": hard_limit,
        "MaxFileSize": hard_limit,
    }

    chat_safety_mount = next(
        mount for mount in api["volumes"] if mount["target"] == "/var/lib/kb-chat-safety"
    )
    assert chat_safety_mount["source"].endswith("/chat-safety")
    assert chat_safety_mount.get("read_only", False) is False
    assert api["environment"]["KB_CHAT_SAFETY_STATE_PATH"] == (
        "/var/lib/kb-chat-safety/poison.json"
    )
    assert api["environment"]["KB_CHAT_MAX_ACTIVE_REQUESTS"] == "8"


def test_offline_preflight_requires_image_manifest_and_clamav_database_evidence() -> None:
    script = (REPOSITORY / "deploy/tencent/preflight-offline.sh").read_text(encoding="utf-8")
    common = (REPOSITORY / "deploy/tencent/offline-operation-common.sh").read_text(encoding="utf-8")

    assert 'image_manifest=$(offline_contract_manifest "$contract_dir")' in script
    assert 'verify-offline-images.sh" verify' in script
    assert "release.env.images" in common
    assert 'install -d -o root -g root -m 0755 "$KB_DATA_ROOT/capacity-probe"' in script
    assert "chat_safety_directory=$KB_DATA_ROOT/chat-safety" in script
    assert '[ -L "$chat_safety_directory" ]' in script
    assert 'install -d -o 10001 -g 10001 -m 0700 "$chat_safety_directory"' in script
    assert 'chat_safety_uid=$(stat -c %u -- "$chat_safety_directory")' in script
    assert 'chat_safety_gid=$(stat -c %g -- "$chat_safety_directory")' in script
    assert "offline_require_no_chat_safety_poison preflight" in script
    assert script.index("chat_safety_directory=") < script.index("project_marker_volume=")
    assert "shutil.disk_usage(probe)" in script
    assert 'verify-offline-network-cidrs.py"' in script
    assert "172.30.240.0/24" in script
    assert "172.30.241.0/24" in script
    assert "172.30.242.0/24" in script
    assert "172.30.243.0/24" in script
    assert "172.30.244.0/24" in script
    assert "{{.DockerRootDir}}" in script
    assert "at least 40 GiB free for images and rollback" in script
    assert "at least 10 percent and 100000 free inodes" in script
    assert "minimum_total_kib=292968750" in script
    assert "at least 300 GB total capacity" in script
    assert "validate_existing_project_inventory" in script
    assert "existing project resources failed the exact offline ownership inventory" in script
    assert "io.heyi.knowledgebases.owner" in script
    assert "io.heyi.knowledgebases.stack" in script
    assert "com.docker.compose.project.config_files" in script
    run_blocks = [
        block
        for block in script.split('offline_compose preflight "$contract_dir" \\')[1:]
        if "run --pull never --rm --no-deps" in block
    ]
    clamav_blocks = [block for block in run_blocks if "\n  clamav-db-preflight" in block]
    assert len(clamav_blocks) == 1
    for binding in (
        "io.heyi.knowledgebases.contract-sha256",
        "io.heyi.knowledgebases.adoption-transaction",
        "com.docker.compose.project.config_files",
    ):
        assert binding in clamav_blocks[0]


def test_offline_mutation_boundaries_recheck_the_persistent_chat_safety_hold() -> None:
    deploy = (REPOSITORY / "deploy/tencent/deploy-offline.sh").read_text(encoding="utf-8")
    install = (REPOSITORY / "deploy/tencent/install-offline.sh").read_text(encoding="utf-8")

    assert (
        deploy.index("quiesce_owned_business_writers")
        < deploy.index("offline_require_no_chat_safety_poison deploy")
        < deploy.index("--profile ops run --pull never --rm migrate")
    )
    assert (
        install.index('preflight-offline.sh"')
        < install.index("offline_require_no_chat_safety_poison install")
        < install.index("--profile ops run --pull never --rm migrate")
    )


def test_offline_image_and_preflight_require_the_complete_document_parser_toolchain() -> None:
    dockerfile = (REPOSITORY / "Dockerfile").read_text(encoding="utf-8")
    preflight = (REPOSITORY / "deploy/tencent/preflight-offline.sh").read_text(encoding="utf-8")

    for pinned_package in (
        "bubblewrap=0.8.0-2+deb12u1",
        "libreoffice-nogui=4:7.4.7-1+deb12u14",
        "poppler-utils=22.12.0-2+deb12u2",
        "procps=2:4.0.2-3",
    ):
        assert pinned_package in dockerfile
    assert "python -m app.document_parser_preflight --require-all" in preflight
    run_blocks = [
        block
        for block in preflight.split('offline_compose preflight "$contract_dir" \\')[1:]
        if "run --pull never --rm --no-deps" in block
    ]
    api_blocks = [block for block in run_blocks if "\n  api-preflight \\" in block]
    assert len(api_blocks) == 2
    for block in api_blocks:
        assert "io.heyi.knowledgebases.contract-sha256" in block
        assert "io.heyi.knowledgebases.adoption-transaction" in block
        assert "com.docker.compose.project.config_files" in block


def test_offline_public_api_is_routed_before_the_web_fallback() -> None:
    caddyfile = (REPOSITORY / "deploy/tencent/Caddyfile.offline").read_text(encoding="utf-8")

    public_matcher = "@public_api path /api/v1/public/*"
    public_proxy = "reverse_proxy @public_api api:8000"
    web_proxy = "reverse_proxy web:3000"
    assert caddyfile.index(public_matcher) < caddyfile.index(public_proxy)
    assert caddyfile.index(public_proxy) < caddyfile.index(web_proxy)
    public_block = caddyfile.split(public_proxy, 1)[1].split("}", 1)[0]
    for header in (
        "X-KB-Client-IP",
        "X-KB-Client-Timestamp",
        "X-KB-Client-Signature",
    ):
        assert f"header_up -{header}" in public_block


def test_offline_api_metadata_is_lan_local_and_precedes_the_web_fallback() -> None:
    caddyfile = (REPOSITORY / "deploy/tencent/Caddyfile.offline").read_text(encoding="utf-8")

    metadata_matcher = "@api_metadata path /openapi.json /health/live /health/ready"
    metadata_proxy = "reverse_proxy @api_metadata api:8000"
    web_proxy = "reverse_proxy web:3000"
    assert caddyfile.index(metadata_matcher) < caddyfile.index(metadata_proxy)
    assert caddyfile.index(metadata_proxy) < caddyfile.index(web_proxy)
    metadata_block = caddyfile.split(metadata_proxy, 1)[1].split("}", 1)[0]
    for header in (
        "X-KB-Client-IP",
        "X-KB-Client-Timestamp",
        "X-KB-Client-Signature",
    ):
        assert f"header_up -{header}" in metadata_block
    assert "connect-src 'self' https://{$KB_PUBLIC_HOST}:{$KB_OBJECTS_HTTPS_PORT}" in caddyfile
    assert "@api_metadata path /docs" not in caddyfile
    assert "@api_metadata path /redoc" not in caddyfile

    compose = offline_compose_config()
    proxy_environment = compose["services"]["proxy"]["environment"]
    assert proxy_environment["KB_OBJECTS_HTTPS_PORT"] == "19444"


def test_offline_deployment_documentation_matches_the_enforced_release_boundary() -> None:
    deployment = (REPOSITORY / "docs/TENCENT_OFFLINE_ENTERPRISE_DEPLOYMENT.zh-CN.md").read_text(
        encoding="utf-8"
    )
    acceptance_standard = (
        REPOSITORY / "docs/ENTERPRISE_FINAL_ACCEPTANCE_STANDARD.zh-CN.md"
    ).read_text(encoding="utf-8")
    capacity = (REPOSITORY / "docs/PERFORMANCE_CAPACITY_MODEL.zh-CN.md").read_text(encoding="utf-8")

    def final_acceptance_block(document: str) -> str:
        for fenced in document.split("```bash\n")[1:]:
            block, separator, _remainder = fenced.partition("\n```")
            if separator and "scripts/acceptance.py" in block:
                return block
        raise AssertionError("final acceptance Bash block is missing")

    assert final_acceptance_block(deployment) == final_acceptance_block(acceptance_standard)
    assert deployment.count("up -d --pull never --no-build") >= 1
    assert "install-offline.sh" in deployment
    assert "deploy-offline.sh" in deployment
    assert "api-preflight" in deployment
    assert "network_mode: none" in deployment
    assert "`--no-build` 只适用于 `docker compose up`" in deployment
    assert "4.80 vCPU / 8.75 GiB" in deployment
    assert "/api/v1/public/*" in deployment
    assert "source_status.reason=external_processing_disabled" in deployment
    assert "回滚时不执行 `down`" in deployment
    assert "enter-maintenance-offline.sh" in deployment
    assert "rollback-offline.sh" in deployment
    assert "KB_MIGRATION_IMAGE" in deployment
    assert "runtime.env" in deployment
    assert "release.env" in deployment
    assert "| **合计** | **4.80** | **8,960 MiB（8.75 GiB）** |" in capacity
    assert "受控网关 4.95 CPU / 8.875 GiB 稳态上限" in capacity
    assert "当前判定：**FAIL / NO-GO**" in capacity


def test_maintenance_and_rollback_scripts_enforce_safe_command_boundaries() -> None:
    enter = (REPOSITORY / "deploy/tencent/enter-maintenance-offline.sh").read_text(encoding="utf-8")
    rollback = (REPOSITORY / "deploy/tencent/rollback-offline.sh").read_text(encoding="utf-8")
    maintenance_preflight = (
        REPOSITORY / "deploy/tencent/preflight-maintenance-offline.sh"
    ).read_text(encoding="utf-8")

    assert "prepare-offline-contract.sh" in enter
    assert "preflight-maintenance-offline.sh" in enter
    assert "preflight-offline.sh" not in enter
    assert "--pull never" in enter
    assert "--no-build" in enter
    assert "--no-deps" in enter
    for script in (enter, rollback):
        assert " compose down" not in script
        assert "alembic downgrade" not in script
        assert " run migrate" not in script
        assert " run bootstrap" not in script

    assert 'docker stop --time 30 "$proxy_id"' in enter
    assert 'docker start "$proxy_id"' in enter
    assert "compose start proxy" not in enter
    assert "original_proxy_running" in enter
    assert "RESTORE_FAILED" in enter
    assert "verify-maintenance-endpoint.py" in enter
    assert "quiesce_business_writers" in enter
    quiesce_block = enter.split("quiesce_business_writers() {", 1)[1].split("\n}", 1)[0]
    normalized_quiesce = " ".join(quiesce_block.replace("\\\n", " ").split())
    assert (
        'stop --timeout "$business_writer_stop_timeout_seconds" '
        "api maintenance web llm-egress minio-multipart-gc"
    ) in normalized_quiesce
    for forbidden in ("docker kill", "docker rm -f", "stop --timeout 30", "stop --timeout 60"):
        assert forbidden not in quiesce_block
    assert "maintenance_ready_writers_quiesced" in enter
    assert "--compose-config-stdin" in enter
    assert 'sh "$script_dir/enter-maintenance-offline.sh"' in rollback
    assert "docker compose" not in rollback
    assert "compose up" not in rollback
    assert "compose start" not in rollback
    assert "compose exec" not in rollback
    assert "schema-only shim" in rollback
    assert "business traffic remains blocked" in rollback
    assert "complete forward-fix" in rollback
    for forbidden in ("run --pull", "up -d", "docker start", "docker stop", "docker exec"):
        assert forbidden not in maintenance_preflight
    assert "config --quiet" in maintenance_preflight


def test_offline_public_api_trusts_only_the_fixed_internal_proxy_network() -> None:
    config = offline_compose_config()

    assert config["networks"]["frontend"]["internal"] is True
    assert config["networks"]["frontend"]["ipam"]["config"] == [{"subnet": "172.30.240.0/24"}]
    assert config["services"]["api"]["environment"]["KB_TRUSTED_PROXY_CIDRS"] == (
        '["172.30.240.0/24"]'
    )
