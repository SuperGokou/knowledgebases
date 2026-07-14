from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

REPOSITORY = Path(__file__).resolve().parents[1]


def offline_compose_config() -> dict[str, Any]:
    completed = subprocess.run(  # noqa: S603
        [
            "docker",
            "compose",
            "--project-name",
            "heyi-kb-offline",
            "--env-file",
            str(REPOSITORY / "deploy/tencent/offline.env.example"),
            "--file",
            str(REPOSITORY / "deploy/tencent/compose.offline.yml"),
            "--profile",
            "ops",
            "config",
        ],
        cwd=REPOSITORY,
        capture_output=True,
        check=True,
        shell=False,
        text=True,
        timeout=30,
    )
    parsed = yaml.safe_load(completed.stdout)
    assert isinstance(parsed, dict)
    return parsed


def test_offline_redis_has_only_entrypoint_initialization_capabilities() -> None:
    config = offline_compose_config()
    redis = config["services"]["redis"]

    assert set(redis["cap_drop"]) == {"ALL"}
    assert set(redis["cap_add"]) == {"CHOWN", "SETGID", "SETUID"}
    maxmemory_index = redis["command"].index("--maxmemory")
    assert redis["command"][maxmemory_index + 1] == "512mb"


def test_offline_data_services_do_not_publish_host_ports() -> None:
    config = offline_compose_config()

    for service in ("postgres", "redis", "minio", "clamd", "api", "web"):
        assert not config["services"][service].get("ports"), service
    assert config["networks"]["backend"]["internal"] is True
    assert config["networks"]["frontend"]["internal"] is True
    assert config["networks"]["edge"].get("internal", False) is False
    assert config["networks"]["backend"]["ipam"]["config"] == [
        {"subnet": "172.30.241.0/24"}
    ]
    assert config["networks"]["edge"]["ipam"]["config"] == [
        {"subnet": "172.30.242.0/24"}
    ]
    assert config["services"]["proxy"]["networks"] == {
        "edge": None,
        "frontend": None,
    }
    for service_name, service in config["services"].items():
        if service_name != "proxy":
            assert "edge" not in service.get("networks", {}), service_name


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


def test_offline_images_are_content_addressed() -> None:
    config = offline_compose_config()

    for service_name, service in config["services"].items():
        image = service.get("image")
        if image is not None:
            assert "@sha256:" in image, service_name
            assert len(image.rsplit("@sha256:", maxsplit=1)[1]) == 64, service_name


def test_offline_compose_uses_exported_amd64_platform_digests() -> None:
    compose_text = (REPOSITORY / "deploy/tencent/compose.offline.yml").read_text(
        encoding="utf-8"
    )
    expected_platform_images = {
        "postgres:17.5-bookworm@sha256:2088c1744625793a8a89118d2dee63fb121139141ff0ff53bd72e63bb6089d0d",
        "redis:8.0.3-bookworm@sha256:97a98080e13ec15bc4684baa57e6f25a8cbce5c0372789194d04bfd178cb34d4",
        "quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z@sha256:3f97c5651cb6662b880c787a232b6b34fec8d8922e08d6617b25d241a21164bb",
        "quay.io/minio/mc:RELEASE.2025-04-16T18-13-26Z@sha256:2582c2f48b1e31545143ba5285c67d7b38c8b8f6912142d0630686dc7aaac28b",
        "caddy:2.10.2-alpine@sha256:d8c17a862962def15cde69863a3a463f25a2664942eafd7bdbf050e9c3116b83",
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


def test_offline_image_verifier_rejects_mutable_manifest_entries() -> None:
    script = (REPOSITORY / "deploy/tencent/verify-offline-images.sh").read_text(
        encoding="utf-8"
    )

    assert "image must be pinned by sha256 digest" in script
    assert "RepoDigests" in script
    assert "local image digest does not match manifest" in script


def test_offline_image_verifier_closes_mutable_and_mismatched_paths(
    tmp_path: Path,
) -> None:
    fake_docker = tmp_path / "docker"
    fake_docker.write_text(
        """#!/usr/bin/env sh
set -eu
if [ "$1" = "compose" ]; then
  printf '%s\\n' "$FAKE_COMPOSE_IMAGE"
elif [ "$1" = "image" ] && [ "$2" = "inspect" ]; then
  printf '%s\\n' "$FAKE_REPO_DIGEST"
else
  exit 64
fi
""",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    env_file = tmp_path / "offline.env"
    env_file.write_text("COMPOSE_PROJECT_NAME=heyi-kb-offline\n", encoding="utf-8")
    manifest = tmp_path / "images.txt"
    verifier = REPOSITORY / "deploy/tencent/verify-offline-images.sh"

    def verify(image: str, repo_digest: str) -> subprocess.CompletedProcess[str]:
        manifest.write_bytes(f"{image}\n".encode())
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f".:{environment['PATH']}",
                "FAKE_COMPOSE_IMAGE": image,
                "FAKE_REPO_DIGEST": repo_digest,
            }
        )
        return subprocess.run(  # noqa: S603
            ["sh", str(verifier), "verify", str(env_file), str(manifest)],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            timeout=30,
        )

    mutable = verify("example/app:release", "example/app@sha256:" + "a" * 64)
    assert mutable.returncode != 0
    assert "must be pinned" in mutable.stderr

    pinned = "example/app:release@sha256:" + "a" * 64
    mismatch = verify(pinned, "example/app@sha256:" + "b" * 64)
    assert mismatch.returncode != 0
    assert "does not match manifest" in mismatch.stderr

    valid = verify(pinned, "example/app@sha256:" + "a" * 64)
    assert valid.returncode == 0, valid.stderr
    assert "every image is loaded" in valid.stdout


def test_offline_web_uses_a_fixed_public_origin_for_csrf_validation() -> None:
    config = offline_compose_config()

    assert config["services"]["web"]["environment"]["KB_PUBLIC_ORIGIN"] == (
        "https://10.0.0.10:19443"
    )


def test_offline_api_uses_a_distinct_non_admin_database_identity() -> None:
    config = offline_compose_config()
    api_database = urlparse(config["services"]["api"]["environment"]["KB_DATABASE_URL"])
    migration_database = urlparse(
        config["services"]["migrate"]["environment"]["KB_DATABASE_URL"]
    )

    assert api_database.username == "knowledge-runtime"
    assert migration_database.username == "knowledge"
    assert api_database.username != migration_database.username


def test_runtime_database_role_is_initialized_without_cluster_privileges() -> None:
    script = (REPOSITORY / "docker/postgres/init-runtime-role.sh").read_text(
        encoding="utf-8"
    )

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
    script = (REPOSITORY / "docker/postgres/init-runtime-role.sh").read_text(
        encoding="utf-8"
    )

    assert "REVOKE UPDATE, DELETE, TRUNCATE" in script
    assert "GRANT SELECT, INSERT ON TABLE public.audit_logs" in script
    assert "CREATE EVENT TRIGGER enforce_audit_log_runtime_privileges" in script
    assert "ON ddl_command_end" in script
    assert "WHEN TAG IN ('CREATE TABLE', 'ALTER TABLE')" in script


def test_offline_preflight_rejects_shared_database_identity() -> None:
    script = (REPOSITORY / "deploy/tencent/preflight-offline.sh").read_text(
        encoding="utf-8"
    )

    assert '[ "$POSTGRES_USER" != "$POSTGRES_APP_USER" ]' in script
    assert "database owner and runtime role must be different" in script


def test_offline_object_proxy_does_not_log_presigned_request_uris() -> None:
    caddyfile = (REPOSITORY / "deploy/tencent/Caddyfile.offline").read_text(
        encoding="utf-8"
    )
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
    allocated_memory = sum(
        int(config["services"][name]["mem_limit"]) for name in steady_services
    )
    assert allocated_cpu <= 4.85
    assert allocated_memory <= int(9.375 * 1024**3)
    for name in steady_services:
        assert config["services"][name]["stop_grace_period"] == "30s", name


def test_offline_one_shot_services_have_bounded_resources_and_processes() -> None:
    config = offline_compose_config()

    for service_name in ("minio-init", "clamav-db-preflight", "migrate", "bootstrap"):
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
    clamd_config = (REPOSITORY / "docker/clamav/clamd.conf").read_text(
        encoding="utf-8"
    )
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
        mount
        for mount in preflight["volumes"]
        if mount["target"] == "/var/lib/clamav"
    )
    assert preflight_database_mount == database_mount


def test_offline_api_has_read_only_capacity_probe_and_aligned_hard_upload_limit() -> None:
    config = offline_compose_config()
    api = config["services"]["api"]
    maintenance = config["services"]["maintenance"]

    for service in (api, maintenance):
        capacity_mount = next(
            mount
            for mount in service["volumes"]
            if mount["target"] == "/var/lib/kb-capacity"
        )
        assert capacity_mount["source"].endswith("/capacity-probe")
        assert capacity_mount["read_only"] is True
        assert service["environment"]["KB_STORAGE_CAPACITY_PROBE_PATH"] == (
            "/var/lib/kb-capacity"
        )
        assert service["environment"]["KB_PLATFORM_MAX_UPLOAD_BYTES"] == (
            service["environment"]["KB_MALWARE_SCAN_MAX_STREAM_BYTES"]
        )

    hard_limit = int(api["environment"]["KB_PLATFORM_MAX_UPLOAD_BYTES"])
    clamd_config = (REPOSITORY / "docker/clamav/clamd.conf").read_text(encoding="utf-8")
    directives = {
        parts[0]: int(parts[1])
        for line in clamd_config.splitlines()
        if len(parts := line.split()) == 2 and parts[0] in {
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


def test_offline_preflight_requires_image_manifest_and_clamav_database_evidence() -> None:
    script = (REPOSITORY / "deploy/tencent/preflight-offline.sh").read_text(
        encoding="utf-8"
    )

    assert "image_manifest=$env_file.images" in script
    assert 'verify-offline-images.sh" verify' in script
    assert 'install -d -o root -g root -m 0755 "$KB_DATA_ROOT/capacity-probe"' in script
    assert 'shutil.disk_usage(probe)' in script
    assert 'verify-offline-network-cidrs.py"' in script
    assert "172.30.240.0/24" in script
    assert "172.30.241.0/24" in script
    assert "run --pull never --rm --no-deps clamav-db-preflight" in script


def test_offline_image_and_preflight_require_the_complete_document_parser_toolchain() -> None:
    dockerfile = (REPOSITORY / "Dockerfile").read_text(encoding="utf-8")
    preflight = (REPOSITORY / "deploy/tencent/preflight-offline.sh").read_text(
        encoding="utf-8"
    )

    for pinned_package in (
        "bubblewrap=0.8.0-2+deb12u1",
        "libreoffice-nogui=4:7.4.7-1+deb12u14",
        "poppler-utils=22.12.0-2+deb12u2",
        "procps=2:4.0.2-3",
    ):
        assert pinned_package in dockerfile
    assert "python -m app.document_parser_preflight --require-all" in preflight


def test_offline_public_api_is_routed_before_the_web_fallback() -> None:
    caddyfile = (REPOSITORY / "deploy/tencent/Caddyfile.offline").read_text(
        encoding="utf-8"
    )

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


def test_offline_deployment_documentation_matches_the_enforced_release_boundary() -> None:
    deployment = (
        REPOSITORY / "docs/TENCENT_OFFLINE_ENTERPRISE_DEPLOYMENT.zh-CN.md"
    ).read_text(encoding="utf-8")
    capacity = (REPOSITORY / "docs/PERFORMANCE_CAPACITY_MODEL.zh-CN.md").read_text(
        encoding="utf-8"
    )

    assert deployment.count("up -d --pull never --no-build") >= 2
    assert deployment.count("--profile ops run --rm --pull never") >= 2
    assert "`--no-build` 只适用于 `docker compose up`" in deployment
    assert "4.80 vCPU / 8.75 GiB" in deployment
    assert "/api/v1/public/*" in deployment
    assert "source_status.reason=external_processing_disabled" in deployment
    assert "回滚时不执行 `down`" in deployment
    assert "4.80 CPU / 8.75 GiB 稳态上限" in capacity
def test_offline_public_api_trusts_only_the_fixed_internal_proxy_network() -> None:
    config = offline_compose_config()

    assert config["networks"]["frontend"]["internal"] is True
    assert config["networks"]["frontend"]["ipam"]["config"] == [
        {"subnet": "172.30.240.0/24"}
    ]
    assert config["services"]["api"]["environment"]["KB_TRUSTED_PROXY_CIDRS"] == (
        '["172.30.240.0/24"]'
    )
