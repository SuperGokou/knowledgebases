import base64
import json

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.db.session import engine_options

_CHAT_REPLAY_KEY = base64.urlsafe_b64encode(b"r" * 32).decode("ascii")


def production_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "production",
        "jwt_secret": "4f" * 32,  # pragma: allowlist secret
        "bootstrap_admin_password": "A-production-admin-password-123!",  # pragma: allowlist secret
        "database_url": (
            "postgresql+psycopg://user:password@db.example.com/postgres"  # pragma: allowlist secret
            "?sslmode=verify-full"
        ),
        "redis_url": (
            "rediss://default:password@"  # pragma: allowlist secret
            "redis.example.com:6379/0"
        ),
        "s3_endpoint_url": "https://objects.example.com",
        "s3_public_endpoint_url": "https://objects.example.com",
        "s3_access_key": "production-access-key",
        "s3_secret_key": "production-secret-key",  # pragma: allowlist secret
        "s3_use_ssl": True,
        "chat_replay_encryption_keys": {1: _CHAT_REPLAY_KEY},
        "chat_replay_active_key_version": 1,
    }
    values.update(overrides)
    return Settings(**values)


def test_jwt_clock_skew_has_a_small_bounded_default() -> None:
    assert Settings(_env_file=None).jwt_clock_skew_seconds == 3
    assert Settings(_env_file=None, jwt_clock_skew_seconds=0).jwt_clock_skew_seconds == 0
    assert Settings(_env_file=None, jwt_clock_skew_seconds=30).jwt_clock_skew_seconds == 30


@pytest.mark.parametrize("clock_skew_seconds", [-1, 31])
def test_jwt_clock_skew_rejects_values_outside_the_security_boundary(
    clock_skew_seconds: int,
) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_clock_skew_seconds=clock_skew_seconds)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("jwt_secret", "dev-only-replace-with-at-least-32-random-characters-0123456789"),
        ("bootstrap_admin_password", "DevOnly-Replace-This-Admin-Password-123!"),
    ],
)
def test_production_rejects_published_example_secrets(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        production_settings(**{field: value})


@pytest.mark.parametrize(
    "password",
    [
        "a" * 16,
        "Lowercase-only-password",
        "UPPERCASE-ONLY-PASSWORD",
        "NoSymbolPassword123",
        "NoNumericPassword!",
        "Whitespace password-123!",
        "Unicode-password-123-" + chr(0x4E2D) + chr(0x6587) + "!",
        "A1!" + ("x" * 254),
    ],
)
def test_production_rejects_weak_or_oversized_bootstrap_admin_password(
    password: str,
) -> None:
    with pytest.raises(ValidationError, match="KB_BOOTSTRAP_ADMIN_PASSWORD"):
        production_settings(bootstrap_admin_password=password)


@pytest.mark.parametrize("password", ["", " \t\r\n"])
def test_production_upgrade_treats_blank_bootstrap_admin_password_as_absent(
    password: str,
) -> None:
    settings = production_settings(bootstrap_admin_password=password)

    assert settings.bootstrap_admin_password is None


def test_production_upgrade_rejects_nonempty_weak_bootstrap_password_without_echoing_it() -> None:
    password = "nonemptybutweakpassword"

    with pytest.raises(ValidationError, match="KB_BOOTSTRAP_ADMIN_PASSWORD") as captured:
        production_settings(bootstrap_admin_password=password)

    assert password not in str(captured.value)


def test_production_upgrade_preserves_a_strong_bootstrap_password_as_a_secret() -> None:
    password = "Strong-upgrade-password-123!"

    settings = production_settings(bootstrap_admin_password=password)

    assert settings.bootstrap_admin_password is not None
    assert settings.bootstrap_admin_password.get_secret_value() == password
    assert password not in str(settings.bootstrap_admin_password)


def test_production_rejects_debug_and_plain_http_object_urls() -> None:
    with pytest.raises(ValidationError):
        production_settings(debug=True)
    with pytest.raises(ValidationError):
        production_settings(s3_public_endpoint_url="http://objects.example.com")
    with pytest.raises(ValidationError):
        production_settings(s3_endpoint_url="http://objects.example.com")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "database_url",
            "postgresql+asyncpg://knowledge:knowledge@"  # pragma: allowlist secret
            "localhost/knowledge",
        ),
        ("redis_url", "redis://127.0.0.1:6379/0"),
    ],
)
def test_production_rejects_local_service_endpoints(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        production_settings(**{field: value})


def test_production_requires_tls_redis_and_exact_cors_origins() -> None:
    with pytest.raises(ValidationError):
        production_settings(
            redis_url=(
                "redis://user:password@"  # pragma: allowlist secret
                "redis.example.com:6379/0"
            )
        )
    with pytest.raises(ValidationError):
        production_settings(cors_origins=("*",))
    with pytest.raises(ValidationError):
        production_settings(cors_origins=("null",))


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg://user:pass@db.example.com/knowledge",
        "postgresql+psycopg://user:pass@db.example.com/knowledge?sslmode=require",
        "postgresql+psycopg://user:pass@db.example.com/knowledge?sslmode=verify-ca",
        "postgresql+asyncpg://user:pass@db.example.com/knowledge?ssl=require",
    ],
)
def test_standard_production_requires_verified_database_tls(database_url: str) -> None:
    with pytest.raises(ValidationError, match="verify-full"):
        production_settings(database_url=database_url)


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg://user:pass@db.example.com/knowledge?sslmode=verify-full",
        "postgresql+asyncpg://user:pass@db.example.com/knowledge?ssl=verify-full",
    ],
)
def test_standard_production_accepts_verified_database_tls(database_url: str) -> None:
    settings = production_settings(database_url=database_url)

    assert settings.database_url == database_url


def test_production_rejects_example_object_storage_credentials() -> None:
    with pytest.raises(ValidationError):
        production_settings(s3_access_key="knowledge")
    with pytest.raises(ValidationError):
        production_settings(s3_secret_key="knowledge-secret")  # pragma: allowlist secret


def test_production_accepts_explicit_secure_values() -> None:
    settings = production_settings()

    assert settings.environment == "production"


def test_production_requires_a_valid_chat_replay_keyring() -> None:
    with pytest.raises(ValidationError, match="CHAT_REPLAY_ENCRYPTION_KEYS"):
        production_settings(
            chat_replay_encryption_keys={},
            chat_replay_active_key_version=None,
        )
    with pytest.raises(ValidationError, match="32-byte base64url"):
        production_settings(
            chat_replay_encryption_keys={1: "not-a-cryptographic-key"},
            chat_replay_active_key_version=1,
        )
    with pytest.raises(ValidationError, match="active key version"):
        production_settings(
            chat_replay_encryption_keys={1: _CHAT_REPLAY_KEY},
            chat_replay_active_key_version=2,
        )


def test_chat_replay_keyring_loads_from_unprefixed_json_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "CHAT_REPLAY_ENCRYPTION_KEYS",
        json.dumps({"7": _CHAT_REPLAY_KEY}),
    )
    monkeypatch.setenv("CHAT_REPLAY_ACTIVE_KEY_VERSION", "7")

    settings = Settings(_env_file=None, environment="test")

    assert settings.chat_replay_active_key_version == 7
    assert settings.chat_replay_encryption_keys[7].get_secret_value() == _CHAT_REPLAY_KEY


def test_isolated_production_accepts_only_compose_local_data_services() -> None:
    settings = production_settings(
        deployment_profile="isolated",
        database_url=("postgresql+asyncpg://knowledge:password@postgres:5432/knowledge"),
        redis_url="redis://:password@redis:6379/0",
        s3_endpoint_url="http://minio:9000",
        s3_public_endpoint_url="https://knowledge.internal:19444",
        malware_scan_host="clamd",
        storage_capacity_probe_path="/var/lib/kb-capacity",
    )

    assert settings.deployment_profile == "isolated"
    assert settings.external_llm_enabled is False
    assert settings.llm_egress_mode == "strict_offline"


def test_llm_egress_mode_defaults_to_strict_offline() -> None:
    settings = Settings(_env_file=None, environment="test")

    assert settings.llm_egress_mode == "strict_offline"
    assert settings.llm_egress_gateway_url is None


def test_isolated_production_accepts_only_the_fixed_controlled_llm_gateway() -> None:
    settings = production_settings(
        deployment_profile="isolated",
        llm_egress_mode="controlled_gateway",
        llm_egress_gateway_url="http://llm-egress:8080",
        llm_egress_approved_providers="deepseek,qwen,minimax",
        database_url="postgresql+asyncpg://knowledge:password@postgres:5432/knowledge",
        redis_url="redis://:password@redis:6379/0",
        s3_endpoint_url="http://minio:9000",
        s3_public_endpoint_url="https://knowledge.internal:19444",
        malware_scan_host="clamd",
        storage_capacity_probe_path="/var/lib/kb-capacity",
    )

    assert settings.llm_egress_mode == "controlled_gateway"
    assert settings.external_llm_enabled is True
    assert settings.llm_egress_gateway_url == "http://llm-egress:8080"
    assert settings.approved_llm_providers == ("deepseek", "qwen", "minimax")


@pytest.mark.parametrize(
    "gateway_url",
    (
        "https://llm-egress:8080",
        "http://llm-egress:8080/",
        "http://127.0.0.1:8080",
        "http://attacker.internal:8080",
    ),
)
def test_controlled_llm_gateway_rejects_every_noncanonical_url(gateway_url: str) -> None:
    with pytest.raises(ValidationError, match="KB_LLM_EGRESS_GATEWAY_URL"):
        Settings(
            _env_file=None,
            environment="test",
            deployment_profile="isolated",
            llm_egress_mode="controlled_gateway",
            llm_egress_gateway_url=gateway_url,
        )


def test_strict_offline_mode_rejects_an_enabled_gateway_url() -> None:
    with pytest.raises(ValidationError, match="must be empty"):
        Settings(
            _env_file=None,
            environment="test",
            llm_egress_mode="strict_offline",
            llm_egress_gateway_url="http://llm-egress:8080",
        )


def test_controlled_llm_gateway_rejects_custom_qwen_workspace_hosts() -> None:
    with pytest.raises(ValidationError, match="workspace hosts"):
        Settings(
            _env_file=None,
            environment="test",
            deployment_profile="isolated",
            llm_egress_mode="controlled_gateway",
            llm_egress_gateway_url="http://llm-egress:8080",
            qwen_allowed_workspace_hosts=("tenant.cn-beijing.maas.aliyuncs.com",),
        )


def test_controlled_llm_gateway_is_only_valid_for_isolated_deployments() -> None:
    with pytest.raises(ValidationError, match="isolated deployments"):
        Settings(
            _env_file=None,
            environment="test",
            deployment_profile="standard",
            llm_egress_mode="controlled_gateway",
            llm_egress_gateway_url="http://llm-egress:8080",
        )


def test_isolated_deployment_rejects_direct_llm_egress() -> None:
    with pytest.raises(ValidationError, match="direct LLM egress"):
        Settings(
            _env_file=None,
            environment="test",
            deployment_profile="isolated",
            llm_egress_mode="direct",
        )


def test_isolated_production_requires_the_private_clamd_service() -> None:
    with pytest.raises(ValidationError):
        production_settings(
            deployment_profile="isolated",
            database_url="postgresql+asyncpg://knowledge:pass@postgres:5432/knowledge",
            redis_url="redis://:pass@redis:6379/0",
            s3_endpoint_url="http://minio:9000",
            s3_public_endpoint_url="https://knowledge.internal:19444",
            malware_scan_host="scanner.example.com",
        )


def test_upload_platform_limit_and_scanner_limit_must_match() -> None:
    with pytest.raises(ValidationError, match="platform upload limit"):
        Settings(
            platform_max_upload_bytes=1_024,
            malware_scan_max_stream_bytes=2_048,
        )


def test_isolated_production_requires_fixed_storage_safety_policy() -> None:
    common: dict[str, object] = {
        "deployment_profile": "isolated",
        "database_url": "postgresql+asyncpg://knowledge:pass@postgres:5432/knowledge",
        "redis_url": "redis://:pass@redis:6379/0",
        "s3_endpoint_url": "http://minio:9000",
        "s3_public_endpoint_url": "https://knowledge.internal:19444",
        "malware_scan_host": "clamd",
        "storage_capacity_probe_path": "/var/lib/kb-capacity",
    }

    settings = production_settings(**common)
    assert settings.platform_max_upload_bytes == settings.malware_scan_max_stream_bytes

    for field, value in (
        ("storage_capacity_probe_path", None),
        ("storage_warning_percent", 71),
        ("storage_bulk_stop_percent", 81),
        ("storage_reject_percent", 91),
        ("storage_object_stop_bytes", 179_000_000_000),
        ("platform_max_upload_bytes", 1_000),
    ):
        overrides = {**common, field: value}
        if field == "platform_max_upload_bytes":
            overrides["malware_scan_max_stream_bytes"] = value
        with pytest.raises(ValidationError):
            production_settings(**overrides)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("database_url", "postgresql+asyncpg://user:pass@db.example.com/knowledge"),
        ("redis_url", "redis://:pass@cache.example.com:6379/0"),
        ("s3_endpoint_url", "http://objects.example.com:9000"),
    ],
)
def test_isolated_production_rejects_nonlocal_data_services(
    field: str,
    value: str,
) -> None:
    overrides: dict[str, object] = {
        "deployment_profile": "isolated",
        "database_url": "postgresql+asyncpg://knowledge:pass@postgres:5432/knowledge",
        "redis_url": "redis://:pass@redis:6379/0",
        "s3_endpoint_url": "http://minio:9000",
        "s3_public_endpoint_url": "https://knowledge.internal:19444",
        field: value,
    }
    with pytest.raises(ValidationError):
        production_settings(**overrides)


def test_removed_external_llm_enable_flag_is_rejected_as_a_second_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KB_EXTERNAL_LLM_ENABLED", "true")
    with pytest.raises(ValidationError, match="KB_EXTERNAL_LLM_ENABLED was removed"):
        Settings(
            _env_file=None,
            environment="test",
        )


def test_multipart_threshold_can_be_lowered_for_integration_testing() -> None:
    settings = Settings(multipart_threshold_bytes=1)

    assert settings.multipart_threshold_bytes == 1


def test_database_pool_and_timeout_budget_is_configurable() -> None:
    settings = Settings(
        database_pool_size=7,
        database_max_overflow=3,
        database_pool_timeout_seconds=9,
        database_statement_timeout_ms=12_000,
        database_lock_timeout_ms=4_000,
        database_idle_transaction_timeout_ms=20_000,
    )

    options = engine_options(settings)

    assert options["pool_size"] == 7
    assert options["max_overflow"] == 3
    assert options["pool_timeout"] == 9
    assert options["connect_args"]["server_settings"] == {
        "statement_timeout": "12000",
        "lock_timeout": "4000",
        "idle_in_transaction_session_timeout": "20000",
    }


def test_vercel_environment_enables_serverless_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("CRON_SECRET", "a-secure-cron-secret-value")

    settings = Settings(_env_file=None)

    assert settings.serverless is True
    assert settings.cron_secret is not None


def test_serverless_production_requires_cron_secret() -> None:
    with pytest.raises(ValidationError):
        production_settings(serverless=True, cron_secret=None)


def test_production_rejects_short_optional_bff_secret() -> None:
    with pytest.raises(ValidationError):
        production_settings(bff_shared_secret="too-short")  # pragma: allowlist secret


def test_marketplace_and_existing_secret_aliases_are_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://user:pass@db.example.test/db",  # pragma: allowlist secret
    )
    monkeypatch.setenv(
        "KV_URL",
        "rediss://default:pass@redis.example.test:6379/0",  # pragma: allowlist secret
    )
    monkeypatch.setenv("DEEPSEEK_API_KEY", "deepseek-secret-value")

    settings = Settings(_env_file=None)

    assert settings.database_url == (
        "postgresql+psycopg://user:pass@"  # pragma: allowlist secret
        "db.example.test/db"
    )
    assert settings.redis_url.startswith("rediss://")
    assert settings.deepseek_api_key is not None


def test_existing_qwen_and_minimax_environment_names_are_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QWEN_BASE_URL", "https://dashscope-us.aliyuncs.com/compatible-mode/v1")
    monkeypatch.setenv("QWEN_MODEL_NAME", "qwen-plus")
    monkeypatch.setenv("MINIMAX_BASE_URL", "https://api.minimax.io/v1")
    monkeypatch.setenv("MINIMAX_MODEL_NAME", "MiniMax-M2.7")

    settings = Settings(_env_file=None)

    assert settings.qwen_base_url.startswith("https://dashscope-us.aliyuncs.com/")
    assert settings.qwen_model == "qwen-plus"
    assert settings.minimax_base_url == "https://api.minimax.io/v1"
    assert settings.minimax_model == "MiniMax-M2.7"


def test_qwen_workspace_hosts_are_exact_and_normalized() -> None:
    settings = Settings(
        environment="test",
        qwen_allowed_workspace_hosts=(
            "Tenant.US-East-1.maas.aliyuncs.com.",
            "tenant.us-east-1.maas.aliyuncs.com",
        ),
    )
    assert settings.qwen_allowed_workspace_hosts == ("tenant.us-east-1.maas.aliyuncs.com",)

    with pytest.raises(ValidationError):
        Settings(
            environment="test",
            qwen_allowed_workspace_hosts=("*.maas.aliyuncs.com",),
        )


def test_trusted_proxy_networks_must_be_narrow_private_cidrs() -> None:
    settings = Settings(
        environment="test",
        trusted_proxy_cidrs=("172.30.240.0/24", "fd12:3456:789a::/64"),
    )
    assert settings.trusted_proxy_cidrs == (
        "172.30.240.0/24",
        "fd12:3456:789a::/64",
    )

    for invalid in (
        "0.0.0.0/0",
        "198.51.100.0/24",
        "172.30.240.1/24",
        "10.0.0.0/8",
        "2001:db8::/64",
        "fc00::/7",
    ):
        with pytest.raises(ValidationError):
            Settings(environment="test", trusted_proxy_cidrs=(invalid,))


def test_settings_validation_errors_hide_sensitive_input() -> None:
    marker = "do-not-render-this-sensitive-configuration-value"

    with pytest.raises(ValidationError) as captured:
        Settings(
            _env_file=None,
            environment="production",
            database_url=(
                "postgresql+psycopg://user:password@"  # pragma: allowlist secret
                "localhost:5432/knowledge"
            ),
            jwt_secret=marker * 2,
            llm_credentials_encryption_key=marker,
        )

    rendered = str(captured.value)
    assert marker not in rendered
    assert "input_value" not in rendered
