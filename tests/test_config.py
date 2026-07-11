import pytest
from pydantic import ValidationError

from app.core.config import Settings


def production_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "production",
        "jwt_secret": "4f" * 32,  # pragma: allowlist secret
        "bootstrap_admin_password": "A-production-admin-password-123!",  # pragma: allowlist secret
        "database_url": (
            "postgresql+psycopg://user:password@db.example.com/postgres"  # pragma: allowlist secret
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
    }
    values.update(overrides)
    return Settings(**values)


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


def test_production_rejects_example_object_storage_credentials() -> None:
    with pytest.raises(ValidationError):
        production_settings(s3_access_key="knowledge")
    with pytest.raises(ValidationError):
        production_settings(s3_secret_key="knowledge-secret")  # pragma: allowlist secret


def test_production_accepts_explicit_secure_values() -> None:
    settings = production_settings()

    assert settings.environment == "production"


def test_multipart_threshold_can_be_lowered_for_integration_testing() -> None:
    settings = Settings(multipart_threshold_bytes=1)

    assert settings.multipart_threshold_bytes == 1


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
    assert settings.qwen_allowed_workspace_hosts == (
        "tenant.us-east-1.maas.aliyuncs.com",
    )

    with pytest.raises(ValidationError):
        Settings(
            environment="test",
            qwen_allowed_workspace_hosts=("*.maas.aliyuncs.com",),
        )


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
