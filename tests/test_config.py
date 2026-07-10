import pytest
from pydantic import ValidationError

from app.core.config import Settings


def production_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "production",
        "jwt_secret": "4f" * 32,
        "bootstrap_admin_password": "A-production-admin-password-123!",
        "database_url": "postgresql+psycopg://user:password@db.example.com/postgres",
        "redis_url": "rediss://default:password@redis.example.com:6379/0",
        "s3_endpoint_url": "https://objects.example.com",
        "s3_public_endpoint_url": "https://objects.example.com",
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
        ("database_url", "postgresql+asyncpg://knowledge:knowledge@localhost/knowledge"),
        ("redis_url", "redis://127.0.0.1:6379/0"),
    ],
)
def test_production_rejects_local_service_endpoints(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        production_settings(**{field: value})


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
        production_settings(bff_shared_secret="too-short")


def test_marketplace_and_existing_secret_aliases_are_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@db.example.test/db")
    monkeypatch.setenv("KV_URL", "rediss://default:pass@redis.example.test:6379/0")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "deepseek-secret-value")

    settings = Settings(_env_file=None)

    assert settings.database_url == "postgresql+psycopg://user:pass@db.example.test/db"
    assert settings.redis_url.startswith("rediss://")
    assert settings.deepseek_api_key is not None
