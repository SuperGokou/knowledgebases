from __future__ import annotations

from functools import lru_cache
from typing import Literal
from urllib.parse import urlparse

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="KB_",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    app_name: str = "Enterprise Knowledge Base"
    environment: Literal["development", "test", "production"] = "development"
    debug: bool = False
    serverless: bool = Field(
        default=False,
        validation_alias=AliasChoices("KB_SERVERLESS", "VERCEL"),
    )
    api_prefix: str = "/api/v1"
    database_url: str = "postgresql+asyncpg://knowledge:knowledge@localhost:5432/knowledge"
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: SecretStr = SecretStr(
        "development-only-change-this-secret-before-production-0123456789"
    )
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "enterprise-knowledge-base"
    jwt_audience: str = "knowledge-base-api"
    access_token_minutes: int = Field(default=15, ge=1, le=1_440)
    refresh_token_days: int = Field(default=7, ge=1, le=90)

    s3_endpoint_url: str = "http://localhost:9000"
    s3_public_endpoint_url: str = "http://localhost:9000"
    s3_region: str = "us-east-1"
    s3_access_key: SecretStr = SecretStr("knowledge")
    s3_secret_key: SecretStr = SecretStr("knowledge-secret")
    s3_bucket: str = "knowledge-base"
    s3_use_ssl: bool = False
    s3_addressing_style: Literal["auto", "path", "virtual"] = "path"
    presigned_url_seconds: int = Field(default=900, ge=60, le=3_600)
    multipart_threshold_bytes: int = Field(default=100 * 1024 * 1024, ge=1)
    multipart_part_size_bytes: int = Field(
        default=64 * 1024 * 1024,
        ge=5 * 1024 * 1024,
        le=5 * 1024 * 1024 * 1024,
    )
    upload_session_hours: int = Field(default=24, ge=1, le=168)

    allowed_extensions: tuple[str, ...] = (
        ".txt",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".csv",
        ".pdf",
        ".ppt",
        ".pptx",
    )
    cors_origins: tuple[str, ...] = ("http://localhost:3000",)
    trusted_hosts: tuple[str, ...] = (
        "localhost",
        "127.0.0.1",
        "testserver",
        "*.vercel.app",
    )
    default_requests_per_minute: int = Field(default=60, ge=1)
    login_attempts_per_minute: int = Field(default=10, ge=1)
    login_attempts_per_account_per_minute: int = Field(default=5, ge=1)
    refresh_attempts_per_minute: int = Field(default=30, ge=1)
    max_api_body_bytes: int = Field(default=1024 * 1024, ge=1024, le=16 * 1024 * 1024)
    cron_secret: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("CRON_SECRET", "KB_CRON_SECRET"),
    )
    maintenance_batch_size: int = Field(default=100, ge=1, le=500)
    maintenance_max_batches: int = Field(default=10, ge=1, le=100)

    bootstrap_admin_email: str = "admin@example.com"
    bootstrap_admin_password: SecretStr | None = None

    @field_validator("allowed_extensions")
    @classmethod
    def normalize_extensions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            sorted({item.lower() if item.startswith(".") else f".{item.lower()}" for item in value})
        )

    @field_validator("environment", mode="before")
    @classmethod
    def normalize_environment(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @model_validator(mode="after")
    def reject_development_secrets_in_production(self) -> Settings:
        if self.environment == "production":
            jwt_secret = self.jwt_secret.get_secret_value()
            admin_password = (
                self.bootstrap_admin_password.get_secret_value()
                if self.bootstrap_admin_password is not None
                else None
            )
            placeholder_markers = ("dev-only", "devonly", "development-only", "changeme", "replace")
            if len(jwt_secret) < 64 or any(
                marker in jwt_secret.lower() for marker in placeholder_markers
            ):
                raise ValueError(
                    "KB_JWT_SECRET must be a non-example secret of at least 64 characters"
                )
            if admin_password is not None and (
                len(admin_password) < 16
                or any(marker in admin_password.lower() for marker in placeholder_markers)
            ):
                raise ValueError("KB_BOOTSTRAP_ADMIN_PASSWORD must be changed in production")
            if self.debug:
                raise ValueError("KB_DEBUG must be false in production")
            for variable, endpoint in (
                ("KB_DATABASE_URL", self.database_url),
                ("KB_REDIS_URL", self.redis_url),
            ):
                if urlparse(endpoint).hostname in {None, "localhost", "127.0.0.1", "::1"}:
                    raise ValueError(f"{variable} must reference an external production service")
            if not self.s3_endpoint_url.lower().startswith("https://"):
                raise ValueError("KB_S3_ENDPOINT_URL must use HTTPS in production")
            if not self.s3_public_endpoint_url.lower().startswith("https://"):
                raise ValueError("KB_S3_PUBLIC_ENDPOINT_URL must use HTTPS in production")
            if not self.s3_use_ssl:
                raise ValueError("KB_S3_USE_SSL must be true in production")
            if self.serverless and (
                self.cron_secret is None
                or len(self.cron_secret.get_secret_value()) < 16
            ):
                raise ValueError("CRON_SECRET must contain at least 16 characters on serverless")
            if self.access_token_minutes > 60:
                raise ValueError("access tokens must not exceed 60 minutes in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
