from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, urlparse

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="KB_",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
        hide_input_in_errors=True,
    )

    app_name: str = "Enterprise Knowledge Base"
    environment: Literal["development", "test", "production"] = "development"
    debug: bool = False
    serverless: bool = Field(
        default=False,
        validation_alias=AliasChoices("KB_SERVERLESS", "VERCEL"),
    )
    deployment_profile: Literal["standard", "isolated"] = "standard"
    external_llm_enabled: bool = True
    api_prefix: str = "/api/v1"
    database_url: str = Field(
        default=(
            "postgresql+asyncpg://knowledge:knowledge@"  # pragma: allowlist secret
            "localhost:5432/knowledge"
        ),
        validation_alias=AliasChoices("KB_DATABASE_URL", "DATABASE_URL"),
    )
    database_pool_size: int = Field(default=8, ge=1, le=50)
    database_max_overflow: int = Field(default=4, ge=0, le=50)
    database_pool_timeout_seconds: int = Field(default=10, ge=1, le=60)
    database_statement_timeout_ms: int = Field(default=15_000, ge=1_000, le=120_000)
    database_lock_timeout_ms: int = Field(default=5_000, ge=100, le=60_000)
    database_idle_transaction_timeout_ms: int = Field(
        default=30_000,
        ge=1_000,
        le=300_000,
    )
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        validation_alias=AliasChoices("KB_REDIS_URL", "KV_URL", "REDIS_URL"),
    )

    jwt_secret: SecretStr = SecretStr(
        "development-only-change-this-secret-before-production-"  # pragma: allowlist secret
        "0123456789"
    )
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "enterprise-knowledge-base"
    jwt_audience: str = "knowledge-base-api"
    access_token_minutes: int = Field(default=15, ge=1, le=1_440)
    refresh_token_days: int = Field(default=7, ge=1, le=90)
    bff_shared_secret: SecretStr | None = None

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
    platform_max_upload_bytes: int = Field(
        default=2 * 1024 * 1024 * 1024,
        ge=1024,
        le=4 * 1024 * 1024 * 1024,
    )
    platform_max_files_per_user: int = Field(default=100_000, ge=1, le=10_000_000)
    platform_max_files_total: int = Field(default=2_000_000, ge=1, le=100_000_000)
    platform_max_entries_per_knowledge_base: int = Field(
        default=100_000,
        ge=1,
        le=10_000_000,
    )
    platform_max_entry_bytes_per_knowledge_base: int = Field(
        default=2 * 1024 * 1024 * 1024,
        ge=1024,
        le=100 * 1024 * 1024 * 1024,
    )
    storage_capacity_probe_path: Path | None = None
    storage_warning_percent: int = Field(default=70, ge=1, le=99)
    storage_bulk_stop_percent: int = Field(default=80, ge=1, le=99)
    storage_reject_percent: int = Field(default=90, ge=1, le=100)
    storage_object_stop_bytes: int = Field(default=180_000_000_000, ge=1)

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
    trusted_proxy_cidrs: tuple[str, ...] = ()
    default_requests_per_minute: int = Field(default=60, ge=1)
    authenticated_precheck_requests_per_minute: int = Field(default=10_000, ge=1)
    login_attempts_per_minute: int = Field(default=10, ge=1)
    login_attempts_per_account_per_minute: int = Field(default=5, ge=1)
    refresh_attempts_per_minute: int = Field(default=30, ge=1)
    api_key_auth_attempts_per_minute: int = Field(default=60, ge=1)
    max_api_body_bytes: int = Field(default=1024 * 1024, ge=1024, le=16 * 1024 * 1024)
    cron_secret: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("CRON_SECRET", "KB_CRON_SECRET"),
    )
    maintenance_batch_size: int = Field(default=100, ge=1, le=500)
    maintenance_max_batches: int = Field(default=10, ge=1, le=100)
    malware_scan_host: str = "127.0.0.1"
    malware_scan_port: int = Field(default=3310, ge=1, le=65_535)
    malware_scan_timeout_seconds: float = Field(default=120, gt=0, le=3_600)
    malware_scan_max_stream_bytes: int = Field(
        default=2 * 1024 * 1024 * 1024,
        ge=1024,
        le=4 * 1024 * 1024 * 1024,
    )
    malware_scan_chunk_size_bytes: int = Field(
        default=1024 * 1024,
        ge=64 * 1024,
        le=8 * 1024 * 1024,
    )
    malware_scan_reclaim_seconds: int = Field(default=300, ge=60, le=7_200)

    # Phase-one OKF compiler. The API key is optional so uploads keep working
    # while the external processor is intentionally disabled.
    deepseek_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("KB_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"),
    )
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-v4-flash"
    qwen_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("KB_QWEN_API_KEY", "QWEN_API_KEY"),
    )
    qwen_base_url: str = Field(
        default="https://dashscope.aliyuncs.com/compatible-mode/v1",
        validation_alias=AliasChoices("KB_QWEN_BASE_URL", "QWEN_BASE_URL"),
    )
    qwen_model: str = Field(
        default="qwen-plus",
        validation_alias=AliasChoices("KB_QWEN_MODEL", "QWEN_MODEL_NAME", "QWEN_MODEL"),
    )
    qwen_allowed_workspace_hosts: tuple[str, ...] = ()
    minimax_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("KB_MINIMAX_API_KEY", "MINIMAX_API_KEY"),
    )
    minimax_base_url: str = Field(
        default="https://api.minimax.io/v1",
        validation_alias=AliasChoices("KB_MINIMAX_BASE_URL", "MINIMAX_BASE_URL"),
    )
    minimax_model: str = Field(
        default="MiniMax-M2.7",
        validation_alias=AliasChoices(
            "KB_MINIMAX_MODEL", "MINIMAX_MODEL_NAME", "MINIMAX_MODEL"
        ),
    )
    llm_default_provider: Literal["deepseek", "qwen", "minimax"] = "deepseek"
    llm_tenant_key: str = Field(default="default", min_length=1, max_length=100)
    llm_credentials_encryption_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "KB_LLM_CREDENTIAL_ENCRYPTION_KEY",
            "KB_LLM_CREDENTIALS_ENCRYPTION_KEY",
        ),
    )
    deepseek_timeout_seconds: float = Field(default=45, ge=5, le=120)
    deepseek_max_tokens: int = Field(default=4_096, ge=256, le=32_768)
    okf_source_max_bytes: int = Field(default=1_000_000, ge=1_024, le=5_000_000)
    okf_conversion_max_attempts: int = Field(default=4, ge=1, le=10)
    okf_conversion_lease_seconds: int = Field(default=300, ge=60, le=3_600)
    okf_conversion_batch_size: int = Field(default=5, ge=1, le=20)
    okf_conversion_time_budget_seconds: float = Field(default=50, ge=5, le=300)

    bootstrap_admin_email: str = "admin@example.com"
    bootstrap_admin_password: SecretStr | None = None

    @field_validator("allowed_extensions")
    @classmethod
    def normalize_extensions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            sorted({item.lower() if item.startswith(".") else f".{item.lower()}" for item in value})
        )

    @field_validator("qwen_allowed_workspace_hosts")
    @classmethod
    def normalize_qwen_workspace_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized: set[str] = set()
        for item in value:
            hostname = item.strip().lower().rstrip(".")
            if (
                not hostname
                or "*" in hostname
                or "://" in hostname
                or "/" in hostname
                or hostname == "maas.aliyuncs.com"
                or not hostname.endswith(".maas.aliyuncs.com")
            ):
                raise ValueError(
                    "KB_QWEN_ALLOWED_WORKSPACE_HOSTS must contain exact *.maas.aliyuncs.com "
                    "hostnames without schemes, paths, ports, or wildcards"
                )
            normalized.add(hostname)
        return tuple(sorted(normalized))

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def normalize_trusted_proxy_cidrs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized: set[str] = set()
        for item in value:
            if not item or item != item.strip():
                raise ValueError("KB_TRUSTED_PROXY_CIDRS must contain exact CIDR values")
            try:
                network = ip_network(item, strict=True)
            except ValueError as error:
                raise ValueError(
                    "KB_TRUSTED_PROXY_CIDRS must contain canonical CIDR values"
                ) from error
            if isinstance(network, IPv4Network):
                minimum_prefix = 24
                approved = any(
                    network.subnet_of(parent)
                    for parent in (
                        IPv4Network("10.0.0.0/8"),
                        IPv4Network("172.16.0.0/12"),
                        IPv4Network("192.168.0.0/16"),
                        IPv4Network("127.0.0.0/8"),
                    )
                )
            else:
                assert isinstance(network, IPv6Network)
                minimum_prefix = 64
                approved = any(
                    network.subnet_of(parent)
                    for parent in (
                        IPv6Network("fc00::/7"),
                        IPv6Network("::1/128"),
                    )
                )
            if network.prefixlen < minimum_prefix or not approved:
                raise ValueError(
                    "KB_TRUSTED_PROXY_CIDRS must contain narrow private proxy networks"
                )
            normalized.add(str(network))
        return tuple(sorted(normalized))

    @field_validator("database_url", mode="before")
    @classmethod
    def normalize_database_driver(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        if value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+psycopg://", 1)
        if value.startswith("postgres://"):
            return value.replace("postgres://", "postgresql+psycopg://", 1)
        return value

    @field_validator("environment", mode="before")
    @classmethod
    def normalize_environment(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @model_validator(mode="after")
    def reject_development_secrets_in_production(self) -> Settings:
        if self.platform_max_upload_bytes != self.malware_scan_max_stream_bytes:
            raise ValueError(
                "platform upload limit must equal the malware scan stream limit"
            )
        if not (
            self.storage_warning_percent
            < self.storage_bulk_stop_percent
            < self.storage_reject_percent
        ):
            raise ValueError("storage watermarks must increase from warning to rejection")
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
            if self.bff_shared_secret is not None:
                bff_secret = self.bff_shared_secret.get_secret_value()
                if bff_secret and len(bff_secret) < 32:
                    raise ValueError(
                        "KB_BFF_SHARED_SECRET must contain at least 32 characters when configured"
                    )
            if self.debug:
                raise ValueError("KB_DEBUG must be false in production")
            if self.deployment_profile == "isolated":
                expected_storage_policy = {
                    "storage_warning_percent": 70,
                    "storage_bulk_stop_percent": 80,
                    "storage_reject_percent": 90,
                    "storage_object_stop_bytes": 180_000_000_000,
                    "platform_max_upload_bytes": 2 * 1024 * 1024 * 1024,
                }
                if self.storage_capacity_probe_path != Path("/var/lib/kb-capacity"):
                    raise ValueError(
                        "KB_STORAGE_CAPACITY_PROBE_PATH must reference the isolated "
                        "read-only capacity probe"
                    )
                for field_name, required_value in expected_storage_policy.items():
                    if getattr(self, field_name) != required_value:
                        raise ValueError(
                            f"{field_name} must be {required_value} in isolated deployments"
                        )
                isolated_services = (
                    ("KB_DATABASE_URL", self.database_url, {"postgresql+asyncpg"}, "postgres"),
                    ("KB_REDIS_URL", self.redis_url, {"redis"}, "redis"),
                    ("KB_S3_ENDPOINT_URL", self.s3_endpoint_url, {"http"}, "minio"),
                )
                for variable, endpoint, allowed_schemes, required_host in isolated_services:
                    parsed_endpoint = urlparse(endpoint)
                    if (
                        parsed_endpoint.scheme not in allowed_schemes
                        or parsed_endpoint.hostname != required_host
                    ):
                        raise ValueError(
                            f"{variable} must reference the isolated Compose service "
                            f"{required_host!r}"
                        )
                if self.malware_scan_host != "clamd":
                    raise ValueError(
                        "KB_MALWARE_SCAN_HOST must reference the isolated Compose service "
                        "'clamd'"
                    )
                if self.external_llm_enabled:
                    raise ValueError(
                        "KB_EXTERNAL_LLM_ENABLED must be false in isolated deployments"
                    )
            else:
                for variable, endpoint in (
                    ("KB_DATABASE_URL", self.database_url),
                    ("KB_REDIS_URL", self.redis_url),
                ):
                    if urlparse(endpoint).hostname in {
                        None,
                        "localhost",
                        "127.0.0.1",
                        "::1",
                    }:
                        raise ValueError(
                            f"{variable} must reference an external production service"
                        )
                parsed_database = urlparse(self.database_url)
                database_query = parse_qs(
                    parsed_database.query,
                    keep_blank_values=True,
                )
                tls_parameter = (
                    "ssl" if parsed_database.scheme == "postgresql+asyncpg" else "sslmode"
                )
                tls_values = database_query.get(tls_parameter, [])
                if len(tls_values) != 1 or tls_values[0].lower() != "verify-full":
                    raise ValueError(
                        "KB_DATABASE_URL must require certificate-verified TLS "
                        f"with {tls_parameter}=verify-full in standard production"
                    )
                if urlparse(self.redis_url).scheme != "rediss":
                    raise ValueError("KB_REDIS_URL must use TLS (rediss://) in production")
            if "*" in self.cors_origins or "null" in {
                origin.strip().lower() for origin in self.cors_origins
            }:
                raise ValueError(
                    "KB_CORS_ORIGINS must contain exact trusted origins in production"
                )
            if (
                self.s3_access_key.get_secret_value() == "knowledge"
                or self.s3_secret_key.get_secret_value() == "knowledge-secret"
            ):
                raise ValueError("S3 example credentials must be changed in production")
            if (
                self.deployment_profile != "isolated"
                and not self.s3_endpoint_url.lower().startswith("https://")
            ):
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
            if self.external_llm_enabled:
                for variable, endpoint in (
                    ("KB_DEEPSEEK_BASE_URL", self.deepseek_base_url),
                    ("KB_QWEN_BASE_URL", self.qwen_base_url),
                    ("KB_MINIMAX_BASE_URL", self.minimax_base_url),
                ):
                    parsed_llm_url = urlparse(endpoint)
                    if parsed_llm_url.scheme != "https" or not parsed_llm_url.hostname:
                        raise ValueError(
                            f"{variable} must be an absolute HTTPS URL in production"
                        )
            if self.llm_credentials_encryption_key is not None and len(
                self.llm_credentials_encryption_key.get_secret_value()
            ) < 32:
                raise ValueError(
                    "KB_LLM_CREDENTIALS_ENCRYPTION_KEY must contain at least 32 characters"
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
