from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Collection
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models import LlmProviderConfig
from app.schemas.llm import LlmProviderName
from app.services.llm_provider import (
    OpenAICompatibleClient,
    OpenAICompatibleConfig,
    acquire_shared_llm_client,
)

CredentialSource = Literal["database", "environment", "none"]
SUPPORTED_PROVIDERS: tuple[LlmProviderName, ...] = ("deepseek", "qwen", "minimax")


@dataclass(frozen=True, slots=True)
class ProviderDefault:
    model: str
    base_url: str


PROVIDER_DEFAULTS: dict[LlmProviderName, ProviderDefault] = {
    "deepseek": ProviderDefault(model="deepseek-v4-flash", base_url="https://api.deepseek.com"),
    "qwen": ProviderDefault(
        model="qwen-plus",
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    ),
    "minimax": ProviderDefault(model="MiniMax-M2.7", base_url="https://api.minimax.io/v1"),
}

_CONTROLLED_PROVIDER_BASE_URLS: dict[LlmProviderName, str] = {
    "deepseek": "https://api.deepseek.com",
    "qwen": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "minimax": "https://api.minimax.io/v1",
}
_CONTROLLED_PROVIDER_GATEWAY_PATHS: dict[LlmProviderName, str] = {
    "deepseek": "/deepseek",
    "qwen": "/qwen/compatible-mode/v1",
    "minimax": "/minimax/v1",
}


class LlmConfigurationError(RuntimeError):
    pass


class CredentialCipher:
    def __init__(self, settings: Settings) -> None:
        secret = settings.llm_credentials_encryption_key
        if secret is None or len(secret.get_secret_value()) < 32:
            raise LlmConfigurationError("credential_encryption_key_missing")
        derived = hashlib.sha256(secret.get_secret_value().encode("utf-8")).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(derived))

    def encrypt(self, value: str, *, provider: LlmProviderName) -> str:
        payload = json.dumps(
            {"version": 1, "provider": provider, "secret": value},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return self._fernet.encrypt(payload).decode("ascii")

    def decrypt(self, value: str, *, provider: LlmProviderName) -> str:
        try:
            cleartext = self._fernet.decrypt(value.encode("ascii")).decode("utf-8")
            payload = json.loads(cleartext)
            secret_value = payload.get("secret") if isinstance(payload, dict) else None
            if (
                not isinstance(payload, dict)
                or payload.get("version") != 1
                or payload.get("provider") != provider
                or not isinstance(secret_value, str)
                or not secret_value
            ):
                raise ValueError("credential payload does not match its provider")
            return secret_value
        except (InvalidToken, UnicodeError, ValueError, TypeError) as error:
            raise LlmConfigurationError("credential_decryption_failed") from error


def validate_provider_base_url(
    provider: LlmProviderName,
    value: str,
    *,
    qwen_workspace_hosts: Collection[str] = (),
) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("provider base_url contains an invalid port") from error
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("provider base_url must be an absolute HTTPS URL without credentials")

    allowed = False
    if provider == "deepseek":
        allowed = hostname == "api.deepseek.com"
    elif provider == "minimax":
        allowed = hostname == "api.minimax.io"
    elif provider == "qwen":
        allowed = (
            hostname
            in {
                "dashscope.aliyuncs.com",
                "dashscope-us.aliyuncs.com",
                "dashscope-intl.aliyuncs.com",
            }
            or hostname in qwen_workspace_hosts
        )
    if not allowed:
        raise ValueError(f"base_url host is not approved for provider {provider}")
    return normalized


def validate_provider_runtime_policy(
    settings: Settings,
    provider: LlmProviderName,
    logical_base_url: str,
) -> None:
    """Reject provider URLs that the selected egress topology cannot route safely."""

    if settings.llm_egress_mode == "controlled_gateway":
        if provider not in settings.approved_llm_providers:
            raise LlmConfigurationError("controlled_gateway_provider_not_approved")
        if logical_base_url != _CONTROLLED_PROVIDER_BASE_URLS[provider]:
            raise LlmConfigurationError("controlled_gateway_provider_url_not_allowed")


async def ensure_provider_configs(
    session: AsyncSession, settings: Settings
) -> list[LlmProviderConfig]:
    rows = list((await session.scalars(select(LlmProviderConfig))).all())
    by_provider = {row.provider: row for row in rows}
    has_default = any(row.is_default for row in rows)
    preferred_default = settings.llm_default_provider
    if (
        settings.llm_egress_mode == "controlled_gateway"
        and preferred_default not in settings.approved_llm_providers
    ):
        preferred_default = settings.approved_llm_providers[0]
    for provider in SUPPORTED_PROVIDERS:
        if provider in by_provider:
            continue
        default = _settings_default(settings, provider)
        row = LlmProviderConfig(
            provider=provider,
            model=default.model,
            base_url=default.base_url,
            is_default=not has_default and provider == preferred_default,
        )
        if row.is_default:
            has_default = True
        session.add(row)
        rows.append(row)
        by_provider[provider] = row
    if not has_default:
        by_provider[preferred_default].is_default = True
    await session.flush()
    return sorted(rows, key=lambda row: SUPPORTED_PROVIDERS.index(_provider_name(row.provider)))


def credential_source(row: LlmProviderConfig, settings: Settings) -> CredentialSource:
    if row.api_key_ciphertext:
        return "database"
    if _environment_key(settings, _provider_name(row.provider)):
        return "environment"
    return "none"


async def resolve_provider_client(
    session: AsyncSession,
    settings: Settings,
    *,
    provider: LlmProviderName | None = None,
) -> OpenAICompatibleClient:
    if not settings.external_llm_enabled or settings.llm_egress_mode == "strict_offline":
        raise LlmConfigurationError("external_llm_disabled")
    if provider is None:
        row = await session.scalar(
            select(LlmProviderConfig).where(LlmProviderConfig.is_default.is_(True))
        )
        selected_provider = (
            settings.llm_default_provider if row is None else _provider_name(row.provider)
        )
    else:
        row = await session.get(LlmProviderConfig, provider)
        selected_provider = provider
    if row is None:
        default = _settings_default(settings, selected_provider)
        base_url = validate_provider_base_url(
            selected_provider,
            default.base_url,
            qwen_workspace_hosts=settings.qwen_allowed_workspace_hosts,
        )
        model = default.model
        api_key: str | None = _environment_key(settings, selected_provider)
    else:
        base_url = validate_provider_base_url(
            selected_provider,
            row.base_url,
            qwen_workspace_hosts=settings.qwen_allowed_workspace_hosts,
        )
        model = row.model
        api_key = None
    if row is not None and row.api_key_ciphertext:
        api_key = CredentialCipher(settings).decrypt(
            row.api_key_ciphertext,
            provider=selected_provider,
        )
    elif row is not None:
        api_key = _environment_key(settings, selected_provider)
    runtime_base_url = _runtime_provider_base_url(
        settings,
        selected_provider,
        base_url,
    )
    return await acquire_shared_llm_client(
        OpenAICompatibleConfig(
            provider=selected_provider,
            api_key=api_key,
            base_url=runtime_base_url,
            model=model,
            timeout_seconds=settings.deepseek_timeout_seconds,
            max_tokens=settings.deepseek_max_tokens,
        )
    )


def _runtime_provider_base_url(
    settings: Settings,
    provider: LlmProviderName,
    logical_base_url: str,
) -> str:
    """Map reviewed logical provider URLs onto the fixed same-host gateway."""

    validate_provider_runtime_policy(settings, provider, logical_base_url)
    if settings.llm_egress_mode != "controlled_gateway":
        return logical_base_url
    gateway_url = settings.llm_egress_gateway_url
    if gateway_url is None:
        raise LlmConfigurationError("controlled_gateway_url_missing")
    return f"{gateway_url}{_CONTROLLED_PROVIDER_GATEWAY_PATHS[provider]}"


def _settings_default(settings: Settings, provider: LlmProviderName) -> ProviderDefault:
    if provider == "deepseek":
        return ProviderDefault(settings.deepseek_model, settings.deepseek_base_url)
    if provider == "qwen":
        return ProviderDefault(settings.qwen_model, settings.qwen_base_url)
    return ProviderDefault(settings.minimax_model, settings.minimax_base_url)


def _environment_key(settings: Settings, provider: LlmProviderName) -> str | None:
    secret = {
        "deepseek": settings.deepseek_api_key,
        "qwen": settings.qwen_api_key,
        "minimax": settings.minimax_api_key,
    }[provider]
    return secret.get_secret_value() if secret is not None else None


def _provider_name(value: str) -> LlmProviderName:
    if value not in SUPPORTED_PROVIDERS:
        raise LlmConfigurationError("unsupported_provider_in_database")
    return value
