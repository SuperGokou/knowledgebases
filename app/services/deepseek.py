"""Backward-compatible DeepSeek names over the generic provider adapter."""

from __future__ import annotations

from app.core.config import Settings
from app.services.llm_provider import (
    LlmProviderError,
    LlmResult,
    OkfConceptDraft,
    OpenAICompatibleClient,
    OpenAICompatibleConfig,
)

DeepSeekConversionError = LlmProviderError
DeepSeekResult = LlmResult

__all__ = [
    "DeepSeekClient",
    "DeepSeekConversionError",
    "DeepSeekResult",
    "OkfConceptDraft",
]


class DeepSeekClient(OpenAICompatibleClient):
    def __init__(self, settings: Settings) -> None:
        super().__init__(
            OpenAICompatibleConfig(
                provider="deepseek",
                api_key=(
                    settings.deepseek_api_key.get_secret_value()
                    if settings.deepseek_api_key is not None
                    else None
                ),
                base_url=settings.deepseek_base_url,
                model=settings.deepseek_model,
                timeout_seconds=settings.deepseek_timeout_seconds,
                max_tokens=settings.deepseek_max_tokens,
            )
        )
