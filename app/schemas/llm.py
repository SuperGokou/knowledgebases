from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

LlmProviderName = Literal["deepseek", "qwen", "minimax"]


class LlmProviderUpdate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    model: str | None = Field(default=None, min_length=1, max_length=100)
    base_url: str | None = Field(default=None, min_length=1, max_length=500)
    api_key: SecretStr | None = Field(default=None, repr=False)
    clear_api_key: bool = False
    make_default: bool = False
    input_micro_usd_per_million_tokens: int | None = Field(
        default=None, ge=0, le=10**15
    )
    output_micro_usd_per_million_tokens: int | None = Field(
        default=None, ge=0, le=10**15
    )

    @field_validator("model")
    @classmethod
    def safe_model_name(cls, value: str | None) -> str | None:
        if value is not None and any(not (char.isalnum() or char in "._:-") for char in value):
            raise ValueError(
                "model may contain only letters, numbers, dot, underscore, colon, hyphen"
            )
        return value

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value().strip()) < 8:
            raise ValueError("api_key is too short")
        return value

    @model_validator(mode="after")
    def reject_conflicting_secret_operations(self) -> LlmProviderUpdate:
        if self.api_key is not None and self.clear_api_key:
            raise ValueError("api_key and clear_api_key cannot be used together")
        if (self.input_micro_usd_per_million_tokens is None) != (
            self.output_micro_usd_per_million_tokens is None
        ):
            raise ValueError("input and output model prices must be updated together")
        return self


class LlmProviderRead(BaseModel):
    provider: LlmProviderName
    model: str
    base_url: str
    is_default: bool
    configured: bool
    credential_source: Literal["database", "environment", "none"]
    updated_at: datetime | None = None
    pricing_configured: bool
    input_micro_usd_per_million_tokens: int | None = None
    output_micro_usd_per_million_tokens: int | None = None


class LlmProvidersResponse(BaseModel):
    default_provider: LlmProviderName
    providers: list[LlmProviderRead]
