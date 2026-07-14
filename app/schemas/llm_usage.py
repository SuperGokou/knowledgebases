from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.db.models import LlmUsageStatus


class LlmUsageRead(BaseModel):
    """Content-free billing evidence safe for authorized administrative views."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_key: str
    user_id: UUID | None
    api_key_id: UUID | None
    knowledge_base_id: UUID | None
    provider: str
    model: str
    operation: str
    status: LlmUsageStatus
    reserved_input_tokens: int = Field(ge=0)
    reserved_output_tokens: int = Field(ge=0)
    reserved_token_count: int = Field(ge=0)
    reserved_cost_micro_usd: int = Field(ge=0)
    actual_input_tokens: int | None = Field(default=None, ge=0)
    actual_output_tokens: int | None = Field(default=None, ge=0)
    actual_token_count: int | None = Field(default=None, ge=0)
    actual_cost_micro_usd: int | None = Field(default=None, ge=0)
    error_code: str | None
    created_at: datetime
    settled_at: datetime | None


class LlmUsagePage(BaseModel):
    items: list[LlmUsageRead]
    next_cursor: UUID | None = None


class LlmUsageReconciliation(BaseModel):
    """Explicit operator attestation for releasing a stale provider-egress lease."""

    provider_egress_terminated: Literal[True]
    reason: str = Field(min_length=10, max_length=1000)


class LlmBudgetPolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    tenant_key: str = Field(min_length=1, max_length=100)
    user_id: UUID | None = None
    api_key_id: UUID | None = None
    provider: str | None = Field(default=None, min_length=1, max_length=30)
    model: str | None = Field(default=None, min_length=1, max_length=100)
    daily_token_limit: int | None = Field(default=None, ge=0)
    monthly_token_limit: int | None = Field(default=None, ge=0)
    daily_cost_limit_micro_usd: int | None = Field(default=None, ge=0)
    monthly_cost_limit_micro_usd: int | None = Field(default=None, ge=0)
    enabled: bool = True

    @model_validator(mode="after")
    def validate_scope_and_limits(self) -> LlmBudgetPolicyCreate:
        if self.model is not None and self.provider is None:
            raise ValueError("provider is required when model is scoped")
        if all(
            value is None
            for value in (
                self.daily_token_limit,
                self.monthly_token_limit,
                self.daily_cost_limit_micro_usd,
                self.monthly_cost_limit_micro_usd,
            )
        ):
            raise ValueError("at least one hard token or cost limit is required")
        return self


class LlmBudgetPolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    daily_token_limit: int | None = Field(default=None, ge=0)
    monthly_token_limit: int | None = Field(default=None, ge=0)
    daily_cost_limit_micro_usd: int | None = Field(default=None, ge=0)
    monthly_cost_limit_micro_usd: int | None = Field(default=None, ge=0)
    enabled: bool | None = None


class LlmBudgetPolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    tenant_key: str
    user_id: UUID | None
    api_key_id: UUID | None
    provider: str | None
    model: str | None
    daily_token_limit: int | None
    monthly_token_limit: int | None
    daily_cost_limit_micro_usd: int | None
    monthly_cost_limit_micro_usd: int | None
    enabled: bool
    created_at: datetime
    updated_at: datetime
