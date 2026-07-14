from __future__ import annotations

from typing import Annotated, cast

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select, update

from app.api.dependencies import DatabaseSession, require_permission
from app.api.errors import ApiError
from app.core.config import Settings, get_settings
from app.db.models import LlmModelPrice, LlmProviderConfig
from app.schemas.llm import (
    LlmProviderName,
    LlmProviderRead,
    LlmProvidersResponse,
    LlmProviderUpdate,
)
from app.services.access import AccessContext
from app.services.audit import AuditResult, add_audit_event
from app.services.llm_settings import (
    CredentialCipher,
    LlmConfigurationError,
    credential_source,
    ensure_provider_configs,
    validate_provider_base_url,
)

router = APIRouter()


@router.get("", response_model=LlmProvidersResponse)
async def list_llm_providers(
    session: DatabaseSession,
    _: Annotated[AccessContext, Depends(require_permission("llm:manage"))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LlmProvidersResponse:
    rows = await ensure_provider_configs(session, settings)
    prices = list((await session.scalars(select(LlmModelPrice))).all())
    await session.commit()
    return _response(rows, settings, prices)


@router.patch("/{provider}", response_model=LlmProviderRead)
async def update_llm_provider(
    provider: LlmProviderName,
    payload: LlmProviderUpdate,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("llm:manage"))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LlmProviderRead:
    await ensure_provider_configs(session, settings)
    rows = list(
        (
            await session.scalars(
                select(LlmProviderConfig).order_by(LlmProviderConfig.provider).with_for_update()
            )
        ).all()
    )
    row = next((item for item in rows if item.provider == provider), None)
    if row is None:
        raise ApiError(
            status_code=404,
            code="llm_provider_not_found",
            message="LLM provider not found",
        )

    if payload.model is not None:
        row.model = payload.model
    try:
        row.base_url = validate_provider_base_url(
            provider,
            payload.base_url or row.base_url,
            qwen_workspace_hosts=settings.qwen_allowed_workspace_hosts,
        )
    except ValueError as error:
        raise ApiError(
            status_code=422,
            code="invalid_llm_base_url",
            message=str(error),
        ) from error

    credential_changed = payload.api_key is not None or payload.clear_api_key
    pricing_changed = payload.input_micro_usd_per_million_tokens is not None
    if payload.api_key is not None:
        try:
            cipher = CredentialCipher(settings)
        except LlmConfigurationError as error:
            raise ApiError(
                status_code=503,
                code="llm_credential_encryption_unavailable",
                message=(
                    "Configure KB_LLM_CREDENTIAL_ENCRYPTION_KEY before storing provider keys"
                ),
            ) from error
        row.api_key_ciphertext = cipher.encrypt(
            payload.api_key.get_secret_value().strip(),
            provider=provider,
        )
    elif payload.clear_api_key:
        row.api_key_ciphertext = None

    price = await session.get(LlmModelPrice, (provider, row.model))
    if pricing_changed:
        if price is None:
            price = LlmModelPrice(
                provider=provider,
                model=row.model,
                input_micro_usd_per_million_tokens=(
                    payload.input_micro_usd_per_million_tokens or 0
                ),
                output_micro_usd_per_million_tokens=(
                    payload.output_micro_usd_per_million_tokens or 0
                ),
                active=True,
                updated_by=access.user.id,
            )
            session.add(price)
        else:
            price.input_micro_usd_per_million_tokens = (
                payload.input_micro_usd_per_million_tokens or 0
            )
            price.output_micro_usd_per_million_tokens = (
                payload.output_micro_usd_per_million_tokens or 0
            )
            price.active = True
            price.updated_by = access.user.id

    if (row.is_default or payload.make_default) and credential_source(row, settings) == "none":
        raise ApiError(
            status_code=422,
            code="llm_provider_not_configured",
            message="Configure an API key before making this provider the default",
        )

    if payload.make_default and not row.is_default:
        # Flush the old default first to satisfy the single-default partial unique index.
        await session.execute(update(LlmProviderConfig).values(is_default=False))
        await session.flush()
        row.is_default = True
    row.updated_by = access.user.id
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="llm.provider_updated",
        result=AuditResult.SUCCESS,
        resource_type="llm_provider",
        resource_id=provider,
        request_id=getattr(request.state, "request_id", None),
        details={
            "provider": provider,
            "model": row.model,
            "base_url": row.base_url,
            "made_default": payload.make_default,
            "credential_changed": credential_changed,
            "credential_cleared": payload.clear_api_key,
            "pricing_changed": pricing_changed,
        },
    )
    await session.commit()
    await session.refresh(row)
    return _read(row, settings, price)


def _response(
    rows: list[LlmProviderConfig],
    settings: Settings,
    prices: list[LlmModelPrice],
) -> LlmProvidersResponse:
    default = next((row.provider for row in rows if row.is_default), settings.llm_default_provider)
    return LlmProvidersResponse(
        default_provider=cast(LlmProviderName, default),
        providers=[
            _read(
                row,
                settings,
                next(
                    (
                        price
                        for price in prices
                        if price.provider == row.provider
                        and price.model == row.model
                        and price.active
                    ),
                    None,
                ),
            )
            for row in rows
        ],
    )


def _read(
    row: LlmProviderConfig,
    settings: Settings,
    price: LlmModelPrice | None,
) -> LlmProviderRead:
    return LlmProviderRead(
        provider=cast(LlmProviderName, row.provider),
        model=row.model,
        base_url=row.base_url,
        is_default=row.is_default,
        configured=credential_source(row, settings) != "none",
        credential_source=credential_source(row, settings),
        updated_at=row.updated_at,
        pricing_configured=price is not None and price.active,
        input_micro_usd_per_million_tokens=(
            price.input_micro_usd_per_million_tokens if price is not None else None
        ),
        output_micro_usd_per_million_tokens=(
            price.output_micro_usd_per_million_tokens if price is not None else None
        ),
    )
