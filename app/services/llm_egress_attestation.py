from __future__ import annotations

import asyncio
import sys
from typing import NoReturn

from sqlalchemy import select

from app.core.config import get_settings
from app.db.models import LlmProviderConfig
from app.db.session import SessionFactory, engine


class AttestationError(RuntimeError):
    """The active provider could not be captured as a safe locked snapshot."""


async def active_provider_snapshot() -> str:
    """Read the single default provider under a DB share lock without exposing secrets."""

    settings = get_settings()
    if settings.llm_egress_mode != "controlled_gateway":
        raise AttestationError("controlled gateway is not active")
    async with SessionFactory() as session:
        try:
            rows = list(
                (
                    await session.scalars(
                        select(LlmProviderConfig)
                        .where(LlmProviderConfig.is_default.is_(True))
                        .with_for_update(read=True)
                    )
                ).all()
            )
            if len(rows) != 1 or rows[0].provider not in settings.approved_llm_providers:
                raise AttestationError("active provider is outside the approval contract")
            provider = rows[0].provider
            await session.commit()
            return provider
        except BaseException:
            await session.rollback()
            raise


def _blocked() -> NoReturn:
    print("llm-egress-attestation: active provider snapshot unavailable", file=sys.stderr)
    raise SystemExit(70)


async def _main() -> int:
    try:
        provider = await active_provider_snapshot()
    except Exception:
        _blocked()
    print(provider)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(_main()))
    finally:
        asyncio.run(engine.dispose())
