from __future__ import annotations

from secrets import compare_digest
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status

from app.api.dependencies import DatabaseSession, get_storage_service
from app.core.config import Settings, get_settings
from app.maintenance import cleanup_expired_uploads
from app.services.llm_settings import resolve_provider_client
from app.services.okf_conversion import process_okf_conversion_batch
from app.services.storage import StorageService

router = APIRouter()


def cron_authorized(authorization: str | None, settings: Settings) -> bool:
    if settings.cron_secret is None:
        return False
    expected = f"Bearer {settings.cron_secret.get_secret_value()}"
    return compare_digest(authorization or "", expected)


@router.get("/maintenance", include_in_schema=False)
async def run_maintenance(
    session: DatabaseSession,
    settings: Annotated[Settings, Depends(get_settings)],
    storage: Annotated[StorageService, Depends(get_storage_service)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, int]:
    if not cron_authorized(authorization, settings):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    total = 0
    for _ in range(settings.maintenance_max_batches):
        cleaned = await cleanup_expired_uploads(
            session,
            storage,
            batch_size=settings.maintenance_batch_size,
        )
        total += cleaned
        if cleaned < settings.maintenance_batch_size:
            break
    converted = await process_okf_conversion_batch(
        session,
        storage,
        await resolve_provider_client(session, settings),
        settings,
        batch_size=settings.okf_conversion_batch_size,
    )
    return {"cleaned": total, "converted": converted}
