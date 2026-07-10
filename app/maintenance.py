from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.models import File, FileStatus, ReservationStatus, UploadSession, UploadSessionStatus
from app.db.session import SessionFactory
from app.services.audit import add_audit_event
from app.services.deepseek import DeepSeekClient
from app.services.okf_conversion import enqueue_okf_conversion, process_okf_conversion_batch
from app.services.quota import QuotaService
from app.services.storage import StorageService


async def cleanup_expired_uploads(
    session: AsyncSession,
    storage: StorageService,
    *,
    batch_size: int = 100,
) -> int:
    rows = (
        await session.execute(
            select(UploadSession, File)
            .join(File, File.id == UploadSession.file_id)
            .where(
                UploadSession.status.in_(
                    [UploadSessionStatus.INITIATED, UploadSessionStatus.FINALIZING]
                ),
                UploadSession.expires_at < datetime.now(UTC),
            )
            .order_by(UploadSession.expires_at)
            .limit(batch_size)
            .with_for_update(skip_locked=True)
        )
    ).all()
    quota = QuotaService()
    for upload, file in rows:
        if upload.status is UploadSessionStatus.FINALIZING:
            stored = await storage.try_head(key=file.object_key)
            if stored is not None and stored.size_bytes == upload.expected_size_bytes:
                await quota.consume_upload_reservations(
                    session,
                    upload_session_id=upload.id,
                )
                upload.status = UploadSessionStatus.COMPLETED
                upload.completed_at = datetime.now(UTC)
                file.size_bytes = stored.size_bytes
                file.status = FileStatus.PROCESSING
                if stored.checksum_sha256:
                    file.checksum_algorithm = "SHA256"
                    file.checksum_value = stored.checksum_sha256
                add_audit_event(
                    session,
                    actor_id=None,
                    action="upload.finalization_reconciled",
                    resource_type="file",
                    resource_id=str(file.id),
                    details={"status": "processing"},
                )
                conversion = await enqueue_okf_conversion(session, file)
                if conversion is not None:
                    add_audit_event(
                        session,
                        action="okf.conversion_queued",
                        resource_type="okf_conversion_job",
                        resource_id=str(conversion.id),
                        details={"file_id": str(file.id)},
                    )
                continue
            if stored is not None:
                await storage.delete(key=file.object_key)

        if upload.storage_upload_id:
            await storage.abort_multipart(
                key=file.object_key,
                upload_id=upload.storage_upload_id,
            )
        elif file.object_key.startswith("staging/"):
            await storage.delete(key=file.object_key)
        await quota.release_upload_reservations(
            session,
            upload_session_id=upload.id,
            status=ReservationStatus.EXPIRED,
        )
        upload.status = UploadSessionStatus.EXPIRED
        file.status = FileStatus.FAILED
        add_audit_event(
            session,
            actor_id=None,
            action="upload.expired",
            resource_type="file",
            resource_id=str(file.id),
        )
    await session.commit()
    return len(rows)


async def run_maintenance_once(
    session: AsyncSession,
    storage: StorageService,
    settings: Settings,
) -> dict[str, int]:
    cleaned = await cleanup_expired_uploads(
        session, storage, batch_size=settings.maintenance_batch_size
    )
    converted = await process_okf_conversion_batch(
        session,
        storage,
        DeepSeekClient(settings),
        settings,
        batch_size=settings.okf_conversion_batch_size,
    )
    return {"cleaned": cleaned, "converted": converted}


async def run(*, once: bool, interval_seconds: int) -> None:
    settings = get_settings()
    storage = StorageService(settings)
    while True:
        async with SessionFactory() as session:
            result = await run_maintenance_once(session, storage, settings)
            if result["cleaned"] or result["converted"]:
                print(
                    f"Maintenance cleaned={result['cleaned']} converted={result['converted']}"
                )
        if once:
            return
        await asyncio.sleep(interval_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="Knowledge-base maintenance worker")
    parser.add_argument("--once", action="store_true", help="Run one cleanup batch and exit")
    parser.add_argument("--interval", type=int, default=60, help="Loop delay in seconds")
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("--interval must be positive")
    asyncio.run(run(once=args.once, interval_seconds=args.interval))


if __name__ == "__main__":
    main()
