from __future__ import annotations

import argparse
import asyncio
import base64
import hmac
import logging
import signal
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import and_, exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.models import (
    AuditResult,
    File,
    FileStatus,
    MalwareScanStatus,
    QuotaReservation,
    ReservationStatus,
    UploadSession,
    UploadSessionStatus,
)
from app.db.session import SessionFactory
from app.domain.files import UploadMode
from app.services.audit import add_audit_event
from app.services.chat_idempotency import cleanup_chat_idempotency_records
from app.services.llm_provider import close_shared_llm_clients
from app.services.llm_settings import LlmConfigurationError, resolve_provider_client
from app.services.malware_scanner import (
    ClamdScanner,
    MalwareScanner,
    MalwareScannerError,
    ScanVerdict,
)
from app.services.okf_conversion import enqueue_okf_conversion, process_okf_conversion_batch
from app.services.quota import QuotaService
from app.services.storage import StorageService, checksum_sha256_base64_to_hex

_LOGGER = logging.getLogger(__name__)

# The container grants 120 seconds for a graceful stop. A whole maintenance
# cycle must yield before then so cancellation-aware phase cleanup and the
# shared LLM transport shutdown retain a bounded cleanup margin.
MAINTENANCE_CYCLE_TIMEOUT_SECONDS = 105.0


def _single_final_object_key(staging_key: str) -> str:
    if not staging_key.startswith("staging/"):
        return staging_key
    return f"objects/{staging_key.removeprefix('staging/')}"


def _declared_checksum_sha256_base64(file: File) -> tuple[str | None, bool]:
    """Return the declared SHA-256 in S3 form and whether its DB representation is valid."""

    if file.checksum_algorithm is None and file.checksum_value is None:
        return None, True
    if file.checksum_algorithm != "SHA256" or file.checksum_value is None:
        return None, False
    try:
        checksum = bytes.fromhex(file.checksum_value)
    except ValueError:
        return None, False
    if len(checksum) != 32:
        return None, False
    return base64.b64encode(checksum).decode("ascii"), True


@dataclass(frozen=True, slots=True)
class _MalwareScanClaim:
    file_id: UUID
    lease_id: UUID
    object_key: str


async def _claim_next_malware_scan(
    session: AsyncSession,
    settings: Settings,
) -> _MalwareScanClaim | None:
    """Atomically lease one eligible file so queued work cannot outlive its lease."""

    now = datetime.now(UTC)
    file = await session.scalar(
        select(File)
        .where(
            File.status == FileStatus.QUARANTINED,
            or_(
                and_(
                    File.malware_scan_status == MalwareScanStatus.PENDING,
                    or_(
                        File.malware_scan_next_attempt_at.is_(None),
                        File.malware_scan_next_attempt_at <= now,
                    ),
                ),
                and_(
                    File.malware_scan_status == MalwareScanStatus.PROCESSING,
                    File.malware_scan_next_attempt_at <= now,
                ),
            ),
        )
        .order_by(File.created_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if file is None:
        await session.rollback()
        return None

    lease_id = uuid4()
    file.malware_scan_status = MalwareScanStatus.PROCESSING
    file.malware_scan_started_at = now
    file.malware_scan_next_attempt_at = now + timedelta(
        seconds=settings.malware_scan_reclaim_seconds
    )
    file.malware_scan_lease_id = lease_id
    file.malware_scan_attempts += 1
    file.malware_scanned_at = None
    file.malware_signature = None
    file.malware_scan_error_code = None
    add_audit_event(
        session,
        actor_id=None,
        action="file.malware_scan.started",
        result=AuditResult.SUCCESS,
        resource_type="file",
        resource_id=str(file.id),
        details={"attempt": file.malware_scan_attempts},
    )
    claim = _MalwareScanClaim(
        file_id=file.id,
        lease_id=lease_id,
        object_key=file.object_key,
    )
    await session.commit()
    return claim


async def process_malware_scan_batch(
    session: AsyncSession,
    storage: StorageService,
    scanner: MalwareScanner,
    settings: Settings,
    *,
    batch_size: int | None = None,
) -> int:
    """Claim quarantined uploads, stream them through clamd, and fail closed."""

    processed = 0
    limit = batch_size or settings.maintenance_batch_size
    while processed < limit:
        claim = await _claim_next_malware_scan(session, settings)
        if claim is None:
            break
        processed += 1
        result = None
        error_code: str | None = None
        try:
            result = await scanner.scan(
                storage.iter_chunks(
                    key=claim.object_key,
                    chunk_size=settings.malware_scan_chunk_size_bytes,
                )
            )
        except MalwareScannerError as error:
            error_code = error.error_code
        except Exception:  # Storage/network failures are also terminal fail-closed results.
            error_code = "scan_transport_error"

        persisted_file = await session.scalar(
            select(File)
            .where(
                File.id == claim.file_id,
                File.status == FileStatus.QUARANTINED,
                File.malware_scan_status == MalwareScanStatus.PROCESSING,
                File.malware_scan_lease_id == claim.lease_id,
                File.object_key == claim.object_key,
            )
            .execution_options(populate_existing=True)
            .with_for_update()
        )
        if persisted_file is None:
            await session.rollback()
            continue
        persisted_file.malware_scanned_at = datetime.now(UTC)
        persisted_file.malware_scan_lease_id = None
        persisted_file.malware_scan_next_attempt_at = None
        if result is not None and result.verdict is ScanVerdict.CLEAN:
            persisted_file.malware_scan_status = MalwareScanStatus.CLEAN
            persisted_file.status = FileStatus.PROCESSING
            conversion = await enqueue_okf_conversion(session, persisted_file)
            add_audit_event(
                session,
                actor_id=None,
                action="file.malware_scan.clean",
                result=AuditResult.SUCCESS,
                resource_type="file",
                resource_id=str(persisted_file.id),
            )
            if conversion is not None:
                add_audit_event(
                    session,
                    actor_id=None,
                    action="okf.conversion_queued",
                    result=AuditResult.SUCCESS,
                    resource_type="okf_conversion_job",
                    resource_id=str(conversion.id),
                    details={"file_id": str(persisted_file.id)},
                )
        elif result is not None and result.verdict is ScanVerdict.INFECTED:
            persisted_file.malware_scan_status = MalwareScanStatus.INFECTED
            persisted_file.malware_signature = result.signature
            persisted_file.malware_scan_error_code = "malware_detected"
            persisted_file.status = FileStatus.QUARANTINED
            add_audit_event(
                session,
                actor_id=None,
                action="file.malware_scan.infected",
                result=AuditResult.FAILURE,
                resource_type="file",
                resource_id=str(persisted_file.id),
                details={"signature": result.signature},
            )
        else:
            persisted_file.malware_scan_status = MalwareScanStatus.ERROR
            persisted_file.malware_scan_error_code = error_code or "scanner_error"
            persisted_file.status = FileStatus.QUARANTINED
            add_audit_event(
                session,
                actor_id=None,
                action="file.malware_scan.failed_closed",
                result=AuditResult.FAILURE,
                resource_type="file",
                resource_id=str(persisted_file.id),
                details={"error_code": persisted_file.malware_scan_error_code},
            )
        await session.commit()
    return processed


async def cleanup_expired_uploads(
    session: AsyncSession,
    storage: StorageService,
    *,
    batch_size: int = 100,
) -> int:
    @dataclass(frozen=True, slots=True)
    class Claim:
        upload_id: UUID
        file_id: UUID
        original_status: UploadSessionStatus
        mode: str
        object_key: str
        storage_upload_id: str | None
        expected_size_bytes: int
        expected_checksum_sha256: str | None
        checksum_constraint_valid: bool

    async def claim_next() -> Claim | None:
        now = datetime.now(UTC)
        held_reservation = exists().where(
            QuotaReservation.upload_session_id == UploadSession.id,
            QuotaReservation.status == ReservationStatus.HELD,
        )
        row = (
            await session.execute(
                select(UploadSession, File)
                .join(File, File.id == UploadSession.file_id)
                .where(
                    or_(
                        UploadSession.status.in_(
                            [
                                UploadSessionStatus.INITIATED,
                                UploadSessionStatus.FINALIZING,
                            ]
                        ),
                        and_(
                            UploadSession.status.in_(
                                [UploadSessionStatus.ABORTED, UploadSessionStatus.EXPIRED]
                            ),
                            held_reservation,
                        ),
                    ),
                    UploadSession.expires_at < now,
                )
                .order_by(UploadSession.expires_at)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
        ).one_or_none()
        if row is None:
            await session.rollback()
            return None
        upload, file = row
        expected_checksum, checksum_constraint_valid = _declared_checksum_sha256_base64(file)
        original_status = upload.status
        if original_status is UploadSessionStatus.INITIATED:
            # Make completion fail closed before releasing the row lock.
            upload.status = UploadSessionStatus.EXPIRED
        # A failed storage cleanup is retried after this bounded lease.
        upload.expires_at = now + timedelta(minutes=15)
        claim = Claim(
            upload_id=upload.id,
            file_id=file.id,
            original_status=original_status,
            mode=upload.mode,
            object_key=file.object_key,
            storage_upload_id=upload.storage_upload_id,
            expected_size_bytes=upload.expected_size_bytes,
            expected_checksum_sha256=expected_checksum,
            checksum_constraint_valid=checksum_constraint_valid,
        )
        await session.commit()
        return claim

    quota = QuotaService()
    processed = 0
    while processed < batch_size:
        claim = await claim_next()
        if claim is None:
            break
        processed += 1
        finalization_rejection_action: str | None = None
        finalization_rejection_details: dict[str, object] | None = None
        if claim.original_status is UploadSessionStatus.FINALIZING:
            published_key = claim.object_key
            if claim.mode == UploadMode.SINGLE.value:
                final_key = _single_final_object_key(claim.object_key)
                stored = await storage.try_head(key=final_key)
                if stored is None:
                    stored = await storage.try_head(key=claim.object_key)
                    staging_matches_claim = (
                        stored is not None
                        and stored.size_bytes == claim.expected_size_bytes
                        and claim.checksum_constraint_valid
                        and (
                            claim.expected_checksum_sha256 is None
                            or (
                                stored.checksum_sha256 is not None
                                and hmac.compare_digest(
                                    stored.checksum_sha256,
                                    claim.expected_checksum_sha256,
                                )
                            )
                        )
                    )
                    if staging_matches_claim:
                        stored = await storage.promote(
                            source_key=claim.object_key,
                            destination_key=final_key,
                            upload_session_id=str(claim.upload_id),
                        )
                published_key = final_key
            else:
                stored = await storage.try_head(key=claim.object_key)
            if stored is not None and stored.size_bytes != claim.expected_size_bytes:
                finalization_rejection_action = "upload.rejected_size_mismatch"
                finalization_rejection_details = {
                    "expected": claim.expected_size_bytes,
                    "actual": stored.size_bytes,
                }
            elif stored is not None and (
                not claim.checksum_constraint_valid
                or (
                    claim.expected_checksum_sha256 is not None
                    and (
                        stored.checksum_sha256 is None
                        or not hmac.compare_digest(
                            stored.checksum_sha256,
                            claim.expected_checksum_sha256,
                        )
                    )
                )
            ):
                finalization_rejection_action = "upload.rejected_checksum_mismatch"
            if (
                stored is not None
                and finalization_rejection_action is None
                and stored.size_bytes == claim.expected_size_bytes
            ):
                row = (
                    await session.execute(
                        select(UploadSession, File)
                        .join(File, File.id == UploadSession.file_id)
                        .where(UploadSession.id == claim.upload_id)
                        .with_for_update()
                    )
                ).one_or_none()
                if row is None or row[0].status is not UploadSessionStatus.FINALIZING:
                    await session.rollback()
                    if claim.mode == UploadMode.SINGLE.value:
                        await storage.delete(key=published_key)
                        await storage.seal_single_upload(
                            key=claim.object_key,
                            upload_session_id=str(claim.upload_id),
                        )
                    else:
                        await storage.delete(key=claim.object_key)
                    continue
                upload, file = row
                await quota.consume_upload_reservations(
                    session,
                    upload_session_id=claim.upload_id,
                )
                upload.status = UploadSessionStatus.COMPLETED
                upload.completed_at = datetime.now(UTC)
                file.object_key = published_key
                file.size_bytes = stored.size_bytes
                file.status = FileStatus.QUARANTINED
                file.malware_scan_status = MalwareScanStatus.PENDING
                stored_checksum_hex = checksum_sha256_base64_to_hex(stored.checksum_sha256)
                if stored_checksum_hex is not None and file.checksum_value is None:
                    file.checksum_algorithm = "SHA256"
                    file.checksum_value = stored_checksum_hex
                add_audit_event(
                    session,
                    actor_id=None,
                    action="upload.finalization_reconciled",
                    result=AuditResult.SUCCESS,
                    resource_type="file",
                    resource_id=str(file.id),
                    details={"status": "quarantined", "malware_scan_status": "pending"},
                )
                await session.commit()
                continue
            if stored is not None:
                if claim.mode == UploadMode.SINGLE.value:
                    await storage.delete(key=published_key)
                    await storage.seal_single_upload(
                        key=claim.object_key,
                        upload_session_id=str(claim.upload_id),
                    )
                else:
                    await storage.delete(key=claim.object_key)

        if claim.storage_upload_id:
            await storage.abort_multipart(
                key=claim.object_key,
                upload_id=claim.storage_upload_id,
            )
        elif claim.object_key.startswith("staging/"):
            await storage.seal_single_upload(
                key=claim.object_key,
                upload_session_id=str(claim.upload_id),
            )
        row = (
            await session.execute(
                select(UploadSession, File)
                .join(File, File.id == UploadSession.file_id)
                .where(UploadSession.id == claim.upload_id)
                .with_for_update()
            )
        ).one_or_none()
        if row is None:
            await session.rollback()
            continue
        upload, file = row
        if upload.status is UploadSessionStatus.COMPLETED:
            await session.rollback()
            continue
        aborted = (
            claim.original_status is UploadSessionStatus.ABORTED
            or upload.status is UploadSessionStatus.ABORTED
        )
        finalization_failed = (
            claim.original_status is UploadSessionStatus.FINALIZING
            and finalization_rejection_action is not None
        )
        await quota.release_upload_reservations(
            session,
            upload_session_id=claim.upload_id,
            status=(
                ReservationStatus.RELEASED
                if aborted or finalization_failed
                else ReservationStatus.EXPIRED
            ),
        )
        upload.status = (
            UploadSessionStatus.ABORTED
            if aborted
            else (
                UploadSessionStatus.FAILED if finalization_failed else UploadSessionStatus.EXPIRED
            )
        )
        file.status = FileStatus.FAILED
        add_audit_event(
            session,
            actor_id=None,
            action=(
                "upload.abort_reconciled"
                if aborted
                else finalization_rejection_action or "upload.expired"
            ),
            result=AuditResult.DENIED if finalization_failed else AuditResult.SUCCESS,
            resource_type="file",
            resource_id=str(file.id),
            details=finalization_rejection_details,
        )
        await session.commit()
    return processed


async def run_maintenance_once(
    session: AsyncSession,
    storage: StorageService,
    settings: Settings,
) -> dict[str, int]:
    cleaned = await cleanup_expired_uploads(
        session, storage, batch_size=settings.maintenance_batch_size
    )
    chat_idempotency = await cleanup_chat_idempotency_records(
        session,
        settings,
        batch_size=settings.chat_idempotency_cleanup_batch_size,
        max_batches=settings.chat_idempotency_cleanup_max_batches,
    )
    scanner = ClamdScanner(
        host=settings.malware_scan_host,
        port=settings.malware_scan_port,
        timeout_seconds=settings.malware_scan_timeout_seconds,
        max_stream_bytes=settings.malware_scan_max_stream_bytes,
    )
    scanned = await process_malware_scan_batch(
        session,
        storage,
        scanner,
        settings,
        batch_size=settings.maintenance_batch_size,
    )
    client = None
    provider_configuration_valid = True
    if settings.external_llm_enabled:
        try:
            client = await resolve_provider_client(session, settings)
        except (LlmConfigurationError, ValueError) as error:
            provider_configuration_valid = False
            _LOGGER.error(
                "LLM provider configuration rejected; OKF conversions remain queued",
                extra={"llm_configuration_error": str(error)},
            )
    if not provider_configuration_valid:
        converted = 0
    elif client is None:
        converted = await process_okf_conversion_batch(
            session,
            storage,
            None,
            settings,
            batch_size=settings.okf_conversion_batch_size,
        )
    else:
        async with client:
            converted = await process_okf_conversion_batch(
                session,
                storage,
                client,
                settings,
                batch_size=settings.okf_conversion_batch_size,
            )
    return {
        "cleaned": cleaned,
        "chat_idempotency": chat_idempotency,
        "scanned": scanned,
        "converted": converted,
    }


async def run(
    *,
    once: bool,
    interval_seconds: int,
    shutdown_event: asyncio.Event | None = None,
) -> None:
    settings = get_settings()
    storage = StorageService(settings)
    try:
        while True:
            async with SessionFactory() as session:
                cycle_deadline = asyncio.timeout(MAINTENANCE_CYCLE_TIMEOUT_SECONDS)
                try:
                    async with cycle_deadline:
                        result = await run_maintenance_once(session, storage, settings)
                except TimeoutError:
                    # Only translate the deadline that this worker owns. A phase
                    # raising an unrelated TimeoutError remains an operational
                    # failure and must not be hidden as a normal cycle expiry.
                    if not cycle_deadline.expired():
                        raise
                    _LOGGER.error(
                        "Maintenance cycle deadline exceeded",
                        extra={
                            "cycle_timeout_seconds": (MAINTENANCE_CYCLE_TIMEOUT_SECONDS),
                            "shutdown_requested": bool(
                                shutdown_event is not None and shutdown_event.is_set()
                            ),
                        },
                    )
                else:
                    if any(result.values()):
                        _LOGGER.info(
                            "Maintenance batch completed",
                            extra={
                                "cleaned": result["cleaned"],
                                "chat_idempotency": result["chat_idempotency"],
                                "scanned": result["scanned"],
                                "converted": result["converted"],
                            },
                        )
            if once or (shutdown_event is not None and shutdown_event.is_set()):
                return
            if shutdown_event is None:
                await asyncio.sleep(interval_seconds)
            else:
                try:
                    await asyncio.wait_for(shutdown_event.wait(), timeout=interval_seconds)
                except TimeoutError:
                    continue
                return
    finally:
        await close_shared_llm_clients()


async def run_with_shutdown_signals(*, once: bool, interval_seconds: int) -> None:
    """Translate Linux container stop signals into cancellable async cleanup."""

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()
    worker = asyncio.create_task(
        run(
            once=once,
            interval_seconds=interval_seconds,
            shutdown_event=shutdown_event,
        )
    )
    forced_shutdown = False
    installed: list[signal.Signals] = []

    def request_shutdown() -> None:
        nonlocal forced_shutdown
        if not shutdown_event.is_set():
            # First signal stops new batches and lets the current governed provider
            # operation finish, preserving metering and idempotency semantics.
            shutdown_event.set()
            return
        forced_shutdown = True
        _LOGGER.warning("Second shutdown signal forced maintenance cancellation")
        worker.cancel()

    for shutdown_signal in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(shutdown_signal, request_shutdown)
        except (NotImplementedError, RuntimeError):
            # Windows' event loop lacks add_signal_handler; asyncio.run still
            # cancels the main task for KeyboardInterrupt and executes run.finally.
            continue
        installed.append(shutdown_signal)
    try:
        await worker
    except asyncio.CancelledError:
        if not forced_shutdown:
            raise
    finally:
        for shutdown_signal in installed:
            loop.remove_signal_handler(shutdown_signal)


def main() -> None:
    parser = argparse.ArgumentParser(description="Knowledge-base maintenance worker")
    parser.add_argument("--once", action="store_true", help="Run one cleanup batch and exit")
    parser.add_argument("--interval", type=int, default=60, help="Loop delay in seconds")
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("--interval must be positive")
    asyncio.run(run_with_shutdown_signals(once=args.once, interval_seconds=args.interval))


if __name__ == "__main__":
    main()
