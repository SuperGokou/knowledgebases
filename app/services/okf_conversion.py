from __future__ import annotations

import logging
import re
from asyncio import to_thread
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from time import monotonic
from uuid import UUID, uuid4

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.core.config import Settings
from app.db.models import (
    File,
    FileStatus,
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
    KnowledgeIngestionStatus,
    MalwareScanStatus,
    OkfConversionJob,
    OkfConversionStatus,
)
from app.services.audit import AuditResult, add_audit_event
from app.services.document_parser import (
    SUPPORTED_DOCUMENT_EXTENSIONS,
    DocumentParseError,
    ParsedDocument,
    ParseLimits,
    parse_document,
    parser_capabilities,
)
from app.services.llm_egress_policy import (
    acquire_llm_egress_locks,
    external_llm_egress_allowed,
)
from app.services.llm_provider import (
    LlmProviderError,
    LlmResult,
    MeteringOutcome,
    OkfConceptDraft,
    OpenAICompatibleClient,
)
from app.services.llm_usage import (
    GovernedLlmExecutor,
    LlmBudgetConfigurationUnavailable,
    LlmBudgetExceeded,
    LlmEgressDenied,
    LlmUsageDimensions,
    LlmUsageDuplicate,
    LlmUsageMeteringMismatch,
    LlmUsagePricingUnavailable,
    LlmUsageUnmetered,
    find_active_llm_egress,
)
from app.services.storage import StorageService

PROMPT_VERSION = "okf-phase1-v1"
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _ClaimedFile:
    id: UUID
    owner_id: UUID
    knowledge_base_id: UUID | None
    bucket: str
    object_key: str
    original_name: str
    extension: str
    content_type: str
    size_bytes: int
    checksum_algorithm: str | None
    checksum_value: str | None
    status: FileStatus
    knowledge_status: KnowledgeIngestionStatus
    malware_scan_status: MalwareScanStatus
    version: int
    deleted_at: datetime | None


@dataclass(frozen=True)
class _ClaimedConversion:
    job_id: UUID
    knowledge_base_id: UUID
    attempts: int
    retry_generation: int
    external_llm_processing_enabled: bool
    file: _ClaimedFile


def _claimed_file_identity_conditions(file: _ClaimedFile) -> tuple[ColumnElement[bool], ...]:
    return (
        File.id == file.id,
        File.owner_id == file.owner_id,
        File.knowledge_base_id == file.knowledge_base_id,
        File.bucket == file.bucket,
        File.object_key == file.object_key,
        File.original_name == file.original_name,
        File.extension == file.extension,
        File.content_type == file.content_type,
        File.size_bytes == file.size_bytes,
        (
            File.checksum_algorithm.is_(None)
            if file.checksum_algorithm is None
            else File.checksum_algorithm == file.checksum_algorithm
        ),
        (
            File.checksum_value.is_(None)
            if file.checksum_value is None
            else File.checksum_value == file.checksum_value
        ),
        File.status == file.status,
        File.knowledge_status == file.knowledge_status,
        File.malware_scan_status == file.malware_scan_status,
        File.version == file.version,
        (
            File.deleted_at.is_(None)
            if file.deleted_at is None
            else File.deleted_at == file.deleted_at
        ),
    )


async def _claim_is_current(
    session: AsyncSession,
    *,
    claim: _ClaimedConversion,
    lease_id: UUID,
    lock_egress_scope: bool = False,
) -> bool:
    if lock_egress_scope:
        await acquire_llm_egress_locks(
            session,
            (("okf_conversion_job", claim.job_id),),
        )
    file = claim.file
    current_id = await session.scalar(
        select(OkfConversionJob.id)
        .join(File, File.id == OkfConversionJob.file_id)
        .where(
            OkfConversionJob.id == claim.job_id,
            OkfConversionJob.status == OkfConversionStatus.PROCESSING,
            OkfConversionJob.lease_id == lease_id,
            OkfConversionJob.file_id == file.id,
            OkfConversionJob.file_version == file.version,
            OkfConversionJob.knowledge_base_id == claim.knowledge_base_id,
            *_claimed_file_identity_conditions(file),
        )
    )
    # This check is deliberately a short transaction. The final write still
    # repeats the lease predicate under a row lock to close later races.
    await session.commit()
    return current_id is not None


async def _external_processing_allowed_at_egress(
    session: AsyncSession,
    claim: _ClaimedConversion,
    lease_id: UUID,
) -> bool:
    allowed = await external_llm_egress_allowed(
        session,
        user_id=claim.file.owner_id,
        knowledge_base_id=claim.knowledge_base_id,
        api_key_id=None,
        required_permission=None,
        minimum_access=KnowledgeBaseAccessLevel.EDITOR,
    )
    if not allowed:
        return False
    # The durable HELD usage row now exists. Validate the job/file identity only
    # after the mutable authorization check, under the same advisory scope used
    # by stale-lease reclaim. Reclaimers must observe HELD and stand down until
    # provider settlement, so no database transaction spans provider I/O.
    return await _claim_is_current(
        session,
        claim=claim,
        lease_id=lease_id,
        lock_egress_scope=True,
    )


async def enqueue_okf_conversion(session: AsyncSession, file: File) -> OkfConversionJob | None:
    """Create the durable hand-off in the same transaction as upload completion."""

    if file.knowledge_base_id is None:
        return None
    existing = await session.scalar(
        select(OkfConversionJob).where(
            OkfConversionJob.file_id == file.id,
            OkfConversionJob.file_version == file.version,
        )
    )
    if existing is not None:
        return existing
    job = OkfConversionJob(
        file_id=file.id,
        knowledge_base_id=file.knowledge_base_id,
        file_version=file.version,
        prompt_version=PROMPT_VERSION,
    )
    file.knowledge_status = KnowledgeIngestionStatus.PENDING
    file.knowledge_error_code = None
    session.add(job)
    await session.flush()
    return job


async def process_okf_conversion_batch(
    session: AsyncSession,
    storage: StorageService,
    client: OpenAICompatibleClient | None,
    settings: Settings,
    *,
    batch_size: int,
) -> int:
    processed = 0
    deadline = monotonic() + settings.okf_conversion_time_budget_seconds
    for _ in range(batch_size):
        if processed and deadline - monotonic() < settings.deepseek_timeout_seconds:
            break
        job = await _claim_job(session, settings)
        if job is None:
            break
        processed += 1
        job_id = job.id
        lease_id = job.lease_id
        if lease_id is None:
            continue
        try:
            await _process_claimed_job(session, storage, client, settings, job_id, lease_id)
        except Exception:
            # One malformed object or transient SDK failure must not fail the
            # whole cron batch. Details stay in server telemetry; the durable
            # record stores a bounded, non-sensitive classification.
            logger.exception(
                "OKF conversion job failed unexpectedly",
                extra={"okf_conversion_job_id": str(job_id)},
            )
            await session.rollback()
            await _mark_failure(
                session,
                job_id,
                lease_id,
                code="unexpected_processing_error",
                retryable=True,
                settings=settings,
            )
    return processed


async def _claim_job(session: AsyncSession, settings: Settings) -> OkfConversionJob | None:
    now = datetime.now(UTC)
    stale_before = now - timedelta(seconds=settings.okf_conversion_lease_seconds)
    eligible = or_(
        and_(
            OkfConversionJob.status.in_(
                [OkfConversionStatus.PENDING, OkfConversionStatus.RETRY_WAIT]
            ),
            or_(
                OkfConversionJob.next_attempt_at.is_(None),
                OkfConversionJob.next_attempt_at <= now,
            ),
        ),
        and_(
            OkfConversionJob.status == OkfConversionStatus.PROCESSING,
            OkfConversionJob.locked_at < stale_before,
        ),
    )
    job = await session.scalar(
        select(OkfConversionJob)
        .where(eligible)
        .order_by(OkfConversionJob.created_at, OkfConversionJob.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if job is None:
        await session.rollback()
        return None
    await acquire_llm_egress_locks(
        session,
        (("okf_conversion_job", job.id),),
    )
    owner_id = await session.scalar(select(File.owner_id).where(File.id == job.file_id))
    if (
        job.status is OkfConversionStatus.PROCESSING
        and owner_id is not None
        and await find_active_llm_egress(
            session,
            knowledge_base_id=job.knowledge_base_id,
            user_id=owner_id,
            operation="okf.compile",
        )
        is not None
    ):
        # A committed HELD usage row is the transaction-free provider-egress
        # lease. Never replace its OKF worker lease while provider I/O may run.
        await session.rollback()
        return None
    job.status = OkfConversionStatus.PROCESSING
    job.locked_at = now
    job.lease_id = uuid4()
    job.attempts += 1
    job.error_code = None
    await session.commit()
    return job


async def _process_claimed_job(
    session: AsyncSession,
    storage: StorageService,
    client: OpenAICompatibleClient | None,
    settings: Settings,
    job_id: UUID,
    lease_id: UUID,
) -> None:
    row = (
        await session.execute(
            select(
                OkfConversionJob,
                File,
                KnowledgeBase.external_llm_processing_enabled,
            )
            .join(File, File.id == OkfConversionJob.file_id)
            .join(KnowledgeBase, KnowledgeBase.id == OkfConversionJob.knowledge_base_id)
            .where(
                OkfConversionJob.id == job_id,
                OkfConversionJob.status == OkfConversionStatus.PROCESSING,
                OkfConversionJob.lease_id == lease_id,
            )
        )
    ).one_or_none()
    if row is None:
        await session.rollback()
        return
    claimed_job, claimed_file, external_llm_processing_enabled = row
    claim = _ClaimedConversion(
        job_id=claimed_job.id,
        knowledge_base_id=claimed_job.knowledge_base_id,
        attempts=claimed_job.attempts,
        retry_generation=claimed_job.retry_generation,
        file=_ClaimedFile(
            id=claimed_file.id,
            owner_id=claimed_file.owner_id,
            knowledge_base_id=claimed_file.knowledge_base_id,
            bucket=claimed_file.bucket,
            object_key=claimed_file.object_key,
            original_name=claimed_file.original_name,
            extension=claimed_file.extension,
            content_type=claimed_file.content_type,
            size_bytes=claimed_file.size_bytes,
            checksum_algorithm=claimed_file.checksum_algorithm,
            checksum_value=claimed_file.checksum_value,
            status=claimed_file.status,
            knowledge_status=claimed_file.knowledge_status,
            malware_scan_status=claimed_file.malware_scan_status,
            version=claimed_file.version,
            deleted_at=claimed_file.deleted_at,
        ),
        external_llm_processing_enabled=external_llm_processing_enabled,
    )
    # The claim is already durable. Release the read transaction and pooled
    # connection before object-store I/O and CPU-bound document parsing.
    await session.rollback()
    file = claim.file
    if file.extension not in SUPPORTED_DOCUMENT_EXTENSIONS:
        await _finish_terminal(
            session,
            job_id,
            lease_id,
            OkfConversionStatus.UNSUPPORTED,
            "parser_unsupported_extension",
        )
        return
    if file.size_bytes > settings.okf_source_max_bytes:
        await _finish_terminal(
            session, job_id, lease_id, OkfConversionStatus.UNSUPPORTED, "source_too_large"
        )
        return
    capabilities = parser_capabilities()
    if not capabilities.get(file.extension, False):
        capability_code = (
            "parser_pdf_capability_unavailable"
            if file.extension == ".pdf"
            else "parser_legacy_capability_unavailable"
        )
        await _finish_terminal(
            session,
            job_id,
            lease_id,
            OkfConversionStatus.UNSUPPORTED,
            capability_code,
        )
        return
    try:
        raw = await storage.read_bytes(key=file.object_key, max_bytes=settings.okf_source_max_bytes)
    except ValueError:
        await _finish_terminal(
            session, job_id, lease_id, OkfConversionStatus.UNSUPPORTED, "source_too_large"
        )
        return
    try:
        parsed = await to_thread(
            parse_document,
            raw,
            file.extension,
            ParseLimits(
                max_source_bytes=settings.okf_source_max_bytes,
                max_output_chars=settings.okf_source_max_bytes,
            ),
        )
    except DocumentParseError as error:
        await _finish_terminal(
            session,
            job_id,
            lease_id,
            OkfConversionStatus.UNSUPPORTED,
            error.code,
        )
        return
    source_text = parsed.text
    if not await _claim_is_current(session, claim=claim, lease_id=lease_id):
        return

    external_allowed = settings.external_llm_enabled and claim.external_llm_processing_enabled
    if external_allowed:
        if client is None or not client.configured:
            await _mark_failure(
                session,
                job_id,
                lease_id,
                code="llm_not_configured",
                retryable=True,
                settings=settings,
            )
            return
        try:
            result = await GovernedLlmExecutor().compile_okf(
                session,
                client=client,
                dimensions=LlmUsageDimensions(
                    tenant_key=settings.llm_tenant_key,
                    user_id=file.owner_id,
                    api_key_id=None,
                    knowledge_base_id=claim.knowledge_base_id,
                    provider=client.provider,
                    model=client.model,
                    operation="okf.compile",
                ),
                idempotency_key=(
                    f"okf:{claim.job_id}:generation:{claim.retry_generation}:"
                    f"attempt:{claim.attempts}"
                ),
                source_text=source_text,
                provider_user_id=f"kb_{claim.knowledge_base_id.hex}",
                maximum_output_tokens=settings.deepseek_max_tokens,
                before_egress=lambda: _external_processing_allowed_at_egress(
                    session,
                    claim,
                    lease_id,
                ),
            )
        except LlmEgressDenied:
            # Consent was revoked after source loading/reservation. Keep processing
            # inside the trust boundary using the lossless local compiler.
            result = _compile_local_okf(file, source_text)
        except LlmBudgetExceeded:
            await _mark_failure(
                session,
                job_id,
                lease_id,
                code="llm_budget_exceeded",
                retryable=True,
                settings=settings,
            )
            return
        except (LlmUsagePricingUnavailable, LlmBudgetConfigurationUnavailable):
            await _mark_failure(
                session,
                job_id,
                lease_id,
                code="llm_governance_unavailable",
                retryable=True,
                settings=settings,
            )
            return
        except (LlmUsageDuplicate, LlmUsageUnmetered, LlmUsageMeteringMismatch):
            await _mark_failure(
                session,
                job_id,
                lease_id,
                code="llm_usage_unreconciled",
                retryable=False,
                settings=settings,
            )
            return
        except LlmProviderError as error:
            await _mark_failure(
                session,
                job_id,
                lease_id,
                code=error.code,
                retryable=(
                    error.retryable and error.metering_outcome is not MeteringOutcome.UNKNOWN
                ),
                settings=settings,
            )
            return
    else:
        result = _compile_local_okf(file, source_text)
    await _persist_result(session, job_id, lease_id, file, result, parsed=parsed)


def _compile_local_okf(file: File | _ClaimedFile, source_text: str) -> LlmResult:
    """Create a lossless local draft when external model processing is disabled."""

    title = file.original_name.rsplit(".", maxsplit=1)[0].strip() or "Untitled document"
    normalized_source = source_text.strip()
    body = f"# {title}\n\n{normalized_source}"
    return LlmResult(
        draft=OkfConceptDraft(
            type="document",
            title=title[:500],
            description="Locally imported without external model transformation.",
            tags=["local-import", file.extension.removeprefix(".")],
            body_markdown=body,
        ),
        provider="local",
        model="local-deterministic-v1",
        prompt_tokens=0,
        completion_tokens=0,
    )


async def _persist_result(
    session: AsyncSession,
    job_id: UUID,
    lease_id: UUID,
    file: File | _ClaimedFile,
    result: LlmResult,
    *,
    parsed: ParsedDocument | None = None,
) -> None:
    # A recovered lease may race a prior worker. Lock and re-check before insert.
    locked = await session.scalar(
        select(OkfConversionJob)
        .where(
            OkfConversionJob.id == job_id,
            OkfConversionJob.status == OkfConversionStatus.PROCESSING,
            OkfConversionJob.lease_id == lease_id,
        )
        .with_for_update()
    )
    if locked is None:
        await session.rollback()
        return
    file_conditions: tuple[ColumnElement[bool], ...] = (File.id == file.id,)
    if isinstance(file, _ClaimedFile):
        file_conditions = _claimed_file_identity_conditions(file)
    locked_file = await session.scalar(select(File).where(*file_conditions).with_for_update())
    if locked_file is None:
        await session.rollback()
        return
    locked_file.knowledge_status = KnowledgeIngestionStatus.DRAFT_READY
    locked_file.knowledge_error_code = None
    now = datetime.now(UTC)
    entry = KnowledgeEntry(
        knowledge_base_id=locked.knowledge_base_id,
        source_file_id=file.id,
        entry_type=result.draft.type,
        title=result.draft.title,
        content=result.draft.body_markdown,
        source_path=f"generated/{file.id}/{_slug(result.draft.title)}.md",
        format_version="okf/0.1",
        # Model-derived knowledge always requires an explicit approval transition.
        # The source file's state must never implicitly publish content generated later.
        publication_status=KnowledgeEntryPublicationStatus.DRAFT,
        custom_metadata={
            "okf_version": "0.1",
            "description": result.draft.description,
            "resource": f"kb-file://{file.id}",
            "tags": result.draft.tags,
            "timestamp": now.isoformat().replace("+00:00", "Z"),
            "generator": {
                "provider": result.provider,
                "model": result.model,
                "prompt_version": locked.prompt_version,
            },
            "source_parser": parsed.parser if parsed is not None else "legacy-call",
            "source_locations": list(parsed.source_locations) if parsed is not None else [],
        },
    )
    session.add(entry)
    await session.flush()
    locked.output_entry_id = entry.id
    locked.status = OkfConversionStatus.SUCCEEDED
    locked.model = result.model
    locked.locked_at = None
    locked.lease_id = None
    locked.completed_at = now
    add_audit_event(
        session,
        action="okf.conversion_succeeded",
        result=AuditResult.SUCCESS,
        resource_type="okf_conversion_job",
        resource_id=str(locked.id),
        details={
            "file_id": str(file.id),
            "entry_id": str(entry.id),
            "model": result.model,
            "prompt_version": locked.prompt_version,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
        },
    )
    await session.commit()


async def _mark_failure(
    session: AsyncSession,
    job_id: UUID,
    lease_id: UUID,
    *,
    code: str,
    retryable: bool,
    settings: Settings,
) -> None:
    locked = await session.scalar(
        select(OkfConversionJob)
        .where(
            OkfConversionJob.id == job_id,
            OkfConversionJob.status == OkfConversionStatus.PROCESSING,
            OkfConversionJob.lease_id == lease_id,
        )
        .with_for_update()
    )
    if locked is None:
        await session.rollback()
        return
    exhausted = locked.attempts >= settings.okf_conversion_max_attempts
    locked.status = (
        OkfConversionStatus.FAILED if exhausted or not retryable else OkfConversionStatus.RETRY_WAIT
    )
    locked.error_code = code
    locked.locked_at = None
    locked.lease_id = None
    locked.next_attempt_at = (
        None
        if locked.status is OkfConversionStatus.FAILED
        else datetime.now(UTC) + timedelta(seconds=min(30 * (2 ** (locked.attempts - 1)), 900))
    )
    if locked.status is OkfConversionStatus.FAILED:
        locked.completed_at = datetime.now(UTC)
    file = await session.get(File, locked.file_id)
    if file is not None:
        file.knowledge_status = (
            KnowledgeIngestionStatus.FAILED
            if locked.status is OkfConversionStatus.FAILED
            else KnowledgeIngestionStatus.PENDING
        )
        file.knowledge_error_code = code
    add_audit_event(
        session,
        action="okf.conversion_failed",
        result=AuditResult.FAILURE,
        resource_type="okf_conversion_job",
        resource_id=str(locked.id),
        details={"error_code": code, "retrying": not exhausted and retryable},
    )
    await session.commit()


async def _finish_terminal(
    session: AsyncSession,
    job_id: UUID,
    lease_id: UUID,
    status: OkfConversionStatus,
    error_code: str,
) -> None:
    job = await session.scalar(
        select(OkfConversionJob)
        .where(
            OkfConversionJob.id == job_id,
            OkfConversionJob.status == OkfConversionStatus.PROCESSING,
            OkfConversionJob.lease_id == lease_id,
        )
        .with_for_update()
    )
    if job is None:
        await session.rollback()
        return
    job.status = status
    job.error_code = error_code
    job.locked_at = None
    job.lease_id = None
    job.completed_at = datetime.now(UTC)
    file = await session.get(File, job.file_id)
    if file is not None:
        file.knowledge_status = (
            KnowledgeIngestionStatus.UNSUPPORTED
            if status is OkfConversionStatus.UNSUPPORTED
            else KnowledgeIngestionStatus.FAILED
        )
        file.knowledge_error_code = error_code
    add_audit_event(
        session,
        action="okf.conversion_skipped",
        result=AuditResult.SUCCESS,
        resource_type="okf_conversion_job",
        resource_id=str(job.id),
        details={"reason": error_code},
    )
    await session.commit()


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9\u4e00-\u9fff]+", "-", value).strip("-").lower()
    return (normalized or "concept")[:120]
