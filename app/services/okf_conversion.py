from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta
from time import monotonic
from uuid import UUID, uuid4

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models import (
    File,
    FileStatus,
    KnowledgeBase,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
    OkfConversionJob,
    OkfConversionStatus,
)
from app.services.audit import add_audit_event
from app.services.llm_provider import LlmProviderError, LlmResult, OpenAICompatibleClient
from app.services.storage import StorageService

PROMPT_VERSION = "okf-phase1-v1"
SUPPORTED_TEXT_EXTENSIONS = frozenset({".txt", ".csv"})
logger = logging.getLogger(__name__)


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
    session.add(job)
    await session.flush()
    return job


async def process_okf_conversion_batch(
    session: AsyncSession,
    storage: StorageService,
    client: OpenAICompatibleClient,
    settings: Settings,
    *,
    batch_size: int,
) -> int:
    if not client.configured:
        return 0
    processed = 0
    deadline = monotonic() + settings.okf_conversion_time_budget_seconds
    for _ in range(batch_size):
        if processed and deadline - monotonic() < settings.deepseek_timeout_seconds:
            break
        job = await _claim_job(session, settings)
        if job is None:
            break
        processed += 1
        lease_id = job.lease_id
        if lease_id is None:
            continue
        try:
            await _process_claimed_job(
                session, storage, client, settings, job.id, lease_id
            )
        except Exception:
            # One malformed object or transient SDK failure must not fail the
            # whole cron batch. Details stay in server telemetry; the durable
            # record stores a bounded, non-sensitive classification.
            logger.exception(
                "OKF conversion job failed unexpectedly",
                extra={"okf_conversion_job_id": str(job.id)},
            )
            await session.rollback()
            await _mark_failure(
                session,
                job.id,
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
        .join(KnowledgeBase, KnowledgeBase.id == OkfConversionJob.knowledge_base_id)
        .where(eligible, KnowledgeBase.external_llm_processing_enabled.is_(True))
        .order_by(OkfConversionJob.created_at, OkfConversionJob.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if job is None:
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
    client: OpenAICompatibleClient,
    settings: Settings,
    job_id: UUID,
    lease_id: UUID,
) -> None:
    row = (
        await session.execute(
            select(OkfConversionJob, File, KnowledgeBase)
            .join(File, File.id == OkfConversionJob.file_id)
            .join(KnowledgeBase, KnowledgeBase.id == OkfConversionJob.knowledge_base_id)
            .where(OkfConversionJob.id == job_id, OkfConversionJob.lease_id == lease_id)
        )
    ).one_or_none()
    if row is None:
        return
    job, file, knowledge_base = row
    if not knowledge_base.external_llm_processing_enabled:
        await _release_for_policy_change(session, job_id, lease_id)
        return
    if file.extension not in SUPPORTED_TEXT_EXTENSIONS:
        await _finish_terminal(
            session, job_id, lease_id, OkfConversionStatus.UNSUPPORTED, "parser_required"
        )
        return
    if file.size_bytes > settings.okf_source_max_bytes:
        await _finish_terminal(
            session, job_id, lease_id, OkfConversionStatus.UNSUPPORTED, "source_too_large"
        )
        return
    try:
        raw = await storage.read_bytes(
            key=file.object_key, max_bytes=settings.okf_source_max_bytes
        )
        source_text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        await _finish_terminal(
            session, job_id, lease_id, OkfConversionStatus.UNSUPPORTED, "non_utf8_text"
        )
        return
    except ValueError:
        await _finish_terminal(
            session, job_id, lease_id, OkfConversionStatus.UNSUPPORTED, "source_too_large"
        )
        return
    if not source_text.strip():
        await _finish_terminal(
            session, job_id, lease_id, OkfConversionStatus.UNSUPPORTED, "empty_source"
        )
        return

    # Re-read consent immediately before the external request; object access
    # can take time and a manager may have opted out after this job was claimed.
    await session.refresh(knowledge_base)
    if not knowledge_base.external_llm_processing_enabled:
        await _release_for_policy_change(session, job_id, lease_id)
        return

    try:
        result = await client.compile_okf(source_text, user_id=f"kb_{job.knowledge_base_id.hex}")
    except LlmProviderError as error:
        await _mark_failure(
            session,
            job_id,
            lease_id,
            code=error.code,
            retryable=error.retryable,
            settings=settings,
        )
        return
    await _persist_result(session, job_id, lease_id, file, result)


async def _persist_result(
    session: AsyncSession,
    job_id: UUID,
    lease_id: UUID,
    file: File,
    result: LlmResult,
) -> None:
    # A recovered lease may race a prior worker. Lock and re-check before insert.
    locked = await session.scalar(
        select(OkfConversionJob)
        .where(
            OkfConversionJob.id == job_id,
            OkfConversionJob.lease_id == lease_id,
        )
        .with_for_update()
    )
    if locked is None or locked.status is not OkfConversionStatus.PROCESSING:
        await session.rollback()
        return
    locked_file = await session.scalar(
        select(File).where(File.id == file.id).with_for_update()
    )
    if locked_file is None:
        await session.rollback()
        return
    now = datetime.now(UTC)
    entry = KnowledgeEntry(
        knowledge_base_id=locked.knowledge_base_id,
        source_file_id=file.id,
        entry_type=result.draft.type,
        title=result.draft.title,
        content=result.draft.body_markdown,
        source_path=f"generated/{file.id}/{_slug(result.draft.title)}.md",
        format_version="okf/0.1",
        publication_status=(
            KnowledgeEntryPublicationStatus.PUBLISHED
            if locked_file.status is FileStatus.AVAILABLE
            else KnowledgeEntryPublicationStatus.DRAFT
        ),
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
            OkfConversionJob.lease_id == lease_id,
        )
        .with_for_update()
    )
    if locked is None:
        return
    exhausted = locked.attempts >= settings.okf_conversion_max_attempts
    locked.status = (
        OkfConversionStatus.FAILED
        if exhausted or not retryable
        else OkfConversionStatus.RETRY_WAIT
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
    add_audit_event(
        session,
        action="okf.conversion_failed",
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
            OkfConversionJob.lease_id == lease_id,
        )
        .with_for_update()
    )
    if job is None:
        return
    job.status = status
    job.error_code = error_code
    job.locked_at = None
    job.lease_id = None
    job.completed_at = datetime.now(UTC)
    add_audit_event(
        session,
        action="okf.conversion_skipped",
        resource_type="okf_conversion_job",
        resource_id=str(job.id),
        details={"reason": error_code},
    )
    await session.commit()


async def _release_for_policy_change(
    session: AsyncSession, job_id: UUID, lease_id: UUID
) -> None:
    job = await session.scalar(
        select(OkfConversionJob)
        .where(
            OkfConversionJob.id == job_id,
            OkfConversionJob.lease_id == lease_id,
        )
        .with_for_update()
    )
    if job is None:
        return
    job.status = OkfConversionStatus.PENDING
    job.attempts = max(0, job.attempts - 1)
    job.error_code = "external_processing_not_allowed"
    job.locked_at = None
    job.lease_id = None
    await session.commit()


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9\u4e00-\u9fff]+", "-", value).strip("-").lower()
    return (normalized or "concept")[:120]
