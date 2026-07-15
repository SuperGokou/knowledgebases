from __future__ import annotations

import base64
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import and_, exists, false, func, or_, select, text

from app.api.dependencies import DatabaseSession, get_storage_service, require_permission
from app.api.errors import ApiError
from app.core.config import Settings, get_settings
from app.core.time import as_utc
from app.db.models import (
    File,
    FileStatus,
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
    KnowledgeIngestionStatus,
    MalwareScanStatus,
    OkfConversionJob,
    OkfConversionStatus,
    QuotaReservation,
    ReservationStatus,
    UploadSession,
    UploadSessionStatus,
)
from app.domain.errors import FilePolicyViolation
from app.domain.files import UploadMode, plan_upload, validate_upload
from app.schemas.files import (
    CompleteUploadRequest,
    DownloadGrant,
    FileRead,
    OkfConversionRead,
    PartUrl,
    PartUrlRequest,
    PartUrlResponse,
    UploadInitiateRequest,
    UploadInitiateResponse,
    UploadSessionRead,
)
from app.services.access import AccessContext
from app.services.audit import AuditResult, add_audit_event
from app.services.knowledge_bases import require_knowledge_base_access
from app.services.list_search import literal_contains_pattern
from app.services.quota import QuotaService, QuotaSpec, daily_window_start, lifetime_window_start
from app.services.storage import StorageService, StoredObject
from app.services.storage_capacity import (
    FilesystemCapacity,
    StoragePolicyViolation,
    assess_storage_capacity,
    effective_upload_limit,
)

router = APIRouter()

_STORAGE_CAPACITY_ADVISORY_LOCK = 0x4B4253544F524147


def _checksum_base64(checksum_hex: str | None) -> str | None:
    if checksum_hex is None:
        return None
    return base64.b64encode(bytes.fromhex(checksum_hex)).decode("ascii")


def _object_key(
    user_id: UUID,
    file_id: UUID,
    extension: str,
    mode: UploadMode,
) -> str:
    now = datetime.now(UTC)
    prefix = "staging" if mode is UploadMode.SINGLE else "objects"
    return f"{prefix}/users/{user_id}/{now:%Y/%m}/{file_id}{extension}"


def _final_object_key(staging_key: str) -> str:
    if not staging_key.startswith("staging/"):
        raise ValueError("upload object is not in the staging prefix")
    return f"objects/{staging_key.removeprefix('staging/')}"


def _initiate_response(
    upload: UploadSession,
    *,
    upload_url: str | None = None,
    required_headers: dict[str, str] | None = None,
) -> UploadInitiateResponse:
    return UploadInitiateResponse(
        upload_session_id=upload.id,
        file_id=upload.file_id,
        mode=upload.mode,
        expires_at=upload.expires_at,
        part_size_bytes=upload.part_size_bytes,
        part_count=upload.part_count,
        upload_url=upload_url,
        required_headers=required_headers or {},
    )


async def _cleanup_completed_upload_objects(
    storage: StorageService,
    *,
    mode: str,
    source_key: str,
    final_key: str,
    upload_session_id: UUID,
) -> None:
    if mode == UploadMode.SINGLE.value:
        if final_key != source_key:
            await storage.delete(key=final_key)
        await storage.seal_single_upload(
            key=source_key,
            upload_session_id=str(upload_session_id),
        )
        return
    await storage.delete(key=source_key)


async def _owned_upload(
    session: DatabaseSession,
    *,
    upload_session_id: UUID,
    user_id: UUID,
    lock: bool = False,
) -> tuple[UploadSession, File]:
    statement = (
        select(UploadSession, File)
        .join(File, File.id == UploadSession.file_id)
        .where(UploadSession.id == upload_session_id, UploadSession.user_id == user_id)
    )
    if lock:
        statement = statement.execution_options(populate_existing=True).with_for_update()
    row = (await session.execute(statement)).one_or_none()
    if row is None:
        raise ApiError(status_code=404, code="upload_not_found", message="Upload session not found")
    return row[0], row[1]


async def _has_held_upload_reservation(
    session: DatabaseSession,
    *,
    upload_session_id: UUID,
) -> bool:
    return bool(
        await session.scalar(
            select(
                exists().where(
                    QuotaReservation.upload_session_id == upload_session_id,
                    QuotaReservation.status == ReservationStatus.HELD,
                )
            )
        )
    )


async def _locked_object_usage(session: DatabaseSession) -> tuple[int, int]:
    bind = session.get_bind()
    if bind.dialect.name == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": _STORAGE_CAPACITY_ADVISORY_LOCK},
        )
    used = (
        await session.execute(
            select(
                func.coalesce(func.sum(File.size_bytes), 0),
                func.count(File.id),
            ).where(
                File.deleted_at.is_(None),
                File.status.not_in((FileStatus.FAILED, FileStatus.DELETED)),
            )
        )
    ).one()
    return int(used[0] or 0), int(used[1] or 0)


def _effective_count_limit(role_limit: int | None, *, platform_limit: int) -> int:
    if role_limit is None:
        return platform_limit
    return min(role_limit, platform_limit)


async def _enforce_storage_policy(
    *,
    session: DatabaseSession,
    settings: Settings,
    response: Response,
    incoming_bytes: int,
    is_bulk: bool,
) -> None:
    object_used_bytes, object_count = await _locked_object_usage(session)
    if incoming_bytes > 0 and object_count >= settings.platform_max_files_total:
        raise ApiError(
            status_code=507,
            code="platform_file_count_limit_reached",
            message="The platform file-count safety limit has been reached",
        )
    if settings.storage_capacity_probe_path is None:
        return
    try:
        filesystem = FilesystemCapacity.from_path(settings.storage_capacity_probe_path)
    except StoragePolicyViolation as error:
        raise ApiError(
            status_code=503,
            code=error.reason_code,
            message="Storage capacity evidence is temporarily unavailable",
        ) from error
    assessment = assess_storage_capacity(
        filesystem=filesystem,
        object_used_bytes=object_used_bytes,
        incoming_bytes=incoming_bytes,
        is_bulk=is_bulk,
        warning_percent=settings.storage_warning_percent,
        bulk_stop_percent=settings.storage_bulk_stop_percent,
        reject_percent=settings.storage_reject_percent,
        object_stop_bytes=settings.storage_object_stop_bytes,
    )
    response.headers["X-KB-Storage-Policy"] = assessment.level
    if not assessment.allowed:
        raise ApiError(
            status_code=507,
            code=assessment.reason_code or "storage_capacity_rejected",
            message="Storage safety policy rejected this upload",
        )


async def _record_finalization_rejection(
    *,
    session: DatabaseSession,
    access: AccessContext,
    upload_session_id: UUID,
    request: Request,
    action: str,
    details: dict[str, object] | None = None,
) -> bool:
    upload, file = await _owned_upload(
        session,
        upload_session_id=upload_session_id,
        user_id=access.user.id,
        lock=True,
    )
    if upload.status is not UploadSessionStatus.FINALIZING:
        await session.rollback()
        return False
    if file.knowledge_base_id is not None:
        await require_knowledge_base_access(
            session,
            access,
            file.knowledge_base_id,
            minimum=KnowledgeBaseAccessLevel.EDITOR,
            lock=True,
        )
    upload.status = UploadSessionStatus.FAILED
    file.status = FileStatus.FAILED
    await QuotaService().release_upload_reservations(
        session,
        upload_session_id=upload.id,
        status=ReservationStatus.RELEASED,
    )
    add_audit_event(
        session,
        actor_id=access.user.id,
        action=action,
        result=AuditResult.DENIED,
        resource_type="file",
        resource_id=str(file.id),
        request_id=getattr(request.state, "request_id", None),
        details=details,
    )
    await session.commit()
    return True


@router.get("", response_model=list[FileRead])
async def list_files(
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("file:read"))],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    search: Annotated[str | None, Query(max_length=200)] = None,
) -> list[File]:
    statement = select(File).where(File.deleted_at.is_(None))
    if not access.allows("file:read:any"):
        owned_knowledge_base = exists().where(
            KnowledgeBase.id == File.knowledge_base_id,
            KnowledgeBase.owner_id == access.user.id,
        )
        role_grant = (
            exists().where(
                KnowledgeBaseRoleGrant.knowledge_base_id == File.knowledge_base_id,
                KnowledgeBaseRoleGrant.role_id.in_(access.role_ids),
            )
            if access.role_ids
            else false()
        )
        statement = statement.where(
            or_(
                and_(
                    File.knowledge_base_id.is_(None),
                    File.owner_id == access.user.id,
                ),
                owned_knowledge_base,
                role_grant,
            )
        )
    term = search.strip() if search else ""
    if term:
        pattern = literal_contains_pattern(term)
        statement = statement.where(File.original_name.ilike(pattern, escape="\\"))
    statement = statement.order_by(File.created_at.desc(), File.id).limit(limit).offset(offset)
    return list((await session.scalars(statement)).all())


@router.post("/uploads", response_model=UploadInitiateResponse, status_code=201)
async def initiate_upload(
    payload: UploadInitiateRequest,
    request: Request,
    response: Response,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("file:upload"))],
    settings: Annotated[Settings, Depends(get_settings)],
    storage: Annotated[StorageService, Depends(get_storage_service)],
) -> UploadInitiateResponse:
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    if len(json.dumps(payload.custom_metadata, ensure_ascii=False).encode("utf-8")) > 16_384:
        raise ApiError(
            status_code=422,
            code="metadata_too_large",
            message="Custom metadata must not exceed 16 KiB",
        )

    if payload.knowledge_base_id is not None:
        await require_knowledge_base_access(
            session,
            access,
            payload.knowledge_base_id,
            minimum=KnowledgeBaseAccessLevel.EDITOR,
            lock=True,
        )

    maximum = effective_upload_limit(
        access.limits.get("max_upload_bytes", 0),
        platform_limit_bytes=settings.platform_max_upload_bytes,
    )
    try:
        validated = validate_upload(
            payload.filename,
            payload.size_bytes,
            maximum,
            set(settings.allowed_extensions),
        )
    except FilePolicyViolation as error:
        status_code = 413 if "maximum upload size" in str(error) else 422
        raise ApiError(
            status_code=status_code, code="file_policy_violation", message=str(error)
        ) from error

    existing_row = (
        await session.execute(
            select(UploadSession, File)
            .join(File, File.id == UploadSession.file_id)
            .where(
                UploadSession.user_id == access.user.id,
                UploadSession.idempotency_key == payload.idempotency_key,
            )
        )
    ).one_or_none()
    if existing_row is not None:
        existing, existing_file = existing_row
        if (
            existing_file.original_name != validated.filename
            or existing.expected_size_bytes != validated.size_bytes
            or existing_file.knowledge_base_id != payload.knowledge_base_id
        ):
            raise ApiError(
                status_code=409,
                code="idempotency_conflict",
                message="Idempotency key was already used with another upload request",
            )
        if existing.status is not UploadSessionStatus.INITIATED:
            return _initiate_response(existing)
        if as_utc(existing.expires_at) <= datetime.now(UTC):
            raise ApiError(
                status_code=410,
                code="upload_expired",
                message="Upload session has expired and cannot be re-signed",
            )
        plan = plan_upload(
            size_bytes=existing.expected_size_bytes,
            multipart_threshold_bytes=settings.multipart_threshold_bytes,
            preferred_part_size=existing.part_size_bytes,
        )
        if existing.mode == UploadMode.SINGLE.value:
            signed = await storage.initiate(
                key=existing_file.object_key,
                content_type=existing_file.content_type,
                upload_session_id=str(existing.id),
                expected_size_bytes=existing.expected_size_bytes,
                plan=plan,
                expected_checksum_sha256_base64=_checksum_base64(existing_file.checksum_value),
            )
            return _initiate_response(
                existing,
                upload_url=signed.url,
                required_headers=signed.required_headers,
            )
        if existing.storage_upload_id is None:
            # The admission transaction may have committed before a prior S3
            # initiation attempt failed. Release the read transaction before
            # retrying external I/O; the persisted reservation remains the
            # authoritative admission decision.
            await session.commit()
            initiated = await storage.initiate(
                key=existing_file.object_key,
                content_type=existing_file.content_type,
                upload_session_id=str(existing.id),
                expected_size_bytes=existing.expected_size_bytes,
                plan=plan,
                expected_checksum_sha256_base64=None,
            )
            persisted, _ = await _owned_upload(
                session,
                upload_session_id=existing.id,
                user_id=access.user.id,
                lock=True,
            )
            duplicate_upload_id: str | None = None
            if persisted.storage_upload_id is None:
                persisted.storage_upload_id = initiated.upload_id
            elif initiated.upload_id != persisted.storage_upload_id:
                duplicate_upload_id = initiated.upload_id
            await session.commit()
            if duplicate_upload_id is not None:
                await storage.abort_multipart(
                    key=existing_file.object_key,
                    upload_id=duplicate_upload_id,
                )
        return _initiate_response(existing)

    plan = plan_upload(
        size_bytes=validated.size_bytes,
        multipart_threshold_bytes=settings.multipart_threshold_bytes,
        preferred_part_size=settings.multipart_part_size_bytes,
    )
    await _enforce_storage_policy(
        session=session,
        settings=settings,
        response=response,
        incoming_bytes=validated.size_bytes,
        is_bulk=plan.mode is UploadMode.MULTIPART,
    )
    if payload.checksum_sha256 is not None and plan.mode is UploadMode.MULTIPART:
        raise ApiError(
            status_code=422,
            code="multipart_checksum_not_supported",
            message=(
                "Whole-object SHA-256 verification is currently supported only "
                "for single-part uploads"
            ),
        )
    file_id = uuid4()
    upload_id = uuid4()
    expires_at = datetime.now(UTC) + timedelta(hours=settings.upload_session_hours)
    file = File(
        id=file_id,
        owner_id=access.user.id,
        knowledge_base_id=payload.knowledge_base_id,
        bucket=settings.s3_bucket,
        object_key=_object_key(access.user.id, file_id, validated.extension, plan.mode),
        original_name=validated.filename,
        extension=validated.extension,
        content_type=payload.content_type,
        size_bytes=validated.size_bytes,
        checksum_algorithm="SHA256" if payload.checksum_sha256 else None,
        checksum_value=payload.checksum_sha256.lower() if payload.checksum_sha256 else None,
        custom_metadata=payload.custom_metadata,
        status=FileStatus.UPLOADING,
    )
    upload = UploadSession(
        id=upload_id,
        file_id=file_id,
        user_id=access.user.id,
        idempotency_key=payload.idempotency_key,
        mode=plan.mode.value,
        part_size_bytes=plan.part_size_bytes,
        part_count=plan.part_count,
        expected_size_bytes=validated.size_bytes,
        expires_at=expires_at,
    )
    session.add_all([file, upload])
    await session.flush()

    await QuotaService().reserve_many(
        session,
        user_id=access.user.id,
        upload_session_id=upload.id,
        specs=[
            QuotaSpec(
                key="daily_upload_bytes",
                amount=validated.size_bytes,
                limit=access.limits.get("daily_upload_bytes", 0),
                window_start=daily_window_start(),
            ),
            QuotaSpec(
                key="storage_bytes",
                amount=validated.size_bytes,
                limit=access.limits.get("storage_bytes", 0),
                window_start=lifetime_window_start(),
            ),
            QuotaSpec(
                key="file_count",
                amount=1,
                limit=_effective_count_limit(
                    access.limits.get("file_count"),
                    platform_limit=settings.platform_max_files_per_user,
                ),
                window_start=lifetime_window_start(),
            ),
        ],
        expires_at=expires_at,
    )
    # Persist admission and release quota/capacity locks before the network
    # call. If S3 is unavailable, the INITIATED row and reservation are safely
    # retryable by the same idempotency key and expire through maintenance.
    await session.commit()
    initiated = await storage.initiate(
        key=file.object_key,
        content_type=file.content_type,
        upload_session_id=str(upload.id),
        expected_size_bytes=upload.expected_size_bytes,
        plan=plan,
        expected_checksum_sha256_base64=_checksum_base64(file.checksum_value),
    )
    persisted_upload, persisted_file = await _owned_upload(
        session,
        upload_session_id=upload.id,
        user_id=access.user.id,
        lock=True,
    )
    redundant_upload_id: str | None = None
    if persisted_upload.storage_upload_id is None:
        persisted_upload.storage_upload_id = initiated.upload_id
    elif initiated.upload_id != persisted_upload.storage_upload_id:
        redundant_upload_id = initiated.upload_id
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="upload.initiated",
        result=AuditResult.SUCCESS,
        resource_type="file",
        resource_id=str(persisted_file.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "size_bytes": persisted_file.size_bytes,
            "mode": plan.mode.value,
            "knowledge_base_id": str(persisted_file.knowledge_base_id)
            if persisted_file.knowledge_base_id
            else None,
        },
    )
    await session.commit()
    if redundant_upload_id is not None:
        await storage.abort_multipart(
            key=persisted_file.object_key,
            upload_id=redundant_upload_id,
        )
    return _initiate_response(
        persisted_upload,
        upload_url=initiated.url,
        required_headers=initiated.required_headers,
    )


@router.post("/uploads/{upload_session_id}/parts", response_model=PartUrlResponse)
async def create_part_urls(
    upload_session_id: UUID,
    payload: PartUrlRequest,
    response: Response,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("file:upload"))],
    settings: Annotated[Settings, Depends(get_settings)],
    storage: Annotated[StorageService, Depends(get_storage_service)],
) -> PartUrlResponse:
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    upload, file = await _owned_upload(
        session, upload_session_id=upload_session_id, user_id=access.user.id
    )
    if file.knowledge_base_id is not None:
        await require_knowledge_base_access(
            session,
            access,
            file.knowledge_base_id,
            minimum=KnowledgeBaseAccessLevel.EDITOR,
            lock=True,
        )
    if upload.mode != UploadMode.MULTIPART.value or not upload.storage_upload_id:
        raise ApiError(status_code=409, code="not_multipart", message="Upload is not multipart")
    if upload.status is not UploadSessionStatus.INITIATED:
        raise ApiError(
            status_code=409, code="upload_state_conflict", message="Upload is not active"
        )
    await _enforce_storage_policy(
        session=session,
        settings=settings,
        response=response,
        incoming_bytes=0,
        is_bulk=True,
    )
    if upload.status is UploadSessionStatus.INITIATED and as_utc(upload.expires_at) <= datetime.now(
        UTC
    ):
        raise ApiError(status_code=410, code="upload_expired", message="Upload session has expired")
    if any(number < 1 or number > upload.part_count for number in payload.part_numbers):
        raise ApiError(status_code=422, code="invalid_part", message="Part number is out of range")
    urls = storage.presign_parts(
        key=file.object_key,
        upload_id=upload.storage_upload_id,
        part_numbers=payload.part_numbers,
        expected_size_bytes=upload.expected_size_bytes,
        part_size_bytes=upload.part_size_bytes,
    )
    return PartUrlResponse(
        parts=[
            PartUrl(
                part_number=number,
                url=urls[number].url,
                size_bytes=urls[number].size_bytes,
            )
            for number in payload.part_numbers
        ],
        expires_in=settings.presigned_url_seconds,
    )


@router.post("/uploads/{upload_session_id}/complete", response_model=FileRead)
async def complete_upload(
    upload_session_id: UUID,
    payload: CompleteUploadRequest,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("file:upload"))],
    storage: Annotated[StorageService, Depends(get_storage_service)],
) -> File:
    upload, file = await _owned_upload(
        session,
        upload_session_id=upload_session_id,
        user_id=access.user.id,
        lock=True,
    )
    if file.knowledge_base_id is not None:
        await require_knowledge_base_access(
            session,
            access,
            file.knowledge_base_id,
            minimum=KnowledgeBaseAccessLevel.EDITOR,
            lock=True,
        )
    if upload.status is UploadSessionStatus.COMPLETED:
        return file
    if upload.status not in {
        UploadSessionStatus.INITIATED,
        UploadSessionStatus.FINALIZING,
    }:
        raise ApiError(
            status_code=409,
            code="upload_state_conflict",
            message="Upload is not active",
        )
    if upload.status is UploadSessionStatus.INITIATED and as_utc(upload.expires_at) <= datetime.now(
        UTC
    ):
        raise ApiError(status_code=410, code="upload_expired", message="Upload session has expired")

    mode = upload.mode
    source_key = file.object_key
    final_key = _final_object_key(source_key) if mode == UploadMode.SINGLE.value else source_key
    expected_size = upload.expected_size_bytes
    expected_checksum = _checksum_base64(file.checksum_value)
    storage_upload_id = upload.storage_upload_id
    parts: list[dict[str, object]] = []
    if mode == UploadMode.MULTIPART.value:
        numbers = sorted(item.part_number for item in payload.parts)
        if numbers != list(range(1, upload.part_count + 1)):
            raise ApiError(
                status_code=422,
                code="incomplete_parts",
                message="Every multipart part must be supplied exactly once",
            )
        if not storage_upload_id:
            raise ApiError(
                status_code=409,
                code="missing_upload_id",
                message="Storage upload ID is missing",
            )
        for item in sorted(payload.parts, key=lambda value: value.part_number):
            part: dict[str, object] = {"PartNumber": item.part_number, "ETag": item.etag}
            if item.checksum_sha256:
                part["ChecksumSHA256"] = item.checksum_sha256
            parts.append(part)
    elif payload.parts:
        raise ApiError(
            status_code=422,
            code="unexpected_parts",
            message="Single upload has no parts",
        )

    upload.status = UploadSessionStatus.FINALIZING
    current_expiry = (
        as_utc(upload.expires_at) if upload.expires_at is not None else datetime.now(UTC)
    )
    upload.expires_at = max(current_expiry, datetime.now(UTC) + timedelta(minutes=15))
    # This commit releases both the upload and KB row locks before every S3
    # operation for both single and multipart completion attempts.
    await session.commit()

    stored: StoredObject | None
    if mode == UploadMode.MULTIPART.value:
        await storage.complete_multipart(
            key=source_key,
            upload_id=cast(str, storage_upload_id),
            parts=parts,
        )
        stored = await storage.head(key=source_key)
    else:
        # Prefer an already-promoted final object so a retry after a process
        # crash does not mistake the staging tombstone for uploaded content.
        stored = await storage.try_head(key=final_key)
        if stored is None:
            stored = await storage.try_head(key=source_key)
            if stored is None:
                raise ApiError(
                    status_code=409,
                    code="stored_object_missing",
                    message="The uploaded object is not available in storage",
                )
            stored = await storage.promote(
                source_key=source_key,
                destination_key=final_key,
                upload_session_id=str(upload_session_id),
            )
    if stored is None:
        raise ApiError(
            status_code=409,
            code="stored_object_missing",
            message="The uploaded object is not available in storage",
        )

    rejection_code: str | None = None
    rejection_action: str | None = None
    rejection_message: str | None = None
    rejection_details: dict[str, object] | None = None
    if stored.size_bytes != expected_size:
        rejection_code = "uploaded_size_mismatch"
        rejection_action = "upload.rejected_size_mismatch"
        rejection_message = "Stored object size differs from the declared size"
        rejection_details = {"expected": expected_size, "actual": stored.size_bytes}
    elif expected_checksum is not None and (
        stored.checksum_sha256 is None
        or not hmac.compare_digest(stored.checksum_sha256, expected_checksum)
    ):
        rejection_code = "uploaded_checksum_mismatch"
        rejection_action = "upload.rejected_checksum_mismatch"
        rejection_message = "Stored object SHA-256 differs from the declared checksum"

    if rejection_code is not None:
        # Cleanup happens while no database transaction is open. Only then do
        # we conditionally transition FINALIZING -> FAILED.
        await _cleanup_completed_upload_objects(
            storage,
            mode=mode,
            source_key=source_key,
            final_key=final_key,
            upload_session_id=upload_session_id,
        )
        recorded = await _record_finalization_rejection(
            session=session,
            access=access,
            upload_session_id=upload_session_id,
            request=request,
            action=cast(str, rejection_action),
            details=rejection_details,
        )
        if not recorded:
            raise ApiError(
                status_code=409,
                code="upload_state_conflict",
                message="Upload state changed while finalization was in progress",
            )
        raise ApiError(
            status_code=422,
            code=rejection_code,
            message=cast(str, rejection_message),
        )

    # Re-read under lock with populate_existing. Objects retained across the
    # pre-S3 commit are not authoritative after abort/finalization races.
    upload, file = await _owned_upload(
        session,
        upload_session_id=upload_session_id,
        user_id=access.user.id,
        lock=True,
    )
    if upload.status is UploadSessionStatus.COMPLETED:
        await session.rollback()
        return file
    if upload.status is not UploadSessionStatus.FINALIZING:
        concurrent_status = upload.status
        await session.rollback()
        await _cleanup_completed_upload_objects(
            storage,
            mode=mode,
            source_key=source_key,
            final_key=final_key,
            upload_session_id=upload_session_id,
        )
        raise ApiError(
            status_code=409,
            code="upload_state_conflict",
            message=f"Upload became {concurrent_status.value} during finalization",
        )
    if file.knowledge_base_id is not None:
        await require_knowledge_base_access(
            session,
            access,
            file.knowledge_base_id,
            minimum=KnowledgeBaseAccessLevel.EDITOR,
            lock=True,
        )

    file.object_key = final_key
    await QuotaService().consume_upload_reservations(session, upload_session_id=upload.id)
    upload.status = UploadSessionStatus.COMPLETED
    upload.completed_at = datetime.now(UTC)
    file.size_bytes = stored.size_bytes
    file.status = FileStatus.QUARANTINED
    if stored.checksum_sha256 and file.checksum_value is None:
        file.checksum_algorithm = "SHA256"
        file.checksum_value = stored.checksum_sha256
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="upload.completed",
        result=AuditResult.SUCCESS,
        resource_type="file",
        resource_id=str(file.id),
        request_id=getattr(request.state, "request_id", None),
        details={"status": "quarantined", "malware_scan_status": "pending"},
    )
    await session.commit()
    await session.refresh(file)
    return file


@router.get("/{file_id}/okf-conversion", response_model=OkfConversionRead)
async def get_okf_conversion(
    file_id: UUID,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("file:read"))],
) -> OkfConversionJob:
    row = (
        await session.execute(
            select(OkfConversionJob, File)
            .join(File, File.id == OkfConversionJob.file_id)
            .where(OkfConversionJob.file_id == file_id)
            .order_by(OkfConversionJob.file_version.desc())
            .limit(1)
        )
    ).one_or_none()
    if row is None:
        raise ApiError(
            status_code=404,
            code="okf_conversion_not_found",
            message="Conversion not found",
        )
    conversion = cast(OkfConversionJob, row[0])
    file = cast(File, row[1])
    if not access.allows("file:read:any"):
        if file.knowledge_base_id is None:
            if file.owner_id != access.user.id:
                raise ApiError(
                    status_code=404,
                    code="okf_conversion_not_found",
                    message="Conversion not found",
                )
        else:
            await require_knowledge_base_access(session, access, file.knowledge_base_id)
    return conversion


@router.post("/{file_id}/okf-conversion/retry", response_model=OkfConversionRead)
async def retry_okf_conversion(
    file_id: UUID,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("file:approve"))],
) -> OkfConversionJob:
    row = (
        await session.execute(
            select(OkfConversionJob, File)
            .join(File, File.id == OkfConversionJob.file_id)
            .where(OkfConversionJob.file_id == file_id)
            .order_by(OkfConversionJob.file_version.desc())
            .limit(1)
            .with_for_update()
        )
    ).one_or_none()
    if row is None:
        raise ApiError(
            status_code=404,
            code="okf_conversion_not_found",
            message="Conversion not found",
        )
    conversion = cast(OkfConversionJob, row[0])
    file = cast(File, row[1])
    await require_knowledge_base_access(
        session,
        access,
        conversion.knowledge_base_id,
        minimum=KnowledgeBaseAccessLevel.MANAGER,
        lock=True,
    )
    if file.status is not FileStatus.PROCESSING:
        raise ApiError(
            status_code=409,
            code="okf_retry_file_state_conflict",
            message="Only files awaiting approval can retry an OKF conversion",
        )
    if conversion.status not in {
        OkfConversionStatus.FAILED,
        OkfConversionStatus.UNSUPPORTED,
    }:
        raise ApiError(
            status_code=409,
            code="okf_conversion_state_conflict",
            message="Only terminal failed conversions can be retried",
        )
    conversion.status = OkfConversionStatus.PENDING
    conversion.attempts = 0
    conversion.retry_generation += 1
    conversion.error_code = None
    conversion.next_attempt_at = None
    conversion.locked_at = None
    conversion.lease_id = None
    conversion.completed_at = None
    file.knowledge_status = KnowledgeIngestionStatus.PENDING
    file.knowledge_error_code = None
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="okf.conversion_retried",
        result=AuditResult.SUCCESS,
        resource_type="okf_conversion_job",
        resource_id=str(conversion.id),
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(conversion)
    return conversion


@router.delete("/uploads/{upload_session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def abort_upload(
    upload_session_id: UUID,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("file:upload"))],
    storage: Annotated[StorageService, Depends(get_storage_service)],
) -> None:
    upload, file = await _owned_upload(
        session,
        upload_session_id=upload_session_id,
        user_id=access.user.id,
        lock=True,
    )
    if upload.status is UploadSessionStatus.COMPLETED:
        raise ApiError(
            status_code=409, code="upload_completed", message="Completed upload cannot be aborted"
        )
    if upload.status is UploadSessionStatus.EXPIRED:
        return
    if upload.status is UploadSessionStatus.ABORTED and not await _has_held_upload_reservation(
        session,
        upload_session_id=upload.id,
    ):
        return
    if upload.status is not UploadSessionStatus.ABORTED:
        # Persist a terminal application state before releasing the DB lock.
        # The held reservation is intentionally retained until storage cleanup
        # succeeds; a failed request is retryable and maintenance can reconcile
        # it after expires_at.
        upload.status = UploadSessionStatus.ABORTED
        upload.expires_at = datetime.now(UTC)
        file.status = FileStatus.FAILED
        await session.commit()
    else:
        # This is a cleanup retry for an already terminal row. Release the row
        # lock before idempotent S3 cleanup.
        await session.commit()
    if upload.storage_upload_id:
        await storage.abort_multipart(key=file.object_key, upload_id=upload.storage_upload_id)
    else:
        await storage.seal_single_upload(
            key=file.object_key,
            upload_session_id=str(upload.id),
        )
    upload, file = await _owned_upload(
        session,
        upload_session_id=upload_session_id,
        user_id=access.user.id,
        lock=True,
    )
    if not await _has_held_upload_reservation(session, upload_session_id=upload.id):
        return
    await QuotaService().release_upload_reservations(session, upload_session_id=upload.id)
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="upload.aborted",
        result=AuditResult.SUCCESS,
        resource_type="file",
        resource_id=str(file.id),
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()


@router.get("/uploads/{upload_session_id}", response_model=UploadSessionRead)
async def get_upload(
    upload_session_id: UUID,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("file:upload"))],
) -> UploadSession:
    upload, _ = await _owned_upload(
        session, upload_session_id=upload_session_id, user_id=access.user.id
    )
    return upload


@router.post("/{file_id}/approve", response_model=FileRead)
async def approve_processed_file(
    file_id: UUID,
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("file:approve"))],
) -> File:
    file = await session.scalar(select(File).where(File.id == file_id).with_for_update())
    if file is None:
        raise ApiError(status_code=404, code="file_not_found", message="File not found")
    if file.knowledge_base_id is not None:
        await require_knowledge_base_access(
            session,
            access,
            file.knowledge_base_id,
            minimum=KnowledgeBaseAccessLevel.MANAGER,
            lock=True,
        )
    elif (
        file.owner_id != access.user.id
        and not access.user.is_superuser
        and "file:approve:any" not in access.permissions
    ):
        raise ApiError(status_code=404, code="file_not_found", message="File not found")
    if file.malware_scan_status is not MalwareScanStatus.CLEAN:
        raise ApiError(
            status_code=409,
            code="malware_scan_not_clean",
            message="File cannot be approved before a clean malware scan",
            details={"status": file.malware_scan_status.value},
        )
    if file.status is not FileStatus.PROCESSING:
        raise ApiError(
            status_code=409, code="file_state_conflict", message="File is not awaiting approval"
        )

    latest_conversion = await session.scalar(
        select(OkfConversionJob).where(
            OkfConversionJob.file_id == file.id,
            OkfConversionJob.file_version == file.version,
        )
    )
    if latest_conversion is None or latest_conversion.status is not OkfConversionStatus.SUCCEEDED:
        raise ApiError(
            status_code=409,
            code="okf_conversion_not_completed",
            message=(
                "The current file version requires a successful OKF conversion before approval"
            ),
            details={
                "file_version": file.version,
                "status": latest_conversion.status.value if latest_conversion is not None else None,
            },
        )

    if latest_conversion.output_entry_id is None:
        raise ApiError(
            status_code=409,
            code="okf_conversion_result_missing",
            message="The completed OKF conversion has no generated draft to approve",
        )
    generated_entry = await session.scalar(
        select(KnowledgeEntry)
        .where(
            KnowledgeEntry.id == latest_conversion.output_entry_id,
            KnowledgeEntry.source_file_id == file.id,
            KnowledgeEntry.publication_status == KnowledgeEntryPublicationStatus.DRAFT,
        )
        .with_for_update()
    )
    if generated_entry is None:
        raise ApiError(
            status_code=409,
            code="okf_conversion_result_missing",
            message="The completed OKF conversion draft is unavailable for approval",
        )

    file.status = FileStatus.AVAILABLE
    file.available_at = datetime.now(UTC)
    generated_entry.publication_status = KnowledgeEntryPublicationStatus.PUBLISHED
    file.knowledge_status = KnowledgeIngestionStatus.INDEXED
    file.knowledge_error_code = None
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="file.approved",
        result=AuditResult.SUCCESS,
        resource_type="file",
        resource_id=str(file.id),
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(file)
    return file


@router.post("/{file_id}/download", response_model=DownloadGrant)
async def create_download_grant(
    file_id: UUID,
    request: Request,
    response: Response,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("file:read"))],
    settings: Annotated[Settings, Depends(get_settings)],
    storage: Annotated[StorageService, Depends(get_storage_service)],
) -> DownloadGrant:
    file = await session.scalar(select(File).where(File.id == file_id, File.deleted_at.is_(None)))
    if file is None:
        raise ApiError(status_code=404, code="file_not_found", message="File not found")
    if not access.allows("file:read:any"):
        if file.knowledge_base_id is not None:
            await require_knowledge_base_access(session, access, file.knowledge_base_id)
        elif file.owner_id != access.user.id:
            raise ApiError(
                status_code=403,
                code="permission_denied",
                message="File access denied",
            )
    if file.malware_scan_status is not MalwareScanStatus.CLEAN:
        raise ApiError(
            status_code=409,
            code="malware_scan_not_clean",
            message="File cannot be downloaded without a clean malware scan",
            details={"status": file.malware_scan_status.value},
        )
    if file.status is not FileStatus.AVAILABLE:
        raise ApiError(
            status_code=409, code="file_not_available", message="File is not available for download"
        )

    await QuotaService().consume(
        session,
        user_id=access.user.id,
        key="daily_downloads",
        amount=1,
        limit=access.limits.get("daily_downloads", 0),
        window_start=daily_window_start(),
    )
    url = storage.presign_download(key=file.object_key, filename=file.original_name)
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="file.download_grant.issued",
        result=AuditResult.SUCCESS,
        resource_type="file",
        resource_id=str(file.id),
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
    )
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return DownloadGrant(url=url, expires_in=min(settings.presigned_url_seconds, 300))
