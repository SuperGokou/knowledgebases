from __future__ import annotations

import base64
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import and_, exists, false, or_, select, update

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
    OkfConversionJob,
    OkfConversionStatus,
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
from app.services.audit import add_audit_event
from app.services.knowledge_bases import require_knowledge_base_access
from app.services.okf_conversion import enqueue_okf_conversion
from app.services.quota import QuotaService, QuotaSpec, daily_window_start, lifetime_window_start
from app.services.storage import StorageService

router = APIRouter()


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
        statement = statement.with_for_update()
    row = (await session.execute(statement)).one_or_none()
    if row is None:
        raise ApiError(status_code=404, code="upload_not_found", message="Upload session not found")
    return row[0], row[1]


@router.get("", response_model=list[FileRead])
async def list_files(
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_permission("file:read"))],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
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
        )

    maximum = access.limits.get("max_upload_bytes", 0)
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
                expected_checksum_sha256_base64=_checksum_base64(
                    existing_file.checksum_value
                ),
            )
            return _initiate_response(
                existing,
                upload_url=signed.url,
                required_headers=signed.required_headers,
            )
        return _initiate_response(existing)

    plan = plan_upload(
        size_bytes=validated.size_bytes,
        multipart_threshold_bytes=settings.multipart_threshold_bytes,
        preferred_part_size=settings.multipart_part_size_bytes,
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
        ],
        expires_at=expires_at,
    )

    initiated = await storage.initiate(
        key=file.object_key,
        content_type=file.content_type,
        upload_session_id=str(upload.id),
        expected_size_bytes=upload.expected_size_bytes,
        plan=plan,
        expected_checksum_sha256_base64=_checksum_base64(file.checksum_value),
    )
    upload.storage_upload_id = initiated.upload_id
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="upload.initiated",
        resource_type="file",
        resource_id=str(file.id),
        request_id=getattr(request.state, "request_id", None),
        details={
            "size_bytes": file.size_bytes,
            "mode": plan.mode.value,
            "knowledge_base_id": str(file.knowledge_base_id)
            if file.knowledge_base_id
            else None,
        },
    )
    try:
        await session.commit()
    except Exception:
        await session.rollback()
        if initiated.upload_id:
            await storage.abort_multipart(key=file.object_key, upload_id=initiated.upload_id)
        raise
    return _initiate_response(
        upload,
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
        )
    if upload.mode != UploadMode.MULTIPART.value or not upload.storage_upload_id:
        raise ApiError(status_code=409, code="not_multipart", message="Upload is not multipart")
    if upload.status is not UploadSessionStatus.INITIATED:
        raise ApiError(
            status_code=409, code="upload_state_conflict", message="Upload is not active"
        )
    if (
        upload.status is UploadSessionStatus.INITIATED
        and as_utc(upload.expires_at) <= datetime.now(UTC)
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
        )
    if upload.status is UploadSessionStatus.COMPLETED:
        return file
    if upload.status not in {
        UploadSessionStatus.INITIATED,
        UploadSessionStatus.FINALIZING,
    }:
        raise ApiError(
            status_code=409, code="upload_state_conflict", message="Upload is not active"
        )
    if (
        upload.status is UploadSessionStatus.INITIATED
        and as_utc(upload.expires_at) <= datetime.now(UTC)
    ):
        raise ApiError(status_code=410, code="upload_expired", message="Upload session has expired")

    if upload.mode == UploadMode.MULTIPART.value:
        numbers = sorted(item.part_number for item in payload.parts)
        if numbers != list(range(1, upload.part_count + 1)):
            raise ApiError(
                status_code=422,
                code="incomplete_parts",
                message="Every multipart part must be supplied exactly once",
            )
        if not upload.storage_upload_id:
            raise ApiError(
                status_code=409, code="missing_upload_id", message="Storage upload ID is missing"
            )
        parts = []
        for item in sorted(payload.parts, key=lambda value: value.part_number):
            part: dict[str, object] = {"PartNumber": item.part_number, "ETag": item.etag}
            if item.checksum_sha256:
                part["ChecksumSHA256"] = item.checksum_sha256
            parts.append(part)
        if upload.status is UploadSessionStatus.INITIATED:
            upload.status = UploadSessionStatus.FINALIZING
            # Keep the maintenance worker away while CompleteMultipartUpload is
            # in flight. A crashed request becomes eligible for reconciliation
            # after this bounded grace period.
            upload.expires_at = max(
                as_utc(upload.expires_at),
                datetime.now(UTC) + timedelta(minutes=15),
            )
            await session.commit()
        await storage.complete_multipart(
            key=file.object_key,
            upload_id=upload.storage_upload_id,
            parts=parts,
        )
    elif payload.parts:
        raise ApiError(
            status_code=422, code="unexpected_parts", message="Single upload has no parts"
        )

    if upload.mode == UploadMode.SINGLE.value:
        final_key = _final_object_key(file.object_key)
        stored = await storage.try_head(key=file.object_key)
        if stored is None:
            stored = await storage.try_head(key=final_key)
            if stored is None:
                raise ApiError(
                    status_code=409,
                    code="stored_object_missing",
                    message="The uploaded object is not available in storage",
                )
            file.object_key = final_key
    else:
        stored = await storage.head(key=file.object_key)
    if stored.size_bytes != upload.expected_size_bytes:
        await storage.delete(key=file.object_key)
        upload.status = UploadSessionStatus.FAILED
        file.status = FileStatus.FAILED
        await QuotaService().release_upload_reservations(
            session, upload_session_id=upload.id, status=ReservationStatus.RELEASED
        )
        add_audit_event(
            session,
            actor_id=access.user.id,
            action="upload.rejected_size_mismatch",
            resource_type="file",
            resource_id=str(file.id),
            request_id=getattr(request.state, "request_id", None),
            details={"expected": upload.expected_size_bytes, "actual": stored.size_bytes},
        )
        await session.commit()
        raise ApiError(
            status_code=422,
            code="uploaded_size_mismatch",
            message="Stored object size differs from the declared size",
        )

    if file.checksum_value is not None:
        actual_checksum = stored.checksum_sha256
        expected_checksum = _checksum_base64(file.checksum_value)
        if actual_checksum is None or expected_checksum is None or not hmac.compare_digest(
            actual_checksum,
            expected_checksum,
        ):
            await storage.delete(key=file.object_key)
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
                action="upload.rejected_checksum_mismatch",
                resource_type="file",
                resource_id=str(file.id),
                request_id=getattr(request.state, "request_id", None),
            )
            await session.commit()
            raise ApiError(
                status_code=422,
                code="uploaded_checksum_mismatch",
                message="Stored object SHA-256 differs from the declared checksum",
            )

    if file.object_key.startswith("staging/"):
        final_key = _final_object_key(file.object_key)
        stored = await storage.promote(
            source_key=file.object_key,
            destination_key=final_key,
        )
        file.object_key = final_key

    await QuotaService().consume_upload_reservations(session, upload_session_id=upload.id)
    upload.status = UploadSessionStatus.COMPLETED
    upload.completed_at = datetime.now(UTC)
    file.size_bytes = stored.size_bytes
    file.status = FileStatus.PROCESSING
    if stored.checksum_sha256 and file.checksum_value is None:
        file.checksum_algorithm = "SHA256"
        file.checksum_value = stored.checksum_sha256
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="upload.completed",
        resource_type="file",
        resource_id=str(file.id),
        request_id=getattr(request.state, "request_id", None),
        details={"status": "processing"},
    )
    conversion = await enqueue_okf_conversion(session, file)
    if conversion is not None:
        add_audit_event(
            session,
            actor_id=access.user.id,
            action="okf.conversion_queued",
            resource_type="okf_conversion_job",
            resource_id=str(conversion.id),
            request_id=getattr(request.state, "request_id", None),
            details={"file_id": str(file.id), "prompt_version": conversion.prompt_version},
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
    conversion = await session.scalar(
        select(OkfConversionJob)
        .where(OkfConversionJob.file_id == file_id)
        .order_by(OkfConversionJob.file_version.desc())
        .limit(1)
        .with_for_update()
    )
    if conversion is None:
        raise ApiError(
            status_code=404,
            code="okf_conversion_not_found",
            message="Conversion not found",
        )
    await require_knowledge_base_access(
        session,
        access,
        conversion.knowledge_base_id,
        minimum=KnowledgeBaseAccessLevel.MANAGER,
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
    conversion.error_code = None
    conversion.next_attempt_at = None
    conversion.locked_at = None
    conversion.lease_id = None
    conversion.completed_at = None
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="okf.conversion_retried",
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
    if upload.status in {UploadSessionStatus.ABORTED, UploadSessionStatus.EXPIRED}:
        return
    if upload.storage_upload_id:
        await storage.abort_multipart(key=file.object_key, upload_id=upload.storage_upload_id)
    else:
        await storage.delete(key=file.object_key)
    await QuotaService().release_upload_reservations(session, upload_session_id=upload.id)
    upload.status = UploadSessionStatus.ABORTED
    file.status = FileStatus.FAILED
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="upload.aborted",
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
        )
    elif (
        file.owner_id != access.user.id
        and not access.user.is_superuser
        and "file:approve:any" not in access.permissions
    ):
        raise ApiError(status_code=404, code="file_not_found", message="File not found")
    if file.status is not FileStatus.PROCESSING:
        raise ApiError(
            status_code=409, code="file_state_conflict", message="File is not awaiting approval"
        )
    file.status = FileStatus.AVAILABLE
    file.available_at = datetime.now(UTC)
    await session.execute(
        update(KnowledgeEntry)
        .where(
            KnowledgeEntry.source_file_id == file.id,
            KnowledgeEntry.publication_status == KnowledgeEntryPublicationStatus.DRAFT,
        )
        .values(publication_status=KnowledgeEntryPublicationStatus.PUBLISHED)
    )
    add_audit_event(
        session,
        actor_id=access.user.id,
        action="file.approved",
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
        resource_type="file",
        resource_id=str(file.id),
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
    )
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return DownloadGrant(url=url, expires_in=min(settings.presigned_url_seconds, 300))
