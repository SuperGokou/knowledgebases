from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import Response

from app.api.errors import ApiError
from app.api.v1.routes import files as file_routes
from app.core.config import get_settings
from app.db.models import File, FileStatus, UploadSession, UploadSessionStatus, User
from app.domain.files import UploadMode
from app.schemas.files import CompletedPart, CompleteUploadRequest, UploadInitiateRequest
from app.services.access import AccessContext
from app.services.storage import InitiatedStorageUpload, StoredObject


def _access() -> AccessContext:
    return AccessContext(
        user=User(id=uuid4(), email="uploader@example.com", password_hash="unused"),
        role_ids=(),
        permissions=frozenset({"file:upload"}),
        max_role_priority=0,
        limits={
            "max_upload_bytes": 2_000_000_000,
            "daily_upload_bytes": 2_000_000_000,
            "storage_bytes": 2_000_000_000,
        },
    )


def _request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(request_id="security-boundary-test"))


@pytest.mark.asyncio
async def test_multipart_initiation_commits_admission_before_storage_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    session = MagicMock()
    query_result = MagicMock()
    query_result.one_or_none.return_value = None
    session.execute = AsyncMock(return_value=query_result)
    session.flush = AsyncMock()
    session.commit = AsyncMock(side_effect=lambda: events.append("commit"))
    session.rollback = AsyncMock()
    admitted: list[object] = []
    session.add_all.side_effect = lambda values: admitted.extend(values)

    async def reserve_many(*_args: object, **_kwargs: object) -> None:
        events.append("reserve")

    async def initiate(**_kwargs: object) -> InitiatedStorageUpload:
        events.append("storage")
        return InitiatedStorageUpload(
            upload_id="multipart-security-test",
            url=None,
            required_headers={},
        )

    storage = SimpleNamespace(initiate=initiate, abort_multipart=AsyncMock())
    monkeypatch.setattr(file_routes.QuotaService, "reserve_many", reserve_many)

    async def owned_upload(*_args: object, **_kwargs: object) -> tuple[UploadSession, File]:
        persisted_file = next(item for item in admitted if isinstance(item, File))
        persisted_upload = next(item for item in admitted if isinstance(item, UploadSession))
        return persisted_upload, persisted_file

    monkeypatch.setattr(file_routes, "_owned_upload", owned_upload)

    settings = get_settings().model_copy(update={"multipart_threshold_bytes": 1})
    result = await file_routes.initiate_upload(
        UploadInitiateRequest(
            filename="large.pdf",
            size_bytes=2,
            content_type="application/pdf",
            idempotency_key="security-multipart-init",
        ),
        _request(),  # type: ignore[arg-type]
        Response(),
        session,
        _access(),
        settings,
        storage,  # type: ignore[arg-type]
    )

    assert result.mode == UploadMode.MULTIPART.value
    assert events == ["reserve", "commit", "storage", "commit"]


@pytest.mark.asyncio
async def test_finalizing_retry_releases_database_lock_before_storage_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    access = _access()
    upload = UploadSession(
        id=uuid4(),
        file_id=uuid4(),
        user_id=uuid4(),
        idempotency_key="security-complete",
        mode=UploadMode.MULTIPART.value,
        part_size_bytes=5,
        part_count=1,
        expected_size_bytes=5,
        storage_upload_id="multipart-security-test",
        status=UploadSessionStatus.FINALIZING,
    )
    file = File(
        id=upload.file_id,
        owner_id=upload.user_id,
        bucket="kb",
        object_key=f"objects/{upload.file_id}.pdf",
        original_name="large.pdf",
        extension=".pdf",
        content_type="application/pdf",
        size_bytes=5,
        status=FileStatus.UPLOADING,
    )
    session = MagicMock()
    session.commit = AsyncMock(side_effect=lambda: events.append("commit"))
    session.refresh = AsyncMock()

    async def owned_upload(*_args: object, **_kwargs: object) -> tuple[UploadSession, File]:
        return upload, file

    async def complete_multipart(**_kwargs: object) -> None:
        events.append("storage")

    async def head(**_kwargs: object) -> StoredObject:
        return StoredObject(
            size_bytes=5,
            etag='"etag"',
            version_id=None,
            checksum_sha256=None,
            content_type="application/pdf",
        )

    async def consume(*_args: object, **_kwargs: object) -> None:
        events.append("consume")

    async def reauthorize(*_args: object, **_kwargs: object) -> AccessContext:
        events.append("reauthorize")
        return access

    monkeypatch.setattr(file_routes, "_owned_upload", owned_upload)
    monkeypatch.setattr(file_routes, "_reauthorize_upload_finalization", reauthorize)
    monkeypatch.setattr(file_routes.QuotaService, "consume_upload_reservations", consume)
    storage = SimpleNamespace(complete_multipart=complete_multipart, head=head)

    await file_routes.complete_upload(
        upload.id,
        CompleteUploadRequest(parts=[CompletedPart(part_number=1, etag='"etag"')]),
        _request(),  # type: ignore[arg-type]
        session,
        access,
        storage,  # type: ignore[arg-type]
    )

    assert events == ["commit", "storage", "reauthorize", "consume", "commit"]


@pytest.mark.asyncio
async def test_multipart_completion_fails_closed_when_storage_has_no_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upload = UploadSession(
        id=uuid4(),
        file_id=uuid4(),
        user_id=uuid4(),
        idempotency_key="security-missing-object",
        mode=UploadMode.MULTIPART.value,
        part_size_bytes=5,
        part_count=1,
        expected_size_bytes=5,
        storage_upload_id="multipart-security-test",
        status=UploadSessionStatus.FINALIZING,
    )
    file = File(
        id=upload.file_id,
        owner_id=upload.user_id,
        bucket="kb",
        object_key=f"objects/{upload.file_id}.pdf",
        original_name="large.pdf",
        extension=".pdf",
        content_type="application/pdf",
        size_bytes=5,
        status=FileStatus.UPLOADING,
    )
    session = MagicMock()
    session.commit = AsyncMock()

    async def owned_upload(*_args: object, **_kwargs: object) -> tuple[UploadSession, File]:
        return upload, file

    async def complete_multipart(**_kwargs: object) -> None:
        return None

    async def head(**_kwargs: object) -> None:
        return None

    monkeypatch.setattr(file_routes, "_owned_upload", owned_upload)
    storage = SimpleNamespace(complete_multipart=complete_multipart, head=head)

    with pytest.raises(ApiError) as captured:
        await file_routes.complete_upload(
            upload.id,
            CompleteUploadRequest(parts=[CompletedPart(part_number=1, etag='"etag"')]),
            _request(),  # type: ignore[arg-type]
            session,
            _access(),
            storage,  # type: ignore[arg-type]
        )

    assert captured.value.status_code == 409
    assert captured.value.code == "stored_object_missing"


@pytest.mark.asyncio
async def test_abort_persists_in_progress_state_before_storage_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    upload = UploadSession(
        id=uuid4(),
        file_id=uuid4(),
        user_id=uuid4(),
        idempotency_key="security-abort",
        mode=UploadMode.MULTIPART.value,
        part_size_bytes=5,
        part_count=1,
        expected_size_bytes=5,
        storage_upload_id="multipart-security-test",
        status=UploadSessionStatus.INITIATED,
    )
    file = File(
        id=upload.file_id,
        owner_id=upload.user_id,
        bucket="kb",
        object_key=f"objects/{upload.file_id}.pdf",
        original_name="large.pdf",
        extension=".pdf",
        content_type="application/pdf",
        size_bytes=5,
        status=FileStatus.UPLOADING,
    )
    session = MagicMock()
    session.commit = AsyncMock(side_effect=lambda: events.append("commit"))

    async def owned_upload(*_args: object, **_kwargs: object) -> tuple[UploadSession, File]:
        return upload, file

    async def abort_multipart(**_kwargs: object) -> None:
        events.append("storage")

    async def release(*_args: object, **_kwargs: object) -> None:
        events.append("release")

    monkeypatch.setattr(file_routes, "_owned_upload", owned_upload)
    monkeypatch.setattr(file_routes.QuotaService, "release_upload_reservations", release)
    monkeypatch.setattr(
        file_routes,
        "_has_held_upload_reservation",
        AsyncMock(return_value=True),
    )
    storage = SimpleNamespace(abort_multipart=abort_multipart)

    await file_routes.abort_upload(
        upload.id,
        _request(),  # type: ignore[arg-type]
        session,
        _access(),
        storage,  # type: ignore[arg-type]
    )

    assert events == ["commit", "storage", "release", "commit"]
    assert upload.status is UploadSessionStatus.ABORTED


@pytest.mark.asyncio
async def test_single_completion_releases_all_database_locks_before_storage_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    access = _access()
    upload = UploadSession(
        id=uuid4(),
        file_id=uuid4(),
        user_id=uuid4(),
        idempotency_key="security-single-complete",
        mode=UploadMode.SINGLE.value,
        part_size_bytes=5,
        part_count=1,
        expected_size_bytes=5,
        status=UploadSessionStatus.INITIATED,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    source_key = f"staging/users/{upload.user_id}/{upload.file_id}.pdf"
    final_key = f"objects/users/{upload.user_id}/{upload.file_id}.pdf"
    file = File(
        id=upload.file_id,
        owner_id=upload.user_id,
        bucket="kb",
        object_key=source_key,
        original_name="single.pdf",
        extension=".pdf",
        content_type="application/pdf",
        size_bytes=5,
        status=FileStatus.UPLOADING,
    )
    session = MagicMock()
    session.commit = AsyncMock(side_effect=lambda: events.append("commit"))
    session.refresh = AsyncMock()

    async def owned_upload(*_args: object, **_kwargs: object) -> tuple[UploadSession, File]:
        return upload, file

    async def try_head(*, key: str) -> StoredObject | None:
        events.append(f"head:{key}")
        if key == final_key:
            return None
        return StoredObject(
            size_bytes=5,
            etag='"etag"',
            version_id=None,
            checksum_sha256=None,
            content_type="application/pdf",
        )

    async def promote(**_kwargs: object) -> StoredObject:
        events.append("promote")
        return StoredObject(
            size_bytes=5,
            etag='"etag"',
            version_id=None,
            checksum_sha256=None,
            content_type="application/pdf",
        )

    async def consume(*_args: object, **_kwargs: object) -> None:
        events.append("consume")

    async def reauthorize(*_args: object, **_kwargs: object) -> AccessContext:
        events.append("reauthorize")
        return access

    monkeypatch.setattr(file_routes, "_owned_upload", owned_upload)
    monkeypatch.setattr(file_routes, "_reauthorize_upload_finalization", reauthorize)
    monkeypatch.setattr(file_routes.QuotaService, "consume_upload_reservations", consume)
    storage = SimpleNamespace(try_head=try_head, promote=promote)

    await file_routes.complete_upload(
        upload.id,
        CompleteUploadRequest(parts=[]),
        _request(),  # type: ignore[arg-type]
        session,
        access,
        storage,  # type: ignore[arg-type]
    )

    assert events == [
        "commit",
        f"head:{final_key}",
        f"head:{source_key}",
        "promote",
        "reauthorize",
        "consume",
        "commit",
    ]


@pytest.mark.asyncio
async def test_completion_cannot_resurrect_a_concurrently_aborted_upload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    access = _access()
    upload_id = uuid4()
    file_id = uuid4()
    user_id = uuid4()
    stale_upload = UploadSession(
        id=upload_id,
        file_id=file_id,
        user_id=user_id,
        idempotency_key="security-complete-abort-race",
        mode=UploadMode.MULTIPART.value,
        part_size_bytes=5,
        part_count=1,
        expected_size_bytes=5,
        storage_upload_id="multipart-security-test",
        status=UploadSessionStatus.FINALIZING,
    )
    fresh_upload = UploadSession(
        id=upload_id,
        file_id=file_id,
        user_id=user_id,
        idempotency_key="security-complete-abort-race",
        mode=UploadMode.MULTIPART.value,
        part_size_bytes=5,
        part_count=1,
        expected_size_bytes=5,
        storage_upload_id="multipart-security-test",
        status=UploadSessionStatus.ABORTED,
    )
    stale_file = File(
        id=file_id,
        owner_id=user_id,
        bucket="kb",
        object_key=f"objects/{file_id}.pdf",
        original_name="race.pdf",
        extension=".pdf",
        content_type="application/pdf",
        size_bytes=5,
        status=FileStatus.UPLOADING,
    )
    fresh_file = File(
        id=file_id,
        owner_id=user_id,
        bucket="kb",
        object_key=stale_file.object_key,
        original_name="race.pdf",
        extension=".pdf",
        content_type="application/pdf",
        size_bytes=5,
        status=FileStatus.FAILED,
    )
    reads = 0

    async def owned_upload(*_args: object, **_kwargs: object) -> tuple[UploadSession, File]:
        nonlocal reads
        reads += 1
        return (stale_upload, stale_file) if reads == 1 else (fresh_upload, fresh_file)

    session = MagicMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    consume = AsyncMock()
    deleted: list[str] = []

    async def complete_multipart(**_kwargs: object) -> None:
        return None

    async def head(**_kwargs: object) -> StoredObject:
        return StoredObject(
            size_bytes=5,
            etag='"etag"',
            version_id=None,
            checksum_sha256=None,
            content_type="application/pdf",
        )

    async def delete(*, key: str) -> None:
        deleted.append(key)

    async def reauthorize(*_args: object, **_kwargs: object) -> AccessContext:
        return access

    monkeypatch.setattr(file_routes, "_owned_upload", owned_upload)
    monkeypatch.setattr(file_routes, "_reauthorize_upload_finalization", reauthorize)
    monkeypatch.setattr(file_routes.QuotaService, "consume_upload_reservations", consume)
    storage = SimpleNamespace(
        complete_multipart=complete_multipart,
        head=head,
        delete=delete,
    )

    with pytest.raises(ApiError) as captured:
        await file_routes.complete_upload(
            upload_id,
            CompleteUploadRequest(parts=[CompletedPart(part_number=1, etag='"etag"')]),
            _request(),  # type: ignore[arg-type]
            session,
            access,
            storage,  # type: ignore[arg-type]
        )

    assert captured.value.code == "upload_state_conflict"
    assert fresh_upload.status is UploadSessionStatus.ABORTED
    consume.assert_not_awaited()
    assert deleted == [fresh_file.object_key]
