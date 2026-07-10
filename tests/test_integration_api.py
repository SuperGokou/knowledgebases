from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.api.dependencies import get_storage_service, redis_dependency
from app.core.config import Settings, get_settings
from app.core.security import PasswordService
from app.db.base import Base
from app.db.models import (
    File,
    FileStatus,
    LimitDefinition,
    Permission,
    QuotaReservation,
    ReservationStatus,
    Role,
    RoleLimit,
    RolePermission,
    UploadSession,
    UploadSessionStatus,
    User,
    UserRole,
)
from app.db.session import get_db
from app.main import app
from app.maintenance import cleanup_expired_uploads
from app.services.storage import InitiatedStorageUpload, PresignedPart, StoredObject


class FakeRedis:
    def __init__(self) -> None:
        self.counters: dict[str, int] = {}

    async def eval(self, _script: str, _keys: int, key: str, ttl_ms: int) -> list[int]:
        self.counters[key] = self.counters.get(key, 0) + 1
        return [self.counters[key], ttl_ms]

    async def ping(self) -> bool:
        return True


@dataclass
class FakeStorage:
    head_size: int = 1
    initiated_keys: list[str] = field(default_factory=list)
    completed_uploads: list[str] = field(default_factory=list)
    deleted_keys: list[str] = field(default_factory=list)
    promoted_keys: list[tuple[str, str]] = field(default_factory=list)

    async def initiate(self, **kwargs: Any) -> InitiatedStorageUpload:
        key = str(kwargs["key"])
        plan = kwargs["plan"]
        self.initiated_keys.append(key)
        if plan.mode.value == "single":
            return InitiatedStorageUpload(
                upload_id=None,
                url="http://storage.local/single-upload",
                required_headers={"Content-Type": str(kwargs["content_type"])},
            )
        return InitiatedStorageUpload(upload_id="multipart-123", url=None, required_headers={})

    def presign_parts(
        self,
        *,
        key: str,
        upload_id: str,
        part_numbers: list[int],
        expected_size_bytes: int,
        part_size_bytes: int,
    ) -> dict[int, PresignedPart]:
        return {
            number: PresignedPart(
                url=f"http://storage.local/{key}?uploadId={upload_id}&partNumber={number}",
                size_bytes=min(
                    part_size_bytes,
                    expected_size_bytes - ((number - 1) * part_size_bytes),
                ),
            )
            for number in part_numbers
        }

    async def complete_multipart(
        self, *, key: str, upload_id: str, parts: list[dict[str, Any]]
    ) -> None:
        assert upload_id == "multipart-123"
        assert parts
        self.completed_uploads.append(key)

    async def head(self, *, key: str) -> StoredObject:
        assert key in self.initiated_keys
        return StoredObject(
            size_bytes=self.head_size,
            etag='"etag"',
            version_id=None,
            checksum_sha256=None,
            content_type="application/pdf",
        )

    async def try_head(self, *, key: str) -> StoredObject | None:
        if key not in self.initiated_keys:
            return None
        return await self.head(key=key)

    async def abort_multipart(self, *, key: str, upload_id: str) -> None:
        self.deleted_keys.append(key)

    async def delete(self, *, key: str) -> None:
        self.deleted_keys.append(key)

    async def promote(self, *, source_key: str, destination_key: str) -> StoredObject:
        self.promoted_keys.append((source_key, destination_key))
        self.initiated_keys.append(destination_key)
        self.deleted_keys.append(source_key)
        return await self.head(key=destination_key)

    def presign_download(self, *, key: str, filename: str) -> str:
        return f"http://storage.local/download/{key}?filename={filename}"


@dataclass
class ApiHarness:
    client: httpx.AsyncClient
    storage: FakeStorage
    redis: FakeRedis
    session_factory: async_sessionmaker[AsyncSession]

    async def login(self) -> dict[str, Any]:
        response = await self.client.post(
            "/api/v1/auth/token",
            data={"username": "admin@example.com", "password": "Admin-password-123!"},
        )
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        return response.json()


@pytest_asyncio.fixture
async def api_harness() -> ApiHarness:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with session_factory() as session:
        permissions = [
            Permission(code=code, name=code)
            for code in (
                "file:read",
                "file:read:any",
                "file:upload",
                "file:approve",
                "user:manage",
                "role:read",
                "role:manage",
                "role:assign",
            )
        ]
        limits = [
            LimitDefinition(key=key, name=key, unit=unit, window=window)
            for key, unit, window in (
                ("requests_per_minute", "requests", "minute"),
                ("max_upload_bytes", "bytes", "request"),
                ("daily_upload_bytes", "bytes", "day"),
                ("storage_bytes", "bytes", "lifetime"),
                ("daily_downloads", "downloads", "day"),
            )
        ]
        role = Role(code="admin", name="Administrator", is_system=True)
        user = User(
            email="admin@example.com",
            password_hash=PasswordService().hash("Admin-password-123!"),
        )
        session.add_all([*permissions, *limits, role, user])
        await session.flush()
        session.add_all(
            [RolePermission(role_id=role.id, permission_id=item.id) for item in permissions]
        )
        limit_values = {
            "requests_per_minute": 1_000,
            "max_upload_bytes": 2_000_000_000,
            "daily_upload_bytes": 2_000_000_000,
            "storage_bytes": 2_000_000_000,
            "daily_downloads": 100,
        }
        session.add_all(
            [
                RoleLimit(
                    role_id=role.id,
                    limit_definition_id=item.id,
                    value=limit_values[item.key],
                )
                for item in limits
            ]
        )
        session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id))
        await session.commit()

    fake_redis = FakeRedis()
    fake_storage = FakeStorage()

    async def override_db() -> Any:
        async with session_factory() as session:
            yield session

    async def override_redis() -> Any:
        yield fake_redis

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[redis_dependency] = override_redis
    app.dependency_overrides[get_storage_service] = lambda: fake_storage
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield ApiHarness(
            client=client,
            storage=fake_storage,
            redis=fake_redis,
            session_factory=session_factory,
        )

    app.dependency_overrides.clear()
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.mark.asyncio
async def test_admin_role_user_and_refresh_workflow(api_harness: ApiHarness) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    forbidden_escalation = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={"code": "higher", "name": "Higher", "priority": 1},
    )
    assert forbidden_escalation.status_code == 403

    refresh = await api_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert refresh.status_code == 200, refresh.text
    assert refresh.headers["cache-control"] == "no-store"

    role = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={
            "code": "uploader",
            "name": "Uploader",
            "priority": -1,
            "permission_codes": ["file:read", "file:upload"],
            "limits": {"max_upload_bytes": 1_000, "daily_downloads": 2},
        },
    )
    assert role.status_code == 201, role.text
    assert role.json()["permission_codes"] == ["file:read", "file:upload"]
    assert role.json()["limits"] == {"daily_downloads": 2, "max_upload_bytes": 1_000}
    role_id = role.json()["id"]
    assert (
        await api_harness.client.patch(
            f"/api/v1/roles/{role_id}", headers=headers, json={"name": "Data Uploader"}
        )
    ).status_code == 200
    assert (
        await api_harness.client.put(
            f"/api/v1/roles/{role_id}/permissions",
            headers=headers,
            json={"permission_codes": ["file:read"]},
        )
    ).status_code == 200
    assert (
        await api_harness.client.put(
            f"/api/v1/roles/{role_id}/limits",
            headers=headers,
            json={"limits": {"max_upload_bytes": 2_000}},
        )
    ).status_code == 200
    assert (await api_harness.client.get("/api/v1/roles", headers=headers)).status_code == 200
    assert (await api_harness.client.get("/api/v1/permissions", headers=headers)).status_code == 200
    limit_catalog = await api_harness.client.get("/api/v1/limits", headers=headers)
    assert limit_catalog.status_code == 200
    assert "max_upload_bytes" in {item["key"] for item in limit_catalog.json()}
    role_detail = await api_harness.client.get(f"/api/v1/roles/{role_id}", headers=headers)
    assert role_detail.status_code == 200
    assert role_detail.json()["permission_codes"] == ["file:read"]
    assert role_detail.json()["limits"] == {"max_upload_bytes": 2_000}

    user = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "new.user@example.com",
            "password": "New-user-password-123!",
            "display_name": "New User",
            "role_ids": [role_id],
        },
    )
    assert user.status_code == 201, user.text
    assert user.json()["role_ids"] == [role_id]
    user_id = user.json()["id"]
    assert (
        await api_harness.client.patch(
            f"/api/v1/users/{user_id}", headers=headers, json={"display_name": "Renamed"}
        )
    ).status_code == 200
    assert (
        await api_harness.client.put(
            f"/api/v1/users/{user_id}/roles", headers=headers, json={"role_ids": [role_id]}
        )
    ).status_code == 200
    assert (await api_harness.client.get("/api/v1/users", headers=headers)).status_code == 200

    roles = (await api_harness.client.get("/api/v1/roles", headers=headers)).json()
    system_admin_id = next(item["id"] for item in roles if item["code"] == "admin")
    forbidden_system_assignment = await api_harness.client.put(
        f"/api/v1/users/{user_id}/roles",
        headers=headers,
        json={"role_ids": [system_admin_id]},
    )
    assert forbidden_system_assignment.status_code == 403


@pytest.mark.asyncio
async def test_single_upload_approval_and_download_workflow(api_harness: ApiHarness) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    api_harness.storage.head_size = 5

    initiated = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "report.pdf",
            "size_bytes": 5,
            "content_type": "application/pdf",
            "custom_metadata": {"department": "finance"},
            "idempotency_key": "single-upload-001",
        },
    )
    assert initiated.status_code == 201, initiated.text
    upload = initiated.json()
    assert upload["mode"] == "single"
    assert upload["upload_url"] == "http://storage.local/single-upload"

    completed = await api_harness.client.post(
        f"/api/v1/files/uploads/{upload['upload_session_id']}/complete",
        headers=headers,
        json={"parts": []},
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "processing"
    assert api_harness.storage.promoted_keys
    file_id = completed.json()["id"]

    approved = await api_harness.client.post(f"/api/v1/files/{file_id}/approve", headers=headers)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "available"

    grant = await api_harness.client.post(f"/api/v1/files/{file_id}/download", headers=headers)
    assert grant.status_code == 200, grant.text
    assert grant.headers["cache-control"] == "no-store"
    assert grant.json()["url"].startswith("http://storage.local/download/")
    assert "objects/" in grant.json()["url"]
    listed = await api_harness.client.get("/api/v1/files", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["id"] == file_id


@pytest.mark.asyncio
async def test_multipart_upload_signs_batches_and_completes(api_harness: ApiHarness) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    size = get_settings().multipart_threshold_bytes + 1
    api_harness.storage.head_size = size

    initiated = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "large.pdf",
            "size_bytes": size,
            "content_type": "application/pdf",
            "idempotency_key": "multipart-upload-001",
        },
    )
    assert initiated.status_code == 201, initiated.text
    upload = initiated.json()
    assert upload["mode"] == "multipart"
    part_numbers = list(range(1, upload["part_count"] + 1))

    signed = await api_harness.client.post(
        f"/api/v1/files/uploads/{upload['upload_session_id']}/parts",
        headers=headers,
        json={"part_numbers": part_numbers},
    )
    assert signed.status_code == 200, signed.text
    assert len(signed.json()["parts"]) == upload["part_count"]

    completed = await api_harness.client.post(
        f"/api/v1/files/uploads/{upload['upload_session_id']}/complete",
        headers=headers,
        json={
            "parts": [
                {"part_number": number, "etag": f'"etag-{number}"'} for number in part_numbers
            ]
        },
    )
    assert completed.status_code == 200, completed.text
    assert api_harness.storage.completed_uploads


@pytest.mark.asyncio
async def test_expired_finalizing_upload_can_be_retried_idempotently(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    size = get_settings().multipart_threshold_bytes + 1
    api_harness.storage.head_size = size
    initiated = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "recover.pdf",
            "size_bytes": size,
            "idempotency_key": "multipart-recovery-001",
        },
    )
    upload = initiated.json()
    upload_id = UUID(upload["upload_session_id"])
    async with api_harness.session_factory() as session:
        row = await session.get(UploadSession, upload_id)
        assert row is not None
        row.status = UploadSessionStatus.FINALIZING
        row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        await session.commit()

    completed = await api_harness.client.post(
        f"/api/v1/files/uploads/{upload_id}/complete",
        headers=headers,
        json={
            "parts": [
                {"part_number": number, "etag": f'\"etag-{number}\"'}
                for number in range(1, upload["part_count"] + 1)
            ]
        },
    )

    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "processing"


@pytest.mark.asyncio
async def test_maintenance_reconciles_stale_finalizing_upload(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    size = get_settings().multipart_threshold_bytes + 1
    api_harness.storage.head_size = size
    initiated = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "maintenance-recovery.pdf",
            "size_bytes": size,
            "idempotency_key": "multipart-recovery-002",
        },
    )
    upload_id = UUID(initiated.json()["upload_session_id"])
    async with api_harness.session_factory() as session:
        upload = await session.get(UploadSession, upload_id)
        assert upload is not None
        upload.status = UploadSessionStatus.FINALIZING
        upload.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        await session.commit()

    async with api_harness.session_factory() as session:
        cleaned = await cleanup_expired_uploads(session, api_harness.storage)

    assert cleaned == 1
    async with api_harness.session_factory() as session:
        upload = await session.get(UploadSession, upload_id)
        assert upload is not None
        file = await session.get(File, upload.file_id)
        reservations = list(
            (
                await session.scalars(
                    select(QuotaReservation).where(
                        QuotaReservation.upload_session_id == upload_id
                    )
                )
            ).all()
        )
        assert upload.status is UploadSessionStatus.COMPLETED
        assert file is not None and file.status is FileStatus.PROCESSING
        assert {item.status for item in reservations} == {ReservationStatus.CONSUMED}


@pytest.mark.asyncio
async def test_internal_maintenance_requires_cron_secret(api_harness: ApiHarness) -> None:
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={"cron_secret": Settings(cron_secret="a-secure-cron-secret-value").cron_secret}
    )
    try:
        denied = await api_harness.client.get("/api/v1/internal/maintenance")
        wrong = await api_harness.client.get(
            "/api/v1/internal/maintenance",
            headers={"Authorization": "Bearer wrong-secret"},
        )
        accepted = await api_harness.client.get(
            "/api/v1/internal/maintenance",
            headers={"Authorization": "Bearer a-secure-cron-secret-value"},
        )
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert denied.status_code == 401
    assert wrong.status_code == 401
    assert accepted.status_code == 200
    assert accepted.json() == {"cleaned": 0}


@pytest.mark.asyncio
async def test_login_endpoint_is_ip_rate_limited(api_harness: ApiHarness) -> None:
    responses = [
        await api_harness.client.post(
            "/api/v1/auth/token",
            data={"username": "missing@example.com", "password": "Wrong-password-123!"},
        )
        for _ in range(11)
    ]

    assert responses[-1].status_code == 429


@pytest.mark.asyncio
async def test_authentication_rejects_bad_credentials_tokens_and_refresh_replay(
    api_harness: ApiHarness,
) -> None:
    denied = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "admin@example.com", "password": "Wrong-password-123!"},
    )
    assert denied.status_code == 401

    invalid_refresh = await api_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "not-a-valid-refresh-token-value"},
    )
    assert invalid_refresh.status_code == 401

    tokens = await api_harness.login()
    first_refresh = await api_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert first_refresh.status_code == 200
    replay = await api_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert replay.status_code == 401

    invalid_access = await api_harness.client.get(
        "/api/v1/files",
        headers={"Authorization": "Bearer invalid-token"},
    )
    assert invalid_access.status_code == 401


@pytest.mark.asyncio
async def test_admin_rejects_duplicate_and_unknown_user_role_mutations(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    duplicate_email = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={"email": "admin@example.com", "password": "Another-password-123!"},
    )
    assert duplicate_email.status_code == 409

    unknown_role = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "unknown.role@example.com",
            "password": "Another-password-123!",
            "role_ids": ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
        },
    )
    assert unknown_role.status_code == 422

    role = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={"code": "duplicate", "name": "Duplicate"},
    )
    assert role.status_code == 201
    duplicate_role = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={"code": "duplicate", "name": "Duplicate again"},
    )
    assert duplicate_role.status_code == 409

    missing = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert (
        await api_harness.client.patch(
            f"/api/v1/roles/{missing}", headers=headers, json={"name": "Missing"}
        )
    ).status_code == 404
    assert (
        await api_harness.client.patch(
            f"/api/v1/users/{missing}", headers=headers, json={"display_name": "Missing"}
        )
    ).status_code == 404


@pytest.mark.asyncio
async def test_file_policy_idempotency_and_abort_rejection_paths(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    unsupported = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "payload.exe",
            "size_bytes": 1,
            "idempotency_key": "unsupported-file-001",
        },
    )
    assert unsupported.status_code == 422

    oversized = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "too-large.pdf",
            "size_bytes": 2_000_000_001,
            "idempotency_key": "oversized-file-001",
        },
    )
    assert oversized.status_code == 413

    metadata_too_large = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "metadata.pdf",
            "size_bytes": 1,
            "custom_metadata": {"large": "x" * 17_000},
            "idempotency_key": "metadata-file-001",
        },
    )
    assert metadata_too_large.status_code == 422

    request = {
        "filename": "abort-me.pdf",
        "size_bytes": 4,
        "content_type": "application/pdf",
        "idempotency_key": "abort-file-001",
    }
    initiated = await api_harness.client.post(
        "/api/v1/files/uploads", headers=headers, json=request
    )
    assert initiated.status_code == 201, initiated.text
    upload = initiated.json()
    replay = await api_harness.client.post("/api/v1/files/uploads", headers=headers, json=request)
    assert replay.status_code == 201
    conflict = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={**request, "filename": "different.pdf"},
    )
    assert conflict.status_code == 409

    assert (
        await api_harness.client.get(
            f"/api/v1/files/uploads/{upload['upload_session_id']}", headers=headers
        )
    ).status_code == 200
    assert (
        await api_harness.client.post(
            f"/api/v1/files/uploads/{upload['upload_session_id']}/parts",
            headers=headers,
            json={"part_numbers": [1]},
        )
    ).status_code == 409
    aborted = await api_harness.client.delete(
        f"/api/v1/files/uploads/{upload['upload_session_id']}", headers=headers
    )
    assert aborted.status_code == 204
    assert (
        await api_harness.client.delete(
            f"/api/v1/files/uploads/{upload['upload_session_id']}", headers=headers
        )
    ).status_code == 204


@pytest.mark.asyncio
async def test_upload_size_mismatch_and_multipart_validation_paths(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    api_harness.storage.head_size = 6

    single = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "mismatch.pdf",
            "size_bytes": 5,
            "idempotency_key": "mismatch-file-001",
        },
    )
    mismatch = await api_harness.client.post(
        f"/api/v1/files/uploads/{single.json()['upload_session_id']}/complete",
        headers=headers,
        json={"parts": []},
    )
    assert mismatch.status_code == 422
    assert api_harness.storage.deleted_keys

    size = get_settings().multipart_threshold_bytes + 1
    api_harness.storage.head_size = size
    multipart = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "invalid-parts.pdf",
            "size_bytes": size,
            "idempotency_key": "invalid-parts-001",
        },
    )
    upload = multipart.json()
    out_of_range = await api_harness.client.post(
        f"/api/v1/files/uploads/{upload['upload_session_id']}/parts",
        headers=headers,
        json={"part_numbers": [upload["part_count"] + 1]},
    )
    assert out_of_range.status_code == 422
    duplicate_parts = await api_harness.client.post(
        f"/api/v1/files/uploads/{upload['upload_session_id']}/parts",
        headers=headers,
        json={"part_numbers": [1, 1]},
    )
    assert duplicate_parts.status_code == 422
    incomplete = await api_harness.client.post(
        f"/api/v1/files/uploads/{upload['upload_session_id']}/complete",
        headers=headers,
        json={"parts": [{"part_number": 1, "etag": '"only-one"'}]},
    )
    assert incomplete.status_code == 422
    assert (
        await api_harness.client.delete(
            f"/api/v1/files/uploads/{upload['upload_session_id']}", headers=headers
        )
    ).status_code == 204


@pytest.mark.asyncio
async def test_readiness_uses_database_and_redis(api_harness: ApiHarness) -> None:
    response = await api_harness.client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
