from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from pydantic import SecretStr
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.api.dependencies import get_storage_service, redis_dependency
from app.core.config import Settings, get_settings
from app.core.security import PasswordService
from app.db.base import Base
from app.db.models import (
    ApiKey,
    AuditLog,
    AuditResult,
    File,
    FileStatus,
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
    KnowledgeIngestionStatus,
    LimitDefinition,
    LlmBudgetPolicy,
    LlmModelPrice,
    LlmProviderConfig,
    LlmUsageRecord,
    LlmUsageStatus,
    MalwareScanStatus,
    OkfConversionJob,
    OkfConversionStatus,
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
    UserStatus,
)
from app.db.schema_version import EXPECTED_ALEMBIC_HEADS
from app.db.session import get_db
from app.main import app
from app.maintenance import cleanup_expired_uploads, process_malware_scan_batch
from app.services.llm_provider import LlmChatResult, LlmProviderError
from app.services.llm_settings import LlmConfigurationError
from app.services.malware_scanner import ScanResult, ScanVerdict
from app.services.storage import InitiatedStorageUpload, PresignedPart, StoredObject
from app.services.storage_capacity import FilesystemCapacity


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
    sealed_keys: list[tuple[str, str]] = field(default_factory=list)
    object_bytes: bytes = b"clean test object"
    delete_error: Exception | None = None

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
        if self.delete_error is not None:
            raise self.delete_error
        self.deleted_keys.append(key)

    async def seal_single_upload(self, *, key: str, upload_session_id: str) -> None:
        self.sealed_keys.append((key, upload_session_id))

    async def promote(
        self,
        *,
        source_key: str,
        destination_key: str,
        upload_session_id: str,
    ) -> StoredObject:
        self.promoted_keys.append((source_key, destination_key))
        self.initiated_keys.append(destination_key)
        await self.seal_single_upload(
            key=source_key,
            upload_session_id=upload_session_id,
        )
        return await self.head(key=destination_key)

    async def iter_chunks(self, *, key: str, chunk_size: int) -> Any:
        assert key in self.initiated_keys
        for offset in range(0, len(self.object_bytes), chunk_size):
            yield self.object_bytes[offset : offset + chunk_size]

    def presign_download(self, *, key: str, filename: str) -> str:
        return f"http://storage.local/download/{key}?filename={filename}"


class FakeCleanScanner:
    async def scan(self, chunks: Any) -> ScanResult:
        assert [chunk async for chunk in chunks]
        return ScanResult(verdict=ScanVerdict.CLEAN)


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


def _signed_bff_headers(*, secret: str, client_ip: str, timestamp: int) -> dict[str, str]:
    canonical = f"v1\n{timestamp}\n{client_ip}".encode()
    signature = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
    return {
        "X-KB-Client-IP": client_ip,
        "X-KB-Client-Timestamp": str(timestamp),
        "X-KB-Client-Signature": signature,
    }


@pytest_asyncio.fixture
async def api_harness() -> ApiHarness:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        await connection.execute(
            text("CREATE TABLE alembic_version (version_num VARCHAR(32) PRIMARY KEY)")
        )
        await connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
            {"revision": next(iter(EXPECTED_ALEMBIC_HEADS))},
        )

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
                "knowledge:create",
                "knowledge:read",
                "knowledge:update",
                "knowledge:grant",
                "chat:query",
                "api-key:manage",
                "llm:manage",
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

    logout = await api_harness.client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh.json()["refresh_token"]},
    )
    assert logout.status_code == 204, logout.text
    revoked_refresh = await api_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh.json()["refresh_token"]},
    )
    assert revoked_refresh.status_code == 401

    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

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
    assert completed.json()["status"] == "quarantined"
    assert completed.json()["malware_scan_status"] == "pending"
    assert api_harness.storage.promoted_keys
    assert api_harness.storage.sealed_keys == [
        (api_harness.storage.promoted_keys[0][0], upload["upload_session_id"])
    ]
    file_id = completed.json()["id"]

    approved = await api_harness.client.post(f"/api/v1/files/{file_id}/approve", headers=headers)
    assert approved.status_code == 409, approved.text
    assert approved.json()["error"]["code"] == "malware_scan_not_clean"

    # Defense in depth: even a forged primary state cannot bypass scan evidence.
    async with api_harness.session_factory() as session:
        persisted = await session.get(File, UUID(file_id))
        assert persisted is not None
        persisted.status = FileStatus.PROCESSING
        await session.commit()
    forged_approval = await api_harness.client.post(
        f"/api/v1/files/{file_id}/approve",
        headers=headers,
    )
    assert forged_approval.status_code == 409
    assert forged_approval.json()["error"]["code"] == "malware_scan_not_clean"
    async with api_harness.session_factory() as session:
        persisted = await session.get(File, UUID(file_id))
        assert persisted is not None
        persisted.status = FileStatus.AVAILABLE
        await session.commit()
    forged_download = await api_harness.client.post(
        f"/api/v1/files/{file_id}/download",
        headers=headers,
    )
    assert forged_download.status_code == 409
    assert forged_download.json()["error"]["code"] == "malware_scan_not_clean"
    async with api_harness.session_factory() as session:
        persisted = await session.get(File, UUID(file_id))
        assert persisted is not None
        persisted.status = FileStatus.QUARANTINED
        await session.commit()

    async with api_harness.session_factory() as session:
        scanned = await process_malware_scan_batch(
            session,
            api_harness.storage,
            FakeCleanScanner(),
            get_settings(),
        )
    assert scanned == 1

    approved = await api_harness.client.post(f"/api/v1/files/{file_id}/approve", headers=headers)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "available"
    assert approved.json()["malware_scan_status"] == "clean"

    grant = await api_harness.client.post(f"/api/v1/files/{file_id}/download", headers=headers)
    assert grant.status_code == 200, grant.text
    assert grant.headers["cache-control"] == "no-store"
    assert grant.json()["url"].startswith("http://storage.local/download/")
    assert "objects/" in grant.json()["url"]
    listed = await api_harness.client.get("/api/v1/files", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["id"] == file_id


@pytest.mark.asyncio
async def test_file_delete_enforces_owner_or_superuser_and_cleans_source_entries(
    api_harness: ApiHarness,
) -> None:
    owner_password = "File-owner-password-123!"
    outsider_password = "File-outsider-password-123!"
    async with api_harness.session_factory() as session:
        admin = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert admin is not None
        admin.is_superuser = True

        owner = User(
            email="file-owner@example.com",
            password_hash=PasswordService().hash(owner_password),
        )
        outsider = User(
            email="file-outsider@example.com",
            password_hash=PasswordService().hash(outsider_password),
        )
        # No role or file permission is assigned: database ownership is the grant.
        session.add_all([owner, outsider])
        await session.flush()
        knowledge_base = KnowledgeBase(owner_id=owner.id, name="File deletion tests")
        session.add(knowledge_base)
        await session.flush()

        files = [
            File(
                owner_id=owner.id,
                knowledge_base_id=knowledge_base.id,
                bucket="kb",
                object_key=f"objects/delete-{label}-{uuid4()}.txt",
                original_name=f"{label}.txt",
                extension=".txt",
                content_type="text/plain",
                size_bytes=10,
                status=FileStatus.AVAILABLE,
            )
            for label in ("owner", "superuser", "storage-failure")
        ]
        session.add_all(files)
        await session.flush()
        entries = [
            KnowledgeEntry(
                knowledge_base_id=knowledge_base.id,
                source_file_id=file.id,
                entry_type="document",
                title=file.original_name,
                content="searchable source text",
            )
            for file in files
        ]
        session.add_all(entries)
        await session.commit()
        owner_id = owner.id
        outsider_id = outsider.id
        file_ids = [file.id for file in files]
        object_keys = [file.object_key for file in files]
        entry_ids = [entry.id for entry in entries]

    async def login(email: str, password: str) -> dict[str, str]:
        response = await api_harness.client.post(
            "/api/v1/auth/token",
            data={"username": email, "password": password},
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    owner_headers = await login("file-owner@example.com", owner_password)
    outsider_headers = await login("file-outsider@example.com", outsider_password)
    admin_headers = {
        "Authorization": f"Bearer {(await api_harness.login())['access_token']}"
    }

    # Ownership alone is sufficient: this account has neither file:read nor file:delete.
    owner_delete = await api_harness.client.delete(
        f"/api/v1/files/{file_ids[0]}", headers=owner_headers
    )
    assert owner_delete.status_code == 204, owner_delete.text

    denied = await api_harness.client.delete(
        f"/api/v1/files/{file_ids[1]}", headers=outsider_headers
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "file_delete_denied"

    superuser_delete = await api_harness.client.delete(
        f"/api/v1/files/{file_ids[1]}", headers=admin_headers
    )
    assert superuser_delete.status_code == 204, superuser_delete.text

    api_harness.storage.delete_error = RuntimeError("storage offline")
    failed = await api_harness.client.delete(
        f"/api/v1/files/{file_ids[2]}", headers=owner_headers
    )
    assert failed.status_code == 503
    assert failed.json()["error"]["code"] == "file_storage_delete_failed"
    api_harness.storage.delete_error = None

    assert api_harness.storage.deleted_keys == object_keys[:2]
    async with api_harness.session_factory() as session:
        persisted_files = [await session.get(File, file_id) for file_id in file_ids]
        persisted_entries = [await session.get(KnowledgeEntry, entry_id) for entry_id in entry_ids]
        assert all(item is not None for item in persisted_files)
        assert all(item is not None for item in persisted_entries)
        assert persisted_files[0].status is FileStatus.DELETED  # type: ignore[union-attr]
        assert persisted_files[0].deleted_at is not None  # type: ignore[union-attr]
        assert persisted_entries[0].deleted_at is not None  # type: ignore[union-attr]
        assert persisted_files[1].status is FileStatus.DELETED  # type: ignore[union-attr]
        assert persisted_entries[1].deleted_at is not None  # type: ignore[union-attr]
        assert persisted_files[2].status is FileStatus.AVAILABLE  # type: ignore[union-attr]
        assert persisted_files[2].deleted_at is None  # type: ignore[union-attr]
        assert persisted_entries[2].deleted_at is None  # type: ignore[union-attr]

        audits = list(
            (
                await session.scalars(
                    select(AuditLog)
                    .where(
                        AuditLog.resource_type == "file",
                        AuditLog.resource_id.in_([str(file_id) for file_id in file_ids]),
                        AuditLog.action.in_(["file.delete", "file.deleted"]),
                    )
                    .order_by(AuditLog.id)
                )
            ).all()
        )
        assert [(audit.actor_id, audit.result) for audit in audits] == [
            (owner_id, AuditResult.SUCCESS),
            (outsider_id, AuditResult.DENIED),
            (admin.id, AuditResult.SUCCESS),
            (owner_id, AuditResult.FAILURE),
        ]


@pytest.mark.parametrize(
    ("outcome", "expected_scan_status", "expected_error_code"),
    [
        ("infected", "infected", "malware_detected"),
        ("timeout", "error", "scanner_timeout"),
        ("unavailable", "error", "scanner_unavailable"),
    ],
)
@pytest.mark.asyncio
async def test_malware_scan_failures_remain_quarantined_and_inaccessible(
    api_harness: ApiHarness,
    outcome: str,
    expected_scan_status: str,
    expected_error_code: str,
) -> None:
    from app.services.malware_scanner import (
        MalwareScannerTimeout,
        MalwareScannerUnavailable,
    )

    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    object_key = f"objects/malware-{outcome}-{uuid4()}.txt"
    async with api_harness.session_factory() as session:
        owner = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert owner is not None
        file = File(
            owner_id=owner.id,
            bucket="kb",
            object_key=object_key,
            original_name="eicar.txt",
            extension=".txt",
            content_type="text/plain",
            size_bytes=5,
            status=FileStatus.QUARANTINED,
        )
        session.add(file)
        await session.commit()
        file_id = file.id
    api_harness.storage.initiated_keys.append(object_key)

    class Scanner:
        async def scan(self, chunks: Any) -> ScanResult:
            assert [chunk async for chunk in chunks]
            if outcome == "infected":
                return ScanResult(
                    verdict=ScanVerdict.INFECTED,
                    signature="Win.Test.EICAR_HDB-1",
                )
            if outcome == "timeout":
                raise MalwareScannerTimeout("test timeout")
            raise MalwareScannerUnavailable("test unavailable")

    async with api_harness.session_factory() as session:
        assert (
            await process_malware_scan_batch(
                session,
                api_harness.storage,
                Scanner(),
                get_settings(),
            )
            == 1
        )

    async with api_harness.session_factory() as session:
        persisted = await session.get(File, file_id)
        assert persisted is not None
        assert persisted.status is FileStatus.QUARANTINED
        assert persisted.malware_scan_status.value == expected_scan_status
        assert persisted.malware_scan_error_code == expected_error_code
        if outcome == "infected":
            assert persisted.malware_signature == "Win.Test.EICAR_HDB-1"

    approval = await api_harness.client.post(
        f"/api/v1/files/{file_id}/approve",
        headers=headers,
    )
    assert approval.status_code == 409
    assert approval.json()["error"]["code"] == "malware_scan_not_clean"
    download = await api_harness.client.post(
        f"/api/v1/files/{file_id}/download",
        headers=headers,
    )
    assert download.status_code == 409
    assert download.json()["error"]["code"] == "malware_scan_not_clean"


@pytest.mark.parametrize(
    ("latest_status", "expected_status_code"),
    [
        (OkfConversionStatus.PENDING, 409),
        (OkfConversionStatus.PROCESSING, 409),
        (OkfConversionStatus.RETRY_WAIT, 409),
        (OkfConversionStatus.SUCCEEDED, 200),
        (OkfConversionStatus.FAILED, 200),
        (OkfConversionStatus.UNSUPPORTED, 200),
    ],
)
@pytest.mark.asyncio
async def test_file_approval_follows_latest_okf_job_state(
    api_harness: ApiHarness,
    latest_status: OkfConversionStatus,
    expected_status_code: int,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    async with api_harness.session_factory() as session:
        owner = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert owner is not None
        knowledge_base = KnowledgeBase(owner_id=owner.id, name=f"Approval {latest_status.value}")
        session.add(knowledge_base)
        await session.flush()
        file = File(
            owner_id=owner.id,
            knowledge_base_id=knowledge_base.id,
            bucket="kb",
            object_key=f"objects/approval-{uuid4()}.txt",
            original_name="approval.txt",
            extension=".txt",
            content_type="text/plain",
            size_bytes=1,
            status=FileStatus.PROCESSING,
            malware_scan_status=MalwareScanStatus.CLEAN,
            version=2,
        )
        session.add(file)
        await session.flush()

        previous_entry = KnowledgeEntry(
            knowledge_base_id=knowledge_base.id,
            source_file_id=file.id,
            entry_type="previous",
            title="Previous conversion",
            content="Previous draft must remain unpublished.",
            publication_status=KnowledgeEntryPublicationStatus.DRAFT,
        )
        session.add(previous_entry)
        await session.flush()
        session.add(
            OkfConversionJob(
                file_id=file.id,
                knowledge_base_id=knowledge_base.id,
                file_version=1,
                prompt_version="test-v1",
                status=OkfConversionStatus.SUCCEEDED,
                output_entry_id=previous_entry.id,
            )
        )

        latest_entry: KnowledgeEntry | None = None
        if latest_status is OkfConversionStatus.SUCCEEDED:
            latest_entry = KnowledgeEntry(
                knowledge_base_id=knowledge_base.id,
                source_file_id=file.id,
                entry_type="latest",
                title="Latest conversion",
                content="Latest approved draft.",
                publication_status=KnowledgeEntryPublicationStatus.DRAFT,
            )
            session.add(latest_entry)
            await session.flush()
        latest_job = OkfConversionJob(
            file_id=file.id,
            knowledge_base_id=knowledge_base.id,
            file_version=2,
            prompt_version="test-v2",
            status=latest_status,
            output_entry_id=latest_entry.id if latest_entry is not None else None,
            error_code=(
                "test_terminal_failure"
                if latest_status in {OkfConversionStatus.FAILED, OkfConversionStatus.UNSUPPORTED}
                else None
            ),
        )
        session.add(latest_job)
        await session.commit()
        file_id = file.id
        previous_entry_id = previous_entry.id
        latest_entry_id = latest_entry.id if latest_entry is not None else None

    response = await api_harness.client.post(
        f"/api/v1/files/{file_id}/approve",
        headers=headers,
    )
    assert response.status_code == expected_status_code, response.text
    if response.status_code == 200:
        expected_knowledge_status = {
            OkfConversionStatus.SUCCEEDED: KnowledgeIngestionStatus.INDEXED,
            OkfConversionStatus.FAILED: KnowledgeIngestionStatus.FAILED,
            OkfConversionStatus.UNSUPPORTED: KnowledgeIngestionStatus.UNSUPPORTED,
        }[latest_status]
        assert response.json()["knowledge_status"] == expected_knowledge_status.value
        assert response.json()["searchable"] is (
            expected_knowledge_status is KnowledgeIngestionStatus.INDEXED
        )

    async with api_harness.session_factory() as session:
        persisted_file = await session.get(File, file_id)
        persisted_previous = await session.get(KnowledgeEntry, previous_entry_id)
        assert persisted_file is not None
        assert persisted_previous is not None
        assert persisted_previous.publication_status is KnowledgeEntryPublicationStatus.DRAFT
        if expected_status_code == 409:
            assert response.json()["error"]["code"] == "okf_conversion_in_progress"
            assert persisted_file.status is FileStatus.PROCESSING
        else:
            assert persisted_file.status is FileStatus.AVAILABLE
            assert persisted_file.knowledge_status is expected_knowledge_status
        if latest_entry_id is not None:
            persisted_latest = await session.get(KnowledgeEntry, latest_entry_id)
            assert persisted_latest is not None
            assert (
                persisted_latest.publication_status
                is KnowledgeEntryPublicationStatus.PUBLISHED
            )


@pytest.mark.parametrize(
    ("conversion_status", "file_status", "expected_status_code"),
    [
        (OkfConversionStatus.FAILED, FileStatus.AVAILABLE, 409),
        (OkfConversionStatus.UNSUPPORTED, FileStatus.AVAILABLE, 409),
        (OkfConversionStatus.FAILED, FileStatus.PROCESSING, 200),
        (OkfConversionStatus.UNSUPPORTED, FileStatus.PROCESSING, 200),
    ],
)
@pytest.mark.asyncio
async def test_okf_retry_requires_file_to_remain_in_processing(
    api_harness: ApiHarness,
    conversion_status: OkfConversionStatus,
    file_status: FileStatus,
    expected_status_code: int,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    async with api_harness.session_factory() as session:
        owner = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert owner is not None
        knowledge_base = KnowledgeBase(
            owner_id=owner.id,
            name=f"Retry {conversion_status.value} {file_status.value}",
        )
        session.add(knowledge_base)
        await session.flush()
        file = File(
            owner_id=owner.id,
            knowledge_base_id=knowledge_base.id,
            bucket="kb",
            object_key=f"objects/retry-{uuid4()}.txt",
            original_name="retry.txt",
            extension=".txt",
            content_type="text/plain",
            size_bytes=1,
            status=file_status,
            available_at=datetime.now(UTC) if file_status is FileStatus.AVAILABLE else None,
        )
        session.add(file)
        await session.flush()
        conversion = OkfConversionJob(
            file_id=file.id,
            knowledge_base_id=knowledge_base.id,
            file_version=1,
            prompt_version="test-retry-v1",
            status=conversion_status,
            attempts=4,
            error_code="test_terminal_failure",
            completed_at=datetime.now(UTC),
        )
        session.add(conversion)
        await session.commit()
        file_id = file.id
        conversion_id = conversion.id

    response = await api_harness.client.post(
        f"/api/v1/files/{file_id}/okf-conversion/retry",
        headers=headers,
    )
    assert response.status_code == expected_status_code, response.text

    async with api_harness.session_factory() as session:
        persisted = await session.get(OkfConversionJob, conversion_id)
        assert persisted is not None
        if expected_status_code == 409:
            assert response.json()["error"]["code"] == "okf_retry_file_state_conflict"
            assert persisted.status is conversion_status
            assert persisted.error_code == "test_terminal_failure"
        else:
            assert persisted.status is OkfConversionStatus.PENDING
            assert persisted.attempts == 0
            assert persisted.retry_generation == 1
            assert persisted.error_code is None


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
    assert completed.json()["status"] == "quarantined"
    assert completed.json()["malware_scan_status"] == "pending"


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
        assert file is not None and file.status is FileStatus.QUARANTINED
        assert file.malware_scan_status.value == "pending"
        assert {item.status for item in reservations} == {ReservationStatus.CONSUMED}


@pytest.mark.asyncio
async def test_maintenance_promotes_stale_single_finalization_without_db_locking_s3(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    api_harness.storage.head_size = 5
    initiated = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "single-maintenance-recovery.pdf",
            "size_bytes": 5,
            "idempotency_key": "single-maintenance-recovery-001",
        },
    )
    assert initiated.status_code == 201, initiated.text
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
    assert api_harness.storage.promoted_keys
    async with api_harness.session_factory() as session:
        upload = await session.get(UploadSession, upload_id)
        assert upload is not None
        file = await session.get(File, upload.file_id)
        assert upload.status is UploadSessionStatus.COMPLETED
        assert file is not None
        assert file.status is FileStatus.QUARANTINED
        assert file.object_key.startswith("objects/")


@pytest.mark.asyncio
async def test_maintenance_retries_aborted_upload_storage_cleanup(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    size = get_settings().multipart_threshold_bytes + 1
    initiated = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "abort-reconcile.pdf",
            "size_bytes": size,
            "idempotency_key": "abort-reconcile-001",
        },
    )
    assert initiated.status_code == 201, initiated.text
    upload_id = UUID(initiated.json()["upload_session_id"])

    async with api_harness.session_factory() as session:
        upload = await session.get(UploadSession, upload_id)
        assert upload is not None
        upload.status = UploadSessionStatus.ABORTED
        upload.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    async with api_harness.session_factory() as session:
        cleaned = await cleanup_expired_uploads(session, api_harness.storage)
    assert cleaned == 1
    assert api_harness.storage.deleted_keys

    async with api_harness.session_factory() as session:
        upload = await session.get(UploadSession, upload_id)
        assert upload is not None
        assert upload.status is UploadSessionStatus.ABORTED
        held = await session.scalar(
            select(QuotaReservation).where(
                QuotaReservation.upload_session_id == upload_id,
                QuotaReservation.status == ReservationStatus.HELD,
            )
        )
        assert held is None


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
    assert accepted.json() == {"cleaned": 0, "scanned": 0, "converted": 0}


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
    successor = first_refresh.json()
    replay = await api_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert replay.status_code == 401

    compromised_successor = await api_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": successor["refresh_token"]},
    )
    assert compromised_successor.status_code == 401
    invalidated_access = await api_harness.client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {successor['access_token']}"},
    )
    assert invalidated_access.status_code == 401

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
async def test_only_superuser_can_delete_unowned_user_account(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    blocked_target = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={"email": "owns-data@example.com", "password": "Owns-data-password-123!"},
    )
    deletable_target = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={"email": "delete-me@example.com", "password": "Delete-me-password-123!"},
    )
    assert blocked_target.status_code == 201
    assert deletable_target.status_code == 201

    target_id = UUID(deletable_target.json()["id"])
    denied = await api_harness.client.delete(f"/api/v1/users/{target_id}", headers=headers)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "superuser_required"

    async with api_harness.session_factory() as session:
        admin = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert admin is not None
        admin.is_superuser = True
        blocked_user_id = UUID(blocked_target.json()["id"])
        knowledge_base = KnowledgeBase(owner_id=blocked_user_id, name="保留数据")
        session.add(knowledge_base)
        await session.flush()
        session.add(
            File(
                owner_id=blocked_user_id,
                knowledge_base_id=knowledge_base.id,
                bucket="kb",
                object_key=f"objects/user-delete-blocked-{uuid4()}.txt",
                original_name="保留文件.txt",
                extension=".txt",
                content_type="text/plain",
                size_bytes=1,
            )
        )
        await session.commit()
        admin_id = admin.id

    self_delete = await api_harness.client.delete(f"/api/v1/users/{admin_id}", headers=headers)
    assert self_delete.status_code == 409
    assert self_delete.json()["error"]["code"] == "self_delete_denied"

    owns_data = await api_harness.client.delete(f"/api/v1/users/{blocked_user_id}", headers=headers)
    assert owns_data.status_code == 409
    assert owns_data.json()["error"]["code"] == "user_owns_resources"
    assert owns_data.json()["error"]["details"] == {
        "owned_files": 1,
        "owned_knowledge_bases": 1,
    }

    deleted = await api_harness.client.delete(f"/api/v1/users/{target_id}", headers=headers)
    assert deleted.status_code == 204
    assert deleted.content == b""

    async with api_harness.session_factory() as session:
        assert await session.get(User, target_id) is None
        audit = await session.scalar(
            select(AuditLog).where(
                AuditLog.action == "user.deleted",
                AuditLog.resource_id == str(target_id),
            )
        )
        assert audit is not None
        assert audit.actor_id == admin_id
        assert audit.details["email"] == "delete-me@example.com"


@pytest.mark.asyncio
async def test_only_superuser_can_reset_password_and_existing_sessions_are_revoked(
    api_harness: ApiHarness,
) -> None:
    admin_tokens = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {admin_tokens['access_token']}"}
    old_password = "Original-password-123!"
    new_password = "Replacement-password-456!"
    created = await api_harness.client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"email": "password-target@example.com", "password": old_password},
    )
    assert created.status_code == 201
    target_id = UUID(created.json()["id"])
    target_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "password-target@example.com", "password": old_password},
    )
    assert target_login.status_code == 200

    denied = await api_harness.client.put(
        f"/api/v1/users/{target_id}/password",
        headers=admin_headers,
        json={"password": new_password},
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "superuser_required"

    async with api_harness.session_factory() as session:
        admin = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert admin is not None
        admin.is_superuser = True
        await session.commit()
        admin_id = admin.id

    too_short = await api_harness.client.put(
        f"/api/v1/users/{target_id}/password",
        headers=admin_headers,
        json={"password": "short"},
    )
    assert too_short.status_code == 422
    reset = await api_harness.client.put(
        f"/api/v1/users/{target_id}/password",
        headers=admin_headers,
        json={"password": new_password},
    )
    assert reset.status_code == 204
    assert reset.content == b""

    revoked_access = await api_harness.client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {target_login.json()['access_token']}"},
    )
    assert revoked_access.status_code == 401
    assert revoked_access.json()["error"]["code"] == "token_revoked"
    old_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "password-target@example.com", "password": old_password},
    )
    assert old_login.status_code == 401
    new_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "password-target@example.com", "password": new_password},
    )
    assert new_login.status_code == 200

    async with api_harness.session_factory() as session:
        audit = await session.scalar(
            select(AuditLog).where(
                AuditLog.action == "user.password_reset",
                AuditLog.resource_id == str(target_id),
            )
        )
        assert audit is not None
        assert audit.actor_id == admin_id
        assert audit.details == {"sessions_revoked": True}


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
    assert api_harness.storage.sealed_keys[-1] == (
        api_harness.storage.initiated_keys[-1],
        upload["upload_session_id"],
    )
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
    assert api_harness.storage.sealed_keys[-1][1] == single.json()["upload_session_id"]

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


@pytest.mark.asyncio
async def test_knowledge_base_chat_demo_and_acl_boundaries(api_harness: ApiHarness) -> None:
    tokens = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    created = await api_harness.client.post(
        "/api/v1/knowledge-bases",
        headers=admin_headers,
        json={
            "name": "Engineering Handbook",
            "description": "Internal engineering knowledge",
            "custom_metadata": {"default_format": "okf"},
        },
    )
    assert created.status_code == 201, created.text
    knowledge_base = created.json()
    knowledge_base_id = knowledge_base["id"]
    assert knowledge_base["access_level"] == "manager"

    updated = await api_harness.client.patch(
        f"/api/v1/knowledge-bases/{knowledge_base_id}",
        headers=admin_headers,
        json={"description": "Curated engineering knowledge"},
    )
    assert updated.status_code == 200
    assert updated.json()["description"] == "Curated engineering knowledge"

    initiated = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=admin_headers,
        json={
            "filename": "password-reset.txt",
            "size_bytes": 25,
            "knowledge_base_id": knowledge_base_id,
            "idempotency_key": "knowledge-file-001",
        },
    )
    assert initiated.status_code == 201, initiated.text
    source_file_id = initiated.json()["file_id"]

    entry = await api_harness.client.post(
        f"/api/v1/knowledge-bases/{knowledge_base_id}/entries",
        headers=admin_headers,
        json={
            "source_file_id": source_file_id,
            "entry_type": "article",
            "title": "Reset a password",
            "content": "To reset a password, open Settings and choose Reset password.",
            "source_path": "index.md",
            "format_version": "0.1",
            "custom_metadata": {"type": "article", "owner": "identity-team"},
        },
    )
    assert entry.status_code == 201, entry.text
    entry_body = entry.json()
    assert entry_body["source_file_id"] == source_file_id
    assert entry_body["format_version"] == "0.1"
    assert entry_body["custom_metadata"] == {"type": "article", "owner": "identity-team"}

    viewer_role = await api_harness.client.post(
        "/api/v1/roles",
        headers=admin_headers,
        json={
            "code": "knowledge_viewer",
            "name": "Knowledge Viewer",
            "permission_codes": ["knowledge:read", "chat:query", "file:read"],
        },
    )
    assert viewer_role.status_code == 201, viewer_role.text
    viewer_role_id = viewer_role.json()["id"]
    outsider_role = await api_harness.client.post(
        "/api/v1/roles",
        headers=admin_headers,
        json={
            "code": "knowledge_outsider",
            "name": "Knowledge Outsider",
            "permission_codes": [
                "knowledge:read",
                "chat:query",
                "file:read",
                "file:upload",
            ],
        },
    )
    assert outsider_role.status_code == 201, outsider_role.text

    grants = await api_harness.client.put(
        f"/api/v1/knowledge-bases/{knowledge_base_id}/role-grants",
        headers=admin_headers,
        json={"grants": [{"role_id": viewer_role_id, "access_level": "reader"}]},
    )
    assert grants.status_code == 200, grants.text
    assert grants.json()[0]["role_id"] == viewer_role_id

    viewer = await api_harness.client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "viewer@example.com",
            "password": "Viewer-password-123!",
            "role_ids": [viewer_role_id],
        },
    )
    assert viewer.status_code == 201, viewer.text
    outsider = await api_harness.client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "outsider@example.com",
            "password": "Outsider-password-123!",
            "role_ids": [outsider_role.json()["id"]],
        },
    )
    assert outsider.status_code == 201, outsider.text

    viewer_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "viewer@example.com", "password": "Viewer-password-123!"},
    )
    viewer_headers = {
        "Authorization": f"Bearer {viewer_login.json()['access_token']}"
    }
    me = await api_harness.client.get("/api/v1/auth/me", headers=viewer_headers)
    assert me.status_code == 200, me.text
    assert set(me.json()["permission_codes"]) == {"knowledge:read", "chat:query", "file:read"}
    assert me.json()["role_ids"] == [viewer_role_id]

    visible = await api_harness.client.get("/api/v1/knowledge-bases", headers=viewer_headers)
    assert visible.status_code == 200
    assert [item["id"] for item in visible.json()] == [knowledge_base_id]
    assert visible.json()[0]["access_level"] == "reader"

    entries = await api_harness.client.get(
        f"/api/v1/knowledge-bases/{knowledge_base_id}/entries", headers=viewer_headers
    )
    assert entries.status_code == 200
    assert entries.json()[0]["id"] == entry_body["id"]

    search = await api_harness.client.post(
        f"/api/v1/knowledge-bases/{knowledge_base_id}/search",
        headers=viewer_headers,
        json={"query": "password", "limit": 5},
    )
    assert search.status_code == 200, search.text
    assert search.json()["items"][0]["entry_id"] == entry_body["id"]
    assert search.json()["items"][0]["source_path"] == "index.md"

    chat = await api_harness.client.post(
        "/api/v1/chat/query",
        headers=viewer_headers,
        json={
            "knowledge_base_id": knowledge_base_id,
            "message": "How do I reset my password?",
            "limit": 5,
        },
    )
    assert chat.status_code == 200, chat.text
    assert chat.json()["mode"] == "retrieval"
    assert chat.json()["citations"][0]["entry_id"] == entry_body["id"]
    assert chat.json()["citations"][0]["citation_number"] == 1
    assert chat.json()["citations"][0]["marker"] == "[1]"
    assert chat.json()["source_status"] == {
        "status": "grounded",
        "strategy": "retrieval",
        "reason": "external_processing_disabled",
        "citation_count": 1,
    }
    chat_entry_id = chat.json()["citations"][0]["entry_id"]
    assert chat.json()["answer"].endswith(
        "答案来源（知识库）：\n"
        f"[1] Reset a password（entry:{chat_entry_id} · path:index.md）"
    )

    viewer_files = await api_harness.client.get("/api/v1/files", headers=viewer_headers)
    assert viewer_files.status_code == 200
    assert viewer_files.json()[0]["knowledge_base_id"] == knowledge_base_id
    denied_update = await api_harness.client.patch(
        f"/api/v1/knowledge-bases/{knowledge_base_id}",
        headers=viewer_headers,
        json={"name": "Escalated"},
    )
    assert denied_update.status_code == 403

    outsider_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "outsider@example.com", "password": "Outsider-password-123!"},
    )
    outsider_headers = {
        "Authorization": f"Bearer {outsider_login.json()['access_token']}"
    }
    hidden = await api_harness.client.get("/api/v1/knowledge-bases", headers=outsider_headers)
    assert hidden.status_code == 200
    assert hidden.json() == []
    denied_chat = await api_harness.client.post(
        "/api/v1/chat/query",
        headers=outsider_headers,
        json={"knowledge_base_id": knowledge_base_id, "message": "password"},
    )
    assert denied_chat.status_code == 404
    denied_upload = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=outsider_headers,
        json={
            "filename": "forbidden.txt",
            "size_bytes": 1,
            "knowledge_base_id": knowledge_base_id,
            "idempotency_key": "forbidden-knowledge-file-001",
        },
    )
    assert denied_upload.status_code == 404


@pytest.mark.asyncio
async def test_revoked_knowledge_grant_removes_file_and_upload_access(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases",
        headers=admin_headers,
        json={"name": "Revocation Test"},
    )
    knowledge_base_id = knowledge_base.json()["id"]

    editor_role = await api_harness.client.post(
        "/api/v1/roles",
        headers=admin_headers,
        json={
            "code": "knowledge_editor",
            "name": "Knowledge Editor",
            "permission_codes": [
                "knowledge:read",
                "knowledge:update",
                "file:read",
                "file:upload",
            ],
            "limits": {
                "requests_per_minute": 1000,
                "max_upload_bytes": 2_000_000_000,
                "daily_upload_bytes": 2_000_000_000,
                "storage_bytes": 2_000_000_000,
                "daily_downloads": 100,
            },
        },
    )
    editor_role_id = editor_role.json()["id"]
    assert (
        await api_harness.client.put(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/role-grants",
            headers=admin_headers,
            json={"grants": [{"role_id": editor_role_id, "access_level": "editor"}]},
        )
    ).status_code == 200
    assert (
        await api_harness.client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "email": "editor@example.com",
                "password": "Editor-password-123!",
                "role_ids": [editor_role_id],
            },
        )
    ).status_code == 201

    editor_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "editor@example.com", "password": "Editor-password-123!"},
    )
    editor_headers = {
        "Authorization": f"Bearer {editor_login.json()['access_token']}"
    }

    api_harness.storage.head_size = 1
    completed_upload = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=editor_headers,
        json={
            "filename": "completed.txt",
            "size_bytes": 1,
            "knowledge_base_id": knowledge_base_id,
            "idempotency_key": "revoked-completed-001",
        },
    )
    completed_file_id = completed_upload.json()["file_id"]
    assert (
        await api_harness.client.post(
            f"/api/v1/files/uploads/{completed_upload.json()['upload_session_id']}/complete",
            headers=editor_headers,
            json={"parts": []},
        )
    ).status_code == 200
    async with api_harness.session_factory() as session:
        assert (
            await process_malware_scan_batch(
                session,
                api_harness.storage,
                FakeCleanScanner(),
                get_settings(),
            )
            == 1
        )
    async with api_harness.session_factory() as session:
        conversion = await session.scalar(
            select(OkfConversionJob).where(OkfConversionJob.file_id == UUID(completed_file_id))
        )
        assert conversion is not None
        conversion.status = OkfConversionStatus.UNSUPPORTED
        conversion.error_code = "parser_required"
        await session.commit()
    assert (
        await api_harness.client.post(
            f"/api/v1/files/{completed_file_id}/approve", headers=admin_headers
        )
    ).status_code == 200

    multipart_size = get_settings().multipart_threshold_bytes + 1
    api_harness.storage.head_size = multipart_size
    active_upload = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=editor_headers,
        json={
            "filename": "active.pdf",
            "size_bytes": multipart_size,
            "knowledge_base_id": knowledge_base_id,
            "idempotency_key": "revoked-active-001",
        },
    )
    active_upload_id = active_upload.json()["upload_session_id"]

    assert (
        await api_harness.client.put(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/role-grants",
            headers=admin_headers,
            json={"grants": []},
        )
    ).status_code == 200

    listed = await api_harness.client.get("/api/v1/files", headers=editor_headers)
    assert listed.status_code == 200
    assert listed.json() == []
    assert (
        await api_harness.client.post(
            f"/api/v1/files/{completed_file_id}/download", headers=editor_headers
        )
    ).status_code == 404
    assert (
        await api_harness.client.post(
            f"/api/v1/files/uploads/{active_upload_id}/parts",
            headers=editor_headers,
            json={"part_numbers": [1]},
        )
    ).status_code == 404
    assert (
        await api_harness.client.post(
            f"/api/v1/files/uploads/{active_upload_id}/complete",
            headers=editor_headers,
            json={"parts": []},
        )
    ).status_code == 404


@pytest.mark.asyncio
async def test_punctuation_only_search_never_falls_back_to_all_entries(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases", headers=headers, json={"name": "Search Boundary"}
    )
    knowledge_base_id = knowledge_base.json()["id"]
    assert (
        await api_harness.client.post(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/entries",
            headers=headers,
            json={"entry_type": "note", "title": "Visible", "content": "ordinary content"},
        )
    ).status_code == 201

    search = await api_harness.client.post(
        f"/api/v1/knowledge-bases/{knowledge_base_id}/search",
        headers=headers,
        json={"query": "!!!", "limit": 10},
    )
    assert search.status_code == 200
    assert search.json()["items"] == []


@pytest.mark.asyncio
async def test_bff_signed_client_ip_requires_valid_fresh_hmac(api_harness: ApiHarness) -> None:
    secret = "bff-shared-secret-value-32-characters"
    settings = get_settings().model_copy(update={"bff_shared_secret": SecretStr(secret)})
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        now = int(time.time())
        valid_ip = "203.0.113.10"
        valid = await api_harness.client.post(
            "/api/v1/auth/token",
            headers=_signed_bff_headers(secret=secret, client_ip=valid_ip, timestamp=now),
            data={"username": "missing-valid@example.com", "password": "Wrong-password-123!"},
        )
        assert valid.status_code == 401
        assert f"auth:login:ip:{valid_ip}" in api_harness.redis.counters

        api_harness.redis.counters.clear()
        forged_ip = "203.0.113.11"
        forged_headers = _signed_bff_headers(
            secret=secret, client_ip=forged_ip, timestamp=now
        )
        forged_headers["X-KB-Client-Signature"] = "0" * 64
        forged = await api_harness.client.post(
            "/api/v1/auth/token",
            headers=forged_headers,
            data={"username": "missing-forged@example.com", "password": "Wrong-password-123!"},
        )
        assert forged.status_code == 400
        assert forged.json()["error"]["code"] == "invalid_bff_signature"
        assert f"auth:login:ip:{forged_ip}" not in api_harness.redis.counters
        assert api_harness.redis.counters == {}

        api_harness.redis.counters.clear()
        expired_ip = "203.0.113.12"
        expired = await api_harness.client.post(
            "/api/v1/auth/token",
            headers=_signed_bff_headers(
                secret=secret,
                client_ip=expired_ip,
                timestamp=now - 120,
            ),
            data={"username": "missing-expired@example.com", "password": "Wrong-password-123!"},
        )
        assert expired.status_code == 400
        assert expired.json()["error"]["code"] == "invalid_bff_signature"
        assert f"auth:login:ip:{expired_ip}" not in api_harness.redis.counters
        assert api_harness.redis.counters == {}

        login_ip = "203.0.113.13"
        authenticated = await api_harness.client.post(
            "/api/v1/auth/token",
            headers=_signed_bff_headers(secret=secret, client_ip=login_ip, timestamp=now),
            data={"username": "admin@example.com", "password": "Admin-password-123!"},
        )
        assert authenticated.status_code == 200
        api_harness.redis.counters.clear()
        refresh_ip = "203.0.113.14"
        refreshed = await api_harness.client.post(
            "/api/v1/auth/refresh",
            headers=_signed_bff_headers(secret=secret, client_ip=refresh_ip, timestamp=now),
            json={"refresh_token": authenticated.json()["refresh_token"]},
        )
        assert refreshed.status_code == 200
        assert f"auth:refresh:ip:{refresh_ip}" in api_harness.redis.counters
    finally:
        app.dependency_overrides.pop(get_settings, None)


@pytest.mark.asyncio
async def test_unsigned_forwarded_ip_is_trusted_only_on_vercel(api_harness: ApiHarness) -> None:
    forwarded_ip = "198.51.100.20"
    serverless = get_settings().model_copy(update={"serverless": True})
    app.dependency_overrides[get_settings] = lambda: serverless
    try:
        response = await api_harness.client.post(
            "/api/v1/auth/token",
            headers={
                "X-KB-Client-IP": "203.0.113.250",
                "X-Vercel-Forwarded-For": forwarded_ip,
            },
            data={"username": "missing-vercel@example.com", "password": "Wrong-password-123!"},
        )
        assert response.status_code == 401
        assert f"auth:login:ip:{forwarded_ip}" in api_harness.redis.counters
    finally:
        app.dependency_overrides.pop(get_settings, None)

    api_harness.redis.counters.clear()
    local = get_settings().model_copy(update={"serverless": False})
    app.dependency_overrides[get_settings] = lambda: local
    try:
        response = await api_harness.client.post(
            "/api/v1/auth/token",
            headers={"X-Vercel-Forwarded-For": forwarded_ip},
            data={"username": "missing-local@example.com", "password": "Wrong-password-123!"},
        )
        assert response.status_code == 401
        assert f"auth:login:ip:{forwarded_ip}" not in api_harness.redis.counters
        assert "auth:login:ip:127.0.0.1" in api_harness.redis.counters
    finally:
        app.dependency_overrides.pop(get_settings, None)


@pytest.mark.asyncio
async def test_unsigned_forwarded_ip_is_trusted_from_configured_proxy_only(
    api_harness: ApiHarness,
) -> None:
    forwarded_ip = "198.51.100.21"
    trusted = get_settings().model_copy(
        update={"serverless": False, "trusted_proxy_cidrs": ("127.0.0.0/24",)}
    )
    app.dependency_overrides[get_settings] = lambda: trusted
    try:
        response = await api_harness.client.post(
            "/api/v1/auth/token",
            headers={"X-Vercel-Forwarded-For": forwarded_ip},
            data={"username": "missing-proxy@example.com", "password": "Wrong-password-123!"},
        )
        assert response.status_code == 401
        assert f"auth:login:ip:{forwarded_ip}" in api_harness.redis.counters
    finally:
        app.dependency_overrides.pop(get_settings, None)


@pytest.mark.asyncio
async def test_chat_only_role_can_select_and_query_but_not_browse_entries(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases", headers=admin_headers, json={"name": "Chat Only"}
    )
    knowledge_base_id = knowledge_base.json()["id"]
    role = await api_harness.client.post(
        "/api/v1/roles",
        headers=admin_headers,
        json={
            "code": "chat_only",
            "name": "Chat Only",
            "permission_codes": ["chat:query"],
        },
    )
    role_id = role.json()["id"]
    assert (
        await api_harness.client.put(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/role-grants",
            headers=admin_headers,
            json={"grants": [{"role_id": role_id, "access_level": "reader"}]},
        )
    ).status_code == 200
    assert (
        await api_harness.client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "email": "chat-only@example.com",
                "password": "Chat-only-password-123!",
                "role_ids": [role_id],
            },
        )
    ).status_code == 201
    login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "chat-only@example.com", "password": "Chat-only-password-123!"},
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    listed = await api_harness.client.get("/api/v1/knowledge-bases", headers=headers)
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [knowledge_base_id]
    chat = await api_harness.client.post(
        "/api/v1/chat/query",
        headers=headers,
        json={"knowledge_base_id": knowledge_base_id, "message": "hello"},
    )
    assert chat.status_code == 200
    assert chat.json()["citations"] == []
    assert chat.json()["source_status"] == {
        "status": "no_results",
        "strategy": "retrieval",
        "reason": "no_matching_content",
        "citation_count": 0,
    }
    assert chat.json()["answer"].endswith("答案来源：当前知识库未检索到可引用内容。")
    assert (
        await api_harness.client.get(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/entries", headers=headers
        )
    ).status_code == 403
    assert (
        await api_harness.client.post(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/search",
            headers=headers,
            json={"query": "hello"},
        )
    ).status_code == 403


@pytest.mark.asyncio
async def test_create_user_with_roles_requires_role_assign(api_harness: ApiHarness) -> None:
    tokens = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    target_role = await api_harness.client.post(
        "/api/v1/roles",
        headers=admin_headers,
        json={"code": "assignment_target", "name": "Assignment Target", "priority": -1},
    )
    manager_role = await api_harness.client.post(
        "/api/v1/roles",
        headers=admin_headers,
        json={
            "code": "user_manager_only",
            "name": "User Manager Only",
            "priority": 0,
            "permission_codes": ["user:manage"],
        },
    )
    assert (
        await api_harness.client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "email": "user-manager@example.com",
                "password": "User-manager-password-123!",
                "role_ids": [manager_role.json()["id"]],
            },
        )
    ).status_code == 201
    login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={
            "username": "user-manager@example.com",
            "password": "User-manager-password-123!",
        },
    )
    manager_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    without_roles = await api_harness.client.post(
        "/api/v1/users",
        headers=manager_headers,
        json={"email": "plain-user@example.com", "password": "Plain-user-password-123!"},
    )
    assert without_roles.status_code == 201
    with_roles = await api_harness.client.post(
        "/api/v1/users",
        headers=manager_headers,
        json={
            "email": "assigned-user@example.com",
            "password": "Assigned-user-password-123!",
            "role_ids": [target_role.json()["id"]],
        },
    )
    assert with_roles.status_code == 403
    assert with_roles.json()["error"]["code"] == "permission_denied"


@pytest.mark.asyncio
async def test_atomic_role_policy_replaces_both_halves_or_neither(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    role = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={
            "code": "atomic_policy",
            "name": "Atomic Policy",
            "priority": -1,
            "permission_codes": ["file:read"],
            "limits": {"max_upload_bytes": 10},
        },
    )
    role_id = role.json()["id"]

    replaced = await api_harness.client.put(
        f"/api/v1/roles/{role_id}/policy",
        headers=headers,
        json={
            "permission_codes": ["file:upload"],
            "limits": {"max_upload_bytes": 20, "daily_upload_bytes": 30},
        },
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["permission_codes"] == ["file:upload"]
    assert replaced.json()["limits"] == {
        "daily_upload_bytes": 30,
        "max_upload_bytes": 20,
    }

    rejected = await api_harness.client.put(
        f"/api/v1/roles/{role_id}/policy",
        headers=headers,
        json={
            "permission_codes": ["file:read"],
            "limits": {"not_in_catalog": 0},
        },
    )
    assert rejected.status_code == 422
    unchanged = await api_harness.client.get(f"/api/v1/roles/{role_id}", headers=headers)
    assert unchanged.json()["permission_codes"] == ["file:upload"]
    assert unchanged.json()["limits"] == {
        "daily_upload_bytes": 30,
        "max_upload_bytes": 20,
    }


@pytest.mark.asyncio
async def test_upload_only_role_can_select_editor_knowledge_base(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases", headers=admin_headers, json={"name": "Upload Target"}
    )
    knowledge_base_id = knowledge_base.json()["id"]
    role = await api_harness.client.post(
        "/api/v1/roles",
        headers=admin_headers,
        json={
            "code": "upload_only",
            "name": "Upload Only",
            "permission_codes": ["file:upload"],
            "limits": {
                "max_upload_bytes": 1000,
                "daily_upload_bytes": 1000,
                "storage_bytes": 1000,
            },
        },
    )
    role_id = role.json()["id"]
    assert (
        await api_harness.client.put(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/role-grants",
            headers=admin_headers,
            json={"grants": [{"role_id": role_id, "access_level": "editor"}]},
        )
    ).status_code == 200
    assert (
        await api_harness.client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "email": "upload-only@example.com",
                "password": "Upload-only-password-123!",
                "role_ids": [role_id],
            },
        )
    ).status_code == 201
    login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "upload-only@example.com", "password": "Upload-only-password-123!"},
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    listed = await api_harness.client.get("/api/v1/knowledge-bases", headers=headers)
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [knowledge_base_id]
    uploaded = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "upload-only.txt",
            "size_bytes": 1,
            "knowledge_base_id": knowledge_base_id,
            "idempotency_key": "upload-only-file-001",
        },
    )
    assert uploaded.status_code == 201, uploaded.text
    assert (
        await api_harness.client.get(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/entries", headers=headers
        )
    ).status_code == 403
    assert (
        await api_harness.client.post(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/search",
            headers=headers,
            json={"query": "hello"},
        )
    ).status_code == 403


@pytest.mark.asyncio
async def test_scoped_api_key_lifecycle_and_public_endpoints(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases", headers=headers, json={"name": "Partner API"}
    )
    assert knowledge_base.status_code == 201
    knowledge_base_id = knowledge_base.json()["id"]
    entry = await api_harness.client.post(
        f"/api/v1/knowledge-bases/{knowledge_base_id}/entries",
        headers=headers,
        json={
            "entry_type": "policy",
            "title": "Refund Policy",
            "content": "Refunds need approval.",
        },
    )
    assert entry.status_code == 201, entry.text

    created = await api_harness.client.post(
        "/api/v1/api-keys",
        headers=headers,
        json={
            "name": "Partner integration",
            "permission_codes": ["chat:query", "knowledge:read"],
            "knowledge_base_ids": [knowledge_base_id],
            "requests_per_minute": 20,
        },
    )
    assert created.status_code == 201, created.text
    assert created.headers["cache-control"] == "no-store"
    cleartext = created.json()["key"]
    api_key_id = created.json()["id"]
    assert cleartext.startswith("kb_live_")
    assert "key_hash" not in created.json()

    listed = await api_harness.client.get("/api/v1/api-keys", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["key_prefix"] == cleartext[:20]
    assert "key" not in listed.json()[0]
    async with api_harness.session_factory() as session:
        stored = await session.get(ApiKey, UUID(api_key_id))
        assert stored is not None
        assert stored.key_hash != cleartext
        assert len(stored.key_hash) == 64

    api_headers = {"X-API-Key": cleartext}
    searched = await api_harness.client.post(
        f"/api/v1/public/knowledge-bases/{knowledge_base_id}/search",
        headers=api_headers,
        json={"query": "refund"},
    )
    assert searched.status_code == 200, searched.text
    assert searched.json()["mode"] == "retrieval"
    assert searched.json()["items"][0]["title"] == "Refund Policy"
    chatted = await api_harness.client.post(
        "/api/v1/public/chat/query",
        headers=api_headers,
        json={"knowledge_base_id": knowledge_base_id, "message": "refund"},
    )
    assert chatted.status_code == 200, chatted.text
    assert chatted.json()["mode"] == "retrieval"
    used = await api_harness.client.get("/api/v1/api-keys", headers=headers)
    assert used.json()[0]["last_used_at"] is not None

    async with api_harness.session_factory() as session:
        chat_permission_id = await session.scalar(
            select(Permission.id).where(Permission.code == "chat:query")
        )
        assert chat_permission_id is not None
        await session.execute(
            delete(RolePermission).where(
                RolePermission.permission_id == chat_permission_id
            )
        )
        await session.commit()
    permission_removed = await api_harness.client.post(
        "/api/v1/public/chat/query",
        headers=api_headers,
        json={"knowledge_base_id": knowledge_base_id, "message": "refund"},
    )
    assert permission_removed.status_code == 403

    out_of_scope = await api_harness.client.post(
        "/api/v1/knowledge-bases", headers=headers, json={"name": "Not in key scope"}
    )
    denied = await api_harness.client.post(
        f"/api/v1/public/knowledge-bases/{out_of_scope.json()['id']}/search",
        headers=api_headers,
        json={"query": "anything"},
    )
    assert denied.status_code == 404

    revoked = await api_harness.client.delete(
        f"/api/v1/api-keys/{api_key_id}", headers=headers
    )
    assert revoked.status_code == 204
    rejected = await api_harness.client.post(
        "/api/v1/public/chat/query",
        headers=api_headers,
        json={"knowledge_base_id": knowledge_base_id, "message": "refund"},
    )
    assert rejected.status_code == 401

    limited = await api_harness.client.post(
        "/api/v1/api-keys",
        headers=headers,
        json={
            "name": "One request per minute",
            "permission_codes": ["knowledge:read"],
            "knowledge_base_ids": [knowledge_base_id],
            "requests_per_minute": 1,
        },
    )
    assert limited.status_code == 201
    limited_headers = {"X-API-Key": limited.json()["key"]}
    assert (
        await api_harness.client.post(
            f"/api/v1/public/knowledge-bases/{knowledge_base_id}/search",
            headers=limited_headers,
            json={"query": "refund"},
        )
    ).status_code == 200
    rate_limited = await api_harness.client.post(
        f"/api/v1/public/knowledge-bases/{knowledge_base_id}/search",
        headers=limited_headers,
        json={"query": "refund"},
    )
    assert rate_limited.status_code == 429
    assert int(rate_limited.headers["retry-after"]) >= 1
    assert rate_limited.headers["x-ratelimit-limit"] == "1"
    assert rate_limited.headers["x-ratelimit-remaining"] == "0"

    async with api_harness.session_factory() as session:
        expiring = await session.get(ApiKey, UUID(limited.json()["id"]))
        assert expiring is not None
        expiring.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    assert (
        await api_harness.client.post(
            f"/api/v1/public/knowledge-bases/{knowledge_base_id}/search",
            headers=limited_headers,
            json={"query": "refund"},
        )
    ).status_code == 401

    active = await api_harness.client.post(
        "/api/v1/api-keys",
        headers=headers,
        json={
            "name": "Disabled user test",
            "permission_codes": ["knowledge:read"],
            "knowledge_base_ids": [knowledge_base_id],
        },
    )
    assert active.status_code == 201
    async with api_harness.session_factory() as session:
        target = await session.get(User, UUID(active.json()["user_id"]))
        assert target is not None
        target.status = UserStatus.DISABLED
        await session.commit()
    disabled_user = await api_harness.client.post(
        f"/api/v1/public/knowledge-bases/{knowledge_base_id}/search",
        headers={"X-API-Key": active.json()["key"]},
        json={"query": "refund"},
    )
    assert disabled_user.status_code == 401


@pytest.mark.asyncio
async def test_non_superuser_cannot_issue_api_key_for_another_account(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    key_manager_role = await api_harness.client.post(
        "/api/v1/roles",
        headers=admin_headers,
        json={
            "code": "api_key_manager_without_impersonation",
            "name": "API Key Manager",
            "permission_codes": ["api-key:manage"],
        },
    )
    assert key_manager_role.status_code == 201, key_manager_role.text
    target_role = await api_harness.client.post(
        "/api/v1/roles",
        headers=admin_headers,
        json={
            "code": "api_key_target",
            "name": "API Key Target",
            "permission_codes": ["chat:query"],
        },
    )
    assert target_role.status_code == 201, target_role.text
    manager = await api_harness.client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "api-key-manager@example.com",
            "password": "API-key-manager-password-123!",
            "role_ids": [key_manager_role.json()["id"]],
        },
    )
    target = await api_harness.client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "api-key-target@example.com",
            "password": "API-key-target-password-123!",
            "role_ids": [target_role.json()["id"]],
        },
    )
    assert manager.status_code == 201, manager.text
    assert target.status_code == 201, target.text
    manager_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={
            "username": "api-key-manager@example.com",
            "password": "API-key-manager-password-123!",
        },
    )
    manager_headers = {
        "Authorization": f"Bearer {manager_login.json()['access_token']}"
    }
    denied = await api_harness.client.post(
        "/api/v1/api-keys",
        headers=manager_headers,
        json={
            "name": "Cross-account credential",
            "user_id": target.json()["id"],
            "permission_codes": ["chat:query"],
            "knowledge_base_ids": [str(uuid4())],
            "requests_per_minute": 10,
        },
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "api_key_escalation_denied"


@pytest.mark.asyncio
async def test_llm_provider_settings_are_allowlisted_encrypted_and_never_echoed(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    providers = await api_harness.client.get("/api/v1/llm/providers", headers=headers)
    assert providers.status_code == 200, providers.text
    provider_payload = providers.json()
    assert provider_payload["runtime_enabled"] is True
    assert provider_payload["runtime_profile"] == "standard"
    assert provider_payload["runtime_reason"] == "enabled"
    assert {item["provider"] for item in provider_payload["providers"]} == {
        "deepseek",
        "qwen",
        "minimax",
    }
    assert all("api_key" not in item for item in provider_payload["providers"])

    disabled_settings = get_settings().model_copy(
        update={"deployment_profile": "isolated", "external_llm_enabled": False}
    )
    app.dependency_overrides[get_settings] = lambda: disabled_settings
    try:
        disabled_runtime = await api_harness.client.get("/api/v1/llm/providers", headers=headers)
        assert disabled_runtime.status_code == 200, disabled_runtime.text
        assert disabled_runtime.json()["runtime_enabled"] is False
        assert disabled_runtime.json()["runtime_profile"] == "isolated"
        assert disabled_runtime.json()["runtime_reason"] == "deployment_external_llm_disabled"
    finally:
        app.dependency_overrides.pop(get_settings, None)

    private_connected_settings = get_settings().model_copy(
        update={
            "deployment_profile": "private_connected",
            "external_llm_enabled": True,
            "llm_https_proxy": "http://llm-egress-proxy:8080",
        }
    )
    app.dependency_overrides[get_settings] = lambda: private_connected_settings
    try:
        private_connected_runtime = await api_harness.client.get(
            "/api/v1/llm/providers", headers=headers
        )
        assert private_connected_runtime.status_code == 200, private_connected_runtime.text
        assert private_connected_runtime.json()["runtime_enabled"] is True
        assert private_connected_runtime.json()["runtime_profile"] == "private_connected"
        assert private_connected_runtime.json()["runtime_reason"] == "enabled"
    finally:
        app.dependency_overrides.pop(get_settings, None)

    unconfigured_default_settings = get_settings().model_copy(
        update={"deepseek_api_key": None}
    )
    app.dependency_overrides[get_settings] = lambda: unconfigured_default_settings
    try:
        price_only = await api_harness.client.patch(
            "/api/v1/llm/providers/deepseek",
            headers=headers,
            json={
                "input_micro_usd_per_million_tokens": 100_000,
                "output_micro_usd_per_million_tokens": 200_000,
            },
        )
        assert price_only.status_code == 200, price_only.text
        assert price_only.json()["is_default"] is True
        assert price_only.json()["configured"] is False
        assert price_only.json()["pricing_configured"] is True
    finally:
        app.dependency_overrides.pop(get_settings, None)

    blocked = await api_harness.client.patch(
        "/api/v1/llm/providers/qwen",
        headers=headers,
        json={"base_url": "https://attacker.example/v1"},
    )
    assert blocked.status_code == 422
    unconfigured_settings = get_settings().model_copy(update={"qwen_api_key": None})
    app.dependency_overrides[get_settings] = lambda: unconfigured_settings
    try:
        unconfigured_default = await api_harness.client.patch(
            "/api/v1/llm/providers/qwen",
            headers=headers,
            json={"make_default": True},
        )
        assert unconfigured_default.status_code == 422
        assert unconfigured_default.json()["error"]["code"] == "llm_provider_not_configured"
    finally:
        app.dependency_overrides.pop(get_settings, None)
    no_encryption_key = await api_harness.client.patch(
        "/api/v1/llm/providers/qwen",
        headers=headers,
        json={"api_key": "qwen-secret-api-key"},
    )
    assert no_encryption_key.status_code == 503

    settings = get_settings().model_copy(
        update={
            "llm_credentials_encryption_key": SecretStr(
                "test-only-provider-encryption-key-1234567890"
            )
        }
    )
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        updated = await api_harness.client.patch(
            "/api/v1/llm/providers/qwen",
            headers=headers,
            json={
                "model": "qwen-plus",
                "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
                "api_key": "qwen-secret-api-key",
                "make_default": True,
                "input_micro_usd_per_million_tokens": 800_000,
                "output_micro_usd_per_million_tokens": 2_000_000,
            },
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["is_default"] is True
        assert updated.json()["configured"] is True
        assert updated.json()["credential_source"] == "database"
        assert updated.json()["pricing_configured"] is True
        assert updated.json()["input_micro_usd_per_million_tokens"] == 800_000
        assert updated.json()["output_micro_usd_per_million_tokens"] == 2_000_000
        assert "api_key" not in updated.json()

        refreshed = await api_harness.client.get("/api/v1/llm/providers", headers=headers)
        assert refreshed.json()["default_provider"] == "qwen"
        assert "qwen-secret-api-key" not in refreshed.text
        async with api_harness.session_factory() as session:
            stored = await session.get(LlmProviderConfig, "qwen")
            assert stored is not None
            assert stored.api_key_ciphertext
            assert stored.api_key_ciphertext != "qwen-secret-api-key"
            price = await session.get(LlmModelPrice, ("qwen", "qwen-plus"))
            assert price is not None
            assert price.input_micro_usd_per_million_tokens == 800_000
    finally:
        app.dependency_overrides.pop(get_settings, None)


@pytest.mark.parametrize(
    "fabricated_source_block",
    [
        "**Sources:**\n- https://fabricated.example/policy [1]",
        "- Sources:\n- https://fabricated.example/policy [1]",
        "> Sources:\n- https://fabricated.example/policy [1]",
        "**Sources:** https://fabricated.example/policy [1]",
        "- 来源：https://fabricated.example/policy [1]",
    ],
)
@pytest.mark.asyncio
async def test_chat_generation_requires_kb_opt_in_and_reports_selected_model(
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
    fabricated_source_block: str,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases", headers=headers, json={"name": "LLM Consent"}
    )
    knowledge_base_id = knowledge_base.json()["id"]
    assert (
        await api_harness.client.post(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/entries",
            headers=headers,
            json={
                "entry_type": "policy",
                "title": "Travel Policy",
                "content": "Travel expenses require manager approval.",
            },
        )
    ).status_code == 201

    async with api_harness.session_factory() as session:
        session.add_all(
            [
                LlmModelPrice(
                    provider="qwen",
                    model="qwen-plus",
                    input_micro_usd_per_million_tokens=1_000_000,
                    output_micro_usd_per_million_tokens=2_000_000,
                    active=True,
                ),
                LlmModelPrice(
                    provider="minimax",
                    model="MiniMax-M2.7",
                    input_micro_usd_per_million_tokens=1_000_000,
                    output_micro_usd_per_million_tokens=2_000_000,
                    active=True,
                ),
                LlmBudgetPolicy(
                    name="test tenant LLM budget",
                    tenant_key="default",
                    daily_token_limit=100_000,
                    monthly_token_limit=1_000_000,
                    daily_cost_limit_micro_usd=100_000,
                    monthly_cost_limit_micro_usd=1_000_000,
                    enabled=True,
                ),
            ]
        )
        await session.commit()

    calls: list[list[dict[str, str]]] = []
    model_answer = "Manager approval is required [1]."
    review_answer = '{"verdict":"pass","unsupported_claims":[]}'
    review_provider_failure = False

    class FakeClient:
        configured = True

        def __init__(self, provider: str, model: str) -> None:
            self.provider = provider
            self.model = model

        async def complete_chat(
            self,
            messages: list[dict[str, str]],
            *,
            temperature: float = 0.2,
            max_tokens: int | None = None,
        ) -> LlmChatResult:
            del temperature, max_tokens
            calls.append(messages)
            is_review = "strict grounding auditor" in messages[0]["content"]
            if is_review and review_provider_failure:
                raise LlmProviderError(
                    "llm_upstream_error",
                    provider=self.provider,
                    retryable=True,
                    upstream_status=503,
                )
            content = review_answer if is_review else model_answer
            return LlmChatResult(
                content=content,
                provider=self.provider,
                model=self.model,
                prompt_tokens=10,
                completion_tokens=8,
            )

    generation_client = FakeClient("qwen", "qwen-plus")
    review_client = FakeClient("minimax", "MiniMax-M2.7")

    async def fake_resolve(
        *_args: object,
        provider: str | None = None,
        **_kwargs: object,
    ) -> FakeClient:
        return review_client if provider == "minimax" else generation_client

    monkeypatch.setattr("app.services.chat.resolve_provider_client", fake_resolve)
    payload = {"knowledge_base_id": knowledge_base_id, "message": "travel approval"}
    without_consent = await api_harness.client.post(
        "/api/v1/chat/query", headers=headers, json=payload
    )
    assert without_consent.status_code == 200
    assert without_consent.json()["mode"] == "retrieval"
    assert calls == []

    opted_in = await api_harness.client.patch(
        f"/api/v1/knowledge-bases/{knowledge_base_id}",
        headers=headers,
        json={"external_llm_processing_enabled": True},
    )
    assert opted_in.status_code == 200

    disabled_settings = get_settings().model_copy(
        update={"deployment_profile": "isolated", "external_llm_enabled": False}
    )
    app.dependency_overrides[get_settings] = lambda: disabled_settings
    try:
        disabled_by_deployment = await api_harness.client.post(
            "/api/v1/chat/query",
            headers={**headers, "Idempotency-Key": "deployment-disabled-e2e"},
            json=payload,
        )
        assert disabled_by_deployment.status_code == 200, disabled_by_deployment.text
        assert disabled_by_deployment.json()["source_status"] == {
            "status": "grounded",
            "strategy": "retrieval_fallback",
            "reason": "deployment_external_llm_disabled",
            "citation_count": 1,
        }
        assert calls == []
    finally:
        app.dependency_overrides.pop(get_settings, None)

    generated = await api_harness.client.post(
        "/api/v1/chat/query",
        headers={**headers, "Idempotency-Key": "grounded-generation-e2e"},
        json=payload,
    )
    assert generated.status_code == 200, generated.text
    assert generated.json()["mode"] == "rag"
    assert generated.json()["provider"] == "qwen"
    assert generated.json()["model"] == "qwen-plus"
    assert generated.json()["answer"].startswith("Manager approval is required [1].")
    generated_entry_id = generated.json()["citations"][0]["entry_id"]
    assert generated.json()["answer"].endswith(
        f"答案来源（知识库）：\n[1] Travel Policy（entry:{generated_entry_id}）"
    )
    assert generated.json()["citations"][0]["citation_number"] == 1
    assert generated.json()["citations"][0]["marker"] == "[1]"
    assert generated.json()["source_status"] == {
        "status": "grounded",
        "strategy": "rag",
        "reason": "llm_generated",
        "citation_count": 1,
    }
    assert generated.json()["answer_review"] == {
        "status": "passed",
        "reason": "semantic_verified",
    }
    assert len(calls) == 2
    async with api_harness.session_factory() as session:
        usage_rows = list(
            (
                await session.scalars(
                    select(LlmUsageRecord).order_by(LlmUsageRecord.operation)
                )
            ).all()
        )
    assert [row.operation for row in usage_rows] == ["chat.answer", "chat.review"]
    assert all(row.status is LlmUsageStatus.SETTLED for row in usage_rows)
    assert all(row.actual_token_count == 18 for row in usage_rows)
    llm_payload = json.loads(calls[0][1]["content"])
    assert llm_payload == {
        "question": "travel approval",
        "knowledge_context": [
            {
                "citation_number": 1,
                "title": "Travel Policy",
                "excerpt": "Travel expenses require manager approval.",
            }
        ],
    }
    assert "KNOWLEDGE_CONTEXT_START" not in calls[0][1]["content"]

    model_answer = "CONFIDENTIAL_GENERATED_DRAFT must never be returned [1]."
    review_cases = (
        (
            "review-rejected-e2e",
            '{"verdict":"fail","unsupported_claims":["unsupported"]}',
            False,
            "answer_review_rejected",
        ),
        ("review-invalid-e2e", "not-json", False, "answer_review_invalid"),
        (
            "review-provider-failure-e2e",
            '{"verdict":"pass","unsupported_claims":[]}',
            True,
            "answer_review_unavailable",
        ),
    )
    for idempotency_key, review_payload, provider_failure, expected_reason in review_cases:
        review_answer = review_payload
        review_provider_failure = provider_failure
        rejected = await api_harness.client.post(
            "/api/v1/chat/query",
            headers={**headers, "Idempotency-Key": idempotency_key},
            json=payload,
        )
        assert rejected.status_code == 200, rejected.text
        assert rejected.json()["mode"] == "retrieval"
        assert rejected.json()["answer_review"]["status"] == "fallback"
        assert rejected.json()["source_status"] == {
            "status": "grounded",
            "strategy": "retrieval_fallback",
            "reason": expected_reason,
            "citation_count": 1,
        }
        assert "CONFIDENTIAL_GENERATED_DRAFT" not in rejected.json()["answer"]

    review_answer = '{"verdict":"pass","unsupported_claims":[]}'
    review_provider_failure = False

    model_answer = "This answer cites a source that was never retrieved [99]."
    invalid_citation = await api_harness.client.post(
        "/api/v1/chat/query", headers=headers, json=payload
    )
    assert invalid_citation.status_code == 200, invalid_citation.text
    assert invalid_citation.json()["mode"] == "retrieval"
    assert invalid_citation.json()["source_status"] == {
        "status": "grounded",
        "strategy": "retrieval_fallback",
        "reason": "invalid_model_citations",
        "citation_count": 1,
    }
    assert "never retrieved" not in invalid_citation.json()["answer"]

    model_answer = "This answer contains no source marker."
    missing_citation = await api_harness.client.post(
        "/api/v1/chat/query", headers=headers, json=payload
    )
    assert missing_citation.status_code == 200, missing_citation.text
    assert missing_citation.json()["mode"] == "retrieval"
    assert missing_citation.json()["source_status"]["reason"] == "missing_model_citations"
    assert "no source marker" not in missing_citation.json()["answer"]

    model_answer = "The first paragraph is grounded [1].\n\nThe second paragraph is not."
    partially_cited = await api_harness.client.post(
        "/api/v1/chat/query", headers=headers, json=payload
    )
    assert partially_cited.status_code == 200, partially_cited.text
    assert partially_cited.json()["mode"] == "retrieval"
    assert partially_cited.json()["source_status"]["reason"] == "missing_model_citations"
    assert "second paragraph" not in partially_cited.json()["answer"]

    model_answer = (
        "Manager approval is required [1].\n\n"
        f"{fabricated_source_block}"
    )
    fabricated_sources = await api_harness.client.post(
        "/api/v1/chat/query", headers=headers, json=payload
    )
    assert fabricated_sources.status_code == 200, fabricated_sources.text
    assert fabricated_sources.json()["mode"] == "retrieval"
    assert fabricated_sources.json()["source_status"]["reason"] == "invalid_model_citations"
    assert "fabricated.example" not in fabricated_sources.json()["answer"]

    class UnconfiguredClient:
        provider = "qwen"
        model = "qwen-plus"
        configured = False

    async def fake_unconfigured_resolve(
        *_args: object, **_kwargs: object
    ) -> UnconfiguredClient:
        return UnconfiguredClient()

    monkeypatch.setattr(
        "app.services.chat.resolve_provider_client", fake_unconfigured_resolve
    )
    unconfigured = await api_harness.client.post(
        "/api/v1/chat/query", headers=headers, json=payload
    )
    assert unconfigured.status_code == 200, unconfigured.text
    assert unconfigured.json()["source_status"] == {
        "status": "grounded",
        "strategy": "retrieval_fallback",
        "reason": "provider_unconfigured",
        "citation_count": 1,
    }

    async def fake_invalid_config_resolve(*_args: object, **_kwargs: object) -> None:
        raise LlmConfigurationError("credential_encryption_key_missing")

    monkeypatch.setattr(
        "app.services.chat.resolve_provider_client", fake_invalid_config_resolve
    )
    invalid_config = await api_harness.client.post(
        "/api/v1/chat/query", headers=headers, json=payload
    )
    assert invalid_config.status_code == 200, invalid_config.text
    assert invalid_config.json()["source_status"]["reason"] == "provider_configuration_error"

    class FailingClient:
        provider = "qwen"
        model = "qwen-plus"
        configured = True

        async def complete_chat(
            self,
            messages: list[dict[str, str]],
            *,
            temperature: float = 0.2,
            max_tokens: int | None = None,
        ) -> LlmChatResult:
            del messages, temperature, max_tokens
            raise LlmProviderError(
                "llm_upstream_error",
                provider=self.provider,
                retryable=True,
                upstream_status=503,
            )

    async def fake_failing_resolve(*_args: object, **_kwargs: object) -> FailingClient:
        return FailingClient()

    monkeypatch.setattr("app.services.chat.resolve_provider_client", fake_failing_resolve)
    provider_unavailable = await api_harness.client.post(
        "/api/v1/chat/query", headers=headers, json=payload
    )
    assert provider_unavailable.status_code == 200, provider_unavailable.text
    assert provider_unavailable.json()["source_status"]["reason"] == "provider_unavailable"


@pytest.mark.asyncio
async def test_non_superuser_cannot_list_issue_or_revoke_another_users_api_key(
    api_harness: ApiHarness,
) -> None:
    admin_tokens = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {admin_tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases", headers=admin_headers, json={"name": "Tenant Isolation"}
    )
    knowledge_base_id = knowledge_base.json()["id"]

    operator_role = await api_harness.client.post(
        "/api/v1/roles",
        headers=admin_headers,
        json={
            "code": "api_key_operator",
            "name": "API Key Operator",
            "permission_codes": ["api-key:manage", "knowledge:read"],
        },
    )
    assert operator_role.status_code == 201, operator_role.text
    role_id = operator_role.json()["id"]
    assert (
        await api_harness.client.put(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/role-grants",
            headers=admin_headers,
            json={"grants": [{"role_id": role_id, "access_level": "reader"}]},
        )
    ).status_code == 200
    operator = await api_harness.client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "key-operator@example.com",
            "password": "Key-operator-password-123!",
            "role_ids": [role_id],
        },
    )
    assert operator.status_code == 201, operator.text
    operator_id = operator.json()["id"]
    operator_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={
            "username": "key-operator@example.com",
            "password": "Key-operator-password-123!",
        },
    )
    assert operator_login.status_code == 200
    operator_headers = {
        "Authorization": f"Bearer {operator_login.json()['access_token']}"
    }
    issued = await api_harness.client.post(
        "/api/v1/api-keys",
        headers=operator_headers,
        json={
            "name": "Operator-owned key",
            "permission_codes": ["knowledge:read"],
            "knowledge_base_ids": [knowledge_base_id],
        },
    )
    assert issued.status_code == 201, issued.text

    own_list = await api_harness.client.get("/api/v1/api-keys", headers=operator_headers)
    assert [item["id"] for item in own_list.json()] == [issued.json()["id"]]
    concealed = await api_harness.client.get("/api/v1/api-keys", headers=admin_headers)
    assert concealed.status_code == 200
    assert concealed.json() == []
    concealed_with_filter = await api_harness.client.get(
        f"/api/v1/api-keys?user_id={operator_id}", headers=admin_headers
    )
    assert concealed_with_filter.status_code == 200
    assert concealed_with_filter.json() == []

    cross_issue = await api_harness.client.post(
        "/api/v1/api-keys",
        headers=admin_headers,
        json={
            "name": "Forbidden cross-account key",
            "user_id": operator_id,
            "permission_codes": ["knowledge:read"],
            "knowledge_base_ids": [knowledge_base_id],
        },
    )
    assert cross_issue.status_code == 403
    denied_revoke = await api_harness.client.delete(
        f"/api/v1/api-keys/{issued.json()['id']}", headers=admin_headers
    )
    assert denied_revoke.status_code == 404

    still_usable = await api_harness.client.post(
        f"/api/v1/public/knowledge-bases/{knowledge_base_id}/search",
        headers={"X-API-Key": issued.json()["key"]},
        json={"query": "tenant"},
    )
    assert still_usable.status_code == 200, still_usable.text


@pytest.mark.asyncio
async def test_platform_upload_cap_applies_to_an_unlimited_admin_role(
    api_harness: ApiHarness,
) -> None:
    async with api_harness.session_factory() as session:
        role_limit = await session.scalar(
            select(RoleLimit)
            .join(LimitDefinition, LimitDefinition.id == RoleLimit.limit_definition_id)
            .where(LimitDefinition.key == "max_upload_bytes")
        )
        assert role_limit is not None
        role_limit.value = None
        await session.commit()

    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={
            "platform_max_upload_bytes": 1_024,
            "malware_scan_max_stream_bytes": 1_024,
        }
    )
    try:
        tokens = await api_harness.login()
        response = await api_harness.client.post(
            "/api/v1/files/uploads",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={
                "filename": "platform-capped.pdf",
                "size_bytes": 1_025,
                "idempotency_key": "platform-hard-cap-001",
            },
        )
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "file_policy_violation"


@pytest.mark.asyncio
async def test_object_storage_stop_line_rejects_before_a_presigned_url_is_issued(
    api_harness: ApiHarness,
    tmp_path: Path,
) -> None:
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={
            "storage_capacity_probe_path": tmp_path,
            "storage_object_stop_bytes": 10,
        }
    )
    try:
        tokens = await api_harness.login()
        response = await api_harness.client.post(
            "/api/v1/files/uploads",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={
                "filename": "stop-line.pdf",
                "size_bytes": 10,
                "idempotency_key": "storage-stop-line-001",
            },
        )
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert response.status_code == 507
    assert response.json()["error"]["code"] == "object_storage_stop_line_reached"
    assert api_harness.storage.initiated_keys == []


@pytest.mark.asyncio
async def test_file_count_quota_blocks_tiny_file_cardinality_amplification(
    api_harness: ApiHarness,
) -> None:
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={
            "platform_max_files_per_user": 1,
            "platform_max_files_total": 10,
        }
    )
    try:
        tokens = await api_harness.login()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        first = await api_harness.client.post(
            "/api/v1/files/uploads",
            headers=headers,
            json={
                "filename": "tiny-1.txt",
                "size_bytes": 1,
                "idempotency_key": "tiny-file-count-001",
            },
        )
        second = await api_harness.client.post(
            "/api/v1/files/uploads",
            headers=headers,
            json={
                "filename": "tiny-2.txt",
                "size_bytes": 1,
                "idempotency_key": "tiny-file-count-002",
            },
        )
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert first.status_code == 201, first.text
    assert second.status_code == 429, second.text
    assert second.json()["error"]["code"] == "quota_exceeded"
    assert len(api_harness.storage.initiated_keys) == 1


@pytest.mark.asyncio
async def test_multipart_storage_initiation_failure_is_idempotently_retryable(
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    request = {
        "filename": "retry-init.pdf",
        "size_bytes": get_settings().multipart_threshold_bytes + 1,
        "idempotency_key": "retry-storage-init-001",
    }
    original_initiate = api_harness.storage.initiate
    attempts = 0

    async def flaky_initiate(**kwargs: Any) -> InitiatedStorageUpload:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("simulated object store outage")
        return await original_initiate(**kwargs)

    monkeypatch.setattr(api_harness.storage, "initiate", flaky_initiate)
    first = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json=request,
    )
    retried = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json=request,
    )

    assert first.status_code == 500
    assert retried.status_code == 201, retried.text
    upload_id = UUID(retried.json()["upload_session_id"])
    async with api_harness.session_factory() as session:
        upload = await session.get(UploadSession, upload_id)
        assert upload is not None
        assert upload.status is UploadSessionStatus.INITIATED
        assert upload.storage_upload_id == "multipart-123"


@pytest.mark.asyncio
async def test_abort_storage_failure_keeps_cleanup_retryable(
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    initiated = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "retry-abort.pdf",
            "size_bytes": get_settings().multipart_threshold_bytes + 1,
            "idempotency_key": "retry-storage-abort-001",
        },
    )
    assert initiated.status_code == 201, initiated.text
    upload_id = UUID(initiated.json()["upload_session_id"])
    original_abort = api_harness.storage.abort_multipart
    attempts = 0

    async def flaky_abort(**kwargs: Any) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("simulated object store outage")
        await original_abort(**kwargs)

    monkeypatch.setattr(api_harness.storage, "abort_multipart", flaky_abort)
    first = await api_harness.client.delete(
        f"/api/v1/files/uploads/{upload_id}",
        headers=headers,
    )
    async with api_harness.session_factory() as session:
        upload = await session.get(UploadSession, upload_id)
        assert upload is not None
        assert upload.status is UploadSessionStatus.ABORTED
        held_before_retry = await session.scalar(
            select(QuotaReservation).where(
                QuotaReservation.upload_session_id == upload_id,
                QuotaReservation.status == ReservationStatus.HELD,
            )
        )
        assert held_before_retry is not None
    retried = await api_harness.client.delete(
        f"/api/v1/files/uploads/{upload_id}",
        headers=headers,
    )

    assert first.status_code == 500
    assert retried.status_code == 204, retried.text
    async with api_harness.session_factory() as session:
        held_after_retry = await session.scalar(
            select(QuotaReservation).where(
                QuotaReservation.upload_session_id == upload_id,
                QuotaReservation.status == ReservationStatus.HELD,
            )
        )
        assert held_after_retry is None


@pytest.mark.asyncio
async def test_concurrent_abort_wins_over_inflight_multipart_completion(
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    size = get_settings().multipart_threshold_bytes + 1
    api_harness.storage.head_size = size
    initiated = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=headers,
        json={
            "filename": "complete-abort-race.pdf",
            "size_bytes": size,
            "idempotency_key": "complete-abort-race-001",
        },
    )
    assert initiated.status_code == 201, initiated.text
    upload = initiated.json()
    entered_storage = asyncio.Event()
    release_storage = asyncio.Event()
    original_complete = api_harness.storage.complete_multipart

    async def delayed_complete(**kwargs: Any) -> None:
        entered_storage.set()
        await release_storage.wait()
        await original_complete(**kwargs)

    monkeypatch.setattr(api_harness.storage, "complete_multipart", delayed_complete)
    completion_task = asyncio.create_task(
        api_harness.client.post(
            f"/api/v1/files/uploads/{upload['upload_session_id']}/complete",
            headers=headers,
            json={
                "parts": [
                    {"part_number": number, "etag": f'"etag-{number}"'}
                    for number in range(1, upload["part_count"] + 1)
                ]
            },
        )
    )
    await asyncio.wait_for(entered_storage.wait(), timeout=2)
    aborted = await api_harness.client.delete(
        f"/api/v1/files/uploads/{upload['upload_session_id']}",
        headers=headers,
    )
    release_storage.set()
    completed = await asyncio.wait_for(completion_task, timeout=2)

    assert aborted.status_code == 204, aborted.text
    assert completed.status_code == 409, completed.text
    assert completed.json()["error"]["code"] == "upload_state_conflict"
    upload_id = UUID(upload["upload_session_id"])
    async with api_harness.session_factory() as session:
        persisted = await session.get(UploadSession, upload_id)
        assert persisted is not None
        assert persisted.status is UploadSessionStatus.ABORTED
        held = await session.scalar(
            select(QuotaReservation).where(
                QuotaReservation.upload_session_id == upload_id,
                QuotaReservation.status == ReservationStatus.HELD,
            )
        )
        assert held is None
    assert api_harness.storage.deleted_keys


@pytest.mark.asyncio
async def test_platform_file_count_stop_line_is_global_and_precedes_storage_io(
    api_harness: ApiHarness,
) -> None:
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={
            "platform_max_files_per_user": 10,
            "platform_max_files_total": 1,
        }
    )
    try:
        tokens = await api_harness.login()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        first = await api_harness.client.post(
            "/api/v1/files/uploads",
            headers=headers,
            json={
                "filename": "global-tiny-1.txt",
                "size_bytes": 1,
                "idempotency_key": "global-file-count-001",
            },
        )
        second = await api_harness.client.post(
            "/api/v1/files/uploads",
            headers=headers,
            json={
                "filename": "global-tiny-2.txt",
                "size_bytes": 1,
                "idempotency_key": "global-file-count-002",
            },
        )
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert first.status_code == 201, first.text
    assert second.status_code == 507, second.text
    assert second.json()["error"]["code"] == "platform_file_count_limit_reached"
    assert len(api_harness.storage.initiated_keys) == 1


@pytest.mark.asyncio
async def test_knowledge_entry_count_and_byte_caps_fail_closed(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases",
        headers=headers,
        json={"name": "Bounded manual entries"},
    )
    assert knowledge_base.status_code == 201, knowledge_base.text
    knowledge_base_id = knowledge_base.json()["id"]

    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={
            "platform_max_entries_per_knowledge_base": 1,
            "platform_max_entry_bytes_per_knowledge_base": 5,
        }
    )
    try:
        first = await api_harness.client.post(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/entries",
            headers=headers,
            json={
                "entry_type": "manual",
                "title": "First",
                "content": "12345",
            },
        )
        count_denied = await api_harness.client.post(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/entries",
            headers=headers,
            json={
                "entry_type": "manual",
                "title": "Second",
                "content": "x",
            },
        )
        bytes_denied = await api_harness.client.patch(
            f"/api/v1/knowledge-bases/{knowledge_base_id}/entries/{first.json()['id']}",
            headers=headers,
            json={"content": "123456"},
        )
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert first.status_code == 201, first.text
    assert count_denied.status_code == 507, count_denied.text
    assert count_denied.json()["error"]["code"] == "knowledge_entry_count_limit_reached"
    assert bytes_denied.status_code == 507, bytes_denied.text
    assert bytes_denied.json()["error"]["code"] == "knowledge_entry_bytes_limit_reached"


@pytest.mark.asyncio
async def test_manual_entries_cannot_forge_system_generated_integrity_metadata(
    api_harness: ApiHarness,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases",
        headers=headers,
        json={"name": "Protected parser metadata"},
    )
    assert knowledge_base.status_code == 201, knowledge_base.text
    knowledge_base_id = knowledge_base.json()["id"]

    forged = await api_harness.client.post(
        f"/api/v1/knowledge-bases/{knowledge_base_id}/entries",
        headers=headers,
        json={
            "entry_type": "document",
            "title": "Forged spreadsheet",
            "content": "[worksheet:Sheet1!A1] 部门",
            "custom_metadata": {
                "source_parser": "ooxml-xlsx",
                "generator": {"provider": "local", "model": "local-deterministic-v1"},
            },
        },
    )
    assert forged.status_code == 422
    assert forged.json()["error"]["code"] == "reserved_entry_metadata"

    manual = await api_harness.client.post(
        f"/api/v1/knowledge-bases/{knowledge_base_id}/entries",
        headers=headers,
        json={
            "entry_type": "manual",
            "title": "Manual note",
            "content": "Human-authored content",
            "custom_metadata": {"owner": "quality"},
        },
    )
    assert manual.status_code == 201, manual.text

    forged_update = await api_harness.client.patch(
        f"/api/v1/knowledge-bases/{knowledge_base_id}/entries/{manual.json()['id']}",
        headers=headers,
        json={
            "custom_metadata": {
                "owner": "quality",
                "source_text_sha256": "0" * 64,
            }
        },
    )
    assert forged_update.status_code == 422
    assert forged_update.json()["error"]["code"] == "reserved_entry_metadata"


@pytest.mark.asyncio
async def test_bulk_watermark_stops_new_part_urls_for_an_existing_session(
    api_harness: ApiHarness,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capacities = iter(
        [
            FilesystemCapacity(total_bytes=100, used_bytes=79, free_bytes=21),
            FilesystemCapacity(total_bytes=100, used_bytes=80, free_bytes=20),
        ]
    )
    monkeypatch.setattr(
        FilesystemCapacity,
        "from_path",
        classmethod(lambda _cls, _path: next(capacities)),
    )
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={
            "multipart_threshold_bytes": 1,
            "storage_capacity_probe_path": tmp_path,
        }
    )
    try:
        tokens = await api_harness.login()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        initiated = await api_harness.client.post(
            "/api/v1/files/uploads",
            headers=headers,
            json={
                "filename": "watermark.pdf",
                "size_bytes": 6,
                "idempotency_key": "storage-bulk-stop-001",
            },
        )
        assert initiated.status_code == 201, initiated.text
        response = await api_harness.client.post(
            f"/api/v1/files/uploads/{initiated.json()['upload_session_id']}/parts",
            headers=headers,
            json={"part_numbers": [1]},
        )
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert response.status_code == 507
    assert response.json()["error"]["code"] == "storage_bulk_uploads_paused"


@pytest.mark.asyncio
async def test_knowledge_base_delete_enforces_owner_or_superuser_and_preserves_files(
    api_harness: ApiHarness,
) -> None:
    async with api_harness.session_factory() as session:
        await session.execute(text("PRAGMA foreign_keys=ON"))
        admin_role = await session.scalar(select(Role).where(Role.code == "admin"))
        assert admin_role is not None
        owner = User(
            email="knowledge-owner@example.com",
            password_hash=PasswordService().hash("Owner-password-123!"),
        )
        superuser = User(
            email="knowledge-superuser@example.com",
            password_hash=PasswordService().hash("Superuser-password-123!"),
            is_superuser=True,
        )
        session.add_all([owner, superuser])
        await session.flush()

        owner_knowledge_base = KnowledgeBase(owner_id=owner.id, name="Owner deletable")
        session.add(owner_knowledge_base)
        await session.flush()
        source_file = File(
            owner_id=owner.id,
            knowledge_base_id=owner_knowledge_base.id,
            bucket="kb",
            object_key=f"objects/preserved-{uuid4()}.txt",
            original_name="preserved.txt",
            extension=".txt",
            content_type="text/plain",
            size_bytes=9,
        )
        session.add(source_file)
        await session.flush()
        entry = KnowledgeEntry(
            knowledge_base_id=owner_knowledge_base.id,
            source_file_id=source_file.id,
            entry_type="document",
            title="Delete with space",
            content="knowledge",
        )
        grant = KnowledgeBaseRoleGrant(
            knowledge_base_id=owner_knowledge_base.id,
            role_id=admin_role.id,
            access_level=KnowledgeBaseAccessLevel.READER,
            granted_by=owner.id,
        )
        session.add_all([entry, grant])

        manager_knowledge_base = KnowledgeBase(owner_id=owner.id, name="Manager cannot delete")
        session.add(manager_knowledge_base)
        await session.flush()
        manager_grant = KnowledgeBaseRoleGrant(
            knowledge_base_id=manager_knowledge_base.id,
            role_id=admin_role.id,
            access_level=KnowledgeBaseAccessLevel.MANAGER,
            granted_by=owner.id,
        )
        session.add(manager_grant)
        await session.commit()
        owner_knowledge_base_id = owner_knowledge_base.id
        manager_knowledge_base_id = manager_knowledge_base.id
        source_file_id = source_file.id
        entry_id = entry.id
        grant_id = grant.id

    owner_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": owner.email, "password": "Owner-password-123!"},
    )
    assert owner_login.status_code == 200, owner_login.text
    owner_deleted = await api_harness.client.delete(
        f"/api/v1/knowledge-bases/{owner_knowledge_base_id}",
        headers={"Authorization": f"Bearer {owner_login.json()['access_token']}"},
    )
    assert owner_deleted.status_code == 204, owner_deleted.text

    async with api_harness.session_factory() as session:
        assert await session.get(KnowledgeBase, owner_knowledge_base_id) is None
        assert await session.get(KnowledgeEntry, entry_id) is None
        assert await session.get(KnowledgeBaseRoleGrant, grant_id) is None
        preserved_file = await session.get(File, source_file_id)
        assert preserved_file is not None
        assert preserved_file.knowledge_base_id is None

    admin_tokens = await api_harness.login()
    manager_denied = await api_harness.client.delete(
        f"/api/v1/knowledge-bases/{manager_knowledge_base_id}",
        headers={"Authorization": f"Bearer {admin_tokens['access_token']}"},
    )
    assert manager_denied.status_code == 403, manager_denied.text
    assert manager_denied.json()["error"]["code"] == "knowledge_base_delete_denied"

    superuser_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={
            "username": superuser.email,
            "password": "Superuser-password-123!",
        },
    )
    assert superuser_login.status_code == 200, superuser_login.text
    superuser_deleted = await api_harness.client.delete(
        f"/api/v1/knowledge-bases/{manager_knowledge_base_id}",
        headers={"Authorization": f"Bearer {superuser_login.json()['access_token']}"},
    )
    assert superuser_deleted.status_code == 204, superuser_deleted.text

    async with api_harness.session_factory() as session:
        assert await session.get(KnowledgeBase, manager_knowledge_base_id) is None
        actions = list(
            (
                await session.scalars(
                    select(AuditLog.action).where(
                        AuditLog.resource_type == "knowledge_base",
                        AuditLog.resource_id.in_(
                            [str(owner_knowledge_base_id), str(manager_knowledge_base_id)]
                        ),
                    )
                )
            ).all()
        )
        assert actions.count("knowledge_base.deleted") == 2
        assert actions.count("knowledge_base.delete_denied") == 1
