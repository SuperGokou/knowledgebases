from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest

from app.db.models import File, FileStatus, MalwareScanStatus
from tests.test_integration_api import ApiHarness, api_harness  # noqa: F401


async def _create_limited_user(
    harness: ApiHarness,
    *,
    admin_headers: dict[str, str],
    permissions: list[str],
    limits: dict[str, int],
    label: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    unique = uuid4().hex
    role = await harness.client.post(
        "/api/v1/roles",
        headers=admin_headers,
        json={
            "code": f"quota_{label}_{unique}",
            "name": f"Quota {label} {unique}",
            "priority": -9_000,
            "permission_codes": permissions,
            "limits": limits,
        },
    )
    assert role.status_code == 201, role.text
    password = "Quota-route-password-123!"
    email = f"quota-{label}-{unique}@example.com"
    user = await harness.client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": email,
            "password": password,
            "role_ids": [role.json()["id"]],
        },
    )
    assert user.status_code == 201, user.text
    login = await harness.client.post(
        "/api/v1/auth/token",
        data={"username": email, "password": password},
    )
    assert login.status_code == 200, login.text
    return role.json(), {"Authorization": f"Bearer {login.json()['access_token']}"}


@pytest.mark.asyncio
async def test_daily_upload_bytes_exhaustion_is_enforced_on_upload_route(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    admin = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {admin['access_token']}"}
    _, member_headers = await _create_limited_user(
        api_harness,
        admin_headers=admin_headers,
        permissions=["file:upload"],
        limits={
            "max_upload_bytes": 10,
            "daily_upload_bytes": 5,
            "storage_bytes": 100,
        },
        label="upload",
    )

    first = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=member_headers,
        json={
            "filename": "quota-first.txt",
            "size_bytes": 3,
            "idempotency_key": f"quota-upload-{uuid4()}",
        },
    )
    denied = await api_harness.client.post(
        "/api/v1/files/uploads",
        headers=member_headers,
        json={
            "filename": "quota-denied.txt",
            "size_bytes": 3,
            "idempotency_key": f"quota-upload-{uuid4()}",
        },
    )

    assert first.status_code == 201, first.text
    assert denied.status_code == 429, denied.text
    assert denied.json()["error"]["code"] == "quota_exceeded"
    assert denied.json()["error"]["details"] == {
        "limit": 5,
        "remaining": 2,
        "requested": 3,
    }
    assert len(api_harness.storage.initiated_keys) == 1


@pytest.mark.asyncio
async def test_role_request_rate_exhaustion_is_enforced_on_chat_route(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    admin = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {admin['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases",
        headers=admin_headers,
        json={"name": f"Quota chat {uuid4().hex}"},
    )
    assert knowledge_base.status_code == 201, knowledge_base.text
    knowledge_base_id = knowledge_base.json()["id"]
    entry = await api_harness.client.post(
        f"/api/v1/knowledge-bases/{knowledge_base_id}/entries",
        headers=admin_headers,
        json={
            "entry_type": "manual",
            "title": "Quota chat evidence",
            "content": "The quota chat acceptance token is ROUTE-QUOTA-2026.",
        },
    )
    assert entry.status_code == 201, entry.text
    role, member_headers = await _create_limited_user(
        api_harness,
        admin_headers=admin_headers,
        permissions=["chat:query", "knowledge:read"],
        limits={"requests_per_minute": 1},
        label="chat",
    )
    grant = await api_harness.client.put(
        f"/api/v1/knowledge-bases/{knowledge_base_id}/role-grants",
        headers=admin_headers,
        json={
            "expected_version": knowledge_base.json()["role_grant_version"],
            "grants": [{"role_id": role["id"], "access_level": "reader"}],
        },
    )
    assert grant.status_code == 200, grant.text

    first = await api_harness.client.post(
        "/api/v1/chat/query",
        headers={**member_headers, "Idempotency-Key": f"quota-chat-{uuid4()}"},
        json={
            "knowledge_base_id": knowledge_base_id,
            "message": "What is the quota chat acceptance token?",
            "limit": 5,
        },
    )
    denied = await api_harness.client.post(
        "/api/v1/chat/query",
        headers={**member_headers, "Idempotency-Key": f"quota-chat-{uuid4()}"},
        json={
            "knowledge_base_id": knowledge_base_id,
            "message": "Repeat the quota chat acceptance token.",
            "limit": 5,
        },
    )

    assert first.status_code == 200, first.text
    assert denied.status_code == 429, denied.text
    assert denied.json()["error"]["code"] == "rate_limit_exceeded"
    assert denied.headers["X-RateLimit-Limit"] == "1"
    assert denied.headers["X-RateLimit-Remaining"] == "0"


@pytest.mark.asyncio
async def test_daily_download_exhaustion_is_enforced_on_download_route(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    admin = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {admin['access_token']}"}
    _, member_headers = await _create_limited_user(
        api_harness,
        admin_headers=admin_headers,
        permissions=["file:read"],
        limits={"daily_downloads": 1},
        label="download",
    )
    me = await api_harness.client.get("/api/v1/auth/me", headers=member_headers)
    assert me.status_code == 200, me.text
    async with api_harness.session_factory() as session:
        file = File(
            owner_id=UUID(me.json()["id"]),
            bucket="kb",
            object_key=f"objects/quota/{uuid4()}.txt",
            original_name="quota-download.txt",
            extension=".txt",
            content_type="text/plain",
            size_bytes=1,
            status=FileStatus.AVAILABLE,
            malware_scan_status=MalwareScanStatus.CLEAN,
        )
        session.add(file)
        await session.commit()
        file_id = file.id

    first = await api_harness.client.post(
        f"/api/v1/files/{file_id}/download",
        headers=member_headers,
    )
    denied = await api_harness.client.post(
        f"/api/v1/files/{file_id}/download",
        headers=member_headers,
    )

    assert first.status_code == 200, first.text
    assert denied.status_code == 429, denied.text
    assert denied.json()["error"]["code"] == "quota_exceeded"
    assert denied.json()["error"]["details"] == {
        "limit": 1,
        "remaining": 0,
        "requested": 1,
    }
