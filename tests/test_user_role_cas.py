from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import select

from app.db.models import AuditLog, User

pytest_plugins = ("test_integration_api",)


async def _create_role(
    api_harness: Any,
    headers: dict[str, str],
    *,
    code: str,
) -> str:
    response = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={"code": code, "name": code, "priority": -1},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


@pytest.mark.asyncio
async def test_user_role_replacement_requires_strict_cas_and_audits_versions(
    api_harness: Any,
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    original_role_id = await _create_role(
        api_harness,
        headers,
        code="cas-original-role",
    )
    replacement_role_id = await _create_role(
        api_harness,
        headers,
        code="cas-replacement-role",
    )
    created = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "cas-target@example.com",
            "password": "CAS-target-password-123!",
            "role_ids": [original_role_id],
        },
    )
    assert created.status_code == 201, created.text
    created_body: dict[str, Any] = created.json()
    user_id = str(created_body["id"])
    user_uuid = UUID(user_id)
    assert created_body["role_assignment_version"] == 1

    missing_version = await api_harness.client.put(
        f"/api/v1/users/{user_id}/roles",
        headers=headers,
        json={"role_ids": [original_role_id]},
    )
    assert missing_version.status_code == 422, missing_version.text

    async with api_harness.session_factory() as session:
        token_version_before = await session.scalar(
            select(User.token_version).where(User.id == user_uuid)
        )
    assert token_version_before == 0

    no_op = await api_harness.client.put(
        f"/api/v1/users/{user_id}/roles",
        headers=headers,
        json={
            "expected_version": 1,
            "role_ids": [original_role_id],
        },
    )
    assert no_op.status_code == 200, no_op.text
    assert no_op.json()["role_assignment_version"] == 1

    changed = await api_harness.client.put(
        f"/api/v1/users/{user_id}/roles",
        headers=headers,
        json={
            "expected_version": 1,
            "role_ids": [replacement_role_id],
        },
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["role_assignment_version"] == 2

    stale_restore = await api_harness.client.put(
        f"/api/v1/users/{user_id}/roles",
        headers=headers,
        json={
            "expected_version": 1,
            "role_ids": [original_role_id],
        },
    )
    assert stale_restore.status_code == 409, stale_restore.text
    assert stale_restore.json()["error"]["code"] == "stale_role_assignment"
    assert stale_restore.json()["error"]["details"] == {"current_version": 2}

    async with api_harness.session_factory() as session:
        user = await session.scalar(select(User).where(User.id == user_uuid))
        assert user is not None
        assert user.token_version == 1
        assert user.role_assignment_version == 2
        audits = list(
            (
                await session.scalars(
                    select(AuditLog)
                    .where(
                        AuditLog.action == "user.roles.replaced",
                        AuditLog.resource_id == user_id,
                    )
                    .order_by(AuditLog.id)
                )
            ).all()
        )
    assert [event.details for event in audits] == [
        {"from_version": 1, "to_version": 2},
    ]
