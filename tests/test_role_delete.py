from __future__ import annotations

from typing import Any, cast
from uuid import UUID

import pytest
from sqlalchemy import func, select

from app.db.models import (
    AuditLog,
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    Role,
    RoleLimit,
    RolePermission,
    User,
    UserRole,
)
from app.main import app

pytest_plugins = ("test_integration_api",)


def test_openapi_requires_role_delete_policy_snapshot() -> None:
    operation = app.openapi()["paths"]["/api/v1/roles/{role_id}"]["delete"]
    expected_version = next(
        parameter
        for parameter in operation["parameters"]
        if parameter["in"] == "query" and parameter["name"] == "expected_version"
    )

    assert expected_version["required"] is True
    assert expected_version["schema"]["minimum"] == 1
    assert operation["responses"]["204"] == {"description": "Successful Response"}


async def _authorization(api_harness: Any) -> dict[str, str]:
    tokens = await api_harness.login()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def _create_role(api_harness: Any, headers: dict[str, str], *, code: str) -> dict[str, Any]:
    response = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={
            "code": code,
            "name": f"Role {code}",
            "priority": -10,
            "permission_codes": ["file:read"],
            "limits": {"daily_downloads": 2},
        },
    )
    assert response.status_code == 201, response.text
    return cast(dict[str, Any], response.json())


@pytest.mark.asyncio
async def test_unreferenced_custom_role_delete_requires_cas_and_audits(api_harness: Any) -> None:
    headers = await _authorization(api_harness)
    role = await _create_role(api_harness, headers, code="delete-ready")
    role_id = str(role["id"])
    role_uuid = UUID(role_id)

    missing_version = await api_harness.client.delete(f"/api/v1/roles/{role_id}", headers=headers)
    assert missing_version.status_code == 422, missing_version.text

    deleted = await api_harness.client.delete(
        f"/api/v1/roles/{role_id}?expected_version={role['policy_version']}",
        headers=headers,
    )
    assert deleted.status_code == 204, deleted.text
    assert deleted.content == b""

    missing = await api_harness.client.get(f"/api/v1/roles/{role_id}", headers=headers)
    assert missing.status_code == 404, missing.text

    async with api_harness.session_factory() as session:
        assert await session.get(Role, role_uuid) is None
        assert (
            await session.scalar(
                select(func.count())
                .select_from(RolePermission)
                .where(RolePermission.role_id == role_uuid)
            )
            == 0
        )
        assert (
            await session.scalar(
                select(func.count()).select_from(RoleLimit).where(RoleLimit.role_id == role_uuid)
            )
            == 0
        )
        audits = list(
            (
                await session.scalars(
                    select(AuditLog).where(
                        AuditLog.action == "role.deleted",
                        AuditLog.resource_id == role_id,
                    )
                )
            ).all()
        )
    assert len(audits) == 1
    assert audits[0].details == {
        "code": "delete-ready",
        "name": "Role delete-ready",
        "policy_version": role["policy_version"],
    }


@pytest.mark.asyncio
async def test_role_delete_rejects_stale_version_and_system_role(api_harness: Any) -> None:
    headers = await _authorization(api_harness)
    role = await _create_role(api_harness, headers, code="delete-stale")
    role_id = str(role["id"])
    updated = await api_harness.client.patch(
        f"/api/v1/roles/{role_id}",
        headers=headers,
        json={"expected_version": role["policy_version"], "name": "Renamed"},
    )
    assert updated.status_code == 200, updated.text

    stale = await api_harness.client.delete(
        f"/api/v1/roles/{role_id}?expected_version={role['policy_version']}",
        headers=headers,
    )
    assert stale.status_code == 409, stale.text
    assert stale.json()["error"]["code"] == "stale_role_policy"
    assert stale.json()["error"]["details"] == {"current_version": updated.json()["policy_version"]}

    roles = await api_harness.client.get("/api/v1/roles", headers=headers)
    assert roles.status_code == 200, roles.text
    system_role = next(item for item in roles.json() if item["is_system"])
    protected = await api_harness.client.delete(
        f"/api/v1/roles/{system_role['id']}?expected_version={system_role['policy_version']}",
        headers=headers,
    )
    assert protected.status_code == 403, protected.text
    assert protected.json()["error"]["code"] == "system_role"


@pytest.mark.asyncio
async def test_role_delete_fails_closed_when_referenced_without_cascading(api_harness: Any) -> None:
    headers = await _authorization(api_harness)
    role = await _create_role(api_harness, headers, code="delete-in-use")
    role_id = str(role["id"])
    role_uuid = UUID(role_id)

    created_user = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "role-reference@example.com",
            "password": "Role-reference-password-123!",
            "role_ids": [role_id],
        },
    )
    assert created_user.status_code == 201, created_user.text
    user_uuid = UUID(str(created_user.json()["id"]))

    async with api_harness.session_factory() as session:
        admin = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert admin is not None
        knowledge_base = KnowledgeBase(name="Role reference", owner_id=admin.id)
        session.add(knowledge_base)
        await session.flush()
        session.add(
            KnowledgeBaseRoleGrant(
                knowledge_base_id=knowledge_base.id,
                role_id=role_uuid,
                access_level=KnowledgeBaseAccessLevel.READER,
                granted_by=admin.id,
            )
        )
        await session.commit()
        knowledge_base_id = knowledge_base.id

    rejected = await api_harness.client.delete(
        f"/api/v1/roles/{role_id}?expected_version={role['policy_version']}",
        headers=headers,
    )
    assert rejected.status_code == 409, rejected.text
    assert rejected.json()["error"] == {
        "code": "role_in_use",
        "message": "Role is still assigned or granted and cannot be deleted",
        "details": {
            "references": {
                "knowledge_base_grants": 1,
                "user_assignments": 1,
            }
        },
    }

    async with api_harness.session_factory() as session:
        assert await session.get(Role, role_uuid) is not None
        assert (
            await session.scalar(
                select(func.count())
                .select_from(UserRole)
                .where(
                    UserRole.user_id == user_uuid,
                    UserRole.role_id == role_uuid,
                )
            )
            == 1
        )
        assert (
            await session.scalar(
                select(func.count())
                .select_from(KnowledgeBaseRoleGrant)
                .where(
                    KnowledgeBaseRoleGrant.knowledge_base_id == knowledge_base_id,
                    KnowledgeBaseRoleGrant.role_id == role_uuid,
                )
            )
            == 1
        )
