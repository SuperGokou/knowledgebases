from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import func, select
from starlette.requests import Request

from app.api.errors import ApiError
from app.api.v1.routes.roles import delete_role
from app.core.security import PasswordService
from app.db.models import (
    AuditLog,
    AuditResult,
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    Permission,
    Role,
    RoleLimit,
    RolePermission,
    User,
    UserRole,
)
from app.main import app
from app.services.access import AccessContext

pytest_plugins = ("test_integration_api",)


async def _admin_headers(api_harness: Any) -> dict[str, str]:
    tokens = await api_harness.login()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def _create_custom_role(
    api_harness: Any,
    headers: dict[str, str],
    *,
    code: str,
    name: str,
) -> dict[str, Any]:
    response = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={
            "code": code,
            "name": name,
            "priority": -1,
            "permission_codes": ["file:read"],
            "limits": {"daily_downloads": 7},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


async def _deleted_audit_count(api_harness: Any, role_id: UUID) -> int:
    async with api_harness.session_factory() as session:
        return int(
            await session.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.action == "role.deleted",
                    AuditLog.resource_id == str(role_id),
                )
            )
            or 0
        )


def test_role_delete_openapi_contract_requires_bounded_expected_name() -> None:
    operation = app.openapi()["paths"]["/api/v1/roles/{role_id}"]["delete"]
    parameters = {item["name"]: item for item in operation["parameters"]}

    assert operation["responses"].keys() >= {"204", "422"}
    assert parameters["role_id"]["in"] == "path"
    assert parameters["role_id"]["required"] is True
    assert parameters["expected_name"]["in"] == "query"
    assert parameters["expected_name"]["required"] is True
    assert parameters["expected_name"]["schema"]["minLength"] == 1
    assert parameters["expected_name"]["schema"]["maxLength"] == 200
    assert parameters["expected_policy_etag"]["in"] == "query"
    assert parameters["expected_policy_etag"]["required"] is True
    assert parameters["expected_policy_etag"]["schema"] == {
        "type": "string",
        "maxLength": 64,
        "minLength": 64,
        "pattern": "^[0-9a-f]{64}$",
        "title": "Expected Policy Etag",
    }


@pytest.mark.asyncio
async def test_delete_unused_custom_role_commits_policy_cleanup_and_audit_atomically(
    api_harness: Any,
) -> None:
    headers = await _admin_headers(api_harness)
    role = await _create_custom_role(
        api_harness,
        headers,
        code="temporary_delete",
        name="待删除临时角色",
    )
    role_id = UUID(role["id"])

    response = await api_harness.client.delete(
        f"/api/v1/roles/{role_id}",
        headers=headers,
        params={
            "expected_name": role["name"],
            "expected_policy_etag": role["policy_etag"],
        },
    )

    assert response.status_code == 204, response.text
    assert response.content == b""
    request_id = response.headers["x-request-id"]
    async with api_harness.session_factory() as session:
        assert await session.get(Role, role_id) is None
        permission_rows = int(
            await session.scalar(
                select(func.count())
                .select_from(RolePermission)
                .where(RolePermission.role_id == role_id)
            )
            or 0
        )
        limit_rows = int(
            await session.scalar(
                select(func.count())
                .select_from(RoleLimit)
                .where(RoleLimit.role_id == role_id)
            )
            or 0
        )
        audits = list(
            (
                await session.scalars(
                    select(AuditLog).where(
                        AuditLog.action == "role.deleted",
                        AuditLog.resource_id == str(role_id),
                    )
                )
            ).all()
        )

    assert permission_rows == 0
    assert limit_rows == 0
    assert len(audits) == 1
    assert audits[0].result == AuditResult.SUCCESS
    assert audits[0].request_id == request_id
    assert audits[0].details == {
        "code": role["code"],
        "name": role["name"],
        "policy_etag": role["policy_etag"],
        "priority": role["priority"],
    }

    repeated = await api_harness.client.delete(
        f"/api/v1/roles/{role_id}",
        headers=headers,
        params={
            "expected_name": role["name"],
            "expected_policy_etag": role["policy_etag"],
        },
    )
    assert repeated.status_code == 404
    assert repeated.json()["error"]["code"] == "role_not_found"
    assert await _deleted_audit_count(api_harness, role_id) == 1


@pytest.mark.asyncio
async def test_delete_system_role_is_forbidden_without_audit(api_harness: Any) -> None:
    headers = await _admin_headers(api_harness)
    roles = (await api_harness.client.get("/api/v1/roles", headers=headers)).json()
    system_role = next(item for item in roles if item["is_system"])
    role_id = UUID(system_role["id"])

    response = await api_harness.client.delete(
        f"/api/v1/roles/{role_id}",
        headers=headers,
        params={
            "expected_name": system_role["name"],
            "expected_policy_etag": system_role["policy_etag"],
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "system_role"
    async with api_harness.session_factory() as session:
        assert await session.get(Role, role_id) is not None
    assert await _deleted_audit_count(api_harness, role_id) == 0


@pytest.mark.asyncio
async def test_delete_rejects_stale_role_name_and_preserves_role(api_harness: Any) -> None:
    headers = await _admin_headers(api_harness)
    role = await _create_custom_role(
        api_harness,
        headers,
        code="rename_before_delete",
        name="删除确认前名称",
    )
    role_id = UUID(role["id"])
    renamed = await api_harness.client.patch(
        f"/api/v1/roles/{role_id}",
        headers=headers,
        json={"name": "删除确认后名称"},
    )
    assert renamed.status_code == 200, renamed.text

    response = await api_harness.client.delete(
        f"/api/v1/roles/{role_id}",
        headers=headers,
        params={
            "expected_name": role["name"],
            "expected_policy_etag": role["policy_etag"],
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "role_changed"
    async with api_harness.session_factory() as session:
        persisted = await session.get(Role, role_id)
        assert persisted is not None
        assert persisted.name == "删除确认后名称"
    assert await _deleted_audit_count(api_harness, role_id) == 0


@pytest.mark.asyncio
async def test_delete_rejects_stale_policy_etag_and_preserves_role(api_harness: Any) -> None:
    headers = await _admin_headers(api_harness)
    role = await _create_custom_role(
        api_harness,
        headers,
        code="policy_change_before_delete",
        name="策略变更前已确认角色",
    )
    role_id = UUID(role["id"])
    changed = await api_harness.client.put(
        f"/api/v1/roles/{role_id}/permissions",
        headers=headers,
        json={"permission_codes": []},
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["policy_etag"] != role["policy_etag"]

    response = await api_harness.client.delete(
        f"/api/v1/roles/{role_id}",
        headers=headers,
        params={
            "expected_name": role["name"],
            "expected_policy_etag": role["policy_etag"],
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "stale_role_policy"
    async with api_harness.session_factory() as session:
        assert await session.get(Role, role_id) is not None
    assert await _deleted_audit_count(api_harness, role_id) == 0


@pytest.mark.asyncio
async def test_delete_in_use_role_reports_all_references_without_cascading(
    api_harness: Any,
) -> None:
    headers = await _admin_headers(api_harness)
    role = await _create_custom_role(
        api_harness,
        headers,
        code="referenced_role",
        name="仍在使用的角色",
    )
    role_id = UUID(role["id"])

    async with api_harness.session_factory() as session:
        admin = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert admin is not None
        member = User(
            email="role-reference@example.com",
            password_hash=PasswordService().hash("Reference-password-123!"),
        )
        knowledge_base = KnowledgeBase(owner_id=admin.id, name="角色引用测试知识库")
        session.add_all([member, knowledge_base])
        await session.flush()
        session.add_all(
            [
                UserRole(user_id=member.id, role_id=role_id, assigned_by=admin.id),
                KnowledgeBaseRoleGrant(
                    knowledge_base_id=knowledge_base.id,
                    role_id=role_id,
                    access_level=KnowledgeBaseAccessLevel.READER,
                    granted_by=admin.id,
                ),
            ]
        )
        await session.commit()
        member_id = member.id
        knowledge_base_id = knowledge_base.id

    response = await api_harness.client.delete(
        f"/api/v1/roles/{role_id}",
        headers=headers,
        params={
            "expected_name": role["name"],
            "expected_policy_etag": role["policy_etag"],
        },
    )

    assert response.status_code == 409
    assert response.json()["error"] == {
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
        assert await session.get(Role, role_id) is not None
        assert (
            await session.scalar(
                select(func.count())
                .select_from(UserRole)
                .where(UserRole.user_id == member_id, UserRole.role_id == role_id)
            )
            == 1
        )
        assert (
            await session.scalar(
                select(func.count())
                .select_from(KnowledgeBaseRoleGrant)
                .where(
                    KnowledgeBaseRoleGrant.knowledge_base_id == knowledge_base_id,
                    KnowledgeBaseRoleGrant.role_id == role_id,
                )
            )
            == 1
        )
    assert await _deleted_audit_count(api_harness, role_id) == 0


@pytest.mark.asyncio
async def test_delete_reauthorizes_actor_inside_the_locked_transaction(api_harness: Any) -> None:
    headers = await _admin_headers(api_harness)
    target = await _create_custom_role(
        api_harness,
        headers,
        code="reauthorization_target",
        name="实时授权校验目标",
    )
    target_id = UUID(target["id"])

    async with api_harness.session_factory() as session:
        manage_permission = await session.scalar(
            select(Permission).where(Permission.code == "role:manage")
        )
        assert manage_permission is not None
        actor_role = Role(code="transient_role_admin", name="临时角色管理员", priority=100)
        actor = User(
            email="transient-role-admin@example.com",
            password_hash=PasswordService().hash("Transient-admin-password-123!"),
        )
        session.add_all([actor_role, actor])
        await session.flush()
        session.add_all(
            [
                RolePermission(role_id=actor_role.id, permission_id=manage_permission.id),
                UserRole(user_id=actor.id, role_id=actor_role.id),
            ]
        )
        await session.commit()
        stale_access = AccessContext(
            user=actor,
            permissions=frozenset({"role:manage"}),
            limits={},
            role_ids=frozenset({actor_role.id}),
            max_role_priority=actor_role.priority,
        )
        await session.execute(
            RolePermission.__table__.delete().where(RolePermission.role_id == actor_role.id)
        )
        await session.commit()

    request = Request({"type": "http", "method": "DELETE", "path": "/", "headers": []})
    request.state.request_id = "reauthorization-test"
    async with api_harness.session_factory() as session:
        with pytest.raises(ApiError) as exc_info:
            await delete_role(
                role_id=target_id,
                request=request,
                session=session,
                access=stale_access,
                expected_name=target["name"],
                expected_policy_etag=target["policy_etag"],
            )
        await session.rollback()

    assert exc_info.value.status_code == 403
    assert exc_info.value.code == "permission_denied"
    async with api_harness.session_factory() as session:
        assert await session.get(Role, target_id) is not None
    assert await _deleted_audit_count(api_harness, target_id) == 0
