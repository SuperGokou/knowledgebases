from __future__ import annotations

import inspect
from datetime import UTC, datetime
from typing import cast

import pytest
from sqlalchemy import Table, select

from app.db.models import AuditLog, Permission, Role, RolePermission, User
from app.schemas.audit import AuditResult
from app.services.audit import add_audit_event
from tests.test_integration_api import ApiHarness, api_harness  # noqa: F401


async def _grant_audit_read(harness: ApiHarness) -> None:
    async with harness.session_factory() as session:
        role = await session.scalar(select(Role).where(Role.code == "admin"))
        assert role is not None
        permission = Permission(code="audit:read", name="View audit logs")
        session.add(permission)
        await session.flush()
        session.add(RolePermission(role_id=role.id, permission_id=permission.id))
        await session.commit()


def test_add_audit_event_requires_the_writer_to_choose_a_result() -> None:
    parameter = inspect.signature(add_audit_event).parameters["result"]
    assert parameter.default is inspect.Parameter.empty


def test_audit_result_has_a_dedicated_indexed_column() -> None:
    table = cast(Table, AuditLog.__table__)
    result = table.c.result
    indexed_columns = {column.name for index in table.indexes for column in index.columns}

    assert result.nullable is False
    assert "result" in indexed_columns


@pytest.mark.asyncio
async def test_audit_result_filter_uses_persisted_result_not_action_suffix(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    await _grant_audit_read(api_harness)
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    async with api_harness.session_factory() as session:
        actor = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert actor is not None
        session.add_all(
            [
                AuditLog(
                    actor_id=actor.id,
                    action="file.malware_scan.failed_closed",
                    result=AuditResult.FAILURE,
                    resource_type="file",
                    resource_id="failed-closed",
                    details={},
                    created_at=datetime.now(UTC),
                ),
                AuditLog(
                    actor_id=actor.id,
                    action="legacy.name.failed",
                    result=AuditResult.SUCCESS,
                    resource_type="file",
                    resource_id="successful-despite-name",
                    details={},
                    created_at=datetime.now(UTC),
                ),
            ]
        )
        await session.commit()

    response = await api_harness.client.get(
        "/api/v1/audit-logs",
        headers=headers,
        params={"result": "failure"},
    )

    assert response.status_code == 200, response.text
    assert [item["resource_id"] for item in response.json()["items"]] == ["failed-closed"]
    assert response.json()["items"][0]["result"] == "failure"
