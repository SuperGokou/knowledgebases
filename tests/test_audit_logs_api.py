from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import AuditLog, AuditResult, Permission, Role, RolePermission, User
from tests.test_integration_api import ApiHarness, api_harness  # noqa: F401


async def _grant_audit_read(harness: ApiHarness) -> None:
    async with harness.session_factory() as session:
        role = await session.scalar(select(Role).where(Role.code == "admin"))
        assert role is not None
        permission = Permission(
            code="audit:read",
            name="View audit logs",
            description="Read the redacted security audit trail",
        )
        session.add(permission)
        await session.flush()
        session.add(RolePermission(role_id=role.id, permission_id=permission.id))
        await session.commit()


@pytest.mark.asyncio
async def test_audit_log_api_requires_audit_read_permission(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    tokens = await api_harness.login()
    response = await api_harness.client.get(
        "/api/v1/audit-logs",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "permission_denied"


@pytest.mark.asyncio
async def test_audit_log_api_filters_redacts_and_uses_stable_cursor_pagination(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    await _grant_audit_read(api_harness)
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    now = datetime.now(UTC)

    async with api_harness.session_factory() as session:
        actor = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert actor is not None
        session.add_all(
            [
                AuditLog(
                    actor_id=actor.id,
                    action="file.approved",
                    result=AuditResult.SUCCESS,
                    resource_type="file",
                    resource_id="file-older",
                    request_id="request-older",
                    ip_address="198.51.100.10",
                    details={
                        "password": "must-never-leave-the-database",
                        "api_key": "secret-key",
                    },
                    created_at=now - timedelta(minutes=2),
                ),
                AuditLog(
                    actor_id=actor.id,
                    action="file.approved",
                    result=AuditResult.SUCCESS,
                    resource_type="file",
                    resource_id="file-newer",
                    request_id="request-newer",
                    ip_address="198.51.100.11",
                    details={"token": "secret-token"},
                    created_at=now - timedelta(minutes=1),
                ),
                AuditLog(
                    actor_id=actor.id,
                    action="auth.login.denied",
                    result=AuditResult.DENIED,
                    resource_type="user",
                    resource_id="blocked-user",
                    details={"email": "sensitive@example.com"},
                    created_at=now,
                ),
                AuditLog(
                    actor_id=actor.id,
                    action="okf.conversion_failed",
                    result=AuditResult.FAILURE,
                    resource_type="okf_conversion_job",
                    resource_id="job-1",
                    details={"upstream_payload": "private-content"},
                    created_at=now + timedelta(minutes=1),
                ),
            ]
        )
        await session.commit()
        actor_id = actor.id

    denied = await api_harness.client.get(
        "/api/v1/audit-logs",
        headers=headers,
        params={"result": "denied", "actor_id": str(actor_id)},
    )
    assert denied.status_code == 200, denied.text
    assert [item["action"] for item in denied.json()["items"]] == ["auth.login.denied"]

    failed = await api_harness.client.get(
        "/api/v1/audit-logs",
        headers=headers,
        params={
            "result": "failure",
            "resource_type": "okf_conversion_job",
            "resource_id": "job-1",
        },
    )
    assert failed.status_code == 200, failed.text
    assert [item["action"] for item in failed.json()["items"]] == ["okf.conversion_failed"]

    first_page = await api_harness.client.get(
        "/api/v1/audit-logs",
        headers=headers,
        params={
            "action": "file.approved",
            "created_from": (now - timedelta(minutes=3)).isoformat(),
            "created_to": now.isoformat(),
            "limit": 1,
        },
    )
    assert first_page.status_code == 200, first_page.text
    first_body = first_page.json()
    assert [item["resource_id"] for item in first_body["items"]] == ["file-newer"]
    assert first_body["next_cursor"] is not None

    second_page = await api_harness.client.get(
        "/api/v1/audit-logs",
        headers=headers,
        params={
            "action": "file.approved",
            "created_from": (now - timedelta(minutes=3)).isoformat(),
            "created_to": now.isoformat(),
            "limit": 1,
            "cursor": first_body["next_cursor"],
        },
    )
    assert second_page.status_code == 200, second_page.text
    second_body = second_page.json()
    assert [item["resource_id"] for item in second_body["items"]] == ["file-older"]
    assert second_body["next_cursor"] is None

    exposed_keys = set(first_body["items"][0])
    assert exposed_keys == {
        "id",
        "actor_id",
        "action",
        "resource_type",
        "resource_id",
        "request_id",
        "result",
        "created_at",
    }
    serialized = first_page.text.lower()
    for forbidden in (
        "details",
        "ip_address",
        "must-never-leave-the-database",
        "secret-key",
        "secret-token",
        "sensitive@example.com",
        "private-content",
    ):
        assert forbidden not in serialized


@pytest.mark.asyncio
async def test_audit_log_api_rejects_an_inverted_time_range(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    await _grant_audit_read(api_harness)
    tokens = await api_harness.login()
    now = datetime.now(UTC)

    response = await api_harness.client.get(
        "/api/v1/audit-logs",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        params={
            "created_from": now.isoformat(),
            "created_to": (now - timedelta(seconds=1)).isoformat(),
        },
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_time_range"


@pytest.mark.asyncio
async def test_audit_log_api_rejects_naive_filter_timestamps(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    await _grant_audit_read(api_harness)
    tokens = await api_harness.login()

    response = await api_harness.client.get(
        "/api/v1/audit-logs",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        params={"created_from": "2026-07-12T12:00:00"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
