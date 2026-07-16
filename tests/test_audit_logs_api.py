from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routes import audit_logs as audit_logs_route
from app.db.models import AuditLog, AuditResult, Permission, Role, RolePermission, User
from app.main import app
from app.services.audit import list_audit_events
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


async def _export_attempts(harness: ApiHarness, request_id: str) -> list[AuditLog]:
    async with harness.session_factory() as session:
        return list(
            (
                await session.scalars(
                    select(AuditLog)
                    .where(
                        AuditLog.action == "audit.exported",
                        AuditLog.request_id == request_id,
                    )
                    .order_by(AuditLog.id)
                )
            ).all()
        )


def test_audit_log_csv_export_keeps_all_filters_in_openapi() -> None:
    operation = app.openapi()["paths"]["/api/v1/audit-logs/export"]["get"]
    parameters = {parameter["name"]: parameter for parameter in operation["parameters"]}

    assert list(parameters) == [
        "actor_id",
        "action",
        "resource_type",
        "resource_id",
        "result",
        "created_from",
        "created_to",
    ]
    assert "UUID" in parameters["actor_id"]["description"]
    assert "1 to 150" in parameters["action"]["description"]
    assert "success, failure, or denied" in parameters["result"]["description"]
    assert "RFC 3339" in parameters["created_from"]["description"]


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
    assert first_page.headers["cache-control"] == "no-store, private"
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
async def test_audit_log_query_projects_only_export_safe_columns(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    async with api_harness.session_factory() as session:
        session.add(
            AuditLog(
                action="projection.test",
                result=AuditResult.SUCCESS,
                resource_type="test",
                ip_address="198.51.100.30",
                details={"secret": "must-not-enter-the-query-result"},
            )
        )
        await session.commit()

    async with api_harness.session_factory() as session:
        events, _ = await list_audit_events(session, action="projection.test")

    assert len(events) == 1
    assert events[0].action == "projection.test"
    assert not hasattr(events[0], "details")
    assert not hasattr(events[0], "ip_address")


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


@pytest.mark.asyncio
async def test_audit_log_csv_export_requires_audit_read_permission(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    tokens = await api_harness.login()
    request_id = "audit-export-denied"

    response = await api_harness.client.get(
        "/api/v1/audit-logs/export",
        headers={
            "Authorization": f"Bearer {tokens['access_token']}",
            "X-Request-ID": request_id,
        },
        params={"action": "sensitive-filter-value"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "permission_denied"
    assert response.headers["cache-control"] == "no-store, private"
    attempts = await _export_attempts(api_harness, request_id)
    assert len(attempts) == 1
    assert attempts[0].result is AuditResult.DENIED
    assert attempts[0].ip_address is None
    assert attempts[0].details == {
        "filter_fields": ["action"],
        "max_rows": 5000,
        "reason": "permission_denied",
    }
    assert "sensitive-filter-value" not in str(attempts[0].details)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case_name", "params", "expected_filter_fields", "expected_reason"),
    [
        ("uuid", [("actor_id", "not-a-uuid")], ["actor_id"], "invalid_query_value"),
        (
            "timestamp",
            [("created_from", "not-a-timestamp")],
            ["created_from"],
            "invalid_query_value",
        ),
        (
            "naive-timestamp",
            [("created_to", "2026-07-15T10:30:00")],
            ["created_to"],
            "invalid_query_value",
        ),
        ("enum", [("result", "maybe")], ["result"], "invalid_query_value"),
        ("empty-action", [("action", "")], ["action"], "invalid_query_value"),
        (
            "action-bound",
            [("action", "sensitive-" + ("x" * 151))],
            ["action"],
            "invalid_query_value",
        ),
        (
            "resource-type-bound",
            [("resource_type", "x" * 101)],
            ["resource_type"],
            "invalid_query_value",
        ),
        (
            "resource-id-bound",
            [("resource_id", "x" * 256)],
            ["resource_id"],
            "invalid_query_value",
        ),
        (
            "duplicate",
            [("action", "first-secret"), ("action", "second-secret")],
            ["action"],
            "duplicate_query_parameter",
        ),
        (
            "unknown",
            [("password", "must-never-be-audited")],
            [],
            "unknown_query_parameter",
        ),
    ],
)
async def test_audit_log_csv_export_audits_manual_filter_validation_failures(
    api_harness: ApiHarness,  # noqa: F811
    case_name: str,
    params: list[tuple[str, str | int | float | bool | None]],
    expected_filter_fields: list[str],
    expected_reason: str,
) -> None:
    await _grant_audit_read(api_harness)
    tokens = await api_harness.login()
    request_id = f"audit-export-invalid-{case_name}"

    response = await api_harness.client.get(
        "/api/v1/audit-logs/export",
        headers={
            "Authorization": f"Bearer {tokens['access_token']}",
            "X-Request-ID": request_id,
        },
        params=params,
    )

    assert response.status_code == 422, response.text
    assert response.headers["cache-control"] == "no-store, private"
    attempts = await _export_attempts(api_harness, request_id)
    assert len(attempts) == 1
    attempt = attempts[0]
    assert attempt.result is AuditResult.FAILURE
    assert attempt.ip_address is None
    assert attempt.details == {
        "filter_fields": expected_filter_fields,
        "max_rows": 5000,
        "reason": expected_reason,
    }
    serialized = str(attempt.details).lower()
    for forbidden in ("first-secret", "second-secret", "must-never-be-audited", "sensitive-"):
        assert forbidden not in serialized


@pytest.mark.asyncio
async def test_audit_log_csv_export_rejects_invalid_time_ranges(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    await _grant_audit_read(api_harness)
    tokens = await api_harness.login()
    now = datetime.now(UTC)
    inverted_request_id = "audit-export-invalid-range"
    naive_request_id = "audit-export-invalid-naive-time"

    inverted = await api_harness.client.get(
        "/api/v1/audit-logs/export",
        headers={
            "Authorization": f"Bearer {tokens['access_token']}",
            "X-Request-ID": inverted_request_id,
        },
        params={
            "created_from": now.isoformat(),
            "created_to": (now - timedelta(seconds=1)).isoformat(),
        },
    )
    naive = await api_harness.client.get(
        "/api/v1/audit-logs/export",
        headers={
            "Authorization": f"Bearer {tokens['access_token']}",
            "X-Request-ID": naive_request_id,
        },
        params={"created_from": "2026-07-12T12:00:00"},
    )

    assert inverted.status_code == 422
    assert inverted.json()["error"]["code"] == "invalid_time_range"
    assert naive.status_code == 422
    assert naive.json()["error"]["code"] == "validation_error"
    inverted_attempts = await _export_attempts(api_harness, inverted_request_id)
    naive_attempts = await _export_attempts(api_harness, naive_request_id)
    assert len(inverted_attempts) == len(naive_attempts) == 1
    assert inverted_attempts[0].result is AuditResult.FAILURE
    assert inverted_attempts[0].details == {
        "filter_fields": ["created_from", "created_to"],
        "max_rows": 5000,
        "reason": "invalid_time_range",
    }
    assert naive_attempts[0].result is AuditResult.FAILURE
    assert naive_attempts[0].details == {
        "filter_fields": ["created_from"],
        "max_rows": 5000,
        "reason": "invalid_query_value",
    }


@pytest.mark.asyncio
async def test_audit_log_csv_export_is_bounded_redacted_safe_and_audited(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    await _grant_audit_read(api_harness)
    tokens = await api_harness.login()
    request_id = "audit-export-success"
    headers = {
        "Authorization": f"Bearer {tokens['access_token']}",
        "X-Request-ID": request_id,
    }
    now = datetime.now(UTC)

    async with api_harness.session_factory() as session:
        actor = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert actor is not None
        session.add_all(
            [
                AuditLog(
                    actor_id=actor.id,
                    action="report.export_candidate",
                    result=AuditResult.SUCCESS,
                    resource_type="report",
                    resource_id='=HYPERLINK("https://invalid.example")',
                    request_id="request,with,commas",
                    ip_address="198.51.100.20",
                    details={
                        "password": "must-never-be-exported",
                        "document_text": "private-document-content",
                    },
                    created_at=now,
                ),
                AuditLog(
                    actor_id=actor.id,
                    action="unrelated.event",
                    result=AuditResult.FAILURE,
                    resource_type="other",
                    resource_id="other-resource",
                    details={"token": "unrelated-secret"},
                    created_at=now,
                ),
            ]
        )
        await session.commit()
        actor_id = actor.id

    response = await api_harness.client.get(
        "/api/v1/audit-logs/export",
        headers=headers,
        params={
            "action": "report.export_candidate",
            "actor_id": str(actor_id),
            "resource_type": "report",
            "resource_id": '=HYPERLINK("https://invalid.example")',
            "result": "success",
            "created_from": (now - timedelta(seconds=1)).isoformat(),
            "created_to": (now + timedelta(seconds=1)).isoformat(),
        },
    )

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    disposition = response.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="audit-logs-')
    assert disposition.endswith(".csv\"; filename*=UTF-8''" + disposition.split('"')[1])
    assert response.headers["cache-control"] == "no-store, private"
    assert response.content.startswith(b"\xef\xbb\xbf")

    decoded = response.content.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(decoded, newline="")))
    assert rows[0] == [
        "id",
        "created_at",
        "result",
        "action",
        "actor_id",
        "resource_type",
        "resource_id",
        "request_id",
    ]
    assert len(rows) == 2
    assert rows[1][2:6] == [
        "success",
        "report.export_candidate",
        str(actor_id),
        "report",
    ]
    assert rows[1][6].startswith("'=HYPERLINK")
    assert rows[1][7] == "request,with,commas"
    serialized = decoded.lower()
    for forbidden in (
        "details",
        "ip_address",
        "must-never-be-exported",
        "private-document-content",
        "unrelated-secret",
    ):
        assert forbidden not in serialized

    export_events = await _export_attempts(api_harness, request_id)
    assert len(export_events) == 1
    export_event = export_events[0]
    assert export_event.actor_id == actor_id
    assert export_event.result is AuditResult.SUCCESS
    assert export_event.resource_type == "audit_log"
    assert export_event.resource_id is None
    assert export_event.request_id == response.headers["x-request-id"]
    assert export_event.details == {
        "filter_fields": [
            "action",
            "actor_id",
            "resource_type",
            "resource_id",
            "result",
            "created_from",
            "created_to",
        ],
        "max_rows": 5000,
        "row_count": 1,
    }


@pytest.mark.asyncio
async def test_audit_log_csv_export_rejects_oversized_result_and_audits_failure(
    api_harness: ApiHarness,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _grant_audit_read(api_harness)
    tokens = await api_harness.login()
    monkeypatch.setattr(audit_logs_route, "AUDIT_EXPORT_MAX_ROWS", 2)
    request_id = "audit-export-too-large"

    async with api_harness.session_factory() as session:
        actor = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert actor is not None
        session.add_all(
            [
                AuditLog(
                    actor_id=actor.id,
                    action="bulk.export_candidate",
                    result=AuditResult.SUCCESS,
                    resource_type="file",
                    resource_id=f"file-{index}",
                    details={"secret": f"secret-{index}"},
                )
                for index in range(3)
            ]
        )
        await session.commit()
        actor_id = actor.id

    response = await api_harness.client.get(
        "/api/v1/audit-logs/export",
        headers={
            "Authorization": f"Bearer {tokens['access_token']}",
            "X-Request-ID": request_id,
        },
        params={"action": "bulk.export_candidate"},
    )

    assert response.status_code == 422
    assert response.json()["error"] == {
        "code": "audit_export_too_large",
        "message": "Audit export exceeds 2 rows; narrow the filters and retry",
    }
    assert response.headers["cache-control"] == "no-store, private"

    export_events = await _export_attempts(api_harness, request_id)
    assert len(export_events) == 1
    export_event = export_events[0]
    assert export_event.actor_id == actor_id
    assert export_event.result is AuditResult.FAILURE
    assert export_event.details == {
        "filter_fields": ["action"],
        "max_rows": 2,
        "reason": "result_limit_exceeded",
    }


@pytest.mark.asyncio
async def test_audit_log_csv_export_fails_closed_when_audit_commit_fails(
    api_harness: ApiHarness,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _grant_audit_read(api_harness)
    tokens = await api_harness.login()
    request_id = "audit-export-commit-failure"

    async def fail_commit(_session: AsyncSession) -> None:
        raise RuntimeError("simulated audit database failure")

    with monkeypatch.context() as commit_failure:
        commit_failure.setattr(AsyncSession, "commit", fail_commit)
        response = await api_harness.client.get(
            "/api/v1/audit-logs/export",
            headers={
                "Authorization": f"Bearer {tokens['access_token']}",
                "X-Request-ID": request_id,
            },
        )

    assert response.status_code == 503, response.text
    assert response.json()["error"] == {
        "code": "audit_persistence_failed",
        "message": "The audit export could not be recorded",
    }
    assert response.headers["cache-control"] == "no-store, private"
    assert "content-disposition" not in response.headers
    assert await _export_attempts(api_harness, request_id) == []
