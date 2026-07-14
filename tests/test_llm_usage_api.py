from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.security import PasswordService
from app.db.models import (
    AuditLog,
    LlmBudgetPolicy,
    LlmModelPrice,
    LlmUsageStatus,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.services.llm_usage import (
    LlmUsageDimensions,
    LlmUsageGovernance,
)
from tests.test_integration_api import ApiHarness, api_harness  # noqa: F401


async def _grant_audit_read(harness: ApiHarness) -> None:
    async with harness.session_factory() as session:
        role = await session.scalar(select(Role).where(Role.code == "admin"))
        assert role is not None
        permission = Permission(
            code="audit:read",
            name="View audit evidence",
            description="Read content-free LLM usage evidence",
        )
        session.add(permission)
        await session.flush()
        session.add(RolePermission(role_id=role.id, permission_id=permission.id))
        await session.commit()


async def _grant_quota_manage(harness: ApiHarness) -> None:
    async with harness.session_factory() as session:
        role = await session.scalar(select(Role).where(Role.code == "admin"))
        assert role is not None
        permission = Permission(
            code="quota:manage",
            name="Manage quotas",
            description="Manage hard LLM budgets",
        )
        session.add(permission)
        await session.flush()
        session.add(RolePermission(role_id=role.id, permission_id=permission.id))
        await session.commit()


@pytest.mark.asyncio
async def test_usage_ledger_query_requires_audit_permission_and_never_returns_content(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    await _grant_audit_read(api_harness)
    tokens = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    async with api_harness.session_factory() as session:
        admin = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert admin is not None
        session.add_all(
            [
                LlmModelPrice(
                    provider="qwen",
                    model="qwen-plus",
                    input_micro_usd_per_million_tokens=1_000_000,
                    output_micro_usd_per_million_tokens=2_000_000,
                    active=True,
                ),
                LlmBudgetPolicy(
                    name="tenant budget",
                    tenant_key="default",
                    daily_token_limit=10_000,
                    monthly_token_limit=100_000,
                    daily_cost_limit_micro_usd=10_000,
                    monthly_cost_limit_micro_usd=100_000,
                    enabled=True,
                ),
            ]
        )
        await session.flush()
        usage = await LlmUsageGovernance().reserve(
            session,
            dimensions=LlmUsageDimensions(
                tenant_key="default",
                user_id=admin.id,
                api_key_id=None,
                knowledge_base_id=None,
                provider="qwen",
                model="qwen-plus",
                operation="chat.answer",
            ),
            idempotency_key="safe-ledger-api-test",
            estimated_input_tokens=100,
            maximum_output_tokens=100,
        )
        await LlmUsageGovernance().settle(
            session,
            usage_id=usage.id,
            input_tokens=50,
            output_tokens=25,
        )

        password = "No-ledger-permission-123!"
        unprivileged = User(
            email="no-ledger@example.com",
            password_hash=PasswordService().hash(password),
        )
        role = Role(code="no_ledger", name="No ledger")
        chat_permission = await session.scalar(
            select(Permission).where(Permission.code == "chat:query")
        )
        assert chat_permission is not None
        session.add_all([unprivileged, role])
        await session.flush()
        session.add_all(
            [
                UserRole(user_id=unprivileged.id, role_id=role.id),
                RolePermission(role_id=role.id, permission_id=chat_permission.id),
            ]
        )
        await session.commit()

    response = await api_harness.client.get(
        "/api/v1/llm/usage",
        headers=admin_headers,
        params={"provider": "qwen", "model": "qwen-plus", "limit": 10},
    )
    assert response.status_code == 200, response.text
    assert response.json()["items"][0]["actual_token_count"] == 75
    item_keys = set(response.json()["items"][0])
    assert not item_keys & {"prompt", "answer", "messages", "content", "idempotency_key"}

    login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "no-ledger@example.com", "password": password},
    )
    assert login.status_code == 200
    denied = await api_harness.client.get(
        "/api/v1/llm/usage",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_usage_ledger_cursor_is_stable_and_bounded(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    await _grant_audit_read(api_harness)
    tokens = await api_harness.login()
    response = await api_harness.client.get(
        "/api/v1/llm/usage",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        params={"limit": 101},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_budget_policy_management_is_permission_protected_and_validated(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    denied = await api_harness.client.post(
        "/api/v1/llm/budget-policies",
        headers=headers,
        json={"name": "tenant budget", "tenant_key": "default"},
    )
    assert denied.status_code == 403

    await _grant_quota_manage(api_harness)
    invalid = await api_harness.client.post(
        "/api/v1/llm/budget-policies",
        headers=headers,
        json={"name": "tenant budget", "tenant_key": "default"},
    )
    assert invalid.status_code == 422

    created = await api_harness.client.post(
        "/api/v1/llm/budget-policies",
        headers=headers,
        json={
            "name": "qwen tenant budget",
            "tenant_key": "default",
            "provider": "qwen",
            "model": "qwen-plus",
            "daily_token_limit": 5_000_000_000,
            "monthly_token_limit": 150_000_000_000,
            "daily_cost_limit_micro_usd": 2_000_000_000,
            "monthly_cost_limit_micro_usd": 60_000_000_000,
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["daily_token_limit"] == 5_000_000_000

    listed = await api_harness.client.get("/api/v1/llm/budget-policies", headers=headers)
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [created.json()["id"]]


@pytest.mark.asyncio
async def test_stale_egress_lease_reconciliation_requires_permission_attestation_and_audit(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    async with api_harness.session_factory() as session:
        admin = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert admin is not None
        session.add_all(
            [
                LlmModelPrice(
                    provider="qwen",
                    model="qwen-plus",
                    input_micro_usd_per_million_tokens=1_000_000,
                    output_micro_usd_per_million_tokens=2_000_000,
                    active=True,
                ),
                LlmBudgetPolicy(
                    name="reconciliation budget",
                    tenant_key="default",
                    daily_token_limit=10_000,
                    enabled=True,
                ),
            ]
        )
        await session.flush()
        usage = await LlmUsageGovernance().reserve(
            session,
            dimensions=LlmUsageDimensions(
                tenant_key="default",
                user_id=admin.id,
                api_key_id=None,
                knowledge_base_id=None,
                provider="qwen",
                model="qwen-plus",
                operation="chat.answer",
            ),
            idempotency_key="stale-lease-reconciliation",
            estimated_input_tokens=100,
            maximum_output_tokens=100,
        )
        await session.commit()
        usage_id = usage.id

    endpoint = f"/api/v1/llm/usage/{usage_id}/reconcile"
    denied = await api_harness.client.post(
        endpoint,
        headers=headers,
        json={
            "provider_egress_terminated": True,
            "reason": "Provider execution was independently confirmed stopped.",
        },
    )
    assert denied.status_code == 403

    await _grant_quota_manage(api_harness)
    invalid = await api_harness.client.post(
        endpoint,
        headers=headers,
        json={
            "provider_egress_terminated": False,
            "reason": "Provider execution status has not been verified.",
        },
    )
    assert invalid.status_code == 422

    reconciled = await api_harness.client.post(
        endpoint,
        headers=headers,
        json={
            "provider_egress_terminated": True,
            "reason": "Provider execution was independently confirmed stopped.",
        },
    )
    assert reconciled.status_code == 200, reconciled.text
    assert reconciled.json()["status"] == LlmUsageStatus.RELEASED
    assert reconciled.json()["error_code"] == "operator_reconciled_no_egress"

    async with api_harness.session_factory() as session:
        audit = await session.scalar(
            select(AuditLog).where(
                AuditLog.action == "llm.usage_reconciled",
                AuditLog.resource_id == str(usage_id),
            )
        )
        assert audit is not None
        assert audit.actor_id is not None
        assert audit.details["provider_egress_terminated"] is True
