from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import select

from app.core.security import PasswordService
from app.db.models import AuditLog, KnowledgeBase, RefreshToken, User
from app.main import app
from app.schemas.users import UserPasswordReset

pytest_plugins = ("test_integration_api",)


def test_openapi_exposes_secret_minimized_password_reset_contract() -> None:
    schema = app.openapi()
    operation = schema["paths"]["/api/v1/users/{user_id}/password"]["put"]
    self_operation = schema["paths"]["/api/v1/users/me/password"]["put"]
    payload_ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    payload_name = payload_ref.rsplit("/", 1)[-1]
    payload = schema["components"]["schemas"][payload_name]

    assert operation["responses"]["204"] == {"description": "Successful Response"}
    assert self_operation["responses"]["204"] == {"description": "Successful Response"}
    assert (
        self_operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        == payload_ref
    )
    assert payload["required"] == ["new_password"]
    assert payload["additionalProperties"] is False
    assert set(payload["properties"]) == {"current_password", "new_password"}
    assert payload["properties"]["current_password"]["writeOnly"] is True
    assert payload["properties"]["new_password"]["minLength"] == 12
    assert payload["properties"]["new_password"]["maxLength"] == 256
    assert payload["properties"]["new_password"]["writeOnly"] is True


def test_password_reset_schema_masks_both_secrets_in_diagnostics() -> None:
    current_password = "Current-diagnostic-password-123!"
    new_password = "New-diagnostic-password-456!"
    payload = UserPasswordReset(
        current_password=current_password,
        new_password=new_password,
    )

    diagnostics = f"{payload!r} {payload.model_dump_json()}"
    assert current_password not in diagnostics
    assert new_password not in diagnostics


async def _authorization(api_harness: Any) -> tuple[dict[str, Any], dict[str, str]]:
    tokens = await api_harness.login()
    return tokens, {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.mark.asyncio
async def test_ordinary_authenticated_user_changes_own_password_through_me_endpoint(
    api_harness: Any,
) -> None:
    _, manager_headers = await _authorization(api_harness)
    old_password = "Ordinary-current-123!"
    new_password = "Ordinary-replaced-456!"
    created = await api_harness.client.post(
        "/api/v1/users",
        headers=manager_headers,
        json={
            "email": "ordinary-password-change@example.com",
            "password": old_password,
            "role_ids": [],
        },
    )
    assert created.status_code == 201, created.text
    user_id = UUID(created.json()["id"])

    login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "ordinary-password-change@example.com", "password": old_password},
    )
    assert login.status_code == 200, login.text
    tokens: dict[str, Any] = login.json()
    user_headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    member_management = await api_harness.client.get("/api/v1/users", headers=user_headers)
    assert member_management.status_code == 403, member_management.text
    assert member_management.json()["error"]["code"] == "permission_denied"

    missing_proof = await api_harness.client.put(
        "/api/v1/users/me/password",
        headers=user_headers,
        json={"new_password": new_password},
    )
    assert missing_proof.status_code == 422, missing_proof.text
    assert missing_proof.json()["error"]["code"] == "current_password_required"

    wrong_proof = await api_harness.client.put(
        "/api/v1/users/me/password",
        headers=user_headers,
        json={
            "current_password": "Wrong-current-123!",
            "new_password": new_password,
        },
    )
    assert wrong_proof.status_code == 401, wrong_proof.text
    assert wrong_proof.json()["error"]["code"] == "invalid_current_password"

    changed = await api_harness.client.put(
        "/api/v1/users/me/password",
        headers=user_headers,
        json={"current_password": old_password, "new_password": new_password},
    )
    assert changed.status_code == 204, changed.text
    assert changed.headers["cache-control"] == "no-store"

    async with api_harness.session_factory() as session:
        user = await session.get(User, user_id)
        assert user is not None
        assert user.token_version == 1
        assert PasswordService().verify(new_password, user.password_hash)
        refresh_rows = list(
            (
                await session.scalars(select(RefreshToken).where(RefreshToken.user_id == user_id))
            ).all()
        )
        assert refresh_rows
        assert all(row.revoked_at is not None for row in refresh_rows)

    stale_access = await api_harness.client.get("/api/v1/auth/me", headers=user_headers)
    assert stale_access.status_code == 401, stale_access.text
    stale_refresh = await api_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert stale_refresh.status_code == 401, stale_refresh.text
    old_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "ordinary-password-change@example.com", "password": old_password},
    )
    assert old_login.status_code == 401, old_login.text
    new_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "ordinary-password-change@example.com", "password": new_password},
    )
    assert new_login.status_code == 200, new_login.text


@pytest.mark.asyncio
async def test_self_password_change_has_a_low_frequency_account_limiter(
    api_harness: Any,
) -> None:
    _, manager_headers = await _authorization(api_harness)
    password = "Rate-limited-current-123!"
    created = await api_harness.client.post(
        "/api/v1/users",
        headers=manager_headers,
        json={
            "email": "password-rate-limit@example.com",
            "password": password,
            "role_ids": [],
        },
    )
    assert created.status_code == 201, created.text
    login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "password-rate-limit@example.com", "password": password},
    )
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    for attempt in range(5):
        rejected = await api_harness.client.put(
            "/api/v1/users/me/password",
            headers=headers,
            json={
                "current_password": f"Wrong-current-{attempt}-123!",
                "new_password": "Replacement-password-456!",
            },
        )
        assert rejected.status_code == 401, rejected.text

    limited = await api_harness.client.put(
        "/api/v1/users/me/password",
        headers=headers,
        json={
            "current_password": password,
            "new_password": "Replacement-password-456!",
        },
    )
    assert limited.status_code == 429, limited.text
    assert limited.json()["error"]["code"] == "rate_limit_exceeded"
    assert int(limited.headers["retry-after"]) >= 1


@pytest.mark.asyncio
async def test_manager_cannot_bypass_self_change_limiter_through_the_admin_route(
    api_harness: Any,
) -> None:
    _, headers = await _authorization(api_harness)
    me = await api_harness.client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200, me.text
    user_id = str(me.json()["id"])

    for attempt in range(5):
        rejected = await api_harness.client.put(
            "/api/v1/users/me/password",
            headers=headers,
            json={
                "current_password": f"Wrong-manager-current-{attempt}-123!",
                "new_password": "Replacement-password-456!",
            },
        )
        assert rejected.status_code == 401, rejected.text

    bypass = await api_harness.client.put(
        f"/api/v1/users/{user_id}/password",
        headers=headers,
        json={
            "current_password": "Admin-password-123!",
            "new_password": "Replacement-password-456!",
        },
    )
    assert bypass.status_code == 429, bypass.text
    assert bypass.json()["error"]["code"] == "rate_limit_exceeded"


@pytest.mark.asyncio
async def test_self_password_change_fails_closed_when_its_redis_limiter_is_unavailable(
    api_harness: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, manager_headers = await _authorization(api_harness)
    password = "Redis-failure-current-123!"
    created = await api_harness.client.post(
        "/api/v1/users",
        headers=manager_headers,
        json={
            "email": "password-redis-failure@example.com",
            "password": password,
            "role_ids": [],
        },
    )
    assert created.status_code == 201, created.text
    login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "password-redis-failure@example.com", "password": password},
    )
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    original_eval = api_harness.redis.eval

    async def fail_only_password_change(
        script: str,
        keys: int,
        key: str,
        ttl_ms: int,
    ) -> list[int]:
        if key.startswith("rate:password-change:user:"):
            raise ConnectionError("password-change Redis unavailable")
        return await original_eval(script, keys, key, ttl_ms)

    monkeypatch.setattr(api_harness.redis, "eval", fail_only_password_change)
    failed = await api_harness.client.put(
        "/api/v1/users/me/password",
        headers=headers,
        json={
            "current_password": password,
            "new_password": "Replacement-password-456!",
        },
    )
    assert failed.status_code == 503, failed.text
    assert failed.json()["error"]["code"] == "rate_limiter_unavailable"

    unchanged = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "password-redis-failure@example.com", "password": password},
    )
    assert unchanged.status_code == 200, unchanged.text


@pytest.mark.asyncio
async def test_self_password_change_fails_closed_when_effective_role_limiter_is_unavailable(
    api_harness: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, headers = await _authorization(api_harness)
    original_eval = api_harness.redis.eval

    async def fail_only_effective_role_limit(
        script: str,
        keys: int,
        key: str,
        ttl_ms: int,
    ) -> list[int]:
        if key.startswith("rate:user:"):
            raise ConnectionError("effective role limiter unavailable")
        return await original_eval(script, keys, key, ttl_ms)

    monkeypatch.setattr(api_harness.redis, "eval", fail_only_effective_role_limit)
    failed = await api_harness.client.put(
        "/api/v1/users/me/password",
        headers=headers,
        json={
            "current_password": "Admin-password-123!",
            "new_password": "Replacement-password-456!",
        },
    )
    assert failed.status_code == 503, failed.text
    assert failed.json()["error"]["code"] == "rate_limiter_unavailable"


@pytest.mark.asyncio
async def test_admin_password_reset_revokes_sessions_and_never_audits_secret(
    api_harness: Any,
) -> None:
    _, headers = await _authorization(api_harness)
    async with api_harness.session_factory() as session:
        actor = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert actor is not None
        actor.is_superuser = True
        await session.commit()

    old_password = "Old-target-password-123!"
    new_password = "New-target-password-456!"
    created = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "password-target@example.com",
            "password": old_password,
            "role_ids": [],
        },
    )
    assert created.status_code == 201, created.text
    user_id = str(created.json()["id"])
    user_uuid = UUID(user_id)

    target_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "password-target@example.com", "password": old_password},
    )
    assert target_login.status_code == 200, target_login.text
    target_tokens: dict[str, Any] = target_login.json()

    reset = await api_harness.client.put(
        f"/api/v1/users/{user_id}/password",
        headers=headers,
        json={"new_password": new_password},
    )
    assert reset.status_code == 204, reset.text
    assert reset.content == b""
    assert reset.headers["cache-control"] == "no-store"

    async with api_harness.session_factory() as session:
        user = await session.get(User, user_uuid)
        assert user is not None
        assert user.token_version == 1
        assert PasswordService().verify(new_password, user.password_hash)
        assert not PasswordService().verify(old_password, user.password_hash)
        refresh_rows = list(
            (
                await session.scalars(select(RefreshToken).where(RefreshToken.user_id == user_uuid))
            ).all()
        )
        audits = list(
            (
                await session.scalars(
                    select(AuditLog).where(
                        AuditLog.action == "user.password.reset",
                        AuditLog.resource_id == user_id,
                    )
                )
            ).all()
        )

    assert refresh_rows
    assert all(row.revoked_at is not None for row in refresh_rows)
    assert len(audits) == 1
    assert audits[0].details == {
        "from_token_version": 0,
        "revoked_refresh_tokens": 1,
        "to_token_version": 1,
    }
    serialized_audit = str(audits[0].details).lower()
    assert old_password.lower() not in serialized_audit
    assert new_password.lower() not in serialized_audit
    assert "password_hash" not in serialized_audit

    stale_access = await api_harness.client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {target_tokens['access_token']}"},
    )
    assert stale_access.status_code == 401, stale_access.text
    stale_refresh = await api_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": target_tokens["refresh_token"]},
    )
    assert stale_refresh.status_code == 401, stale_refresh.text
    old_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "password-target@example.com", "password": old_password},
    )
    assert old_login.status_code == 401, old_login.text
    new_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "password-target@example.com", "password": new_password},
    )
    assert new_login.status_code == 200, new_login.text


@pytest.mark.asyncio
async def test_password_reset_rejects_weak_or_extra_secret_fields(api_harness: Any) -> None:
    _, headers = await _authorization(api_harness)
    weak_create = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "weak-create@example.com",
            "password": "abcdefghijkl",
            "role_ids": [],
        },
    )
    assert weak_create.status_code == 422, weak_create.text

    created = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "password-validation@example.com",
            "password": "Initial-password-123!",
            "role_ids": [],
        },
    )
    assert created.status_code == 201, created.text
    user_id = str(created.json()["id"])

    weak = await api_harness.client.put(
        f"/api/v1/users/{user_id}/password",
        headers=headers,
        json={"new_password": "abcdefghijkl"},
    )
    assert weak.status_code == 422, weak.text

    obsolete_old_password_field = await api_harness.client.put(
        f"/api/v1/users/{user_id}/password",
        headers=headers,
        json={
            "new_password": "Replacement-password-456!",
            "old_password": "must-not-be-accepted-or-logged",
        },
    )
    assert obsolete_old_password_field.status_code == 422, obsolete_old_password_field.text

    async with api_harness.session_factory() as session:
        actor = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert actor is not None
        actor.is_superuser = True
        await session.commit()
    target_current_password = await api_harness.client.put(
        f"/api/v1/users/{user_id}/password",
        headers=headers,
        json={
            "current_password": "Initial-password-123!",
            "new_password": "Replacement-password-456!",
        },
    )
    assert target_current_password.status_code == 422, target_current_password.text
    assert target_current_password.json()["error"]["code"] == "current_password_not_allowed"
    original_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={
            "username": "password-validation@example.com",
            "password": "Initial-password-123!",
        },
    )
    assert original_login.status_code == 200, original_login.text


@pytest.mark.asyncio
async def test_non_superuser_with_user_manage_cannot_reset_knowledge_base_owner_password(
    api_harness: Any,
) -> None:
    _, manager_headers = await _authorization(api_harness)
    old_password = "Owner-current-password-123!"
    replacement = "Owner-hijacked-password-456!"
    created = await api_harness.client.post(
        "/api/v1/users",
        headers=manager_headers,
        json={
            "email": "knowledge-owner@example.com",
            "password": old_password,
            "role_ids": [],
        },
    )
    assert created.status_code == 201, created.text
    owner_id = UUID(created.json()["id"])
    async with api_harness.session_factory() as session:
        session.add(KnowledgeBase(owner_id=owner_id, name="Protected owner knowledge"))
        await session.commit()

    denied = await api_harness.client.put(
        f"/api/v1/users/{owner_id}/password",
        headers=manager_headers,
        json={"new_password": replacement},
    )
    assert denied.status_code == 403, denied.text
    assert denied.json()["error"]["code"] == "superuser_required"

    old_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "knowledge-owner@example.com", "password": old_password},
    )
    assert old_login.status_code == 200, old_login.text
    replacement_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "knowledge-owner@example.com", "password": replacement},
    )
    assert replacement_login.status_code == 401, replacement_login.text

    async with api_harness.session_factory() as session:
        successful_resets = list(
            (
                await session.scalars(
                    select(AuditLog).where(
                        AuditLog.action == "user.password.reset",
                        AuditLog.resource_id == str(owner_id),
                    )
                )
            ).all()
        )
    assert successful_resets == []


@pytest.mark.asyncio
async def test_manager_can_reset_own_password_without_changing_admin_status_or_roles(
    api_harness: Any,
) -> None:
    tokens, headers = await _authorization(api_harness)
    me = await api_harness.client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200, me.text
    user_id = str(me.json()["id"])

    async with api_harness.session_factory() as session:
        before = await session.get(User, UUID(user_id))
        assert before is not None
        before_status = before.status
        before_superuser = before.is_superuser
        before_roles = list(before.role_assignment_version for _ in [0])

    missing_current = await api_harness.client.put(
        f"/api/v1/users/{user_id}/password",
        headers=headers,
        json={"new_password": "Self-reset-password-789!"},
    )
    assert missing_current.status_code == 422, missing_current.text
    assert missing_current.json()["error"]["code"] == "current_password_required"

    wrong_current = await api_harness.client.put(
        f"/api/v1/users/{user_id}/password",
        headers=headers,
        json={
            "current_password": "Wrong-current-password-123!",
            "new_password": "Self-reset-password-789!",
        },
    )
    assert wrong_current.status_code == 401, wrong_current.text
    assert wrong_current.json()["error"]["code"] == "invalid_current_password"
    still_valid = await api_harness.client.get("/api/v1/auth/me", headers=headers)
    assert still_valid.status_code == 200, still_valid.text

    reset = await api_harness.client.put(
        f"/api/v1/users/{user_id}/password",
        headers=headers,
        json={
            "current_password": "Admin-password-123!",
            "new_password": "Self-reset-password-789!",
        },
    )
    assert reset.status_code == 204, reset.text

    stale_access = await api_harness.client.get("/api/v1/auth/me", headers=headers)
    assert stale_access.status_code == 401, stale_access.text
    stale_refresh = await api_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert stale_refresh.status_code == 401, stale_refresh.text
    relogin = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "admin@example.com", "password": "Self-reset-password-789!"},
    )
    assert relogin.status_code == 200, relogin.text

    async with api_harness.session_factory() as session:
        after = await session.get(User, UUID(user_id))
        assert after is not None
        assert after.status is before_status
        assert after.is_superuser is before_superuser
        assert after.role_assignment_version == before_roles[0]
