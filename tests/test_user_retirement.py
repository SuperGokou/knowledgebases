from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select

import app.api.v1.routes.users as user_routes
from app.api.errors import ApiError
from app.db.models import (
    ApiKey,
    AuditLog,
    AuditResult,
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    RefreshToken,
    User,
    UserRole,
    UserStatus,
)
from app.services.api_keys import authenticate_api_key, generate_api_key
from app.services.chat_replay_authorization import (
    authorize_api_key_chat_snapshot,
    authorize_interactive_chat_snapshot,
)
from app.services.llm_egress_policy import external_llm_egress_allowed

pytest_plugins = ("test_integration_api",)


async def _authorization(api_harness: Any) -> tuple[dict[str, Any], dict[str, str]]:
    tokens = await api_harness.login()
    return tokens, {"Authorization": f"Bearer {tokens['access_token']}"}


async def _create_member(
    api_harness: Any,
    headers: dict[str, str],
    *,
    email: str,
    role_ids: list[str] | None = None,
) -> dict[str, Any]:
    response = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": email,
            "password": "Retirement-member-password-123!",
            "role_ids": role_ids or [],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
async def test_invalid_user_mutation_uuid_uses_the_normal_validation_contract(
    api_harness: Any,
) -> None:
    _, headers = await _authorization(api_harness)
    response = await api_harness.client.request(
        "DELETE",
        "/api/v1/users/not-a-uuid",
        headers=headers,
        json={"confirmation_email": "nobody@example.com"},
    )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "validation_error"


@pytest.mark.asyncio
async def test_user_retirement_is_idempotent_and_revokes_every_credential(api_harness: Any) -> None:
    _, headers = await _authorization(api_harness)
    role = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={
            "code": "retirement-target",
            "name": "Retirement target",
            "priority": -100,
            "permission_codes": ["file:read"],
            "limits": {},
        },
    )
    assert role.status_code == 201, role.text
    member = await _create_member(
        api_harness,
        headers,
        email="retirement-target@example.com",
        role_ids=[str(role.json()["id"])],
    )
    user_id = UUID(str(member["id"]))

    member_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={
            "username": "retirement-target@example.com",
            "password": "Retirement-member-password-123!",
        },
    )
    assert member_login.status_code == 200, member_login.text
    member_tokens: dict[str, Any] = member_login.json()

    cleartext_api_key, api_key_hash, api_key_prefix = generate_api_key()
    api_key_id = uuid4()
    api_key_family_id = uuid4()
    async with api_harness.session_factory() as session:
        actor = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert actor is not None
        session.add(
            ApiKey(
                id=api_key_id,
                user_id=user_id,
                created_by=actor.id,
                credential_family_id=api_key_family_id,
                name="Retirement credential",
                key_hash=api_key_hash,
                key_prefix=api_key_prefix,
                permission_codes=["file:read"],
                knowledge_base_ids=[],
                requests_per_minute=10,
            )
        )
        await session.commit()
        actor_id = actor.id

    async with api_harness.session_factory() as session:
        key_access = await authenticate_api_key(session, cleartext_api_key)
        assert key_access.api_key.user_id == user_id

    response = await api_harness.client.request(
        "DELETE",
        f"/api/v1/users/{user_id}",
        headers=headers,
        json={
            "confirmation_email": "retirement-target@example.com",
            "reason": "Employment ended",
        },
    )
    assert response.status_code == 204, response.text
    assert response.content == b""

    repeated = await api_harness.client.request(
        "DELETE",
        f"/api/v1/users/{user_id}",
        headers=headers,
        json={
            "confirmation_email": "retirement-target@example.com",
            "reason": "A repeated request must be side-effect free",
        },
    )
    assert repeated.status_code == 204, repeated.text

    async with api_harness.session_factory() as session:
        retired = await session.get(User, user_id)
        assert retired is not None
        assert retired.status is UserStatus.DISABLED
        assert retired.retired_at is not None
        assert retired.retired_by_id == actor_id
        assert retired.retirement_reason == "Employment ended"
        assert retired.token_version == 1
        assert retired.role_assignment_version == member["role_assignment_version"] + 1
        assert (
            await session.scalar(
                select(func.count()).select_from(UserRole).where(UserRole.user_id == user_id)
            )
            == 0
        )
        refresh_tokens = list(
            (
                await session.scalars(select(RefreshToken).where(RefreshToken.user_id == user_id))
            ).all()
        )
        assert refresh_tokens
        assert all(token.revoked_at is not None for token in refresh_tokens)
        api_keys = list(
            (await session.scalars(select(ApiKey).where(ApiKey.user_id == user_id))).all()
        )
        assert api_keys
        assert all(api_key.revoked_at is not None for api_key in api_keys)
        audits = list(
            (
                await session.scalars(
                    select(AuditLog).where(
                        AuditLog.action == "user.retired",
                        AuditLog.resource_id == str(user_id),
                    )
                )
            ).all()
        )
        assert len(audits) == 1
        assert audits[0].result is AuditResult.SUCCESS
        assert audits[0].details == {
            "reason": "Employment ended",
            "revoked_api_keys": 1,
            "revoked_refresh_tokens": 1,
            "removed_role_assignments": 1,
        }
        assert "password" not in str(audits[0].details).lower()
        assert "token" not in str(audits[0].details).lower().replace("refresh_tokens", "")

    async with api_harness.session_factory() as session:
        with pytest.raises(ApiError) as retired_key:
            await authenticate_api_key(session, cleartext_api_key)
        assert retired_key.value.status_code == 401
        assert retired_key.value.code == "invalid_api_key"

    unavailable_knowledge_base_id = uuid4()
    async with api_harness.session_factory() as session:
        with pytest.raises(ApiError) as bearer_chat:
            await authorize_interactive_chat_snapshot(
                session,
                user_id=user_id,
                expected_token_version=1,
                knowledge_base_id=unavailable_knowledge_base_id,
            )
        assert bearer_chat.value.status_code == 401
        assert bearer_chat.value.code == "inactive_user"
        await session.rollback()

    async with api_harness.session_factory() as session:
        with pytest.raises(ApiError) as api_key_chat:
            await authorize_api_key_chat_snapshot(
                session,
                api_key_id=api_key_id,
                credential_family_id=api_key_family_id,
                user_id=user_id,
                knowledge_base_id=unavailable_knowledge_base_id,
            )
        assert api_key_chat.value.status_code == 401
        assert api_key_chat.value.code == "inactive_user"
        await session.rollback()

    async with api_harness.session_factory() as session:
        assert not await external_llm_egress_allowed(
            session,
            user_id=user_id,
            knowledge_base_id=unavailable_knowledge_base_id,
            api_key_id=api_key_id,
            required_permission="chat:query",
            minimum_access=KnowledgeBaseAccessLevel.READER,
        )

    stale_access = await api_harness.client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {member_tokens['access_token']}"},
    )
    assert stale_access.status_code == 401, stale_access.text
    stale_refresh = await api_harness.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": member_tokens["refresh_token"]},
    )
    assert stale_refresh.status_code == 401, stale_refresh.text
    retired_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={
            "username": "retirement-target@example.com",
            "password": "Retirement-member-password-123!",
        },
    )
    assert retired_login.status_code == 401, retired_login.text

    listing = await api_harness.client.get(
        "/api/v1/users?search=retirement-target%40example.com",
        headers=headers,
    )
    assert listing.status_code == 200, listing.text
    listed = listing.json()[0]
    assert set(listed) == {
        "id",
        "email",
        "display_name",
        "status",
        "is_superuser",
        "role_assignment_version",
        "retired_at",
        "retired_by_id",
        "retirement_reason",
        "created_at",
        "updated_at",
        "role_ids",
    }
    assert listed["retired_at"] is not None
    assert listed["retired_by_id"] == str(actor_id)
    assert listed["retirement_reason"] == "Employment ended"


@pytest.mark.asyncio
async def test_user_retirement_denials_are_audited_without_partial_mutation(
    api_harness: Any,
) -> None:
    _, headers = await _authorization(api_harness)
    me = await api_harness.client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200, me.text
    actor_id = UUID(str(me.json()["id"]))

    self_denied = await api_harness.client.request(
        "DELETE",
        f"/api/v1/users/{actor_id}",
        headers=headers,
        json={"confirmation_email": "admin@example.com", "reason": "must be rejected"},
    )
    assert self_denied.status_code == 409, self_denied.text
    assert self_denied.json()["error"]["code"] == "self_retirement_forbidden"

    target = await _create_member(
        api_harness,
        headers,
        email="knowledge-owner-retirement@example.com",
    )
    target_id = UUID(str(target["id"]))
    async with api_harness.session_factory() as session:
        session.add(KnowledgeBase(owner_id=target_id, name="Ownership must transfer"))
        await session.commit()

    conflict = await api_harness.client.request(
        "DELETE",
        f"/api/v1/users/{target_id}",
        headers=headers,
        json={
            "confirmation_email": "knowledge-owner-retirement@example.com",
            "reason": "must remain atomic",
        },
    )
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["error"] == {
        "code": "user_ownership_conflict",
        "message": "Transfer owned knowledge bases before retiring this account",
        "details": {"references": {"owned_knowledge_bases": 1}},
    }

    async with api_harness.session_factory() as session:
        actor = await session.get(User, actor_id)
        target_user = await session.get(User, target_id)
        assert actor is not None and actor.retired_at is None
        assert target_user is not None
        assert target_user.retired_at is None
        assert target_user.status is UserStatus.ACTIVE
        assert target_user.token_version == 0
        audits = list(
            (
                await session.scalars(
                    select(AuditLog)
                    .where(
                        AuditLog.action == "user.retirement.denied",
                        AuditLog.resource_id.in_({str(actor_id), str(target_id)}),
                    )
                    .order_by(AuditLog.id)
                )
            ).all()
        )
        assert [(audit.resource_id, audit.result, audit.details) for audit in audits] == [
            (
                str(actor_id),
                AuditResult.DENIED,
                {"reason_code": "self_retirement_forbidden"},
            ),
            (
                str(target_id),
                AuditResult.DENIED,
                {
                    "reason_code": "user_ownership_conflict",
                    "references": {"owned_knowledge_bases": 1},
                },
            ),
        ]


@pytest.mark.asyncio
async def test_retirement_atomically_transfers_owned_knowledge_bases(
    api_harness: Any,
) -> None:
    _, headers = await _authorization(api_harness)
    target = await _create_member(
        api_harness,
        headers,
        email="owner-transfer-source@example.com",
    )
    replacement = await _create_member(
        api_harness,
        headers,
        email="owner-transfer-destination@example.com",
    )
    target_id = UUID(target["id"])
    replacement_id = UUID(replacement["id"])
    async with api_harness.session_factory() as session:
        actor = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert actor is not None
        actor.is_superuser = True
        knowledge_bases = [
            KnowledgeBase(owner_id=target_id, name="Transfer first"),
            KnowledgeBase(owner_id=target_id, name="Transfer second"),
        ]
        session.add_all(knowledge_bases)
        await session.commit()
        knowledge_base_ids = {item.id for item in knowledge_bases}

    response = await api_harness.client.request(
        "DELETE",
        f"/api/v1/users/{target_id}",
        headers=headers,
        json={
            "confirmation_email": "owner-transfer-source@example.com",
            "replacement_owner_id": str(replacement_id),
            "reason": "Atomic ownership handoff",
        },
    )

    assert response.status_code == 204, response.text
    async with api_harness.session_factory() as session:
        retired = await session.get(User, target_id)
        assert retired is not None and retired.retired_at is not None
        owners = set(
            (
                await session.scalars(
                    select(KnowledgeBase.owner_id).where(KnowledgeBase.id.in_(knowledge_base_ids))
                )
            ).all()
        )
        assert owners == {replacement_id}
        audit = await session.scalar(
            select(AuditLog).where(
                AuditLog.action == "user.retired",
                AuditLog.resource_id == str(target_id),
            )
        )
        assert audit is not None
        assert audit.details["transferred_knowledge_bases"] == 2
        assert audit.details["knowledge_base_owner_from"] == str(target_id)
        assert audit.details["knowledge_base_owner_to"] == str(replacement_id)
        assert set(audit.details["transferred_knowledge_base_ids"]) == {
            str(item) for item in knowledge_base_ids
        }
        assert audit.details["transferred_knowledge_base_ids_truncated"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("replacement_kind", ["missing", "target", "retired"])
async def test_retirement_rejects_invalid_replacement_owner_without_partial_transfer(
    api_harness: Any,
    replacement_kind: str,
) -> None:
    _, headers = await _authorization(api_harness)
    suffix = uuid4().hex[:10]
    target = await _create_member(
        api_harness,
        headers,
        email=f"invalid-transfer-source-{suffix}@example.com",
    )
    target_id = UUID(target["id"])
    replacement_id = uuid4()
    if replacement_kind == "target":
        replacement_id = target_id
    elif replacement_kind == "retired":
        replacement = await _create_member(
            api_harness,
            headers,
            email=f"invalid-transfer-retired-{suffix}@example.com",
        )
        replacement_id = UUID(replacement["id"])
        async with api_harness.session_factory() as session:
            user = await session.get(User, replacement_id)
            assert user is not None
            user.status = UserStatus.DISABLED
            user.retired_at = user.created_at
            user.retired_by_id = UUID(target["id"])
            await session.commit()
    async with api_harness.session_factory() as session:
        knowledge_base = KnowledgeBase(owner_id=target_id, name="Must stay with source")
        session.add(knowledge_base)
        await session.commit()
        knowledge_base_id = knowledge_base.id

    response = await api_harness.client.request(
        "DELETE",
        f"/api/v1/users/{target_id}",
        headers=headers,
        json={
            "confirmation_email": f"invalid-transfer-source-{suffix}@example.com",
            "replacement_owner_id": str(replacement_id),
        },
    )

    assert response.status_code in {404, 409}, response.text
    assert response.json()["error"]["code"] in {
        "replacement_owner_invalid",
        "replacement_owner_not_found",
    }
    async with api_harness.session_factory() as session:
        source = await session.get(User, target_id)
        knowledge_base = await session.get(KnowledgeBase, knowledge_base_id)
        assert source is not None and source.retired_at is None
        assert knowledge_base is not None and knowledge_base.owner_id == target_id


@pytest.mark.asyncio
async def test_owner_transfer_guard_runs_before_any_owner_mutation(
    api_harness: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, headers = await _authorization(api_harness)
    target = await _create_member(
        api_harness,
        headers,
        email="guarded-transfer-source@example.com",
    )
    replacement = await _create_member(
        api_harness,
        headers,
        email="guarded-transfer-destination@example.com",
    )
    target_id = UUID(target["id"])
    replacement_id = UUID(replacement["id"])
    async with api_harness.session_factory() as session:
        actor = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert actor is not None
        actor.is_superuser = True
        knowledge_base = KnowledgeBase(owner_id=target_id, name="Guarded handoff")
        session.add(knowledge_base)
        await session.commit()
        knowledge_base_id = knowledge_base.id

    async def deny_before_transfer(session: Any, *_args: Any, **_kwargs: Any) -> None:
        current_owner = await session.scalar(
            select(KnowledgeBase.owner_id).where(KnowledgeBase.id == knowledge_base_id)
        )
        assert current_owner == target_id
        await session.commit()
        raise ApiError(
            status_code=409,
            code="external_llm_processing_in_progress",
            message="busy",
        )

    monkeypatch.setattr(
        user_routes,
        "deny_if_active_external_llm_egress",
        deny_before_transfer,
    )
    response = await api_harness.client.request(
        "DELETE",
        f"/api/v1/users/{target_id}",
        headers=headers,
        json={
            "confirmation_email": "guarded-transfer-source@example.com",
            "replacement_owner_id": str(replacement_id),
        },
    )

    assert response.status_code == 409, response.text
    async with api_harness.session_factory() as session:
        source = await session.get(User, target_id)
        knowledge_base = await session.get(KnowledgeBase, knowledge_base_id)
        assert source is not None and source.retired_at is None
        assert knowledge_base is not None and knowledge_base.owner_id == target_id


@pytest.mark.asyncio
async def test_last_superuser_status_and_role_mutations_are_denied_and_audited(
    api_harness: Any,
) -> None:
    _, headers = await _authorization(api_harness)
    async with api_harness.session_factory() as session:
        actor = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert actor is not None
        actor.is_superuser = True
        await session.commit()
        actor_id = actor.id
        role_assignment_version = actor.role_assignment_version

    status_denied = await api_harness.client.patch(
        f"/api/v1/users/{actor_id}",
        headers=headers,
        json={"status": "disabled"},
    )
    assert status_denied.status_code == 409, status_denied.text
    assert status_denied.json()["error"]["code"] == "last_superuser_protected"

    roles_denied = await api_harness.client.put(
        f"/api/v1/users/{actor_id}/roles",
        headers=headers,
        json={"expected_version": role_assignment_version, "role_ids": []},
    )
    assert roles_denied.status_code == 409, roles_denied.text
    assert roles_denied.json()["error"]["code"] == "last_superuser_protected"

    async with api_harness.session_factory() as session:
        actor = await session.get(User, actor_id)
        assert actor is not None
        assert actor.status is UserStatus.ACTIVE
        assert actor.role_assignment_version == role_assignment_version
        assert (
            await session.scalar(
                select(func.count()).select_from(UserRole).where(UserRole.user_id == actor_id)
            )
            == 1
        )
        denied = list(
            (
                await session.scalars(
                    select(AuditLog)
                    .where(
                        AuditLog.resource_id == str(actor_id),
                        AuditLog.result == AuditResult.DENIED,
                    )
                    .order_by(AuditLog.id)
                )
            ).all()
        )
        assert [(item.action, item.details) for item in denied] == [
            (
                "user.status_change.denied",
                {"reason_code": "last_superuser_protected"},
            ),
            (
                "user.roles_replace.denied",
                {"reason_code": "last_superuser_protected"},
            ),
        ]
