from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import event, select
from sqlalchemy.dialects import postgresql

import app.api.v1.routes.knowledge_bases as knowledge_base_routes
import app.api.v1.routes.users as user_routes
from app.core.config import get_settings
from app.core.security import PasswordService
from app.db.models import (
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.main import app
from app.services.rbac_mutation import (
    acquire_rbac_mutation_lock,
    lock_role_union,
    locked_active_actor_roles_statement,
    locked_roles_statement,
    locked_users_statement,
)

pytest_plugins = ("test_integration_api",)


async def _delegated_role_admin_headers(
    api_harness,
    *,
    priority: int = 100,
) -> dict[str, str]:
    actor_id = uuid4()
    email = f"delegated-role-admin-{actor_id.hex}@example.com"
    password = "Delegated-role-admin-password-123!"
    required_codes = {"role:manage", "role:assign", "user:manage"}
    async with api_harness.session_factory() as session:
        permissions = list(
            (
                await session.scalars(select(Permission).where(Permission.code.in_(required_codes)))
            ).all()
        )
        assert {permission.code for permission in permissions} == required_codes
        actor_role = Role(
            code=f"delegated_role_admin_{actor_id.hex}",
            name="Delegated role administrator",
            priority=priority,
        )
        actor = User(
            id=actor_id,
            email=email,
            password_hash=PasswordService().hash(password),
            is_superuser=False,
        )
        session.add_all([actor_role, actor])
        await session.flush()
        session.add_all(
            [
                *[
                    RolePermission(role_id=actor_role.id, permission_id=permission.id)
                    for permission in permissions
                ],
                UserRole(user_id=actor.id, role_id=actor_role.id, assigned_by=actor.id),
            ]
        )
        await session.commit()

    login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": email, "password": password},
    )
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


@pytest.mark.asyncio
async def test_invalid_api_keys_are_source_limited_before_database_lookup(api_harness) -> None:
    settings = get_settings().model_copy(update={"api_key_auth_attempts_per_minute": 2})
    app.dependency_overrides[get_settings] = lambda: settings
    engine = api_harness.session_factory.kw["bind"].sync_engine
    statements: list[str] = []

    def capture(_conn, _cursor, statement, _parameters, _context, _executemany) -> None:
        statements.append(str(statement))

    event.listen(engine, "before_cursor_execute", capture)
    try:
        responses = [
            await api_harness.client.post(
                f"/api/v1/public/knowledge-bases/{uuid4()}/search",
                headers={"X-API-Key": f"kb_live_{index:040d}"},
                json={"query": "bounded validation", "limit": 1},
            )
            for index in range(3)
        ]
    finally:
        event.remove(engine, "before_cursor_execute", capture)
        app.dependency_overrides.pop(get_settings, None)

    assert [response.status_code for response in responses] == [401, 401, 429]
    api_key_queries = [item for item in statements if "api_keys" in item.lower()]
    assert len(api_key_queries) == 2
    source_buckets = {
        key: value
        for key, value in api_harness.redis.counters.items()
        if key.startswith("rate:api-key-auth:source:")
    }
    assert list(source_buckets.values()) == [3]


@pytest.mark.asyncio
async def test_authenticated_precheck_stops_denials_before_database_work(api_harness) -> None:
    user_id = uuid4()
    async with api_harness.session_factory() as session:
        session.add(
            User(
                id=user_id,
                email="limited-security@example.com",
                password_hash=PasswordService().hash("Limited-password-123!"),
            )
        )
        await session.commit()

    login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={
            "username": "limited-security@example.com",
            "password": "Limited-password-123!",
        },
    )
    assert login.status_code == 200
    settings = get_settings().model_copy(
        update={
            "authenticated_precheck_requests_per_minute": 1,
            "default_requests_per_minute": 1_000,
        }
    )
    app.dependency_overrides[get_settings] = lambda: settings
    engine = api_harness.session_factory.kw["bind"].sync_engine
    statements: list[str] = []

    def capture(_conn, _cursor, statement, _parameters, _context, _executemany) -> None:
        statements.append(str(statement))

    event.listen(engine, "before_cursor_execute", capture)
    try:
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        first = await api_harness.client.get("/api/v1/users", headers=headers)
        statements_after_first = len(statements)
        second = await api_harness.client.get("/api/v1/users", headers=headers)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
        app.dependency_overrides.pop(get_settings, None)

    assert first.status_code == 403
    assert second.status_code == 429
    assert len(statements) == statements_after_first
    assert api_harness.redis.counters[f"rate:preauth:user:{user_id}"] == 2
    assert api_harness.redis.counters[f"rate:user:{user_id}"] == 1


@pytest.mark.asyncio
async def test_api_key_scope_denials_consume_the_key_rate_limit(api_harness) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases", headers=headers, json={"name": "Scope limit KB"}
    )
    assert knowledge_base.status_code == 201
    knowledge_base_id = knowledge_base.json()["id"]
    created = await api_harness.client.post(
        "/api/v1/api-keys",
        headers=headers,
        json={
            "name": "Read-only key",
            "permission_codes": ["knowledge:read"],
            "knowledge_base_ids": [knowledge_base_id],
            "requests_per_minute": 1,
        },
    )
    assert created.status_code == 201
    api_key_headers = {
        "X-API-Key": created.json()["key"],
        "Idempotency-Key": "scope-denial-rate-limit",
    }

    first = await api_harness.client.post(
        "/api/v1/public/chat/query",
        headers=api_key_headers,
        json={"knowledge_base_id": knowledge_base_id, "message": "hello"},
    )
    second = await api_harness.client.post(
        "/api/v1/public/chat/query",
        headers=api_key_headers,
        json={"knowledge_base_id": knowledge_base_id, "message": "hello"},
    )

    assert first.status_code == 403
    assert first.json()["error"]["code"] == "api_key_scope_denied"
    assert second.status_code == 429
    credential_family_id = created.json()["credential_family_id"]
    assert api_harness.redis.counters[f"rate:api-key-family:{credential_family_id}"] == 2


def test_role_assignment_statement_locks_selected_roles_on_postgresql() -> None:
    statement = locked_roles_statement({uuid4(), uuid4()})
    compiled = str(statement.compile(dialect=postgresql.dialect())).upper()
    assert "ORDER BY ROLES.ID" in compiled
    assert "FOR NO KEY UPDATE" in compiled


def test_role_grant_mutation_uses_the_shared_rbac_lock_domain() -> None:
    assert knowledge_base_routes.acquire_rbac_mutation_lock is acquire_rbac_mutation_lock
    assert knowledge_base_routes.lock_role_union is lock_role_union


def test_role_assignment_refresh_locks_actor_user_and_roles_on_postgresql() -> None:
    actor_id = uuid4()
    user_sql = str(locked_users_statement({actor_id}).compile(dialect=postgresql.dialect())).upper()
    role_sql = str(
        locked_active_actor_roles_statement(actor_id).compile(dialect=postgresql.dialect())
    ).upper()
    assert "FOR UPDATE" in user_sql
    assert "ORDER BY ROLES.ID" in role_sql
    assert "FOR NO KEY UPDATE" in role_sql
    assert "OF ROLES" in role_sql


@pytest.mark.asyncio
async def test_role_assignment_kb_containment_uses_the_acl_coordination_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert hasattr(user_routes, "_ensure_kb_grants_delegable")
    calls: list[dict[str, object]] = []

    async def fake_require(*_args, **kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(user_routes, "require_knowledge_base_access", fake_require)
    await user_routes._ensure_kb_grants_delegable(  # type: ignore[attr-defined]
        object(),
        object(),
        [(uuid4(), KnowledgeBaseAccessLevel.READER)],
    )

    assert calls == [
        {
            "minimum": KnowledgeBaseAccessLevel.READER,
            "lock": True,
        }
    ]


@pytest.mark.asyncio
async def test_delegated_admin_cannot_mutate_an_equal_priority_role(api_harness) -> None:
    actor_id = uuid4()
    async with api_harness.session_factory() as session:
        role_manage = await session.scalar(
            select(Permission).where(Permission.code == "role:manage")
        )
        assert role_manage is not None
        actor_role = Role(code="peer_actor", name="Peer actor", priority=100)
        target_role = Role(code="peer_target", name="Peer target", priority=100)
        actor = User(
            id=actor_id,
            email="peer-actor@example.com",
            password_hash=PasswordService().hash("Peer-password-123!"),
        )
        session.add_all([actor_role, target_role, actor])
        await session.flush()
        session.add_all(
            [
                RolePermission(role_id=actor_role.id, permission_id=role_manage.id),
                UserRole(user_id=actor.id, role_id=actor_role.id, assigned_by=actor.id),
            ]
        )
        await session.commit()
        target_role_id = target_role.id

    login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "peer-actor@example.com", "password": "Peer-password-123!"},
    )
    assert login.status_code == 200
    response = await api_harness.client.put(
        f"/api/v1/roles/{target_role_id}/policy",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        json={"expected_version": 1, "permission_codes": [], "limits": {}},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "role_escalation_denied"


@pytest.mark.asyncio
async def test_delegated_admin_cannot_create_an_equal_priority_role(api_harness) -> None:
    headers = await _delegated_role_admin_headers(api_harness)
    response = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={
            "code": "equal-created-role",
            "name": "Equal created role",
            "priority": 100,
            "permission_codes": [],
            "limits": {},
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "role_escalation_denied"


@pytest.mark.asyncio
async def test_delegated_admin_cannot_raise_a_role_to_equal_priority(api_harness) -> None:
    headers = await _delegated_role_admin_headers(api_harness)
    created = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={
            "code": "raise-to-equal-role",
            "name": "Raise to equal role",
            "priority": 98,
            "permission_codes": [],
            "limits": {},
        },
    )
    assert created.status_code == 201, created.text

    response = await api_harness.client.patch(
        f"/api/v1/roles/{created.json()['id']}",
        headers=headers,
        json={"expected_version": created.json()["policy_version"], "priority": 100},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "role_escalation_denied"


@pytest.mark.asyncio
async def test_delegated_admin_cannot_assign_an_equal_priority_role(api_harness) -> None:
    async with api_harness.session_factory() as session:
        role = Role(code="equal-assignment-role", name="Equal assignment role", priority=100)
        session.add(role)
        await session.commit()
        equal_role_id = role.id

    headers = await _delegated_role_admin_headers(api_harness)
    create_with_role = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "equal-create-assignment@example.com",
            "password": "Equal-create-password-123!",
            "role_ids": [str(equal_role_id)],
        },
    )
    assert create_with_role.status_code == 403
    assert create_with_role.json()["error"]["code"] == "role_escalation_denied"

    target = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "equal-replace-assignment@example.com",
            "password": "Equal-replace-password-123!",
            "role_ids": [],
        },
    )
    assert target.status_code == 201, target.text
    replace_roles = await api_harness.client.put(
        f"/api/v1/users/{target.json()['id']}/roles",
        headers=headers,
        json={
            "expected_version": target.json()["role_assignment_version"],
            "role_ids": [str(equal_role_id)],
        },
    )

    assert replace_roles.status_code == 403
    assert replace_roles.json()["error"]["code"] == "role_escalation_denied"
    async with api_harness.session_factory() as session:
        assert (
            await session.scalar(
                select(User.id).where(User.email == "equal-create-assignment@example.com")
            )
            is None
        )


@pytest.mark.asyncio
async def test_delegated_admin_can_create_raise_and_assign_below_priority(api_harness) -> None:
    headers = await _delegated_role_admin_headers(api_harness)
    created = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={
            "code": "below-priority-role",
            "name": "Below priority role",
            "priority": 98,
            "permission_codes": [],
            "limits": {},
        },
    )
    assert created.status_code == 201, created.text

    raised = await api_harness.client.patch(
        f"/api/v1/roles/{created.json()['id']}",
        headers=headers,
        json={"expected_version": created.json()["policy_version"], "priority": 99},
    )
    assert raised.status_code == 200, raised.text
    assigned = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "below-priority-assignment@example.com",
            "password": "Below-priority-password-123!",
            "role_ids": [created.json()["id"]],
        },
    )

    assert assigned.status_code == 201, assigned.text
    assert assigned.json()["role_ids"] == [created.json()["id"]]


@pytest.mark.asyncio
async def test_superuser_can_create_raise_and_assign_at_equal_priority(api_harness) -> None:
    async with api_harness.session_factory() as session:
        administrator = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert administrator is not None
        administrator.is_superuser = True
        await session.commit()

    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    equal_role = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={
            "code": "superuser-equal-role",
            "name": "Superuser equal role",
            "priority": 10000,
            "permission_codes": [],
            "limits": {},
        },
    )
    assert equal_role.status_code == 201, equal_role.text
    lower_role = await api_harness.client.post(
        "/api/v1/roles",
        headers=headers,
        json={
            "code": "superuser-raised-role",
            "name": "Superuser raised role",
            "priority": 9998,
            "permission_codes": [],
            "limits": {},
        },
    )
    assert lower_role.status_code == 201, lower_role.text
    raised_role = await api_harness.client.patch(
        f"/api/v1/roles/{lower_role.json()['id']}",
        headers=headers,
        json={"expected_version": lower_role.json()["policy_version"], "priority": 10000},
    )
    assert raised_role.status_code == 200, raised_role.text
    assigned = await api_harness.client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "superuser-equal-assignment@example.com",
            "password": "Superuser-equal-password-123!",
            "role_ids": [equal_role.json()["id"]],
        },
    )

    assert assigned.status_code == 201, assigned.text
    assert assigned.json()["role_ids"] == [equal_role.json()["id"]]


@pytest.mark.asyncio
async def test_role_assignment_cannot_delegate_kb_access_the_actor_lacks(api_harness) -> None:
    actor_id = uuid4()
    async with api_harness.session_factory() as session:
        admin = await session.scalar(select(User).where(User.email == "admin@example.com"))
        permissions = list(
            (
                await session.scalars(
                    select(Permission).where(
                        Permission.code.in_({"user:manage", "role:assign", "knowledge:read"})
                    )
                )
            ).all()
        )
        assert len(permissions) == 3
        actor_role = Role(code="delegated_actor", name="Delegated actor", priority=100)
        kb_reader_role = Role(code="private_kb_reader", name="Private KB reader", priority=10)
        actor = User(
            id=actor_id,
            email="delegated-actor@example.com",
            password_hash=PasswordService().hash("Delegated-password-123!"),
        )
        assert admin is not None
        knowledge_base = KnowledgeBase(owner_id=admin.id, name="Private delegated KB")
        session.add_all([actor_role, kb_reader_role, actor, knowledge_base])
        await session.flush()
        knowledge_read = next(item for item in permissions if item.code == "knowledge:read")
        session.add_all(
            [
                *[
                    RolePermission(role_id=actor_role.id, permission_id=item.id)
                    for item in permissions
                ],
                RolePermission(role_id=kb_reader_role.id, permission_id=knowledge_read.id),
                UserRole(user_id=actor.id, role_id=actor_role.id, assigned_by=admin.id),
                KnowledgeBaseRoleGrant(
                    knowledge_base_id=knowledge_base.id,
                    role_id=kb_reader_role.id,
                    access_level=KnowledgeBaseAccessLevel.READER,
                    granted_by=admin.id,
                ),
            ]
        )
        await session.commit()
        kb_reader_role_id = kb_reader_role.id

    login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={
            "username": "delegated-actor@example.com",
            "password": "Delegated-password-123!",
        },
    )
    assert login.status_code == 200
    response = await api_harness.client.post(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        json={
            "email": "controlled-user@example.com",
            "password": "Controlled-password-123!",
            "role_ids": [str(kb_reader_role_id)],
        },
    )

    assert response.status_code == 404
    async with api_harness.session_factory() as session:
        assert (
            await session.scalar(select(User.id).where(User.email == "controlled-user@example.com"))
            is None
        )
