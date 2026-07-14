from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import event, select
from sqlalchemy.dialects import postgresql

import app.api.v1.routes.users as user_routes
from app.api.v1.routes.users import _locked_roles_statement
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

pytest_plugins = ("test_integration_api",)


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
    api_key_headers = {"X-API-Key": created.json()["key"]}

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
    assert api_harness.redis.counters[f"rate:api-key:{created.json()['id']}"] == 2


def test_role_assignment_statement_locks_selected_roles_on_postgresql() -> None:
    statement = _locked_roles_statement({uuid4(), uuid4()})
    compiled = str(statement.compile(dialect=postgresql.dialect())).upper()
    assert "FOR NO KEY UPDATE" in compiled


def test_role_assignment_refresh_locks_actor_user_and_roles_on_postgresql() -> None:
    assert hasattr(user_routes, "_locked_actor_user_statement")
    assert hasattr(user_routes, "_locked_actor_roles_statement")
    actor_id = uuid4()
    user_sql = str(
        user_routes._locked_actor_user_statement(actor_id).compile(  # type: ignore[attr-defined]
            dialect=postgresql.dialect()
        )
    ).upper()
    role_sql = str(
        user_routes._locked_actor_roles_statement(actor_id).compile(  # type: ignore[attr-defined]
            dialect=postgresql.dialect()
        )
    ).upper()
    assert "FOR UPDATE" in user_sql
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
        json={"permission_codes": [], "limits": {}},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "role_escalation_denied"


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
