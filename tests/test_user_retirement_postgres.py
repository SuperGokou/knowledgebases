from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.api.dependencies as dependencies
import app.api.v1.routes.api_keys as api_key_routes
import app.api.v1.routes.auth as auth_routes
import app.api.v1.routes.public_api as public_api_routes
import app.api.v1.routes.users as user_routes
from app.api.dependencies import redis_dependency
from app.core.security import PasswordService
from app.db.models import (
    ApiKey,
    AuditLog,
    KnowledgeBase,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
    UserStatus,
)
from app.db.session import get_db
from app.main import create_app
from app.services.knowledge_bases import (
    require_knowledge_base_access as require_knowledge_base_access_original,
)
from app.services.knowledge_bases import (
    search_knowledge_entries as search_knowledge_entries_original,
)
from app.services.llm_egress_policy import (
    acquire_llm_egress_locks as acquire_llm_egress_locks_original,
)
from app.services.user_activity import (
    acquire_authenticated_request_locks as acquire_authenticated_request_locks_original,
)
from app.services.user_activity import (
    acquire_user_activity_locks as acquire_user_activity_locks_original,
)
from scripts.postgres_acceptance import assert_acceptance_database

_POSTGRES_URL = os.getenv("KB_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not _POSTGRES_URL,
    reason="KB_TEST_POSTGRES_URL is required for retirement linearization verification",
)


class _FakeRedis:
    def __init__(self) -> None:
        self.counters: dict[str, int] = {}

    async def eval(self, _script: str, _keys: int, key: str, ttl_ms: int) -> list[int]:
        self.counters[key] = self.counters.get(key, 0) + 1
        return [self.counters[key], ttl_ms]


@dataclass(frozen=True, slots=True)
class _RetirementHarness:
    client: httpx.AsyncClient
    session_factory: async_sessionmaker[AsyncSession]
    actor_id: UUID
    actor_email: str
    actor_password: str
    target_id: UUID
    target_email: str
    target_password: str
    replacement_id: UUID
    knowledge_base_id: UUID
    role_id: UUID
    application_name: str

    async def login(self, *, target: bool = False) -> dict[str, Any]:
        response = await self.client.post(
            "/api/v1/auth/token",
            data={
                "username": self.target_email if target else self.actor_email,
                "password": self.target_password if target else self.actor_password,
            },
        )
        assert response.status_code == 200, response.text
        return cast("dict[str, Any]", response.json())

    def retirement_payload(self) -> dict[str, str]:
        return {
            "confirmation_email": self.target_email,
            "replacement_owner_id": str(self.replacement_id),
            "reason": "PostgreSQL linearization acceptance",
        }


async def _permission(session: AsyncSession, code: str) -> Permission:
    existing = await session.scalar(select(Permission).where(Permission.code == code))
    if existing is not None:
        return existing
    permission = Permission(
        code=code,
        name=f"Acceptance {code}",
        description="PostgreSQL retirement acceptance fixture",
    )
    session.add(permission)
    await session.flush()
    return permission


@pytest_asyncio.fixture
async def retirement_harness() -> AsyncIterator[_RetirementHarness]:
    assert _POSTGRES_URL is not None
    unique = uuid4().hex
    application_name = f"kb_user_retirement_{unique}"
    engine = create_async_engine(
        _POSTGRES_URL,
        pool_size=12,
        max_overflow=0,
        connect_args={"server_settings": {"application_name": application_name}},
    )
    async with engine.begin() as connection:
        await assert_acceptance_database(connection)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    actor_password = "Postgres-actor-password-123!"
    target_password = "Postgres-target-password-123!"
    actor = User(
        email=f"retirement-actor-{unique}@example.com",
        password_hash=PasswordService().hash(actor_password),
        is_superuser=True,
    )
    target = User(
        email=f"retirement-target-{unique}@example.com",
        password_hash=PasswordService().hash(target_password),
    )
    replacement = User(
        email=f"retirement-replacement-{unique}@example.com",
        password_hash=PasswordService().hash("Postgres-replacement-password-123!"),
    )
    role = Role(
        code=f"retirement-target-{unique}",
        name="Retirement target acceptance",
        priority=-100,
    )
    async with factory() as session:
        session.add_all([actor, target, replacement, role])
        await session.flush()
        permission = await _permission(session, "knowledge:create")
        read_permission = await _permission(session, "knowledge:read")
        session.add_all(
            [
                RolePermission(role_id=role.id, permission_id=permission.id),
                RolePermission(role_id=role.id, permission_id=read_permission.id),
            ]
        )
        session.add(UserRole(user_id=target.id, role_id=role.id, assigned_by=actor.id))
        knowledge_base = KnowledgeBase(
            owner_id=target.id,
            name=f"Retirement fixture {unique}",
        )
        session.add(knowledge_base)
        await session.commit()
        fixture = _RetirementHarness(
            client=cast("httpx.AsyncClient", None),
            session_factory=factory,
            actor_id=actor.id,
            actor_email=actor.email,
            actor_password=actor_password,
            target_id=target.id,
            target_email=target.email,
            target_password=target_password,
            replacement_id=replacement.id,
            knowledge_base_id=knowledge_base.id,
            role_id=role.id,
            application_name=application_name,
        )

    application = create_app()
    fake_redis = _FakeRedis()

    async def override_db() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            yield session

    async def override_redis() -> AsyncIterator[_FakeRedis]:
        yield fake_redis

    application.dependency_overrides[get_db] = override_db
    application.dependency_overrides[redis_dependency] = override_redis
    transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            yield _RetirementHarness(
                client=client,
                session_factory=factory,
                actor_id=fixture.actor_id,
                actor_email=fixture.actor_email,
                actor_password=fixture.actor_password,
                target_id=fixture.target_id,
                target_email=fixture.target_email,
                target_password=fixture.target_password,
                replacement_id=fixture.replacement_id,
                knowledge_base_id=fixture.knowledge_base_id,
                role_id=fixture.role_id,
                application_name=fixture.application_name,
            )
    finally:
        application.dependency_overrides.clear()
        async with factory() as session:
            await session.execute(
                delete(KnowledgeBase).where(
                    KnowledgeBase.owner_id.in_(
                        {fixture.actor_id, fixture.target_id, fixture.replacement_id}
                    )
                )
            )
            await session.execute(delete(User).where(User.id == fixture.target_id))
            await session.flush()
            await session.execute(delete(User).where(User.id == fixture.replacement_id))
            await session.execute(delete(User).where(User.id == fixture.actor_id))
            await session.flush()
            await session.execute(delete(Role).where(Role.id == fixture.role_id))
            await session.commit()
        await engine.dispose()


async def _wait_for_lock_waiters(
    harness: _RetirementHarness,
    *,
    expected: int = 1,
) -> None:
    deadline = asyncio.get_running_loop().time() + 5
    while asyncio.get_running_loop().time() < deadline:
        async with harness.session_factory() as observer:
            waiters = int(
                await observer.scalar(
                    text(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE application_name = :application_name "
                        "AND wait_event_type = 'Lock'"
                    ),
                    {"application_name": harness.application_name},
                )
                or 0
            )
        if waiters >= expected:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"expected at least {expected} PostgreSQL lock waiter(s)")


async def _issue_target_api_key(
    harness: _RetirementHarness,
    access_token: str,
    *,
    name: str,
) -> httpx.Response:
    return await harness.client.post(
        "/api/v1/api-keys",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "name": name,
            "user_id": str(harness.target_id),
            "permission_codes": ["knowledge:read"],
            "knowledge_base_ids": [str(harness.knowledge_base_id)],
        },
    )


@pytest.mark.asyncio
async def test_postgres_authenticated_kb_create_finishes_before_owner_transfer_retirement(
    retirement_harness: _RetirementHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor_tokens = await retirement_harness.login()
    target_tokens = await retirement_harness.login(target=True)
    entered = asyncio.Event()
    release = asyncio.Event()
    original = acquire_authenticated_request_locks_original

    async def pause_after_authentication_locks(
        session: AsyncSession,
        request: Any,
        actor_id: UUID,
    ) -> Any:
        plan = await original(session, request, actor_id)
        if request.method == "POST" and request.url.path == "/api/v1/knowledge-bases":
            entered.set()
            await release.wait()
        return plan

    monkeypatch.setattr(
        dependencies,
        "acquire_authenticated_request_locks",
        pause_after_authentication_locks,
    )
    create_task = asyncio.create_task(
        retirement_harness.client.post(
            "/api/v1/knowledge-bases",
            headers={"Authorization": f"Bearer {target_tokens['access_token']}"},
            json={"name": "Created before retirement"},
        )
    )
    retirement_task: asyncio.Task[httpx.Response] | None = None
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        retirement_task = asyncio.create_task(
            retirement_harness.client.request(
                "DELETE",
                f"/api/v1/users/{retirement_harness.target_id}",
                headers={"Authorization": f"Bearer {actor_tokens['access_token']}"},
                json=retirement_harness.retirement_payload(),
            )
        )
        await _wait_for_lock_waiters(retirement_harness)
        release.set()
        created, retired = await asyncio.wait_for(
            asyncio.gather(create_task, retirement_task),
            timeout=10,
        )
    finally:
        release.set()
        if not create_task.done():
            create_task.cancel()
        if retirement_task is not None and not retirement_task.done():
            retirement_task.cancel()
        await asyncio.gather(
            create_task,
            *(tuple([retirement_task]) if retirement_task is not None else ()),
            return_exceptions=True,
        )

    assert created.status_code == 201, created.text
    assert retired.status_code == 204, retired.text
    async with retirement_harness.session_factory() as session:
        owner = await session.scalar(
            select(KnowledgeBase.owner_id).where(KnowledgeBase.id == UUID(created.json()["id"]))
        )
    assert owner == retirement_harness.replacement_id


@pytest.mark.asyncio
async def test_postgres_retirement_commits_before_stale_kb_create_is_rejected(
    retirement_harness: _RetirementHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor_tokens = await retirement_harness.login()
    target_tokens = await retirement_harness.login(target=True)
    entered = asyncio.Event()
    release = asyncio.Event()
    original = acquire_llm_egress_locks_original

    async def pause_after_retirement_locks(
        session: AsyncSession,
        scopes: Any,
    ) -> None:
        await original(session, scopes)
        entered.set()
        await release.wait()

    monkeypatch.setattr(
        user_routes,
        "acquire_llm_egress_locks",
        pause_after_retirement_locks,
    )
    retirement_task = asyncio.create_task(
        retirement_harness.client.request(
            "DELETE",
            f"/api/v1/users/{retirement_harness.target_id}",
            headers={"Authorization": f"Bearer {actor_tokens['access_token']}"},
            json=retirement_harness.retirement_payload(),
        )
    )
    create_task: asyncio.Task[httpx.Response] | None = None
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        create_task = asyncio.create_task(
            retirement_harness.client.post(
                "/api/v1/knowledge-bases",
                headers={"Authorization": f"Bearer {target_tokens['access_token']}"},
                json={"name": "Must not land after retirement"},
            )
        )
        await _wait_for_lock_waiters(retirement_harness)
        release.set()
        retired, created = await asyncio.wait_for(
            asyncio.gather(retirement_task, create_task),
            timeout=10,
        )
    finally:
        release.set()
        if not retirement_task.done():
            retirement_task.cancel()
        if create_task is not None and not create_task.done():
            create_task.cancel()
        await asyncio.gather(
            retirement_task,
            *(tuple([create_task]) if create_task is not None else ()),
            return_exceptions=True,
        )

    assert retired.status_code == 204, retired.text
    assert created.status_code == 401, created.text
    assert created.json()["error"]["code"] == "inactive_user"
    async with retirement_harness.session_factory() as session:
        count = int(
            await session.scalar(
                select(func.count())
                .select_from(KnowledgeBase)
                .where(KnowledgeBase.name == "Must not land after retirement")
            )
            or 0
        )
    assert count == 0


@pytest.mark.asyncio
async def test_postgres_api_key_issue_finishes_before_retirement_revokes_the_key(
    retirement_harness: _RetirementHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor_tokens = await retirement_harness.login()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def pause_after_target_access(*args: Any, **kwargs: Any) -> Any:
        result = await require_knowledge_base_access_original(*args, **kwargs)
        entered.set()
        await release.wait()
        return result

    monkeypatch.setattr(
        api_key_routes,
        "require_knowledge_base_access",
        pause_after_target_access,
    )
    issue_task = asyncio.create_task(
        _issue_target_api_key(
            retirement_harness,
            cast("str", actor_tokens["access_token"]),
            name="Issue before retirement",
        )
    )
    retirement_task: asyncio.Task[httpx.Response] | None = None
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        retirement_task = asyncio.create_task(
            retirement_harness.client.request(
                "DELETE",
                f"/api/v1/users/{retirement_harness.target_id}",
                headers={"Authorization": f"Bearer {actor_tokens['access_token']}"},
                json=retirement_harness.retirement_payload(),
            )
        )
        await _wait_for_lock_waiters(retirement_harness)
        release.set()
        issued, retired = await asyncio.wait_for(
            asyncio.gather(issue_task, retirement_task),
            timeout=10,
        )
    finally:
        release.set()
        if not issue_task.done():
            issue_task.cancel()
        if retirement_task is not None and not retirement_task.done():
            retirement_task.cancel()
        await asyncio.gather(
            issue_task,
            *(tuple([retirement_task]) if retirement_task is not None else ()),
            return_exceptions=True,
        )

    assert issued.status_code == 201, issued.text
    assert retired.status_code == 204, retired.text
    async with retirement_harness.session_factory() as session:
        api_key = await session.get(ApiKey, UUID(issued.json()["id"]))
    assert api_key is not None
    assert api_key.revoked_at is not None


@pytest.mark.asyncio
async def test_postgres_retirement_rejects_stale_api_key_issue(
    retirement_harness: _RetirementHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor_tokens = await retirement_harness.login()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def pause_after_retirement_locks(
        session: AsyncSession,
        scopes: Any,
    ) -> None:
        await acquire_llm_egress_locks_original(session, scopes)
        entered.set()
        await release.wait()

    monkeypatch.setattr(
        user_routes,
        "acquire_llm_egress_locks",
        pause_after_retirement_locks,
    )
    retirement_task = asyncio.create_task(
        retirement_harness.client.request(
            "DELETE",
            f"/api/v1/users/{retirement_harness.target_id}",
            headers={"Authorization": f"Bearer {actor_tokens['access_token']}"},
            json=retirement_harness.retirement_payload(),
        )
    )
    issue_task: asyncio.Task[httpx.Response] | None = None
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        issue_task = asyncio.create_task(
            _issue_target_api_key(
                retirement_harness,
                cast("str", actor_tokens["access_token"]),
                name="Must not issue after retirement",
            )
        )
        await _wait_for_lock_waiters(retirement_harness)
        release.set()
        retired, issued = await asyncio.wait_for(
            asyncio.gather(retirement_task, issue_task),
            timeout=10,
        )
    finally:
        release.set()
        if not retirement_task.done():
            retirement_task.cancel()
        if issue_task is not None and not issue_task.done():
            issue_task.cancel()
        await asyncio.gather(
            retirement_task,
            *(tuple([issue_task]) if issue_task is not None else ()),
            return_exceptions=True,
        )

    assert retired.status_code == 204, retired.text
    assert issued.status_code == 404, issued.text
    assert issued.json()["error"]["code"] == "user_not_found"
    async with retirement_harness.session_factory() as session:
        count = int(
            await session.scalar(
                select(func.count())
                .select_from(ApiKey)
                .where(
                    ApiKey.user_id == retirement_harness.target_id,
                    ApiKey.name == "Must not issue after retirement",
                )
            )
            or 0
        )
    assert count == 0


@pytest.mark.asyncio
async def test_postgres_public_api_key_request_finishes_before_retirement(
    retirement_harness: _RetirementHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor_tokens = await retirement_harness.login()
    issued = await _issue_target_api_key(
        retirement_harness,
        cast("str", actor_tokens["access_token"]),
        name="Public request before retirement",
    )
    assert issued.status_code == 201, issued.text
    cleartext = cast("str", issued.json()["key"])
    entered = asyncio.Event()
    release = asyncio.Event()

    async def pause_public_search(*args: Any, **kwargs: Any) -> Any:
        result = await search_knowledge_entries_original(*args, **kwargs)
        entered.set()
        await release.wait()
        return result

    monkeypatch.setattr(public_api_routes, "search_knowledge_entries", pause_public_search)
    public_task = asyncio.create_task(
        retirement_harness.client.post(
            f"/api/v1/public/knowledge-bases/{retirement_harness.knowledge_base_id}/search",
            headers={"X-API-Key": cleartext},
            json={"query": "retirement acceptance", "limit": 5},
        )
    )
    retirement_task: asyncio.Task[httpx.Response] | None = None
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        retirement_task = asyncio.create_task(
            retirement_harness.client.request(
                "DELETE",
                f"/api/v1/users/{retirement_harness.target_id}",
                headers={"Authorization": f"Bearer {actor_tokens['access_token']}"},
                json=retirement_harness.retirement_payload(),
            )
        )
        await _wait_for_lock_waiters(retirement_harness)
        release.set()
        searched, retired = await asyncio.wait_for(
            asyncio.gather(public_task, retirement_task),
            timeout=10,
        )
    finally:
        release.set()
        if not public_task.done():
            public_task.cancel()
        if retirement_task is not None and not retirement_task.done():
            retirement_task.cancel()
        await asyncio.gather(
            public_task,
            *(tuple([retirement_task]) if retirement_task is not None else ()),
            return_exceptions=True,
        )

    assert searched.status_code == 200, searched.text
    assert retired.status_code == 204, retired.text
    async with retirement_harness.session_factory() as session:
        api_key = await session.get(ApiKey, UUID(issued.json()["id"]))
    assert api_key is not None
    assert api_key.revoked_at is not None


@pytest.mark.asyncio
async def test_postgres_retirement_rejects_stale_public_api_key_request(
    retirement_harness: _RetirementHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor_tokens = await retirement_harness.login()
    issued = await _issue_target_api_key(
        retirement_harness,
        cast("str", actor_tokens["access_token"]),
        name="Public request after retirement",
    )
    assert issued.status_code == 201, issued.text
    cleartext = cast("str", issued.json()["key"])
    entered = asyncio.Event()
    release = asyncio.Event()

    async def pause_after_retirement_locks(
        session: AsyncSession,
        scopes: Any,
    ) -> None:
        await acquire_llm_egress_locks_original(session, scopes)
        entered.set()
        await release.wait()

    monkeypatch.setattr(
        user_routes,
        "acquire_llm_egress_locks",
        pause_after_retirement_locks,
    )
    retirement_task = asyncio.create_task(
        retirement_harness.client.request(
            "DELETE",
            f"/api/v1/users/{retirement_harness.target_id}",
            headers={"Authorization": f"Bearer {actor_tokens['access_token']}"},
            json=retirement_harness.retirement_payload(),
        )
    )
    public_task: asyncio.Task[httpx.Response] | None = None
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        public_task = asyncio.create_task(
            retirement_harness.client.post(
                f"/api/v1/public/knowledge-bases/{retirement_harness.knowledge_base_id}/search",
                headers={"X-API-Key": cleartext},
                json={"query": "must be rejected", "limit": 5},
            )
        )
        await _wait_for_lock_waiters(retirement_harness)
        release.set()
        retired, searched = await asyncio.wait_for(
            asyncio.gather(retirement_task, public_task),
            timeout=10,
        )
    finally:
        release.set()
        if not retirement_task.done():
            retirement_task.cancel()
        if public_task is not None and not public_task.done():
            public_task.cancel()
        await asyncio.gather(
            retirement_task,
            *(tuple([public_task]) if public_task is not None else ()),
            return_exceptions=True,
        )

    assert retired.status_code == 204, retired.text
    assert searched.status_code == 401, searched.text
    assert searched.json()["error"]["code"] == "invalid_api_key"


@pytest.mark.asyncio
@pytest.mark.parametrize("auth_operation", ["refresh", "logout"])
async def test_postgres_self_password_change_does_not_deadlock_refresh_or_logout(
    retirement_harness: _RetirementHarness,
    monkeypatch: pytest.MonkeyPatch,
    auth_operation: str,
) -> None:
    target_tokens = await retirement_harness.login(target=True)
    entered = asyncio.Event()
    release = asyncio.Event()
    original = acquire_user_activity_locks_original

    async def pause_auth_with_activity_shared(
        session: AsyncSession,
        locks: Any,
    ) -> None:
        await original(session, locks)
        entered.set()
        await release.wait()

    monkeypatch.setattr(
        auth_routes,
        "acquire_user_activity_locks",
        pause_auth_with_activity_shared,
    )
    auth_task = asyncio.create_task(
        retirement_harness.client.post(
            f"/api/v1/auth/{auth_operation}",
            json={"refresh_token": target_tokens["refresh_token"]},
        )
    )
    password_task: asyncio.Task[httpx.Response] | None = None
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        password_task = asyncio.create_task(
            retirement_harness.client.put(
                "/api/v1/users/me/password",
                headers={"Authorization": f"Bearer {target_tokens['access_token']}"},
                json={
                    "current_password": retirement_harness.target_password,
                    "new_password": "Postgres-new-target-password-456!",
                },
            )
        )
        await _wait_for_lock_waiters(retirement_harness)
        release.set()
        auth_response, password_response = await asyncio.wait_for(
            asyncio.gather(auth_task, password_task),
            timeout=10,
        )
    finally:
        release.set()
        if not auth_task.done():
            auth_task.cancel()
        if password_task is not None and not password_task.done():
            password_task.cancel()
        await asyncio.gather(
            auth_task,
            *(tuple([password_task]) if password_task is not None else ()),
            return_exceptions=True,
        )

    assert auth_response.status_code in {200, 204}, auth_response.text
    assert password_response.status_code == 204, password_response.text


@pytest.mark.asyncio
async def test_postgres_duplicate_retirement_is_idempotent_and_single_audit(
    retirement_harness: _RetirementHarness,
) -> None:
    actor_tokens = await retirement_harness.login()
    responses = await asyncio.wait_for(
        asyncio.gather(
            *(
                retirement_harness.client.request(
                    "DELETE",
                    f"/api/v1/users/{retirement_harness.target_id}",
                    headers={"Authorization": f"Bearer {actor_tokens['access_token']}"},
                    json=retirement_harness.retirement_payload(),
                )
                for _ in range(2)
            )
        ),
        timeout=10,
    )

    assert [response.status_code for response in responses] == [204, 204]
    async with retirement_harness.session_factory() as session:
        audits = int(
            await session.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.action == "user.retired",
                    AuditLog.resource_id == str(retirement_harness.target_id),
                )
            )
            or 0
        )
        owner = await session.scalar(
            select(KnowledgeBase.owner_id).where(
                KnowledgeBase.id == retirement_harness.knowledge_base_id
            )
        )
    assert audits == 1
    assert owner == retirement_harness.replacement_id


@pytest.mark.asyncio
async def test_postgres_cross_disable_preserves_one_active_superuser(
    retirement_harness: _RetirementHarness,
) -> None:
    peer_id = uuid4()
    peer_email = f"retirement-superuser-peer-{peer_id.hex}@example.com"
    peer_password = "Postgres-peer-password-123!"
    saved_superusers: dict[UUID, tuple[UserStatus, int]] = {}
    try:
        async with retirement_harness.session_factory() as session:
            superusers = list(
                (
                    await session.scalars(
                        select(User)
                        .where(User.is_superuser.is_(True))
                        .order_by(User.id)
                        .with_for_update()
                    )
                ).all()
            )
            saved_superusers = {user.id: (user.status, user.token_version) for user in superusers}
            for user in superusers:
                if user.id != retirement_harness.actor_id:
                    user.status = UserStatus.DISABLED
                    user.token_version += 1
            session.add(
                User(
                    id=peer_id,
                    email=peer_email,
                    password_hash=PasswordService().hash(peer_password),
                    is_superuser=True,
                )
            )
            await session.commit()

        actor_tokens = await retirement_harness.login()
        peer_login = await retirement_harness.client.post(
            "/api/v1/auth/token",
            data={"username": peer_email, "password": peer_password},
        )
        assert peer_login.status_code == 200, peer_login.text
        peer_tokens = cast("dict[str, Any]", peer_login.json())

        actor_disables_peer = retirement_harness.client.patch(
            f"/api/v1/users/{peer_id}",
            headers={"Authorization": f"Bearer {actor_tokens['access_token']}"},
            json={"status": "disabled"},
        )
        peer_disables_actor = retirement_harness.client.patch(
            f"/api/v1/users/{retirement_harness.actor_id}",
            headers={"Authorization": f"Bearer {peer_tokens['access_token']}"},
            json={"status": "disabled"},
        )
        responses = await asyncio.wait_for(
            asyncio.gather(actor_disables_peer, peer_disables_actor),
            timeout=10,
        )

        assert sorted(response.status_code for response in responses) == [200, 401]
        denied = next(response for response in responses if response.status_code == 401)
        assert denied.json()["error"]["code"] == "inactive_user"
        async with retirement_harness.session_factory() as session:
            active_ids = set(
                (
                    await session.scalars(
                        select(User.id).where(
                            User.id.in_({retirement_harness.actor_id, peer_id}),
                            User.status == UserStatus.ACTIVE,
                            User.retired_at.is_(None),
                        )
                    )
                ).all()
            )
        assert len(active_ids) == 1
    finally:
        async with retirement_harness.session_factory() as session:
            users = list(
                (
                    await session.scalars(
                        select(User)
                        .where(User.id.in_(set(saved_superusers) | {peer_id}))
                        .with_for_update()
                    )
                ).all()
            )
            users_by_id = {user.id: user for user in users}
            for user_id, (status_value, token_version) in saved_superusers.items():
                restored_user = users_by_id.get(user_id)
                if restored_user is not None:
                    restored_user.status = status_value
                    restored_user.token_version = token_version
            await session.flush()
            await session.execute(delete(User).where(User.id == peer_id))
            await session.commit()
