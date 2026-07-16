from __future__ import annotations

import inspect
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, Mock, call
from uuid import UUID

import pytest
from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.exc import DBAPIError

from app.api.errors import ApiError
from app.api.v1.router import router as v1_router
from app.api.v1.routes.users import _lock_superuser_guard
from app.services.llm_egress_policy import acquire_llm_egress_locks
from app.services.rbac_mutation import acquire_rbac_authorization_lock
from app.services.user_activity import (
    ActivityLockMode,
    acquire_authenticated_request_locks,
    acquire_user_activity_locks,
    authenticated_request_lock_plan,
    matched_route_is_rbac_mutation,
    matched_route_template,
    rbac_mutation_endpoint,
    registered_rbac_mutation_routes,
    registered_route_security,
    user_activity_lock_key,
)


def test_user_activity_lock_key_is_stable_signed_and_domain_separated() -> None:
    user_id = UUID("00000000-0000-4000-8000-000000000401")
    assert user_activity_lock_key(user_id) == user_activity_lock_key(user_id)
    assert -(2**63) <= user_activity_lock_key(user_id) < 2**63
    samples = {user_activity_lock_key(UUID(int=index)) for index in range(1, 2_001)}
    assert len(samples) == 2_000


@pytest.mark.asyncio
async def test_activity_locks_are_acquired_in_uuid_order_with_requested_modes() -> None:
    first = UUID("00000000-0000-4000-8000-000000000001")
    second = UUID("00000000-0000-4000-8000-000000000002")
    session = Mock()
    session.get_bind.return_value = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))
    session.execute = AsyncMock()

    await acquire_user_activity_locks(
        session,
        {
            second: ActivityLockMode.EXCLUSIVE,
            first: ActivityLockMode.SHARED,
        },
    )

    assert session.execute.await_args_list == [
        call(ANY, {"lock_key": user_activity_lock_key(first)}),
        call(ANY, {"lock_key": user_activity_lock_key(second)}),
    ]
    assert "pg_advisory_xact_lock_shared" in str(session.execute.await_args_list[0].args[0])
    assert "pg_advisory_xact_lock(" in str(session.execute.await_args_list[1].args[0])


class _LockTimeoutError(Exception):
    sqlstate = "55P03"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "lock_call",
    [
        lambda session: acquire_rbac_authorization_lock(session),
        lambda session: acquire_user_activity_locks(
            session,
            {UUID("00000000-0000-4000-8000-000000000010"): ActivityLockMode.SHARED},
        ),
        lambda session: acquire_llm_egress_locks(
            session,
            [("user", UUID("00000000-0000-4000-8000-000000000010"))],
        ),
        lambda session: _lock_superuser_guard(session),
    ],
)
async def test_authorization_lock_timeout_is_a_narrow_retryable_503(lock_call: object) -> None:
    session = Mock()
    session.get_bind.return_value = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))
    session.execute = AsyncMock(
        side_effect=DBAPIError("SELECT lock", {}, _LockTimeoutError(), False)
    )

    with pytest.raises(ApiError) as captured:
        await lock_call(session)  # type: ignore[operator]

    assert captured.value.status_code == 503
    assert captured.value.code == "authorization_change_busy"
    assert captured.value.headers == {"Retry-After": "1"}


@pytest.mark.asyncio
async def test_non_lock_database_failure_is_not_masked() -> None:
    session = Mock()
    session.get_bind.return_value = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))
    database_error = DBAPIError("SELECT lock", {}, RuntimeError("database offline"), False)
    session.execute = AsyncMock(side_effect=database_error)

    with pytest.raises(DBAPIError) as captured:
        await acquire_rbac_authorization_lock(session)

    assert captured.value is database_error


def test_rbac_mutation_plan_defers_every_lock_until_handler_reauthorization() -> None:
    actor_id = UUID("00000000-0000-4000-8000-000000000010")

    deferred = authenticated_request_lock_plan(actor_id=actor_id, rbac_mutation=True)

    assert deferred.deferred_rbac_mutation
    assert not deferred.rbac_shared
    assert deferred.user_locks == {}


def test_ordinary_bearer_plan_takes_rbac_shared_before_actor_activity_shared() -> None:
    actor_id = UUID("00000000-0000-4000-8000-000000000010")

    ordinary = authenticated_request_lock_plan(actor_id=actor_id, rbac_mutation=False)

    assert not ordinary.deferred_rbac_mutation
    assert ordinary.rbac_shared
    assert ordinary.user_locks == {actor_id: ActivityLockMode.SHARED}


def _marked_test_app(
    prefix: str = "/control",
    *,
    observer: list[tuple[str | None, bool | None]] | None = None,
) -> FastAPI:
    child = APIRouter(prefix="/users")

    async def capture_route(request: Request) -> None:
        if observer is not None:
            observer.append(
                (matched_route_template(request), matched_route_is_rbac_mutation(request))
            )

    @child.patch("/{user_id}", dependencies=[Depends(capture_route)])
    @rbac_mutation_endpoint
    async def patch_user(user_id: UUID) -> dict[str, str]:
        return {"user_id": str(user_id)}

    application = FastAPI()
    application.include_router(child, prefix=prefix)
    return application


def test_marker_resolves_through_included_router_custom_prefix_root_path_and_uuid_forms() -> None:
    observed: list[tuple[str | None, bool | None]] = []
    application = _marked_test_app("/企业控制面", observer=observed)

    actor_id = UUID("00000000-0000-4000-8000-000000000010")
    with TestClient(application, root_path="/gateway") as client:
        canonical = client.patch(f"/企业控制面/users/{actor_id}")
        compact = client.patch(f"/企业控制面/users/{actor_id.hex}")

    assert canonical.status_code == 200
    assert compact.status_code == 200
    assert observed == [
        ("/企业控制面/users/{user_id}", True),
        ("/企业控制面/users/{user_id}", True),
    ]


@pytest.mark.asyncio
async def test_generic_auth_takes_no_advisory_lock_for_marked_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.services.user_activity as activity

    application = _marked_test_app("/alternate-api")
    actor_id = UUID("00000000-0000-4000-8000-000000000010")
    request = Request(
        {
            "type": "http",
            "method": "PATCH",
            "path": f"/alternate-api/users/{actor_id.hex}",
            "raw_path": f"/alternate-api/users/{actor_id.hex}".encode(),
            "headers": [],
            "query_string": b"",
            "app": application,
        }
    )
    rbac_shared = AsyncMock()
    activity_locks = AsyncMock()
    monkeypatch.setattr(activity, "acquire_rbac_authorization_lock", rbac_shared)
    monkeypatch.setattr(activity, "acquire_user_activity_locks", activity_locks)

    plan = await acquire_authenticated_request_locks(Mock(), request, actor_id)

    assert plan.deferred_rbac_mutation
    rbac_shared.assert_not_awaited()
    activity_locks.assert_not_awaited()


@pytest.mark.asyncio
async def test_generic_auth_ordinary_request_lock_order_is_rbac_then_activity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.services.user_activity as activity

    application = FastAPI()

    @application.post("/knowledge-bases")
    async def create_knowledge_base() -> None:
        return None

    actor_id = UUID("00000000-0000-4000-8000-000000000010")
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/knowledge-bases",
            "raw_path": b"/knowledge-bases",
            "headers": [],
            "query_string": b"",
            "app": application,
        }
    )
    order: list[str] = []

    async def rbac_shared(_session: object) -> None:
        order.append("rbac-shared")

    async def activity_shared(_session: object, _locks: object) -> None:
        order.append("activity-shared")

    monkeypatch.setattr(activity, "acquire_rbac_authorization_lock", rbac_shared)
    monkeypatch.setattr(activity, "acquire_user_activity_locks", activity_shared)

    plan = await acquire_authenticated_request_locks(Mock(), request, actor_id)

    assert plan.rbac_shared
    assert order == ["rbac-shared", "activity-shared"]


def test_every_registered_rbac_mutation_helper_endpoint_has_explicit_marker() -> None:
    application = FastAPI()
    application.include_router(v1_router, prefix="/tenant/control/v9")
    registered = registered_rbac_mutation_routes(application)
    helper_names = {
        "_lock_and_refresh_role_admin",
        "_lock_api_key_creation",
        "_lock_api_key_mutation",
        "_lock_authorized_user_target",
        "_replace_user_password",
        "acquire_rbac_mutation_lock",
    }
    helper_routes: set[tuple[str, str]] = set()
    for route in registered_route_security(application):
        source = inspect.getsource(route.endpoint)
        if any(name in source for name in helper_names):
            helper_routes.add((route.method, route.template))

    assert helper_routes
    assert helper_routes == registered
    assert all(path.startswith("/tenant/control/v9/") for _, path in registered)
    assert all("/api/v1" not in path for _, path in registered)
