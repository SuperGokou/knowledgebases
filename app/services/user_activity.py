from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from re import Pattern
from typing import Any
from uuid import UUID

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.routing import compile_path

from app.services.rbac_mutation import (
    acquire_authorization_advisory_lock,
    acquire_rbac_authorization_lock,
)

_USER_ACTIVITY_LOCK_NAMESPACE = b"enterprise-kb:user-activity:v1\0"
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_RBAC_MUTATION_ATTRIBUTE = "__enterprise_kb_rbac_mutation__"


class ActivityLockMode(StrEnum):
    SHARED = "shared"
    EXCLUSIVE = "exclusive"


@dataclass(frozen=True, slots=True)
class AuthenticatedRequestLockPlan:
    deferred_rbac_mutation: bool
    rbac_shared: bool
    user_locks: dict[UUID, ActivityLockMode]


@dataclass(frozen=True, slots=True)
class RegisteredRouteSecurity:
    method: str
    template: str
    endpoint: Callable[..., Any]
    rbac_mutation: bool


@dataclass(frozen=True, slots=True)
class _TrustedRoute:
    template: str
    methods: frozenset[str]
    path_regex: Pattern[str]
    param_convertors: dict[str, Any]
    endpoint: Callable[..., Any]
    rbac_mutation: bool


@dataclass(frozen=True, slots=True)
class _MatchedRoute:
    route: _TrustedRoute
    path_params: dict[str, Any]


def rbac_mutation_endpoint[Endpoint: Callable[..., Any]](endpoint: Endpoint) -> Endpoint:
    """Mark a control-plane endpoint whose handler performs locked reauthorization.

    The marker follows the endpoint object through nested ``include_router`` calls,
    so it does not depend on an API prefix, URL spelling, or user-controlled path
    text. Place it immediately below the FastAPI route decorator.
    """

    setattr(endpoint, _RBAC_MUTATION_ATTRIBUTE, True)
    return endpoint


def user_activity_lock_key(user_id: UUID) -> int:
    """Return a stable, domain-separated signed PostgreSQL advisory key."""

    digest = hashlib.blake2b(
        _USER_ACTIVITY_LOCK_NAMESPACE + user_id.bytes,
        digest_size=8,
    ).digest()
    return int.from_bytes(digest, byteorder="big", signed=True)


async def acquire_user_activity_locks(
    session: AsyncSession,
    locks: dict[UUID, ActivityLockMode],
) -> None:
    """Acquire transaction locks in UUID order to make multi-user paths deadlock-safe."""

    for user_id in sorted(locks, key=lambda item: item.int):
        await acquire_authorization_advisory_lock(
            session,
            user_activity_lock_key(user_id),
            shared=locks[user_id] is ActivityLockMode.SHARED,
        )


def matched_route_template(request: Request) -> str | None:
    """Resolve the trusted FastAPI route template before dependencies run."""

    matched = _matched_route(request)
    return matched.route.template if matched is not None else None


def matched_route_is_rbac_mutation(request: Request) -> bool | None:
    """Return marker metadata from the matched application route, never raw URL text."""

    matched = _matched_route(request)
    return matched.route.rbac_mutation if matched is not None else None


def registered_rbac_mutation_routes(application: Any) -> frozenset[tuple[str, str]]:
    """Expose the trusted marker registry for fail-closed contract tests."""

    return frozenset(
        (method, route.template)
        for route in _trusted_routes(application)
        if route.rbac_mutation
        for method in route.methods
        if method != "HEAD"
    )


def registered_route_security(application: Any) -> tuple[RegisteredRouteSecurity, ...]:
    """Return the exact flattened route inventory consumed by authentication."""

    return tuple(
        RegisteredRouteSecurity(
            method=method,
            template=route.template,
            endpoint=route.endpoint,
            rbac_mutation=route.rbac_mutation,
        )
        for route in _trusted_routes(application)
        for method in sorted(route.methods)
        if method != "HEAD"
    )


def _matched_route(request: Request) -> _MatchedRoute | None:
    path = request.scope.get("path")
    method = request.method.upper()
    if not isinstance(path, str):
        return None
    for route in _trusted_routes(request.app):
        if method not in route.methods:
            continue
        matched = route.path_regex.match(path)
        if matched is None:
            continue
        params = {
            key: route.param_convertors[key].convert(value)
            for key, value in matched.groupdict().items()
        }
        return _MatchedRoute(route=route, path_params=params)
    return None


@lru_cache(maxsize=8)
def _trusted_routes(application: Any) -> tuple[_TrustedRoute, ...]:
    flattened: list[_TrustedRoute] = []

    def visit(routes: list[Any], prefix: str) -> None:
        for route in routes:
            original_router = getattr(route, "original_router", None)
            include_context = getattr(route, "include_context", None)
            if original_router is not None and include_context is not None:
                visit(list(original_router.routes), f"{prefix}{include_context.prefix}")
                continue
            path = getattr(route, "path", None)
            methods = getattr(route, "methods", None)
            endpoint = getattr(route, "endpoint", None)
            if not isinstance(path, str) or not methods or not callable(endpoint):
                continue
            template = f"{prefix}{path}"
            path_regex, _, param_convertors = compile_path(template)
            flattened.append(
                _TrustedRoute(
                    template=template,
                    methods=frozenset(str(item).upper() for item in methods),
                    path_regex=path_regex,
                    param_convertors=param_convertors,
                    endpoint=endpoint,
                    rbac_mutation=bool(
                        getattr(endpoint, _RBAC_MUTATION_ATTRIBUTE, False) is True
                    ),
                )
            )

    visit(list(application.routes), "")
    return tuple(flattened)


def authenticated_request_lock_plan(
    *,
    actor_id: UUID,
    rbac_mutation: bool,
) -> AuthenticatedRequestLockPlan:
    if rbac_mutation:
        # Initial authentication and permission checks are intentionally lock-free.
        # A marked handler must acquire RBAC-X and reauthorize before it writes.
        return AuthenticatedRequestLockPlan(
            deferred_rbac_mutation=True,
            rbac_shared=False,
            user_locks={},
        )
    return AuthenticatedRequestLockPlan(
        deferred_rbac_mutation=False,
        rbac_shared=True,
        user_locks={actor_id: ActivityLockMode.SHARED},
    )


async def acquire_authenticated_request_locks(
    session: AsyncSession,
    request: Request,
    actor_id: UUID,
) -> AuthenticatedRequestLockPlan:
    matched = _matched_route(request)
    if matched is None:
        if request.method.upper() in _MUTATING_METHODS:
            raise RuntimeError("mutating authenticated request has no matched route template")
        rbac_mutation = False
    else:
        rbac_mutation = matched.route.rbac_mutation
    plan = authenticated_request_lock_plan(
        actor_id=actor_id,
        rbac_mutation=rbac_mutation,
    )
    if plan.deferred_rbac_mutation:
        return plan
    # This is the universal ordering for ordinary authenticated traffic. Every
    # control-plane writer takes RBAC-X before any user activity lock.
    await acquire_rbac_authorization_lock(session)
    await acquire_user_activity_locks(session, plan.user_locks)
    return plan
