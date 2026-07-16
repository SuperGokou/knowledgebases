from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from time import monotonic
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends
from redis.asyncio import Redis
from sqlalchemy import text

from app.api.chat_deadline import chat_route_backlog_size
from app.api.dependencies import DatabaseSession, redis_dependency
from app.api.errors import ApiError
from app.db.schema_version import assert_database_schema_current
from app.services.chat_idempotency import chat_finalization_backlog_size
from app.services.chat_safety import chat_safety_poisoned
from app.services.chat_timeout import chat_cleanup_backlog_size
from app.services.llm_provider import llm_cleanup_backlog_size

router = APIRouter(prefix="/health", tags=["health"])


class DependencyReadinessProbe:
    """Coalesce dependency checks so public polling cannot amplify backend work."""

    def __init__(
        self,
        *,
        success_ttl_seconds: float = 5.0,
        failure_ttl_seconds: float = 1.0,
    ) -> None:
        self.success_ttl_seconds = success_ttl_seconds
        self.failure_ttl_seconds = failure_ttl_seconds
        self.reset()

    def reset(self) -> None:
        self._lock = asyncio.Lock()
        self._available: bool | None = None
        self._expires_at = 0.0

    async def check(self, session: DatabaseSession, redis: Redis) -> bool:
        now = monotonic()
        if self._available is not None and now < self._expires_at:
            return self._available

        async with self._lock:
            now = monotonic()
            if self._available is not None and now < self._expires_at:
                return self._available
            try:
                await session.execute(text("SELECT 1"))
                await assert_database_schema_current(session)
                await cast(Awaitable[Any], redis.ping())
            except Exception:
                self._available = False
                self._expires_at = monotonic() + self.failure_ttl_seconds
            else:
                self._available = True
                self._expires_at = monotonic() + self.success_ttl_seconds
            return self._available


readiness_probe = DependencyReadinessProbe()


@router.get("/live")
async def liveness() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def readiness(
    session: DatabaseSession,
    redis: Annotated[Redis, Depends(redis_dependency)],
) -> dict[str, str]:
    if chat_safety_poisoned():
        raise ApiError(
            status_code=503,
            code="chat_safety_poisoned",
            message="Chat processing requires operator reconciliation and worker restart",
        )
    if (
        chat_cleanup_backlog_size() > 0
        or llm_cleanup_backlog_size() > 0
        or chat_finalization_backlog_size() > 0
        or chat_route_backlog_size() > 0
    ):
        raise ApiError(
            status_code=503,
            code="cleanup_in_progress",
            message="A bounded background cleanup is still in progress",
        )
    if not await readiness_probe.check(session, redis):
        raise ApiError(
            status_code=503,
            code="dependency_unavailable",
            message="One or more required services are unavailable",
        )
    return {"status": "ready"}
