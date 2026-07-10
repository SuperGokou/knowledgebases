from __future__ import annotations

from collections.abc import Awaitable
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends
from redis.asyncio import Redis
from sqlalchemy import text

from app.api.dependencies import DatabaseSession, redis_dependency
from app.api.errors import ApiError

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
async def liveness() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def readiness(
    session: DatabaseSession,
    redis: Annotated[Redis, Depends(redis_dependency)],
) -> dict[str, str]:
    try:
        await session.execute(text("SELECT 1"))
        await cast(Awaitable[Any], redis.ping())
    except Exception as error:
        raise ApiError(
            status_code=503,
            code="dependency_unavailable",
            message="One or more required services are unavailable",
        ) from error
    return {"status": "ready"}
