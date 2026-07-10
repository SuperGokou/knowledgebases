from __future__ import annotations

from functools import lru_cache

from redis.asyncio import Redis

from app.core.config import get_settings


@lru_cache
def get_redis() -> Redis:
    return Redis.from_url(
        get_settings().redis_url,
        decode_responses=False,
        socket_connect_timeout=2,
        socket_timeout=2,
        health_check_interval=30,
    )
