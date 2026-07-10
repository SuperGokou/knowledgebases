from __future__ import annotations

from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Any, cast

from redis.asyncio import Redis

RATE_LIMIT_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
return {current, ttl}
"""


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int


class RateLimiter:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def check(self, *, key: str, limit: int, window_seconds: int = 60) -> RateLimitDecision:
        if limit <= 0:
            return RateLimitDecision(False, limit, 0, window_seconds)
        result = await cast(
            Awaitable[Any],
            self._redis.eval(
                RATE_LIMIT_SCRIPT,
                1,
                key,
                window_seconds * 1000,
            ),
        )
        current, ttl_ms = result
        current_value = int(current)
        retry_after = max(1, (int(ttl_ms) + 999) // 1000)
        return RateLimitDecision(
            allowed=current_value <= limit,
            limit=limit,
            remaining=max(limit - current_value, 0),
            retry_after_seconds=retry_after,
        )
