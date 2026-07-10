from __future__ import annotations

from anyio import CapacityLimiter, to_thread

from app.core.security import PasswordService

_password_work_limiter = CapacityLimiter(4)


async def verify_password(
    service: PasswordService,
    password: str,
    encoded_hash: str,
) -> bool:
    return await to_thread.run_sync(
        service.verify,
        password,
        encoded_hash,
        limiter=_password_work_limiter,
    )


async def hash_password(service: PasswordService, password: str) -> str:
    return await to_thread.run_sync(
        service.hash,
        password,
        limiter=_password_work_limiter,
    )
