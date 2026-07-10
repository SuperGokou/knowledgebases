from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Response, status
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import ApiError
from app.core.config import Settings, get_settings
from app.core.security import PasswordService, TokenError, TokenService
from app.db.models import User, UserStatus
from app.db.session import get_db
from app.infra.redis import get_redis
from app.services.access import AccessContext, AccessService
from app.services.rate_limit import RateLimiter
from app.services.storage import StorageService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


@lru_cache
def get_password_service() -> PasswordService:
    return PasswordService()


@lru_cache
def get_token_service() -> TokenService:
    settings = get_settings()
    return TokenService(
        secret=settings.jwt_secret.get_secret_value(),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        algorithm=settings.jwt_algorithm,
        access_minutes=settings.access_token_minutes,
        refresh_days=settings.refresh_token_days,
    )


@lru_cache
def get_storage_service() -> StorageService:
    return StorageService(get_settings())


async def redis_dependency() -> AsyncIterator[Redis]:
    yield get_redis()


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[AsyncSession, Depends(get_db)],
    tokens: Annotated[TokenService, Depends(get_token_service)],
) -> User:
    try:
        claims = tokens.decode(token, expected_type="access")
    except TokenError as error:
        raise ApiError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="invalid_token",
            message="The access token is invalid or expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error

    user = await session.scalar(select(User).where(User.id == claims.user_id))
    if user is None or user.status is not UserStatus.ACTIVE:
        raise ApiError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="inactive_user",
            message="The user account is not active",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.token_version != claims.token_version:
        raise ApiError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="token_revoked",
            message="The access token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_access_context(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> AccessContext:
    return await AccessService().resolve(session, user)


def require_permission(permission: str) -> Callable[..., object]:
    async def dependency(
        response: Response,
        access: Annotated[AccessContext, Depends(get_access_context)],
        redis: Annotated[Redis, Depends(redis_dependency)],
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> AccessContext:
        if not access.allows(permission):
            raise ApiError(
                status_code=status.HTTP_403_FORBIDDEN,
                code="permission_denied",
                message=f"Permission required: {permission}",
            )

        rate_limit = access.limits.get("requests_per_minute", settings.default_requests_per_minute)
        if rate_limit is not None:
            try:
                decision = await RateLimiter(redis).check(
                    key=f"rate:user:{access.user.id}",
                    limit=rate_limit,
                )
            except Exception as error:
                raise ApiError(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    code="rate_limiter_unavailable",
                    message="Rate limiting service is temporarily unavailable",
                ) from error
            response.headers["X-RateLimit-Limit"] = str(decision.limit)
            response.headers["X-RateLimit-Remaining"] = str(decision.remaining)
            if not decision.allowed:
                raise ApiError(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    code="rate_limit_exceeded",
                    message="Request rate limit exceeded",
                    details={"retry_after_seconds": decision.retry_after_seconds},
                    headers={"Retry-After": str(decision.retry_after_seconds)},
                )
        return access

    return dependency


DatabaseSession = Annotated[AsyncSession, Depends(get_db)]
