from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Request, Response, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.client_ip import request_client_ip
from app.api.errors import ApiError
from app.core.config import Settings, get_settings
from app.core.security import PasswordService, TokenError, TokenService
from app.db.models import User, UserStatus
from app.db.session import get_db
from app.infra.redis import get_redis
from app.services.access import AccessContext, AccessService
from app.services.api_keys import ApiKeyAccess, authenticate_api_key
from app.services.rate_limit import RateLimiter
from app.services.storage import StorageService
from app.services.user_activity import acquire_authenticated_request_locks

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


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
        clock_skew_seconds=settings.jwt_clock_skew_seconds,
    )


@lru_cache
def get_storage_service() -> StorageService:
    return StorageService(get_settings())


async def redis_dependency() -> AsyncIterator[Redis]:
    yield get_redis()


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
    tokens: Annotated[TokenService, Depends(get_token_service)],
    redis: Annotated[Redis, Depends(redis_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
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

    # Enforce a high, configurable hard ceiling using only verified JWT claims
    # before opening the database-backed user/RBAC path. The role-specific
    # limiter still runs later once live policy has been resolved.
    try:
        decision = await RateLimiter(redis).check(
            key=f"rate:preauth:user:{claims.user_id}",
            limit=settings.authenticated_precheck_requests_per_minute,
        )
    except Exception as error:
        raise ApiError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="rate_limiter_unavailable",
            message="Rate limiting service is temporarily unavailable",
        ) from error
    if not decision.allowed:
        raise ApiError(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="rate_limit_exceeded",
            message="Authenticated request hard limit exceeded",
            details={"retry_after_seconds": decision.retry_after_seconds},
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )

    # For ordinary requests this holds the actor's shared activity lock until
    # the handler transaction ends. RBAC mutation routes are identified from
    # FastAPI's matched route template and take the global exclusive lock first,
    # then deterministic actor/target activity locks, preventing lock inversion.
    await acquire_authenticated_request_locks(session, request, claims.user_id)
    user = await session.scalar(
        select(User).where(User.id == claims.user_id).execution_options(populate_existing=True)
    )
    if user is None or user.status is not UserStatus.ACTIVE or user.retired_at is not None:
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


async def _enforce_access_rate_limit(
    response: Response,
    access: AccessContext,
    redis: Redis,
    settings: Settings,
) -> None:
    rate_limit = access.limits.get("requests_per_minute", settings.default_requests_per_minute)
    if rate_limit is None:
        return
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
            headers={
                "Retry-After": str(decision.retry_after_seconds),
                "X-RateLimit-Limit": str(decision.limit),
                "X-RateLimit-Remaining": "0",
            },
        )


async def require_authenticated_access(
    response: Response,
    access: Annotated[AccessContext, Depends(get_access_context)],
    redis: Annotated[Redis, Depends(redis_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AccessContext:
    """Resolve a live principal and enforce effective limits without requiring an RBAC grant."""

    await _enforce_access_rate_limit(response, access, redis, settings)
    return access


def require_permission(permission: str) -> Callable[..., object]:
    async def dependency(
        response: Response,
        access: Annotated[AccessContext, Depends(get_access_context)],
        redis: Annotated[Redis, Depends(redis_dependency)],
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> AccessContext:
        # Meter both allowed and denied requests. Authorization resolution has
        # already consumed database work, so a 403 must not bypass the account
        # bucket and become an unbounded low-privilege amplification path.
        await _enforce_access_rate_limit(response, access, redis, settings)
        if not access.allows(permission):
            raise ApiError(
                status_code=status.HTTP_403_FORBIDDEN,
                code="permission_denied",
                message=f"Permission required: {permission}",
            )
        return access

    return dependency


def require_any_permission(*permissions: str) -> Callable[..., object]:
    if not permissions:
        raise ValueError("at least one permission is required")

    async def dependency(
        response: Response,
        access: Annotated[AccessContext, Depends(get_access_context)],
        redis: Annotated[Redis, Depends(redis_dependency)],
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> AccessContext:
        await _enforce_access_rate_limit(response, access, redis, settings)
        if not any(access.allows(permission) for permission in permissions):
            raise ApiError(
                status_code=status.HTTP_403_FORBIDDEN,
                code="permission_denied",
                message=f"One permission required: {', '.join(permissions)}",
            )
        return access

    return dependency


async def get_api_key_access(
    cleartext: Annotated[str | None, Depends(api_key_header)],
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis, Depends(redis_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ApiKeyAccess:
    source = request_client_ip(request, settings)
    try:
        decision = await RateLimiter(redis).check(
            key=f"rate:api-key-auth:source:{source}",
            limit=settings.api_key_auth_attempts_per_minute,
        )
    except Exception as error:
        raise ApiError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="rate_limiter_unavailable",
            message="Rate limiting service is temporarily unavailable",
        ) from error
    if not decision.allowed:
        raise ApiError(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="rate_limit_exceeded",
            message="Too many API key authentication attempts",
            details={"retry_after_seconds": decision.retry_after_seconds},
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )
    return await authenticate_api_key(session, cleartext)


def require_api_key_permission(permission: str) -> Callable[..., object]:
    async def dependency(
        response: Response,
        key_access: Annotated[ApiKeyAccess, Depends(get_api_key_access)],
        redis: Annotated[Redis, Depends(redis_dependency)],
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> ApiKeyAccess:
        # Meter before scope authorization so repeated 403 responses cannot
        # bypass either the account-wide or credential-specific bucket.
        await _enforce_access_rate_limit(response, key_access.access, redis, settings)
        try:
            decision = await RateLimiter(redis).check(
                key=f"rate:api-key-family:{key_access.api_key.credential_family_id}",
                limit=key_access.api_key.requests_per_minute,
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
                message="API key request rate limit exceeded",
                details={"retry_after_seconds": decision.retry_after_seconds},
                headers={
                    "Retry-After": str(decision.retry_after_seconds),
                    "X-RateLimit-Limit": str(decision.limit),
                    "X-RateLimit-Remaining": "0",
                },
            )
        if not key_access.access.allows(permission):
            raise ApiError(
                status_code=status.HTTP_403_FORBIDDEN,
                code="api_key_scope_denied",
                message=f"API key permission required: {permission}",
            )
        return key_access

    return dependency


DatabaseSession = Annotated[AsyncSession, Depends(get_db)]
