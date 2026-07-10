from __future__ import annotations

import hashlib
import hmac
import time
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from redis.asyncio import Redis
from sqlalchemy import select

from app.api.dependencies import (
    DatabaseSession,
    get_access_context,
    get_password_service,
    get_token_service,
    redis_dependency,
)
from app.api.errors import ApiError
from app.core.config import Settings, get_settings
from app.core.password_async import verify_password
from app.core.security import PasswordService, TokenError, TokenService
from app.core.time import as_utc
from app.db.models import RefreshToken, User, UserStatus
from app.schemas.auth import AuthMe, RefreshRequest, TokenPair
from app.services.access import AccessContext
from app.services.audit import add_audit_event
from app.services.rate_limit import RateLimiter

router = APIRouter()

_BFF_CLIENT_IP_WINDOW_SECONDS = 60
_BFF_CLIENT_IP_HEADERS = (
    "x-kb-client-ip",
    "x-kb-client-timestamp",
    "x-kb-client-signature",
)


def _normalized_ip(value: str | None) -> str | None:
    if value is None or not value or value != value.strip() or len(value) > 64 or "%" in value:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def _verified_bff_client_ip(request: Request, settings: Settings) -> str | None:
    client_ip = request.headers.get(_BFF_CLIENT_IP_HEADERS[0])
    timestamp = request.headers.get(_BFF_CLIENT_IP_HEADERS[1])
    signature = request.headers.get(_BFF_CLIENT_IP_HEADERS[2])
    if client_ip is None or timestamp is None or signature is None:
        return None

    secret = (
        settings.bff_shared_secret.get_secret_value()
        if settings.bff_shared_secret is not None
        else ""
    )
    normalized_ip = _normalized_ip(client_ip)
    if not secret or normalized_ip is None:
        return None
    if (
        not timestamp.isascii()
        or not timestamp.isdigit()
        or len(timestamp) > 20
        or str(int(timestamp)) != timestamp
    ):
        return None
    timestamp_value = int(timestamp)
    if abs(int(time.time()) - timestamp_value) > _BFF_CLIENT_IP_WINDOW_SECONDS:
        return None
    if len(signature) != 64 or any(character not in "0123456789abcdef" for character in signature):
        return None

    canonical = f"v1\n{timestamp}\n{client_ip}".encode()
    expected = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    return normalized_ip


def _auth_client_ip(request: Request, settings: Settings) -> str:
    peer_ip = request.client.host if request.client else "unknown"
    bff_secret_configured = bool(
        settings.bff_shared_secret is not None
        and settings.bff_shared_secret.get_secret_value()
    )
    signed_headers_present = any(
        request.headers.get(name) is not None for name in _BFF_CLIENT_IP_HEADERS
    )
    if bff_secret_configured and signed_headers_present:
        verified_ip = _verified_bff_client_ip(request, settings)
        if verified_ip is None:
            raise ApiError(
                status_code=400,
                code="invalid_bff_signature",
                message="BFF client IP signature is invalid or expired",
            )
        return verified_ip

    if settings.serverless:
        for header in ("x-vercel-forwarded-for", "x-forwarded-for"):
            forwarded_ip = _normalized_ip(request.headers.get(header))
            if forwarded_ip is not None:
                return forwarded_ip
    return peer_ip


@router.get("/me", response_model=AuthMe)
async def current_session(
    response: Response,
    access: Annotated[AccessContext, Depends(get_access_context)],
) -> AuthMe:
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return AuthMe(
        id=access.user.id,
        email=access.user.email,
        display_name=access.user.display_name,
        status=access.user.status,
        is_superuser=access.user.is_superuser,
        permission_codes=sorted(access.permissions),
        role_ids=sorted(access.role_ids, key=str),
        limits=access.limits,
    )


async def _check_auth_rate_limit(
    *,
    redis: Redis,
    key: str,
    limit: int,
) -> None:
    try:
        decision = await RateLimiter(redis).check(key=key, limit=limit)
    except Exception as error:
        raise ApiError(
            status_code=503,
            code="rate_limiter_unavailable",
            message="Authentication rate limiter is temporarily unavailable",
        ) from error
    if not decision.allowed:
        raise ApiError(
            status_code=429,
            code="rate_limit_exceeded",
            message="Too many authentication attempts",
            details={"retry_after_seconds": decision.retry_after_seconds},
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )


def _pair(tokens: TokenService, user: User) -> tuple[TokenPair, RefreshToken]:
    settings = get_settings()
    access = tokens.create_access_token(user_id=user.id, token_version=user.token_version)
    refresh = tokens.create_refresh_token(user_id=user.id, token_version=user.token_version)
    claims = tokens.decode(refresh, expected_type="refresh")
    record = RefreshToken(
        id=claims.token_id,
        user_id=user.id,
        token_hash=tokens.fingerprint(refresh),
        expires_at=claims.expires_at,
    )
    return (
        TokenPair(
            access_token=access,
            refresh_token=refresh,
            expires_in=settings.access_token_minutes * 60,
        ),
        record,
    )


@router.post("/token", response_model=TokenPair)
async def login(
    request: Request,
    response: Response,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: DatabaseSession,
    passwords: Annotated[PasswordService, Depends(get_password_service)],
    tokens: Annotated[TokenService, Depends(get_token_service)],
    redis: Annotated[Redis, Depends(redis_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenPair:
    email = form.username.strip().lower()
    client_ip = _auth_client_ip(request, settings)
    await _check_auth_rate_limit(
        redis=redis,
        key=f"auth:login:ip:{client_ip}",
        limit=settings.login_attempts_per_minute,
    )
    account_key = hashlib.sha256(email.encode("utf-8")).hexdigest()
    await _check_auth_rate_limit(
        redis=redis,
        key=f"auth:login:account:{account_key}",
        limit=settings.login_attempts_per_account_per_minute,
    )
    user = await session.scalar(select(User).where(User.email == email))
    encoded_hash = user.password_hash if user is not None else passwords.dummy_hash
    password_is_valid = await verify_password(passwords, form.password, encoded_hash)
    if user is None or user.status is not UserStatus.ACTIVE or not password_is_valid:
        add_audit_event(
            session,
            action="auth.login.denied",
            resource_type="user",
            request_id=getattr(request.state, "request_id", None),
            ip_address=request.client.host if request.client else None,
            details={"email": email},
        )
        await session.commit()
        raise ApiError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="invalid_credentials",
            message="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    pair, refresh_record = _pair(tokens, user)
    user.last_login_at = datetime.now(UTC)
    session.add(refresh_record)
    add_audit_event(
        session,
        action="auth.login.succeeded",
        resource_type="user",
        resource_id=str(user.id),
        actor_id=user.id,
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
    )
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return pair


@router.post("/refresh", response_model=TokenPair)
async def refresh_tokens(
    payload: RefreshRequest,
    request: Request,
    response: Response,
    session: DatabaseSession,
    tokens: Annotated[TokenService, Depends(get_token_service)],
    redis: Annotated[Redis, Depends(redis_dependency)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenPair:
    client_ip = _auth_client_ip(request, settings)
    await _check_auth_rate_limit(
        redis=redis,
        key=f"auth:refresh:ip:{client_ip}",
        limit=settings.refresh_attempts_per_minute,
    )
    try:
        claims = tokens.decode(payload.refresh_token, expected_type="refresh")
    except TokenError as error:
        raise ApiError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="invalid_refresh_token",
            message="Refresh token is invalid or expired",
        ) from error

    record = await session.scalar(
        select(RefreshToken).where(RefreshToken.id == claims.token_id).with_for_update()
    )
    user = await session.scalar(select(User).where(User.id == claims.user_id))
    now = datetime.now(UTC)
    if record is None or user is None:
        await session.rollback()
        raise ApiError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="invalid_refresh_token",
            message="Refresh token is invalid or has been revoked",
        )
    invalid = (
        record.revoked_at is not None
        or as_utc(record.expires_at) <= now
        or record.token_hash != tokens.fingerprint(payload.refresh_token)
        or user.status is not UserStatus.ACTIVE
        or user.token_version != claims.token_version
    )
    if invalid:
        await session.rollback()
        raise ApiError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="invalid_refresh_token",
            message="Refresh token is invalid or has been revoked",
        )

    record.revoked_at = now
    pair, replacement = _pair(tokens, user)
    session.add(replacement)
    add_audit_event(
        session,
        action="auth.token.refreshed",
        resource_type="user",
        resource_id=str(user.id),
        actor_id=user.id,
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return pair
