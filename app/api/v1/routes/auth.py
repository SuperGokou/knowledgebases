from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from redis.asyncio import Redis
from sqlalchemy import select

from app.api.client_ip import request_client_ip
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
from app.services.audit import AuditResult, add_audit_event
from app.services.rate_limit import RateLimiter

router = APIRouter()

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


def _pair(
    tokens: TokenService,
    user: User,
    *,
    family_id: UUID | None = None,
    parent_id: UUID | None = None,
) -> tuple[TokenPair, RefreshToken]:
    settings = get_settings()
    access = tokens.create_access_token(user_id=user.id, token_version=user.token_version)
    refresh = tokens.create_refresh_token(user_id=user.id, token_version=user.token_version)
    claims = tokens.decode(refresh, expected_type="refresh")
    record = RefreshToken(
        id=claims.token_id,
        family_id=family_id or uuid4(),
        user_id=user.id,
        parent_id=parent_id,
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
    client_ip = request_client_ip(request, settings)
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
            result=AuditResult.DENIED,
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
        result=AuditResult.SUCCESS,
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
    client_ip = request_client_ip(request, settings)
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
    fingerprint_matches = hmac.compare_digest(
        record.token_hash,
        tokens.fingerprint(payload.refresh_token),
    )
    reuse_attempt = record.revoked_at is not None or not fingerprint_matches
    if reuse_attempt:
        if record.reuse_detected_at is None:
            family = list(
                (
                    await session.scalars(
                        select(RefreshToken)
                        .where(RefreshToken.family_id == record.family_id)
                        .with_for_update()
                    )
                ).all()
            )
            for family_token in family:
                if family_token.revoked_at is None:
                    family_token.revoked_at = now
                family_token.reuse_detected_at = now
            user.token_version += 1
            add_audit_event(
                session,
                action="auth.token.reuse_detected",
                result=AuditResult.DENIED,
                resource_type="refresh_token_family",
                resource_id=str(record.family_id),
                actor_id=user.id,
                request_id=getattr(request.state, "request_id", None),
                details={"compromised_token_id": str(record.id)},
            )
            await session.commit()
        else:
            await session.rollback()
        raise ApiError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="refresh_token_reuse_detected",
            message="Refresh token reuse was detected and the session was revoked",
        )

    invalid = (
        as_utc(record.expires_at) <= now
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
    pair, replacement = _pair(
        tokens,
        user,
        family_id=record.family_id,
        parent_id=record.id,
    )
    session.add(replacement)
    # PostgreSQL enforces this self-referential foreign key immediately. Flush
    # the successor row before linking the predecessor to it; otherwise the
    # unit of work may emit the UPDATE before the INSERT.
    await session.flush()
    record.replaced_by_id = replacement.id
    add_audit_event(
        session,
        action="auth.token.refreshed",
        result=AuditResult.SUCCESS,
        resource_type="user",
        resource_id=str(user.id),
        actor_id=user.id,
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return pair


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    payload: RefreshRequest,
    request: Request,
    response: Response,
    session: DatabaseSession,
    tokens: Annotated[TokenService, Depends(get_token_service)],
) -> None:
    """Revoke one refresh-token family member without exposing token validity."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    try:
        claims = tokens.decode(payload.refresh_token, expected_type="refresh")
    except TokenError:
        return

    record = await session.scalar(
        select(RefreshToken).where(RefreshToken.id == claims.token_id).with_for_update()
    )
    if record is None or not hmac.compare_digest(
        record.token_hash,
        tokens.fingerprint(payload.refresh_token),
    ):
        await session.rollback()
        return

    if record.revoked_at is None:
        record.revoked_at = datetime.now(UTC)
        add_audit_event(
            session,
            action="auth.logout.succeeded",
            result=AuditResult.SUCCESS,
            resource_type="user",
            resource_id=str(record.user_id),
            actor_id=record.user_id,
            request_id=getattr(request.state, "request_id", None),
        )
        await session.commit()
