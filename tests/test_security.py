from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest

from app.api import dependencies
from app.core.config import Settings
from app.core.security import PasswordService, TokenError, TokenService


def _token_with_future_not_before(*, secret: str, seconds: int) -> tuple[str, UUID]:
    user_id = uuid4()
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": str(user_id),
            "ver": 0,
            "typ": "access",
            "jti": str(uuid4()),
            "iat": now,
            "nbf": now + timedelta(seconds=seconds),
            "exp": now + timedelta(minutes=1),
            "iss": "knowledge-base",
            "aud": "kb-api",
        },
        secret,
        algorithm="HS256",
    )
    return token, user_id


def test_passwords_use_one_way_hashing() -> None:
    service = PasswordService()
    encoded = service.hash("correct horse battery staple")

    assert encoded != "correct horse battery staple"
    assert service.verify("correct horse battery staple", encoded)
    assert not service.verify("wrong password", encoded)


def test_access_token_round_trip_preserves_identity_and_token_version() -> None:
    service = TokenService(secret="x" * 64, issuer="knowledge-base", audience="kb-api")
    user_id = uuid4()

    token = service.create_access_token(user_id=user_id, token_version=7)
    claims = service.decode(token, expected_type="access")

    assert claims.user_id == user_id
    assert claims.token_version == 7
    assert claims.token_type == "access"


def test_token_type_cannot_be_substituted() -> None:
    service = TokenService(secret="x" * 64, issuer="knowledge-base", audience="kb-api")
    refresh = service.create_refresh_token(user_id=uuid4(), token_version=0)

    with pytest.raises(TokenError, match="token type"):
        service.decode(refresh, expected_type="access")


def test_token_signed_with_another_secret_is_rejected() -> None:
    issuer = TokenService(secret="a" * 64, issuer="knowledge-base", audience="kb-api")
    verifier = TokenService(secret="b" * 64, issuer="knowledge-base", audience="kb-api")
    token = issuer.create_access_token(user_id=uuid4(), token_version=0)

    with pytest.raises(TokenError):
        verifier.decode(token, expected_type="access")


def test_token_accepts_not_before_within_configured_clock_skew() -> None:
    secret = "x" * 64
    service = TokenService(
        secret=secret,
        issuer="knowledge-base",
        audience="kb-api",
        clock_skew_seconds=3,
    )
    token, user_id = _token_with_future_not_before(secret=secret, seconds=2)

    claims = service.decode(token, expected_type="access")

    assert claims.user_id == user_id


def test_token_rejects_not_before_beyond_configured_clock_skew() -> None:
    secret = "x" * 64
    service = TokenService(
        secret=secret,
        issuer="knowledge-base",
        audience="kb-api",
        clock_skew_seconds=3,
    )
    token, _user_id = _token_with_future_not_before(secret=secret, seconds=10)

    with pytest.raises(TokenError):
        service.decode(token, expected_type="access")


def test_token_dependency_injects_the_configured_clock_skew(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "x" * 64
    settings = Settings(
        _env_file=None,
        jwt_secret=secret,
        jwt_issuer="knowledge-base",
        jwt_audience="kb-api",
        jwt_clock_skew_seconds=3,
    )
    monkeypatch.setattr(dependencies, "get_settings", lambda: settings)
    dependencies.get_token_service.cache_clear()
    token, user_id = _token_with_future_not_before(secret=secret, seconds=2)

    try:
        claims = dependencies.get_token_service().decode(token, expected_type="access")
    finally:
        dependencies.get_token_service.cache_clear()

    assert claims.user_id == user_id
