from uuid import uuid4

import pytest

from app.core.security import PasswordService, TokenError, TokenService


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
