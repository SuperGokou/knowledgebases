from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

import jwt
from jwt import InvalidTokenError
from pwdlib import PasswordHash

TokenType = Literal["access", "refresh"]


class TokenError(ValueError):
    """Raised when a JWT is invalid or has the wrong purpose."""


class PasswordService:
    def __init__(self) -> None:
        self._hasher = PasswordHash.recommended()
        self.dummy_hash = self._hasher.hash("constant-time-dummy-password")

    def hash(self, password: str) -> str:
        if len(password) < 12:
            raise ValueError("password must contain at least 12 characters")
        return self._hasher.hash(password)

    def verify(self, password: str, encoded_hash: str) -> bool:
        return self._hasher.verify(password, encoded_hash)


@dataclass(frozen=True, slots=True)
class TokenClaims:
    user_id: UUID
    token_version: int
    token_type: TokenType
    token_id: UUID
    expires_at: datetime


class TokenService:
    def __init__(
        self,
        *,
        secret: str,
        issuer: str,
        audience: str,
        algorithm: str = "HS256",
        access_minutes: int = 15,
        refresh_days: int = 7,
    ) -> None:
        if len(secret) < 32:
            raise ValueError("JWT secret must contain at least 32 characters")
        self._secret = secret
        self._issuer = issuer
        self._audience = audience
        self._algorithm = algorithm
        self._access_lifetime = timedelta(minutes=access_minutes)
        self._refresh_lifetime = timedelta(days=refresh_days)

    def create_access_token(self, *, user_id: UUID, token_version: int) -> str:
        return self._create(user_id, token_version, "access", self._access_lifetime)

    def create_refresh_token(self, *, user_id: UUID, token_version: int) -> str:
        return self._create(user_id, token_version, "refresh", self._refresh_lifetime)

    def _create(
        self,
        user_id: UUID,
        token_version: int,
        token_type: TokenType,
        lifetime: timedelta,
    ) -> str:
        now = datetime.now(UTC)
        payload = {
            "sub": str(user_id),
            "ver": token_version,
            "typ": token_type,
            "jti": str(uuid4()),
            "iat": now,
            "nbf": now,
            "exp": now + lifetime,
            "iss": self._issuer,
            "aud": self._audience,
        }
        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    def decode(self, token: str, *, expected_type: TokenType) -> TokenClaims:
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["sub", "ver", "typ", "jti", "iat", "nbf", "exp"]},
            )
            token_type = payload["typ"]
            if token_type != expected_type:
                raise TokenError(f"unexpected token type: {token_type}")
            return TokenClaims(
                user_id=UUID(payload["sub"]),
                token_version=int(payload["ver"]),
                token_type=token_type,
                token_id=UUID(payload["jti"]),
                expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
            )
        except TokenError:
            raise
        except (InvalidTokenError, KeyError, TypeError, ValueError) as error:
            raise TokenError("invalid token") from error

    @staticmethod
    def fingerprint(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
