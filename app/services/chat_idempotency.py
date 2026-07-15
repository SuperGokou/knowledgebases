from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import os
import zlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import ApiError
from app.core.config import Settings
from app.db.models import ChatIdempotencyRecord, ChatIdempotencyStatus
from app.schemas.chat import ChatQueryRequest, ChatQueryResponse
from app.services.chat_replay_authorization import ChatAuthorizationSnapshot

_ENCODING = "aesgcm-zlib-json-v1"
_AES_256_KEY_BYTES = 32
_AES_GCM_NONCE_BYTES = 12
_AES_GCM_TAG_BYTES = 16
_LOGGER = logging.getLogger(__name__)
AuthorizationCallback = Callable[[AsyncSession], Awaitable[ChatAuthorizationSnapshot]]


@dataclass(frozen=True, slots=True)
class ChatIdempotencyPrincipal:
    """A pseudonymized namespace for a user or stable API credential family.

    The persisted hash domain deliberately remains ``api_key`` for backward
    compatibility with claims created before credential families existed.  A
    migrated family's UUID is initialized from the original key UUID, so
    changing only the subject semantics preserves fail-closed replay across the
    0017 -> 0018 upgrade boundary.
    """

    kind: Literal["user", "api_key"]
    subject_id: UUID

    @classmethod
    def for_user(cls, user_id: UUID) -> ChatIdempotencyPrincipal:
        return cls(kind="user", subject_id=user_id)

    @classmethod
    def for_api_key(cls, credential_family_id: UUID) -> ChatIdempotencyPrincipal:
        return cls(kind="api_key", subject_id=credential_family_id)

    def fingerprint(self) -> str:
        return _sha256(f"chat-principal-v1\0{self.kind}\0{self.subject_id}")


@dataclass(frozen=True, slots=True)
class _ChatReplayKeyring:
    active_version: int
    keys: Mapping[int, bytes]


def _sha256(value: str | bytes) -> str:
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(payload).hexdigest()


def _request_hash(request: ChatQueryRequest) -> str:
    canonical = json.dumps(
        request.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(b"chat-query-request-v1\0" + canonical)


def _decode_key_material(value: str) -> bytes:
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise RuntimeError(
            "chat replay encryption keyring contains invalid key material"
        ) from error
    if len(decoded) != _AES_256_KEY_BYTES:
        raise RuntimeError("chat replay encryption keyring contains invalid key material")
    return decoded


def _load_replay_keyring(settings: Settings) -> _ChatReplayKeyring:
    active_version = settings.chat_replay_active_key_version
    configured = settings.chat_replay_encryption_keys
    if active_version is None or not configured or active_version not in configured:
        raise RuntimeError("chat replay encryption keyring is not configured")
    keys = {
        version: _decode_key_material(secret.get_secret_value())
        for version, secret in configured.items()
    }
    return _ChatReplayKeyring(active_version=active_version, keys=keys)


def _response_aad(record: ChatIdempotencyRecord, key_version: int) -> bytes:
    if record.knowledge_base_id is None or record.knowledge_base_content_version is None:
        raise ValueError("chat replay resource snapshot is incomplete")
    canonical = json.dumps(
        {
            "content_version": record.knowledge_base_content_version,
            "key_version": key_version,
            "knowledge_base_id": str(record.knowledge_base_id),
            "principal_fingerprint": record.principal_hash,
            "record_id": str(record.id),
            "request_hash": record.request_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return b"chat-replay-aad-v1\0" + canonical


def _encode_response(
    record: ChatIdempotencyRecord,
    response: ChatQueryResponse,
    maximum_bytes: int,
    keyring: _ChatReplayKeyring,
) -> tuple[bytes, int, int, bytes]:
    raw = json.dumps(
        response.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if not raw or len(raw) > maximum_bytes:
        raise ValueError("chat response exceeds the durable replay boundary")
    compressed = zlib.compress(raw, level=6)
    if not compressed or len(compressed) + _AES_GCM_TAG_BYTES > maximum_bytes:
        raise ValueError("compressed chat response exceeds the durable replay boundary")
    key_version = keyring.active_version
    nonce = os.urandom(_AES_GCM_NONCE_BYTES)
    ciphertext = AESGCM(keyring.keys[key_version]).encrypt(
        nonce,
        compressed,
        _response_aad(record, key_version),
    )
    if not ciphertext or len(ciphertext) > maximum_bytes:
        raise ValueError("encrypted chat response exceeds the durable replay boundary")
    return ciphertext, len(raw), key_version, nonce


def _decode_response(
    record: ChatIdempotencyRecord,
    maximum_bytes: int,
    keyring: _ChatReplayKeyring,
) -> ChatQueryResponse:
    if (
        record.response_encoding != _ENCODING
        or record.response_body is None
        or record.response_size_bytes is None
        or not 0 < record.response_size_bytes <= maximum_bytes
        or record.response_key_version is None
        or record.response_key_version < 1
        or record.response_nonce is None
        or len(record.response_nonce) != _AES_GCM_NONCE_BYTES
    ):
        raise ValueError("chat idempotency response metadata is invalid")
    ciphertext = bytes(record.response_body)
    if len(ciphertext) <= _AES_GCM_TAG_BYTES or len(ciphertext) > maximum_bytes:
        raise ValueError("chat idempotency response payload is invalid")
    key = keyring.keys.get(record.response_key_version)
    if key is None:
        raise ValueError("chat idempotency replay key is unavailable")
    try:
        compressed = AESGCM(key).decrypt(
            bytes(record.response_nonce),
            ciphertext,
            _response_aad(record, record.response_key_version),
        )
    except InvalidTag as error:
        raise ValueError("chat idempotency response authentication failed") from error
    if not compressed or len(compressed) > maximum_bytes - _AES_GCM_TAG_BYTES:
        raise ValueError("chat idempotency response payload is invalid")

    decompressor = zlib.decompressobj()
    raw = decompressor.decompress(compressed, maximum_bytes + 1)
    if len(raw) > maximum_bytes or decompressor.unconsumed_tail:
        raise ValueError("chat idempotency response exceeded its decompression boundary")
    raw += decompressor.flush(maximum_bytes + 1 - len(raw))
    if (
        len(raw) > maximum_bytes
        or not decompressor.eof
        or decompressor.unused_data
        or len(raw) != record.response_size_bytes
    ):
        raise ValueError("chat idempotency response integrity validation failed")
    return ChatQueryResponse.model_validate_json(raw)


def _clear_response(record: ChatIdempotencyRecord) -> None:
    record.response_body = None
    record.response_encoding = None
    record.response_size_bytes = None
    record.response_key_version = None
    record.response_nonce = None


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _conflict_error() -> ApiError:
    return ApiError(
        status_code=409,
        code="idempotency_conflict",
        message="Idempotency key was already used with another chat request",
    )


def _in_progress_error() -> ApiError:
    return ApiError(
        status_code=409,
        code="idempotency_in_progress",
        message="The original chat request is still processing",
        headers={"Retry-After": "5"},
    )


def _outcome_unknown_error() -> ApiError:
    return ApiError(
        status_code=409,
        code="idempotency_outcome_unknown",
        message="The original chat request outcome cannot be determined safely",
    )


def _resource_changed_error() -> ApiError:
    return ApiError(
        status_code=409,
        code="idempotency_resource_changed",
        message="Knowledge-base content changed after the original chat request",
    )


async def _claim_or_replay(
    session: AsyncSession,
    settings: Settings,
    keyring: _ChatReplayKeyring,
    *,
    principal_hash: str,
    key_hash: str,
    request_hash: str,
    request_knowledge_base_id: UUID,
    authorize: AuthorizationCallback,
) -> tuple[ChatIdempotencyRecord, ChatQueryResponse | None]:
    for _ in range(4):
        snapshot = await authorize(session)
        if snapshot.knowledge_base_id != request_knowledge_base_id:
            await session.rollback()
            raise _resource_changed_error()
        candidate = ChatIdempotencyRecord(
            principal_hash=principal_hash,
            idempotency_key_hash=key_hash,
            request_hash=request_hash,
            knowledge_base_id=snapshot.knowledge_base_id,
            knowledge_base_content_version=snapshot.content_version,
            status=ChatIdempotencyStatus.PROCESSING,
        )
        claimed = False
        try:
            async with session.begin_nested():
                session.add(candidate)
                await session.flush()
                claimed = True
        except IntegrityError:
            claimed = False
        if claimed:
            await session.commit()
            return candidate, None

        existing = await session.scalar(
            select(ChatIdempotencyRecord)
            .where(
                ChatIdempotencyRecord.principal_hash == principal_hash,
                ChatIdempotencyRecord.idempotency_key_hash == key_hash,
            )
            .execution_options(populate_existing=True)
            .with_for_update()
        )
        if existing is None:
            await session.rollback()
            continue
        if existing.request_hash != request_hash:
            await session.rollback()
            raise _conflict_error()

        now = datetime.now(UTC)
        if (
            existing.status
            in {
                ChatIdempotencyStatus.COMPLETED,
                ChatIdempotencyStatus.OUTCOME_UNKNOWN,
                ChatIdempotencyStatus.INVALIDATED,
            }
            and existing.expires_at is not None
            and _as_utc(existing.expires_at) <= now
        ):
            await session.delete(existing)
            await session.commit()
            continue

        if existing.status is ChatIdempotencyStatus.INVALIDATED:
            await session.rollback()
            raise _resource_changed_error()
        if existing.status is ChatIdempotencyStatus.OUTCOME_UNKNOWN:
            await session.rollback()
            raise _outcome_unknown_error()
        if (
            existing.knowledge_base_id != snapshot.knowledge_base_id
            or existing.knowledge_base_content_version != snapshot.content_version
        ):
            existing.status = ChatIdempotencyStatus.INVALIDATED
            _clear_response(existing)
            existing.completed_at = now
            existing.expires_at = now + timedelta(seconds=settings.chat_idempotency_ttl_seconds)
            await session.commit()
            raise _resource_changed_error()

        if existing.status is ChatIdempotencyStatus.COMPLETED:
            try:
                response = _decode_response(
                    existing,
                    settings.chat_idempotency_response_max_bytes,
                    keyring,
                )
            except (ValueError, zlib.error):
                existing.status = ChatIdempotencyStatus.OUTCOME_UNKNOWN
                _clear_response(existing)
                existing.completed_at = now
                existing.expires_at = now + timedelta(seconds=settings.chat_idempotency_ttl_seconds)
                await session.commit()
                raise _outcome_unknown_error() from None
            await session.rollback()
            return existing, response

        last_activity = _as_utc(existing.updated_at or existing.created_at)
        stale_before = now - timedelta(seconds=settings.chat_idempotency_processing_timeout_seconds)
        if last_activity <= stale_before:
            existing.status = ChatIdempotencyStatus.OUTCOME_UNKNOWN
            existing.completed_at = now
            existing.expires_at = now + timedelta(seconds=settings.chat_idempotency_ttl_seconds)
            await session.commit()
            raise _outcome_unknown_error()

        await session.rollback()
        raise _in_progress_error()

    raise _outcome_unknown_error()


async def _store_completed_response(
    session: AsyncSession,
    settings: Settings,
    keyring: _ChatReplayKeyring,
    *,
    record_id: UUID,
    request_hash: str,
    response: ChatQueryResponse,
    authorize: AuthorizationCallback,
) -> None:
    snapshot = await authorize(session)
    record = await session.scalar(
        select(ChatIdempotencyRecord)
        .where(ChatIdempotencyRecord.id == record_id)
        .execution_options(populate_existing=True)
        .with_for_update()
    )
    if record is None or record.request_hash != request_hash:
        raise RuntimeError("chat idempotency claim is no longer active")
    now = datetime.now(UTC)
    if record.status is ChatIdempotencyStatus.INVALIDATED:
        await session.rollback()
        raise _resource_changed_error()
    if record.status is not ChatIdempotencyStatus.PROCESSING:
        raise RuntimeError("chat idempotency claim is no longer active")
    if (
        response.knowledge_base_id != snapshot.knowledge_base_id
        or record.knowledge_base_id != snapshot.knowledge_base_id
        or record.knowledge_base_content_version != snapshot.content_version
    ):
        record.status = ChatIdempotencyStatus.INVALIDATED
        _clear_response(record)
        record.completed_at = now
        record.expires_at = now + timedelta(seconds=settings.chat_idempotency_ttl_seconds)
        await session.commit()
        raise _resource_changed_error()
    encoded, raw_size, key_version, nonce = _encode_response(
        record,
        response,
        settings.chat_idempotency_response_max_bytes,
        keyring,
    )
    record.status = ChatIdempotencyStatus.COMPLETED
    record.response_body = encoded
    record.response_encoding = _ENCODING
    record.response_size_bytes = raw_size
    record.response_key_version = key_version
    record.response_nonce = nonce
    record.completed_at = now
    record.expires_at = now + timedelta(seconds=settings.chat_idempotency_ttl_seconds)
    await session.commit()


async def _mark_outcome_unknown(
    session: AsyncSession,
    settings: Settings,
    *,
    record_id: UUID,
    request_hash: str,
) -> None:
    try:
        await session.rollback()
        record = await session.scalar(
            select(ChatIdempotencyRecord)
            .where(ChatIdempotencyRecord.id == record_id)
            .execution_options(populate_existing=True)
            .with_for_update()
        )
        if (
            record is not None
            and record.request_hash == request_hash
            and record.status is ChatIdempotencyStatus.PROCESSING
        ):
            now = datetime.now(UTC)
            record.status = ChatIdempotencyStatus.OUTCOME_UNKNOWN
            _clear_response(record)
            record.completed_at = now
            record.expires_at = now + timedelta(seconds=settings.chat_idempotency_ttl_seconds)
        await session.commit()
    except Exception as persistence_error:
        await session.rollback()
        _LOGGER.error(
            "Failed to persist an unknown chat idempotency outcome",
            extra={
                "record_id": str(record_id),
                "error_class": type(persistence_error).__name__,
            },
        )


async def execute_chat_query_idempotently(
    session: AsyncSession,
    settings: Settings,
    *,
    principal: ChatIdempotencyPrincipal,
    idempotency_key: str,
    request: ChatQueryRequest,
    operation: Callable[[], Awaitable[ChatQueryResponse]],
    authorize: AuthorizationCallback,
) -> ChatQueryResponse:
    """Execute one logical chat request once and durably replay only known final results."""

    bind = session.bind
    if bind is None:
        raise RuntimeError("chat operation session has no database bind")
    # Resolve and validate the external keyring before creating a durable claim
    # or invoking retrieval/model code. Missing key material can never degrade to
    # a plaintext response or an execution whose outcome cannot be replayed.
    keyring = _load_replay_keyring(settings)
    # Authentication dependencies may have opened a read transaction. Close it
    # before the separate ledger session takes its linearization locks. A commit
    # preserves the already-resolved ORM identity (expire_on_commit=False) while
    # the ledger remains an entirely separate transaction boundary.
    await session.commit()
    request_hash = _request_hash(request)
    async with AsyncSession(bind=bind, expire_on_commit=False) as ledger_session:
        record, replay = await _claim_or_replay(
            ledger_session,
            settings,
            keyring,
            principal_hash=principal.fingerprint(),
            key_hash=_sha256(f"chat-idempotency-key-v1\0{idempotency_key}"),
            request_hash=request_hash,
            request_knowledge_base_id=request.knowledge_base_id,
            authorize=authorize,
        )
        if replay is not None:
            return replay

        try:
            response = await operation()
        except asyncio.CancelledError:
            await _mark_outcome_unknown(
                ledger_session,
                settings,
                record_id=record.id,
                request_hash=request_hash,
            )
            raise
        except Exception as operation_error:
            await _mark_outcome_unknown(
                ledger_session,
                settings,
                record_id=record.id,
                request_hash=request_hash,
            )
            _LOGGER.warning(
                "Chat request ended without a safely replayable outcome",
                extra={
                    "record_id": str(record.id),
                    "error_class": type(operation_error).__name__,
                },
            )
            if (
                isinstance(operation_error, ApiError)
                and operation_error.code == "idempotency_outcome_unknown"
            ):
                raise operation_error
            raise _outcome_unknown_error() from None

        try:
            await _store_completed_response(
                ledger_session,
                settings,
                keyring,
                record_id=record.id,
                request_hash=request_hash,
                response=response,
                authorize=authorize,
            )
        except ApiError as finalization_error:
            if finalization_error.code == "idempotency_resource_changed":
                raise
            await _mark_outcome_unknown(
                ledger_session,
                settings,
                record_id=record.id,
                request_hash=request_hash,
            )
            raise
        except Exception as finalization_error:
            await _mark_outcome_unknown(
                ledger_session,
                settings,
                record_id=record.id,
                request_hash=request_hash,
            )
            _LOGGER.error(
                "Chat response could not be persisted for safe replay",
                extra={
                    "record_id": str(record.id),
                    "error_class": type(finalization_error).__name__,
                },
            )
            raise _outcome_unknown_error() from None
        return response


async def cleanup_chat_idempotency_records(
    session: AsyncSession,
    settings: Settings,
    *,
    batch_size: int,
    max_batches: int = 1,
    now: datetime | None = None,
) -> int:
    """Expire terminal records and fail closed abandoned processing claims.

    Each class receives its own bounded quota so a sustained stream of abandoned
    processing rows cannot starve deletion of expired sensitive responses.
    """

    if batch_size <= 0 or max_batches <= 0:
        raise ValueError("chat idempotency cleanup limits must be positive")
    current = now or datetime.now(UTC)
    stale_before = current - timedelta(seconds=settings.chat_idempotency_processing_timeout_seconds)
    total = 0
    for _ in range(max_batches):
        processing = list(
            (
                await session.scalars(
                    select(ChatIdempotencyRecord)
                    .where(
                        ChatIdempotencyRecord.status == ChatIdempotencyStatus.PROCESSING,
                        ChatIdempotencyRecord.updated_at <= stale_before,
                    )
                    .order_by(ChatIdempotencyRecord.updated_at, ChatIdempotencyRecord.id)
                    .limit(batch_size)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        for record in processing:
            record.status = ChatIdempotencyStatus.OUTCOME_UNKNOWN
            record.completed_at = current
            record.expires_at = current + timedelta(seconds=settings.chat_idempotency_ttl_seconds)

        expired = list(
            (
                await session.scalars(
                    select(ChatIdempotencyRecord)
                    .where(
                        ChatIdempotencyRecord.status.in_(
                            [
                                ChatIdempotencyStatus.COMPLETED,
                                ChatIdempotencyStatus.OUTCOME_UNKNOWN,
                                ChatIdempotencyStatus.INVALIDATED,
                            ]
                        ),
                        ChatIdempotencyRecord.expires_at <= current,
                    )
                    .order_by(ChatIdempotencyRecord.expires_at, ChatIdempotencyRecord.id)
                    .limit(batch_size)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        for record in expired:
            await session.delete(record)
        await session.commit()
        total += len(processing) + len(expired)
        if len(processing) < batch_size and len(expired) < batch_size:
            break
    return total
