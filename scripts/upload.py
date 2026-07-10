#!/usr/bin/env python3
"""Resumable command-line uploader for the enterprise knowledge-base API.

The API authenticates and authorizes the user, reserves quota, and returns
short-lived S3-compatible presigned URLs. File bytes go directly to object
storage; bearer and refresh tokens are never sent to that storage endpoint.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import getpass
import hashlib
import json
import mimetypes
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Any, BinaryIO, cast

USER_AGENT = "knowledge-base-uploader/1.0"
MAX_API_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024
TRANSIENT_HTTP_STATUSES = {408, 425, 429, 500, 502, 503, 504}
TRANSIENT_STORAGE_CODES = {"InternalError", "RequestTimeout", "SlowDown", "ServiceUnavailable"}
SUPPORTED_EXTENSIONS = {
    ".txt",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".csv",
    ".pdf",
    ".ppt",
    ".pptx",
}


class UploadClientError(Exception):
    """A safe, user-facing failure that does not contain credentials or signed URLs."""


class ApiRequestError(UploadClientError):
    def __init__(
        self,
        *,
        status: int,
        code: str,
        message: str,
        request_id: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.request_id = request_id
        self.retry_after = retry_after
        suffix = f" (request_id={request_id})" if request_id else ""
        super().__init__(f"API {status} {code}: {message}{suffix}")


class StorageRequestError(UploadClientError):
    def __init__(
        self,
        *,
        status: int | None,
        code: str,
        message: str,
        can_refresh_url: bool = False,
    ) -> None:
        self.status = status
        self.code = code
        self.can_refresh_url = can_refresh_url
        prefix = f"object storage {status}" if status is not None else "object storage"
        super().__init__(f"{prefix} {code}: {message}")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Turn redirects into HTTP errors so sensitive headers never cross origins."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        response: IO[bytes],
        code: int,
        message: str,
        headers: HTTPMessage,
        new_url: str,
    ) -> urllib.request.Request | None:
        del new_url
        raise urllib.error.HTTPError(request.full_url, code, message, headers, response)


def _open_http(
    request: urllib.request.Request,
    *,
    timeout: float,
    ssl_context: ssl.SSLContext,
) -> Any:
    opener = urllib.request.build_opener(
        _NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=ssl_context),
    )
    return opener.open(request, timeout=timeout)


def _json_object(value: Any, *, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UploadClientError(f"{context} must be a JSON object")
    return cast(dict[str, Any], value)


def _read_limited(response: Any, limit: int = MAX_API_RESPONSE_BYTES) -> bytes:
    body = cast(bytes, response.read(limit + 1))
    if len(body) > limit:
        raise UploadClientError(f"HTTP response exceeded the {limit}-byte safety limit")
    return body


def _decode_json(body: bytes, *, context: str) -> dict[str, Any]:
    if not body:
        return {}
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UploadClientError(f"{context} returned invalid JSON") from error
    return _json_object(value, context=context)


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        return max(0.0, (when - datetime.now(UTC)).total_seconds())


def _backoff(attempt: int, retry_after: float | None = None) -> None:
    if retry_after is None:
        delay = min(30.0, 0.5 * (2**attempt)) + random.uniform(0.0, 0.25)
    else:
        delay = min(60.0, retry_after)
    time.sleep(delay)


def _api_error(error: urllib.error.HTTPError) -> ApiRequestError:
    request_id = error.headers.get("X-Request-ID") if error.headers else None
    retry_after = _retry_after_seconds(error.headers.get("Retry-After") if error.headers else None)
    try:
        body = _read_limited(error)
    finally:
        error.close()

    code = "http_error"
    message = error.reason or "request failed"
    if body:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict):
            api_error = payload.get("error")
            if isinstance(api_error, dict):
                code = str(api_error.get("code") or code)
                message = str(api_error.get("message") or message)
            elif isinstance(payload.get("detail"), str):
                message = str(payload["detail"])
            elif isinstance(payload.get("detail"), list):
                code = "validation_error"
                message = "request validation failed"
    return ApiRequestError(
        status=error.code,
        code=code,
        message=message,
        request_id=request_id,
        retry_after=retry_after,
    )


def _storage_error(error: urllib.error.HTTPError) -> StorageRequestError:
    status = error.code
    try:
        body = error.read(64 * 1024)
    finally:
        error.close()
    code = "http_error"
    message = str(error.reason or "request failed")
    if body:
        try:
            root = ET.fromstring(body)
            code = root.findtext("Code") or code
            message = root.findtext("Message") or message
        except ET.ParseError:
            pass
    return StorageRequestError(
        status=status,
        code=code,
        message=message,
        can_refresh_url=status in {401, 403},
    )


class ApiClient:
    """Small JSON client with token refresh, bounded retries, and safe errors."""

    def __init__(
        self,
        api_url: str,
        *,
        timeout: float,
        retries: int,
        ssl_context: ssl.SSLContext,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.ssl_context = ssl_context
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._access_expires_at = 0.0

    def login(self, email: str, password: str) -> None:
        payload = self._request(
            "/auth/token",
            method="POST",
            form={"username": email, "password": password},
            authenticated=False,
        )
        self._set_tokens(payload)

    def post(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self._request(path, method="POST", json_body=payload, authenticated=True)

    def delete(self, path: str) -> dict[str, Any]:
        return self._request(path, method="DELETE", authenticated=True)

    def _set_tokens(self, payload: Mapping[str, Any]) -> None:
        access_token = payload.get("access_token")
        refresh_token = payload.get("refresh_token")
        expires_in = payload.get("expires_in")
        if not isinstance(access_token, str) or not access_token:
            raise UploadClientError("authentication response did not contain an access token")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise UploadClientError("authentication response did not contain a refresh token")
        if not isinstance(expires_in, int) or expires_in <= 0:
            raise UploadClientError("authentication response contained an invalid expiry")
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._access_expires_at = time.monotonic() + expires_in

    def _refresh(self) -> None:
        if not self._refresh_token:
            raise UploadClientError("access token expired and no refresh token is available")
        payload = self._request(
            "/auth/refresh",
            method="POST",
            json_body={"refresh_token": self._refresh_token},
            authenticated=False,
            retry_transient=False,
        )
        self._set_tokens(payload)

    def _ensure_access_token(self) -> None:
        if not self._access_token:
            raise UploadClientError("not authenticated")
        if time.monotonic() >= self._access_expires_at - 30:
            self._refresh()

    def _request(
        self,
        path: str,
        *,
        method: str,
        json_body: Mapping[str, Any] | None = None,
        form: Mapping[str, str] | None = None,
        authenticated: bool,
        retry_transient: bool = True,
    ) -> dict[str, Any]:
        if json_body is not None and form is not None:
            raise ValueError("a request cannot contain both JSON and form data")

        url = f"{self.api_url}/{path.lstrip('/')}"
        refreshed_after_401 = False
        attempt = 0
        while True:
            if authenticated:
                self._ensure_access_token()
            headers = {
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                "X-Request-ID": str(uuid.uuid4()),
            }
            data: bytes | None = None
            if json_body is not None:
                data = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode(
                    "utf-8"
                )
                headers["Content-Type"] = "application/json"
            elif form is not None:
                data = urllib.parse.urlencode(form).encode("utf-8")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            if authenticated and self._access_token:
                headers["Authorization"] = f"Bearer {self._access_token}"

            request = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with _open_http(
                    request,
                    timeout=self.timeout,
                    ssl_context=self.ssl_context,
                ) as response:
                    body = _read_limited(response)
                return _decode_json(body, context=f"{method} {path}")
            except urllib.error.HTTPError as error:
                parsed = _api_error(error)
                if authenticated and parsed.status == 401 and not refreshed_after_401:
                    self._refresh()
                    refreshed_after_401 = True
                    continue
                if (
                    retry_transient
                    and parsed.status in TRANSIENT_HTTP_STATUSES
                    and attempt < self.retries
                ):
                    _backoff(attempt, parsed.retry_after)
                    attempt += 1
                    continue
                raise parsed from None
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                if retry_transient and attempt < self.retries:
                    _backoff(attempt)
                    attempt += 1
                    continue
                reason = getattr(error, "reason", error)
                raise UploadClientError(
                    f"API network request failed after retries: {reason}"
                ) from error


class FileSlice:
    """A bounded, streaming view of one file range for http.client."""

    def __init__(self, path: Path, offset: int, length: int) -> None:
        self.path = path
        self.offset = offset
        self.remaining = length
        self._handle: BinaryIO | None = None

    def __enter__(self) -> FileSlice:
        self._handle = self.path.open("rb")
        self._handle.seek(self.offset)
        return self

    def __exit__(self, *_: object) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def read(self, size: int = -1) -> bytes:
        if self._handle is None:
            raise RuntimeError("file slice is not open")
        if self.remaining <= 0:
            return b""
        if size is None or size < 0:
            size = self.remaining
        chunk = self._handle.read(min(size, self.remaining))
        self.remaining -= len(chunk)
        return chunk


def _is_loopback_host(hostname: str) -> bool:
    return hostname.rstrip(".").lower() in {"localhost", "127.0.0.1", "::1"}


def _validate_upload_url(
    url: str,
    *,
    api_url: str,
    allow_insecure_storage: bool,
) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UploadClientError("API returned an invalid object-storage URL")
    if parsed.username is not None or parsed.password is not None:
        raise UploadClientError("API returned an object-storage URL containing user information")
    api_scheme = urllib.parse.urlsplit(api_url).scheme
    storage_is_local = _is_loopback_host(parsed.hostname)
    if parsed.scheme != "https" and not storage_is_local and not allow_insecure_storage:
        raise UploadClientError(
            "refusing non-loopback HTTP object storage; use --allow-insecure-storage only in a "
            "trusted development environment"
        )
    if api_scheme == "https" and parsed.scheme != "https" and not allow_insecure_storage:
        raise UploadClientError(
            "refusing HTTPS-to-HTTP storage downgrade; use --allow-insecure-storage only in a "
            "trusted development environment"
        )


def _put_file_range(
    *,
    path: Path,
    offset: int,
    length: int,
    url: str,
    headers: Mapping[str, str],
    timeout: float,
    retries: int,
    ssl_context: ssl.SSLContext,
) -> str | None:
    attempt = 0
    while True:
        request_headers = {str(key): str(value) for key, value in headers.items()}
        request_headers["Content-Length"] = str(length)
        request_headers["User-Agent"] = USER_AGENT
        try:
            with FileSlice(path, offset, length) as body:
                request = urllib.request.Request(
                    url,
                    data=cast(Any, body),
                    headers=request_headers,
                    method="PUT",
                )
                with _open_http(
                    request,
                    timeout=timeout,
                    ssl_context=ssl_context,
                ) as response:
                    response.read(1024)
                    etag = cast(str | None, response.headers.get("ETag"))
            return etag
        except urllib.error.HTTPError as error:
            parsed = _storage_error(error)
            retryable = (
                parsed.status in TRANSIENT_HTTP_STATUSES or parsed.code in TRANSIENT_STORAGE_CODES
            )
            if retryable and attempt < retries:
                _backoff(attempt)
                attempt += 1
                continue
            raise parsed from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            if attempt < retries:
                _backoff(attempt)
                attempt += 1
                continue
            reason = getattr(error, "reason", error)
            raise StorageRequestError(
                status=None,
                code="network_error",
                message=f"request failed after retries: {reason}",
                can_refresh_url=True,
            ) from error


@dataclass(slots=True)
class Checkpoint:
    api_url: str
    source_path: str
    source_size: int
    source_mtime_ns: int
    idempotency_key: str
    content_type: str
    custom_metadata: dict[str, Any]
    checksum_sha256: str | None
    upload_session_id: str | None = None
    file_id: str | None = None
    mode: str | None = None
    part_size_bytes: int | None = None
    part_count: int | None = None
    single_uploaded: bool = False
    completed_parts: dict[int, str] = field(default_factory=dict)
    version: int = 1

    @classmethod
    def load(cls, path: Path) -> Checkpoint:
        try:
            raw = path.read_text(encoding="utf-8")
            value = json.loads(raw)
        except FileNotFoundError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise UploadClientError(f"cannot read checkpoint {path}: {error}") from error
        payload = _json_object(value, context="checkpoint")
        try:
            version = payload["version"]
            completed_raw = payload.get("completed_parts", {})
            if version != 1 or not isinstance(completed_raw, dict):
                raise ValueError("unsupported checkpoint version or shape")
            completed_parts = {int(number): str(etag) for number, etag in completed_raw.items()}
            checkpoint = cls(
                version=1,
                api_url=str(payload["api_url"]),
                source_path=str(payload["source_path"]),
                source_size=int(payload["source_size"]),
                source_mtime_ns=int(payload["source_mtime_ns"]),
                idempotency_key=str(payload["idempotency_key"]),
                content_type=str(payload["content_type"]),
                custom_metadata=_json_object(
                    payload.get("custom_metadata", {}), context="checkpoint custom_metadata"
                ),
                checksum_sha256=(
                    str(payload["checksum_sha256"])
                    if payload.get("checksum_sha256") is not None
                    else None
                ),
                upload_session_id=(
                    str(payload["upload_session_id"])
                    if payload.get("upload_session_id") is not None
                    else None
                ),
                file_id=str(payload["file_id"]) if payload.get("file_id") is not None else None,
                mode=str(payload["mode"]) if payload.get("mode") is not None else None,
                part_size_bytes=(
                    int(payload["part_size_bytes"])
                    if payload.get("part_size_bytes") is not None
                    else None
                ),
                part_count=(
                    int(payload["part_count"]) if payload.get("part_count") is not None else None
                ),
                single_uploaded=payload.get("single_uploaded", False) is True,
                completed_parts=completed_parts,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise UploadClientError(f"checkpoint {path} is invalid: {error}") from error
        if not 8 <= len(checkpoint.idempotency_key) <= 200:
            raise UploadClientError(f"checkpoint {path} has an invalid idempotency key")
        return checkpoint

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        payload = {
            "version": self.version,
            "api_url": self.api_url,
            "source_path": self.source_path,
            "source_size": self.source_size,
            "source_mtime_ns": self.source_mtime_ns,
            "idempotency_key": self.idempotency_key,
            "content_type": self.content_type,
            "custom_metadata": self.custom_metadata,
            "checksum_sha256": self.checksum_sha256,
            "upload_session_id": self.upload_session_id,
            "file_id": self.file_id,
            "mode": self.mode,
            "part_size_bytes": self.part_size_bytes,
            "part_count": self.part_count,
            "single_uploaded": self.single_uploaded,
            "completed_parts": {
                str(number): etag for number, etag in sorted(self.completed_parts.items())
            },
        }
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(path)
            with contextlib.suppress(OSError):
                path.chmod(0o600)
        except OSError as error:
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)
            raise UploadClientError(f"cannot save checkpoint {path}: {error}") from error


def _metadata(value: str | None) -> dict[str, Any]:
    if value is None:
        return {}
    if value.startswith("@"):
        source = Path(value[1:]).expanduser()
        try:
            raw = source.read_bytes()
        except OSError as error:
            raise UploadClientError(f"cannot read metadata file {source}: {error}") from error
    else:
        raw = value.encode("utf-8")
    if len(raw) > MAX_METADATA_BYTES:
        raise UploadClientError("custom metadata must not exceed 16 KiB")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UploadClientError(f"invalid metadata JSON: {error}") from error
    result = _json_object(payload, context="custom metadata")
    if not all(isinstance(key, str) for key in result):
        raise UploadClientError("custom metadata keys must be strings")
    return result


def _calculate_sha256(path: Path) -> str:
    print(f"Calculating SHA-256 for {path.name}; this may take a while...", file=sys.stderr)
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(8 * 1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise UploadClientError(f"cannot hash source file: {error}") from error
    return digest.hexdigest()


def _validate_sha256(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise UploadClientError("--checksum-sha256 must be 64 hexadecimal characters")
    return normalized


def _normalize_api_url(value: str, *, allow_insecure_api: bool) -> str:
    normalized = value.rstrip("/")
    parsed = urllib.parse.urlsplit(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UploadClientError("--api-url must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise UploadClientError("--api-url must not contain embedded credentials")
    if parsed.query or parsed.fragment:
        raise UploadClientError("--api-url must not contain a query string or fragment")
    if (
        parsed.scheme != "https"
        and not _is_loopback_host(parsed.hostname)
        and not allow_insecure_api
    ):
        raise UploadClientError(
            "refusing non-loopback HTTP API because credentials and tokens would be sent in "
            "plaintext; use --allow-insecure-api only in a trusted development environment"
        )
    return normalized


def _source_stat(path: Path) -> os.stat_result:
    try:
        stat = path.stat()
    except OSError as error:
        raise UploadClientError(f"cannot stat source file: {error}") from error
    if not path.is_file():
        raise UploadClientError(f"source is not a regular file: {path}")
    if stat.st_size <= 0:
        raise UploadClientError("empty files are not accepted")
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        supported = ", ".join(sorted(SUPPORTED_EXTENSIONS))
        raise UploadClientError(f"unsupported file extension; expected one of: {supported}")
    return stat


def _assert_source_unchanged(path: Path, checkpoint: Checkpoint) -> None:
    stat = _source_stat(path)
    if stat.st_size != checkpoint.source_size or stat.st_mtime_ns != checkpoint.source_mtime_ns:
        raise UploadClientError(
            "source file changed after the upload began; do not complete this session. "
            "Run again with --restart to abort it and create a new upload."
        )


def _new_checkpoint(
    *,
    path: Path,
    stat: os.stat_result,
    api_url: str,
    idempotency_key: str | None,
    content_type: str,
    custom_metadata: dict[str, Any],
    checksum_sha256: str | None,
) -> Checkpoint:
    key = idempotency_key or f"upload-{uuid.uuid4()}"
    if not 8 <= len(key) <= 200:
        raise UploadClientError("--idempotency-key must be between 8 and 200 characters")
    return Checkpoint(
        api_url=api_url,
        source_path=str(path),
        source_size=stat.st_size,
        source_mtime_ns=stat.st_mtime_ns,
        idempotency_key=key,
        content_type=content_type,
        custom_metadata=custom_metadata,
        checksum_sha256=checksum_sha256,
    )


@dataclass(slots=True)
class PreparedUpload:
    checkpoint: Checkpoint
    checkpoint_path: Path
    old_session_to_abort: str | None = None


def _prepare_upload(args: argparse.Namespace) -> PreparedUpload:
    source = args.file.expanduser().resolve()
    args.file = source
    stat = _source_stat(source)
    api_url = _normalize_api_url(args.api_url, allow_insecure_api=args.allow_insecure_api)
    args.api_url = api_url
    checkpoint_path = (
        args.checkpoint.expanduser().resolve()
        if args.checkpoint
        else source.with_name(f".{source.name}.kb-upload.json")
    )
    existing = Checkpoint.load(checkpoint_path) if checkpoint_path.exists() else None

    requested_metadata = _metadata(args.metadata_json) if args.metadata_json is not None else None
    guessed_type = mimetypes.guess_type(source.name)[0] or "application/octet-stream"
    requested_content_type = args.content_type
    requested_checksum: str | None = None
    if args.checksum_sha256:
        requested_checksum = _validate_sha256(args.checksum_sha256)
    elif args.calculate_sha256:
        requested_checksum = _calculate_sha256(source)

    if existing is not None and not args.restart:
        if existing.api_url != api_url:
            raise UploadClientError("checkpoint belongs to a different API URL; use --restart")
        if existing.source_path != str(source):
            raise UploadClientError("checkpoint belongs to a different source path; use --restart")
        _assert_source_unchanged(source, existing)
        if args.idempotency_key and args.idempotency_key != existing.idempotency_key:
            raise UploadClientError("idempotency key differs from checkpoint; use --restart")
        if requested_content_type and requested_content_type != existing.content_type:
            raise UploadClientError("content type differs from checkpoint; use --restart")
        if requested_metadata is not None and requested_metadata != existing.custom_metadata:
            raise UploadClientError("metadata differs from checkpoint; use --restart")
        if requested_checksum is not None and requested_checksum != existing.checksum_sha256:
            raise UploadClientError("SHA-256 differs from checkpoint; use --restart")
        return PreparedUpload(existing, checkpoint_path)

    content_type = requested_content_type or guessed_type
    metadata = requested_metadata or {}
    checkpoint = _new_checkpoint(
        path=source,
        stat=stat,
        api_url=api_url,
        idempotency_key=args.idempotency_key,
        content_type=content_type,
        custom_metadata=metadata,
        checksum_sha256=requested_checksum,
    )
    old_session = (
        existing.upload_session_id if existing is not None and existing.api_url == api_url else None
    )
    return PreparedUpload(checkpoint, checkpoint_path, old_session)


def _required_string(payload: Mapping[str, Any], key: str, *, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise UploadClientError(f"{context} did not contain a valid {key}")
    return value


def _required_positive_int(payload: Mapping[str, Any], key: str, *, context: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or value <= 0:
        raise UploadClientError(f"{context} did not contain a valid {key}")
    return value


class UploadRunner:
    def __init__(
        self,
        *,
        args: argparse.Namespace,
        api: ApiClient,
        checkpoint: Checkpoint,
        checkpoint_path: Path,
        ssl_context: ssl.SSLContext,
    ) -> None:
        self.args = args
        self.api = api
        self.checkpoint = checkpoint
        self.checkpoint_path = checkpoint_path
        self.ssl_context = ssl_context

    def run(self) -> dict[str, Any]:
        initiation = self._initiate()
        mode = self.checkpoint.mode
        if mode == "single":
            self._upload_single(initiation)
        elif mode == "multipart":
            self._upload_multipart()
        else:
            raise UploadClientError(f"server returned unsupported upload mode: {mode!r}")

        _assert_source_unchanged(self.args.file, self.checkpoint)
        result = self._complete()
        if not self.args.keep_checkpoint:
            try:
                self.checkpoint_path.unlink(missing_ok=True)
            except OSError as error:
                print(f"warning: could not remove checkpoint: {error}", file=sys.stderr)
        return result

    def _initiate(self) -> dict[str, Any]:
        response = self.api.post(
            "/files/uploads",
            {
                "filename": self.args.file.name,
                "size_bytes": self.checkpoint.source_size,
                "content_type": self.checkpoint.content_type,
                "checksum_sha256": self.checkpoint.checksum_sha256,
                "custom_metadata": self.checkpoint.custom_metadata,
                "idempotency_key": self.checkpoint.idempotency_key,
            },
        )
        session_id = _required_string(response, "upload_session_id", context="initiation response")
        file_id = _required_string(response, "file_id", context="initiation response")
        mode = _required_string(response, "mode", context="initiation response")
        part_size = _required_positive_int(
            response, "part_size_bytes", context="initiation response"
        )
        part_count = _required_positive_int(response, "part_count", context="initiation response")
        expected = (
            self.checkpoint.upload_session_id,
            self.checkpoint.file_id,
            self.checkpoint.mode,
            self.checkpoint.part_size_bytes,
            self.checkpoint.part_count,
        )
        actual = (session_id, file_id, mode, part_size, part_count)
        if any(value is not None for value in expected) and expected != actual:
            raise UploadClientError(
                "server upload plan no longer matches the checkpoint; use --restart to abort and "
                "create a new session"
            )
        self.checkpoint.upload_session_id = session_id
        self.checkpoint.file_id = file_id
        self.checkpoint.mode = mode
        self.checkpoint.part_size_bytes = part_size
        self.checkpoint.part_count = part_count
        self.checkpoint.save(self.checkpoint_path)
        print(
            f"Upload session {session_id}: mode={mode}, parts={part_count}, part_size={part_size}",
            file=sys.stderr,
        )
        return response

    def _upload_single(self, initiation: Mapping[str, Any]) -> None:
        if self.checkpoint.single_uploaded:
            print(
                "Single object already uploaded according to checkpoint; completing.",
                file=sys.stderr,
            )
            return
        url = initiation.get("upload_url")
        if not isinstance(url, str) or not url:
            raise UploadClientError(
                "active single-part session has no upload URL; rerun the command to refresh it"
            )
        required_headers = initiation.get("required_headers", {})
        if not isinstance(required_headers, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in required_headers.items()
        ):
            raise UploadClientError("initiation response contained invalid required_headers")
        _validate_upload_url(
            url,
            api_url=self.args.api_url,
            allow_insecure_storage=self.args.allow_insecure_storage,
        )
        _put_file_range(
            path=self.args.file,
            offset=0,
            length=self.checkpoint.source_size,
            url=url,
            headers=cast(dict[str, str], required_headers),
            timeout=self.args.storage_timeout,
            retries=self.args.retries,
            ssl_context=self.ssl_context,
        )
        self.checkpoint.single_uploaded = True
        self.checkpoint.save(self.checkpoint_path)
        print("Single object PUT completed.", file=sys.stderr)

    def _upload_multipart(self) -> None:
        session_id = self.checkpoint.upload_session_id
        part_size = self.checkpoint.part_size_bytes
        part_count = self.checkpoint.part_count
        if not session_id or not part_size or not part_count:
            raise UploadClientError("multipart checkpoint is missing its upload plan")
        invalid = set(self.checkpoint.completed_parts) - set(range(1, part_count + 1))
        if invalid:
            raise UploadClientError(
                "checkpoint contains out-of-range completed parts; use --restart"
            )

        pending = [
            number
            for number in range(1, part_count + 1)
            if number not in self.checkpoint.completed_parts
        ]
        if not pending:
            print(
                "All multipart parts already exist in the checkpoint; completing.", file=sys.stderr
            )
            return
        print(
            f"Uploading {len(pending)} remaining part(s) with {self.args.workers} worker(s)...",
            file=sys.stderr,
        )
        batch_size = min(self.args.url_batch_size, 100)
        for start in range(0, len(pending), batch_size):
            batch = pending[start : start + batch_size]
            self._upload_part_batch(session_id, part_size, part_count, batch)

    def _upload_part_batch(
        self,
        session_id: str,
        part_size: int,
        part_count: int,
        part_numbers: list[int],
    ) -> None:
        remaining = list(part_numbers)
        refresh_round = 0
        while remaining:
            response = self.api.post(
                f"/files/uploads/{session_id}/parts",
                {"part_numbers": remaining},
            )
            items = response.get("parts")
            if not isinstance(items, list):
                raise UploadClientError("part URL response did not contain a parts list")
            urls: dict[int, str] = {}
            for item in items:
                if not isinstance(item, dict):
                    raise UploadClientError("part URL response contained an invalid item")
                number = item.get("part_number")
                url = item.get("url")
                signed_size = item.get("size_bytes")
                if (
                    not isinstance(number, int)
                    or not isinstance(url, str)
                    or not url
                    or not isinstance(signed_size, int)
                    or signed_size <= 0
                ):
                    raise UploadClientError("part URL response contained an invalid item")
                expected_size = min(
                    part_size,
                    self.checkpoint.source_size - ((number - 1) * part_size),
                )
                if signed_size != expected_size:
                    raise UploadClientError(
                        f"signed size for part {number} differs from the local upload plan"
                    )
                _validate_upload_url(
                    url,
                    api_url=self.args.api_url,
                    allow_insecure_storage=self.args.allow_insecure_storage,
                )
                urls[number] = url
            if set(urls) != set(remaining):
                raise UploadClientError("part URL response did not match requested part numbers")

            failures: dict[int, StorageRequestError] = {}
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(self.args.workers, len(remaining)),
                thread_name_prefix="kb-upload",
            ) as executor:
                futures = {
                    executor.submit(
                        self._upload_part,
                        number,
                        part_size,
                        part_count,
                        urls[number],
                    ): number
                    for number in remaining
                }
                for future in concurrent.futures.as_completed(futures):
                    number = futures[future]
                    try:
                        etag = future.result()
                    except StorageRequestError as error:
                        failures[number] = error
                        continue
                    self.checkpoint.completed_parts[number] = etag
                    self.checkpoint.save(self.checkpoint_path)
                    done = len(self.checkpoint.completed_parts)
                    print(
                        f"part {number}/{part_count} uploaded ({done}/{part_count} done)",
                        file=sys.stderr,
                    )

            fatal = {
                number: error for number, error in failures.items() if not error.can_refresh_url
            }
            if fatal:
                number, storage_error = next(iter(sorted(fatal.items())))
                completed = len(self.checkpoint.completed_parts)
                raise UploadClientError(
                    f"part {number} failed; {completed} successful part(s) were checkpointed: "
                    f"{storage_error}"
                ) from storage_error
            remaining = sorted(failures)
            if not remaining:
                return
            refresh_round += 1
            if refresh_round > self.args.url_refreshes:
                first = failures[remaining[0]]
                failed_count = len(remaining)
                raise UploadClientError(
                    f"{failed_count} part(s) still failed after refreshing signed URLs; "
                    f"rerun the same command to resume: {first}"
                ) from first
            print(
                f"Refreshing signed URLs for {len(remaining)} failed part(s)...",
                file=sys.stderr,
            )

    def _upload_part(self, number: int, part_size: int, part_count: int, url: str) -> str:
        offset = (number - 1) * part_size
        length = min(part_size, self.checkpoint.source_size - offset)
        if length <= 0 or number > part_count:
            raise UploadClientError(f"invalid local range for part {number}")
        etag = _put_file_range(
            path=self.args.file,
            offset=offset,
            length=length,
            url=url,
            headers={},
            timeout=self.args.storage_timeout,
            retries=self.args.retries,
            ssl_context=self.ssl_context,
        )
        if not etag:
            raise StorageRequestError(
                status=None,
                code="missing_etag",
                message=f"part {number} response did not contain ETag",
            )
        return etag

    def _complete(self) -> dict[str, Any]:
        session_id = self.checkpoint.upload_session_id
        if not session_id:
            raise UploadClientError("checkpoint is missing upload_session_id")
        if self.checkpoint.mode == "multipart":
            part_count = self.checkpoint.part_count or 0
            expected = set(range(1, part_count + 1))
            if set(self.checkpoint.completed_parts) != expected:
                raise UploadClientError("cannot complete: checkpoint does not contain every part")
            parts = [
                {"part_number": number, "etag": self.checkpoint.completed_parts[number]}
                for number in range(1, part_count + 1)
            ]
        else:
            parts = []
        return self.api.post(
            f"/files/uploads/{session_id}/complete",
            {"parts": parts},
        )


def _positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def _bounded_int(minimum: int, maximum: int) -> Any:
    def parse(value: str) -> int:
        number = int(value)
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f"must be between {minimum} and {maximum}")
        return number

    return parse


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Upload a supported document through the knowledge-base API. Multipart progress is "
            "checkpointed locally and resumes when the same command is run again."
        )
    )
    parser.add_argument("file", type=Path, help="document to upload")
    parser.add_argument(
        "--api-url",
        default=os.environ.get("KB_API_URL", "http://localhost:8000/api/v1"),
        help="versioned API base URL (default: %(default)s; env: KB_API_URL)",
    )
    parser.add_argument(
        "--email",
        default=os.environ.get("KB_EMAIL"),
        help="login email (env: KB_EMAIL)",
    )
    parser.add_argument(
        "--password-env",
        default="KB_PASSWORD",
        help="environment variable containing the password; otherwise prompt securely",
    )
    parser.add_argument("--content-type", help="override detected media type")
    parser.add_argument(
        "--metadata-json",
        help='custom metadata object, either inline JSON or "@path/to/file.json"',
    )
    checksum = parser.add_mutually_exclusive_group()
    checksum.add_argument(
        "--calculate-sha256",
        action="store_true",
        help="scan the entire file and send its SHA-256 (optional and expensive for huge files)",
    )
    checksum.add_argument("--checksum-sha256", help="known 64-character hexadecimal SHA-256")
    parser.add_argument(
        "--idempotency-key", help="stable key (8-200 chars); otherwise checkpointed UUID"
    )
    parser.add_argument(
        "--checkpoint", type=Path, help="checkpoint path (default: beside source file)"
    )
    parser.add_argument(
        "--restart",
        action="store_true",
        help="abort the checkpointed server session and start with a new idempotency key",
    )
    parser.add_argument(
        "--keep-checkpoint", action="store_true", help="keep checkpoint after successful completion"
    )
    parser.add_argument(
        "--workers", type=_bounded_int(1, 32), default=4, help="parallel multipart PUTs (1-32)"
    )
    parser.add_argument(
        "--url-batch-size",
        type=_bounded_int(1, 100),
        default=16,
        help="signed part URLs requested per batch (1-100)",
    )
    parser.add_argument(
        "--url-refreshes",
        type=_bounded_int(0, 10),
        default=2,
        help="times to refresh rejected/expired part URLs in the current run",
    )
    parser.add_argument(
        "--retries", type=_bounded_int(0, 10), default=4, help="transient HTTP retries per request"
    )
    parser.add_argument("--api-timeout", type=_positive_float, default=30.0)
    parser.add_argument("--storage-timeout", type=_positive_float, default=300.0)
    parser.add_argument("--ca-bundle", type=Path, help="custom PEM CA bundle for private endpoints")
    parser.add_argument(
        "--allow-insecure-api",
        action="store_true",
        help="allow credentials over a non-loopback HTTP API (development only)",
    )
    parser.add_argument(
        "--allow-insecure-storage",
        action="store_true",
        help="allow an HTTP storage URL when the API uses HTTPS (development only)",
    )
    return parser


def _password(args: argparse.Namespace) -> str:
    value = os.environ.get(args.password_env)
    if value:
        return value
    try:
        value = getpass.getpass("Knowledge-base password: ")
    except (EOFError, KeyboardInterrupt) as error:
        raise UploadClientError(
            f"password prompt unavailable; set the {args.password_env} environment variable"
        ) from error
    if not value:
        raise UploadClientError("password is required")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    checkpoint_path: Path | None = None
    try:
        if not args.email:
            raise UploadClientError("--email is required (or set KB_EMAIL)")
        prepared = _prepare_upload(args)
        checkpoint_path = prepared.checkpoint_path
        try:
            ssl_context = ssl.create_default_context(
                cafile=str(args.ca_bundle.expanduser()) if args.ca_bundle else None
            )
        except (OSError, ssl.SSLError) as error:
            raise UploadClientError(f"cannot load CA bundle: {error}") from error
        api = ApiClient(
            args.api_url,
            timeout=args.api_timeout,
            retries=args.retries,
            ssl_context=ssl_context,
        )
        api.login(args.email.strip().lower(), _password(args))

        if prepared.old_session_to_abort:
            print(
                f"Aborting previous upload session {prepared.old_session_to_abort}...",
                file=sys.stderr,
            )
            try:
                api.delete(f"/files/uploads/{prepared.old_session_to_abort}")
            except ApiRequestError as error:
                if error.status not in {404, 409}:
                    raise
                print(f"warning: previous session was already terminal: {error}", file=sys.stderr)
        prepared.checkpoint.save(prepared.checkpoint_path)

        runner = UploadRunner(
            args=args,
            api=api,
            checkpoint=prepared.checkpoint,
            checkpoint_path=prepared.checkpoint_path,
            ssl_context=ssl_context,
        )
        result = runner.run()
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        status = result.get("status")
        if status == "processing":
            print(
                "Upload completed and is in processing state; an authorized administrator must "
                "approve it before download.",
                file=sys.stderr,
            )
        return 0
    except KeyboardInterrupt:
        print(
            "\nUpload interrupted; completed multipart parts remain checkpointed.", file=sys.stderr
        )
        if checkpoint_path:
            print(f"Resume checkpoint: {checkpoint_path}", file=sys.stderr)
        return 130
    except UploadClientError as error:
        print(f"Upload failed: {error}", file=sys.stderr)
        if checkpoint_path:
            checkpoint_message = (
                f"Checkpoint: {checkpoint_path}\nRerun the same command to resume, or add "
                "--restart to abort the old server session and begin again."
            )
            print(
                checkpoint_message,
                file=sys.stderr,
            )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
