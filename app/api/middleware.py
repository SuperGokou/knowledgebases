from __future__ import annotations

import asyncio
import math
import re
from typing import cast
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_SAFE_REQUEST_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")


def normalize_request_id(value: str | None) -> str:
    """Return a bounded identifier safe for response headers and structured logs."""

    if value and _SAFE_REQUEST_ID.fullmatch(value):
        return value
    return str(uuid4())


class RequestBodyLimitMiddleware:
    """Bound control-plane bodies while consuming ASGI chunks, before parsing.

    The middleware coalesces at most ``max_bytes`` into one replay message,
    bounds the number and total receive time of ASGI messages, and stops reading
    as soon as any boundary is crossed. The edge proxy must enforce the same or
    a lower byte limit so an individual ASGI message is bounded as well.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_bytes: int,
        path_limits: dict[str, int] | None = None,
        max_messages: int = 1024,
        receive_timeout_seconds: float = 10.0,
    ) -> None:
        if max_bytes < 1:
            raise ValueError("request body byte limit must be positive")
        if max_messages < 1:
            raise ValueError("request body message limit must be positive")
        if not math.isfinite(receive_timeout_seconds) or receive_timeout_seconds <= 0:
            raise ValueError("request body receive timeout must be finite and positive")
        self.app = app
        self._max_bytes = max_bytes
        self._path_limits = path_limits or {}
        self._max_messages = max_messages
        self._receive_timeout_seconds = receive_timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = cast(str, scope.get("path", ""))
        max_bytes = min(self._max_bytes, self._path_limits.get(path, self._max_bytes))
        headers = cast(list[tuple[bytes, bytes]], scope.get("headers", []))
        content_lengths = [value for key, value in headers if key.lower() == b"content-length"]
        transfer_encoding_present = any(key.lower() == b"transfer-encoding" for key, _ in headers)
        if len(content_lengths) > 1:
            await self._reject(
                scope,
                receive,
                send,
                status_code=400,
                code="invalid_content_length",
                message="Duplicate Content-Length headers are not accepted",
            )
            return

        declared_length: int | None = None
        if content_lengths:
            raw_content_length = content_lengths[0]
            if (
                not raw_content_length
                or not raw_content_length.isascii()
                or not raw_content_length.isdigit()
                or transfer_encoding_present
            ):
                await self._reject(
                    scope,
                    receive,
                    send,
                    status_code=400,
                    code="invalid_content_length",
                    message="Content-Length is invalid or conflicts with Transfer-Encoding",
                )
                return
            try:
                declared_length = int(raw_content_length)
            except (ValueError, OverflowError):
                await self._reject(
                    scope,
                    receive,
                    send,
                    status_code=400,
                    code="invalid_content_length",
                    message="Content-Length is outside the supported numeric range",
                )
                return
            if declared_length > max_bytes:
                await self._too_large(scope, receive, send, max_bytes=max_bytes)
                return

        buffered_body = bytearray()
        received_messages = 0
        disconnected = False
        receive_deadline = asyncio.get_running_loop().time() + self._receive_timeout_seconds
        while True:
            remaining = receive_deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                await self._body_timeout(scope, receive, send)
                return
            try:
                async with asyncio.timeout(remaining):
                    message = await receive()
            except TimeoutError:
                await self._body_timeout(scope, receive, send)
                return

            received_messages += 1
            if received_messages > self._max_messages:
                await self._reject(
                    scope,
                    receive,
                    send,
                    status_code=413,
                    code="request_body_too_fragmented",
                    message=(
                        f"API request bodies cannot exceed {self._max_messages} ASGI messages"
                    ),
                )
                return
            message_type = message.get("type")
            if message_type == "http.disconnect":
                disconnected = True
                break
            if message_type != "http.request":
                await self._reject(
                    scope,
                    receive,
                    send,
                    status_code=400,
                    code="invalid_request_body",
                    message="The request body stream contained an invalid ASGI message",
                )
                return
            body = message.get("body", b"")
            more_body = message.get("more_body", False)
            if not isinstance(body, bytes) or not isinstance(more_body, bool):
                await self._reject(
                    scope,
                    receive,
                    send,
                    status_code=400,
                    code="invalid_request_body",
                    message="The request body stream is invalid",
                )
                return
            buffered_body.extend(body)
            if len(buffered_body) > max_bytes:
                await self._too_large(scope, receive, send, max_bytes=max_bytes)
                return
            if not more_body:
                break

        if (
            not disconnected
            and declared_length is not None
            and declared_length != len(buffered_body)
        ):
            await self._reject(
                scope,
                receive,
                send,
                status_code=400,
                code="content_length_mismatch",
                message="Content-Length does not match the received request body",
            )
            return

        buffered: list[Message]
        if disconnected:
            buffered = []
            if buffered_body:
                buffered.append(
                    {
                        "type": "http.request",
                        "body": bytes(buffered_body),
                        "more_body": True,
                    }
                )
            buffered.append({"type": "http.disconnect"})
        else:
            buffered = [
                {
                    "type": "http.request",
                    "body": bytes(buffered_body),
                    "more_body": False,
                }
            ]
        index = 0

        async def replay_receive() -> Message:
            nonlocal index
            if index < len(buffered):
                message = buffered[index]
                index += 1
                return message
            return await receive()

        await self.app(scope, replay_receive, send)

    async def _body_timeout(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        await self._reject(
            scope,
            receive,
            send,
            status_code=408,
            code="request_body_timeout",
            message="The API request body was not received within the allowed time",
        )

    async def _too_large(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        max_bytes: int,
    ) -> None:
        await self._reject(
            scope,
            receive,
            send,
            status_code=413,
            code="request_body_too_large",
            message=f"API request bodies cannot exceed {max_bytes} bytes",
        )

    @staticmethod
    async def _reject(
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        status_code: int,
        code: str,
        message: str,
    ) -> None:
        state = scope.get("state", {})
        response = JSONResponse(
            status_code=status_code,
            content={
                "error": {
                    "code": code,
                    "message": message,
                },
                "request_id": state.get("request_id") if isinstance(state, dict) else None,
            },
        )
        await response(scope, receive, send)


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = normalize_request_id(
            getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID")
        )
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response
