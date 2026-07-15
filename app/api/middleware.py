from __future__ import annotations

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

    The middleware retains at most ``max_bytes`` for replay to FastAPI and stops
    reading as soon as a chunk crosses the limit. The edge proxy must enforce the
    same or a lower limit so an individual ASGI message is bounded as well.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_bytes: int,
        path_limits: dict[str, int] | None = None,
    ) -> None:
        self.app = app
        self._max_bytes = max_bytes
        self._path_limits = path_limits or {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = cast(str, scope.get("path", ""))
        max_bytes = min(self._max_bytes, self._path_limits.get(path, self._max_bytes))
        content_length = next(
            (value for key, value in scope["headers"] if key.lower() == b"content-length"),
            None,
        )
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = -1
            if declared_length > max_bytes:
                await self._too_large(scope, receive, send, max_bytes=max_bytes)
                return

        buffered: list[Message] = []
        received_bytes = 0
        while True:
            message = await receive()
            buffered.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            body = cast(bytes, message.get("body", b""))
            received_bytes += len(body)
            if received_bytes > max_bytes:
                await self._too_large(scope, receive, send, max_bytes=max_bytes)
                return
            if not message.get("more_body", False):
                break

        index = 0

        async def replay_receive() -> Message:
            nonlocal index
            if index < len(buffered):
                message = buffered[index]
                index += 1
                return message
            return await receive()

        await self.app(scope, replay_receive, send)

    async def _too_large(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        max_bytes: int,
    ) -> None:
        state = scope.get("state", {})
        response = JSONResponse(
            status_code=413,
            content={
                "error": {
                    "code": "request_body_too_large",
                    "message": f"API request bodies cannot exceed {max_bytes} bytes",
                },
                "request_id": state.get("request_id") if isinstance(state, dict) else None,
            },
        )
        await response(scope, receive, send)


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = normalize_request_id(request.headers.get("X-Request-ID"))
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response
