from __future__ import annotations

from typing import cast
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyLimitMiddleware:
    """Bound control-plane bodies while consuming ASGI chunks, before parsing.

    The middleware retains at most ``max_bytes`` for replay to FastAPI and stops
    reading as soon as a chunk crosses the limit. The edge proxy must enforce the
    same or a lower limit so an individual ASGI message is bounded as well.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = next(
            (value for key, value in scope["headers"] if key.lower() == b"content-length"),
            None,
        )
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = -1
            if declared_length > self._max_bytes:
                await self._too_large(scope, receive, send)
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
            if received_bytes > self._max_bytes:
                await self._too_large(scope, receive, send)
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

    async def _too_large(self, scope: Scope, receive: Receive, send: Send) -> None:
        state = scope.get("state", {})
        response = JSONResponse(
            status_code=413,
            content={
                "error": {
                    "code": "request_body_too_large",
                    "message": f"API request bodies cannot exceed {self._max_bytes} bytes",
                },
                "request_id": state.get("request_id") if isinstance(state, dict) else None,
            },
        )
        await response(scope, receive, send)


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get("X-Request-ID", "")
        request_id = incoming[:100] if incoming else str(uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response
