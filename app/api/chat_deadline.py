from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from threading import Lock
from typing import Any, Final, cast

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.middleware import normalize_request_id
from app.services.chat_idempotency import chat_finalization_backlog_size
from app.services.chat_safety import (
    chat_safety_poisoned,
    poison_chat_safety,
    register_chat_poison_listener,
)
from app.services.chat_timeout import (
    CHAT_FINALIZATION_RESERVE_SECONDS,
    CHAT_OPERATION_CLEANUP_SECONDS,
    CHAT_OPERATION_TIMEOUT_SECONDS,
    chat_cleanup_backlog_size,
)
from app.services.llm_provider import llm_cleanup_backlog_size

_LOGGER = logging.getLogger(__name__)
_MAX_BUFFERED_RESPONSE_BYTES: Final[int] = 4 * 1024 * 1024
_MAX_BUFFERED_RESPONSE_MESSAGES: Final[int] = 64
_MAX_BUFFERED_HEADER_BYTES: Final[int] = 64 * 1024
_MAX_BUFFERED_HEADERS: Final[int] = 64
_CHAT_RUNTIME_LOCK = Lock()
_ACTIVE_CHAT_REQUESTS = 0
_ACTIVE_CHAT_ROUTES: set[asyncio.Task[None]] = set()
_ROUTE_CANCELLATION_SENT: set[asyncio.Task[None]] = set()
_SUPERVISED_CHAT_ROUTES: set[asyncio.Task[None]] = set()
_SUPERVISED_CHAT_SENDS: set[asyncio.Task[None]] = set()


@dataclass(frozen=True, slots=True)
class ChatRequestDeadlines:
    started_at: float
    operation_deadline: float
    cleanup_deadline: float
    response_deadline: float


@dataclass(slots=True)
class _AdmissionLease:
    released: bool = False

    def release(self) -> None:
        global _ACTIVE_CHAT_REQUESTS
        with _CHAT_RUNTIME_LOCK:
            if self.released:
                return
            self.released = True
            _ACTIVE_CHAT_REQUESTS -= 1
            if _ACTIVE_CHAT_REQUESTS < 0:  # pragma: no cover - defensive invariant.
                _ACTIVE_CHAT_REQUESTS = 0
                raise RuntimeError("chat admission counter underflow")


class _ResponseTranscript:
    def __init__(self) -> None:
        self.messages: list[Message] = []
        self.body_bytes = 0
        self.started = False
        self.finished = False
        self.status_code: int | None = None
        self.closed = False

    async def capture(self, message: Message) -> None:
        if self.closed:
            raise RuntimeError("chat response gate is closed")
        if len(self.messages) >= _MAX_BUFFERED_RESPONSE_MESSAGES:
            self._reject("chat_response_message_boundary_exceeded")
        message_type = message.get("type")
        if message_type == "http.response.start":
            if self.started or self.messages:
                self._reject("chat_response_start_sequence_invalid")
            status_code = message.get("status")
            headers = cast(list[tuple[bytes, bytes]], message.get("headers", []))
            if (
                not isinstance(status_code, int)
                or status_code < 100
                or status_code > 599
                or len(headers) > _MAX_BUFFERED_HEADERS
                or sum(len(name) + len(value) for name, value in headers)
                > _MAX_BUFFERED_HEADER_BYTES
            ):
                self._reject("chat_response_header_boundary_exceeded")
            self.started = True
            self.status_code = status_code
        elif message_type == "http.response.body":
            if not self.started or self.finished:
                self._reject("chat_response_body_sequence_invalid")
            body = cast(bytes, message.get("body", b""))
            self.body_bytes += len(body)
            if self.body_bytes > _MAX_BUFFERED_RESPONSE_BYTES:
                self._reject("chat_response_body_boundary_exceeded")
            if not message.get("more_body", False):
                self.finished = True
        else:
            self._reject("chat_response_message_type_invalid")
        self.messages.append(cast(Message, dict(message)))

    def complete(self) -> bool:
        return self.started and self.finished and self.status_code is not None

    def close_and_discard(self) -> None:
        self.closed = True
        self.messages.clear()

    @staticmethod
    def _reject(reason: str) -> None:
        poison_chat_safety(reason=reason)
        raise RuntimeError("chat response transcript violated its safety boundary")


def require_chat_request_deadlines(request: Request) -> ChatRequestDeadlines:
    deadlines = getattr(request.state, "chat_request_deadlines", None)
    if not isinstance(deadlines, ChatRequestDeadlines):
        raise RuntimeError("chat route is missing its ingress deadline fence")
    return deadlines


def chat_route_backlog_size() -> int:
    with _CHAT_RUNTIME_LOCK:
        return sum(not task.done() for task in _SUPERVISED_CHAT_ROUTES) + sum(
            not task.done() for task in _SUPERVISED_CHAT_SENDS
        )


def chat_active_request_count() -> int:
    with _CHAT_RUNTIME_LOCK:
        return _ACTIVE_CHAT_REQUESTS


def _try_admit(max_active_requests: int) -> _AdmissionLease | None:
    global _ACTIVE_CHAT_REQUESTS
    with _CHAT_RUNTIME_LOCK:
        if max_active_requests <= _ACTIVE_CHAT_REQUESTS:
            return None
        _ACTIVE_CHAT_REQUESTS += 1
    return _AdmissionLease()


def _register_route(task: asyncio.Task[None]) -> None:
    with _CHAT_RUNTIME_LOCK:
        _ACTIVE_CHAT_ROUTES.add(task)


def _forget_route(task: asyncio.Task[None]) -> None:
    with _CHAT_RUNTIME_LOCK:
        _ACTIVE_CHAT_ROUTES.discard(task)
        _ROUTE_CANCELLATION_SENT.discard(task)


def _cancel_route_once(task: asyncio.Task[None]) -> None:
    with _CHAT_RUNTIME_LOCK:
        if task.done() or task in _ROUTE_CANCELLATION_SENT:
            return
        _ROUTE_CANCELLATION_SENT.add(task)
    task.cancel()


def _route_cancellation_was_sent(task: asyncio.Task[None]) -> bool:
    with _CHAT_RUNTIME_LOCK:
        return task in _ROUTE_CANCELLATION_SENT


def _cancel_all_active_routes() -> None:
    with _CHAT_RUNTIME_LOCK:
        routes = tuple(_ACTIVE_CHAT_ROUTES)
    for task in routes:
        try:
            task.get_loop().call_soon_threadsafe(_cancel_route_once, task)
        except RuntimeError:
            continue


register_chat_poison_listener(_cancel_all_active_routes)


def _observe_supervised_route(
    task: asyncio.Task[None],
    lease: _AdmissionLease,
) -> None:
    with _CHAT_RUNTIME_LOCK:
        _SUPERVISED_CHAT_ROUTES.discard(task)
    _forget_route(task)
    lease.release()
    if task.cancelled():
        return
    error: BaseException | None = None
    try:
        task.result()
    except BaseException as task_error:
        error = task_error
    poison_chat_safety(
        reason=(
            "supervised_chat_route_failed"
            if error is not None
            else "supervised_chat_route_completed_after_cancellation"
        ),
        error_class=type(error).__name__ if error is not None else None,
    )


def _supervise_route(
    task: asyncio.Task[None],
    lease: _AdmissionLease,
) -> None:
    with _CHAT_RUNTIME_LOCK:
        if task in _SUPERVISED_CHAT_ROUTES:
            return
        _SUPERVISED_CHAT_ROUTES.add(task)
    task.add_done_callback(lambda completed: _observe_supervised_route(completed, lease))


def _observe_supervised_send(
    task: asyncio.Task[None],
    *,
    response_is_terminal: bool,
) -> None:
    with _CHAT_RUNTIME_LOCK:
        _SUPERVISED_CHAT_SENDS.discard(task)
    if task.cancelled():
        return
    error: BaseException | None = None
    try:
        task.result()
    except BaseException as task_error:
        error = task_error
    if response_is_terminal or isinstance(error, OSError):
        _LOGGER.warning(
            "Supervised chat response transport finished after its delivery fence",
            extra={
                "error_class": type(error).__name__ if error is not None else None,
                "response_is_terminal": response_is_terminal,
            },
        )
        return
    poison_chat_safety(
        reason=(
            "supervised_chat_send_failed"
            if error is not None
            else "supervised_chat_send_completed_after_cancellation"
        ),
        error_class=type(error).__name__ if error is not None else None,
    )


def _supervise_send(
    task: asyncio.Task[None],
    *,
    response_is_terminal: bool,
) -> None:
    with _CHAT_RUNTIME_LOCK:
        if task in _SUPERVISED_CHAT_SENDS:
            return
        _SUPERVISED_CHAT_SENDS.add(task)
    task.add_done_callback(
        lambda completed: _observe_supervised_send(
            completed,
            response_is_terminal=response_is_terminal,
        )
    )


class ChatIngressDeadlineMiddleware:
    """Outermost ASGI fence for both authenticated chat entry points."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        chat_paths: frozenset[str],
        max_active_requests: int,
        cors_origins: frozenset[str] = frozenset(),
        operation_timeout_seconds: float = CHAT_OPERATION_TIMEOUT_SECONDS,
        cleanup_timeout_seconds: float = CHAT_OPERATION_CLEANUP_SECONDS,
        finalization_reserve_seconds: float = CHAT_FINALIZATION_RESERVE_SECONDS,
    ) -> None:
        if not chat_paths:
            raise ValueError("chat ingress paths must not be empty")
        if max_active_requests <= 0:
            raise ValueError("chat active request limit must be positive")
        if (
            operation_timeout_seconds <= 0
            or cleanup_timeout_seconds <= 0
            or finalization_reserve_seconds <= 0
        ):
            raise ValueError("chat ingress deadlines must be positive")
        self.app = app
        self._chat_paths = chat_paths
        self._max_active_requests = max_active_requests
        self._cors_origins = cors_origins
        self._operation_timeout_seconds = operation_timeout_seconds
        self._cleanup_timeout_seconds = cleanup_timeout_seconds
        self._finalization_reserve_seconds = finalization_reserve_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not _matches_chat_path(
            cast(str, scope.get("path", "")), self._chat_paths
        ):
            await self.app(scope, receive, send)
            return

        loop = asyncio.get_running_loop()
        started_at = loop.time()
        deadlines = ChatRequestDeadlines(
            started_at=started_at,
            operation_deadline=started_at + self._operation_timeout_seconds,
            cleanup_deadline=(
                started_at + self._operation_timeout_seconds + self._cleanup_timeout_seconds
            ),
            response_deadline=(
                started_at
                + self._operation_timeout_seconds
                + self._cleanup_timeout_seconds
                + self._finalization_reserve_seconds
            ),
        )
        state = scope.setdefault("state", {})
        state["chat_request_deadlines"] = deadlines
        state["request_id"] = normalize_request_id(
            _header_value(scope, b"x-request-id") or cast(str | None, state.get("request_id"))
        )

        admission_error = _admission_error()
        if admission_error is not None:
            await _send_json(
                scope,
                receive,
                send,
                deadline=deadlines.response_deadline,
                status_code=503,
                code=admission_error,
                message=(
                    "Chat processing is fail-closed pending operator reconciliation"
                    if admission_error == "chat_safety_poisoned"
                    else "A previous request is still completing fail-closed cleanup"
                ),
                cors_origins=self._cors_origins,
            )
            return
        lease = _try_admit(self._max_active_requests)
        if lease is None:
            await _send_json(
                scope,
                receive,
                send,
                deadline=deadlines.response_deadline,
                status_code=503,
                code="chat_capacity_exceeded",
                message="Chat capacity is temporarily exhausted; retry later",
                headers={"Retry-After": "1"},
                cors_origins=self._cors_origins,
            )
            return

        transcript = _ResponseTranscript()
        gate_closed = False
        lease_transferred = False

        async def fenced_receive() -> Message:
            if gate_closed:
                return {"type": "http.disconnect"}
            return await receive()

        async def execute_inner() -> None:
            await self.app(scope, fenced_receive, transcript.capture)

        route_task = asyncio.create_task(execute_inner(), name="chat-ingress-request")
        _register_route(route_task)
        # Close the admission/register race: a poison that landed before this
        # task became visible cannot rely on the one-shot listener fan-out.
        if chat_safety_poisoned():
            _cancel_route_once(route_task)
        outer_cancellation: asyncio.CancelledError | None = None
        try:
            while not route_task.done():
                remaining = deadlines.operation_deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    completed, _ = await asyncio.wait({route_task}, timeout=remaining)
                except asyncio.CancelledError as cancellation:
                    if outer_cancellation is None:
                        outer_cancellation = cancellation
                    break
                if completed:
                    break

            completed_within_operation_budget = (
                route_task.done()
                and loop.time() <= deadlines.operation_deadline
                and outer_cancellation is None
            )
            if completed_within_operation_budget:
                if chat_safety_poisoned():
                    transcript.close_and_discard()
                    if _route_cancellation_was_sent(route_task):
                        error = _task_error(route_task)
                        _LOGGER.critical(
                            "Chat route reached a terminal state after the safety fence",
                            extra={
                                "request_id": state.get("request_id"),
                                "route_cancelled": route_task.cancelled(),
                                "error_class": (
                                    type(error).__name__
                                    if error is not None and not route_task.cancelled()
                                    else None
                                ),
                            },
                        )
                    await _send_json(
                        scope,
                        receive,
                        send,
                        deadline=deadlines.response_deadline,
                        status_code=503,
                        code="chat_safety_poisoned",
                        message=("Chat processing is fail-closed pending operator reconciliation"),
                        cors_origins=self._cors_origins,
                    )
                    return
                if _route_cancellation_was_sent(route_task):
                    error = _task_error(route_task)
                    transcript.close_and_discard()
                    poison_chat_safety(
                        reason=(
                            "chat_route_failed_after_cancellation"
                            if error is not None and not route_task.cancelled()
                            else (
                                "chat_route_cancelled_after_safety_fence"
                                if route_task.cancelled()
                                else "chat_route_completed_after_cancellation"
                            )
                        ),
                        error_class=(
                            type(error).__name__
                            if error is not None and not route_task.cancelled()
                            else None
                        ),
                    )
                    await _send_json(
                        scope,
                        receive,
                        send,
                        deadline=deadlines.response_deadline,
                        status_code=503,
                        code="chat_safety_poisoned",
                        message=("Chat processing is fail-closed pending operator reconciliation"),
                        cors_origins=self._cors_origins,
                    )
                    return
                error = _task_error(route_task)
                if error is None and transcript.complete():
                    await _flush_transcript(
                        transcript,
                        send,
                        deadline=deadlines.response_deadline,
                    )
                    return
                if (
                    error is not None
                    and transcript.complete()
                    and transcript.status_code is not None
                    and transcript.status_code >= 500
                ):
                    _LOGGER.error(
                        "Chat request failed after producing a bounded server-error response",
                        extra={
                            "request_id": state.get("request_id"),
                            "error_class": type(error).__name__,
                        },
                    )
                    await _flush_transcript(
                        transcript,
                        send,
                        deadline=deadlines.response_deadline,
                    )
                    return
                transcript.close_and_discard()
                _LOGGER.error(
                    "Unhandled chat request failure",
                    exc_info=(
                        (type(error), error, error.__traceback__) if error is not None else None
                    ),
                    extra={"request_id": state.get("request_id")},
                )
                await _send_json(
                    scope,
                    receive,
                    send,
                    deadline=deadlines.response_deadline,
                    status_code=500,
                    code="internal_error",
                    message="An unexpected error occurred",
                    cors_origins=self._cors_origins,
                )
                return

            gate_closed = True
            transcript.close_and_discard()
            if not route_task.done():
                _cancel_route_once(route_task)
            cleanup_deadline = min(
                deadlines.cleanup_deadline,
                loop.time() + self._cleanup_timeout_seconds,
            )
            while not route_task.done():
                remaining = cleanup_deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    completed, _ = await asyncio.wait({route_task}, timeout=remaining)
                except asyncio.CancelledError as cancellation:
                    if outer_cancellation is None:
                        outer_cancellation = cancellation
                    continue
                if completed:
                    break

            if not route_task.done():
                _supervise_route(route_task, lease)
                lease_transferred = True
                poison_chat_safety(reason="chat_route_cleanup_exceeded_deadline")
            elif route_task.cancelled():
                pass
            elif _route_cancellation_was_sent(route_task):
                error = _task_error(route_task)
                poison_chat_safety(
                    reason=(
                        "chat_route_failed_after_cancellation"
                        if error is not None
                        else "chat_route_completed_after_cancellation"
                    ),
                    error_class=type(error).__name__ if error is not None else None,
                )
            else:
                _task_error(route_task)

            if outer_cancellation is not None:
                raise outer_cancellation
            if loop.time() >= deadlines.response_deadline:
                poison_chat_safety(reason="chat_response_deadline_missed")
                raise RuntimeError("chat response deadline elapsed before a safe response")
            code = (
                "chat_safety_poisoned"
                if chat_safety_poisoned()
                and route_task.cancelled()
                and loop.time() < deadlines.operation_deadline
                else "chat_request_timeout"
            )
            await _send_json(
                scope,
                receive,
                send,
                deadline=deadlines.response_deadline,
                status_code=503 if code == "chat_safety_poisoned" else 504,
                code=code,
                message=(
                    "Chat processing is fail-closed pending operator reconciliation"
                    if code == "chat_safety_poisoned"
                    else "The chat request exceeded its bounded processing time"
                ),
                cors_origins=self._cors_origins,
            )
        finally:
            if not lease_transferred:
                _forget_route(route_task)
                lease.release()


def _admission_error() -> str | None:
    if chat_safety_poisoned():
        return "chat_safety_poisoned"
    if (
        chat_cleanup_backlog_size() > 0
        or llm_cleanup_backlog_size() > 0
        or chat_finalization_backlog_size() > 0
        or chat_route_backlog_size() > 0
    ):
        return "cleanup_in_progress"
    return None


def _task_error(task: asyncio.Task[None]) -> BaseException | None:
    if task.cancelled():
        return asyncio.CancelledError()
    try:
        task.result()
    except BaseException as error:
        return error
    return None


async def _flush_transcript(
    transcript: _ResponseTranscript,
    send: Send,
    *,
    deadline: float,
) -> None:
    if not transcript.complete():
        raise RuntimeError("chat response transcript is incomplete")
    transcript.closed = True
    await _send_messages(
        transcript.messages,
        send,
        deadline=deadline,
        response_is_terminal=True,
    )


async def _send_json(
    scope: Scope,
    receive: Receive,
    send: Send,
    *,
    deadline: float,
    status_code: int,
    code: str,
    message: str,
    headers: dict[str, str] | None = None,
    cors_origins: frozenset[str] = frozenset(),
) -> None:
    request_id = cast(dict[str, Any], scope.get("state", {})).get("request_id")
    response_headers = {
        "X-Request-ID": str(request_id),
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        **(headers or {}),
    }
    origin = _header_value(scope, b"origin")
    if origin is not None and origin in cors_origins:
        response_headers.update(
            {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }
        )
    response = JSONResponse(
        status_code=status_code,
        content={
            "error": {"code": code, "message": message},
            "request_id": request_id,
        },
        headers=response_headers,
    )
    rendered: list[Message] = []

    async def capture(message: Message) -> None:
        rendered.append(cast(Message, dict(message)))

    await response(scope, receive, capture)
    await _send_messages(
        rendered,
        send,
        deadline=deadline,
        response_is_terminal=False,
    )


async def _send_messages(
    messages: list[Message],
    send: Send,
    *,
    deadline: float,
    response_is_terminal: bool,
) -> None:
    loop = asyncio.get_running_loop()
    response_started = False
    send_attempted = False

    async def deliver() -> None:
        nonlocal response_started, send_attempted
        for message in messages:
            if loop.time() >= deadline:
                raise TimeoutError("chat response deadline elapsed before send")
            send_attempted = True
            await send(message)
            if loop.time() >= deadline:
                raise TimeoutError("chat response send crossed its absolute deadline")
            if message.get("type") == "http.response.start":
                response_started = True

    send_task = asyncio.create_task(deliver(), name="chat-response-send")
    outer_cancellation: asyncio.CancelledError | None = None
    remaining = max(0.0, deadline - loop.time())
    try:
        completed, _ = await asyncio.wait({send_task}, timeout=remaining)
    except asyncio.CancelledError as cancellation:
        outer_cancellation = cancellation
        completed = set()
    if completed:
        error = _task_error(send_task)
        if outer_cancellation is not None:
            raise outer_cancellation from error
        if error is not None:
            if response_is_terminal or isinstance(error, OSError):
                _LOGGER.warning(
                    "Chat response transport failed after the application result was finalized",
                    extra={
                        "error_class": type(error).__name__,
                        "response_is_terminal": response_is_terminal,
                        "response_started": response_started,
                        "send_attempted": send_attempted,
                    },
                )
            else:
                poison_chat_safety(
                    reason=(
                        "chat_response_send_failed_after_start"
                        if response_started or send_attempted
                        else "chat_response_send_failed_before_start"
                    ),
                    error_class=type(error).__name__,
                )
            raise error
        if loop.time() >= deadline:
            if response_is_terminal:
                _LOGGER.error(
                    "Terminal chat response crossed its absolute delivery deadline",
                    extra={
                        "response_started": response_started,
                        "send_attempted": send_attempted,
                    },
                )
            else:
                poison_chat_safety(reason="chat_response_send_crossed_deadline")
            raise RuntimeError("chat response crossed its absolute deadline")
        return

    if not send_task.done():
        send_task.cancel()
        # Do not await here: a second outer cancellation must not interrupt the
        # strong-reference handoff or replace the first cancellation semantics.
        _supervise_send(
            send_task,
            response_is_terminal=response_is_terminal,
        )
    if response_is_terminal:
        _LOGGER.error(
            "Terminal chat response could not be delivered within its bounded deadline",
            extra={
                "outer_cancelled": outer_cancellation is not None,
                "response_started": response_started,
                "send_attempted": send_attempted,
            },
        )
    else:
        poison_chat_safety(
            reason=(
                "chat_response_send_failed_after_start"
                if response_started or send_attempted
                else "chat_response_send_failed_before_start"
            )
        )
    if outer_cancellation is not None:
        raise outer_cancellation
    raise RuntimeError("chat response could not be delivered within its deadline")


def _header_value(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            try:
                return cast(bytes, value).decode("ascii")
            except UnicodeDecodeError:
                return None
    return None


def _matches_chat_path(path: str, chat_paths: frozenset[str]) -> bool:
    return path in chat_paths or (path.endswith("/") and path[:-1] in chat_paths)


def _reset_chat_ingress_for_testing() -> None:
    """Reset process-local admission bookkeeping between isolated tests."""

    global _ACTIVE_CHAT_REQUESTS
    with _CHAT_RUNTIME_LOCK:
        if any(not task.done() for task in _ACTIVE_CHAT_ROUTES):
            raise RuntimeError("cannot reset chat ingress while requests are active")
        _ACTIVE_CHAT_REQUESTS = 0
        _ACTIVE_CHAT_ROUTES.clear()
        _ROUTE_CANCELLATION_SENT.clear()
        _SUPERVISED_CHAT_ROUTES.clear()
        _SUPERVISED_CHAT_SENDS.clear()
