from __future__ import annotations

import asyncio
import time
from time import monotonic
from typing import cast

import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.errors import ServerErrorMiddleware
from starlette.types import ASGIApp, Message, Scope

import app.api.chat_deadline as chat_deadline_module
from app.api.chat_deadline import (
    ChatIngressDeadlineMiddleware,
    chat_active_request_count,
    chat_route_backlog_size,
    require_chat_request_deadlines,
)
from app.api.middleware import RequestBodyLimitMiddleware
from app.services.chat_safety import chat_safety_poisoned, poison_chat_safety

_CHAT_PATH = "/chat"


def _fenced(
    app: ASGIApp,
    *,
    operation_seconds: float = 0.08,
    cleanup_seconds: float = 0.08,
    reserve_seconds: float = 0.16,
    max_active: int = 2,
) -> ChatIngressDeadlineMiddleware:
    return ChatIngressDeadlineMiddleware(
        app,
        chat_paths=frozenset({_CHAT_PATH}),
        max_active_requests=max_active,
        cors_origins=frozenset({"https://workspace.example"}),
        operation_timeout_seconds=operation_seconds,
        cleanup_timeout_seconds=cleanup_seconds,
        finalization_reserve_seconds=reserve_seconds,
    )


def test_production_app_places_chat_fence_outside_server_error_middleware() -> None:
    from app.main import create_app

    stack = create_app().build_middleware_stack()

    assert isinstance(stack, ChatIngressDeadlineMiddleware)
    assert isinstance(stack.app, ServerErrorMiddleware)


@pytest.mark.asyncio
async def test_precheck_consumes_the_same_absolute_chat_budget() -> None:
    app = FastAPI()
    dependency_cancelled = asyncio.Event()
    endpoint_started = False

    async def blocked_precheck() -> None:
        try:
            await asyncio.Event().wait()
        finally:
            dependency_cancelled.set()

    @app.post(_CHAT_PATH)
    async def chat(
        request: Request,
        _precheck: None = Depends(blocked_precheck),
    ) -> dict[str, str]:
        nonlocal endpoint_started
        endpoint_started = True
        require_chat_request_deadlines(request)
        return {"status": "late"}

    started_at = monotonic()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_fenced(app)),
        base_url="http://test",
    ) as client:
        response = await client.post(_CHAT_PATH, json={"message": "bounded"})
    elapsed = monotonic() - started_at

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "chat_request_timeout"
    assert dependency_cancelled.is_set()
    assert endpoint_started is False
    assert elapsed < 0.3
    assert chat_route_backlog_size() == 0
    assert chat_active_request_count() == 0
    assert chat_safety_poisoned() is False


@pytest.mark.parametrize(
    ("path", "method"),
    [
        (_CHAT_PATH, "POST"),
        (f"{_CHAT_PATH}/", "POST"),
        (_CHAT_PATH, "GET"),
        (f"{_CHAT_PATH}/", "PUT"),
    ],
)
@pytest.mark.asyncio
async def test_slow_request_body_cannot_run_before_the_ingress_clock(
    path: str,
    method: str,
) -> None:
    app = FastAPI()
    endpoint_started = False

    @app.post(_CHAT_PATH)
    async def chat(request: Request) -> dict[str, int]:
        nonlocal endpoint_started
        body = await request.body()
        endpoint_started = True
        return {"size": len(body)}

    messages = iter(
        [
            {"type": "http.request", "body": b"{", "more_body": True},
            {"type": "http.request", "body": b"}", "more_body": False},
        ]
    )

    async def receive() -> Message:
        await asyncio.sleep(0.1)
        return cast(Message, next(messages))

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    started_at = monotonic()
    await _fenced(RequestBodyLimitMiddleware(app, max_bytes=1024))(
        _scope(path=path, method=method),
        receive,
        send,
    )
    elapsed = monotonic() - started_at

    assert endpoint_started is False
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 504
    assert elapsed < 0.3


@pytest.mark.asyncio
async def test_event_loop_starvation_cannot_release_a_late_200() -> None:
    app = FastAPI()

    @app.post(_CHAT_PATH)
    async def chat() -> dict[str, str]:
        time.sleep(0.1)
        return {"status": "too-late"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_fenced(app)),
        base_url="http://test",
    ) as client:
        response = await client.post(_CHAT_PATH)

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "chat_request_timeout"


@pytest.mark.asyncio
async def test_starvation_past_the_hard_fence_closes_without_a_late_response() -> None:
    app = FastAPI()
    sent: list[Message] = []

    @app.post(_CHAT_PATH)
    async def chat() -> dict[str, str]:
        time.sleep(0.35)
        return {"status": "must-never-send"}

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    with pytest.raises(RuntimeError, match="deadline elapsed"):
        await _fenced(app)(
            _scope(),
            receive,
            send,
        )

    assert sent == []
    assert chat_safety_poisoned() is True
    assert chat_active_request_count() == 0


@pytest.mark.asyncio
async def test_slow_global_exception_handler_is_inside_the_same_fence() -> None:
    app = FastAPI()

    @app.exception_handler(Exception)
    async def slow_error(_request: Request, _error: Exception) -> JSONResponse:
        await asyncio.sleep(0.35)
        return JSONResponse(status_code=500, content={"error": "late"})

    @app.post(_CHAT_PATH)
    async def chat() -> dict[str, str]:
        raise RuntimeError("boom")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_fenced(app)),
        base_url="http://test",
    ) as client:
        response = await client.post(_CHAT_PATH)

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "chat_request_timeout"


@pytest.mark.asyncio
async def test_capacity_is_rejected_before_a_second_body_or_dependency_runs() -> None:
    app = FastAPI()
    first_started = asyncio.Event()
    release_first = asyncio.Event()
    calls = 0

    @app.post(_CHAT_PATH)
    async def chat() -> dict[str, str]:
        nonlocal calls
        calls += 1
        first_started.set()
        await release_first.wait()
        return {"status": "ok"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_fenced(app, max_active=1)),
        base_url="http://test",
    ) as client:
        first = asyncio.create_task(client.post(_CHAT_PATH))
        await asyncio.wait_for(first_started.wait(), timeout=1)
        rejected = await client.post(
            _CHAT_PATH,
            headers={"Origin": "https://workspace.example"},
        )
        assert rejected.status_code == 503
        assert rejected.json()["error"]["code"] == "chat_capacity_exceeded"
        assert rejected.headers["retry-after"] == "1"
        assert rejected.headers["access-control-allow-origin"] == ("https://workspace.example")
        assert rejected.headers["x-content-type-options"] == "nosniff"
        assert calls == 1
        release_first.set()
        completed = await first

    assert completed.status_code == 200
    assert chat_active_request_count() == 0


@pytest.mark.asyncio
async def test_poisoned_route_cannot_swallow_cancellation_and_release_a_200() -> None:
    app = FastAPI()
    route_started = asyncio.Event()
    cancellation_observed = asyncio.Event()

    @app.post(_CHAT_PATH)
    async def chat() -> Response:
        route_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancellation_observed.set()
            return Response(b"unsafe-200", status_code=200)
        raise AssertionError("unreachable")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_fenced(app)),
        base_url="http://test",
    ) as client:
        response_task = asyncio.create_task(client.post(_CHAT_PATH))
        await asyncio.wait_for(route_started.wait(), timeout=1)
        poison_chat_safety(reason="test_cancel_swallow_fence")
        response = await asyncio.wait_for(response_task, timeout=1)

    assert cancellation_observed.is_set()
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "chat_safety_poisoned"
    assert b"unsafe-200" not in response.content
    assert chat_active_request_count() == 0
    assert chat_route_backlog_size() == 0
    assert chat_safety_poisoned() is True


@pytest.mark.asyncio
async def test_route_that_self_poisons_cannot_immediately_release_a_200() -> None:
    app = FastAPI()

    @app.post(_CHAT_PATH)
    async def chat() -> Response:
        poison_chat_safety(reason="test_self_poison_fence")
        return Response(b"unsafe-self-200", status_code=200)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_fenced(app)),
        base_url="http://test",
    ) as client:
        response = await client.post(_CHAT_PATH)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "chat_safety_poisoned"
    assert b"unsafe-self-200" not in response.content
    assert chat_active_request_count() == 0
    assert chat_route_backlog_size() == 0
    assert chat_safety_poisoned() is True


@pytest.mark.asyncio
async def test_poison_listener_fanout_remains_linear(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    request_count = 32
    started_count = 0
    all_started = asyncio.Event()
    cancellation_callback_count = 0
    original_cancel_route_once = chat_deadline_module._cancel_route_once

    def count_cancel_callback(task: asyncio.Task[None]) -> None:
        nonlocal cancellation_callback_count
        cancellation_callback_count += 1
        original_cancel_route_once(task)

    monkeypatch.setattr(
        chat_deadline_module,
        "_cancel_route_once",
        count_cancel_callback,
    )

    @app.post(_CHAT_PATH)
    async def chat() -> dict[str, str]:
        nonlocal started_count
        started_count += 1
        if started_count == request_count:
            all_started.set()
        await asyncio.Event().wait()
        return {"status": "must-not-escape"}

    fence = _fenced(
        app,
        operation_seconds=2,
        cleanup_seconds=0.5,
        reserve_seconds=0.5,
        max_active=request_count,
    )

    async def invoke() -> int:
        sent: list[Message] = []

        async def receive() -> Message:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: Message) -> None:
            sent.append(message)

        await fence(_scope(), receive, send)
        return cast(int, sent[0]["status"])

    requests = [asyncio.create_task(invoke()) for _ in range(request_count)]
    try:
        await asyncio.wait_for(all_started.wait(), timeout=2)
        poison_chat_safety(reason="test_linear_poison_fanout")
        statuses = await asyncio.wait_for(asyncio.gather(*requests), timeout=2)
    finally:
        for request in requests:
            if not request.done():
                request.cancel()
        await asyncio.gather(*requests, return_exceptions=True)

    assert statuses == [503] * request_count
    assert cancellation_callback_count == request_count
    assert chat_active_request_count() == 0
    assert chat_route_backlog_size() == 0
    assert chat_safety_poisoned() is True


@pytest.mark.asyncio
async def test_valid_large_chat_response_stays_below_the_reviewed_buffer_cap() -> None:
    app = FastAPI()
    payload = b"x" * 1_700_000

    @app.post(_CHAT_PATH)
    async def chat() -> Response:
        return Response(payload, media_type="application/octet-stream")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_fenced(app)),
        base_url="http://test",
    ) as client:
        response = await client.post(_CHAT_PATH)

    assert response.status_code == 200
    assert response.content == payload
    assert chat_safety_poisoned() is False


@pytest.mark.asyncio
async def test_uncooperative_route_is_supervised_and_durably_fail_closed() -> None:
    app = FastAPI()
    release = asyncio.Event()
    dependency_cancelled = asyncio.Event()
    cancellation_count = 0

    async def uncooperative_precheck() -> None:
        nonlocal cancellation_count
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancellation_count += 1
            dependency_cancelled.set()
            await release.wait()

    @app.post(_CHAT_PATH)
    async def chat(
        _precheck: None = Depends(uncooperative_precheck),
    ) -> dict[str, str]:
        return {"status": "must-not-escape"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_fenced(app)),
        base_url="http://test",
    ) as client:
        response = await client.post(_CHAT_PATH)
        blocked = await client.post(_CHAT_PATH)

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "chat_request_timeout"
    assert dependency_cancelled.is_set()
    assert cancellation_count == 1
    assert chat_route_backlog_size() == 1
    assert chat_active_request_count() == 1
    assert chat_safety_poisoned() is True
    assert blocked.status_code == 503
    assert blocked.json()["error"]["code"] == "chat_safety_poisoned"

    release.set()
    for _ in range(100):
        if chat_route_backlog_size() == 0:
            break
        await asyncio.sleep(0.01)
    assert chat_route_backlog_size() == 0
    assert chat_active_request_count() == 0
    assert chat_safety_poisoned() is True


@pytest.mark.asyncio
async def test_send_backpressure_after_response_start_aborts_instead_of_silent_success() -> None:
    app = FastAPI()
    release_send = asyncio.Event()
    body_send_cancelled = asyncio.Event()
    sent: list[Message] = []

    @app.post(_CHAT_PATH)
    async def chat() -> dict[str, str]:
        return {"status": "ok"}

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)
        if message["type"] == "http.response.body":
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                body_send_cancelled.set()
                await release_send.wait()

    fence = _fenced(app)
    with pytest.raises(RuntimeError, match="could not be delivered"):
        await fence(
            _scope(),
            receive,
            send,
        )

    assert [message["type"] for message in sent] == [
        "http.response.start",
        "http.response.body",
    ]
    assert chat_safety_poisoned() is False
    assert chat_route_backlog_size() == 1

    blocked_messages: list[Message] = []

    async def blocked_send(message: Message) -> None:
        blocked_messages.append(message)

    await fence(_scope(), receive, blocked_send)
    assert blocked_messages[0]["status"] == 503
    assert b"cleanup_in_progress" in cast(bytes, blocked_messages[1]["body"])

    await asyncio.wait_for(body_send_cancelled.wait(), timeout=1)
    release_send.set()
    for _ in range(100):
        if chat_route_backlog_size() == 0:
            break
        await asyncio.sleep(0.01)
    assert chat_route_backlog_size() == 0
    assert chat_safety_poisoned() is False


@pytest.mark.parametrize(
    ("transport_error", "fail_after_start"),
    [
        pytest.param(BrokenPipeError("peer closed"), False, id="broken-pipe-before-start"),
        pytest.param(BrokenPipeError("peer closed"), True, id="broken-pipe-after-start"),
        pytest.param(
            ConnectionResetError("peer reset"),
            False,
            id="connection-reset-before-start",
        ),
        pytest.param(
            ConnectionResetError("peer reset"),
            True,
            id="connection-reset-after-start",
        ),
        pytest.param(OSError("transport unavailable"), False, id="os-error-before-start"),
        pytest.param(OSError("transport unavailable"), True, id="os-error-after-start"),
    ],
)
@pytest.mark.asyncio
async def test_terminal_response_transport_disconnect_does_not_poison_worker(
    transport_error: OSError,
    fail_after_start: bool,
) -> None:
    app = FastAPI()
    sent: list[Message] = []

    @app.post(_CHAT_PATH)
    async def chat() -> dict[str, str]:
        return {"status": "committed"}

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)
        if not fail_after_start or message["type"] == "http.response.body":
            raise transport_error

    with pytest.raises(type(transport_error)) as captured:
        await _fenced(app)(_scope(), receive, send)

    assert captured.value is transport_error
    assert sent[0]["type"] == "http.response.start"
    assert chat_safety_poisoned() is False
    assert chat_route_backlog_size() == 0
    assert chat_active_request_count() == 0


@pytest.mark.asyncio
async def test_repeated_outer_cancellation_during_send_preserves_the_first() -> None:
    app = FastAPI()
    body_send_started = asyncio.Event()
    body_send_cancelled = asyncio.Event()
    release_send = asyncio.Event()
    send_cancellation_count = 0

    @app.post(_CHAT_PATH)
    async def chat() -> dict[str, str]:
        return {"status": "ok"}

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        nonlocal send_cancellation_count
        if message["type"] != "http.response.body":
            return
        body_send_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            send_cancellation_count += 1
            body_send_cancelled.set()
            await release_send.wait()

    request = asyncio.create_task(
        _fenced(
            app,
            operation_seconds=2,
            cleanup_seconds=0.5,
            reserve_seconds=0.5,
        )(
            _scope(),
            receive,
            send,
        )
    )
    observed_cancellation: asyncio.CancelledError | None = None
    second_cancellation_accepted = True
    try:
        await asyncio.wait_for(body_send_started.wait(), timeout=2)
        assert request.cancel("FIRST") is True
        await asyncio.wait_for(body_send_cancelled.wait(), timeout=2)
        second_cancellation_accepted = request.cancel("SECOND")
        try:
            await request
        except asyncio.CancelledError as error:
            observed_cancellation = error

        assert observed_cancellation is not None
        assert observed_cancellation.args == ("FIRST",)
        assert second_cancellation_accepted is False
        assert send_cancellation_count == 1
        assert chat_safety_poisoned() is False
        assert chat_route_backlog_size() == 1
    finally:
        release_send.set()
        if not request.done():
            request.cancel()
        await asyncio.gather(request, return_exceptions=True)
        for _ in range(100):
            if chat_route_backlog_size() == 0:
                break
            await asyncio.sleep(0.01)

    assert chat_route_backlog_size() == 0
    assert chat_safety_poisoned() is False


@pytest.mark.asyncio
async def test_synchronous_send_starvation_is_detected_after_the_await_returns() -> None:
    app = FastAPI()
    sent: list[Message] = []

    @app.post(_CHAT_PATH)
    async def chat() -> dict[str, str]:
        return {"status": "ok"}

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)
        if message["type"] == "http.response.body":
            time.sleep(0.35)

    with pytest.raises((RuntimeError, TimeoutError)):
        await _fenced(app)(
            _scope(),
            receive,
            send,
        )

    assert [message["type"] for message in sent] == [
        "http.response.start",
        "http.response.body",
    ]
    assert chat_safety_poisoned() is False


def _scope(*, path: str = _CHAT_PATH, method: str = "POST") -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"host", b"test")],
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
        "state": {},
    }
