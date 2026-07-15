from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any

from app.api.errors import ApiError

CHAT_SERVER_TIMEOUT_SECONDS = 95.0
CHAT_DISCONNECT_POLL_SECONDS = 0.1


async def _wait_for_disconnect(
    is_disconnected: Callable[[], Awaitable[bool]],
    *,
    poll_seconds: float,
) -> None:
    while True:
        if await is_disconnected():
            return
        await asyncio.sleep(poll_seconds)


async def _cancel_and_join(task: asyncio.Task[Any]) -> None:
    if not task.done():
        task.cancel()
    await asyncio.gather(task, return_exceptions=True)


async def run_chat_with_budget[ResultT](
    operation: Callable[[], Coroutine[Any, Any, ResultT]],
    *,
    is_disconnected: Callable[[], Awaitable[bool]],
    timeout_seconds: float = CHAT_SERVER_TIMEOUT_SECONDS,
    disconnect_poll_seconds: float = CHAT_DISCONNECT_POLL_SECONDS,
) -> ResultT:
    """Run one chat operation under a total budget and client disconnect fence.

    Cancelling the operation task propagates into the active ``httpx`` model
    request. The idempotency and usage layers then persist an unknown outcome
    before re-raising cancellation, so no retry can trigger a second provider
    call for an outcome that may already have been billed upstream.
    """

    if timeout_seconds <= 0:
        raise ValueError("chat timeout must be positive")
    if disconnect_poll_seconds <= 0:
        raise ValueError("disconnect poll interval must be positive")

    operation_task: asyncio.Task[ResultT] = asyncio.create_task(
        operation(), name="chat-request-operation"
    )
    disconnect_task: asyncio.Task[None] = asyncio.create_task(
        _wait_for_disconnect(
            is_disconnected,
            poll_seconds=disconnect_poll_seconds,
        ),
        name="chat-request-disconnect-monitor",
    )
    try:
        try:
            async with asyncio.timeout(timeout_seconds):
                completed, _ = await asyncio.wait(
                    {operation_task, disconnect_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
        except TimeoutError as error:
            await _cancel_and_join(operation_task)
            raise ApiError(
                status_code=504,
                code="chat_request_timeout",
                message="The chat request exceeded its bounded processing time",
            ) from error

        # If completion and disconnect race, prefer a response whose operation
        # has already reached a known terminal state.
        if operation_task in completed:
            await _cancel_and_join(disconnect_task)
            return await operation_task

        try:
            disconnect_task.result()
        except Exception as error:
            await _cancel_and_join(operation_task)
            raise ApiError(
                status_code=503,
                code="chat_disconnect_monitor_failed",
                message="The chat connection state could not be verified",
            ) from error

        await _cancel_and_join(operation_task)
        raise ApiError(
            status_code=499,
            code="client_disconnected",
            message="The client disconnected before the chat request completed",
        )
    finally:
        await _cancel_and_join(disconnect_task)
        if not operation_task.done():
            await _cancel_and_join(operation_task)
