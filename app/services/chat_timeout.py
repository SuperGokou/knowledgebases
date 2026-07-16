from __future__ import annotations

import asyncio
import logging
import math
from collections.abc import Awaitable, Callable, Coroutine
from enum import StrEnum
from typing import Any

from app.api.errors import ApiError
from app.services.chat_idempotency import chat_finalization_backlog_size
from app.services.chat_safety import (
    bind_chat_cleanup_deadline,
    chat_safety_poisoned,
    poison_chat_safety,
)
from app.services.llm_provider import llm_cleanup_backlog_size

CHAT_SERVER_TIMEOUT_SECONDS = 95.0
CHAT_OPERATION_TIMEOUT_SECONDS = 85.0
CHAT_OPERATION_CLEANUP_SECONDS = 9.0
CHAT_FINALIZATION_RESERVE_SECONDS = 1.0
CHAT_DISCONNECT_POLL_SECONDS = 0.1
CHAT_DISCONNECT_PROBE_TIMEOUT_SECONDS = 1.0

_LOGGER = logging.getLogger(__name__)
_SUPERVISED_CHAT_TASKS: set[asyncio.Task[Any]] = set()


class _TerminationOutcome(StrEnum):
    CANCELLED = "cancelled"
    FAILED = "failed"
    LATE_SUCCESS = "late_success"
    SUPERVISED = "supervised"


def chat_cleanup_backlog_size() -> int:
    """Return unfinished chat tasks that exceeded request cleanup budget."""

    return sum(not task.done() for task in _SUPERVISED_CHAT_TASKS)


def _observe_supervised_task(task: asyncio.Task[Any]) -> None:
    _SUPERVISED_CHAT_TASKS.discard(task)
    if task.cancelled():
        return
    try:
        error = task.exception()
    except asyncio.CancelledError:
        return
    if error is not None:
        poison_chat_safety(
            reason="supervised_chat_task_failed",
            error_class=type(error).__name__,
        )
        _LOGGER.error(
            "Supervised chat cleanup terminated with an error",
            extra={
                "task_name": task.get_name(),
                "error_class": type(error).__name__,
            },
        )
        return
    poison_chat_safety(reason="supervised_chat_task_completed_after_cancellation")
    _LOGGER.critical(
        "A cancelled chat request task completed after its request deadline",
        extra={"task_name": task.get_name()},
    )


def _supervise_task(task: asyncio.Task[Any]) -> None:
    if task in _SUPERVISED_CHAT_TASKS:
        return
    _SUPERVISED_CHAT_TASKS.add(task)
    task.add_done_callback(_observe_supervised_task)


def _terminal_outcome(task: asyncio.Task[Any]) -> _TerminationOutcome:
    if task.cancelled():
        return _TerminationOutcome.CANCELLED
    try:
        error = task.exception()
    except asyncio.CancelledError:
        return _TerminationOutcome.CANCELLED
    if error is not None:
        poison_chat_safety(
            reason="chat_operation_failed_during_terminalization",
            error_class=type(error).__name__,
        )
        _LOGGER.error(
            "Chat operation failed while finalizing cancellation",
            extra={
                "task_name": task.get_name(),
                "error_class": type(error).__name__,
            },
        )
        return _TerminationOutcome.FAILED
    poison_chat_safety(reason="chat_operation_completed_after_terminal_fence")
    _LOGGER.critical(
        "Chat operation ignored cancellation and completed after its terminal fence",
        extra={"task_name": task.get_name()},
    )
    return _TerminationOutcome.LATE_SUCCESS


async def _terminate_operation(
    task: asyncio.Task[Any],
    *,
    deadline: float,
) -> _TerminationOutcome:
    """Send one cancellation and wait only until the absolute cleanup deadline."""

    if task.done():
        return _terminal_outcome(task)
    task.cancel()
    remaining = max(0.0, deadline - asyncio.get_running_loop().time())
    completed, _ = await asyncio.wait({task}, timeout=remaining)
    if completed:
        return _terminal_outcome(task)
    _supervise_task(task)
    _LOGGER.critical(
        "Chat operation exceeded its cleanup deadline and entered supervised fail-closed mode",
        extra={"task_name": task.get_name()},
    )
    return _TerminationOutcome.SUPERVISED


async def _await_termination_preserving_cancellation(
    task: asyncio.Task[Any],
    *,
    deadline: float,
) -> _TerminationOutcome:
    """Shield bounded cleanup from repeated request cancellation, then restore it."""

    cleanup_task = asyncio.create_task(
        _terminate_operation(task, deadline=deadline),
        name="chat-request-cleanup",
    )
    first_cancellation: asyncio.CancelledError | None = None
    while not cleanup_task.done():
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError as error:
            if first_cancellation is None:
                first_cancellation = error
    cleanup_error: BaseException | None = None
    outcome: _TerminationOutcome | None = None
    try:
        outcome = cleanup_task.result()
    except BaseException as error:
        cleanup_error = error
        poison_chat_safety(
            reason="chat_cleanup_task_failed",
            error_class=type(error).__name__,
        )
        _LOGGER.error(
            "Chat cleanup task failed",
            extra={
                "error_class": type(error).__name__,
                "caller_cancelled": first_cancellation is not None,
            },
        )
    if first_cancellation is not None:
        raise first_cancellation from cleanup_error
    if cleanup_error is not None:
        if isinstance(cleanup_error, asyncio.CancelledError):
            raise RuntimeError("chat_cleanup_cancelled") from cleanup_error
        raise cleanup_error
    if outcome is None:  # pragma: no cover - defensive task result contract.
        raise RuntimeError("chat cleanup returned no terminal outcome")
    return outcome


async def _probe_disconnect(
    is_disconnected: Callable[[], Awaitable[bool]],
    *,
    deadline: float,
    timeout_seconds: float,
) -> bool:
    """Run one non-blocking disconnect probe without coupling its cancellation."""

    loop = asyncio.get_running_loop()

    async def invoke_probe() -> bool:
        return await is_disconnected()

    probe_task: asyncio.Task[bool] = asyncio.create_task(
        invoke_probe(),
        name="chat-request-disconnect-probe",
    )
    try:
        remaining = min(timeout_seconds, max(0.0, deadline - loop.time()))
        completed, _ = await asyncio.wait({probe_task}, timeout=remaining)
    except asyncio.CancelledError:
        if not probe_task.done():
            probe_task.cancel()
            _supervise_task(probe_task)
        raise
    if not completed:
        probe_task.cancel()
        _supervise_task(probe_task)
        if loop.time() >= deadline:
            raise TimeoutError
        raise RuntimeError("chat_disconnect_probe_timeout")
    if probe_task.cancelled():
        raise RuntimeError("chat_disconnect_probe_cancelled")
    return probe_task.result()


async def run_chat_with_budget[ResultT](
    operation: Callable[[], Coroutine[Any, Any, ResultT]],
    *,
    is_disconnected: Callable[[], Awaitable[bool]],
    timeout_seconds: float = CHAT_OPERATION_TIMEOUT_SECONDS,
    operation_cleanup_seconds: float = CHAT_OPERATION_CLEANUP_SECONDS,
    disconnect_poll_seconds: float = CHAT_DISCONNECT_POLL_SECONDS,
    disconnect_probe_timeout_seconds: float = CHAT_DISCONNECT_PROBE_TIMEOUT_SECONDS,
    operation_deadline: float | None = None,
    cleanup_deadline: float | None = None,
) -> ResultT:
    """Run one chat operation under an absolute budget and disconnect fence.

    The disconnect probe is called sequentially between bounded waits, so a
    completed operation never has to cancel and join a long-lived monitor task.
    Cancellation is delivered to the side-effecting operation exactly once.
    If its fail-closed cleanup exceeds the reserved budget, the owned operation
    task is supervised and new chat work is rejected until it terminates.
    """

    if timeout_seconds <= 0:
        raise ValueError("chat timeout must be positive")
    if operation_cleanup_seconds <= 0:
        raise ValueError("chat operation cleanup timeout must be positive")
    if disconnect_poll_seconds <= 0:
        raise ValueError("disconnect poll interval must be positive")
    if disconnect_probe_timeout_seconds <= 0:
        raise ValueError("disconnect probe timeout must be positive")
    if operation_deadline is not None and not math.isfinite(operation_deadline):
        raise ValueError("chat operation deadline must be finite")
    if cleanup_deadline is not None and not math.isfinite(cleanup_deadline):
        raise ValueError("chat cleanup deadline must be finite")
    if (
        timeout_seconds + operation_cleanup_seconds + CHAT_FINALIZATION_RESERVE_SECONDS
        > CHAT_SERVER_TIMEOUT_SECONDS
    ):
        raise ValueError("chat operation and cleanup budgets exceed the server hard deadline")
    if (
        chat_safety_poisoned()
        or chat_cleanup_backlog_size() > 0
        or llm_cleanup_backlog_size() > 0
        or chat_finalization_backlog_size() > 0
    ):
        raise ApiError(
            status_code=503,
            code=("chat_safety_poisoned" if chat_safety_poisoned() else "cleanup_in_progress"),
            message=(
                "Chat processing is fail-closed pending operator reconciliation"
                if chat_safety_poisoned()
                else "A previous request is still completing fail-closed cleanup"
            ),
        )

    loop = asyncio.get_running_loop()
    started_at = loop.time()
    effective_operation_deadline = (
        operation_deadline if operation_deadline is not None else started_at + timeout_seconds
    )
    hard_deadline = (
        cleanup_deadline
        if cleanup_deadline is not None
        else min(
            started_at + CHAT_SERVER_TIMEOUT_SECONDS - CHAT_FINALIZATION_RESERVE_SECONDS,
            effective_operation_deadline + operation_cleanup_seconds,
        )
    )
    if hard_deadline < effective_operation_deadline:
        raise ValueError("chat cleanup deadline cannot precede its operation deadline")
    if loop.time() >= effective_operation_deadline:
        raise ApiError(
            status_code=504,
            code="chat_request_timeout",
            message="The chat request exceeded its bounded processing time",
        )

    async def invoke_operation() -> ResultT:
        with bind_chat_cleanup_deadline(hard_deadline):
            return await operation()

    operation_task: asyncio.Task[ResultT] = asyncio.create_task(
        invoke_operation(),
        name="chat-request-operation",
    )
    cleanup_started = False

    async def terminate_once() -> _TerminationOutcome:
        nonlocal cleanup_started
        if cleanup_started:
            raise RuntimeError("chat operation cleanup was invoked more than once")
        cleanup_started = True
        cleanup_deadline = min(
            hard_deadline,
            loop.time() + operation_cleanup_seconds,
        )
        return await _await_termination_preserving_cancellation(
            operation_task,
            deadline=cleanup_deadline,
        )

    try:
        while True:
            remaining = effective_operation_deadline - loop.time()
            if remaining <= 0:
                await terminate_once()
                raise ApiError(
                    status_code=504,
                    code="chat_request_timeout",
                    message="The chat request exceeded its bounded processing time",
                )

            completed, _ = await asyncio.wait(
                {operation_task},
                timeout=min(disconnect_poll_seconds, remaining),
            )
            if completed:
                return await operation_task

            try:
                disconnected = await _probe_disconnect(
                    is_disconnected,
                    deadline=effective_operation_deadline,
                    timeout_seconds=disconnect_probe_timeout_seconds,
                )
            except asyncio.CancelledError:
                raise
            except TimeoutError as error:
                if operation_task.done():
                    return await operation_task
                await terminate_once()
                raise ApiError(
                    status_code=504,
                    code="chat_request_timeout",
                    message="The chat request exceeded its bounded processing time",
                ) from error
            except Exception as error:
                if operation_task.done():
                    return await operation_task
                await terminate_once()
                raise ApiError(
                    status_code=503,
                    code="chat_disconnect_monitor_failed",
                    message="The chat connection state could not be verified",
                ) from error

            # The operation may have reached a terminal state while the probe was
            # running. Preserve its exact result or exception before interpreting
            # a simultaneous disconnect.
            if operation_task.done():
                return await operation_task
            if disconnected:
                await terminate_once()
                raise ApiError(
                    status_code=499,
                    code="client_disconnected",
                    message="The client disconnected before the chat request completed",
                )
    finally:
        if not cleanup_started and not operation_task.done():
            cleanup_started = True
            cleanup_deadline = min(
                hard_deadline,
                loop.time() + operation_cleanup_seconds,
            )
            await _await_termination_preserving_cancellation(
                operation_task,
                deadline=cleanup_deadline,
            )
