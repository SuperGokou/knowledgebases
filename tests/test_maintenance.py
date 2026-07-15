from __future__ import annotations

import asyncio
import logging
import signal
from typing import Any

import pytest

from app import maintenance
from app.core.config import Settings
from app.maintenance import MAINTENANCE_CYCLE_TIMEOUT_SECONDS, run_maintenance_once
from app.services.llm_settings import LlmConfigurationError


class _SessionContext:
    async def __aenter__(self) -> object:
        return object()

    async def __aexit__(self, *_args: object) -> None:
        return None


def test_cycle_deadline_preserves_margin_inside_container_stop_grace() -> None:
    assert MAINTENANCE_CYCLE_TIMEOUT_SECONDS == 105
    assert MAINTENANCE_CYCLE_TIMEOUT_SECONDS < 120


@pytest.mark.asyncio
async def test_isolated_maintenance_skips_external_conversion_and_keeps_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def cleanup(*_args: Any, **_kwargs: Any) -> int:
        calls.append("cleanup")
        return 2

    async def forbidden_resolve(*_args: Any, **_kwargs: Any) -> None:
        calls.append("resolve")
        raise AssertionError("isolated maintenance must not resolve a public LLM client")

    async def local_conversion(*args: Any, **_kwargs: Any) -> int:
        calls.append("convert")
        assert args[2] is None
        return 1

    async def scan(*_args: Any, **_kwargs: Any) -> int:
        calls.append("scan")
        return 3

    async def idempotency(*_args: Any, **_kwargs: Any) -> int:
        calls.append("idempotency")
        return 4

    monkeypatch.setattr("app.maintenance.cleanup_expired_uploads", cleanup)
    monkeypatch.setattr("app.maintenance.cleanup_chat_idempotency_records", idempotency)
    monkeypatch.setattr("app.maintenance.resolve_provider_client", forbidden_resolve)
    monkeypatch.setattr("app.maintenance.process_malware_scan_batch", scan)
    monkeypatch.setattr("app.maintenance.process_okf_conversion_batch", local_conversion)

    result = await run_maintenance_once(
        session=object(),  # type: ignore[arg-type]
        storage=object(),  # type: ignore[arg-type]
        settings=Settings(environment="test"),
    )

    assert result == {"cleaned": 2, "chat_idempotency": 4, "scanned": 3, "converted": 1}
    assert calls == ["cleanup", "idempotency", "scan", "convert"]


@pytest.mark.asyncio
async def test_invalid_external_provider_configuration_pauses_conversion_without_crashing_worker(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def no_work(*_args: Any, **_kwargs: Any) -> int:
        return 0

    async def invalid_provider(*_args: Any, **_kwargs: Any) -> None:
        raise LlmConfigurationError("controlled_gateway_provider_url_not_allowed")

    async def forbidden_conversion(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("invalid provider configuration must leave conversions queued")

    monkeypatch.setattr(maintenance, "cleanup_expired_uploads", no_work)
    monkeypatch.setattr(maintenance, "cleanup_chat_idempotency_records", no_work)
    monkeypatch.setattr(maintenance, "process_malware_scan_batch", no_work)
    monkeypatch.setattr(maintenance, "resolve_provider_client", invalid_provider)
    monkeypatch.setattr(maintenance, "process_okf_conversion_batch", forbidden_conversion)

    with caplog.at_level(logging.ERROR, logger="app.maintenance"):
        result = await run_maintenance_once(
            session=object(),  # type: ignore[arg-type]
            storage=object(),  # type: ignore[arg-type]
            settings=Settings(environment="test", llm_egress_mode="direct"),
        )

    assert result == {"cleaned": 0, "chat_idempotency": 0, "scanned": 0, "converted": 0}
    record = next(
        item
        for item in caplog.records
        if item.message == "LLM provider configuration rejected; OKF conversions remain queued"
    )
    assert record.__dict__["llm_configuration_error"] == (
        "controlled_gateway_provider_url_not_allowed"
    )


@pytest.mark.asyncio
async def test_worker_closes_llm_pool_on_normal_exit_and_uses_structured_logging(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    closed = 0

    async def batch(*_args: Any, **_kwargs: Any) -> dict[str, int]:
        return {"cleaned": 1, "chat_idempotency": 2, "scanned": 3, "converted": 4}

    async def close_pool() -> None:
        nonlocal closed
        closed += 1

    monkeypatch.setattr(maintenance, "get_settings", lambda: Settings(environment="test"))
    monkeypatch.setattr(maintenance, "StorageService", lambda _settings: object())
    monkeypatch.setattr(maintenance, "SessionFactory", _SessionContext)
    monkeypatch.setattr(maintenance, "run_maintenance_once", batch)
    monkeypatch.setattr(maintenance, "close_shared_llm_clients", close_pool)

    with caplog.at_level(logging.INFO, logger="app.maintenance"):
        await maintenance.run(once=True, interval_seconds=60)

    assert closed == 1
    record = next(item for item in caplog.records if item.message == "Maintenance batch completed")
    assert (
        record.__dict__["cleaned"],
        record.__dict__["chat_idempotency"],
        record.__dict__["scanned"],
        record.__dict__["converted"],
    ) == (
        1,
        2,
        3,
        4,
    )


@pytest.mark.asyncio
async def test_worker_closes_llm_pool_when_batch_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed = 0

    async def failed_batch(*_args: Any, **_kwargs: Any) -> dict[str, int]:
        raise RuntimeError("batch failed")

    async def close_pool() -> None:
        nonlocal closed
        closed += 1

    monkeypatch.setattr(maintenance, "get_settings", lambda: Settings(environment="test"))
    monkeypatch.setattr(maintenance, "StorageService", lambda _settings: object())
    monkeypatch.setattr(maintenance, "SessionFactory", _SessionContext)
    monkeypatch.setattr(maintenance, "run_maintenance_once", failed_batch)
    monkeypatch.setattr(maintenance, "close_shared_llm_clients", close_pool)

    with pytest.raises(RuntimeError, match="batch failed"):
        await maintenance.run(once=True, interval_seconds=60)
    assert closed == 1


@pytest.mark.asyncio
async def test_worker_cancellation_still_closes_llm_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = asyncio.Event()
    closed = asyncio.Event()

    async def blocked_batch(*_args: Any, **_kwargs: Any) -> dict[str, int]:
        entered.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def close_pool() -> None:
        closed.set()

    monkeypatch.setattr(maintenance, "get_settings", lambda: Settings(environment="test"))
    monkeypatch.setattr(maintenance, "StorageService", lambda _settings: object())
    monkeypatch.setattr(maintenance, "SessionFactory", _SessionContext)
    monkeypatch.setattr(maintenance, "run_maintenance_once", blocked_batch)
    monkeypatch.setattr(maintenance, "close_shared_llm_clients", close_pool)

    worker = asyncio.create_task(maintenance.run(once=False, interval_seconds=60))
    await entered.wait()
    worker.cancel()
    with pytest.raises(asyncio.CancelledError):
        await worker
    assert closed.is_set()


@pytest.mark.asyncio
async def test_cycle_deadline_cancels_blocked_phase_logs_and_closes_pool(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    phase_cancelled = asyncio.Event()
    pool_closed = asyncio.Event()

    async def blocked_phase(*_args: Any, **_kwargs: Any) -> dict[str, int]:
        try:
            await asyncio.Event().wait()
        finally:
            phase_cancelled.set()
        raise AssertionError("unreachable")

    async def close_pool() -> None:
        pool_closed.set()

    monkeypatch.setattr(maintenance, "get_settings", lambda: Settings(environment="test"))
    monkeypatch.setattr(maintenance, "StorageService", lambda _settings: object())
    monkeypatch.setattr(maintenance, "SessionFactory", _SessionContext)
    monkeypatch.setattr(maintenance, "run_maintenance_once", blocked_phase)
    monkeypatch.setattr(maintenance, "close_shared_llm_clients", close_pool)
    monkeypatch.setattr(maintenance, "MAINTENANCE_CYCLE_TIMEOUT_SECONDS", 0.01)

    with caplog.at_level(logging.ERROR, logger="app.maintenance"):
        await asyncio.wait_for(
            maintenance.run(once=True, interval_seconds=60),
            timeout=1,
        )

    assert phase_cancelled.is_set()
    assert pool_closed.is_set()
    record = next(
        item for item in caplog.records if item.message == "Maintenance cycle deadline exceeded"
    )
    assert record.__dict__["cycle_timeout_seconds"] == 0.01
    assert record.__dict__["shutdown_requested"] is False


@pytest.mark.asyncio
async def test_cycle_deadline_cancels_blocked_malware_scan_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_cancelled = asyncio.Event()
    pool_closed = asyncio.Event()

    async def no_work(*_args: Any, **_kwargs: Any) -> int:
        return 0

    async def blocked_scan(*_args: Any, **_kwargs: Any) -> int:
        try:
            await asyncio.Event().wait()
        finally:
            scan_cancelled.set()
        raise AssertionError("unreachable")

    async def forbidden_conversion(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("conversion must not start after the scan deadline")

    async def close_pool() -> None:
        pool_closed.set()

    monkeypatch.setattr(maintenance, "get_settings", lambda: Settings(environment="test"))
    monkeypatch.setattr(maintenance, "StorageService", lambda _settings: object())
    monkeypatch.setattr(maintenance, "SessionFactory", _SessionContext)
    monkeypatch.setattr(maintenance, "cleanup_expired_uploads", no_work)
    monkeypatch.setattr(maintenance, "cleanup_chat_idempotency_records", no_work)
    monkeypatch.setattr(maintenance, "process_malware_scan_batch", blocked_scan)
    monkeypatch.setattr(maintenance, "process_okf_conversion_batch", forbidden_conversion)
    monkeypatch.setattr(maintenance, "close_shared_llm_clients", close_pool)
    monkeypatch.setattr(maintenance, "MAINTENANCE_CYCLE_TIMEOUT_SECONDS", 0.01)

    await asyncio.wait_for(
        maintenance.run(once=True, interval_seconds=60),
        timeout=1,
    )

    assert scan_cancelled.is_set()
    assert pool_closed.is_set()


@pytest.mark.asyncio
async def test_cycle_deadline_cancels_blocked_llm_phase_and_releases_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conversion_cancelled = asyncio.Event()
    lease_closed = asyncio.Event()
    pool_closed = asyncio.Event()

    async def no_work(*_args: Any, **_kwargs: Any) -> int:
        return 0

    class FakeLlmLease:
        async def __aenter__(self) -> FakeLlmLease:
            return self

        async def __aexit__(self, *_args: object) -> None:
            lease_closed.set()

    async def resolve_client(*_args: Any, **_kwargs: Any) -> FakeLlmLease:
        return FakeLlmLease()

    async def blocked_conversion(*_args: Any, **_kwargs: Any) -> int:
        try:
            await asyncio.Event().wait()
        finally:
            conversion_cancelled.set()
        raise AssertionError("unreachable")

    async def close_pool() -> None:
        pool_closed.set()

    settings = Settings(environment="test", llm_egress_mode="direct")
    monkeypatch.setattr(maintenance, "get_settings", lambda: settings)
    monkeypatch.setattr(maintenance, "StorageService", lambda _settings: object())
    monkeypatch.setattr(maintenance, "SessionFactory", _SessionContext)
    monkeypatch.setattr(maintenance, "cleanup_expired_uploads", no_work)
    monkeypatch.setattr(maintenance, "cleanup_chat_idempotency_records", no_work)
    monkeypatch.setattr(maintenance, "process_malware_scan_batch", no_work)
    monkeypatch.setattr(maintenance, "resolve_provider_client", resolve_client)
    monkeypatch.setattr(maintenance, "process_okf_conversion_batch", blocked_conversion)
    monkeypatch.setattr(maintenance, "close_shared_llm_clients", close_pool)
    monkeypatch.setattr(maintenance, "MAINTENANCE_CYCLE_TIMEOUT_SECONDS", 0.01)

    await asyncio.wait_for(
        maintenance.run(once=True, interval_seconds=60),
        timeout=1,
    )

    assert conversion_cancelled.is_set()
    assert lease_closed.is_set()
    assert pool_closed.is_set()


@pytest.mark.asyncio
async def test_first_sigterm_at_cycle_start_is_bounded_by_deadline_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    entered = asyncio.Event()
    phase_cancelled = asyncio.Event()
    pool_closed = asyncio.Event()

    async def blocked_phase(*_args: Any, **_kwargs: Any) -> dict[str, int]:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            phase_cancelled.set()
        raise AssertionError("unreachable")

    async def close_pool() -> None:
        pool_closed.set()

    class SignalLoop:
        def __init__(self) -> None:
            self.callbacks: dict[signal.Signals, Any] = {}

        def add_signal_handler(self, shutdown_signal: signal.Signals, callback: Any) -> None:
            self.callbacks[shutdown_signal] = callback

        def remove_signal_handler(self, _shutdown_signal: signal.Signals) -> bool:
            return True

    fake_loop = SignalLoop()
    monkeypatch.setattr(maintenance, "get_settings", lambda: Settings(environment="test"))
    monkeypatch.setattr(maintenance, "StorageService", lambda _settings: object())
    monkeypatch.setattr(maintenance, "SessionFactory", _SessionContext)
    monkeypatch.setattr(maintenance, "run_maintenance_once", blocked_phase)
    monkeypatch.setattr(maintenance, "close_shared_llm_clients", close_pool)
    monkeypatch.setattr(maintenance, "MAINTENANCE_CYCLE_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: fake_loop)

    with caplog.at_level(logging.ERROR, logger="app.maintenance"):
        supervisor = asyncio.create_task(
            maintenance.run_with_shutdown_signals(once=False, interval_seconds=60)
        )
        await entered.wait()
        fake_loop.callbacks[signal.SIGTERM]()
        await asyncio.wait_for(supervisor, timeout=1)

    assert phase_cancelled.is_set()
    assert pool_closed.is_set()
    record = next(
        item for item in caplog.records if item.message == "Maintenance cycle deadline exceeded"
    )
    assert record.__dict__["shutdown_requested"] is True


@pytest.mark.asyncio
async def test_linux_sigterm_drains_current_batch_then_allows_finally_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = asyncio.Event()
    allow_batch_to_finish = asyncio.Event()
    finalized = asyncio.Event()

    async def worker(
        *,
        once: bool,
        interval_seconds: int,
        shutdown_event: asyncio.Event | None = None,
    ) -> None:
        del once, interval_seconds
        entered.set()
        try:
            await allow_batch_to_finish.wait()
            assert shutdown_event is not None and shutdown_event.is_set()
        finally:
            finalized.set()

    class SignalLoop:
        def __init__(self) -> None:
            self.callbacks: dict[signal.Signals, Any] = {}
            self.removed: list[signal.Signals] = []

        def add_signal_handler(self, shutdown_signal: signal.Signals, callback: Any) -> None:
            self.callbacks[shutdown_signal] = callback

        def remove_signal_handler(self, shutdown_signal: signal.Signals) -> bool:
            self.removed.append(shutdown_signal)
            return True

    fake_loop = SignalLoop()
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: fake_loop)
    monkeypatch.setattr(maintenance, "run", worker)

    supervisor = asyncio.create_task(
        maintenance.run_with_shutdown_signals(once=False, interval_seconds=60)
    )
    await entered.wait()
    fake_loop.callbacks[signal.SIGTERM]()
    await asyncio.sleep(0)
    assert supervisor.done() is False
    assert finalized.is_set() is False
    allow_batch_to_finish.set()
    await supervisor

    assert finalized.is_set()
    assert fake_loop.removed == [signal.SIGTERM, signal.SIGINT]
