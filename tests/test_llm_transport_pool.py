from __future__ import annotations

import asyncio
import logging
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from types import TracebackType
from typing import Any

import httpx
import pytest

from app.services.llm_provider import (
    MAX_LLM_LOGICAL_OPERATION_SECONDS,
    LlmClientPool,
    LlmProviderError,
    LlmTransportPoolPolicy,
    OpenAICompatibleConfig,
    acquire_shared_llm_client,
    close_shared_llm_clients,
)


def _config(
    *,
    provider: str = "deepseek",
    api_key: str = "secret-one",
    model: str = "model-one",
    base_url: str = "https://provider.example/v1",
    timeout_seconds: float = 1,
) -> OpenAICompatibleConfig:
    return OpenAICompatibleConfig(
        provider=provider,
        api_key=api_key,
        base_url=base_url,
        model=model,
        timeout_seconds=timeout_seconds,
        max_tokens=100,
    )


def test_default_shutdown_drain_budget_covers_chat_without_exceeding_stop_grace() -> None:
    policy = LlmTransportPoolPolicy()

    assert policy.shutdown_drain_timeout_seconds == 110
    assert MAX_LLM_LOGICAL_OPERATION_SECONDS == 105
    assert 105 < policy.shutdown_drain_timeout_seconds < 120


class PassiveAsyncClient:
    instances: list[PassiveAsyncClient] = []

    def __init__(self, **options: Any) -> None:
        self.options = options
        self.close_calls = 0
        self.__class__.instances.append(self)

    async def aclose(self) -> None:
        self.close_calls += 1


class PassiveRootTransport(httpx.AsyncBaseTransport):
    instances: list[PassiveRootTransport] = []

    def __init__(self, **options: Any) -> None:
        self.options = options
        self.close_calls = 0
        self.__class__.instances.append(self)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected root transport request: {request.url}")

    async def aclose(self) -> None:
        self.close_calls += 1


class SlowCloseAsyncClient(PassiveAsyncClient):
    close_started = asyncio.Event()
    allow_close = asyncio.Event()

    async def aclose(self) -> None:
        self.close_started.set()
        await self.allow_close.wait()
        await super().aclose()


@pytest.fixture(autouse=True)
def _reset_test_clients() -> None:
    PassiveAsyncClient.instances.clear()
    PassiveRootTransport.instances.clear()


@pytest.mark.asyncio
async def test_pool_reuses_one_transport_and_lease_close_only_releases() -> None:
    pool = LlmClientPool(
        client_factory=PassiveAsyncClient,
        transport_factory=PassiveRootTransport,
    )

    first = await pool.acquire(_config())
    second = await pool.acquire(_config())

    assert len(PassiveAsyncClient.instances) == 1
    assert first._http is second._http
    await first.aclose()
    await second.aclose()
    assert PassiveAsyncClient.instances[0].close_calls == 0

    third = await pool.acquire(_config())
    assert third._http is first._http
    await third.aclose()
    await pool.aclose()
    assert PassiveAsyncClient.instances[0].close_calls == 1
    assert PassiveRootTransport.instances[0].close_calls == 1


@pytest.mark.asyncio
async def test_rotation_retires_old_generation_then_drains_live_lease() -> None:
    pool = LlmClientPool(
        client_factory=PassiveAsyncClient,
        transport_factory=PassiveRootTransport,
    )
    old_idle = await pool.acquire(_config(api_key="old-secret"))
    old_live = await pool.acquire(_config(api_key="old-secret"))
    await old_idle.aclose()

    new_live = await pool.acquire(_config(api_key="new-secret"))

    assert len(PassiveAsyncClient.instances) == 2
    assert len(PassiveRootTransport.instances) == 1
    assert PassiveAsyncClient.instances[0].close_calls == 0
    assert PassiveAsyncClient.instances[1].close_calls == 0

    same_new = await pool.acquire(_config(api_key="new-secret"))
    assert len(PassiveAsyncClient.instances) == 2
    await same_new.aclose()

    await old_live.aclose()
    assert PassiveAsyncClient.instances[0].close_calls == 1
    assert PassiveAsyncClient.instances[1].close_calls == 0

    await new_live.aclose()
    await pool.aclose()
    assert PassiveAsyncClient.instances[1].close_calls == 1


@pytest.mark.asyncio
async def test_canonical_endpoint_reuses_generation_and_pool_never_retains_clear_key() -> None:
    pool = LlmClientPool(client_factory=PassiveAsyncClient)
    upper = await pool.acquire(
        _config(
            api_key="very-sensitive-provider-key",
            base_url="https://PROVIDER.EXAMPLE:443/v1/",
        )
    )
    lower = await pool.acquire(
        _config(
            api_key="very-sensitive-provider-key",
            base_url="https://provider.example/v1",
        )
    )

    assert len(PassiveAsyncClient.instances) == 1
    assert upper._http is lower._http
    assert "very-sensitive-provider-key" not in repr(pool.__dict__)

    await upper.aclose()
    await lower.aclose()
    await pool.aclose()


@pytest.mark.asyncio
async def test_pool_builds_explicit_bounded_httpx_transport_options() -> None:
    policy = LlmTransportPoolPolicy(
        max_connections=7,
        max_keepalive_connections=3,
        keepalive_expiry_seconds=11,
        pool_timeout_seconds=0.25,
        provider_max_concurrency=2,
        provider_max_queue=4,
        shutdown_drain_timeout_seconds=1,
    )
    pool = LlmClientPool(
        policy=policy,
        client_factory=PassiveAsyncClient,
        transport_factory=PassiveRootTransport,
    )

    lease = await pool.acquire(_config())
    options = PassiveAsyncClient.instances[0].options

    assert options["follow_redirects"] is False
    assert options["trust_env"] is False
    assert options["timeout"].pool == 0.25
    assert isinstance(options["transport"], httpx.AsyncBaseTransport)
    assert options["event_hooks"]["request"]
    root_options = PassiveRootTransport.instances[0].options
    assert root_options["limits"].max_connections == 7
    assert root_options["limits"].max_keepalive_connections == 3
    assert root_options["limits"].keepalive_expiry == 11
    assert root_options["retries"] == 0
    assert root_options["trust_env"] is False
    assert root_options["http1"] is True
    assert root_options["http2"] is False

    await lease.aclose()
    await pool.aclose()


@pytest.mark.asyncio
async def test_shutdown_waits_for_lease_drain_and_physically_closes_every_generation() -> None:
    policy = LlmTransportPoolPolicy(shutdown_drain_timeout_seconds=1)
    pool = LlmClientPool(policy=policy, client_factory=PassiveAsyncClient)
    lease = await pool.acquire(_config())

    shutdown = asyncio.create_task(pool.aclose())
    await asyncio.sleep(0)
    assert shutdown.done() is False

    await lease.aclose()
    await asyncio.wait_for(shutdown, timeout=1)
    assert PassiveAsyncClient.instances[0].close_calls == 1
    with pytest.raises(RuntimeError, match="pool_closed"):
        await pool.acquire(_config())


@pytest.mark.asyncio
async def test_process_shutdown_rejects_a_new_lease_until_drain_finishes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.services.llm_provider.httpx.AsyncClient", PassiveAsyncClient)
    lease = await acquire_shared_llm_client(_config())
    shutdown = asyncio.create_task(close_shared_llm_clients())
    await asyncio.sleep(0)

    with pytest.raises(RuntimeError, match="pool_closed"):
        await acquire_shared_llm_client(_config())

    await lease.aclose()
    await asyncio.wait_for(shutdown, timeout=1)
    assert PassiveAsyncClient.instances[0].close_calls == 1


@pytest.mark.asyncio
async def test_cancelled_shutdown_caller_still_completes_physical_cleanup() -> None:
    SlowCloseAsyncClient.instances.clear()
    SlowCloseAsyncClient.close_started = asyncio.Event()
    SlowCloseAsyncClient.allow_close = asyncio.Event()
    pool = LlmClientPool(client_factory=SlowCloseAsyncClient)
    lease = await pool.acquire(_config())
    await lease.aclose()

    shutdown = asyncio.create_task(pool.aclose())
    await SlowCloseAsyncClient.close_started.wait()
    shutdown.cancel()
    await asyncio.sleep(0)
    shutdown.cancel()
    await asyncio.sleep(0)
    assert shutdown.done() is False

    SlowCloseAsyncClient.allow_close.set()
    with pytest.raises(asyncio.CancelledError):
        await shutdown
    assert SlowCloseAsyncClient.instances[0].close_calls == 1


@pytest.mark.asyncio
async def test_double_cancelled_lease_release_still_closes_retired_generation() -> None:
    SlowCloseAsyncClient.instances.clear()
    SlowCloseAsyncClient.close_started = asyncio.Event()
    SlowCloseAsyncClient.allow_close = asyncio.Event()
    pool = LlmClientPool(
        client_factory=SlowCloseAsyncClient,
        transport_factory=PassiveRootTransport,
    )
    old = await pool.acquire(_config(api_key="old-secret"))
    current = await pool.acquire(_config(api_key="new-secret"))

    release = asyncio.create_task(old.aclose())
    await SlowCloseAsyncClient.close_started.wait()
    release.cancel()
    await asyncio.sleep(0)
    release.cancel()
    await asyncio.sleep(0)
    assert release.done() is False

    SlowCloseAsyncClient.allow_close.set()
    with pytest.raises(asyncio.CancelledError):
        await release
    assert SlowCloseAsyncClient.instances[0].close_calls == 1

    await old.aclose()  # Idempotent after the cancelled caller observed cleanup.
    await current.aclose()
    await pool.aclose()


@pytest.mark.asyncio
async def test_shutdown_deadline_forces_close_without_logging_credentials(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pool = LlmClientPool(
        policy=LlmTransportPoolPolicy(shutdown_drain_timeout_seconds=0.01),
        client_factory=PassiveAsyncClient,
        transport_factory=PassiveRootTransport,
    )
    lease = await pool.acquire(_config(api_key="never-log-this-provider-key"))

    with caplog.at_level(logging.WARNING, logger="app.services.llm_provider"):
        await pool.aclose()

    assert PassiveAsyncClient.instances[0].close_calls == 1
    assert PassiveRootTransport.instances[0].close_calls == 1
    assert "drain deadline exceeded" in caplog.text
    assert "never-log-this-provider-key" not in caplog.text
    await lease.aclose()


@dataclass
class _ConcurrencyState:
    entered: int = 0
    maximum: int = 0


class BlockingResponseStream(AbstractAsyncContextManager[httpx.Response]):
    def __init__(
        self,
        *,
        request: httpx.Request,
        state: _ConcurrencyState,
        entered: asyncio.Event,
        release: asyncio.Event,
    ) -> None:
        self._request = request
        self._state = state
        self._entered = entered
        self._release = release

    async def __aenter__(self) -> httpx.Response:
        self._state.entered += 1
        self._state.maximum = max(self._state.maximum, self._state.entered)
        self._entered.set()
        await self._release.wait()
        return httpx.Response(
            200,
            request=self._request,
            json={
                "model": "model-one",
                "choices": [{"finish_reason": "stop", "message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self._state.entered -= 1


class BlockingAsyncClient(PassiveAsyncClient):
    state = _ConcurrencyState()
    entered = asyncio.Event()
    release = asyncio.Event()

    def stream(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, Any],
    ) -> BlockingResponseStream:
        del json
        return BlockingResponseStream(
            request=httpx.Request(method, url, headers=headers),
            state=self.state,
            entered=self.entered,
            release=self.release,
        )


@pytest.mark.asyncio
async def test_provider_bulkhead_bounds_queue_and_cancellation_does_not_leak_capacity() -> None:
    BlockingAsyncClient.instances.clear()
    BlockingAsyncClient.state = _ConcurrencyState()
    BlockingAsyncClient.entered = asyncio.Event()
    BlockingAsyncClient.release = asyncio.Event()
    policy = LlmTransportPoolPolicy(
        provider_max_concurrency=1,
        provider_max_queue=1,
        pool_timeout_seconds=0.5,
        shutdown_drain_timeout_seconds=1,
    )
    pool = LlmClientPool(policy=policy, client_factory=BlockingAsyncClient)
    first = await pool.acquire(_config())
    queued = await pool.acquire(_config())
    rejected = await pool.acquire(_config())

    first_task = asyncio.create_task(first.complete_chat([{"role": "user", "content": "one"}]))
    await BlockingAsyncClient.entered.wait()
    queued_task = asyncio.create_task(queued.complete_chat([{"role": "user", "content": "two"}]))
    await asyncio.sleep(0)

    with pytest.raises(LlmProviderError, match="llm_provider_overloaded") as caught:
        await rejected.complete_chat([{"role": "user", "content": "three"}])
    assert caught.value.metering_outcome.value == "not_started"

    queued_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await queued_task
    BlockingAsyncClient.release.set()
    await first_task

    # The cancelled waiter returned its queue admission and semaphore state.
    BlockingAsyncClient.entered = asyncio.Event()
    final = await pool.acquire(_config())
    await final.complete_chat([{"role": "user", "content": "four"}])
    assert BlockingAsyncClient.state.maximum == 1

    for lease in (first, queued, rejected, final):
        await lease.aclose()
    await pool.aclose()


@pytest.mark.asyncio
async def test_double_cancelled_bulkhead_waiter_cannot_leak_queue_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    BlockingAsyncClient.instances.clear()
    BlockingAsyncClient.state = _ConcurrencyState()
    BlockingAsyncClient.entered = asyncio.Event()
    BlockingAsyncClient.release = asyncio.Event()
    pool = LlmClientPool(
        policy=LlmTransportPoolPolicy(
            provider_max_concurrency=1,
            provider_max_queue=1,
            pool_timeout_seconds=1,
            shutdown_drain_timeout_seconds=1,
        ),
        client_factory=BlockingAsyncClient,
        transport_factory=PassiveRootTransport,
    )
    active = await pool.acquire(_config())
    queued = await pool.acquire(_config())
    active_task = asyncio.create_task(active.complete_chat([{"role": "user", "content": "active"}]))
    await BlockingAsyncClient.entered.wait()

    bulkhead = pool._bulkheads["deepseek"]
    original_release = bulkhead._release_admission
    cleanup_started = asyncio.Event()
    allow_cleanup = asyncio.Event()
    cleanup_calls = 0

    async def controlled_release() -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1
        if cleanup_calls == 1:
            cleanup_started.set()
            await allow_cleanup.wait()
        await original_release()

    monkeypatch.setattr(bulkhead, "_release_admission", controlled_release)
    queued_task = asyncio.create_task(queued.complete_chat([{"role": "user", "content": "queued"}]))
    await asyncio.sleep(0)
    queued_task.cancel()
    await cleanup_started.wait()
    queued_task.cancel()
    await asyncio.sleep(0)
    assert queued_task.done() is False

    allow_cleanup.set()
    with pytest.raises(asyncio.CancelledError):
        await queued_task
    BlockingAsyncClient.release.set()
    await active_task

    final = await pool.acquire(_config())
    await final.complete_chat([{"role": "user", "content": "capacity restored"}])
    for lease in (active, queued, final):
        await lease.aclose()
    await pool.aclose()


@pytest.mark.asyncio
async def test_rotated_generations_share_one_provider_bulkhead() -> None:
    BlockingAsyncClient.instances.clear()
    BlockingAsyncClient.state = _ConcurrencyState()
    BlockingAsyncClient.entered = asyncio.Event()
    BlockingAsyncClient.release = asyncio.Event()
    pool = LlmClientPool(
        policy=LlmTransportPoolPolicy(
            provider_max_concurrency=1,
            provider_max_queue=0,
            pool_timeout_seconds=0.5,
            shutdown_drain_timeout_seconds=1,
        ),
        client_factory=BlockingAsyncClient,
    )
    old = await pool.acquire(_config(api_key="old-secret"))
    new = await pool.acquire(_config(api_key="new-secret"))
    old_task = asyncio.create_task(old.complete_chat([{"role": "user", "content": "old"}]))
    await BlockingAsyncClient.entered.wait()

    with pytest.raises(LlmProviderError, match="llm_provider_overloaded"):
        await new.complete_chat([{"role": "user", "content": "new"}])

    BlockingAsyncClient.release.set()
    await old_task
    await old.aclose()
    await new.aclose()
    await pool.aclose()


@pytest.mark.asyncio
async def test_lease_close_drains_its_inflight_stream_before_generation_close() -> None:
    BlockingAsyncClient.instances.clear()
    BlockingAsyncClient.state = _ConcurrencyState()
    BlockingAsyncClient.entered = asyncio.Event()
    BlockingAsyncClient.release = asyncio.Event()
    pool = LlmClientPool(
        client_factory=BlockingAsyncClient,
        transport_factory=PassiveRootTransport,
    )
    old = await pool.acquire(_config(api_key="old-secret"))
    new = await pool.acquire(_config(api_key="new-secret"))
    request = asyncio.create_task(old.complete_chat([{"role": "user", "content": "in flight"}]))
    await BlockingAsyncClient.entered.wait()

    close = asyncio.create_task(old.aclose())
    await asyncio.sleep(0)
    assert close.done() is False
    assert BlockingAsyncClient.instances[0].close_calls == 0
    with pytest.raises(RuntimeError, match="lease_closed"):
        await old.complete_chat([{"role": "user", "content": "too late"}])

    BlockingAsyncClient.release.set()
    await request
    await close
    assert BlockingAsyncClient.instances[0].close_calls == 1

    await new.aclose()
    await pool.aclose()


@pytest.mark.asyncio
async def test_response_cookies_are_never_replayed_and_keys_do_not_share_generation() -> None:
    seen_headers: list[httpx.Headers] = []
    clients: list[httpx.AsyncClient] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(request.headers)
        return httpx.Response(
            200,
            headers={"Set-Cookie": "provider_session=must-not-replay; Secure"},
            json={
                "model": "model-one",
                "choices": [{"finish_reason": "stop", "message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    def factory(**options: Any) -> httpx.AsyncClient:
        options["transport"] = httpx.MockTransport(handler)
        client = httpx.AsyncClient(**options)
        clients.append(client)
        return client

    pool = LlmClientPool(client_factory=factory)
    first = await pool.acquire(_config(api_key="secret-one"))
    same_key = await pool.acquire(_config(api_key="secret-one"))
    rotated = await pool.acquire(_config(api_key="secret-two"))

    await first.complete_chat([{"role": "user", "content": "one"}])
    await same_key.complete_chat([{"role": "user", "content": "two"}])
    await rotated.complete_chat([{"role": "user", "content": "three"}])

    assert len(clients) == 2
    assert [item["authorization"] for item in seen_headers] == [
        "Bearer secret-one",
        "Bearer secret-one",
        "Bearer secret-two",
    ]
    assert all("cookie" not in item for item in seen_headers)
    assert all(len(client.cookies) == 0 for client in clients)
    assert "secret-one" not in repr(_config(api_key="secret-one"))

    for lease in (first, same_key, rotated):
        await lease.aclose()
    await pool.aclose()


@pytest.mark.asyncio
async def test_shutdown_cannot_close_transport_between_json_fallback_posts() -> None:
    calls = 0
    second_post_entered = asyncio.Event()
    allow_second_post = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                400,
                request=request,
                json={"error": {"message": "response_format unsupported"}},
            )
        second_post_entered.set()
        await allow_second_post.wait()
        return httpx.Response(
            200,
            request=request,
            json={
                "model": "model-one",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": (
                                '{"type":"Policy","title":"Approval",'
                                '"description":"Approval is required.","tags":[],'
                                '"body_markdown":"Approval is required."}'
                            )
                        },
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    def factory(**options: Any) -> httpx.AsyncClient:
        options["transport"] = httpx.MockTransport(handler)
        return httpx.AsyncClient(**options)

    pool = LlmClientPool(
        client_factory=factory,
        transport_factory=PassiveRootTransport,
    )
    lease = await pool.acquire(_config())
    compilation = asyncio.create_task(lease.compile_okf("Approval policy", user_id="internal-user"))
    await second_post_entered.wait()

    lease_close = asyncio.create_task(lease.aclose())
    shutdown = asyncio.create_task(pool.aclose())
    await asyncio.sleep(0)
    assert lease_close.done() is False
    assert shutdown.done() is False
    assert PassiveRootTransport.instances[0].close_calls == 0

    allow_second_post.set()
    result = await compilation
    assert result.draft.title == "Approval"
    await lease_close
    await shutdown
    assert calls == 2
    assert PassiveRootTransport.instances[0].close_calls == 1


@pytest.mark.asyncio
async def test_hard_logical_deadline_caps_large_provider_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_cancelled = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        try:
            await asyncio.Event().wait()
        finally:
            request_cancelled.set()
        raise AssertionError("unreachable")

    def factory(**options: Any) -> httpx.AsyncClient:
        options["transport"] = httpx.MockTransport(handler)
        return httpx.AsyncClient(**options)

    monkeypatch.setattr("app.services.llm_provider.MAX_LLM_LOGICAL_OPERATION_SECONDS", 0.01)
    pool = LlmClientPool(
        client_factory=factory,
        transport_factory=PassiveRootTransport,
    )
    lease = await pool.acquire(_config(timeout_seconds=120))

    with pytest.raises(LlmProviderError) as caught:
        await lease.compile_okf("Approval policy", user_id="internal-user")

    assert caught.value.code == "llm_operation_timeout"
    assert caught.value.metering_outcome.value == "unknown"
    assert request_cancelled.is_set()
    await lease.aclose()
    await pool.aclose()


def test_process_pool_is_partitioned_safely_by_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[PassiveAsyncClient] = []

    def factory(**options: Any) -> PassiveAsyncClient:
        client = PassiveAsyncClient(**options)
        created.append(client)
        return client

    monkeypatch.setattr("app.services.llm_provider.httpx.AsyncClient", factory)

    async def use_one_loop() -> None:
        first = await acquire_shared_llm_client(_config())
        second = await acquire_shared_llm_client(_config())
        assert first._http is second._http
        await first.aclose()
        await second.aclose()
        await close_shared_llm_clients()

    asyncio.run(use_one_loop())
    asyncio.run(use_one_loop())

    assert len(created) == 2
    assert [client.close_calls for client in created] == [1, 1]


def test_pooled_lease_rejects_operations_and_close_on_foreign_event_loop() -> None:
    owner_loop = asyncio.new_event_loop()
    foreign_loop = asyncio.new_event_loop()
    pool = LlmClientPool(
        client_factory=PassiveAsyncClient,
        transport_factory=PassiveRootTransport,
    )
    lease = None
    try:
        lease = owner_loop.run_until_complete(pool.acquire(_config()))

        async def misuse_from_foreign_loop() -> None:
            with pytest.raises(RuntimeError, match="llm_client_event_loop_mismatch"):
                await lease.complete_chat([{"role": "user", "content": "hello"}])
            with pytest.raises(RuntimeError, match="llm_client_event_loop_mismatch"):
                await lease.aclose()

        foreign_loop.run_until_complete(misuse_from_foreign_loop())

        # Foreign-loop misuse is fail-fast and does not consume the owner lease.
        assert PassiveAsyncClient.instances[0].close_calls == 0
        owner_loop.run_until_complete(lease.aclose())
        owner_loop.run_until_complete(pool.aclose())
        assert PassiveAsyncClient.instances[0].close_calls == 1
        assert PassiveRootTransport.instances[0].close_calls == 1
    finally:
        if lease is not None and not owner_loop.is_closed():
            if not lease._closed:
                owner_loop.run_until_complete(lease.aclose())
            if not pool._closed:
                owner_loop.run_until_complete(pool.aclose())
        foreign_loop.close()
        owner_loop.close()


@pytest.mark.asyncio
async def test_fastapi_lifespan_closes_the_current_event_loop_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import main as main_module

    closed = 0

    async def close_pool() -> None:
        nonlocal closed
        closed += 1

    monkeypatch.setattr(main_module, "close_shared_llm_clients", close_pool)
    application = main_module.create_app()

    async with application.router.lifespan_context(application):
        assert closed == 0

    assert closed == 1
