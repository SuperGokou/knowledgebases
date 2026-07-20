from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.config import Settings
from app.db.base import Base
from app.db.models import LlmProviderConfig
from app.services.llm_provider import (
    LlmProviderError,
    MeteringOutcome,
    OpenAICompatibleClient,
    OpenAICompatibleConfig,
)
from app.services.llm_settings import (
    CredentialCipher,
    LlmConfigurationError,
    resolve_provider_client,
    validate_provider_base_url,
)


class StubAsyncClient:
    def __init__(
        self,
        responses: list[httpx.Response],
        calls: list[tuple[str, dict[str, str], dict[str, Any]]],
    ) -> None:
        self._responses = responses
        self._calls = calls
        self.closed = False

    async def __aenter__(self) -> StubAsyncClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def aclose(self) -> None:
        self.closed = True

    async def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, Any],
    ) -> httpx.Response:
        self._calls.append((url, headers, json))
        return self._responses.pop(0)

    def stream(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, Any],
    ) -> StubResponseStream:
        assert method == "POST"
        self._calls.append((url, headers, json))
        return StubResponseStream(self._responses.pop(0))


class StubResponseStream:
    def __init__(self, response: httpx.Response) -> None:
        self._response = response

    async def __aenter__(self) -> httpx.Response:
        return self._response

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback


def _response(status_code: int, body: dict[str, Any]) -> httpx.Response:
    return httpx.Response(
        status_code,
        json=body,
        request=httpx.Request("POST", "https://provider.example/chat/completions"),
    )


@pytest.mark.asyncio
async def test_openai_adapter_retries_json_mode_without_provider_specific_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []
    responses = [
        _response(400, {"error": {"message": "response_format unsupported"}}),
        _response(
            200,
            {
                "model": "qwen-plus",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": (
                                '{"type":"Policy","title":"Refunds",'
                                '"description":"Approval policy.","tags":["finance"],'
                                '"body_markdown":"Refunds need approval."}'
                            )
                        },
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 12},
            },
        ),
    ]
    constructor_options: list[dict[str, Any]] = []
    created_clients: list[StubAsyncClient] = []

    def client_factory(**kwargs: Any) -> StubAsyncClient:
        constructor_options.append(kwargs)
        client = StubAsyncClient(responses, calls)
        created_clients.append(client)
        return client

    monkeypatch.setattr("app.services.llm_provider.httpx.AsyncClient", client_factory)
    client = OpenAICompatibleClient(
        OpenAICompatibleConfig(
            provider="qwen",
            api_key="server-secret",
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            model="qwen-plus",
            timeout_seconds=10,
            max_tokens=1000,
        )
    )
    result = await client.compile_okf("Refund policy", user_id="internal-user-id")

    assert result.provider == "qwen"
    assert result.draft.title == "Refunds"
    assert len(calls) == 2
    assert calls[0][0].endswith("/compatible-mode/v1/chat/completions")
    assert "response_format" in calls[0][2]
    assert "response_format" not in calls[1][2]
    assert "thinking" not in calls[0][2]
    assert "user_id" not in calls[0][2]
    assert "user" not in calls[0][2]
    assert len(constructor_options) == 1
    assert all(item["follow_redirects"] is False for item in constructor_options)
    assert all(item["trust_env"] is False for item in constructor_options)
    assert all(item["proxy"] is None for item in constructor_options)
    assert all(item["timeout"].connect == 10 for item in constructor_options)
    await client.aclose()
    assert created_clients[0].closed is True


@pytest.mark.asyncio
async def test_openai_adapter_uses_only_the_explicit_https_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructor_options: list[dict[str, Any]] = []

    def client_factory(**kwargs: Any) -> StubAsyncClient:
        constructor_options.append(kwargs)
        return StubAsyncClient([], [])

    monkeypatch.setenv("HTTPS_PROXY", "http://ambient-proxy.invalid:8080")
    monkeypatch.setattr("app.services.llm_provider.httpx.AsyncClient", client_factory)
    client = OpenAICompatibleClient(
        OpenAICompatibleConfig(
            provider="qwen",
            api_key="server-secret",
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            model="qwen-plus",
            timeout_seconds=10,
            max_tokens=1000,
            https_proxy="http://llm-egress-proxy:3128",
        )
    )

    assert constructor_options == [
        {
            "timeout": httpx.Timeout(10),
            "follow_redirects": False,
            "trust_env": False,
            "proxy": "http://llm-egress-proxy:3128",
        }
    ]
    await client.aclose()


@pytest.mark.asyncio
async def test_openai_adapter_reports_upstream_failure_without_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    def client_factory(**_kwargs: Any) -> StubAsyncClient:
        return StubAsyncClient([_response(429, {"error": {"message": "sensitive"}})], calls)

    monkeypatch.setattr("app.services.llm_provider.httpx.AsyncClient", client_factory)
    client = OpenAICompatibleClient(
        OpenAICompatibleConfig(
            provider="minimax",
            api_key="server-secret",
            base_url="https://api.minimax.io/v1/chat/completions",
            model="MiniMax-M2.7",
            timeout_seconds=10,
            max_tokens=1000,
        )
    )
    with pytest.raises(LlmProviderError) as caught:
        await client.complete_chat([{"role": "user", "content": "hello"}])
    assert caught.value.code == "llm_upstream_error"
    assert caught.value.upstream_status == 429
    assert caught.value.retryable is True
    assert caught.value.metering_outcome is MeteringOutcome.NOT_STARTED
    assert "sensitive" not in str(caught.value)
    assert calls[0][0] == "https://api.minimax.io/v1/chat/completions"


@pytest.mark.asyncio
async def test_openai_adapter_aborts_oversized_provider_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    def client_factory(**_kwargs: Any) -> StubAsyncClient:
        return StubAsyncClient(
            [
                httpx.Response(
                    200,
                    content=b"x" * 257,
                    request=httpx.Request(
                        "POST", "https://provider.example/chat/completions"
                    ),
                )
            ],
            calls,
        )

    monkeypatch.setattr("app.services.llm_provider.httpx.AsyncClient", client_factory)
    client = OpenAICompatibleClient(
        OpenAICompatibleConfig(
            provider="qwen",
            api_key="server-secret",
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            model="qwen-plus",
            timeout_seconds=10,
            max_tokens=1000,
            max_response_bytes=256,
        )
    )

    with pytest.raises(LlmProviderError) as caught:
        await client.complete_chat([{"role": "user", "content": "hello"}])

    assert caught.value.code == "llm_response_too_large"
    assert caught.value.retryable is False
    assert caught.value.metering_outcome is MeteringOutcome.UNKNOWN
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_openai_adapter_treats_server_failure_as_unknown_metering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    def client_factory(**_kwargs: Any) -> StubAsyncClient:
        return StubAsyncClient([_response(503, {"error": {"message": "hidden"}})], calls)

    monkeypatch.setattr("app.services.llm_provider.httpx.AsyncClient", client_factory)
    client = OpenAICompatibleClient(
        OpenAICompatibleConfig(
            provider="qwen",
            api_key="server-secret",
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            model="qwen-plus",
            timeout_seconds=10,
            max_tokens=1000,
        )
    )

    with pytest.raises(LlmProviderError) as caught:
        await client.complete_chat([{"role": "user", "content": "hello"}])

    assert caught.value.upstream_status == 503
    assert caught.value.metering_outcome is MeteringOutcome.UNKNOWN


@pytest.mark.asyncio
async def test_openai_adapter_marks_bad_200_with_usage_as_known_metering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    def client_factory(**_kwargs: Any) -> StubAsyncClient:
        return StubAsyncClient(
            [
                _response(
                    200,
                    {
                        "model": "qwen-plus",
                        "choices": [
                            {
                                "finish_reason": "stop",
                                "message": {"content": "not-json"},
                            }
                        ],
                        "usage": {"prompt_tokens": 17, "completion_tokens": 3},
                    },
                )
            ],
            calls,
        )

    monkeypatch.setattr("app.services.llm_provider.httpx.AsyncClient", client_factory)
    client = OpenAICompatibleClient(
        OpenAICompatibleConfig(
            provider="qwen",
            api_key="server-secret",
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            model="qwen-plus",
            timeout_seconds=10,
            max_tokens=1000,
        )
    )

    with pytest.raises(LlmProviderError) as caught:
        await client.compile_okf("Refund policy", user_id="internal-user-id")

    assert caught.value.code == "llm_invalid_output"
    assert caught.value.metering_outcome is MeteringOutcome.KNOWN
    assert caught.value.prompt_tokens == 17
    assert caught.value.completion_tokens == 3


@pytest.mark.asyncio
async def test_openai_adapter_marks_malformed_200_as_unknown_metering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    def client_factory(**_kwargs: Any) -> StubAsyncClient:
        return StubAsyncClient(
            [
                httpx.Response(
                    200,
                    content=b"not-json",
                    request=httpx.Request("POST", "https://provider.example/chat/completions"),
                )
            ],
            calls,
        )

    monkeypatch.setattr("app.services.llm_provider.httpx.AsyncClient", client_factory)
    client = OpenAICompatibleClient(
        OpenAICompatibleConfig(
            provider="qwen",
            api_key="server-secret",
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            model="qwen-plus",
            timeout_seconds=10,
            max_tokens=1000,
        )
    )

    with pytest.raises(LlmProviderError) as caught:
        await client.complete_chat([{"role": "user", "content": "hello"}])

    assert caught.value.code == "llm_invalid_response"
    assert caught.value.metering_outcome is MeteringOutcome.UNKNOWN


@pytest.mark.parametrize(
    ("provider", "url"),
    [
        ("deepseek", "https://api.deepseek.com"),
        ("minimax", "https://api.minimax.io/v1"),
        ("qwen", "https://dashscope-us.aliyuncs.com/compatible-mode/v1"),
        ("qwen", "https://workspace.us-east-1.maas.aliyuncs.com/compatible-mode/v1"),
    ],
)
def test_provider_base_url_allowlist(provider: str, url: str) -> None:
    workspace_hosts = (
        ("workspace.us-east-1.maas.aliyuncs.com",)
        if "workspace.us-east-1.maas.aliyuncs.com" in url
        else ()
    )
    assert (
        validate_provider_base_url(  # type: ignore[arg-type]
            provider,
            url,
            qwen_workspace_hosts=workspace_hosts,
        )
        == url
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://api.deepseek.com",
        "https://api.deepseek.com.attacker.example/v1",
        "https://user:password@api.deepseek.com/v1",
        "https://api.deepseek.com:444/v1",
        "https://api.deepseek.com/v1?redirect=https://attacker.example",
    ],
)
def test_provider_base_url_rejects_ssrf_shapes(url: str) -> None:
    with pytest.raises(ValueError):
        validate_provider_base_url("deepseek", url)


def test_provider_credentials_are_authenticated_and_key_bound() -> None:
    first = Settings(
        environment="test",
        llm_credentials_encryption_key=SecretStr("a" * 32),
    )
    second = Settings(
        environment="test",
        llm_credentials_encryption_key=SecretStr("b" * 32),
    )
    ciphertext = CredentialCipher(first).encrypt("provider-secret", provider="qwen")
    assert "provider-secret" not in ciphertext
    assert CredentialCipher(first).decrypt(ciphertext, provider="qwen") == "provider-secret"
    with pytest.raises(LlmConfigurationError):
        CredentialCipher(first).decrypt(ciphertext, provider="deepseek")
    with pytest.raises(LlmConfigurationError):
        CredentialCipher(second).decrypt(ciphertext, provider="qwen")


def test_qwen_workspace_host_requires_exact_configuration() -> None:
    workspace_url = "https://tenant.us-east-1.maas.aliyuncs.com/compatible-mode/v1"
    with pytest.raises(ValueError):
        validate_provider_base_url("qwen", workspace_url)
    assert (
        validate_provider_base_url(
            "qwen",
            workspace_url,
            qwen_workspace_hosts=("tenant.us-east-1.maas.aliyuncs.com",),
        )
        == workspace_url
    )


@pytest.mark.asyncio
async def test_provider_resolution_without_rows_is_read_only() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    settings = Settings(
        environment="test",
        llm_default_provider="qwen",
        qwen_api_key=SecretStr("qwen-environment-secret"),
    )
    async with factory() as session:
        client = await resolve_provider_client(session, settings)
        assert client.provider == "qwen"
        assert client.model == settings.qwen_model
        assert client.configured is True
        assert await session.scalar(select(func.count()).select_from(LlmProviderConfig)) == 0
    await engine.dispose()


@pytest.mark.asyncio
async def test_provider_resolution_propagates_the_explicit_https_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    settings = Settings(
        environment="test",
        llm_default_provider="qwen",
        qwen_api_key=SecretStr("qwen-environment-secret"),
        llm_https_proxy="http://llm-egress-proxy:3128",
    )
    captured_configs: list[OpenAICompatibleConfig] = []

    def client_factory(config: OpenAICompatibleConfig) -> OpenAICompatibleClient:
        captured_configs.append(config)
        return OpenAICompatibleClient(config)

    monkeypatch.setattr("app.services.llm_settings.OpenAICompatibleClient", client_factory)
    async with factory() as session:
        client = await resolve_provider_client(session, settings)
        assert client.provider == "qwen"
        assert captured_configs[0].https_proxy == "http://llm-egress-proxy:3128"
        await client.aclose()
    await engine.dispose()


@pytest.mark.asyncio
async def test_provider_resolution_is_disabled_by_isolated_egress_policy() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(environment="test", external_llm_enabled=False)

    async with factory() as session:
        with pytest.raises(LlmConfigurationError, match="external_llm_disabled"):
            await resolve_provider_client(session, settings)

    await engine.dispose()
