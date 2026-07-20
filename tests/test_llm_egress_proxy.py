from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Sequence

import pytest

from app.llm_egress_proxy import (
    DEFAULT_ALLOWED_HOSTS,
    LISTEN_HOST_ENV,
    LISTEN_PORT_ENV,
    ConnectProxy,
    ProxyConfig,
    ProxyRequestError,
    parse_connect_request,
    parse_extra_hosts,
    resolve_public_addresses,
)


class FakeWriter:
    def __init__(self, peer_address: str = "198.51.100.7") -> None:
        self.data = bytearray()
        self.closed = False
        self.peer_address = peer_address

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        return

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return

    def get_extra_info(self, name: str, default: object = None) -> object:
        if name == "peername":
            return (self.peer_address, 32100)
        return default


def _request(host: str, *, port: int = 443, headers: bytes = b"") -> bytes:
    return (
        b"CONNECT "
        + host.encode("ascii")
        + b":"
        + str(port).encode()
        + (b" HTTP/1.1\r\n" + headers + b"\r\n")
    )


def _reader(payload: bytes = b"") -> asyncio.StreamReader:
    reader = asyncio.StreamReader(limit=16 * 1024 + 1)
    if payload:
        reader.feed_data(payload)
    reader.feed_eof()
    return reader


def _address_record(address: str) -> tuple[int, int, int, str, tuple[object, ...]]:
    if ":" in address:
        return (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (address, 443, 0, 0),
        )
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (address, 443),
    )


@pytest.mark.parametrize("host", sorted(DEFAULT_ALLOWED_HOSTS))
def test_connect_allows_each_exact_default_host(host: str) -> None:
    target = parse_connect_request(_request(host), DEFAULT_ALLOWED_HOSTS)

    assert target.host == host
    assert target.port == 443


@pytest.mark.parametrize(
    ("request_bytes", "status_code", "event"),
    [
        (b"GET https://api.deepseek.com/ HTTP/1.1\r\n\r\n", 405, "method_denied"),
        (_request("api.deepseek.com", port=80), 403, "port_denied"),
        (_request("api.deepseek.com.evil.example"), 403, "host_denied"),
        (_request("API.DEEPSEEK.COM"), 400, "invalid_authority"),
        (_request("127.0.0.1"), 400, "invalid_authority"),
        (_request("user@api.deepseek.com"), 400, "invalid_authority"),
    ],
)
def test_connect_rejects_non_connect_non_443_and_non_exact_hosts(
    request_bytes: bytes, status_code: int, event: str
) -> None:
    with pytest.raises(ProxyRequestError) as caught:
        parse_connect_request(request_bytes, DEFAULT_ALLOWED_HOSTS)

    assert caught.value.status_code == status_code
    assert caught.value.event == event


def test_extra_maas_hosts_are_exact_and_added_to_allowlist() -> None:
    extras = parse_extra_hosts("tenant.maas.aliyuncs.com,team.production.maas.aliyuncs.com")

    assert extras == {
        "tenant.maas.aliyuncs.com",
        "team.production.maas.aliyuncs.com",
    }
    target = parse_connect_request(
        _request("tenant.maas.aliyuncs.com"), DEFAULT_ALLOWED_HOSTS | extras
    )
    assert target.host == "tenant.maas.aliyuncs.com"


@pytest.mark.parametrize(
    "raw_value",
    [
        "*.maas.aliyuncs.com",
        "maas.aliyuncs.com",
        "evilmaas.aliyuncs.com",
        "Tenant.maas.aliyuncs.com",
        " tenant.maas.aliyuncs.com",
        "tenant.maas.aliyuncs.com ",
        "https://tenant.maas.aliyuncs.com",
        "127.0.0.1",
        "tenant.maas.aliyuncs.com,",
    ],
)
def test_extra_hosts_reject_wildcards_non_subdomains_and_noncanonical_values(
    raw_value: str,
) -> None:
    with pytest.raises(ValueError):
        parse_extra_hosts(raw_value)


def test_production_bind_environment_uses_compose_contract() -> None:
    config = ProxyConfig.from_environment(
        {
            LISTEN_HOST_ENV: "0.0.0.0",
            LISTEN_PORT_ENV: "8080",
        }
    )

    assert LISTEN_HOST_ENV == "KB_LLM_EGRESS_PROXY_BIND_HOST"
    assert LISTEN_PORT_ENV == "KB_LLM_EGRESS_PROXY_BIND_PORT"
    assert config.listen_host == "0.0.0.0"
    assert config.listen_port == 8080


@pytest.mark.asyncio
async def test_dns_accepts_only_global_addresses() -> None:
    async def resolver(
        host: str, port: int
    ) -> Sequence[tuple[int, int, int, str, tuple[object, ...]]]:
        assert (host, port) == ("api.deepseek.com", 443)
        return [_address_record("8.8.8.8"), _address_record("2606:4700:4700::1111")]

    result = await resolve_public_addresses(
        "api.deepseek.com", 443, timeout_seconds=0.5, resolver=resolver
    )

    assert result == ("8.8.8.8", "2606:4700:4700::1111")


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "192.0.2.1",
        "224.0.0.1",
        "240.0.0.1",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "fc00::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
        "2001:db8::1",
    ],
)
@pytest.mark.asyncio
async def test_dns_rejects_every_non_global_address(address: str) -> None:
    async def resolver(
        host: str, port: int
    ) -> Sequence[tuple[int, int, int, str, tuple[object, ...]]]:
        return [_address_record(address)]

    with pytest.raises(ProxyRequestError) as caught:
        await resolve_public_addresses(
            "api.deepseek.com", 443, timeout_seconds=0.5, resolver=resolver
        )

    assert caught.value.status_code == 403
    assert caught.value.event == "dns_non_public_address"


@pytest.mark.asyncio
async def test_dns_fails_closed_when_public_and_non_global_results_are_mixed() -> None:
    async def resolver(
        host: str, port: int
    ) -> Sequence[tuple[int, int, int, str, tuple[object, ...]]]:
        return [_address_record("8.8.8.8"), _address_record("10.1.2.3")]

    with pytest.raises(ProxyRequestError, match="dns_non_public_address"):
        await resolve_public_addresses(
            "api.deepseek.com", 443, timeout_seconds=0.5, resolver=resolver
        )


def test_oversized_request_header_is_rejected() -> None:
    oversized = _request("api.deepseek.com", headers=b"X-Fill: " + b"a" * 17_000 + b"\r\n")

    with pytest.raises(ProxyRequestError) as caught:
        parse_connect_request(oversized, DEFAULT_ALLOWED_HOSTS)

    assert caught.value.status_code == 431
    assert caught.value.event == "header_too_large"


@pytest.mark.asyncio
async def test_private_dns_is_denied_without_logging_proxy_credentials(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "sk-do-not-log-this-value"

    async def resolver(
        host: str, port: int
    ) -> Sequence[tuple[int, int, int, str, tuple[object, ...]]]:
        return [_address_record("10.0.0.8")]

    async def connector(address: str, port: int) -> tuple[object, object]:
        raise AssertionError("connector must not run for a private DNS result")

    proxy = ConnectProxy(ProxyConfig(), resolver=resolver, connector=connector)  # type: ignore[arg-type]
    writer = FakeWriter()
    caplog.set_level(logging.INFO, logger="app.llm_egress_proxy")

    await proxy.handle_client(
        _reader(
            _request(
                "api.deepseek.com",
                headers=f"Proxy-Authorization: Bearer {secret}\r\n".encode(),
            )
        ),
        writer,
    )

    assert bytes(writer.data).startswith(b"HTTP/1.1 403 Forbidden")
    assert writer.closed is True
    assert secret not in caplog.text
    assert "Proxy-Authorization" not in caplog.text


@pytest.mark.asyncio
async def test_empty_loopback_health_probe_does_not_emit_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    proxy = ConnectProxy(ProxyConfig())
    writer = FakeWriter(peer_address="127.0.0.1")
    caplog.set_level(logging.DEBUG, logger="app.llm_egress_proxy")

    await proxy.handle_client(_reader(), writer)

    assert writer.closed is True
    assert "llm_egress_health_probe" in caplog.text
    assert not [record for record in caplog.records if record.levelno >= logging.WARNING]


@pytest.mark.asyncio
async def test_empty_non_loopback_connection_remains_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    proxy = ConnectProxy(ProxyConfig())
    writer = FakeWriter(peer_address="198.51.100.7")
    caplog.set_level(logging.DEBUG, logger="app.llm_egress_proxy")

    await proxy.handle_client(_reader(), writer)

    assert "event=empty_header" in caplog.text
    assert [record for record in caplog.records if record.levelno == logging.WARNING]


@pytest.mark.asyncio
async def test_connection_limit_returns_503_and_closes_client() -> None:
    proxy = ConnectProxy(ProxyConfig(max_connections=1))
    proxy._active_connections = 1
    writer = FakeWriter()

    await proxy.handle_client(_reader(), writer)

    assert bytes(writer.data).startswith(b"HTTP/1.1 503 Service Unavailable")
    assert writer.closed is True
    assert proxy._active_connections == 1


@pytest.mark.asyncio
async def test_relay_passes_tls_records_without_decrypting_or_rewriting() -> None:
    tls_records = b"\x16\x03\x01\x00\x05hello\x17\x03\x03\x00\x04data"
    proxy = ConnectProxy(ProxyConfig())
    writer = FakeWriter()

    await proxy._relay(_reader(tls_records), writer)

    assert bytes(writer.data) == tls_records


@pytest.mark.asyncio
async def test_tunnel_idle_timeout_tracks_activity_in_both_directions() -> None:
    proxy = ConnectProxy(ProxyConfig(idle_timeout_seconds=0.1))
    client_reader = asyncio.StreamReader()
    upstream_reader = asyncio.StreamReader()
    client_writer = FakeWriter()
    upstream_writer = FakeWriter()

    async def feed_upstream() -> None:
        for chunk in (b"one", b"two", b"three", b"four", b"five"):
            await asyncio.sleep(0.04)
            upstream_reader.feed_data(chunk)
        upstream_reader.feed_eof()

    await asyncio.gather(
        proxy._tunnel(client_reader, client_writer, upstream_reader, upstream_writer),
        feed_upstream(),
    )

    assert bytes(client_writer.data) == b"onetwothreefourfive"


@pytest.mark.asyncio
async def test_tunnel_closes_after_bounded_total_inactivity() -> None:
    proxy = ConnectProxy(ProxyConfig(idle_timeout_seconds=0.01))

    with pytest.raises(TimeoutError):
        await proxy._tunnel(
            asyncio.StreamReader(),
            FakeWriter(),
            asyncio.StreamReader(),
            FakeWriter(),
        )


@pytest.mark.asyncio
async def test_cancelling_tunnel_cleans_up_all_child_tasks() -> None:
    class CancellationProbeProxy(ConnectProxy):
        def __init__(self) -> None:
            super().__init__(ProxyConfig())
            self.started = 0
            self.finished = 0
            self.all_started = asyncio.Event()
            self.block_forever = asyncio.Event()

        async def _block(self) -> None:
            self.started += 1
            if self.started == 3:
                self.all_started.set()
            try:
                await self.block_forever.wait()
            finally:
                self.finished += 1

        async def _relay(self, *args: object, **kwargs: object) -> None:
            await self._block()

        async def _wait_until_idle(self, *args: object, **kwargs: object) -> None:
            await self._block()

    proxy = CancellationProbeProxy()
    tunnel = asyncio.create_task(
        proxy._tunnel(
            asyncio.StreamReader(),
            FakeWriter(),
            asyncio.StreamReader(),
            FakeWriter(),
        )
    )
    await asyncio.wait_for(proxy.all_started.wait(), timeout=0.5)

    tunnel.cancel()
    with pytest.raises(asyncio.CancelledError):
        await tunnel

    assert proxy.started == 3
    assert proxy.finished == 3


@pytest.mark.asyncio
async def test_tunnel_failure_after_200_does_not_append_a_second_http_response() -> None:
    async def resolver(
        host: str, port: int
    ) -> Sequence[tuple[int, int, int, str, tuple[object, ...]]]:
        return [_address_record("8.8.8.8")]

    upstream_writer = FakeWriter()

    async def connector(address: str, port: int) -> tuple[object, object]:
        assert (address, port) == ("8.8.8.8", 443)
        return _reader(), upstream_writer

    class FailingTunnelProxy(ConnectProxy):
        async def _tunnel(self, *args: object) -> None:
            raise TimeoutError

    proxy = FailingTunnelProxy(
        ProxyConfig(),
        resolver=resolver,
        connector=connector,  # type: ignore[arg-type]
    )
    writer = FakeWriter()

    await proxy.handle_client(
        _reader(_request("api.deepseek.com")),
        writer,
    )

    assert bytes(writer.data) == b"HTTP/1.1 200 Connection Established\r\n\r\n"
    assert writer.closed is True
    assert upstream_writer.closed is True
