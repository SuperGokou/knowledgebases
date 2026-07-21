from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol

logger = logging.getLogger(__name__)

DEFAULT_ALLOWED_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "api.deepseek.com",
        "dashscope.aliyuncs.com",
        "dashscope-us.aliyuncs.com",
        "dashscope-intl.aliyuncs.com",
        "api.minimax.io",
    }
)
EXTRA_HOSTS_ENV: Final = "LLM_EGRESS_PROXY_EXTRA_HOSTS"
LISTEN_HOST_ENV: Final = "KB_LLM_EGRESS_PROXY_BIND_HOST"
LISTEN_PORT_ENV: Final = "KB_LLM_EGRESS_PROXY_BIND_PORT"

_MAAS_SUFFIX: Final = ".maas.aliyuncs.com"
_HOST_PATTERN: Final = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
_HEADER_NAME_PATTERN: Final = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}")
_MAX_REQUEST_LINE_BYTES: Final = 2_048
_MAX_HEADER_COUNT: Final = 64
_MAX_HEADER_LINE_BYTES: Final = 4_096
_DEFAULT_MAX_HEADER_BYTES: Final = 16 * 1_024
_RELAY_CHUNK_BYTES: Final = 64 * 1_024
_MAX_RESOLVED_ADDRESSES: Final = 16

type AddressInfo = tuple[int, int, int, str, tuple[object, ...]]
type Resolver = Callable[[str, int], Awaitable[Sequence[AddressInfo]]]
type Connector = Callable[[str, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]


class Writer(Protocol):
    def write(self, data: bytes) -> None: ...

    async def drain(self) -> None: ...

    def close(self) -> None: ...

    async def wait_closed(self) -> None: ...

    def get_extra_info(self, name: str, default: object = None) -> object: ...


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    allowed_hosts: frozenset[str] = DEFAULT_ALLOWED_HOSTS
    listen_host: str = "127.0.0.1"
    listen_port: int = 18_080
    max_connections: int = 128
    max_header_bytes: int = _DEFAULT_MAX_HEADER_BYTES
    connect_timeout_seconds: float = 10.0
    idle_timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        if not self.allowed_hosts:
            raise ValueError("at least one upstream host must be allowed")
        if any(_validate_hostname(host) != host for host in self.allowed_hosts):
            raise ValueError("allowed hosts must be canonical DNS names")
        if self.listen_host not in {"127.0.0.1", "0.0.0.0", "::1", "::"}:
            raise ValueError("listen host must be an explicit local bind address")
        if not 1 <= self.listen_port <= 65_535:
            raise ValueError("listen port must be between 1 and 65535")
        if self.max_connections <= 0:
            raise ValueError("max connections must be positive")
        if self.max_header_bytes < 1_024:
            raise ValueError("max header bytes must be at least 1024")
        if self.connect_timeout_seconds <= 0 or self.idle_timeout_seconds <= 0:
            raise ValueError("timeouts must be positive")

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> ProxyConfig:
        values = os.environ if environ is None else environ
        extra_hosts = parse_extra_hosts(values.get(EXTRA_HOSTS_ENV))
        listen_host = values.get(LISTEN_HOST_ENV, "127.0.0.1")
        listen_port = _parse_port(values.get(LISTEN_PORT_ENV, "18080"))
        return cls(
            allowed_hosts=DEFAULT_ALLOWED_HOSTS | extra_hosts,
            listen_host=listen_host,
            listen_port=listen_port,
        )


@dataclass(frozen=True, slots=True)
class ConnectTarget:
    host: str
    port: int


class ProxyRequestError(Exception):
    def __init__(self, status_code: int, reason: str, event: str) -> None:
        super().__init__(event)
        self.status_code = status_code
        self.reason = reason
        self.event = event


def parse_extra_hosts(raw_value: str | None) -> frozenset[str]:
    """Parse a JSON list of exact MaaS hosts from the shared application policy."""

    if raw_value is None or raw_value == "":
        return frozenset()
    try:
        raw_hosts = json.loads(raw_value)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("extra hosts must be a JSON string array") from error
    if not isinstance(raw_hosts, list) or len(raw_hosts) > 32:
        raise ValueError("extra hosts must be a JSON string array with at most 32 entries")
    hosts: set[str] = set()
    for value in raw_hosts:
        if not isinstance(value, str) or not value:
            raise ValueError("extra hosts must contain non-empty DNS names")
        if value != value.strip() or value != value.lower():
            raise ValueError("extra hosts must be lowercase without surrounding whitespace")
        host = _validate_hostname(value)
        prefix = host[: -len(_MAAS_SUFFIX)] if host.endswith(_MAAS_SUFFIX) else ""
        if not prefix or not host.endswith(_MAAS_SUFFIX):
            raise ValueError("extra hosts must be exact subdomains of maas.aliyuncs.com")
        hosts.add(host)
    return frozenset(hosts)


def parse_connect_request(
    request_head: bytes,
    allowed_hosts: frozenset[str],
    *,
    max_header_bytes: int = _DEFAULT_MAX_HEADER_BYTES,
) -> ConnectTarget:
    if len(request_head) > max_header_bytes:
        raise ProxyRequestError(431, "Request Header Fields Too Large", "header_too_large")
    if not request_head.endswith(b"\r\n\r\n"):
        raise ProxyRequestError(400, "Bad Request", "incomplete_header")
    lines = request_head[:-4].split(b"\r\n")
    if not lines or len(lines[0]) > _MAX_REQUEST_LINE_BYTES:
        raise ProxyRequestError(400, "Bad Request", "invalid_request_line")
    if len(lines) - 1 > _MAX_HEADER_COUNT:
        raise ProxyRequestError(431, "Request Header Fields Too Large", "too_many_headers")
    try:
        method, authority, version = lines[0].decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError) as error:
        raise ProxyRequestError(400, "Bad Request", "invalid_request_line") from error
    if method != "CONNECT":
        raise ProxyRequestError(405, "Method Not Allowed", "method_denied")
    if version not in {"HTTP/1.0", "HTTP/1.1"}:
        raise ProxyRequestError(400, "Bad Request", "invalid_http_version")
    host, port = _parse_authority(authority)
    if port != 443:
        raise ProxyRequestError(403, "Forbidden", "port_denied")
    if host not in allowed_hosts:
        raise ProxyRequestError(403, "Forbidden", "host_denied")
    for line in lines[1:]:
        _validate_header_line(line)
    return ConnectTarget(host=host, port=port)


async def resolve_public_addresses(
    host: str,
    port: int,
    *,
    timeout_seconds: float,
    resolver: Resolver | None = None,
) -> tuple[str, ...]:
    resolve = resolver or _default_resolver
    try:
        records = await asyncio.wait_for(resolve(host, port), timeout=timeout_seconds)
    except TimeoutError as error:
        raise ProxyRequestError(504, "Gateway Timeout", "dns_timeout") from error
    except (OSError, socket.gaierror) as error:
        raise ProxyRequestError(502, "Bad Gateway", "dns_failure") from error
    addresses = _validated_addresses(records)
    if not addresses:
        raise ProxyRequestError(502, "Bad Gateway", "dns_empty")
    return addresses


def _validated_addresses(records: Sequence[AddressInfo]) -> tuple[str, ...]:
    if len(records) > _MAX_RESOLVED_ADDRESSES:
        raise ProxyRequestError(502, "Bad Gateway", "dns_result_limit")
    addresses: list[str] = []
    for family, socket_type, protocol, _, sockaddr in records:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        if socket_type not in {0, socket.SOCK_STREAM}:
            continue
        if protocol not in {0, socket.IPPROTO_TCP}:
            continue
        if not sockaddr or not isinstance(sockaddr[0], str):
            raise ProxyRequestError(502, "Bad Gateway", "dns_invalid_result")
        address = _parse_public_ip(sockaddr[0])
        if address not in addresses:
            addresses.append(address)
    return tuple(addresses)


class ConnectProxy:
    def __init__(
        self,
        config: ProxyConfig,
        *,
        resolver: Resolver | None = None,
        connector: Connector | None = None,
    ) -> None:
        self.config = config
        self._resolver = resolver
        self._connector = connector or _default_connector
        self._active_connections = 0

    async def handle_client(self, reader: asyncio.StreamReader, writer: Writer) -> None:
        if not self._enter_connection():
            try:
                await _send_error(writer, 503, "Service Unavailable")
            finally:
                await _close_writer(writer)
            return
        upstream_writer: Writer | None = None
        response_committed = False
        peer = _peer_label(writer)
        try:
            request_head = await self._read_request_head(reader)
            target = parse_connect_request(
                request_head,
                self.config.allowed_hosts,
                max_header_bytes=self.config.max_header_bytes,
            )
            addresses = await resolve_public_addresses(
                target.host,
                target.port,
                timeout_seconds=self.config.connect_timeout_seconds,
                resolver=self._resolver,
            )
            upstream_reader, upstream_writer = await self._open_upstream(addresses, target.port)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            response_committed = True
            await asyncio.wait_for(writer.drain(), timeout=self.config.connect_timeout_seconds)
            logger.info("llm_egress_tunnel_open peer=%s target=%s", peer, target.host)
            await self._tunnel(reader, writer, upstream_reader, upstream_writer)
        except ProxyRequestError as error:
            if error.event == "empty_header" and _is_loopback_address(peer):
                logger.debug("llm_egress_health_probe peer=%s", peer)
            else:
                logger.warning("llm_egress_request_rejected peer=%s event=%s", peer, error.event)
            if not response_committed:
                await _send_error(writer, error.status_code, error.reason)
        except TimeoutError:
            logger.warning("llm_egress_timeout peer=%s", peer)
            if not response_committed:
                await _send_error(writer, 504, "Gateway Timeout")
        except (ConnectionError, OSError):
            logger.warning("llm_egress_upstream_failure peer=%s", peer)
            if not response_committed:
                await _send_error(writer, 502, "Bad Gateway")
        finally:
            try:
                if upstream_writer is not None:
                    await _close_writer(upstream_writer)
            finally:
                try:
                    await _close_writer(writer)
                finally:
                    self._active_connections -= 1

    async def start(self) -> asyncio.Server:
        return await asyncio.start_server(
            self.handle_client,
            self.config.listen_host,
            self.config.listen_port,
            limit=self.config.max_header_bytes + 1,
        )

    def _enter_connection(self) -> bool:
        if self._active_connections >= self.config.max_connections:
            return False
        self._active_connections += 1
        return True

    async def _read_request_head(self, reader: asyncio.StreamReader) -> bytes:
        try:
            request_head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"),
                timeout=self.config.connect_timeout_seconds,
            )
        except asyncio.LimitOverrunError as error:
            raise ProxyRequestError(
                431, "Request Header Fields Too Large", "header_too_large"
            ) from error
        except asyncio.IncompleteReadError as error:
            if len(error.partial) > self.config.max_header_bytes:
                raise ProxyRequestError(
                    431, "Request Header Fields Too Large", "header_too_large"
                ) from error
            event = "empty_header" if not error.partial else "incomplete_header"
            raise ProxyRequestError(400, "Bad Request", event) from error
        except TimeoutError as error:
            raise ProxyRequestError(408, "Request Timeout", "header_timeout") from error
        if len(request_head) > self.config.max_header_bytes:
            raise ProxyRequestError(431, "Request Header Fields Too Large", "header_too_large")
        return request_head

    async def _open_upstream(
        self, addresses: tuple[str, ...], port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        async def connect() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            last_error: OSError | None = None
            for address in addresses:
                try:
                    return await self._connector(address, port)
                except OSError as error:
                    last_error = error
            raise last_error or OSError("no upstream address available")

        return await asyncio.wait_for(connect(), timeout=self.config.connect_timeout_seconds)

    async def _tunnel(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: Writer,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: Writer,
    ) -> None:
        loop = asyncio.get_running_loop()
        last_activity = loop.time()
        activity = asyncio.Event()

        def record_activity() -> None:
            nonlocal last_activity
            last_activity = loop.time()
            activity.set()

        client_to_upstream = asyncio.create_task(
            self._relay(client_reader, upstream_writer, record_activity)
        )
        upstream_to_client = asyncio.create_task(
            self._relay(upstream_reader, client_writer, record_activity)
        )
        idle_guard = asyncio.create_task(self._wait_until_idle(activity, lambda: last_activity))
        tasks = {client_to_upstream, upstream_to_client, idle_guard}
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _relay(
        self,
        reader: asyncio.StreamReader,
        writer: Writer,
        record_activity: Callable[[], None] | None = None,
    ) -> None:
        while True:
            chunk = await reader.read(_RELAY_CHUNK_BYTES)
            if not chunk:
                return
            writer.write(chunk)
            await writer.drain()
            if record_activity is not None:
                record_activity()

    async def _wait_until_idle(
        self,
        activity: asyncio.Event,
        last_activity: Callable[[], float],
    ) -> None:
        loop = asyncio.get_running_loop()
        while True:
            activity.clear()
            remaining = self.config.idle_timeout_seconds - (loop.time() - last_activity())
            if remaining <= 0:
                raise TimeoutError
            try:
                await asyncio.wait_for(activity.wait(), timeout=remaining)
            except TimeoutError:
                if loop.time() - last_activity() >= self.config.idle_timeout_seconds:
                    raise


def _parse_authority(authority: str) -> tuple[str, int]:
    if authority.count(":") != 1 or any(character in authority for character in "/@?#[]"):
        raise ProxyRequestError(400, "Bad Request", "invalid_authority")
    raw_host, raw_port = authority.rsplit(":", maxsplit=1)
    try:
        host = _validate_hostname(raw_host)
        port = int(raw_port)
    except ValueError as error:
        raise ProxyRequestError(400, "Bad Request", "invalid_authority") from error
    if raw_port != str(port) or not 1 <= port <= 65_535:
        raise ProxyRequestError(400, "Bad Request", "invalid_authority")
    return host, port


def _validate_hostname(host: str) -> str:
    if host != host.lower() or _HOST_PATTERN.fullmatch(host) is None:
        raise ValueError("host must be a canonical lowercase DNS name")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError("IP literals are not allowed")


def _validate_header_line(line: bytes) -> None:
    if len(line) > _MAX_HEADER_LINE_BYTES or b":" not in line or line[:1] in b" \t":
        raise ProxyRequestError(400, "Bad Request", "invalid_header")
    name, value = line.split(b":", maxsplit=1)
    if _HEADER_NAME_PATTERN.fullmatch(name) is None:
        raise ProxyRequestError(400, "Bad Request", "invalid_header")
    if any(byte not in {9} and not 32 <= byte <= 126 for byte in value):
        raise ProxyRequestError(400, "Bad Request", "invalid_header")


def _parse_public_ip(raw_address: str) -> str:
    try:
        address = ipaddress.ip_address(raw_address)
    except ValueError as error:
        raise ProxyRequestError(502, "Bad Gateway", "dns_invalid_address") from error
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    # ``ipaddress`` considers multicast globally scoped on some Python versions;
    # a CONNECT destination must be a globally routable unicast address.
    is_site_local = isinstance(address, ipaddress.IPv6Address) and address.is_site_local
    if not address.is_global or address.is_multicast or is_site_local:
        raise ProxyRequestError(403, "Forbidden", "dns_non_public_address")
    return str(address)


async def _default_resolver(host: str, port: int) -> Sequence[AddressInfo]:
    loop = asyncio.get_running_loop()
    return await loop.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )


async def _default_connector(
    address: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    # Deliberately plain TCP: client TLS bytes pass through unchanged and are never decrypted.
    return await asyncio.open_connection(address, port, ssl=None)


async def _send_error(writer: Writer, status_code: int, reason: str) -> None:
    try:
        response = (
            f"HTTP/1.1 {status_code} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        ).encode("ascii")
        writer.write(response)
        await asyncio.wait_for(writer.drain(), timeout=2.0)
    except (ConnectionError, OSError, TimeoutError):
        return


async def _close_writer(writer: Writer) -> None:
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
    except (ConnectionError, OSError, TimeoutError):
        return


def _peer_label(writer: Writer) -> str:
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return "unknown"


def _is_loopback_address(raw_address: str) -> bool:
    try:
        address = ipaddress.ip_address(raw_address)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def _parse_port(value: str) -> int:
    if not value.isascii() or not value.isdigit() or value != str(int(value)):
        raise ValueError("listen port must be a canonical integer")
    port = int(value)
    if not 1 <= port <= 65_535:
        raise ValueError("listen port must be between 1 and 65535")
    return port


async def _serve() -> None:
    proxy = ConnectProxy(ProxyConfig.from_environment())
    server = await proxy.start()
    logger.info(
        "llm_egress_proxy_started bind=%s port=%d",
        proxy.config.listen_host,
        proxy.config.listen_port,
    )
    async with server:
        await server.serve_forever()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    asyncio.run(_serve())


if __name__ == "__main__":
    main()
