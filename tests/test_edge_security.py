from __future__ import annotations

import asyncio
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from app.api.health import readiness, readiness_probe

REPOSITORY = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def reset_readiness_probe() -> Iterator[None]:
    readiness_probe.reset()
    yield
    readiness_probe.reset()


class CountingSession:
    def __init__(self) -> None:
        self.executions = 0

    async def execute(self, _statement: Any) -> None:
        self.executions += 1


class CountingRedis:
    def __init__(self) -> None:
        self.pings = 0

    async def ping(self) -> bool:
        self.pings += 1
        return True


class BlockingSession(CountingSession):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def execute(self, statement: Any) -> None:
        await super().execute(statement)
        self.started.set()
        await self.release.wait()


@pytest.mark.asyncio
async def test_repeated_readiness_requests_reuse_a_bounded_dependency_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = CountingSession()
    redis = CountingRedis()
    schema_checks = 0

    async def count_schema_check(_session: Any) -> None:
        nonlocal schema_checks
        schema_checks += 1

    monkeypatch.setattr("app.api.health.assert_database_schema_current", count_schema_check)

    assert await readiness(session, redis) == {"status": "ready"}  # type: ignore[arg-type]
    assert await readiness(session, redis) == {"status": "ready"}  # type: ignore[arg-type]

    assert session.executions == 1
    assert redis.pings == 1
    assert schema_checks == 1


@pytest.mark.asyncio
async def test_concurrent_readiness_requests_are_coalesced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = BlockingSession()
    redis = CountingRedis()
    monkeypatch.setattr(
        "app.api.health.assert_database_schema_current",
        lambda _session: asyncio.sleep(0),
    )

    first = asyncio.create_task(readiness(session, redis))  # type: ignore[arg-type]
    await session.started.wait()
    second = asyncio.create_task(readiness(session, redis))  # type: ignore[arg-type]
    await asyncio.sleep(0)
    session.release.set()

    first_result, second_result = await asyncio.gather(first, second)
    assert first_result == {"status": "ready"}
    assert second_result == {"status": "ready"}
    assert session.executions == 1
    assert redis.pings == 1


@pytest.mark.parametrize(
    "relative_path",
    ["deploy/tencent/Caddyfile", "deploy/tencent/Caddyfile.offline"],
)
def test_shipped_caddy_edges_overwrite_the_provider_client_ip_header(
    relative_path: str,
) -> None:
    caddyfile = (REPOSITORY / relative_path).read_text(encoding="utf-8")

    web_proxy = caddyfile.split("reverse_proxy web:3000", 1)[1]
    assert "header_up X-Vercel-Forwarded-For {remote_host}" in web_proxy


@pytest.mark.parametrize(
    ("relative_path", "expected_https_sites"),
    [
        ("deploy/tencent/Caddyfile", 1),
        ("deploy/tencent/Caddyfile.offline", 2),
    ],
)
def test_shipped_caddy_https_sites_enforce_hsts(
    relative_path: str,
    expected_https_sites: int,
) -> None:
    caddyfile = (REPOSITORY / relative_path).read_text(encoding="utf-8")
    site_offsets = [match.start() for match in re.finditer(r"(?m)^https://[^\r\n]+ \{$", caddyfile)]
    https_sites = [
        caddyfile[start:end]
        for start, end in zip(
            site_offsets,
            [*site_offsets[1:], len(caddyfile)],
            strict=True,
        )
    ]

    assert len(https_sites) == expected_https_sites
    for site in https_sites:
        assert 'header >Strict-Transport-Security "max-age=31536000; includeSubDomains"' in site


def test_offline_object_proxy_does_not_log_presigned_query_credentials() -> None:
    caddyfile = (REPOSITORY / "deploy/tencent/Caddyfile.offline").read_text(encoding="utf-8")

    object_vhost = caddyfile.split("https://{$KB_PUBLIC_HOST}:9443", 1)[1]
    assert "log {" not in object_vhost
