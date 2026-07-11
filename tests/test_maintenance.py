from __future__ import annotations

from typing import Any

import pytest

from app.core.config import Settings
from app.maintenance import run_maintenance_once


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

    async def forbidden_conversion(*_args: Any, **_kwargs: Any) -> int:
        calls.append("convert")
        raise AssertionError("isolated maintenance must not process external LLM jobs")

    monkeypatch.setattr("app.maintenance.cleanup_expired_uploads", cleanup)
    monkeypatch.setattr("app.maintenance.resolve_provider_client", forbidden_resolve)
    monkeypatch.setattr("app.maintenance.process_okf_conversion_batch", forbidden_conversion)

    result = await run_maintenance_once(
        session=object(),  # type: ignore[arg-type]
        storage=object(),  # type: ignore[arg-type]
        settings=Settings(environment="test", external_llm_enabled=False),
    )

    assert result == {"cleaned": 2, "converted": 0}
    assert calls == ["cleanup"]
