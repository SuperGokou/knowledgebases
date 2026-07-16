import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

from app.api.errors import ApiError
from app.api.health import readiness, readiness_probe
from app.api.middleware import RequestBodyLimitMiddleware, normalize_request_id
from app.db.schema_version import DatabaseSchemaDriftError
from app.main import app


def test_liveness_endpoint_does_not_require_dependencies() -> None:
    with TestClient(app) as client:
        response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_readiness_rejects_database_schema_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readiness_probe.reset()

    class FakeSession:
        async def execute(self, _statement: Any) -> None:
            return None

    class FakeRedis:
        async def ping(self) -> bool:
            return True

    async def reject_drift(_session: Any) -> None:
        raise DatabaseSchemaDriftError("stale schema")

    monkeypatch.setattr("app.api.health.assert_database_schema_current", reject_drift)

    try:
        with pytest.raises(ApiError) as captured:
            await readiness(FakeSession(), FakeRedis())  # type: ignore[arg-type]
    finally:
        readiness_probe.reset()

    assert captured.value.status_code == 503
    assert captured.value.code == "dependency_unavailable"


@pytest.mark.asyncio
async def test_readiness_rejects_supervised_chat_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnexpectedDependency:
        async def execute(self, _statement: Any) -> None:
            raise AssertionError("dependency probe must not run during chat cleanup")

        async def ping(self) -> bool:
            raise AssertionError("dependency probe must not run during chat cleanup")

    monkeypatch.setattr("app.api.health.chat_cleanup_backlog_size", lambda: 1)
    monkeypatch.setattr("app.api.health.llm_cleanup_backlog_size", lambda: 0)

    with pytest.raises(ApiError) as captured:
        await readiness(UnexpectedDependency(), UnexpectedDependency())  # type: ignore[arg-type]

    assert captured.value.status_code == 503
    assert captured.value.code == "cleanup_in_progress"


@pytest.mark.asyncio
async def test_readiness_rejects_sticky_chat_safety_poison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnexpectedDependency:
        async def execute(self, _statement: Any) -> None:
            raise AssertionError("dependency probe must not run while chat is poisoned")

        async def ping(self) -> bool:
            raise AssertionError("dependency probe must not run while chat is poisoned")

    monkeypatch.setattr("app.api.health.chat_safety_poisoned", lambda: True)

    with pytest.raises(ApiError) as captured:
        await readiness(UnexpectedDependency(), UnexpectedDependency())  # type: ignore[arg-type]

    assert captured.value.status_code == 503
    assert captured.value.code == "chat_safety_poisoned"


def test_openapi_exposes_core_admin_and_file_flows() -> None:
    schema = app.openapi()
    paths = set(schema["paths"])

    assert {
        "/api/v1/auth/token",
        "/api/v1/auth/refresh",
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/v1/users",
        "/api/v1/roles",
        "/api/v1/roles/{role_id}",
        "/api/v1/roles/{role_id}/policy",
        "/api/v1/limits",
        "/api/v1/files",
        "/api/v1/files/uploads",
        "/api/v1/files/uploads/{upload_session_id}/parts",
        "/api/v1/files/uploads/{upload_session_id}/complete",
        "/api/v1/files/{file_id}/download",
        "/api/v1/knowledge-bases",
        "/api/v1/knowledge-bases/{knowledge_base_id}",
        "/api/v1/knowledge-bases/{knowledge_base_id}/role-grants",
        "/api/v1/knowledge-bases/{knowledge_base_id}/entries",
        "/api/v1/knowledge-bases/{knowledge_base_id}/entries/{entry_id}",
        "/api/v1/knowledge-bases/{knowledge_base_id}/search",
        "/api/v1/chat/query",
        "/api/v1/api-keys",
        "/api/v1/api-keys/{api_key_id}",
        "/api/v1/llm/providers",
        "/api/v1/llm/providers/{provider}",
        "/api/v1/llm/usage",
        "/api/v1/llm/budget-policies",
        "/api/v1/llm/budget-policies/{policy_id}",
        "/api/v1/public/chat/query",
        "/api/v1/public/knowledge-bases/{knowledge_base_id}/search",
    } <= paths

    security_schemes = schema["components"]["securitySchemes"]
    assert security_schemes["APIKeyHeader"] == {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
    }


def test_openapi_requires_bounded_log_safe_chat_idempotency_keys() -> None:
    schema = app.openapi()

    for path in ("/api/v1/chat/query", "/api/v1/public/chat/query"):
        parameters = schema["paths"][path]["post"]["parameters"]
        idempotency = next(
            item
            for item in parameters
            if item["in"] == "header" and item["name"] == "Idempotency-Key"
        )

        assert idempotency["required"] is True
        assert idempotency["schema"]["minLength"] == 1
        assert idempotency["schema"]["maxLength"] == 160
        assert idempotency["schema"]["pattern"] == "^[A-Za-z0-9][A-Za-z0-9._:-]*$"


def test_openapi_requires_knowledge_grant_compare_and_swap_version() -> None:
    components = app.openapi()["components"]["schemas"]
    payload = components["KnowledgeBaseRoleGrantSet"]
    knowledge_base = components["KnowledgeBaseRead"]

    assert set(payload["required"]) == {"expected_version", "grants"}
    assert payload["properties"]["expected_version"]["minimum"] == 1
    assert knowledge_base["required"] is not None
    assert "role_grant_version" in knowledge_base["required"]
    assert knowledge_base["properties"]["role_grant_version"]["minimum"] == 1


def test_openapi_requires_role_policy_compare_and_swap_version() -> None:
    components = app.openapi()["components"]["schemas"]

    for schema_name in ("RoleUpdate", "PermissionSet", "LimitSet", "RolePolicySet"):
        payload = components[schema_name]
        assert "expected_version" in payload["required"]
        assert payload["properties"]["expected_version"]["minimum"] == 1

    role = components["RoleRead"]
    assert "policy_version" in role["required"]
    assert role["properties"]["policy_version"]["minimum"] == 1


def test_large_control_plane_request_is_rejected_before_parsing() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/refresh",
            content=b"x" * (1024 * 1024 + 1),
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_body_too_large"


def test_request_id_accepts_only_a_bounded_log_safe_identifier() -> None:
    assert normalize_request_id("edge.req-123:abc_def") == "edge.req-123:abc_def"


@pytest.mark.parametrize(
    "untrusted",
    [
        "trusted\nforged-log-entry",
        "trusted\r\nX-Forged: yes",
        "含有中文",
        "a" * 65,
        "contains spaces",
    ],
)
def test_request_id_replaces_untrusted_values_before_logging_or_response(
    untrusted: str,
) -> None:
    normalized = normalize_request_id(untrusted)

    assert normalized != untrusted
    assert len(normalized) == 36
    assert normalized.count("-") == 4
    assert all(
        character.isascii() and (character.isalnum() or character == "-")
        for character in normalized
    )


@pytest.mark.asyncio
async def test_chunked_request_is_bounded_before_reaching_the_application() -> None:
    called = False
    sent: list[dict[str, object]] = []

    async def downstream(scope: object, receive: object, send: object) -> None:
        del scope, receive, send
        nonlocal called
        called = True

    messages = iter(
        [
            {"type": "http.request", "body": b"1234", "more_body": True},
            {"type": "http.request", "body": b"5678", "more_body": True},
        ]
    )

    async def receive() -> dict[str, object]:
        try:
            return next(messages)
        except StopIteration as error:
            raise AssertionError("middleware read beyond the first over-limit chunk") from error

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    middleware = RequestBodyLimitMiddleware(downstream, max_bytes=5)
    await middleware(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/upload",
            "raw_path": b"/upload",
            "query_string": b"",
            "headers": [(b"transfer-encoding", b"chunked")],
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
            "state": {"request_id": "request-1"},
        },
        receive,
        send,
    )

    assert not called
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413


@pytest.mark.asyncio
async def test_sensitive_route_uses_its_stricter_body_limit() -> None:
    called = False
    sent: list[dict[str, object]] = []

    async def downstream(scope: object, receive: object, send: object) -> None:
        del scope, receive, send
        nonlocal called
        called = True

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"123456", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    middleware = RequestBodyLimitMiddleware(
        downstream,
        max_bytes=100,
        path_limits={"/api/v1/auth/token": 5},
    )
    await middleware(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/api/v1/auth/token",
            "raw_path": b"/api/v1/auth/token",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
            "state": {"request_id": "request-2"},
        },
        receive,
        send,
    )

    assert not called
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413


@pytest.mark.asyncio
async def test_request_body_chunks_are_coalesced_for_bounded_replay() -> None:
    replayed: list[dict[str, object]] = []

    async def downstream(scope: object, receive: object, send: object) -> None:
        del scope, send
        replay = cast(Callable[[], Awaitable[dict[str, object]]], receive)
        replayed.append(await replay())

    messages = iter(
        [
            {"type": "http.request", "body": b"12", "more_body": True},
            {"type": "http.request", "body": b"34", "more_body": True},
            {"type": "http.request", "body": b"56", "more_body": False},
        ]
    )

    async def receive() -> dict[str, object]:
        return next(messages)

    middleware = RequestBodyLimitMiddleware(downstream, max_bytes=10)
    await middleware(_body_scope(), receive, _discard_send)

    assert replayed == [
        {
            "type": "http.request",
            "body": b"123456",
            "more_body": False,
        }
    ]


@pytest.mark.asyncio
async def test_request_body_message_flood_is_rejected_before_downstream() -> None:
    called = False
    sent: list[dict[str, object]] = []

    async def downstream(scope: object, receive: object, send: object) -> None:
        del scope, receive, send
        nonlocal called
        called = True

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"x", "more_body": True}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    middleware = RequestBodyLimitMiddleware(
        downstream,
        max_bytes=100,
        max_messages=3,
    )
    await middleware(_body_scope(), receive, send)

    assert not called
    assert sent[0]["status"] == 413
    assert b"request_body_too_fragmented" in cast(bytes, sent[1]["body"])


@pytest.mark.asyncio
async def test_request_body_receive_deadline_is_absolute() -> None:
    called = False
    sent: list[dict[str, object]] = []

    async def downstream(scope: object, receive: object, send: object) -> None:
        del scope, receive, send
        nonlocal called
        called = True

    async def receive() -> dict[str, object]:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    middleware = RequestBodyLimitMiddleware(
        downstream,
        max_bytes=100,
        receive_timeout_seconds=0.01,
    )
    await middleware(_body_scope(), receive, send)

    assert not called
    assert sent[0]["status"] == 408
    assert b"request_body_timeout" in cast(bytes, sent[1]["body"])


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"1"), (b"Content-Length", b"1")],
        [(b"content-length", b"-1")],
        [(b"content-length", b"1, 1")],
        [(b"content-length", b"9" * 10_000)],
        [(b"content-length", b"1"), (b"transfer-encoding", b"chunked")],
    ],
)
@pytest.mark.asyncio
async def test_ambiguous_content_length_is_rejected(
    headers: list[tuple[bytes, bytes]],
) -> None:
    called = False
    sent: list[dict[str, object]] = []

    async def downstream(scope: object, receive: object, send: object) -> None:
        del scope, receive, send
        nonlocal called
        called = True

    async def receive() -> dict[str, object]:
        raise AssertionError("invalid framing must be rejected before body receive")

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    middleware = RequestBodyLimitMiddleware(downstream, max_bytes=100)
    await middleware(_body_scope(headers=headers), receive, send)

    assert not called
    assert sent[0]["status"] == 400
    assert b"invalid_content_length" in cast(bytes, sent[1]["body"])


@pytest.mark.asyncio
async def test_content_length_mismatch_is_rejected() -> None:
    called = False
    sent: list[dict[str, object]] = []

    async def downstream(scope: object, receive: object, send: object) -> None:
        del scope, receive, send
        nonlocal called
        called = True

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"x", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    middleware = RequestBodyLimitMiddleware(downstream, max_bytes=100)
    await middleware(
        _body_scope(headers=[(b"content-length", b"2")]),
        receive,
        send,
    )

    assert not called
    assert sent[0]["status"] == 400
    assert b"content_length_mismatch" in cast(bytes, sent[1]["body"])


@pytest.mark.asyncio
async def test_partial_body_preserves_disconnect_semantics() -> None:
    replayed: list[dict[str, object]] = []

    async def downstream(scope: object, receive: object, send: object) -> None:
        del scope, send
        replay = cast(Callable[[], Awaitable[dict[str, object]]], receive)
        replayed.append(await replay())
        replayed.append(await replay())

    messages = iter(
        [
            {"type": "http.request", "body": b"partial", "more_body": True},
            {"type": "http.disconnect"},
        ]
    )

    async def receive() -> dict[str, object]:
        return next(messages)

    middleware = RequestBodyLimitMiddleware(downstream, max_bytes=100)
    await middleware(_body_scope(), receive, _discard_send)

    assert replayed == [
        {
            "type": "http.request",
            "body": b"partial",
            "more_body": True,
        },
        {"type": "http.disconnect"},
    ]


def _body_scope(
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> dict[str, object]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/test",
        "raw_path": b"/test",
        "query_string": b"",
        "headers": headers or [],
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
        "state": {"request_id": "request-body-test"},
    }


async def _discard_send(_message: dict[str, object]) -> None:
    return None
