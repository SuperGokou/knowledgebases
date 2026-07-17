from typing import Any

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


def test_openapi_exposes_core_admin_and_file_flows() -> None:
    schema = app.openapi()
    paths = set(schema["paths"])

    assert {
        "/api/v1/auth/token",
        "/api/v1/auth/refresh",
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/v1/users",
        "/api/v1/users/{user_id}/password",
        "/api/v1/roles",
        "/api/v1/roles/{role_id}",
        "/api/v1/roles/{role_id}/policy",
        "/api/v1/limits",
        "/api/v1/files",
        "/api/v1/files/uploads",
        "/api/v1/files/uploads/{upload_session_id}/parts",
        "/api/v1/files/uploads/{upload_session_id}/complete",
        "/api/v1/files/{file_id}",
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
