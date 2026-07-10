import pytest
from fastapi.testclient import TestClient

from app.api.middleware import RequestBodyLimitMiddleware
from app.main import app


def test_liveness_endpoint_does_not_require_dependencies() -> None:
    with TestClient(app) as client:
        response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


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
    } <= paths


def test_large_control_plane_request_is_rejected_before_parsing() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/refresh",
            content=b"x" * (1024 * 1024 + 1),
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_body_too_large"


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
