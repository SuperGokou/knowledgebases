#!/usr/bin/env python3
"""Deterministic OpenAI-compatible stub for capacity-path tests only.

It is intentionally incapable of representing model quality or token throughput.
The process requires an explicit acknowledgement and a dedicated bearer token so
it cannot be mistaken for a production model endpoint.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

ACKNOWLEDGEMENT = "I_UNDERSTAND_STUB_IS_NOT_MODEL_EVIDENCE"
EVIDENCE_CLASSIFICATION = "not_model_capacity"
MAX_REQUEST_BYTES = 2 * 1024 * 1024
DELAY_MARKER = re.compile(r"__capacity_stub_delay_ms_(\d{1,5})__")


class CapacityStubServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        token: str,
        maximum_concurrency: int,
        default_delay_ms: int,
        allow_markers: bool,
    ) -> None:
        super().__init__(server_address, CapacityStubHandler)
        self.token = token
        self.admission = threading.BoundedSemaphore(maximum_concurrency)
        self.default_delay_ms = default_delay_ms
        self.allow_markers = allow_markers


class CapacityStubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def capacity_server(self) -> CapacityStubServer:
        return cast(CapacityStubServer, self.server)

    def log_message(self, format_string: str, *arguments: object) -> None:
        del format_string, arguments

    def _send_json(
        self,
        status: HTTPStatus,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Capacity-Stub", "not-model-evidence")
        self.send_header("X-Capacity-Classification", EVIDENCE_CLASSIFICATION)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/healthz":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "status": "capacity_stub_ready",
                "classification": EVIDENCE_CLASSIFICATION,
                "model_evidence": False,
                "token_capacity_evidence": False,
            },
        )

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") not in {"/chat/completions", "/v1/chat/completions"}:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        expected = f"Bearer {self.capacity_server.token}"
        presented = self.headers.get("Authorization", "")
        if not hmac.compare_digest(presented, expected):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid_stub_token"})
            return
        raw_length = self.headers.get("Content-Length")
        try:
            content_length = int(raw_length or "")
        except ValueError:
            self._send_json(HTTPStatus.LENGTH_REQUIRED, {"error": "content_length_required"})
            return
        if not 0 < content_length <= MAX_REQUEST_BYTES:
            self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body_too_large"})
            return
        try:
            payload = json.loads(self.rfile.read(content_length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "invalid_request"})
            return

        if not self.capacity_server.admission.acquire(blocking=False):
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": {"type": "capacity_stub_overloaded"}},
                headers={"Retry-After": "1"},
            )
            return
        try:
            self._complete(payload)
        finally:
            self.capacity_server.admission.release()

    def _complete(self, payload: dict[str, Any]) -> None:
        messages = payload["messages"]
        text = "\n".join(
            str(message.get("content", "")) for message in messages if isinstance(message, dict)
        )
        if self.capacity_server.allow_markers and "__capacity_stub_429__" in text:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": {"type": "capacity_stub_injected_429"}},
                headers={"Retry-After": "1"},
            )
            return
        if self.capacity_server.allow_markers and "__capacity_stub_500__" in text:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": {"type": "capacity_stub_injected_500"}},
            )
            return
        if self.capacity_server.allow_markers and "__capacity_stub_invalid_json__" in text:
            body = b"not-json"
            self.send_response(HTTPStatus.OK.value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Capacity-Stub", "not-model-evidence")
            self.send_header("X-Capacity-Classification", EVIDENCE_CLASSIFICATION)
            self.end_headers()
            self.wfile.write(body)
            return

        delay_ms = self.capacity_server.default_delay_ms
        if self.capacity_server.allow_markers and (match := DELAY_MARKER.search(text)) is not None:
            delay_ms = min(int(match.group(1)), 30_000)
        if delay_ms:
            time.sleep(delay_ms / 1_000)

        is_review = any(
            isinstance(message, dict)
            and message.get("role") == "system"
            and "strict grounding auditor" in str(message.get("content", "")).lower()
            for message in messages
        )
        content = (
            '{"verdict":"pass","unsupported_claims":[]}'
            if is_review
            else '{"answer":"Capacity path verified against cited evidence [1].","table":null}'
        )
        model = payload.get("model") if isinstance(payload.get("model"), str) else "capacity-stub"
        self._send_json(
            HTTPStatus.OK,
            {
                "id": "capacity-stub-response",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "capacity_classification": EVIDENCE_CLASSIFICATION,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
                # Synthetic accounting proves the application's metering path only.
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 20,
                    "total_tokens": 120,
                },
            },
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the non-production capacity LLM stub.")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--maximum-concurrency", type=int, default=16)
    parser.add_argument("--default-delay-ms", type=int, default=25)
    parser.add_argument("--allow-non-loopback", action="store_true")
    parser.add_argument("--allow-fault-markers", action="store_true")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if os.environ.get("KB_CAPACITY_STUB_ACK") != ACKNOWLEDGEMENT:
        raise SystemExit("set KB_CAPACITY_STUB_ACK=I_UNDERSTAND_STUB_IS_NOT_MODEL_EVIDENCE")
    token = os.environ.get("KB_CAPACITY_STUB_TOKEN", "")
    if len(token) < 32:
        raise SystemExit("KB_CAPACITY_STUB_TOKEN must contain at least 32 characters")
    if arguments.listen not in {"127.0.0.1", "::1", "localhost"} and not (
        arguments.allow_non_loopback
    ):
        raise SystemExit("non-loopback binding requires --allow-non-loopback")
    if not 1 <= arguments.port <= 65_535:
        raise SystemExit("port must be between 1 and 65535")
    if not 1 <= arguments.maximum_concurrency <= 10_000:
        raise SystemExit("maximum concurrency must be between 1 and 10000")
    if not 0 <= arguments.default_delay_ms <= 30_000:
        raise SystemExit("default delay must be between 0 and 30000 ms")
    server = CapacityStubServer(
        (arguments.listen, arguments.port),
        token=token,
        maximum_concurrency=arguments.maximum_concurrency,
        default_delay_ms=arguments.default_delay_ms,
        allow_markers=arguments.allow_fault_markers,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
