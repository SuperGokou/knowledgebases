from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_MAX_RESPONSE_BYTES = 64 * 1024
_BUSINESS_PATHS = (
    "/",
    "/login",
    "/admin/roles",
    "/api/v1/auth/token",
    "/api/v1/public/search",
    "/health/ready",
    "/openapi.json",
)


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _compose_contract(document: dict[str, Any]) -> tuple[str, str, Path]:
    services = document.get("services")
    if not isinstance(services, dict):
        raise ValueError("compose services are missing")
    web = services.get("web")
    proxy = services.get("proxy")
    maintenance = services.get("maintenance-page")
    if (
        not isinstance(web, dict)
        or not isinstance(proxy, dict)
        or not isinstance(maintenance, dict)
    ):
        raise ValueError("web, proxy or maintenance-page service is missing")
    environment = web.get("environment")
    if not isinstance(environment, dict):
        raise ValueError("web environment is missing")
    origin = environment.get("KB_PUBLIC_ORIGIN")
    if not isinstance(origin, str) or not origin.startswith("https://"):
        raise ValueError("strict HTTPS public origin is missing")
    proxy_environment = proxy.get("environment")
    if not isinstance(proxy_environment, dict):
        raise ValueError("proxy environment is missing")
    objects_port = proxy_environment.get("KB_OBJECTS_HTTPS_PORT")
    if not isinstance(objects_port, str) or not objects_port.isdigit():
        raise ValueError("strict HTTPS object port is missing")
    parsed_origin = urlsplit(origin)
    if parsed_origin.scheme != "https" or parsed_origin.hostname is None:
        raise ValueError("strict HTTPS public origin is invalid")
    objects_origin = f"https://{parsed_origin.hostname}:{objects_port}"

    volumes = maintenance.get("volumes")
    if not isinstance(volumes, list):
        raise ValueError("maintenance CA volume is missing")
    data_mount = next(
        (
            volume
            for volume in volumes
            if isinstance(volume, dict) and volume.get("target") == "/data"
        ),
        None,
    )
    if not isinstance(data_mount, dict) or not isinstance(data_mount.get("source"), str):
        raise ValueError("maintenance CA volume source is missing")
    ca_bundle = Path(data_mount["source"]) / "caddy/pki/authorities/local/root.crt"
    return origin.rstrip("/"), objects_origin, ca_bundle


def _request_status(
    origin: str,
    path: str,
    context: ssl.SSLContext,
) -> tuple[int, str, bytes]:
    request = urllib.request.Request(
        f"{origin}{path}",
        headers={"Accept": "application/json,text/html"},
    )
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            _RejectRedirects(),
        )
        response = opener.open(request, timeout=5)
    except urllib.error.HTTPError as exc:
        body = exc.read(_MAX_RESPONSE_BYTES + 1)
        return exc.code, exc.headers.get_content_type(), body
    with response:
        body = response.read(_MAX_RESPONSE_BYTES + 1)
        return response.status, response.headers.get_content_type(), body


def verify_maintenance_contract(document: dict[str, Any]) -> None:
    origin, objects_origin, ca_bundle = _compose_contract(document)
    if ca_bundle.is_symlink() or not ca_bundle.is_file():
        raise ValueError("maintenance CA bundle is not a regular non-symlink file")
    context = ssl.create_default_context(cafile=str(ca_bundle))

    ready_status, ready_type, ready_body = _request_status(origin, "/maintenance/ready", context)
    if ready_status != 200 or ready_type != "application/json":
        raise ValueError("maintenance readiness contract failed")
    ready = json.loads(ready_body)
    if ready != {"status": "ok", "mode": "maintenance", "traffic": "blocked"}:
        raise ValueError("maintenance readiness payload is invalid")

    for path in _BUSINESS_PATHS:
        status, content_type, body = _request_status(origin, path, context)
        if status != 503:
            raise ValueError(f"business path did not fail closed: {path}")
        if len(body) > _MAX_RESPONSE_BYTES:
            raise ValueError(f"maintenance response exceeded the bounded size: {path}")
        if path.startswith("/api/") or path in {"/health/ready", "/openapi.json"}:
            if content_type != "application/json":
                raise ValueError(f"API maintenance response is not JSON: {path}")
            payload = json.loads(body)
            error = payload.get("error") if isinstance(payload, dict) else None
            if not isinstance(error, dict) or error.get("code") != "maintenance_mode":
                raise ValueError(f"API maintenance payload is invalid: {path}")
        elif content_type != "text/html":
            raise ValueError(f"browser maintenance response is not HTML: {path}")

    object_status, object_type, object_body = _request_status(objects_origin, "/", context)
    if object_status != 503 or object_type != "application/json":
        raise ValueError("object-storage maintenance entry did not fail closed")
    if len(object_body) > _MAX_RESPONSE_BYTES:
        raise ValueError("object-storage maintenance response exceeded the bounded size")
    object_payload = json.loads(object_body)
    object_error = object_payload.get("error") if isinstance(object_payload, dict) else None
    if not isinstance(object_error, dict) or object_error.get("code") != "maintenance_mode":
        raise ValueError("object-storage maintenance payload is invalid")


def verify_business_ready_contract(document: dict[str, Any]) -> None:
    origin, objects_origin, ca_bundle = _compose_contract(document)
    if ca_bundle.is_symlink() or not ca_bundle.is_file():
        raise ValueError("business CA bundle is not a regular non-symlink file")
    context = ssl.create_default_context(cafile=str(ca_bundle))
    status, content_type, body = _request_status(origin, "/health/ready", context)
    if status != 200 or content_type != "application/json":
        raise ValueError("restored business readiness contract failed")
    if len(body) > _MAX_RESPONSE_BYTES:
        raise ValueError("restored business readiness response exceeded the bounded size")
    payload = json.loads(body)
    if payload != {"status": "ready"}:
        raise ValueError("restored business readiness payload is invalid")
    object_status, _object_type, object_body = _request_status(
        objects_origin, "/minio/health/ready", context
    )
    if object_status != 200 or len(object_body) > _MAX_RESPONSE_BYTES:
        raise ValueError("restored object-storage readiness contract failed")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Strictly verify the independent maintenance endpoint contract"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--compose-config-stdin",
        action="store_true",
        help="Read docker compose --format json output from standard input",
    )
    mode.add_argument(
        "--business-ready-compose-config-stdin",
        action="store_true",
        help="Verify strict TLS and the restored business readiness contract",
    )
    arguments = parser.parse_args()
    try:
        document = json.load(sys.stdin)
        if not isinstance(document, dict):
            raise ValueError("compose config must be a JSON object")
        if arguments.business_ready_compose_config_stdin:
            verify_business_ready_contract(document)
        else:
            verify_maintenance_contract(document)
    except (OSError, ValueError, json.JSONDecodeError, ssl.SSLError) as exc:
        print(f"maintenance-contract: {exc}", file=sys.stderr)
        return 1
    if arguments.business_ready_compose_config_stdin:
        print("business-contract: strict TLS readiness is 200")
    else:
        print("maintenance-contract: readiness is 200 and all business samples are 503")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
