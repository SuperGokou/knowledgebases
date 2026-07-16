from __future__ import annotations

import hashlib
import hmac
import time
from ipaddress import ip_address, ip_network

from fastapi import Request

from app.api.errors import ApiError
from app.core.config import Settings

_BFF_CLIENT_IP_WINDOW_SECONDS = 60
_BFF_CLIENT_IP_HEADERS = (
    "x-kb-client-ip",
    "x-kb-client-timestamp",
    "x-kb-client-signature",
)


def _normalized_ip(value: str | None) -> str | None:
    if value is None or not value or value != value.strip() or len(value) > 64 or "%" in value:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def _verified_bff_client_ip(request: Request, settings: Settings) -> str | None:
    client_ip = request.headers.get(_BFF_CLIENT_IP_HEADERS[0])
    timestamp = request.headers.get(_BFF_CLIENT_IP_HEADERS[1])
    signature = request.headers.get(_BFF_CLIENT_IP_HEADERS[2])
    if client_ip is None or timestamp is None or signature is None:
        return None

    secret = (
        settings.bff_shared_secret.get_secret_value()
        if settings.bff_shared_secret is not None
        else ""
    )
    normalized_ip = _normalized_ip(client_ip)
    if not secret or normalized_ip is None:
        return None
    if (
        not timestamp.isascii()
        or not timestamp.isdigit()
        or len(timestamp) > 20
        or str(int(timestamp)) != timestamp
    ):
        return None
    timestamp_value = int(timestamp)
    if abs(int(time.time()) - timestamp_value) > _BFF_CLIENT_IP_WINDOW_SECONDS:
        return None
    if len(signature) != 64 or any(character not in "0123456789abcdef" for character in signature):
        return None

    canonical = f"v1\n{timestamp}\n{client_ip}".encode()
    expected = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    return normalized_ip


def _peer_is_trusted_proxy(peer_ip: str, settings: Settings) -> bool:
    normalized_peer = _normalized_ip(peer_ip)
    if normalized_peer is None:
        return False
    address = ip_address(normalized_peer)
    return any(
        address.version == network.version and address in network
        for network in (ip_network(cidr, strict=True) for cidr in settings.trusted_proxy_cidrs)
    )


def request_client_ip(request: Request, settings: Settings) -> str:
    """Resolve a rate-limit identity without trusting arbitrary proxy headers."""

    peer_ip = request.client.host if request.client else "unknown"
    bff_secret_configured = bool(
        settings.bff_shared_secret is not None and settings.bff_shared_secret.get_secret_value()
    )
    signed_headers_present = any(
        request.headers.get(name) is not None for name in _BFF_CLIENT_IP_HEADERS
    )
    if bff_secret_configured and signed_headers_present:
        verified_ip = _verified_bff_client_ip(request, settings)
        if verified_ip is None:
            raise ApiError(
                status_code=400,
                code="invalid_bff_signature",
                message="BFF client IP signature is invalid or expired",
            )
        return verified_ip

    if settings.serverless or _peer_is_trusted_proxy(peer_ip, settings):
        for header in ("x-vercel-forwarded-for", "x-forwarded-for"):
            forwarded_ip = _normalized_ip(request.headers.get(header))
            if forwarded_ip is not None:
                return forwarded_ip
    return peer_ip
