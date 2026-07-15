import base64
from urllib.parse import parse_qs, urlparse

import pytest

from app.core.config import Settings
from app.domain.files import UploadMode, UploadPlan
from app.services.storage import StorageService


def signed_headers(url: str) -> set[str]:
    values = parse_qs(urlparse(url).query)["X-Amz-SignedHeaders"][0]
    return set(values.split(";"))


@pytest.mark.asyncio
async def test_single_upload_signs_exact_content_length() -> None:
    service = StorageService(Settings())
    initiated = await service.initiate(
        key="staging/test.pdf",
        content_type="application/pdf",
        upload_session_id="session-1",
        expected_size_bytes=123,
        plan=UploadPlan(mode=UploadMode.SINGLE, part_size_bytes=123, part_count=1),
    )

    assert initiated.url is not None
    assert initiated.required_headers["Content-Length"] == "123"
    assert "content-length" in signed_headers(initiated.url)


@pytest.mark.asyncio
async def test_single_upload_is_a_create_only_capability() -> None:
    service = StorageService(Settings())
    initiated = await service.initiate(
        key="staging/create-only.pdf",
        content_type="application/pdf",
        upload_session_id="session-create-only",
        expected_size_bytes=123,
        plan=UploadPlan(mode=UploadMode.SINGLE, part_size_bytes=123, part_count=1),
    )

    assert initiated.url is not None
    assert initiated.required_headers["If-None-Match"] == "*"
    assert "if-none-match" in signed_headers(initiated.url)


@pytest.mark.asyncio
async def test_seal_single_upload_replaces_the_capability_key_with_a_tombstone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = StorageService(Settings())
    calls: list[dict[str, object]] = []

    def put_object(**kwargs: object) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(service._client, "put_object", put_object)

    await service.seal_single_upload(
        key="staging/sealed.pdf",
        upload_session_id="session-sealed",
    )

    assert calls == [
        {
            "Bucket": "knowledge-base",
            "Key": "staging/sealed.pdf",
            "Body": b"",
            "ContentLength": 0,
            "ContentType": "application/x-kb-upload-tombstone",
            "Metadata": {
                "upload-session-id": "session-sealed",
                "upload-capability-state": "sealed",
            },
        }
    ]


def test_each_multipart_url_signs_its_expected_part_length() -> None:
    service = StorageService(Settings())
    parts = service.presign_parts(
        key="staging/test.pdf",
        upload_id="upload-1",
        part_numbers=[1, 2],
        expected_size_bytes=11,
        part_size_bytes=6,
    )

    assert parts[1].size_bytes == 6
    assert parts[2].size_bytes == 5
    assert "content-length" in signed_headers(parts[1].url)
    assert "content-length" in signed_headers(parts[2].url)


@pytest.mark.asyncio
async def test_cos_virtual_addressing_places_bucket_in_hostname() -> None:
    service = StorageService(
        Settings(
            s3_endpoint_url="https://cos.ap-beijing.myqcloud.com",
            s3_public_endpoint_url="https://cos.ap-beijing.myqcloud.com",
            s3_bucket="example-1250000000",
            s3_addressing_style="virtual",
            s3_use_ssl=True,
        )
    )
    initiated = await service.initiate(
        key="staging/test.txt",
        content_type="text/plain",
        upload_session_id="session-cos",
        expected_size_bytes=5,
        plan=UploadPlan(mode=UploadMode.SINGLE, part_size_bytes=5, part_count=1),
    )

    assert initiated.url is not None
    assert urlparse(initiated.url).hostname == ("example-1250000000.cos.ap-beijing.myqcloud.com")


@pytest.mark.asyncio
async def test_isolated_storage_signs_the_internal_tls_proxy_origin() -> None:
    service = StorageService(
        Settings(
            environment="production",
            deployment_profile="isolated",
            jwt_secret="4f" * 32,
            database_url="postgresql+asyncpg://knowledge:pass@postgres:5432/knowledge",
            redis_url="redis://:pass@redis:6379/0",
            s3_endpoint_url="http://minio:9000",
            s3_public_endpoint_url="https://knowledge.internal:19444",
            s3_access_key="offline-access-key",
            s3_secret_key="offline-secret-key",
            s3_use_ssl=True,
            malware_scan_host="clamd",
            storage_capacity_probe_path="/var/lib/kb-capacity",
            trusted_hosts=("knowledge.internal",),
            chat_replay_encryption_keys={1: base64.urlsafe_b64encode(b"s" * 32).decode("ascii")},
            chat_replay_active_key_version=1,
        )
    )
    initiated = await service.initiate(
        key="staging/offline.txt",
        content_type="text/plain",
        upload_session_id="session-offline",
        expected_size_bytes=7,
        plan=UploadPlan(mode=UploadMode.SINGLE, part_size_bytes=7, part_count=1),
    )

    assert initiated.url is not None
    parsed = urlparse(initiated.url)
    assert parsed.scheme == "https"
    assert parsed.hostname == "knowledge.internal"
    assert parsed.port == 19444
