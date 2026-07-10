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
    assert urlparse(initiated.url).hostname == (
        "example-1250000000.cos.ap-beijing.myqcloud.com"
    )
