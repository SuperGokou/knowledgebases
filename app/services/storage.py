from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import boto3  # type: ignore[import-untyped]
from botocore.client import BaseClient  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from app.core.config import Settings
from app.domain.files import UploadMode, UploadPlan


@dataclass(frozen=True, slots=True)
class InitiatedStorageUpload:
    upload_id: str | None
    url: str | None
    required_headers: dict[str, str]


@dataclass(frozen=True, slots=True)
class PresignedPart:
    url: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class StoredObject:
    size_bytes: int
    etag: str | None
    version_id: str | None
    checksum_sha256: str | None
    content_type: str | None


class StorageService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        common = {
            "service_name": "s3",
            "aws_access_key_id": settings.s3_access_key.get_secret_value(),
            "aws_secret_access_key": settings.s3_secret_key.get_secret_value(),
            "region_name": settings.s3_region,
            "config": Config(
                signature_version="s3v4",
                s3={"addressing_style": settings.s3_addressing_style},
                connect_timeout=5,
                read_timeout=30,
                max_pool_connections=20,
                retries={"max_attempts": 3, "mode": "standard"},
            ),
            "use_ssl": settings.s3_use_ssl,
        }
        self._client: BaseClient = boto3.client(
            endpoint_url=settings.s3_endpoint_url or None,
            **common,
        )
        self._presigner: BaseClient = boto3.client(
            endpoint_url=settings.s3_public_endpoint_url or None,
            **common,
        )

    async def initiate(
        self,
        *,
        key: str,
        content_type: str,
        upload_session_id: str,
        expected_size_bytes: int,
        plan: UploadPlan,
        expected_checksum_sha256_base64: str | None = None,
    ) -> InitiatedStorageUpload:
        metadata = {"upload-session-id": upload_session_id}
        if plan.mode is UploadMode.SINGLE:
            params = {
                "Bucket": self._settings.s3_bucket,
                "Key": key,
                "ContentType": content_type,
                "ContentLength": expected_size_bytes,
                "Metadata": metadata,
            }
            if expected_checksum_sha256_base64 is not None:
                params["ChecksumSHA256"] = expected_checksum_sha256_base64
            url = self._presigner.generate_presigned_url(
                "put_object",
                Params=params,
                ExpiresIn=self._settings.presigned_url_seconds,
                HttpMethod="PUT",
            )
            required_headers = {
                "Content-Type": content_type,
                "Content-Length": str(expected_size_bytes),
                "x-amz-meta-upload-session-id": upload_session_id,
            }
            if expected_checksum_sha256_base64 is not None:
                required_headers["x-amz-checksum-sha256"] = expected_checksum_sha256_base64
            return InitiatedStorageUpload(
                upload_id=None,
                url=url,
                required_headers=required_headers,
            )

        response = await asyncio.to_thread(
            self._client.create_multipart_upload,
            Bucket=self._settings.s3_bucket,
            Key=key,
            ContentType=content_type,
            Metadata=metadata,
        )
        return InitiatedStorageUpload(
            upload_id=str(response["UploadId"]),
            url=None,
            required_headers={},
        )

    def presign_parts(
        self,
        *,
        key: str,
        upload_id: str,
        part_numbers: list[int],
        expected_size_bytes: int,
        part_size_bytes: int,
    ) -> dict[int, PresignedPart]:
        def sign(number: int) -> PresignedPart:
            size = min(
                part_size_bytes,
                expected_size_bytes - ((number - 1) * part_size_bytes),
            )
            if size <= 0:
                raise ValueError("part number exceeds expected object size")
            url = self._presigner.generate_presigned_url(
                "upload_part",
                Params={
                    "Bucket": self._settings.s3_bucket,
                    "Key": key,
                    "UploadId": upload_id,
                    "PartNumber": number,
                    "ContentLength": size,
                },
                ExpiresIn=self._settings.presigned_url_seconds,
                HttpMethod="PUT",
            )
            return PresignedPart(url=url, size_bytes=size)

        return {number: sign(number) for number in part_numbers}

    async def complete_multipart(
        self,
        *,
        key: str,
        upload_id: str,
        parts: list[dict[str, Any]],
    ) -> None:
        try:
            await asyncio.to_thread(
                self._client.complete_multipart_upload,
                Bucket=self._settings.s3_bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code")
            if error_code != "NoSuchUpload" or await self.try_head(key=key) is None:
                raise

    async def head(self, *, key: str) -> StoredObject:
        try:
            result = await asyncio.to_thread(
                self._client.head_object,
                Bucket=self._settings.s3_bucket,
                Key=key,
                ChecksumMode="ENABLED",
            )
        except ClientError:
            # Older S3-compatible stores may not implement ChecksumMode yet.
            result = await asyncio.to_thread(
                self._client.head_object,
                Bucket=self._settings.s3_bucket,
                Key=key,
            )
        return StoredObject(
            size_bytes=int(result["ContentLength"]),
            etag=result.get("ETag"),
            version_id=result.get("VersionId"),
            checksum_sha256=result.get("ChecksumSHA256"),
            content_type=result.get("ContentType"),
        )

    async def try_head(self, *, key: str) -> StoredObject | None:
        try:
            return await self.head(key=key)
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code")
            status_code = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if error_code in {"404", "NoSuchKey", "NotFound"} or status_code == 404:
                return None
            raise

    async def abort_multipart(self, *, key: str, upload_id: str) -> None:
        try:
            await asyncio.to_thread(
                self._client.abort_multipart_upload,
                Bucket=self._settings.s3_bucket,
                Key=key,
                UploadId=upload_id,
            )
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code")
            status_code = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if error_code not in {"404", "NoSuchUpload", "NotFound"} and status_code != 404:
                raise

    async def delete(self, *, key: str) -> None:
        await asyncio.to_thread(
            self._client.delete_object,
            Bucket=self._settings.s3_bucket,
            Key=key,
        )

    async def read_bytes(self, *, key: str, max_bytes: int) -> bytes:
        """Read a bounded object for text extraction without unbounded memory use."""

        def read() -> bytes:
            response = self._client.get_object(
                Bucket=self._settings.s3_bucket,
                Key=key,
                Range=f"bytes=0-{max_bytes}",
            )
            body = response["Body"]
            try:
                return bytes(body.read(max_bytes + 1))
            finally:
                body.close()

        data = await asyncio.to_thread(read)
        if len(data) > max_bytes:
            raise ValueError("object exceeds conversion input limit")
        return data

    async def promote(self, *, source_key: str, destination_key: str) -> StoredObject:
        """Copy a verified staging object to a key never exposed by a write URL."""
        await asyncio.to_thread(
            self._client.copy_object,
            Bucket=self._settings.s3_bucket,
            Key=destination_key,
            CopySource={"Bucket": self._settings.s3_bucket, "Key": source_key},
            MetadataDirective="COPY",
        )
        promoted = await self.head(key=destination_key)
        await self.delete(key=source_key)
        return promoted

    def presign_download(self, *, key: str, filename: str) -> str:
        ascii_name = re.sub(r"[^A-Za-z0-9._-]", "_", filename) or "download"
        disposition = f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename)}"
        return str(
            self._presigner.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self._settings.s3_bucket,
                    "Key": key,
                    "ResponseContentDisposition": disposition,
                },
                ExpiresIn=min(self._settings.presigned_url_seconds, 300),
                HttpMethod="GET",
            )
        )
