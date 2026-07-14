from __future__ import annotations

from datetime import datetime
from typing import Any, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.db.models import (
    FileStatus,
    KnowledgeIngestionStatus,
    MalwareScanStatus,
    OkfConversionStatus,
    UploadSessionStatus,
)


class UploadInitiateRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=500)
    size_bytes: int = Field(gt=0)
    content_type: str = Field(default="application/octet-stream", max_length=255)
    checksum_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-fA-F]{64}$",
        description="Optional lowercase or uppercase hexadecimal SHA-256 for single-part uploads",
    )
    custom_metadata: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=8, max_length=200)
    knowledge_base_id: UUID | None = None


class UploadInitiateResponse(BaseModel):
    upload_session_id: UUID
    file_id: UUID
    mode: str
    expires_at: datetime
    part_size_bytes: int
    part_count: int
    upload_url: str | None = None
    required_headers: dict[str, str] = Field(default_factory=dict)


class PartUrlRequest(BaseModel):
    part_numbers: list[int] = Field(min_length=1, max_length=100)

    @field_validator("part_numbers")
    @classmethod
    def unique_parts(cls, value: list[int]) -> list[int]:
        if len(value) != len(set(value)):
            raise ValueError("part numbers must be unique")
        return value


class PartUrl(BaseModel):
    part_number: int
    url: str
    size_bytes: int


class PartUrlResponse(BaseModel):
    parts: list[PartUrl]
    expires_in: int


class CompletedPart(BaseModel):
    part_number: int = Field(ge=1, le=10_000)
    etag: str = Field(min_length=1, max_length=200)
    checksum_sha256: str | None = Field(default=None, max_length=200)


class CompleteUploadRequest(BaseModel):
    parts: list[CompletedPart] = Field(default_factory=list, max_length=10_000)


class UploadSessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    file_id: UUID
    user_id: UUID
    mode: str
    part_size_bytes: int
    part_count: int
    expected_size_bytes: int
    status: UploadSessionStatus
    expires_at: datetime


class FileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    owner_id: UUID
    knowledge_base_id: UUID | None
    original_name: str
    extension: str
    content_type: str
    size_bytes: int
    checksum_algorithm: str | None
    checksum_value: str | None
    status: FileStatus
    knowledge_status: KnowledgeIngestionStatus
    knowledge_error_code: str | None
    malware_scan_status: MalwareScanStatus
    malware_signature: str | None
    malware_scan_error_code: str | None
    malware_scan_started_at: datetime | None
    malware_scanned_at: datetime | None
    searchable: bool = False
    custom_metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    available_at: datetime | None

    @model_validator(mode="after")
    def derive_searchable_state(self) -> Self:
        self.searchable = self.knowledge_status is KnowledgeIngestionStatus.INDEXED
        return self


class DownloadGrant(BaseModel):
    url: str
    expires_in: int


class OkfConversionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    file_id: UUID
    knowledge_base_id: UUID
    file_version: int
    status: OkfConversionStatus
    attempts: int
    model: str | None
    prompt_version: str
    output_entry_id: UUID | None
    error_code: str | None
    next_attempt_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime
