from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePath

from app.domain.errors import FilePolicyViolation


class UploadMode(StrEnum):
    SINGLE = "single"
    MULTIPART = "multipart"


@dataclass(frozen=True, slots=True)
class ValidatedUpload:
    filename: str
    extension: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class UploadPlan:
    mode: UploadMode
    part_size_bytes: int
    part_count: int


def validate_upload(
    filename: str,
    size_bytes: int,
    max_upload_bytes: int | None,
    allowed_extensions: set[str] | frozenset[str],
) -> ValidatedUpload:
    """Validate file name, final extension, non-empty size, and role limit."""
    safe_name = PurePath(filename).name.strip()
    if not safe_name or safe_name in {".", ".."}:
        raise FilePolicyViolation("filename is required")

    extension = PurePath(safe_name).suffix.lower()
    normalized_allowed = {item.lower() for item in allowed_extensions}
    if extension not in normalized_allowed:
        raise FilePolicyViolation(f"unsupported file extension: {extension or '(none)'}")
    if size_bytes <= 0:
        raise FilePolicyViolation("file size must be greater than zero")
    if max_upload_bytes is not None and size_bytes > max_upload_bytes:
        raise FilePolicyViolation(f"file exceeds maximum upload size of {max_upload_bytes} bytes")

    return ValidatedUpload(filename=safe_name, extension=extension, size_bytes=size_bytes)


def plan_upload(
    *,
    size_bytes: int,
    multipart_threshold_bytes: int,
    preferred_part_size: int,
    max_parts: int = 10_000,
) -> UploadPlan:
    """Choose single/multipart upload and grow parts to respect the S3 part cap."""
    if min(size_bytes, multipart_threshold_bytes, preferred_part_size, max_parts) <= 0:
        raise ValueError("upload planning values must be positive")

    if size_bytes < multipart_threshold_bytes:
        return UploadPlan(mode=UploadMode.SINGLE, part_size_bytes=size_bytes, part_count=1)

    minimum_part_size = math.ceil(size_bytes / max_parts)
    part_size = max(preferred_part_size, minimum_part_size)
    part_count = math.ceil(size_bytes / part_size)
    return UploadPlan(
        mode=UploadMode.MULTIPART,
        part_size_bytes=part_size,
        part_count=part_count,
    )
