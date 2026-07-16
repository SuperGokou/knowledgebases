from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

DECIMAL_GB = 1_000_000_000
DEFAULT_OBJECT_STOP_BYTES = 180 * DECIMAL_GB
DEFAULT_WARNING_PERCENT = 70
DEFAULT_BULK_STOP_PERCENT = 80
DEFAULT_REJECT_PERCENT = 90

StorageLevel = Literal["normal", "warning", "bulk_blocked", "blocked"]


class StoragePolicyViolation(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class FilesystemCapacity:
    total_bytes: int
    used_bytes: int
    free_bytes: int

    @classmethod
    def from_path(cls, path: Path) -> FilesystemCapacity:
        try:
            usage = shutil.disk_usage(path)
        except OSError as error:
            raise StoragePolicyViolation(
                "storage_capacity_probe_unavailable",
                "storage capacity probe is unavailable",
            ) from error
        return cls(
            total_bytes=usage.total,
            used_bytes=usage.used,
            free_bytes=usage.free,
        )

    @property
    def used_percent(self) -> float:
        if self.total_bytes <= 0:
            return 100.0
        return (self.used_bytes / self.total_bytes) * 100


@dataclass(frozen=True, slots=True)
class StorageAssessment:
    allowed: bool
    level: StorageLevel
    reason_code: str | None
    filesystem_used_percent: float
    projected_object_bytes: int


def assess_storage_capacity(
    *,
    filesystem: FilesystemCapacity,
    object_used_bytes: int,
    incoming_bytes: int,
    is_bulk: bool,
    warning_percent: int = DEFAULT_WARNING_PERCENT,
    bulk_stop_percent: int = DEFAULT_BULK_STOP_PERCENT,
    reject_percent: int = DEFAULT_REJECT_PERCENT,
    object_stop_bytes: int = DEFAULT_OBJECT_STOP_BYTES,
) -> StorageAssessment:
    projected_object_bytes = object_used_bytes + incoming_bytes
    used_percent = filesystem.used_percent
    if projected_object_bytes >= object_stop_bytes:
        return StorageAssessment(
            allowed=False,
            level="blocked",
            reason_code="object_storage_stop_line_reached",
            filesystem_used_percent=used_percent,
            projected_object_bytes=projected_object_bytes,
        )
    if used_percent >= reject_percent:
        return StorageAssessment(
            allowed=False,
            level="blocked",
            reason_code="storage_capacity_critical",
            filesystem_used_percent=used_percent,
            projected_object_bytes=projected_object_bytes,
        )
    if used_percent >= bulk_stop_percent:
        return StorageAssessment(
            allowed=not is_bulk,
            level="bulk_blocked",
            reason_code="storage_bulk_uploads_paused" if is_bulk else None,
            filesystem_used_percent=used_percent,
            projected_object_bytes=projected_object_bytes,
        )
    if used_percent >= warning_percent:
        return StorageAssessment(
            allowed=True,
            level="warning",
            reason_code=None,
            filesystem_used_percent=used_percent,
            projected_object_bytes=projected_object_bytes,
        )
    return StorageAssessment(
        allowed=True,
        level="normal",
        reason_code=None,
        filesystem_used_percent=used_percent,
        projected_object_bytes=projected_object_bytes,
    )


def effective_upload_limit(
    role_limit_bytes: int | None,
    *,
    platform_limit_bytes: int,
) -> int:
    if role_limit_bytes is None:
        return platform_limit_bytes
    return min(role_limit_bytes, platform_limit_bytes)
