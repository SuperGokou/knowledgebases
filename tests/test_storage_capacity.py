from __future__ import annotations

from pathlib import Path

import pytest

from app.services.storage_capacity import (
    DECIMAL_GB,
    FilesystemCapacity,
    StoragePolicyViolation,
    assess_storage_capacity,
    effective_upload_limit,
)


def capacity_at(percent: int) -> FilesystemCapacity:
    total = 1_000
    used = percent * 10
    return FilesystemCapacity(total_bytes=total, used_bytes=used, free_bytes=total - used)


@pytest.mark.parametrize(
    ("percent", "expected_level"),
    [(69, "normal"), (70, "warning"), (79, "warning")],
)
def test_watermarks_below_bulk_stop_allow_single_and_multipart(
    percent: int,
    expected_level: str,
) -> None:
    for is_bulk in (False, True):
        assessment = assess_storage_capacity(
            filesystem=capacity_at(percent),
            object_used_bytes=0,
            incoming_bytes=1,
            is_bulk=is_bulk,
        )

        assert assessment.level == expected_level
        assert assessment.allowed is True


@pytest.mark.parametrize("percent", [80, 89])
def test_bulk_stop_watermark_rejects_multipart_but_allows_single(percent: int) -> None:
    single = assess_storage_capacity(
        filesystem=capacity_at(percent),
        object_used_bytes=0,
        incoming_bytes=1,
        is_bulk=False,
    )
    bulk = assess_storage_capacity(
        filesystem=capacity_at(percent),
        object_used_bytes=0,
        incoming_bytes=1,
        is_bulk=True,
    )

    assert single.allowed is True
    assert single.level == "bulk_blocked"
    assert bulk.allowed is False
    assert bulk.reason_code == "storage_bulk_uploads_paused"


def test_reject_watermark_blocks_every_upload_at_90_percent() -> None:
    for is_bulk in (False, True):
        assessment = assess_storage_capacity(
            filesystem=capacity_at(90),
            object_used_bytes=0,
            incoming_bytes=1,
            is_bulk=is_bulk,
        )

        assert assessment.allowed is False
        assert assessment.level == "blocked"
        assert assessment.reason_code == "storage_capacity_critical"


@pytest.mark.parametrize(
    ("used_bytes", "incoming_bytes", "allowed"),
    [
        (179 * DECIMAL_GB, DECIMAL_GB - 1, True),
        (179 * DECIMAL_GB, DECIMAL_GB, False),
        (180 * DECIMAL_GB, 1, False),
    ],
)
def test_object_stop_line_blocks_uploads_that_reach_180_decimal_gb(
    used_bytes: int,
    incoming_bytes: int,
    allowed: bool,
) -> None:
    assessment = assess_storage_capacity(
        filesystem=FilesystemCapacity(
            total_bytes=300 * DECIMAL_GB,
            used_bytes=1,
            free_bytes=300 * DECIMAL_GB - 1,
        ),
        object_used_bytes=used_bytes,
        incoming_bytes=incoming_bytes,
        is_bulk=False,
    )

    assert assessment.allowed is allowed
    if not allowed:
        assert assessment.reason_code == "object_storage_stop_line_reached"


def test_platform_upload_limit_always_caps_an_unlimited_role() -> None:
    assert effective_upload_limit(None, platform_limit_bytes=2_147_483_648) == 2_147_483_648
    assert (
        effective_upload_limit(4_000_000_000, platform_limit_bytes=2_147_483_648) == 2_147_483_648
    )
    assert effective_upload_limit(1_000, platform_limit_bytes=2_147_483_648) == 1_000
    assert effective_upload_limit(0, platform_limit_bytes=2_147_483_648) == 0


def test_missing_capacity_probe_fails_closed_when_policy_is_required(tmp_path: Path) -> None:
    missing = tmp_path / "missing-probe"

    with pytest.raises(StoragePolicyViolation, match="capacity probe"):
        FilesystemCapacity.from_path(missing)
