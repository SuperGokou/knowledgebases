import pytest

from app.domain.errors import FilePolicyViolation
from app.domain.files import UploadMode, plan_upload, validate_upload

ALLOWED_EXTENSIONS = {
    ".txt",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".csv",
    ".pdf",
    ".ppt",
    ".pptx",
}


@pytest.mark.parametrize(
    "filename",
    [
        "notes.txt",
        "contract.DOC",
        "report.docx",
        "legacy.xls",
        "budget.xlsx",
        "records.csv",
        "manual.pdf",
        "slides.ppt",
        "deck.pptx",
    ],
)
def test_supported_document_types_are_accepted(filename: str) -> None:
    result = validate_upload(
        filename=filename,
        size_bytes=1,
        max_upload_bytes=100,
        allowed_extensions=ALLOWED_EXTENSIONS,
    )

    assert result.extension == "." + filename.rsplit(".", 1)[-1].lower()


def test_double_extension_uses_final_extension() -> None:
    with pytest.raises(FilePolicyViolation, match="unsupported file extension"):
        validate_upload(
            filename="invoice.pdf.exe",
            size_bytes=1,
            max_upload_bytes=100,
            allowed_extensions=ALLOWED_EXTENSIONS,
        )


def test_empty_and_oversized_files_are_rejected() -> None:
    with pytest.raises(FilePolicyViolation, match="greater than zero"):
        validate_upload("empty.pdf", 0, 100, ALLOWED_EXTENSIONS)

    with pytest.raises(FilePolicyViolation, match="maximum upload size"):
        validate_upload("large.pdf", 101, 100, ALLOWED_EXTENSIONS)


def test_small_upload_uses_single_presigned_put() -> None:
    plan = plan_upload(size_bytes=10, multipart_threshold_bytes=100, preferred_part_size=20)

    assert plan.mode is UploadMode.SINGLE
    assert plan.part_count == 1


def test_large_upload_uses_multipart_and_never_exceeds_s3_part_limit() -> None:
    plan = plan_upload(
        size_bytes=100_000,
        multipart_threshold_bytes=100,
        preferred_part_size=5,
        max_parts=10_000,
    )

    assert plan.mode is UploadMode.MULTIPART
    assert plan.part_count <= 10_000
    assert plan.part_size_bytes >= 10
