from __future__ import annotations

import json

from app import document_parser_preflight


def test_preflight_passes_for_built_in_offline_parsers(
    capsys,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    monkeypatch.setattr(
        document_parser_preflight,
        "parser_capabilities",
        lambda: {".txt": True, ".docx": True, ".pdf": False},
    )

    assert document_parser_preflight.main(["--require", ".txt", ".docx"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "pass"
    assert report["missing"] == []


def test_preflight_blocks_missing_or_unknown_parser_capabilities(
    capsys,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    monkeypatch.setattr(
        document_parser_preflight,
        "parser_capabilities",
        lambda: {".txt": True, ".pdf": False},
    )

    assert document_parser_preflight.main(["--require", ".pdf", ".doc"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "blocked"
    assert report["missing"] == [".doc", ".pdf"]
    assert report["unknown"] == [".doc"]


def test_require_all_covers_every_advertised_upload_format_and_fails_closed(
    capsys,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    monkeypatch.setattr(
        document_parser_preflight,
        "parser_capabilities",
        lambda: {
            ".txt": True,
            ".doc": False,
            ".docx": True,
            ".xls": False,
            ".xlsx": True,
            ".csv": True,
            ".pdf": False,
            ".ppt": False,
            ".pptx": True,
        },
    )

    assert document_parser_preflight.main(["--require-all"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["required"] == [
        ".csv",
        ".doc",
        ".docx",
        ".pdf",
        ".ppt",
        ".pptx",
        ".txt",
        ".xls",
        ".xlsx",
    ]
    assert report["missing"] == [".doc", ".pdf", ".ppt", ".xls"]
    assert report["status"] == "blocked"
