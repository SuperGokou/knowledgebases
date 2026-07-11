from __future__ import annotations

from uuid import uuid4

from app.schemas.chat import ChatCitation
from app.services.chat import _parse_generated_response, _retrieval_presentation


def _citation(excerpt: str) -> ChatCitation:
    return ChatCitation(
        entry_id=uuid4(),
        source_file_id=uuid4(),
        title="公司概况",
        excerpt=excerpt,
        source_path="company/profile.md",
        format_version="okf/0.1",
        citation_number=1,
        marker="[1]",
    )


def test_retrieval_presentation_removes_markdown_noise_and_builds_data_table() -> None:
    citation = _citation(
        "## 联系方式\n\n| 项目 | 信息 |\n| --- | --- |\n"
        "| **联系人** | 张经理 |\n| **联系电话** | 0514-00000000 |"
    )

    answer, table = _retrieval_presentation("公司联系人信息", [citation])

    assert answer.startswith("根据知识库中的公司资料")
    assert "##" not in answer
    assert "**" not in answer
    assert "| ---" not in answer
    assert "[1]" in answer
    assert table is not None
    assert table.title == "公司联系人信息"
    assert table.columns == ["项目", "信息"]
    assert table.rows == [["联系人", "张经理"], ["联系电话", "0514-00000000"]]
    assert table.citation_numbers == [1]


def test_generated_response_accepts_a_grounded_structured_table() -> None:
    payload = (
        '{"answer":"公司联系人如下 [1]。","table":{"title":"公司联系人信息",'
        '"columns":["项目","信息"],"rows":[["联系人","张经理"]],'
        '"citation_numbers":[1]}}'
    )

    generated = _parse_generated_response(payload, [_citation("联系人：张经理")])

    assert generated is not None
    assert generated.answer == "公司联系人如下 [1]。"
    assert generated.table is not None
    assert generated.table.rows == [["联系人", "张经理"]]


def test_generated_response_rejects_invalid_table_shape_or_unknown_source() -> None:
    bad_shape = (
        '{"answer":"联系人如下 [1]。","table":{"title":"联系人",'
        '"columns":["项目","信息"],"rows":[["联系人"]],"citation_numbers":[1]}}'
    )
    bad_source = (
        '{"answer":"联系人如下 [1]。","table":{"title":"联系人",'
        '"columns":["项目","信息"],"rows":[["联系人","张经理"]],'
        '"citation_numbers":[99]}}'
    )
    citations = [_citation("联系人：张经理")]

    assert _parse_generated_response(bad_shape, citations) is None
    assert _parse_generated_response(bad_source, citations) is None
