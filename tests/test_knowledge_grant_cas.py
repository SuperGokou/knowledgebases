from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.knowledge_bases import KnowledgeBaseRoleGrantSet


def test_knowledge_grant_replacement_requires_expected_version() -> None:
    with pytest.raises(ValidationError) as captured:
        KnowledgeBaseRoleGrantSet.model_validate({"grants": []})

    errors = captured.value.errors()
    assert any(error["loc"] == ("expected_version",) for error in errors)


@pytest.mark.parametrize("value", [0, -1])
def test_knowledge_grant_expected_version_must_be_positive(value: int) -> None:
    with pytest.raises(ValidationError):
        KnowledgeBaseRoleGrantSet.model_validate(
            {
                "expected_version": value,
                "grants": [],
            }
        )
