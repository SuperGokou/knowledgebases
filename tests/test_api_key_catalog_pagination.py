from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.db.models import ApiKey, KnowledgeBase, User
from tests.test_integration_api import ApiHarness, api_harness  # noqa: F401


@pytest.mark.asyncio
async def test_api_keys_are_reachable_with_stable_fifty_plus_one_pagination(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    created_at = datetime(2030, 1, 1, tzinfo=UTC)

    async with api_harness.session_factory() as session:
        owner = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert owner is not None
        session.add_all(
            [
                ApiKey(
                    user_id=owner.id,
                    created_by=owner.id,
                    credential_family_id=uuid4(),
                    name=f"pagination-key-{index:03d}",
                    key_hash=f"{index + 1:064x}",
                    key_prefix=f"kbp_{index:020d}",
                    permission_codes=["knowledge:read"],
                    knowledge_base_ids=[],
                    requests_per_minute=60,
                    created_at=created_at + timedelta(seconds=index),
                )
                for index in range(55)
            ]
        )
        await session.commit()

    collected: list[dict[str, object]] = []
    for offset in (0, 50):
        response = await api_harness.client.get(
            "/api/v1/api-keys",
            headers=headers,
            params={"limit": 51, "offset": offset},
        )
        assert response.status_code == 200, response.text
        collected.extend(response.json()[:50])

    key_prefix = "pagination-key-"
    names = [str(item["name"]) for item in collected if str(item["name"]).startswith(key_prefix)]
    assert names == [f"pagination-key-{index:03d}" for index in range(54, -1, -1)]


@pytest.mark.asyncio
async def test_knowledge_catalog_searches_literal_names_beyond_the_first_hundred(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    created_at = datetime(2030, 2, 1, tzinfo=UTC)
    special_name = "归档知识库 %_ literal"

    async with api_harness.session_factory() as session:
        owner = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert owner is not None
        session.add_all(
            [
                KnowledgeBase(
                    owner_id=owner.id,
                    name=special_name if index == 0 else f"分页知识库 {index:03d}",
                    updated_at=created_at + timedelta(seconds=index),
                    created_at=created_at + timedelta(seconds=index),
                )
                for index in range(105)
            ]
        )
        await session.commit()

    collected: list[dict[str, object]] = []
    for offset in (0, 50, 100):
        response = await api_harness.client.get(
            "/api/v1/knowledge-bases",
            headers=headers,
            params={"limit": 51, "offset": offset},
        )
        assert response.status_code == 200, response.text
        collected.extend(response.json()[:50])

    assert special_name in {str(item["name"]) for item in collected}

    searched = await api_harness.client.get(
        "/api/v1/knowledge-bases",
        headers=headers,
        params={"limit": 51, "offset": 0, "q": "%_"},
    )
    assert searched.status_code == 200, searched.text
    assert [item["name"] for item in searched.json()] == [special_name]

    unbounded = await api_harness.client.get(
        "/api/v1/knowledge-bases",
        headers=headers,
        params={"q": "x" * 201},
    )
    assert unbounded.status_code == 422, unbounded.text


def test_openapi_exposes_api_key_rotation_and_bounded_knowledge_search() -> None:
    from app.main import app

    schema = app.openapi()
    assert "post" in schema["paths"]["/api/v1/api-keys/{api_key_id}/rotate"]

    parameters = schema["paths"]["/api/v1/knowledge-bases"]["get"]["parameters"]
    query = next(item for item in parameters if item["name"] == "q")
    query_alternatives = query["schema"]["anyOf"]
    string_schema = next(item for item in query_alternatives if item.get("type") == "string")
    assert string_schema["maxLength"] == 200
