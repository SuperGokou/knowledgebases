from __future__ import annotations

import pytest

from app.db.models import Role
from tests.test_integration_api import ApiHarness, api_harness  # noqa: F401


@pytest.mark.asyncio
async def test_role_catalog_supports_stable_pagination_and_literal_search(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    async with api_harness.session_factory() as session:
        session.add_all(
            Role(
                code=f"catalog-{index:03d}",
                name=("Literal %_ Role" if index == 104 else f"Catalog Role {index:03d}"),
                description="Role catalog pagination fixture",
                priority=-100,
            )
            for index in range(105)
        )
        await session.commit()

    pages: list[list[dict[str, object]]] = []
    for offset in (0, 50, 100):
        response = await api_harness.client.get(
            "/api/v1/roles",
            headers=headers,
            params={"limit": 51, "offset": offset},
        )
        assert response.status_code == 200, response.text
        pages.append(response.json()[:50])

    flattened = [item for page in pages for item in page]
    flattened_ids = [str(item["id"]) for item in flattened]
    assert len(flattened_ids) == len(set(flattened_ids))
    assert "catalog-104" in {str(item["code"]) for item in pages[2]}
    assert [
        (-int(item["priority"]), str(item["code"]), str(item["id"])) for item in flattened
    ] == sorted((-int(item["priority"]), str(item["code"]), str(item["id"])) for item in flattened)

    name_search = await api_harness.client.get(
        "/api/v1/roles",
        headers=headers,
        params={"limit": 51, "offset": 0, "q": "%_"},
    )
    code_search = await api_harness.client.get(
        "/api/v1/roles",
        headers=headers,
        params={"limit": 51, "offset": 0, "q": "catalog-104"},
    )
    assert name_search.status_code == 200, name_search.text
    assert code_search.status_code == 200, code_search.text
    assert [item["code"] for item in name_search.json()] == ["catalog-104"]
    assert [item["code"] for item in code_search.json()] == ["catalog-104"]


@pytest.mark.asyncio
async def test_role_catalog_rejects_unbounded_search_terms(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    tokens = await api_harness.login()
    response = await api_harness.client.get(
        "/api/v1/roles",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        params={"q": "x" * 201},
    )
    assert response.status_code == 422, response.text


@pytest.mark.asyncio
async def test_assignable_role_catalog_does_not_leak_forbidden_candidates(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    admin_tokens = await api_harness.login()
    admin_headers = {"Authorization": f"Bearer {admin_tokens['access_token']}"}

    async def create_role(
        code: str,
        *,
        priority: int,
        permission_codes: list[str] | None = None,
        limits: dict[str, int] | None = None,
    ) -> dict[str, object]:
        response = await api_harness.client.post(
            "/api/v1/roles",
            headers=admin_headers,
            json={
                "code": code,
                "name": code.replace("-", " ").title(),
                "priority": priority,
                "permission_codes": permission_codes or [],
                "limits": limits or {},
            },
        )
        assert response.status_code == 201, response.text
        return response.json()

    actor_role = await create_role(
        "catalog-actor",
        priority=-10,
        permission_codes=["role:read", "role:assign"],
    )
    safe_role = await create_role("candidate-safe", priority=-100)
    equal_priority_role = await create_role("candidate-equal", priority=-10)
    permission_role = await create_role(
        "candidate-permission",
        priority=-100,
        permission_codes=["knowledge:grant"],
    )
    limit_role = await create_role(
        "candidate-limit",
        priority=-100,
        limits={"requests_per_minute": 1},
    )
    knowledge_role = await create_role("candidate-hidden-kb", priority=-100)

    actor_password = "Catalog-actor-password-123!"
    actor = await api_harness.client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "catalog-actor@example.com",
            "password": actor_password,
            "display_name": "Catalog actor",
            "role_ids": [actor_role["id"]],
        },
    )
    assert actor.status_code == 201, actor.text

    knowledge_base = await api_harness.client.post(
        "/api/v1/knowledge-bases",
        headers=admin_headers,
        json={"name": "Hidden candidate knowledge base"},
    )
    assert knowledge_base.status_code == 201, knowledge_base.text
    knowledge_payload = knowledge_base.json()
    grant = await api_harness.client.put(
        f"/api/v1/knowledge-bases/{knowledge_payload['id']}/role-grants",
        headers=admin_headers,
        json={
            "expected_version": knowledge_payload["role_grant_version"],
            "grants": [{"role_id": knowledge_role["id"], "access_level": "reader"}],
        },
    )
    assert grant.status_code == 200, grant.text

    actor_login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "catalog-actor@example.com", "password": actor_password},
    )
    assert actor_login.status_code == 200, actor_login.text
    actor_headers = {"Authorization": f"Bearer {actor_login.json()['access_token']}"}

    management_view = await api_harness.client.get(
        "/api/v1/roles",
        headers=actor_headers,
        params={"limit": 50, "q": "candidate-"},
    )
    candidate_view = await api_harness.client.get(
        "/api/v1/roles",
        headers=actor_headers,
        params={"assignable": True, "limit": 50, "q": "candidate-"},
    )
    system_candidate = await api_harness.client.get(
        "/api/v1/roles",
        headers=admin_headers,
        params={"assignable": True, "q": "admin"},
    )
    assert management_view.status_code == 200, management_view.text
    assert candidate_view.status_code == 200, candidate_view.text
    assert system_candidate.status_code == 200, system_candidate.text
    assert {item["id"] for item in management_view.json()} == {
        safe_role["id"],
        equal_priority_role["id"],
        permission_role["id"],
        limit_role["id"],
        knowledge_role["id"],
    }
    # Candidates intentionally use the stricter `< actor priority` boundary;
    # the equal-priority role remains visible only in the management catalog.
    assert [item["id"] for item in candidate_view.json()] == [safe_role["id"]]
    assert system_candidate.json() == []
