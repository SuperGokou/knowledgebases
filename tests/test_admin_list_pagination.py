from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

from app.db.models import File, FileStatus, User
from tests.test_integration_api import ApiHarness, api_harness  # noqa: F401


@pytest.mark.asyncio
async def test_users_and_files_beyond_first_hundred_are_reachable_and_searchable(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    special_user_email = "pagination-literal-101@example.com"
    special_file_name = "pagination-literal-%_-101.txt"

    async with api_harness.session_factory() as session:
        owner = await session.scalar(select(User).where(User.email == "admin@example.com"))
        assert owner is not None
        users = [
            User(
                email=(
                    special_user_email if index == 101 else f"pagination-{index:03d}@example.com"
                ),
                display_name=(
                    "Literal %_ member" if index == 101 else f"Pagination member {index:03d}"
                ),
                password_hash="not-used-by-pagination-test",
            )
            for index in range(105)
        ]
        files = [
            File(
                owner_id=owner.id,
                bucket="kb",
                object_key=f"objects/pagination/{uuid4()}.txt",
                original_name=(
                    special_file_name if index == 101 else f"pagination-{index:03d}.txt"
                ),
                extension=".txt",
                content_type="text/plain",
                size_bytes=index + 1,
                status=FileStatus.AVAILABLE,
            )
            for index in range(105)
        ]
        session.add_all([*users, *files])
        await session.commit()

    user_pages: list[dict[str, object]] = []
    file_pages: list[dict[str, object]] = []
    for offset in (0, 50, 100):
        users_response = await api_harness.client.get(
            "/api/v1/users",
            headers=headers,
            params={"limit": 51, "offset": offset},
        )
        files_response = await api_harness.client.get(
            "/api/v1/files",
            headers=headers,
            params={"limit": 51, "offset": offset},
        )
        assert users_response.status_code == 200, users_response.text
        assert files_response.status_code == 200, files_response.text
        user_pages.extend(users_response.json()[:50])
        file_pages.extend(files_response.json()[:50])

    assert special_user_email in {str(item["email"]) for item in user_pages}
    assert special_file_name in {str(item["original_name"]) for item in file_pages}

    user_search = await api_harness.client.get(
        "/api/v1/users",
        headers=headers,
        params={"limit": 51, "offset": 0, "search": "%_"},
    )
    file_search = await api_harness.client.get(
        "/api/v1/files",
        headers=headers,
        params={"limit": 51, "offset": 0, "search": "%_"},
    )
    assert user_search.status_code == 200, user_search.text
    assert file_search.status_code == 200, file_search.text
    assert [item["email"] for item in user_search.json()] == [special_user_email]
    assert [item["original_name"] for item in file_search.json()] == [special_file_name]


@pytest.mark.asyncio
async def test_admin_list_search_rejects_unbounded_terms(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    tokens = await api_harness.login()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    for path in ("/api/v1/users", "/api/v1/files"):
        response = await api_harness.client.get(
            path,
            headers=headers,
            params={"search": "x" * 201},
        )
        assert response.status_code == 422, response.text
