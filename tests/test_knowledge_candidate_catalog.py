from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.security import PasswordService
from app.db.models import (
    KnowledgeBase,
    KnowledgeBaseAccessLevel,
    KnowledgeBaseRoleGrant,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)
from tests.test_integration_api import ApiHarness, api_harness  # noqa: F401


@pytest.mark.asyncio
async def test_minimum_access_is_filtered_inside_acl_query_before_pagination(
    api_harness: ApiHarness,  # noqa: F811
) -> None:
    password = "Catalog-password-123!"
    base_time = datetime(2030, 3, 1, tzinfo=UTC)

    async with api_harness.session_factory() as session:
        admin = await session.scalar(select(User).where(User.email == "admin@example.com"))
        upload_permission = await session.scalar(
            select(Permission).where(Permission.code == "file:upload")
        )
        assert admin is not None
        assert upload_permission is not None

        catalog_role = Role(code="catalog_member", name="Catalog member", priority=-100)
        operator = User(
            email="catalog-member@example.com",
            password_hash=PasswordService().hash(password),
        )
        session.add_all([catalog_role, operator])
        await session.flush()
        session.add_all(
            [
                RolePermission(
                    role_id=catalog_role.id,
                    permission_id=upload_permission.id,
                ),
                UserRole(
                    user_id=operator.id,
                    role_id=catalog_role.id,
                    assigned_by=admin.id,
                ),
            ]
        )

        reader_bases = [
            KnowledgeBase(
                owner_id=admin.id,
                name=f"Reader catalog {index:03d}",
                created_at=base_time + timedelta(seconds=100 + index),
                updated_at=base_time + timedelta(seconds=100 + index),
            )
            for index in range(60)
        ]
        editor_bases = [
            KnowledgeBase(
                owner_id=admin.id,
                name=("Editor literal %_ candidate" if index == 0 else f"Editor catalog {index}"),
                created_at=base_time + timedelta(seconds=index),
                updated_at=base_time + timedelta(seconds=index),
            )
            for index in range(3)
        ]
        manager_base = KnowledgeBase(
            owner_id=admin.id,
            name="Manager catalog",
            created_at=base_time - timedelta(seconds=1),
            updated_at=base_time - timedelta(seconds=1),
        )
        session.add_all([*reader_bases, *editor_bases, manager_base])
        await session.flush()
        session.add_all(
            [
                *[
                    KnowledgeBaseRoleGrant(
                        knowledge_base_id=item.id,
                        role_id=catalog_role.id,
                        access_level=KnowledgeBaseAccessLevel.READER,
                        granted_by=admin.id,
                    )
                    for item in reader_bases
                ],
                *[
                    KnowledgeBaseRoleGrant(
                        knowledge_base_id=item.id,
                        role_id=catalog_role.id,
                        access_level=KnowledgeBaseAccessLevel.EDITOR,
                        granted_by=admin.id,
                    )
                    for item in editor_bases
                ],
                KnowledgeBaseRoleGrant(
                    knowledge_base_id=manager_base.id,
                    role_id=catalog_role.id,
                    access_level=KnowledgeBaseAccessLevel.MANAGER,
                    granted_by=admin.id,
                ),
            ]
        )
        await session.commit()

    login = await api_harness.client.post(
        "/api/v1/auth/token",
        data={"username": "catalog-member@example.com", "password": password},
    )
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    editable = await api_harness.client.get(
        "/api/v1/knowledge-bases",
        headers=headers,
        params={"limit": 51, "offset": 0, "minimum_access_level": "editor"},
    )
    assert editable.status_code == 200, editable.text
    assert {item["name"] for item in editable.json()} == {
        "Editor literal %_ candidate",
        "Editor catalog 1",
        "Editor catalog 2",
        "Manager catalog",
    }
    assert {item["access_level"] for item in editable.json()} == {"editor", "manager"}

    manageable = await api_harness.client.get(
        "/api/v1/knowledge-bases",
        headers=headers,
        params={"minimum_access_level": "manager"},
    )
    assert manageable.status_code == 200, manageable.text
    assert [item["name"] for item in manageable.json()] == ["Manager catalog"]

    literal_search = await api_harness.client.get(
        "/api/v1/knowledge-bases",
        headers=headers,
        params={
            "q": "%_",
            "minimum_access_level": "editor",
            "limit": 51,
            "offset": 0,
        },
    )
    assert literal_search.status_code == 200, literal_search.text
    assert [item["name"] for item in literal_search.json()] == ["Editor literal %_ candidate"]


def test_openapi_bounds_minimum_knowledge_access_catalog_filter() -> None:
    from app.main import app

    parameters = app.openapi()["paths"]["/api/v1/knowledge-bases"]["get"]["parameters"]
    minimum = next(item for item in parameters if item["name"] == "minimum_access_level")
    assert minimum["in"] == "query"
    enum_reference = next(item for item in minimum["schema"]["anyOf"] if "$ref" in item)["$ref"]
    enum_name = enum_reference.rsplit("/", 1)[-1]
    assert app.openapi()["components"]["schemas"][enum_name]["enum"] == [
        "reader",
        "editor",
        "manager",
    ]
