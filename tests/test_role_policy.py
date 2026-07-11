import pytest

from app.api.errors import ApiError
from app.api.v1.routes.roles import _ensure_role_mutable
from app.db.models import Role, User
from app.services.access import AccessContext


def access_context(*, is_superuser: bool) -> AccessContext:
    return AccessContext(
        user=User(
            email="admin@example.com",
            password_hash="not-used",
            is_superuser=is_superuser,
        ),
        permissions=frozenset({"*"}),
        limits={},
        role_ids=frozenset(),
        max_role_priority=10_000,
    )


def test_system_role_is_immutable_even_for_superuser() -> None:
    access = access_context(is_superuser=True)
    role = Role(code="system_admin", name="系统管理员", is_system=True, priority=10_000)

    with pytest.raises(ApiError) as captured:
        _ensure_role_mutable(access, role)

    assert captured.value.code == "system_role"


def test_superuser_can_still_modify_custom_roles() -> None:
    access = access_context(is_superuser=True)
    role = Role(code="custom_admin", name="自定义管理员", is_system=False, priority=10_000)

    _ensure_role_mutable(access, role)
