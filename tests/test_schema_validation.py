import pytest
from pydantic import ValidationError

from app.schemas.auth import RefreshRequest
from app.schemas.roles import LimitSet, RoleCreate, RolePolicySet, RoleUpdate
from app.schemas.users import UserUpdate


def test_non_nullable_patch_fields_reject_explicit_null() -> None:
    with pytest.raises(ValidationError):
        RoleUpdate(name=None)
    with pytest.raises(ValidationError):
        RoleUpdate(priority=None)
    with pytest.raises(ValidationError):
        UserUpdate(status=None)


def test_role_create_strips_whitespace_and_rejects_blank_name() -> None:
    role = RoleCreate(code="  uploader  ", name="  知识上传员  ")
    assert role.code == "uploader"
    assert role.name == "知识上传员"

    with pytest.raises(ValidationError):
        RoleCreate(code="uploader", name="   ")


@pytest.mark.parametrize("schema", [RoleCreate, LimitSet, RolePolicySet])
def test_role_limit_values_fit_postgresql_bigint(schema: type[object]) -> None:
    maximum = 9_223_372_036_854_775_807
    if schema is RoleCreate:
        valid_payload = {"code": "bounded", "name": "Bounded", "limits": {"quota": maximum}}
        invalid_payload = {
            "code": "overflow",
            "name": "Overflow",
            "limits": {"quota": maximum + 1},
        }
    else:
        valid_payload = {"limits": {"quota": maximum}}
        invalid_payload = {"limits": {"quota": maximum + 1}}
        if schema is RolePolicySet:
            valid_payload["permission_codes"] = []
            invalid_payload["permission_codes"] = []

    schema(**valid_payload)
    with pytest.raises(ValidationError):
        schema(**invalid_payload)


def test_refresh_token_has_a_bounded_request_size() -> None:
    RefreshRequest(refresh_token="x" * 20)

    with pytest.raises(ValidationError):
        RefreshRequest(refresh_token="x" * 4_097)
