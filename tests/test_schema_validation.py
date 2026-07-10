import pytest
from pydantic import ValidationError

from app.schemas.roles import LimitSet, RoleCreate, RolePolicySet, RoleUpdate
from app.schemas.users import UserUpdate


def test_non_nullable_patch_fields_reject_explicit_null() -> None:
    with pytest.raises(ValidationError):
        RoleUpdate(name=None)
    with pytest.raises(ValidationError):
        RoleUpdate(priority=None)
    with pytest.raises(ValidationError):
        UserUpdate(status=None)


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
