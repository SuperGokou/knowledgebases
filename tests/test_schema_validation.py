import pytest
from pydantic import ValidationError

from app.main import app
from app.schemas.auth import RefreshRequest
from app.schemas.roles import LimitSet, PermissionSet, RoleCreate, RolePolicySet, RoleUpdate
from app.schemas.users import UserCreate, UserPasswordReset, UserUpdate


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


@pytest.mark.parametrize("schema", [RoleCreate, RoleUpdate])
def test_role_description_is_bounded_to_2000_characters(schema: type[object]) -> None:
    if schema is RoleCreate:
        valid_payload = {"code": "bounded", "name": "Bounded", "description": "x" * 2_000}
        invalid_payload = {"code": "overflow", "name": "Overflow", "description": "x" * 2_001}
    else:
        valid_payload = {"expected_version": 1, "description": "x" * 2_000}
        invalid_payload = {"expected_version": 1, "description": "x" * 2_001}

    schema(**valid_payload)
    with pytest.raises(ValidationError):
        schema(**invalid_payload)


def test_role_description_openapi_contract_matches_the_runtime_limit() -> None:
    components = app.openapi()["components"]["schemas"]

    for schema_name in ("RoleCreate", "RoleUpdate"):
        description = components[schema_name]["properties"]["description"]
        string_schema = next(item for item in description["anyOf"] if item["type"] == "string")
        assert string_schema["maxLength"] == 2_000


@pytest.mark.parametrize(
    "password",
    [
        "Valid-Password-123!汉",
        "Valid-Password-123!é",
        "Valid-Password-123!😀",
    ],
)
def test_password_contract_rejects_non_ascii_code_points(password: str) -> None:
    with pytest.raises(ValidationError):
        UserCreate(email="ascii-contract@example.com", password=password)
    with pytest.raises(ValidationError):
        UserPasswordReset(current_password="current", new_password=password)


def test_password_contract_accepts_printable_ascii_boundary_symbol() -> None:
    password = "Ascii-Boundary-123~"
    UserCreate(email="ascii-boundary@example.com", password=password)
    UserPasswordReset(current_password="current", new_password=password)


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
        valid_payload = {"expected_version": 1, "limits": {"quota": maximum}}
        invalid_payload = {"expected_version": 1, "limits": {"quota": maximum + 1}}
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


@pytest.mark.parametrize(
    ("schema", "payload"),
    [
        (RoleUpdate, {"name": "Renamed"}),
        (PermissionSet, {"permission_codes": []}),
        (LimitSet, {"limits": {}}),
        (RolePolicySet, {"permission_codes": [], "limits": {}}),
    ],
)
def test_role_mutations_require_a_positive_policy_snapshot(
    schema: type[object], payload: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        schema(**payload)
    with pytest.raises(ValidationError):
        schema(**payload, expected_version=0)
    schema(**payload, expected_version=1)
